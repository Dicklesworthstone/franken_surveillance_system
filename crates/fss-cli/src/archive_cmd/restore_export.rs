#![forbid(unsafe_code)]
//! Recover an independently pinned copied selection into a new native archive.
//!
//! A complete native preflight precedes destination creation. The second pass owns one
//! recording at a time and uses the existing root-last publisher/catalog writer. Its input
//! account is the remainder of the first pass's allowance, not a renewed budget. A failed
//! destination is retained for inspection; a final receipt acknowledges only a fully indexed,
//! cold-reopened selection, never the original archive's completeness or coverage history.

use super::*;
use fss_core::CanonicalEncode;
use fss_publication::ScopedPublicationIo;
use fss_reference::rtsp::recording_archive::{ArchiveWriteProgress, CodecRecordingArchiveWriter};
use verify_export::bundle;

mod io;

const RESTORATION_SCHEMA: &str = "fss.local_archive_export_restoration.v1";
const COMPLETION_SCHEMA: &str = "fss.local_archive_restore_completion.v1";

struct InputClock<'a, C>(&'a C);
impl<C: OperationClock> bundle::Clock for InputClock<'_, C> {
    fn check(&self) -> bundle::Result<()> {
        let now = self
            .0
            .now_ns()
            .map_err(|_| ExportVerificationError::Deadline)?;
        if now >= self.0.deadline_ns() {
            return Err(ExportVerificationError::Deadline);
        }
        if self
            .0
            .cancel_requested(PublishCutPoint::AfterChildrenVerified)
        {
            return Err(ExportVerificationError::Cancelled);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WindowIdentity {
    original_ordinal: usize,
    root: ContentDigest,
    requested: Range<u64>,
    returned: Range<u64>,
    bytes: u64,
}
impl From<&bundle::Window> for WindowIdentity {
    fn from(window: &bundle::Window) -> Self {
        Self {
            original_ordinal: window.ordinal,
            root: window.root,
            requested: window.requested.clone(),
            returned: window.returned.clone(),
            bytes: window.bytes,
        }
    }
}

struct Selection {
    receipt: bundle::Receipt,
    windows: Vec<WindowIdentity>,
    pages: Vec<ContentDigest>,
    retained_objects: usize,
    retained_bytes: u64,
}

struct Observations {
    phase: &'static str,
    windows: usize,
    pages: usize,
    indexed: usize,
    pending_window: bool,
    pending_page: bool,
    snapshot: Option<ContentDigest>,
    cold_verified: bool,
    input_bytes: u64,
    input_calls: u64,
    input_accounting: &'static str,
    completion: Option<ContentDigest>,
    steps: usize,
}
impl Observations {
    fn new(selection: &Selection) -> Self {
        Self {
            phase: "opening_destination",
            windows: 0,
            pages: 0,
            indexed: 0,
            pending_window: false,
            pending_page: false,
            snapshot: None,
            cold_verified: false,
            input_bytes: selection.receipt.charged_read_bytes,
            input_calls: selection.receipt.io_calls,
            input_accounting: "observed_reads",
            completion: None,
            steps: 0,
        }
    }
}

pub(super) fn execute<C: OperationClock + Send + Sync + 'static>(
    options: &ArchiveOptions,
    clock: Arc<C>,
) -> Result<String> {
    if options.action != Action::RestoreExport {
        return Err(malformed("restore execution requires restore-export"));
    }
    clock.check()?;
    // Original packets cannot acquire an unmasked path through a restore. Retain the
    // current policy owner and its exclusive lock through publication and receipt sync.
    let _privacy = refuse_masked_export(options)?;
    clock.check()?;
    match options.codec {
        Codec::Avc => restore_for::<AvcArchiveCodec, C>(options, clock),
        Codec::Hevc => restore_for::<HevcArchiveCodec, C>(options, clock),
    }
}

fn restore_for<F: ArchiveCodec, C: OperationClock + Send + Sync + 'static>(
    options: &ArchiveOptions,
    clock: Arc<C>,
) -> Result<String> {
    options.archive_limits.validate()?;
    options
        .storage_limits
        .validate()
        .map_err(ArchiveCommandError::Storage)?;
    let namespace = CodecArchiveNamespace::<F>::new(options.scope.clone())?;
    let completion = options
        .expected_completion
        .ok_or(ArchiveCommandError::ExportVerification(
            ExportVerificationError::CompletionPinMismatch,
        ))?;
    let input_scope = scope(options, namespace.digest());
    let input_clock = InputClock(clock.as_ref());
    let limits = input_limits(options);
    let selection = preflight::<F>(
        options,
        &namespace,
        &input_scope,
        limits,
        &input_clock,
        completion,
    )?;
    clock.check()?;

    // Both complete passes share one finite account. Price a second identical pass before
    // any mkdir; observed drift can still refuse later and leaves no completion claim.
    let remaining_bytes = limits
        .read_bytes
        .checked_sub(selection.receipt.charged_read_bytes)
        .filter(|remaining| *remaining >= selection.receipt.charged_read_bytes)
        .ok_or(ArchiveCommandError::ExportVerification(
            ExportVerificationError::Limit("read_bytes"),
        ))?;
    let remaining_calls = limits
        .io_calls
        .checked_sub(selection.receipt.io_calls)
        .filter(|remaining| *remaining >= selection.receipt.io_calls)
        .ok_or(ArchiveCommandError::ExportVerification(
            ExportVerificationError::Limit("io_calls"),
        ))?;
    let second_limits = bundle::Limits {
        read_bytes: remaining_bytes,
        io_calls: remaining_calls,
        ..limits
    };
    let output = options
        .output
        .as_deref()
        .ok_or(ArchiveCommandError::OutputScope)?;
    let mut protected = vec![options.root.as_path()];
    if let Some((privacy, _)) = &options.privacy {
        protected.push(privacy.as_path());
    }
    let io_clock = Arc::clone(&clock);
    let permit = Arc::new(move || io_clock.check().is_ok());
    let io = io::RestoreIo::create(
        output,
        &protected,
        options.restore_io_bytes,
        options.restore_io_operations,
        permit,
    )?;
    let mut observed = Observations::new(&selection);
    let result = restore_selected::<F, C>(
        options,
        &clock,
        &namespace,
        &input_scope,
        second_limits,
        &selection,
        &io,
        &mut observed,
    )
    .map_err(|cause| io.failure().unwrap_or(cause));
    // Successful reads release unused reservations. If any second-pass read/open fails,
    // its remaining reservation stays charged: an interrupted reader cannot renew it.
    let report = report(
        options,
        namespace.digest(),
        &selection,
        &observed,
        &io,
        result.is_ok(),
    )?;
    match result {
        Ok(()) => Ok(report),
        Err(cause) => Err(ArchiveCommandError::RestoreIncomplete {
            report,
            cause: Box::new(cause),
        }),
    }
}

fn scope(options: &ArchiveOptions, namespace: ContentDigest) -> bundle::Scope {
    bundle::Scope {
        codec: options.codec.name(),
        sensor: options.scope.recording.sensor.as_str().to_owned(),
        stream: options.scope.recording.stream.as_str().to_owned(),
        generation: options.scope.recording.generation,
        anchor: options.scope.recording.anchor,
        receive_clock: options.scope.recording.receive_clock,
        decode_clock: options.scope.decode_clock,
        time_scale: options.scope.time_scale,
        namespace,
    }
}

fn input_limits(options: &ArchiveOptions) -> bundle::Limits {
    bundle::Limits {
        windows: options.archive_limits.max_windows,
        files: options
            .storage_limits
            .spool
            .max_objects
            .min(bundle::MAX_FILES),
        file_bytes: options.storage_limits.spool.max_total_bytes,
        read_bytes: options.verify_read_budget,
        io_calls: options.verify_io_budget,
        window_bytes: MAX_RECORDING_BYTES,
    }
}

fn verified_window<F: ArchiveCodec>(
    bytes: bundle::WindowBytes,
    scope: &CatalogScope,
) -> Result<(F::Recording, WindowIdentity)> {
    let identity = WindowIdentity::from(&bytes.window);
    let recording = F::restore_recording(
        bytes.window.root,
        &bytes.manifest,
        [bytes.source, bytes.initialization, bytes.media, bytes.index],
        scope,
    )?;
    let plan = F::plan(&recording);
    if plan.summary().decode_interval != identity.returned
        || plan.manifest().root() != identity.root
        || plan.byte_len() as u64 != identity.bytes
    {
        return Err(ArchiveError::Metadata.into());
    }
    Ok((recording, identity))
}

fn preflight<F: ArchiveCodec>(
    options: &ArchiveOptions,
    namespace: &CodecArchiveNamespace<F>,
    scope: &bundle::Scope,
    limits: bundle::Limits,
    clock: &impl bundle::Clock,
    completion: ContentDigest,
) -> Result<Selection> {
    let mut input = bundle::Bundle::open(&options.root, completion, scope, limits, clock)
        .map_err(ArchiveCommandError::ExportVerification)?;
    let mut windows = Vec::new();
    let mut pages = Vec::new();
    let mut inventory = BTreeMap::new();
    let mut builder = None;
    let mut page_windows = 0;
    let mut total = 0;
    while let Some(bytes) = input
        .next_window()
        .map_err(ArchiveCommandError::ExportVerification)?
    {
        clock
            .check()
            .map_err(ArchiveCommandError::ExportVerification)?;
        let (recording, identity) = verified_window::<F>(bytes, &options.scope)?;
        let plan = F::plan(&recording);
        for (_, digest, bytes) in plan.children() {
            retain_object(&mut inventory, &mut total, digest, bytes.len(), options)?;
        }
        retain_object(
            &mut inventory,
            &mut total,
            plan.manifest().root(),
            plan.manifest().canonical_bytes().len(),
            options,
        )?;
        if builder.is_none() {
            builder = Some(F::builder(options.scope.clone())?);
        }
        F::push(
            builder.as_mut().ok_or(ArchiveError::Metadata)?,
            &namespace.window_slot(windows.len())?,
            &recording,
        )?;
        windows.try_reserve(1).map_err(|_| ArchiveError::Limit)?;
        windows.push(identity);
        page_windows += 1;
        if page_windows == options.archive_limits.windows_per_page {
            preflight_page::<F>(
                builder.take().ok_or(ArchiveError::Metadata)?,
                &mut inventory,
                &mut total,
                &mut pages,
                options,
            )?;
            page_windows = 0;
        }
        clock
            .check()
            .map_err(ArchiveCommandError::ExportVerification)?;
    }
    if let Some(builder) = builder {
        preflight_page::<F>(builder, &mut inventory, &mut total, &mut pages, options)?;
    }
    let roots = windows
        .len()
        .checked_add(pages.len())
        .ok_or(ArchiveError::Limit)?;
    // The completed archive also has two auxiliary receipt names. Native discovery
    // bounds each inventory separately (including foreign top-level entries), so a
    // subsequent ordinary query must admit both names even for an empty selection.
    if roots > options.storage_limits.max_roots
        || roots.max(2) > options.archive_limits.max_scan_roots
    {
        return Err(ArchiveError::Limit.into());
    }
    let receipt = input
        .finish()
        .map_err(ArchiveCommandError::ExportVerification)?;
    clock
        .check()
        .map_err(ArchiveCommandError::ExportVerification)?;
    Ok(Selection {
        receipt,
        windows,
        pages,
        retained_objects: inventory.len(),
        retained_bytes: total,
    })
}

fn retain_object(
    inventory: &mut BTreeMap<ContentDigest, usize>,
    total: &mut u64,
    digest: ContentDigest,
    bytes: usize,
    options: &ArchiveOptions,
) -> Result<()> {
    if let Some(prior) = inventory.get(&digest) {
        return if *prior == bytes {
            Ok(())
        } else {
            Err(ArchiveError::Metadata.into())
        };
    }
    let next = total.checked_add(bytes as u64).ok_or(ArchiveError::Limit)?;
    if inventory.len() == options.storage_limits.spool.max_objects
        || next > options.storage_limits.spool.max_total_bytes
        || bytes > options.storage_limits.spool.max_object_bytes
    {
        return Err(ArchiveError::Limit.into());
    }
    inventory.insert(digest, bytes);
    *total = next;
    Ok(())
}

fn preflight_page<F: ArchiveCodec>(
    builder: F::Builder,
    inventory: &mut BTreeMap<ContentDigest, usize>,
    total: &mut u64,
    pages: &mut Vec<ContentDigest>,
    options: &ArchiveOptions,
) -> Result<()> {
    if pages.len() == options.archive_limits.max_pages {
        return Err(ArchiveError::Limit.into());
    }
    let page = F::prepare(builder)?;
    let manifest = F::manifest(&page);
    if manifest.children().len() > options.storage_limits.max_children {
        return Err(ArchiveError::Limit.into());
    }
    retain_object(
        inventory,
        total,
        manifest.metadata_digest().ok_or(ArchiveError::Metadata)?,
        F::index(&page).len(),
        options,
    )?;
    retain_object(
        inventory,
        total,
        manifest.root(),
        manifest.canonical_bytes().len(),
        options,
    )?;
    pages.try_reserve(1).map_err(|_| ArchiveError::Limit)?;
    pages.push(manifest.root());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn restore_selected<F: ArchiveCodec, C: OperationClock + Send + Sync + 'static>(
    options: &ArchiveOptions,
    clock: &Arc<C>,
    namespace: &CodecArchiveNamespace<F>,
    scope: &bundle::Scope,
    limits: bundle::Limits,
    selection: &Selection,
    io: &Arc<io::RestoreIo>,
    observed: &mut Observations,
) -> Result<()> {
    io.check()?;
    let scoped: Arc<dyn ScopedPublicationIo> = io.clone();
    let mut publisher = LocalRootPublisher::open_scoped(io.root(), options.storage_limits, scoped)
        .map_err(ArchiveCommandError::Storage)?;
    io.check()?;
    let mut writer = CodecRecordingArchiveWriter::<F>::open(
        &mut publisher,
        CodecArchiveNamespace::new(options.scope.clone())?,
        options.archive_limits,
        clock.now_ns()?,
        clock.deadline_ns(),
        clock.as_ref(),
    )?;
    // No existing inventory can be silently merged into this explicit fresh destination.
    if !writer.snapshot().windows().is_empty() || !writer.snapshot().pages().is_empty() {
        return Err(ArchiveError::RecoveryRequired.into());
    }
    let step_limit = selection
        .windows
        .len()
        .checked_mul(4)
        .and_then(|n| {
            selection
                .pages
                .len()
                .checked_mul(8)
                .and_then(|p| n.checked_add(p))
        })
        .and_then(|n| n.checked_add(16))
        .ok_or(ArchiveError::Limit)?;
    observed.phase = "restoring_windows";
    let driven = (|| -> Result<()> {
        // Reserve the remaining input allowance before opening pass two. Success refunds
        // unused bytes/calls; a failed open/read retains the complete reservation.
        observed.input_bytes = options.verify_read_budget;
        observed.input_calls = options.verify_io_budget;
        observed.input_accounting = "remaining_reservation_retained";
        let input_clock = InputClock(clock.as_ref());
        let mut input = bundle::Bundle::open(
            &options.root,
            selection.receipt.completion,
            scope,
            limits,
            &input_clock,
        )
        .map_err(ArchiveCommandError::ExportVerification)?;
        let mut next = 0;
        while let Some(bytes) = input
            .next_window()
            .map_err(ArchiveCommandError::ExportVerification)?
        {
            clock.check()?;
            let (recording, identity) = verified_window::<F>(bytes, &options.scope)?;
            if selection.windows.get(next) != Some(&identity) {
                return Err(ArchiveCommandError::ExportVerification(
                    ExportVerificationError::Changed,
                ));
            }
            let reserved = F::plan(&recording).byte_len();
            let admission = writer
                .offer(recording, reserved, clock.now_ns()?)
                .map_err(|refusal| ArchiveCommandError::Archive(*refusal.reason))?;
            if admission.ordinal != next || admission.root != identity.root {
                return Err(ArchiveError::Metadata.into());
            }
            settle(&mut writer, clock.as_ref(), io, observed, step_limit, false)?;
            next += 1;
        }
        observed.phase = "checking_source_again";
        let receipt = input
            .finish()
            .map_err(ArchiveCommandError::ExportVerification)?;
        observed.input_bytes = selection
            .receipt
            .charged_read_bytes
            .checked_add(receipt.charged_read_bytes)
            .ok_or(ArchiveError::Limit)?;
        observed.input_calls = selection
            .receipt
            .io_calls
            .checked_add(receipt.io_calls)
            .ok_or(ArchiveError::Limit)?;
        observed.input_accounting = "observed_reads";
        if next != selection.windows.len() || !same_receipt(&selection.receipt, &receipt) {
            return Err(ArchiveCommandError::ExportVerification(
                ExportVerificationError::Changed,
            ));
        }
        clock.check()?;
        observed.phase = "publishing_catalogs";
        writer.finish();
        settle(&mut writer, clock.as_ref(), io, observed, step_limit, true)
    })();
    // Retirement transfers every acknowledgement and pending state even when a syscall or
    // native step was indeterminate. Releasing RAM never deletes staged or durable originals.
    let retirement = writer.retire();
    observed.windows = retirement.snapshot.windows().len();
    observed.pages = retirement.snapshot.pages().len();
    observed.indexed = retirement.snapshot.indexed_windows();
    observed.pending_window = retirement.pending.is_some();
    observed.pending_page = retirement.prepared_page.is_some();
    drop(retirement);
    driven?;
    drop(publisher);

    observed.phase = "reopening_archive";
    clock.check()?;
    let scoped: Arc<dyn ScopedPublicationIo> = io.clone();
    let publisher = LocalRootPublisher::open_scoped(io.root(), options.storage_limits, scoped)
        .map_err(ArchiveCommandError::Storage)?;
    let snapshot = CodecArchiveSnapshot::<F>::load(
        &publisher,
        CodecArchiveNamespace::new(options.scope.clone())?,
        options.archive_limits,
        clock.as_ref(),
    )?;
    if Some(snapshot.digest()?) != observed.snapshot
        || snapshot.namespace().digest() != namespace.digest()
        || snapshot.windows().len() != selection.windows.len()
        || snapshot.indexed_windows() != selection.windows.len()
        || snapshot.pages().len() != selection.pages.len()
        || snapshot
            .windows()
            .iter()
            .zip(&selection.windows)
            .any(|(actual, expected)| {
                actual.root() != expected.root || actual.decode_interval() != expected.returned
            })
        || snapshot
            .pages()
            .iter()
            .zip(&selection.pages)
            .any(|(actual, expected)| F::manifest(actual.catalog()).root() != *expected)
    {
        return Err(ArchiveError::Metadata.into());
    }
    observed.cold_verified = true;
    io.check()?;
    clock.check()?;
    observed.phase = "publishing_completion";
    let receipt = completion_report(options, namespace.digest(), selection, observed)?;
    observed.completion = Some(ContentDigest::sha256(receipt.as_bytes()));
    let digest = io.write_completion(receipt.as_bytes())?;
    if Some(digest) != observed.completion || !io.completion_durable() {
        return Err(ArchiveError::Metadata.into());
    }
    // Retain the reopened archive locks and privacy owner through receipt publication.
    clock.check()?;
    io.check()?;
    drop(publisher);
    observed.phase = "complete";
    Ok(())
}

fn settle<F: ArchiveCodec>(
    writer: &mut CodecRecordingArchiveWriter<'_, F>,
    clock: &impl OperationClock,
    io: &io::RestoreIo,
    observed: &mut Observations,
    limit: usize,
    finishing: bool,
) -> Result<()> {
    loop {
        if observed.steps == limit {
            return Err(ArchiveCommandError::RestoreBudget("writer_steps"));
        }
        clock.check()?;
        io.check()?;
        observed.steps += 1;
        let progress = writer.step(clock.now_ns()?, clock)?;
        // Capture acknowledged facts before a post-effect clock/budget probe may refuse.
        observed.windows = writer.snapshot().windows().len();
        observed.pages = writer.snapshot().pages().len();
        observed.indexed = writer.snapshot().indexed_windows();
        if let ArchiveWriteProgress::Finished {
            snapshot_digest,
            windows,
            pages,
        } = progress
        {
            observed.snapshot = Some(snapshot_digest);
            if !finishing
                || windows != observed.windows
                || pages != observed.pages
                || observed.indexed != windows
            {
                return Err(ArchiveError::Metadata.into());
            }
            io.check()?;
            clock.check()?;
            return Ok(());
        }
        io.check()?;
        if matches!(progress, ArchiveWriteProgress::Ready { .. }) {
            return if finishing {
                Err(ArchiveError::Metadata.into())
            } else {
                Ok(())
            };
        }
        if matches!(progress, ArchiveWriteProgress::Exhausted) {
            return Err(ArchiveError::Metadata.into());
        }
    }
}

fn same_receipt(a: &bundle::Receipt, b: &bundle::Receipt) -> bool {
    a.completion == b.completion
        && a.request_observation == b.request_observation
        && a.snapshot_claim == b.snapshot_claim
        && a.query == b.query
        && a.windows == b.windows
        && a.recording_bytes == b.recording_bytes
        && a.file_bytes == b.file_bytes
        && a.files == b.files
        && a.pending_copy_present == b.pending_copy_present
}

fn context(options: &ArchiveOptions, namespace: ContentDigest, selection: &Selection) -> String {
    format!(
        "\"codec\":\"{}\",\"sensor\":{},\"stream\":{},\"generation\":{},\"anchor\":{},\"receive_clock\":{},\"decode_clock\":{},\"time_scale\":{},\"namespace\":{},\"completion_sha256\":{},\"request_sha256_observed\":{},\"request_binding\":\"semantic_consistency_only_unpinned_by_completion_v1\",\"original_snapshot_claim\":{},\"original_query\":{}",
        options.codec.name(),
        quoted(options.scope.recording.sensor.as_str()),
        quoted(options.scope.recording.stream.as_str()),
        options.scope.recording.generation,
        quoted(&options.scope.recording.anchor.to_text()),
        quoted(&options.scope.recording.receive_clock.to_text()),
        quoted(&options.scope.decode_clock.to_text()),
        options.scope.time_scale,
        quoted(&namespace.to_text()),
        quoted(&selection.receipt.completion.to_text()),
        quoted(&selection.receipt.request_observation.to_text()),
        quoted(&selection.receipt.snapshot_claim.to_text()),
        interval(&selection.receipt.query),
    )
}

fn completion_report(
    options: &ArchiveOptions,
    namespace: ContentDigest,
    selection: &Selection,
    observed: &Observations,
) -> Result<String> {
    let snapshot = observed.snapshot.ok_or(ArchiveError::Metadata)?;
    if !observed.cold_verified
        || observed.windows != selection.windows.len()
        || observed.indexed != observed.windows
        || observed.pages != selection.pages.len()
        || observed.pending_window
        || observed.pending_page
    {
        return Err(ArchiveError::Metadata.into());
    }
    bounded(format!(
        "{{\"schema\":\"{COMPLETION_SCHEMA}\",{},\"new_snapshot\":{},\"restored_windows\":{},\"restored_pages\":{},\"indexed_windows\":{},\"retained_objects\":{},\"retained_bytes\":{},\"native_source_provenance_verified\":true,\"playback_bytes_verified\":true,\"decoded_pictures_verified\":false,\"original_catalog_reconstructed\":false,\"original_clock_index_restored\":false,\"coverage_claim\":\"not_claimed\",\"filesystem_snapshot_atomic\":false,\"complete\":true}}\n",
        context(options, namespace, selection),
        quoted(&snapshot.to_text()),
        observed.windows,
        observed.pages,
        observed.indexed,
        selection.retained_objects,
        selection.retained_bytes,
    ))
}

fn report(
    options: &ArchiveOptions,
    namespace: ContentDigest,
    selection: &Selection,
    observed: &Observations,
    io: &io::RestoreIo,
    complete: bool,
) -> Result<String> {
    let digest = |value: Option<ContentDigest>| {
        value.map_or_else(|| "null".to_owned(), |v| quoted(&v.to_text()))
    };
    bounded(format!(
        "{{\"schema\":\"{RESTORATION_SCHEMA}\",\"command\":\"restore-export\",{},\"phase\":\"{}\",\"output_created\":true,\"source_preflight_verified\":true,\"selected_windows\":{},\"restored_windows\":{},\"restored_pages\":{},\"indexed_windows\":{},\"pending_window\":{},\"pending_page\":{},\"new_snapshot\":{},\"destination_cold_verified\":{},\"restore_completion_sha256\":{},\"restore_completion_visible\":{},\"restore_completion_durable\":{},\"input_read_bytes_charged\":{},\"input_io_calls_charged\":{},\"input_accounting\":\"{}\",\"local_io_bytes_charged\":{},\"local_io_operations_charged\":{},\"writer_steps\":{},\"native_source_provenance_verified\":true,\"playback_bytes_verified\":true,\"decoded_pictures_verified\":false,\"original_catalog_reconstructed\":false,\"original_clock_index_restored\":false,\"coverage_claim\":\"not_claimed\",\"filesystem_snapshot_atomic\":false,\"publication_reconciliation_required\":{},\"complete\":{}}}\n",
        context(options, namespace, selection),
        observed.phase,
        selection.windows.len(),
        observed.windows,
        observed.pages,
        observed.indexed,
        observed.pending_window,
        observed.pending_page,
        digest(observed.snapshot),
        observed.cold_verified,
        digest(observed.completion),
        io.completion_visible(),
        io.completion_durable(),
        observed.input_bytes,
        observed.input_calls,
        observed.input_accounting,
        io.bytes(),
        io.operations(),
        observed.steps,
        !complete,
        complete,
    ))
}

fn bounded(report: String) -> Result<String> {
    if report.len() > MAX_REPORT_BYTES {
        return Err(ArchiveCommandError::ReportLimit);
    }
    Ok(report)
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
