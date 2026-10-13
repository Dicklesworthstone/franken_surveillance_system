#![forbid(unsafe_code)]
//! Storage-only recovery of the exact epochs enumerated by a reconnect plan.
//!
//! Planning checks protected journal metadata, not source custody. A separate approval binds
//! every observed tip, selected work pin, directory identity, original limit and recovery deadline.
//! Execution locks all journals, checks that approval, and replays ALL selected work before the
//! first confirmation/publication. Restoration is incremental, not an atomic multi-store commit.
//! No socket, credential lease, new epoch, tail repair or additional catalog page is created here.

use std::fs::{self, Metadata};
use std::path::{Path, PathBuf};
use std::time::Instant;

use fss_cli::agent_json::{object, string};
use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
};
use fss_publication::{
    LocalPublicationReceipt, LocalRootPublisher, NeverCancel, PublishCancellation, PublishCutPoint,
    PublishOutcome,
};
use fss_reference::rtsp::archive_pins::{
    ArchivePinAnchor, ArchivePinPhase, CodecArchivePinJournal, StoredArchivePin,
};
use fss_reference::rtsp::recording_archive::{ArchiveCodec, AvcArchiveCodec, HevcArchiveCodec};

use super::ReconnectPlan;

const FORMAT: &str = "fss.rtsp_reconnect_recovery_cli.v1";
const POLICY: &str = "storage-only:exact-observed-tips:all-selected-source-preflight:original-work-only:no-camera:no-secret:no-tail-repair:no-new-pages:no-cross-epoch-continuity:v1";
const ROOT: &str = "ERR-CAPTURE-RTSP-ROOT-001";
const STORAGE: &str = "ERR-CAPTURE-RTSP-STORAGE-001";
const STATE: &str = "ERR-CAPTURE-RTSP-STATE-001";
const APPROVAL: &str = "ERR-CAPTURE-RTSP-APPROVAL-001";
const OUTPUT: &str = "ERR-CAPTURE-RTSP-OUTPUT-001";
const DEADLINE: &str = "ERR-CAPTURE-RTSP-DEADLINE-001";
const AUTHORITY: &str = "ERR-CAPTURE-RTSP-AUTHORITY-001";
const REPORT_LIMIT: usize = 524_288;
const CAPS: [&str; 4] = [
    "CAP-READ-MEDIA-001",
    "CAP-OBJECT-STAGE-001",
    "CAP-OBJECT-PUBLISH-001",
    "CAP-RETENTION-COMMIT-001",
];

type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity(u64, u64);

#[cfg(unix)]
fn identity(metadata: &Metadata) -> Result<Identity> {
    use std::os::unix::fs::MetadataExt;
    Ok(Identity(metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn identity(_: &Metadata) -> Result<Identity> {
    // No weak path-only replacement check without the native identity contract.
    Err(ROOT)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Location {
    canonical: PathBuf,
    parent: Identity,
    directory: Option<Identity>,
}

fn locate(path: &Path) -> Result<Location> {
    let parent = fs::canonicalize(path.parent().ok_or(ROOT)?).map_err(|_| ROOT)?;
    let parent_metadata = fs::metadata(&parent).map_err(|_| ROOT)?;
    if !parent_metadata.is_dir() {
        return Err(ROOT);
    }
    let canonical = parent.join(path.file_name().ok_or(ROOT)?);
    let directory = match fs::symlink_metadata(&canonical) {
        Ok(metadata) if metadata.is_dir() => Some(identity(&metadata)?),
        Ok(_) => return Err(ROOT),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(ROOT),
    };
    let result = Location {
        canonical,
        parent: identity(&parent_metadata)?,
        directory,
    };
    // Refuse a replaced parent rather than mixing observations of two trees.
    if identity(&fs::metadata(&parent).map_err(|_| ROOT)?)? != result.parent {
        return Err(ROOT);
    }
    Ok(result)
}

fn disjoint(locations: &[Location]) -> Result<()> {
    for (index, current) in locations.iter().enumerate() {
        for other in &locations[..index] {
            if current.canonical.starts_with(&other.canonical)
                || other.canonical.starts_with(&current.canonical)
                || current.directory.is_some_and(|id| Some(id) == other.directory)
            {
                return Err(ROOT);
            }
        }
    }
    Ok(())
}

fn archive_layout(path: &Path) -> Result<()> {
    for name in [
        "roots",
        "tombstones",
        "spool",
        "spool/objects",
        "spool/staging",
        "spool/verified",
    ] {
        if !fs::symlink_metadata(path.join(name))
            .map_err(|_| ROOT)?
            .is_dir()
        {
            return Err(ROOT);
        }
    }
    for name in ["LOCK", "spool/LOCK"] {
        if !fs::symlink_metadata(path.join(name))
            .map_err(|_| ROOT)?
            .is_file()
        {
            return Err(ROOT);
        }
    }
    Ok(())
}

struct Clock<'a> {
    start: Instant,
    timeout: u64,
    cancellation: &'a dyn PublishCancellation,
    authority: Option<ContextAuthority>,
}

impl Clock<'_> {
    fn now(&self) -> Result<u64> {
        let now = u64::try_from(self.start.elapsed().as_nanos()).map_err(|_| DEADLINE)?;
        if now >= self.timeout {
            return Err(DEADLINE);
        }
        if let Some(authority) = &self.authority {
            authority.validate().map_err(|_| AUTHORITY)?;
            if authority.cancellation_reason.is_some()
                || !CAPS.iter().all(|cap| authority.has_capability(cap))
            {
                return Err(AUTHORITY);
            }
        }
        if self
            .cancellation
            .cancel_requested(PublishCutPoint::AfterChildrenVerified)
        {
            return Err(AUTHORITY);
        }
        Ok(now)
    }
}

impl PublishCancellation for Clock<'_> {
    fn cancel_requested(&self, cut: PublishCutPoint) -> bool {
        self.now().is_err() || self.cancellation.cancel_requested(cut)
    }
}

struct Entry<C: ArchiveCodec> {
    root: Location,
    pins: Location,
    journal: Option<CodecArchivePinJournal<C>>,
    anchor: Option<ArchivePinAnchor>,
    selected: Option<(ArchivePinPhase, StoredArchivePin)>,
    publisher: Option<LocalRootPublisher>,
    window_slot: Option<String>,
    catalog_slot: Option<String>,
}

fn load<C: ArchiveCodec>(plan: &ReconnectPlan, clock: &Clock<'_>) -> Result<Vec<Entry<C>>> {
    if plan.attempts.is_empty() || plan.attempts.len() > 16 {
        return Err(STATE);
    }
    let mut locations = Vec::new();
    for attempt in &plan.attempts {
        clock.now()?;
        locations.push(locate(&attempt.root)?);
        locations.push(locate(&attempt.pins)?);
    }
    disjoint(&locations)?;
    // A lone archive is not an empty journal. A lone journal is not permission to initialize
    // a replacement archive. Check every layout before opening any native owner.
    for pair in locations.as_chunks::<2>().0 {
        if pair[0].directory.is_some() != pair[1].directory.is_some() {
            return Err(ROOT);
        }
        if pair[0].directory.is_some() {
            archive_layout(&pair[0].canonical)?;
        }
    }
    let mut entries = Vec::new();
    for (attempt, pair) in plan.attempts.iter().zip(locations.as_chunks::<2>().0) {
        clock.now()?;
        let journal = if pair[1].directory.is_some() {
            Some(
                CodecArchivePinJournal::<C>::open_complete(
                    &pair[1].canonical,
                    attempt.pin_scope(),
                    None,
                    attempt.pin_limits(),
                    clock,
                )
                .map_err(|_| STORAGE)?,
            )
        } else {
            None
        };
        let anchor = journal.as_ref().map(CodecArchivePinJournal::anchor);
        let selected = journal.as_ref().and_then(|journal| {
            journal
                .state()
                .candidate()
                .map(|pin| (ArchivePinPhase::Candidate, pin.clone()))
                .or_else(|| {
                    journal
                        .state()
                        .last_confirmed()
                        .map(|pin| (ArchivePinPhase::Confirmed, pin.clone()))
                })
        });
        entries.push(Entry {
            root: pair[0].clone(),
            pins: pair[1].clone(),
            journal,
            anchor,
            selected,
            publisher: None,
            window_slot: None,
            catalog_slot: None,
        });
    }
    recheck(plan, &mut entries, clock)?;
    Ok(entries)
}

fn locations_unchanged<C: ArchiveCodec>(
    plan: &ReconnectPlan,
    entries: &[Entry<C>],
    clock: &Clock<'_>,
) -> Result<()> {
    for (attempt, entry) in plan.attempts.iter().zip(entries) {
        clock.now()?;
        if locate(&attempt.root)? != entry.root || locate(&attempt.pins)? != entry.pins {
            return Err(ROOT);
        }
    }
    Ok(())
}

fn recheck<C: ArchiveCodec>(
    plan: &ReconnectPlan,
    entries: &mut [Entry<C>],
    clock: &Clock<'_>,
) -> Result<()> {
    locations_unchanged(plan, entries, clock)?;
    for entry in entries {
        if let Some(journal) = &mut entry.journal {
            journal.verify(clock).map_err(|_| STORAGE)?;
            if Some(journal.anchor()) != entry.anchor {
                return Err(STATE);
            }
        }
    }
    clock.now()?;
    Ok(())
}

fn encode_location(e: &mut CanonicalEncoder, location: &Location) -> Result<()> {
    e.text(location.canonical.to_str().ok_or(ROOT)?);
    e.u64(location.parent.0);
    e.u64(location.parent.1);
    e.bool(location.directory.is_some());
    if let Some(id) = location.directory {
        e.u64(id.0);
        e.u64(id.1);
    }
    Ok(())
}

fn digest<C: ArchiveCodec>(
    plan: &ReconnectPlan,
    entries: &[Entry<C>],
    timeout: u64,
) -> Result<ContentDigest> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.rtsp_reconnect_recovery_plan.v1");
    e.text(POLICY);
    e.digest(plan.digest()?);
    e.u64(timeout);
    e.u64(REPORT_LIMIT as u64);
    e.u64(entries.len() as u64);
    for entry in entries {
        encode_location(&mut e, &entry.root)?;
        encode_location(&mut e, &entry.pins)?;
        e.bool(entry.anchor.is_some());
        if let Some(anchor) = entry.anchor {
            e.u64(anchor.sequence);
            e.digest(anchor.root);
        }
        e.bool(entry.selected.is_some());
        if let Some((phase, pin)) = &entry.selected {
            e.bool(*phase == ArchivePinPhase::Candidate);
            e.text(pin.slot().as_str());
            e.digest(pin.root());
            e.digest(pin.retirement_digest());
            e.u64(pin.new_payload_bytes() as u64);
        }
    }
    Ok(ContentDigest::sha256(
        &e.finish_checked().map_err(|_| STATE)?,
    ))
}

fn anchor_json(anchor: Option<ArchivePinAnchor>) -> String {
    anchor.map_or_else(
        || "null".into(),
        |a| {
            object(&[
                ("sequence", a.sequence.to_string()),
                ("root", string(&a.root.to_text())),
            ])
        },
    )
}

fn pin_json(selected: Option<&(ArchivePinPhase, StoredArchivePin)>) -> String {
    selected.map_or_else(
        || "null".into(),
        |(phase, pin)| {
            object(&[
                (
                    "phase",
                    string(if *phase == ArchivePinPhase::Candidate {
                        "candidate"
                    } else {
                        "confirmed"
                    }),
                ),
                ("slot", string(pin.slot().as_str())),
                ("root", string(&pin.root().to_text())),
                ("retirement", string(&pin.retirement_digest().to_text())),
                ("new_payload_bytes", pin.new_payload_bytes().to_string()),
            ])
        },
    )
}

fn receipt_json(
    receipt: Option<&LocalPublicationReceipt>,
    slot: Option<&str>,
) -> Result<String> {
    match (receipt, slot) {
        (None, None) => Ok("null".into()),
        (Some(receipt), Some(slot)) => Ok(object(&[
            ("slot", string(slot)),
            ("root", string(&receipt.root.to_text())),
            (
                "outcome",
                string(if receipt.outcome == PublishOutcome::AlreadyPublished {
                    "already_durable"
                } else {
                    "published"
                }),
            ),
        ])),
        _ => Err(STATE),
    }
}

fn observation<C: ArchiveCodec>(entry: &Entry<C>) -> &'static str {
    if entry.journal.is_none() {
        "both_stores_unobserved"
    } else if entry.selected.is_none() {
        "no_saved_work_pin"
    } else {
        "saved_work_requires_source_verification"
    }
}

fn preview_codec<C: ArchiveCodec>(plan: &ReconnectPlan, timeout: u64) -> Result<String> {
    let clock = Clock {
        start: Instant::now(),
        timeout,
        cancellation: &NeverCancel,
        authority: None,
    };
    let entries = load::<C>(plan, &clock)?;
    let approval = digest(plan, &entries, timeout)?;
    let mut rows = Vec::new();
    let mut maximum_pin_bytes = 0_u64;
    for (index, (attempt, entry)) in plan.attempts.iter().zip(&entries).enumerate() {
        maximum_pin_bytes = maximum_pin_bytes
            .checked_add(attempt.pin_limits().max_bytes as u64)
            .ok_or(STATE)?;
        rows.push(object(&[
            ("attempt", (index + 1).to_string()),
            (
                "generation",
                attempt.recording_config().scope.generation.to_string(),
            ),
            ("root", string(entry.root.canonical.to_str().ok_or(ROOT)?)),
            ("pins", string(entry.pins.canonical.to_str().ok_or(ROOT)?)),
            ("journal", anchor_json(entry.anchor)),
            ("selected_work", pin_json(entry.selected.as_ref())),
            ("observation", string(observation(entry))),
            ("work_custody", string("not_checked")),
        ]));
    }
    let report = object(&[
        ("schema", string(FORMAT)),
        ("phase", string("planned")),
        ("policy", string(POLICY)),
        ("approval", string(&approval.to_text())),
        ("capture_plan", string(&plan.digest()?.to_text())),
        ("recovery_timeout_ns", timeout.to_string()),
        ("maximum_pin_bytes", maximum_pin_bytes.to_string()),
        (
            "maximum_archive_spool_bytes",
            plan.maximum_storage_bytes.to_string(),
        ),
        ("maximum_report_bytes", REPORT_LIMIT.to_string()),
        ("attempts", format!("[{}]", rows.join(","))),
        (
            "trust",
            string("explicit-scope-and-protected-directories:not-an-independent-rollback-proof"),
        ),
        (
            "effects",
            string("metadata-inspection-only:no-original-read-or-publication"),
        ),
        ("network_requested", "false".into()),
        ("capture_complete", "false".into()),
        ("continuity_across_attempts", "false".into()),
    ]);
    clock.now()?;
    if report.len() > REPORT_LIMIT {
        return Err(OUTPUT);
    }
    Ok(report)
}

pub(super) fn preview(plan: &ReconnectPlan, timeout: u64) -> Result<String> {
    match plan.attempts.first().ok_or(STATE)?.codec() {
        "avc" => preview_codec::<AvcArchiveCodec>(plan, timeout),
        "hevc" => preview_codec::<HevcArchiveCodec>(plan, timeout),
        _ => Err(STATE),
    }
}

struct Reports<F> {
    emit: F,
    sequence: u64,
    bytes: usize,
}
impl<F: FnMut(&[u8]) -> Result<()>> Reports<F> {
    fn row(&mut self, kind: &str, detail: String) -> Result<()> {
        let row = object(&[
            ("schema", string(FORMAT)),
            ("sequence", self.sequence.to_string()),
            ("kind", string(kind)),
            ("detail", detail),
        ]) + "\n";
        if row.len() > REPORT_LIMIT.saturating_sub(self.bytes) {
            return Err(OUTPUT);
        }
        (self.emit)(row.as_bytes())?;
        self.bytes += row.len();
        self.sequence = self.sequence.checked_add(1).ok_or(OUTPUT)?;
        Ok(())
    }
}

fn preflight<C: ArchiveCodec>(
    plan: &ReconnectPlan,
    entries: &mut [Entry<C>],
    clock: &Clock<'_>,
) -> Result<()> {
    for index in 0..entries.len() {
        locations_unchanged(plan, entries, clock)?;
        let entry = &mut entries[index];
        if let Some((phase, _)) = &entry.selected {
            let attempt = &plan.attempts[index];
            let publisher =
                LocalRootPublisher::open(&entry.root.canonical, attempt.publication_limits())
                    .map_err(|_| STORAGE)?;
            clock.now()?;
            let work = entry
                .journal
                .as_mut()
                .ok_or(STATE)?
                .load_work(*phase, &publisher, attempt.work_limits(), clock)
                .map_err(|_| STORAGE)?;
            let namespace = work.snapshot.namespace();
            // Keep the original typed slots, not a scan for the newest recording. These allow
            // subsequent import even when the original capture stdout was lost.
            if work.pending.is_some() {
                entry.window_slot = Some(
                    namespace
                        .window_slot(work.snapshot.windows().len())
                        .map_err(|_| STORAGE)?
                        .as_str()
                        .to_owned(),
                );
            }
            if work.prepared_page.is_some() {
                entry.catalog_slot = Some(
                    namespace
                        .page_slot(work.snapshot.indexed_windows())
                        .map_err(|_| STORAGE)?
                        .as_str()
                        .to_owned(),
                );
            }
            // Preflight does not consume the durable work or retain duplicate media buffers.
            // The native restoration revalidates it under the still-held exclusive owners.
            drop(work);
            entry.publisher = Some(publisher);
        }
    }
    recheck(plan, entries, clock)
}

fn restore<C: ArchiveCodec>(
    plan: &ReconnectPlan,
    entries: &mut [Entry<C>],
    clock: &Clock<'_>,
    reports: &mut Reports<impl FnMut(&[u8]) -> Result<()>>,
) -> Result<()> {
    let mut restored = 0_usize;
    let mut durable = 0_usize;
    let mut indexed = 0_usize;
    for index in 0..entries.len() {
        locations_unchanged(plan, entries, clock)?;
        let entry = &mut entries[index];
        let attempt = &plan.attempts[index];
        let detail = if let Some((_, expected)) = &entry.selected {
            let journal = entry.journal.as_mut().ok_or(STATE)?;
            journal.verify(clock).map_err(|_| STORAGE)?;
            if Some(journal.anchor()) != entry.anchor {
                return Err(STATE);
            }
            let result = journal
                .restore_work(
                    entry.publisher.as_mut().ok_or(STATE)?,
                    attempt.work_limits(),
                    clock.now()?,
                    clock.timeout,
                    clock,
                )
                .map_err(|_| STORAGE)?;
            if &result.pin != expected {
                return Err(STATE);
            }
            restored = restored.checked_add(1).ok_or(STATE)?;
            durable = durable.checked_add(result.durable_windows).ok_or(STATE)?;
            indexed = indexed.checked_add(result.indexed_windows).ok_or(STATE)?;
            let scope = attempt.catalog_scope();
            object(&[
                ("attempt", (index + 1).to_string()),
                ("codec", string(attempt.codec())),
                ("root", string(entry.root.canonical.to_str().ok_or(ROOT)?)),
                ("pins", string(entry.pins.canonical.to_str().ok_or(ROOT)?)),
                ("sensor", string(scope.recording.sensor.as_str())),
                ("stream", string(scope.recording.stream.as_str())),
                ("generation", scope.recording.generation.to_string()),
                ("anchor", string(&scope.recording.anchor.to_text())),
                ("receive_clock", string(&scope.recording.receive_clock.to_text())),
                ("decode_clock", string(&scope.decode_clock.to_text())),
                ("time_scale", scope.time_scale.to_string()),
                ("work_root", string(&result.pin.root().to_text())),
                ("journal", anchor_json(Some(result.journal_anchor))),
                ("confirmation_recorded", result.confirmation.is_some().to_string()),
                (
                    "window",
                    receipt_json(result.window.as_ref(), entry.window_slot.as_deref())?,
                ),
                (
                    "catalog",
                    receipt_json(result.catalog.as_ref(), entry.catalog_slot.as_deref())?,
                ),
                ("durable_windows", result.durable_windows.to_string()),
                ("indexed_windows", result.indexed_windows.to_string()),
                (
                    "indexing_remaining",
                    (result.indexed_windows != result.durable_windows).to_string(),
                ),
                ("work_custody", string("verified")),
                ("source_bytes_emitted", "false".into()),
                ("capture_complete", "false".into()),
            ])
        } else {
            object(&[
                ("attempt", (index + 1).to_string()),
                ("observation", string(observation(entry))),
                ("work_custody", string("not_checked")),
                ("capture_complete", "false".into()),
            ])
        };
        // A lost output stops BEFORE the next attempt. Re-preview the current tips to retry
        // original slots after any earlier native commits; never fabricate a fresh ordinal.
        reports.row("attempt_recovery", detail)?;
    }
    clock.now()?;
    reports.row(
        "recovery_terminal",
        object(&[
            ("selected_work_restored", restored.to_string()),
            ("durable_windows_in_checked_archives", durable.to_string()),
            ("indexed_windows_in_checked_archives", indexed.to_string()),
            (
                "unobserved_attempts",
                entries.iter().filter(|entry| entry.journal.is_none()).count().to_string(),
            ),
            (
                "archives_without_work_pin",
                entries.iter().filter(|entry| entry.journal.is_some() && entry.selected.is_none()).count().to_string(),
            ),
            ("operation_complete", "true".into()),
            ("capture_complete", "false".into()),
            ("continuity_across_attempts", "false".into()),
            ("absence_certifiable", "false".into()),
            ("network_requested", "false".into()),
            ("source_bytes_emitted", "false".into()),
        ]),
    )
}

fn execute_codec<C: ArchiveCodec>(
    plan: &ReconnectPlan,
    timeout: u64,
    emit: impl FnMut(&[u8]) -> Result<()>,
    cancellation: &dyn PublishCancellation,
) -> Result<()> {
    let mut clock = Clock {
        start: Instant::now(),
        timeout,
        cancellation,
        authority: None,
    };
    let mut entries = load::<C>(plan, &clock)?;
    let approval = digest(plan, &entries, timeout)?;
    if plan.approve != Some(approval) {
        return Err(APPROVAL);
    }
    let first = plan.attempts.first().ok_or(STATE)?;
    clock.authority = Some(
        ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:rtsp-reconnect-recovery".into(),
            operation_id: OperationId::parse("operation:rtsp-reconnect-recovery")
                .map_err(|_| STATE)?,
            principal: first.principal.clone(),
            capabilities: CAPS.iter().map(|cap| (*cap).to_owned()).collect(),
            deadline: None,
            priority: 10,
            budgets: BudgetVector::default(),
            privacy_scope: "privacy:owner-original-rtsp-custody".into(),
            retention_scope: "retention:explicit-original-rtsp-scope".into(),
            anchor_universe: approval,
            generation: first.recording_config().scope.generation,
        })
        .map_err(|_| AUTHORITY)?,
    );
    let mut reports = Reports {
        emit,
        sequence: 0,
        bytes: 0,
    };
    reports.row(
        "recovery_started",
        object(&[
            ("approval", string(&approval.to_text())),
            ("network_requested", "false".into()),
            ("publication_started", "false".into()),
        ]),
    )?;
    // Keep ALL journal locks and every selected archive owner until restoration has stopped.
    // A cooperative writer cannot change an earlier preflighted store while a later one runs.
    preflight(plan, &mut entries, &clock)?;
    reports.row(
        "source_preflight_complete",
        object(&[
            (
                "selected_attempts",
                entries.iter().filter(|entry| entry.selected.is_some()).count().to_string(),
            ),
            ("publication_started", "false".into()),
        ]),
    )?;
    restore(plan, &mut entries, &clock, &mut reports)
}

pub(super) fn execute(plan: &ReconnectPlan, timeout: u64) -> Result<()> {
    match plan.attempts.first().ok_or(STATE)?.codec() {
        "avc" => execute_codec::<AvcArchiveCodec>(plan, timeout, crate::write_bounded, &NeverCancel),
        "hevc" => execute_codec::<HevcArchiveCodec>(plan, timeout, crate::write_bounded, &NeverCancel),
        _ => Err(STATE),
    }
}

#[cfg(all(test, unix))]
#[path = "recovery_tests.rs"]
mod tests;
