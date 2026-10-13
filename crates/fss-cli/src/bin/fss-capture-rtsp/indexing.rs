#![forbid(unsafe_code)]
//! Explicit offline catalog completion after original reconnect work has settled.
//! The original windows never change. Preview replays source custody; approval binds the
//! complete inventory and exact next catalog. Publication uses the existing independent
//! pin -> work -> confirmation -> catalog barriers, never a bare metadata write.

use super::*;
use fss_publication::LocalPublicationState;
use fss_reference::rtsp::archive_pins::{CodecJournaledArchiveWriter, JournaledArchiveProgress};
use fss_reference::rtsp::recording_archive::{ArchiveWriteProgress, CodecArchiveNamespace, CodecArchiveSnapshot};
use fss_reference::rtsp::recording_catalog::MAX_CATALOG_WINDOWS;

const INDEX_FORMAT: &str = "fss.rtsp_reconnect_index_cli.v1";
const INDEX_POLICY: &str = "storage-only:all-archives-source-verified:exact-inventory-and-page:require-settled-work:journal-before-catalog:no-camera:no-secret:no-new-recordings:no-cross-epoch-continuity:v1";
const WORK: &str = "ERR-CAPTURE-RTSP-WORK-001";

#[derive(Clone, Debug, PartialEq, Eq)]
struct Quote {
    snapshot: ContentDigest,
    windows: usize,
    indexed: usize,
    pages: usize,
    catalog: Option<ContentDigest>,
    commands: u64,
}

fn inventory<C: ArchiveCodec>(plan: &ReconnectPlan, entries: &mut [Entry<C>], clock: &Clock<'_>) -> Result<Vec<Option<Quote>>> {
    let mut quotes = Vec::new();
    for index in 0..entries.len() {
        locations_unchanged(plan, entries, clock)?;
        let entry = &mut entries[index];
        let attempt = &plan.attempts[index];
        let Some(journal) = &mut entry.journal else {
            quotes.push(None);
            continue;
        };
        let publisher = LocalRootPublisher::open(&entry.root.canonical, attempt.publication_limits()).map_err(|_| STORAGE)?;
        // Indexing cannot authorize recovery, replace a candidate, or abandon prior work.
        journal.require_settled(&publisher, attempt.work_limits(), clock).map_err(|_| STORAGE)?;
        let namespace = CodecArchiveNamespace::<C>::new(attempt.catalog_scope().clone()).map_err(|_| STORAGE)?;
        let snapshot = CodecArchiveSnapshot::<C>::load(&publisher, namespace, attempt.work_limits().archive, clock).map_err(|_| STORAGE)?;
        let tail = snapshot.windows().len().checked_sub(snapshot.indexed_windows()).ok_or(STATE)?;
        // Match the existing native recovered-tail flush, without inventing a new page layout.
        if tail > MAX_CATALOG_WINDOWS || (tail != 0 && snapshot.pages().len() >= attempt.work_limits().archive.max_pages) {
            return Err(WORK);
        }
        // One finish, page start, N verifications, preparation, candidate, acknowledgement,
        // work+confirmation, index staging, publication, and terminal observation: N + 9.
        let commands = if tail == 0 { 0 } else { tail as u64 + 9 };
        if commands > attempt.max_steps { return Err(WORK); }
        let catalog = if tail == 0 {
            None
        } else {
            let mut builder = C::builder(attempt.catalog_scope().clone()).map_err(|_| STORAGE)?;
            for descriptor in &snapshot.windows()[snapshot.indexed_windows()..] {
                clock.now()?;
                let recording = C::load_recording(&publisher, descriptor.slot(), descriptor.root(), &attempt.catalog_scope().recording, clock).map_err(|_| STORAGE)?;
                C::push(&mut builder, descriptor.slot(), &recording).map_err(|_| STORAGE)?;
            }
            let page = C::prepare(builder).map_err(|_| STORAGE)?;
            Some(C::manifest(&page).root())
        };
        quotes.push(Some(Quote {
            snapshot: snapshot.digest().map_err(|_| STORAGE)?,
            windows: snapshot.windows().len(),
            indexed: snapshot.indexed_windows(),
            pages: snapshot.pages().len(),
            catalog,
            commands,
        }));
        entry.publisher = Some(publisher);
    }
    recheck(plan, entries, clock)?;
    Ok(quotes)
}

fn index_digest<C: ArchiveCodec>(plan: &ReconnectPlan, entries: &[Entry<C>], quotes: &[Option<Quote>], timeout: u64) -> Result<ContentDigest> {
    if entries.len() != quotes.len() { return Err(STATE); }
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.rtsp_reconnect_index_plan.v1");
    encoder.text(INDEX_POLICY);
    encoder.digest(digest(plan, entries, timeout)?);
    encoder.u64(quotes.len() as u64);
    for quote in quotes {
        encoder.bool(quote.is_some());
        if let Some(quote) = quote {
            encoder.digest(quote.snapshot);
            encoder.u64(quote.windows as u64);
            encoder.u64(quote.indexed as u64);
            encoder.u64(quote.pages as u64);
            encoder.u64(quote.commands);
            encoder.bool(quote.catalog.is_some());
            if let Some(root) = quote.catalog { encoder.digest(root); }
        }
    }
    Ok(ContentDigest::sha256(&encoder.finish_checked().map_err(|_| STATE)?))
}

fn quote_json(quote: Option<&Quote>) -> String {
    quote.map_or_else(|| "null".into(), |q| object(&[
        ("snapshot", string(&q.snapshot.to_text())),
        ("durable_windows", q.windows.to_string()),
        ("indexed_windows", q.indexed.to_string()),
        ("existing_pages", q.pages.to_string()),
        ("new_pages", usize::from(q.catalog.is_some()).to_string()),
        ("maximum_writer_commands", q.commands.to_string()),
        ("next_catalog_root", q.catalog.map_or_else(|| "null".into(), |r| string(&r.to_text()))),
    ]))
}

fn preview_codec<C: ArchiveCodec>(plan: &ReconnectPlan, timeout: u64) -> Result<String> {
    let clock = Clock { start: Instant::now(), timeout, cancellation: &NeverCancel, authority: None };
    let mut entries = load::<C>(plan, &clock)?;
    let quotes = inventory(plan, &mut entries, &clock)?;
    let approval = index_digest(plan, &entries, &quotes, timeout)?;
    let rows = entries.iter().zip(&quotes).enumerate().map(|(index, (entry, quote))| {
        Ok(object(&[
            ("attempt", (index + 1).to_string()),
            ("root", string(entry.root.canonical.to_str().ok_or(ROOT)?)),
            ("journal", anchor_json(entry.anchor)),
            ("observation", string(if quote.is_some() { "source_verified_inventory" } else { "both_stores_unobserved" })),
            ("index", quote_json(quote.as_ref())),
        ]))
    }).collect::<Result<Vec<_>>>()?;
    let report = object(&[
        ("schema", string(INDEX_FORMAT)),
        ("phase", string("planned")),
        ("policy", string(INDEX_POLICY)),
        ("approval", string(&approval.to_text())),
        ("capture_plan", string(&plan.digest()?.to_text())),
        ("recovery_timeout_ns", timeout.to_string()),
        ("maximum_report_bytes", REPORT_LIMIT.to_string()),
        ("attempts", format!("[{}]", rows.join(","))),
        ("effects", string("source-inspection-only:no-new-journal-or-catalog-publication")),
        ("network_requested", "false".into()),
        ("source_bytes_emitted", "false".into()),
        ("capture_complete", "false".into()),
        ("continuity_across_attempts", "false".into()),
    ]);
    clock.now()?;
    if report.len() > REPORT_LIMIT { return Err(OUTPUT); }
    Ok(report)
}

pub(super) fn preview_index(plan: &ReconnectPlan, timeout: u64) -> Result<String> {
    match plan.attempts.first().ok_or(STATE)?.codec() {
        "avc" => preview_codec::<AvcArchiveCodec>(plan, timeout),
        "hevc" => preview_codec::<HevcArchiveCodec>(plan, timeout),
        _ => Err(STATE),
    }
}

fn pages_json<C: ArchiveCodec>(snapshot: &CodecArchiveSnapshot<C>) -> String {
    let rows = snapshot.pages().iter().map(|page| object(&[
        ("slot", string(page.slot().as_str())),
        ("root", string(&C::manifest(page.catalog()).root().to_text())),
        ("first_ordinal", page.first_ordinal().to_string()),
        ("windows", C::entries(page.catalog()).len().to_string()),
    ])).collect::<Vec<_>>();
    format!("[{}]", rows.join(","))
}

fn execute_codec<C: ArchiveCodec>(plan: &ReconnectPlan, timeout: u64, emit: impl FnMut(&[u8]) -> Result<()>, cancellation: &dyn PublishCancellation) -> Result<()> {
    let mut clock = Clock { start: Instant::now(), timeout, cancellation, authority: None };
    let mut entries = load::<C>(plan, &clock)?;
    // This mode explicitly requests source inspection even for preview. All complete originals
    // and settled pins are verified before accepting any publication approval.
    let quotes = inventory(plan, &mut entries, &clock)?;
    let approval = index_digest(plan, &entries, &quotes, timeout)?;
    if plan.approve != Some(approval) { return Err(APPROVAL); }
    let first = plan.attempts.first().ok_or(STATE)?;
    clock.authority = Some(ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rtsp-reconnect-index".into(),
        operation_id: OperationId::parse("operation:rtsp-reconnect-index").map_err(|_| STATE)?,
        principal: first.principal.clone(),
        capabilities: CAPS.iter().map(|cap| (*cap).to_owned()).collect(),
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:owner-original-rtsp-custody".into(),
        retention_scope: "retention:explicit-original-rtsp-scope".into(),
        anchor_universe: approval,
        generation: first.recording_config().scope.generation,
    }).map_err(|_| AUTHORITY)?);
    let mut reports = Reports { emit, sequence: 0, bytes: 0 };
    reports.row_with_schema(INDEX_FORMAT, "index_started", object(&[
        ("approval", string(&approval.to_text())),
        ("all_observed_archives_source_verified", "true".into()),
        ("publication_started", "false".into()),
        ("network_requested", "false".into()),
    ]))?;
    recheck(plan, &mut entries, &clock)?;
    let mut checked = 0_usize;
    let mut created = 0_usize;
    for index in 0..entries.len() {
        locations_unchanged(plan, &entries, &clock)?;
        let entry = &mut entries[index];
        let attempt = &plan.attempts[index];
        let Some(quote) = &quotes[index] else {
            reports.row_with_schema(INDEX_FORMAT, "attempt_index", object(&[
                ("attempt", (index + 1).to_string()),
                ("observation", string("both_stores_unobserved")),
                ("index_complete", "false".into()),
            ]))?;
            continue;
        };
        let journal = entry.journal.as_mut().ok_or(STATE)?;
        journal.verify(&clock).map_err(|_| STORAGE)?;
        if Some(journal.anchor()) != entry.anchor { return Err(APPROVAL); }
        let publisher = entry.publisher.as_mut().ok_or(STATE)?;
        let namespace = CodecArchiveNamespace::<C>::new(attempt.catalog_scope().clone()).map_err(|_| STORAGE)?;
        let mut writer = CodecJournaledArchiveWriter::<C>::open(publisher, journal, namespace, attempt.work_limits().archive, attempt.work_limits(), attempt.max_steps, clock.now()?, timeout, &clock).map_err(|_| STORAGE)?;
        if writer.snapshot().digest().map_err(|_| STORAGE)? != quote.snapshot {
            let _retained = writer.retire();
            return Err(APPROVAL);
        }
        let result = (|| {
            if let Some(expected) = quote.catalog {
                writer.finish(clock.now()?).map_err(|_| STORAGE)?;
                for _ in 0..quote.commands {
                    clock.now()?;
                    if locate(&attempt.root)? != entry.root || locate(&attempt.pins)? != entry.pins { return Err(ROOT); }
                    match writer.step(clock.now()?, &clock).map_err(|_| STORAGE)? {
                        JournaledArchiveProgress::Archive(ArchiveWriteProgress::CatalogPrepared { root }) => {
                            if root != expected { return Err(STATE); }
                        }
                        JournaledArchiveProgress::WorkConfirmed { checkpoint, pin_receipt, .. } => {
                            reports.row_with_schema(INDEX_FORMAT, "index_work_confirmed", object(&[
                                ("attempt", (index + 1).to_string()),
                                ("work_slot", string(checkpoint.slot().as_str())),
                                ("work_root", string(&checkpoint.root().to_text())),
                                ("journal", anchor_json(Some(pin_receipt.anchor()))),
                            ]))?;
                        }
                        JournaledArchiveProgress::Archive(ArchiveWriteProgress::CatalogPublished { first_ordinal, windows, receipt }) => {
                            if first_ordinal != quote.indexed || windows != quote.windows - quote.indexed || receipt.root != expected || receipt.claims.local != LocalPublicationState::Durable { return Err(STATE); }
                            created += 1;
                        }
                        JournaledArchiveProgress::Archive(ArchiveWriteProgress::Finished { windows, pages, .. }) => {
                            if windows != quote.windows || pages != quote.pages + 1 || writer.snapshot().indexed_windows() != windows { return Err(STATE); }
                            return Ok(());
                        }
                        JournaledArchiveProgress::Archive(ArchiveWriteProgress::WindowDurable { .. } | ArchiveWriteProgress::Exhausted | ArchiveWriteProgress::Ready { .. }) => return Err(STATE),
                        JournaledArchiveProgress::PinPersisted { .. }
                        | JournaledArchiveProgress::Archive(ArchiveWriteProgress::PageStarted { .. } | ArchiveWriteProgress::PageWindowVerified { .. } | ArchiveWriteProgress::CatalogIndexStaged { .. }) => {}
                    }
                }
                return Err(WORK);
            }
            Ok(())
        })();
        // No newly captured media exists here. Original windows remain durable; any prepared
        // page/checkpoint after a cut is retained by the native independent recovery protocol.
        let retained = writer.retire();
        result?;
        let snapshot = retained.writer.archive.snapshot;
        checked += 1;
        entry.anchor = Some(journal.anchor());
        journal.require_settled(publisher, attempt.work_limits(), &clock).map_err(|_| STORAGE)?;
        let scope = attempt.catalog_scope();
        reports.row_with_schema(INDEX_FORMAT, "attempt_index", object(&[
            ("attempt", (index + 1).to_string()),
            ("codec", string(attempt.codec())),
            ("root", string(entry.root.canonical.to_str().ok_or(ROOT)?)),
            ("sensor", string(scope.recording.sensor.as_str())),
            ("stream", string(scope.recording.stream.as_str())),
            ("generation", scope.recording.generation.to_string()),
            ("anchor", string(&scope.recording.anchor.to_text())),
            ("receive_clock", string(&scope.recording.receive_clock.to_text())),
            ("decode_clock", string(&scope.decode_clock.to_text())),
            ("time_scale", scope.time_scale.to_string()),
            ("journal", anchor_json(entry.anchor)),
            ("snapshot", string(&snapshot.digest().map_err(|_| STORAGE)?.to_text())),
            ("durable_windows", snapshot.windows().len().to_string()),
            ("indexed_windows", snapshot.indexed_windows().to_string()),
            ("catalogs", pages_json(&snapshot)),
            ("index_complete", "true".into()),
            ("capture_complete", "false".into()),
        ]))?;
    }
    recheck(plan, &mut entries, &clock)?;
    reports.row_with_schema(INDEX_FORMAT, "index_terminal", object(&[
        ("checked_archives", checked.to_string()),
        ("catalogs_published", created.to_string()),
        ("unobserved_attempts", (entries.len() - checked).to_string()),
        ("operation_complete", "true".into()),
        ("capture_complete", "false".into()),
        ("continuity_across_attempts", "false".into()),
        ("absence_certifiable", "false".into()),
        ("network_requested", "false".into()),
        ("source_bytes_emitted", "false".into()),
    ]))
}

pub(super) fn execute_index(plan: &ReconnectPlan, timeout: u64) -> Result<()> {
    match plan.attempts.first().ok_or(STATE)?.codec() {
        "avc" => execute_codec::<AvcArchiveCodec>(plan, timeout, crate::write_bounded, &NeverCancel),
        "hevc" => execute_codec::<HevcArchiveCodec>(plan, timeout, crate::write_bounded, &NeverCancel),
        _ => Err(STATE),
    }
}

#[cfg(all(test, unix))]
#[path = "indexing_tests.rs"]
mod tests;
