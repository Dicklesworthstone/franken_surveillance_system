#![forbid(unsafe_code)]
//! Fault campaign for the file import (`FileIngestAdapter`, ADP-FILE-001; fss-2h5zq.24).
//!
//! Every row states its expected outcome before it runs. The expectations come from:
//! - `file_adapter.rs` steps 14-16 and fss-2h5zq.23 round 3 ("Commits"): capsule batches
//!   `c0..c<K-1>` first (the first creates the import object at generation 1), then
//!   `publish_and_commit` of slot `fi-<id>`, then the manifest batch (generation 2). Complete
//!   means the manifest batch exists and the slot is ledgered; capsule batches without it are an
//!   incomplete import that doctor reports and a re-import completes with no duplicate delta.
//! - fss-publication `local/mod.rs` ("A crash or cancellation at any cut point before step 5
//!   leaves nothing visible"; reopen admits a renamed root and reports temps as orphaned) and
//!   `ledger.rs` (the crash table: after the rename or after `Durable`, reopen shows
//!   `PendingLedger`; an indeterminate append is `Ledgered` or `PendingLedger` after reconcile).
//! - fss-ledger `journal.rs` append order: body write, body sync, commit-trailer write, commit
//!   sync. A failure after a body phase leaves no trailer (reconcile: `NotCommitted`); a
//!   failure after a commit phase leaves the trailer (reconcile: `Committed`).
//! - fss-2h5zq.24 round 3: tamper gives `CustodyUnavailable{SpoolError::Corrupt}` in-session and
//!   a broken root after reopen; bad span metadata gives a custody mismatch, never a panic.
//!
//! The fixture `h264/clean.264` has 5 access units. With `max_batch_deltas = 2` the plan holds
//! 6 entries (init + 5 capsules), i.e. capsule batches c0, c1, c2 (K = 3), then the manifest.
//!
//! No-Claim: in-process injection (cancellation, `inject_crash_at`, journal phase failures,
//! dropping the deployment) is not process death or power loss.

mod file_import_fault_support;

use std::fs;
use std::path::Path;

use file_import_fault_support::{
    Outcome, RECEIVE_NS, TestResult, assert_clean_after_reopen, assert_complete_once,
    assert_spans_match, classify, cx, doctor_incomplete, expected_reimport, fixture, fresh_dir,
    hex, identity_hex, open, request, standard, view,
};
use fss_core::{
    CanonicalEncoder, ContentDigest, EvidenceDelta, ObjectId, Plane, SensorId, StreamId,
    TimestampNs,
};
use fss_ledger::DurableAppendReconciliation;
use fss_object::SpoolError;
use fss_publication::{LedgerCutPoint, PublishCutPoint, SlotName};
use fss_reference::ingest::file_adapter::{
    STAGE_CAPACITY, STAGE_COMMIT_CAPSULES, STAGE_COMMIT_MANIFEST, STAGE_PUBLISH_ROOT, STAGE_READ,
    STAGE_SPLIT, STAGE_STAGE,
};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::{
    AppendPhase, DeploymentLimits, FileIngestAdapter, FileIngestError, FileIngestLimits,
    FileIngestOutcome, FileIngestRequest, IncompleteTailPolicy, RecoveryAction,
    ReferenceDeployment, fetch_segment_bytes,
};

const H264: &str = "h264/clean.264";
const CHUNK: u64 = 512;
const KNOB: usize = 2;
const K: usize = 3;

#[derive(Clone, Copy, Debug)]
enum AppendTarget {
    Capsule(usize),
    LocalRoot,
    Manifest,
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    /// Cancellation requested before the call (the stat checkpoint).
    CancelBeforeStart,
    /// Cancellation at the `occurrence`-th reach of a stage.
    CancelAt(&'static str, usize),
    /// `LocalRootPublisher::inject_crash_at` for the import's publication.
    PublishCrash(PublishCutPoint),
    /// `ReferenceDeployment::inject_ledger_crash_at(AfterRootDurable)`.
    LedgerCrash,
    /// `fail_ledger_append_after_phase` on the append of `target`, reconciled in-process with
    /// `reconcile_ledger_append(Truncate)`.
    AppendIndeterminate(AppendTarget, AppendPhase),
}

/// Pre-stated expectation of one row.
struct Row {
    id: String,
    fault: Fault,
    outcome: Outcome,
    /// Expected (root visible, root ledgered) after reopen.
    root: (bool, bool),
}

fn row(id: impl Into<String>, fault: Fault, outcome: Outcome, root: (bool, bool)) -> Row {
    Row {
        id: id.into(),
        fault,
        outcome,
        root,
    }
}

const NONE: (bool, bool) = (false, false);
const PENDING: (bool, bool) = (true, false);
const LEDGERED: (bool, bool) = (true, true);

/// The fault table. Expected outcomes are derived from the contracts cited in the module docs:
/// every fault before the first capsule batch is `Untouched`; every fault after capsule batch
/// `j` and before the manifest batch commit is `Incomplete(j)`; an indeterminate manifest
/// append whose trailer reached the disk is `Complete`.
fn table() -> Vec<Row> {
    use AppendPhase::{BodySync, BodyWrite, CommitSync, CommitWrite};
    use AppendTarget::{Capsule, LocalRoot, Manifest};
    use Fault::{AppendIndeterminate, CancelAt, CancelBeforeStart, LedgerCrash, PublishCrash};
    use Outcome::{Complete, Incomplete, Untouched};
    let mut rows = vec![
        // Cancellation: every stage before c0 leaves nothing committed (file_adapter.rs
        // checkpoints before any stage/append); `STAGE_STAGE` fires before the first stage.
        row(
            "f01-cancel-before-start",
            CancelBeforeStart,
            Untouched,
            NONE,
        ),
        row("f02-cancel-read", CancelAt(STAGE_READ, 1), Untouched, NONE),
        row(
            "f03-cancel-split",
            CancelAt(STAGE_SPLIT, 1),
            Untouched,
            NONE,
        ),
        row(
            "f04-cancel-capacity",
            CancelAt(STAGE_CAPACITY, 1),
            Untouched,
            NONE,
        ),
        row(
            "f05-cancel-stage",
            CancelAt(STAGE_STAGE, 1),
            Untouched,
            NONE,
        ),
        // Polled before every capsule batch: occurrence k+1 cancels after k batches.
        row(
            "f06-cancel-before-c0",
            CancelAt(STAGE_COMMIT_CAPSULES, 1),
            Untouched,
            NONE,
        ),
        row(
            "f07-cancel-after-c0",
            CancelAt(STAGE_COMMIT_CAPSULES, 2),
            Incomplete(1),
            NONE,
        ),
        row(
            "f08-cancel-after-c1",
            CancelAt(STAGE_COMMIT_CAPSULES, 3),
            Incomplete(2),
            NONE,
        ),
        row(
            "f09-cancel-publish",
            CancelAt(STAGE_PUBLISH_ROOT, 1),
            Incomplete(K),
            NONE,
        ),
        // Pre-rename publication cut points: cancellation leaves nothing visible and removes the
        // temporary record (publish_and_commit docs).
        row(
            "f10-cancel-children-verified",
            CancelAt("after_children_verified", 1),
            Incomplete(K),
            NONE,
        ),
        row(
            "f11-cancel-manifest-body",
            CancelAt("after_manifest_body", 1),
            Incomplete(K),
            NONE,
        ),
        row(
            "f12-cancel-root-temp",
            CancelAt("after_root_temp_write", 1),
            Incomplete(K),
            NONE,
        ),
        row(
            "f13-cancel-commit-manifest",
            CancelAt(STAGE_COMMIT_MANIFEST, 1),
            Incomplete(K),
            LEDGERED,
        ),
        // Crashes at every PublishCutPoint (all after c0..c2 are committed).
        row(
            "f14-crash-children-verified",
            PublishCrash(PublishCutPoint::AfterChildrenVerified),
            Incomplete(K),
            NONE,
        ),
        row(
            "f15-crash-manifest-body",
            PublishCrash(PublishCutPoint::AfterManifestBody),
            Incomplete(K),
            NONE,
        ),
        row(
            "f16-crash-root-temp",
            PublishCrash(PublishCutPoint::AfterRootTempWrite),
            Incomplete(K),
            NONE,
        ),
        row(
            "f17-crash-root-rename",
            PublishCrash(PublishCutPoint::AfterRootRename),
            Incomplete(K),
            PENDING,
        ),
        row(
            "f18-crash-root-durable",
            LedgerCrash,
            Incomplete(K),
            PENDING,
        ),
    ];
    // Indeterminate append on every batch, every phase.
    let mut n = 19;
    for (target, body, commit, body_root, commit_root) in [
        (Capsule(0), Untouched, Incomplete(1), NONE, NONE),
        (Capsule(1), Incomplete(1), Incomplete(2), NONE, NONE),
        (Capsule(2), Incomplete(2), Incomplete(K), NONE, NONE),
        (LocalRoot, Incomplete(K), Incomplete(K), PENDING, LEDGERED),
        (Manifest, Incomplete(K), Complete, LEDGERED, LEDGERED),
    ] {
        for phase in [BodyWrite, BodySync, CommitWrite, CommitSync] {
            let committed = matches!(phase, CommitWrite | CommitSync);
            let (outcome, root) = if committed {
                (commit, commit_root)
            } else {
                (body, body_root)
            };
            let id = format!("f{n:02}-append-{target:?}-{phase:?}")
                .to_lowercase()
                .replace(['(', ')'], "");
            rows.push(row(id, AppendIndeterminate(target, phase), outcome, root));
            n += 1;
        }
    }
    rows
}

/// Stage and occurrence at which a first attempt stops right before the append of `target`.
fn stop_before(target: AppendTarget) -> Option<(&'static str, usize)> {
    match target {
        AppendTarget::Capsule(0) => None,
        AppendTarget::Capsule(k) => Some((STAGE_COMMIT_CAPSULES, k + 1)),
        AppendTarget::LocalRoot => Some((STAGE_PUBLISH_ROOT, 1)),
        AppendTarget::Manifest => Some((STAGE_COMMIT_MANIFEST, 1)),
    }
}

fn run_row(row: &Row) -> TestResult {
    let id = row.id.as_str();
    let dir = fresh_dir(id)?;
    let source = fixture(H264)?;
    let bytes = fs::read(&source)?;
    let req = request(&source, CHUNK, KNOB)?;
    let hex = identity_hex(&req)?.ok_or("fixture must have an identity")?;

    // Phase 1: the faulted attempt.
    match row.fault {
        Fault::CancelBeforeStart => {
            let mut dep = open(&dir, standard())?;
            let cx1 = cx(id)?;
            cx1.request_cancellation();
            let result = FileIngestAdapter::ingest(req.clone(), &cx1, &mut dep);
            expect_cancelled(id, &result, &cx1)?;
        }
        Fault::CancelAt(stage, occurrence) => {
            let mut dep = open(&dir, standard())?;
            let cx1 = cx(id)?;
            cx1.set_cancel_at_checkpoint_occurrence(stage, occurrence);
            let result = FileIngestAdapter::ingest(req.clone(), &cx1, &mut dep);
            expect_cancelled(id, &result, &cx1)?;
        }
        Fault::PublishCrash(point) => {
            let mut dep = open(&dir, standard())?;
            dep.publisher_mut().inject_crash_at(point);
            let result = FileIngestAdapter::ingest(req.clone(), &cx(id)?, &mut dep);
            expect_error_containing(id, &result, "InjectedCrash")?;
        }
        Fault::LedgerCrash => {
            let mut dep = open(&dir, standard())?;
            dep.inject_ledger_crash_at(LedgerCutPoint::AfterRootDurable);
            let result = FileIngestAdapter::ingest(req.clone(), &cx(id)?, &mut dep);
            expect_error_containing(id, &result, "InjectedCrash")?;
        }
        Fault::AppendIndeterminate(target, phase) => {
            if let Some((stage, occurrence)) = stop_before(target) {
                let mut dep = open(&dir, standard())?;
                let cx0 = cx(id)?;
                cx0.set_cancel_at_checkpoint_occurrence(stage, occurrence);
                let result = FileIngestAdapter::ingest(req.clone(), &cx0, &mut dep);
                expect_cancelled(id, &result, &cx0)?;
            }
            let mut dep = open(&dir, standard())?;
            let batches_before = dep.ledger().batches().len();
            dep.fail_ledger_append_after_phase(phase);
            let result = FileIngestAdapter::ingest(req.clone(), &cx(id)?, &mut dep);
            expect_error_containing(id, &result, "Indeterminate")?;
            let reconciled = dep
                .ledgered_publisher()
                .reconcile_ledger_append(IncompleteTailPolicy::Truncate)?;
            let committed = matches!(phase, AppendPhase::CommitWrite | AppendPhase::CommitSync);
            match (committed, &reconciled) {
                (true, DurableAppendReconciliation::Committed { .. })
                | (false, DurableAppendReconciliation::NotCommitted { .. }) => {}
                _ => {
                    return Err(format!("{}: unexpected reconciliation {reconciled:?}", id).into());
                }
            }
            let expected_after = batches_before + usize::from(committed);
            if dep.ledger().batches().len() != expected_after {
                return Err(format!("{}: reconcile left the wrong batch count", id).into());
            }
        }
    }

    // Phase 2: reopen and classify against the pre-stated outcome.
    let outcome = {
        let dep = open(&dir, standard())?;
        let outcome = classify(&dep, &hex, &cx(id)?)?;
        let v = view(&dep, &hex);
        if outcome != row.outcome || (v.root_visible, v.root_ledgered) != row.root {
            return Err(format!(
                "{}: expected {:?} root {:?}, observed {outcome:?} {v:?}",
                id, row.outcome, row.root
            )
            .into());
        }
        if matches!(
            row.fault,
            Fault::PublishCrash(PublishCutPoint::AfterRootTempWrite)
        ) {
            // The crashed temp record is reported, never deleted implicitly.
            if dep.recovery_report().orphaned_temps.is_empty() {
                return Err(format!("{}: orphaned root temp not reported", id).into());
            }
        }
        outcome
    };
    let listed = doctor_incomplete(&dir)?;
    let expected_listed = match outcome {
        Outcome::Incomplete(_) => vec![hex.clone()],
        Outcome::Untouched | Outcome::Complete => Vec::new(),
    };
    if listed != expected_listed {
        return Err(format!("{}: doctor lists {listed:?}", id).into());
    }

    // Phase 3: re-import completes exactly once; a second re-import appends nothing.
    let mut dep = open(&dir, standard())?;
    let cx3 = cx(id)?;
    let receipt = FileIngestAdapter::ingest(req.clone(), &cx3, &mut dep)?;
    if receipt.outcome != expected_reimport(outcome) {
        return Err(format!(
            "{}: re-import reported {:?}, expected {:?}",
            id,
            receipt.outcome,
            expected_reimport(outcome)
        )
        .into());
    }
    assert_complete_once(&dep, &receipt, &bytes, &cx3)?;
    if receipt.batch_ids.len() != K + 1 {
        return Err(format!("{}: {} planned batches", id, receipt.batch_ids.len()).into());
    }
    let batches = dep.ledger().batches().len();
    let again = FileIngestAdapter::ingest(req, &cx3, &mut dep)?;
    if again.outcome != FileIngestOutcome::IdempotentExisting
        || dep.ledger().batches().len() != batches
        || again.import_root != receipt.import_root
    {
        return Err(format!("{}: second re-import was not idempotent", id).into());
    }
    drop(dep);
    assert_clean_after_reopen(&dir, standard())?;
    eprintln!(
        "CAPLOG fault={} expected={:?} observed={outcome:?} reimport={}",
        id,
        row.outcome,
        receipt.outcome.as_str()
    );
    Ok(())
}

fn expect_cancelled(
    id: &str,
    result: &Result<fss_reference::FileIngestReceipt, FileIngestError>,
    cx: &fss_reference::ReplayCx,
) -> TestResult {
    match result {
        Err(error) if format!("{error:?}").contains("Cancel") => {}
        other => return Err(format!("{id}: expected cancellation, got {other:?}").into()),
    }
    if !cx.is_drain_completed() {
        return Err(format!("{id}: cancellation did not drain and finalize").into());
    }
    Ok(())
}

fn expect_error_containing(
    id: &str,
    result: &Result<fss_reference::FileIngestReceipt, FileIngestError>,
    needle: &str,
) -> TestResult {
    match result {
        Err(error) if format!("{error:?}").contains(needle) => Ok(()),
        other => Err(format!("{id}: expected an error naming {needle}, got {other:?}").into()),
    }
}

#[test]
fn fault_table_rows_meet_their_pre_stated_outcomes() -> TestResult {
    let rows = table();
    assert_eq!(
        rows.len(),
        38,
        "18 fault rows plus 5 targets x 4 append phases"
    );
    let mut failures = Vec::new();
    for row in &rows {
        if let Err(error) = run_row(row) {
            failures.push(format!("{}: {error}", row.id));
        }
    }
    assert!(
        failures.is_empty(),
        "fault rows failed:\n{}",
        failures.join("\n")
    );
    Ok(())
}

/// f39: an indeterminate c0 append that is NOT reconciled in-process. Expected (journal.rs: the
/// body is on disk without a trailer; reference_deployment open rejects incomplete tails): the
/// reopen is refused with `IncompleteJournalTail`, `open_for_recovery` truncates the tail, and
/// the import is then `Untouched`; a re-import completes it as `New`.
#[test]
fn f39_unreconciled_indeterminate_append_requires_tail_recovery() -> TestResult {
    let dir = fresh_dir("f39-unreconciled")?;
    let source = fixture(H264)?;
    let bytes = fs::read(&source)?;
    let req = request(&source, CHUNK, KNOB)?;
    let hex = identity_hex(&req)?.ok_or("identity")?;
    {
        let mut dep = open(&dir, standard())?;
        dep.fail_ledger_append_after_phase(AppendPhase::BodyWrite);
        let result = FileIngestAdapter::ingest(req.clone(), &cx("f39")?, &mut dep);
        expect_error_containing("f39", &result, "Indeterminate")?;
    }
    match open(&dir, standard()) {
        Err(error) if format!("{error:?}").contains("IncompleteJournalTail") => {}
        Err(other) => return Err(format!("f39: unexpected reopen error {other:?}").into()),
        Ok(_) => return Err("f39: reopen admitted an incomplete journal tail".into()),
    }
    ReferenceDeployment::open_for_recovery(
        &dir,
        RecoveryAction::TruncateIncompleteLedgerTail,
        &cx("f39-recover")?,
    )?;
    let mut dep = open(&dir, standard())?;
    let cx2 = cx("f39-2")?;
    assert_eq!(classify(&dep, &hex, &cx2)?, Outcome::Untouched);
    let receipt = FileIngestAdapter::ingest(req, &cx2, &mut dep)?;
    assert_eq!(receipt.outcome, FileIngestOutcome::New);
    assert_complete_once(&dep, &receipt, &bytes, &cx2)?;
    drop(dep);
    assert_clean_after_reopen(&dir, standard())
}

// ---------------------------------------------------------------------------------------------
// Tamper and corruption
// ---------------------------------------------------------------------------------------------

fn flip_last_byte(path: &Path) -> TestResult {
    let mut stored = fs::read(path)?;
    let last = stored.last_mut().ok_or("stored object is empty")?;
    *last ^= 0x5a;
    let mut permissions = fs::metadata(path)?.permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions)?;
    fs::write(path, stored)?;
    Ok(())
}

/// t01-t02: a byte flipped in stored chunk 1 (of a 512-byte-chunk import).
///
/// Expected (fss-2h5zq.24 round 3; spool/mod.rs "every read rehashes"): in-session, every segment
/// that touches chunk 1 (including one straddling a chunk boundary) fails with
/// `CustodyUnavailable { chunk_index: 1, source: SpoolError::Corrupt }`, and every other segment
/// still reassembles exactly. After reopen the spool indexes the chunk as corrupt, the import
/// root is a broken root (not admitted), `RetainedFileImport::open` refuses, and reconcile is not
/// clean. A re-import never reports success over corrupt custody: it fails typed
/// (`Spool(Corrupt)`: restaging never overwrites corrupt bytes) and appends no batch.
#[test]
fn t01_tampered_chunk_is_custody_unavailable_then_broken_root() -> TestResult {
    let dir = fresh_dir("t01-tamper")?;
    let source = fixture(H264)?;
    let bytes = fs::read(&source)?;
    let req = request(&source, CHUNK, KNOB)?;
    let cx1 = cx("t01")?;
    let mut dep = open(&dir, standard())?;
    let receipt = FileIngestAdapter::ingest(req.clone(), &cx1, &mut dep)?;
    let manifest = receipt.manifest.clone();
    let chunk = *manifest
        .ordered_chunks
        .get(1)
        .ok_or("need at least two chunks")?;
    flip_last_byte(&dep.publisher().spool().object_path(chunk))?;

    let (chunk_start, chunk_end) = (CHUNK, 2 * CHUNK);
    let mut affected = 0;
    let mut straddling = false;
    for (index, span) in manifest.segment_spans.iter().enumerate() {
        let touches = span.offset < chunk_end && span.offset + span.len > chunk_start;
        let result = fetch_segment_bytes(&manifest, &dep, index);
        if touches {
            affected += 1;
            straddling |= span.offset < chunk_start || span.offset + span.len > chunk_end;
            match result {
                Err(FileIngestError::CustodyUnavailable {
                    segment_index,
                    chunk_index: 1,
                    chunk: refused,
                    source,
                }) if segment_index == index
                    && refused == chunk
                    && matches!(*source, SpoolError::Corrupt { .. }) => {}
                other => {
                    return Err(format!(
                        "segment {index}: expected CustodyUnavailable, got {other:?}"
                    )
                    .into());
                }
            }
        } else {
            let start = usize::try_from(span.offset)?;
            let end = start + usize::try_from(span.len)?;
            if result?.as_slice() != &bytes[start..end] {
                return Err(format!("untouched segment {index} changed").into());
            }
        }
    }
    assert!(affected > 0, "chunk 1 must back at least one segment");
    assert!(
        straddling,
        "a segment touching chunk 1 must straddle a chunk boundary"
    );
    let batches = dep.ledger().batches().len();
    drop(dep);

    let mut dep = open(&dir, standard())?;
    let slot = SlotName::parse(&format!("fi-{}", hex(receipt.import_identity)))?;
    assert!(
        dep.publisher().root(&slot).is_none(),
        "tampered root must not be admitted"
    );
    assert!(
        !dep.recovery_report().broken_roots.is_empty(),
        "tampered root must be reported broken"
    );
    assert!(
        dep.recovery_report()
            .spool
            .corrupt
            .iter()
            .any(|c| c.digest == chunk),
        "the tampered chunk must be indexed corrupt"
    );
    let cx2 = cx("t01-2")?;
    assert!(
        RetainedFileImport::open(
            &dep,
            receipt.import_identity,
            RetainedReadLimits::default(),
            &cx2
        )
        .is_err(),
        "a broken import is never retained evidence"
    );
    assert!(
        !dep.reconcile()?.is_clean(),
        "reconcile must surface the broken root"
    );
    match FileIngestAdapter::ingest(req, &cx2, &mut dep) {
        Err(error) if format!("{error:?}").contains("Corrupt") => {}
        other => return Err(format!("re-import over corrupt custody: {other:?}").into()),
    }
    assert_eq!(
        dep.ledger().batches().len(),
        batches,
        "no batch over corrupt custody"
    );
    Ok(())
}

/// t03: corrupted span metadata in a manifest (an untrusted read-back). Expected (fss-2h5zq.24
/// round 3, "CustodyMismatch is tested by corrupting span metadata"): a wrong digest or a shifted
/// span is `SegmentDigestMismatch`; an empty, out-of-file, overflowing or chunkless span, or a
/// zero chunk size, is `CorruptSegment`. Never a panic and never bytes.
#[test]
fn t03_bad_span_metadata_is_a_typed_custody_mismatch() -> TestResult {
    let dir = fresh_dir("t03-spans")?;
    let source = fixture(H264)?;
    let cx1 = cx("t03")?;
    let mut dep = open(&dir, standard())?;
    let receipt = FileIngestAdapter::ingest(request(&source, CHUNK, KNOB)?, &cx1, &mut dep)?;
    let base = receipt.manifest.clone();
    let input = base.input_bytes;

    let mismatch = |label: &str, mutate: &dyn Fn(&mut fss_reference::FileImportManifest)| {
        let mut manifest = base.clone();
        mutate(&mut manifest);
        match fetch_segment_bytes(&manifest, &dep, 0) {
            Err(FileIngestError::SegmentDigestMismatch {
                segment_index: 0, ..
            }) => Ok(()),
            other => Err(format!(
                "{label}: expected SegmentDigestMismatch, got {other:?}"
            )),
        }
    };
    let corrupt = |label: &str, mutate: &dyn Fn(&mut fss_reference::FileImportManifest)| {
        let mut manifest = base.clone();
        mutate(&mut manifest);
        match fetch_segment_bytes(&manifest, &dep, 0) {
            Err(FileIngestError::CorruptSegment { .. }) => Ok(()),
            other => Err(format!("{label}: expected CorruptSegment, got {other:?}")),
        }
    };
    let mut failures = Vec::new();
    let checks: Vec<Result<(), String>> = vec![
        mismatch("wrong digest", &|m| {
            m.segment_spans[0].segment_sha256 = ContentDigest::sha256(b"not the segment");
        }),
        mismatch("shifted span", &|m| m.segment_spans[0].offset += 1),
        corrupt("empty span", &|m| m.segment_spans[0].len = 0),
        corrupt("span past the file", &|m| m.segment_spans[0].offset = input),
        corrupt("overflowing span", &|m| {
            m.segment_spans[0].offset = u64::MAX
        }),
        corrupt("huge length", &|m| m.segment_spans[0].len = u64::MAX),
        corrupt("zero chunk size", &|m| m.chunk_bytes = 0),
        corrupt("missing chunks", &|m| m.ordered_chunks.clear()),
    ];
    for check in checks {
        if let Err(error) = check {
            failures.push(error);
        }
    }
    // A wrong chunk geometry reassembles the wrong bytes or the wrong length; either is typed.
    let mut wrong_geometry = base.clone();
    wrong_geometry.chunk_bytes = CHUNK * 2;
    for (index, span) in base.segment_spans.iter().enumerate() {
        match fetch_segment_bytes(&wrong_geometry, &dep, index) {
            Err(FileIngestError::SegmentDigestMismatch { .. })
            | Err(FileIngestError::CorruptSegment { .. }) => {}
            Ok(_) if span.offset + span.len <= CHUNK => {
                // Wholly inside chunk 0, which both geometries place identically.
            }
            other => failures.push(format!("wrong geometry segment {index}: {other:?}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

/// t04: a file made of two identical chunks (one JPEG twice, chunk size = its length).
/// Expected (fss-2h5zq.23 round 3 "the custody object is an ObjectManifest whose children are
/// the DEDUPLICATED chunk digests"): two ordered chunks with equal digests, one unique chunk, two
/// capsules, exact reassembly, idempotent re-import, clean reopen; tampering the one shared chunk
/// makes BOTH segments `CustodyUnavailable`.
#[test]
fn t04_repeated_chunks_dedup_and_share_custody() -> TestResult {
    let dir = fresh_dir("t04-repeat")?;
    let frame = fs::read(fixture("jpeg/gray_16x16_flat.jpg")?)?;
    let doubled = [frame.as_slice(), frame.as_slice()].concat();
    let input = dir.join("doubled.mjpeg");
    fs::write(&input, &doubled)?;
    let deployment_dir = dir.join("deployment");
    let req = request(&input, frame.len() as u64, KNOB)?;
    let cx1 = cx("t04")?;
    let mut dep = open(&deployment_dir, standard())?;
    let receipt = FileIngestAdapter::ingest(req.clone(), &cx1, &mut dep)?;
    assert_eq!(receipt.chunk_count, 2);
    assert_eq!(receipt.unique_chunk_count, 1);
    assert_eq!(
        receipt.manifest.ordered_chunks[0],
        receipt.manifest.ordered_chunks[1]
    );
    assert_eq!(receipt.capsule_count, 2);
    assert_ne!(
        receipt.capsules[0].capsule_id,
        receipt.capsules[1].capsule_id
    );
    assert_complete_once(&dep, &receipt, &doubled, &cx1)?;
    let again = FileIngestAdapter::ingest(req, &cx1, &mut dep)?;
    assert_eq!(again.outcome, FileIngestOutcome::IdempotentExisting);
    drop(dep);
    assert_clean_after_reopen(&deployment_dir, standard())?;

    let dep = open(&deployment_dir, standard())?;
    flip_last_byte(
        &dep.publisher()
            .spool()
            .object_path(receipt.manifest.ordered_chunks[0]),
    )?;
    for index in 0..2 {
        match fetch_segment_bytes(&receipt.manifest, &dep, index) {
            Err(FileIngestError::CustodyUnavailable { source, .. })
                if matches!(*source, SpoolError::Corrupt { .. }) => {}
            other => return Err(format!("shared chunk segment {index}: {other:?}").into()),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Multi-batch partitioning
// ---------------------------------------------------------------------------------------------

/// m01: knob 2 on the 5-AU fixture plans c0 = {init, cap0}, c1 = {cap1, cap2}, c2 = {cap3, cap4}
/// and the manifest batch (fss-2h5zq.23 round 3 "Deterministic partition").
#[test]
fn m01_knob_partitions_capsule_batches_in_order() -> TestResult {
    let dir = fresh_dir("m01-partition")?;
    let source = fixture(H264)?;
    let bytes = fs::read(&source)?;
    let cx1 = cx("m01")?;
    let mut dep = open(&dir, standard())?;
    let receipt = FileIngestAdapter::ingest(request(&source, CHUNK, KNOB)?, &cx1, &mut dep)?;
    assert_eq!(receipt.outcome, FileIngestOutcome::New);
    assert_eq!(receipt.capsule_count, 5);
    assert_complete_once(&dep, &receipt, &bytes, &cx1)?;
    let prefix = format!("batch:file-import:{}:", hex(receipt.import_identity));
    let sizes: Vec<(String, usize, bool)> = dep
        .ledger()
        .batches()
        .iter()
        .filter_map(|b| {
            b.batch_id.as_str().strip_prefix(&prefix).map(|part| {
                (
                    part.to_owned(),
                    // The acquisition history (fss-2h5zq.25) rides in the manifest batch only;
                    // the partition counts the import's own deltas.
                    b.deltas
                        .iter()
                        .filter(|d| d.family != "acquisition_transition")
                        .count(),
                    b.deltas
                        .iter()
                        .any(|d| d.family == "file_import" && d.new_generation == 1),
                )
            })
        })
        .collect();
    assert_eq!(
        sizes,
        vec![
            ("c0".to_owned(), 2, true),
            ("c1".to_owned(), 2, false),
            ("c2".to_owned(), 2, false),
            ("manifest".to_owned(), 2, false),
        ]
    );
    for batch in dep.ledger().batches() {
        if batch
            .deltas
            .iter()
            .any(|d| d.family == "acquisition_transition")
        {
            assert_eq!(batch.batch_id.as_str(), format!("{prefix}manifest"));
        }
    }
    Ok(())
}

/// m02: MJPEG with knob 1 plans c0 = {init}, c1..c3 = one capsule each. Every retained capsule
/// resolves through the `c<k>` lookup of `recorded_decode` (checked by `assert_complete_once`).
#[test]
fn m02_single_entry_batches_resolve_through_retained_reads() -> TestResult {
    let dir = fresh_dir("m02-knob1")?;
    let source = fixture("mjpeg/mjpeg_clean_3frames.mjpeg")?;
    let bytes = fs::read(&source)?;
    let cx1 = cx("m02")?;
    let mut dep = open(&dir, standard())?;
    let receipt = FileIngestAdapter::ingest(request(&source, CHUNK, 1)?, &cx1, &mut dep)?;
    assert_eq!(receipt.capsule_count, 3);
    assert_eq!(receipt.batch_ids.len(), 5, "c0..c3 and the manifest batch");
    assert_complete_once(&dep, &receipt, &bytes, &cx1)
}

/// m03: the default knob keeps existing small imports byte-stable: the limits digest equals the
/// pre-knob encoding, so the import identity (and every id derived from it) is unchanged, and the
/// plan is the single `c0` batch plus the manifest batch.
#[test]
fn m03_default_knob_keeps_identity_and_single_batch() -> TestResult {
    let limits = FileIngestLimits::standard();
    let mut legacy = CanonicalEncoder::new();
    legacy.text("fss.canonical.v1");
    legacy.text("fss.file_ingest.limits.v1");
    legacy.u64(limits.max_file_bytes);
    legacy.u64(limits.chunk_bytes);
    legacy.u64(limits.max_segments as u64);
    legacy.u64(limits.annexb_limits.max_input_bytes as u64);
    legacy.u64(limits.annexb_limits.max_nal_bytes as u64);
    legacy.u64(limits.annexb_limits.max_nals as u64);
    legacy.u64(limits.annexb_limits.max_aus as u64);
    legacy.u64(limits.mjpeg_limits.max_input_bytes as u64);
    legacy.u64(limits.mjpeg_limits.max_frames as u64);
    legacy.u64(limits.mjpeg_limits.max_frame_bytes as u64);
    assert_eq!(
        limits.canonical_digest(),
        ContentDigest::sha256(&legacy.finish()),
        "default limits digest must equal the pre-knob encoding"
    );
    let changed = FileIngestLimits {
        max_batch_deltas: 2,
        ..FileIngestLimits::standard()
    };
    assert_ne!(changed.canonical_digest(), limits.canonical_digest());

    let dir = fresh_dir("m03-default")?;
    let source = fixture(H264)?;
    let bytes = fs::read(&source)?;
    let cx1 = cx("m03")?;
    let mut dep = open(&dir, standard())?;
    let req = FileIngestRequest::new(
        source,
        SensorId::parse("sensor:fault-cam")?,
        StreamId::parse("stream:fault-main")?,
    )
    .with_receive_time(TimestampNs(RECEIVE_NS));
    let receipt = FileIngestAdapter::ingest(req, &cx1, &mut dep)?;
    assert_eq!(
        receipt.batch_ids.len(),
        2,
        "small import: c0 and manifest only"
    );
    assert_complete_once(&dep, &receipt, &bytes, &cx1)
}

/// m04: re-importing the same file with a different batch knob is a different identity (the knob
/// is in the limits digest), never a `BatchIdConflict`; both imports complete independently.
#[test]
fn m04_different_knob_is_a_new_identity() -> TestResult {
    let dir = fresh_dir("m04-knobs")?;
    let source = fixture(H264)?;
    let bytes = fs::read(&source)?;
    let cx1 = cx("m04")?;
    let mut dep = open(&dir, standard())?;
    let first = FileIngestAdapter::ingest(request(&source, CHUNK, 2)?, &cx1, &mut dep)?;
    let second = FileIngestAdapter::ingest(request(&source, CHUNK, 3)?, &cx1, &mut dep)?;
    assert_ne!(first.import_identity, second.import_identity);
    assert_eq!(second.outcome, FileIngestOutcome::New);
    assert_eq!(first.batch_ids.len(), 4);
    assert_eq!(
        second.batch_ids.len(),
        3,
        "knob 3: c0 {{init, 2}}, c1 {{3}}, manifest"
    );
    assert_complete_once(&dep, &first, &bytes, &cx1)?;
    assert_complete_once(&dep, &second, &bytes, &cx1)?;
    drop(dep);
    assert_clean_after_reopen(&dir, standard())
}

/// m05: a deployment journal record bound below the single-batch size splits the capsule phase
/// further (fss-2h5zq.23 round 3 "Split a batch at the first of ... encode_batch(..).len()"), and
/// every committed batch fits the bound. The input is one JPEG repeated 24 times, so the single
/// c0 (init + 24 capsules) is the largest record of the probe import.
#[test]
fn m05_record_bound_splits_batches() -> TestResult {
    let frame = fs::read(fixture("jpeg/gray_16x16_flat.jpg")?)?;
    let bytes = frame.repeat(24);
    let source_dir = fresh_dir("m05-source")?;
    let source = source_dir.join("frames24.mjpeg");
    fs::write(&source, &bytes)?;
    // Probe: record sizes of one default-knob import.
    let probe_dir = fresh_dir("m05-probe")?;
    let cx0 = cx("m05-probe")?;
    let mut probe = open(&probe_dir, standard())?;
    let probe_receipt =
        FileIngestAdapter::ingest(request(&source, CHUNK, 16_384)?, &cx0, &mut probe)?;
    assert_eq!(probe_receipt.batch_ids.len(), 2);
    let lens: Vec<(String, usize)> = probe
        .ledger()
        .batches()
        .iter()
        .map(|b| {
            Ok((
                b.batch_id.as_str().to_owned(),
                fss_ledger::encode_batch(b)?.len(),
            ))
        })
        .collect::<Result<_, fss_ledger::BatchCodecError>>()?;
    let c0_len = lens
        .iter()
        .find(|(id, _)| id.ends_with(":c0"))
        .map(|(_, len)| *len)
        .ok_or("probe c0")?;
    let other_max = lens
        .iter()
        .filter(|(id, _)| !id.ends_with(":c0"))
        .map(|(_, len)| *len)
        .max()
        .ok_or("probe batches")?;
    assert!(other_max < c0_len, "precondition: c0 is the largest record");
    let bound = u32::try_from(c0_len - 1)?.max(u32::try_from(other_max)?);

    let dir = fresh_dir("m05-bounded")?;
    let limits = DeploymentLimits {
        journal_record_max_bytes: bound,
        ..DeploymentLimits::standard()
    };
    let cx1 = cx("m05")?;
    let mut dep = open(&dir, limits)?;
    let receipt = FileIngestAdapter::ingest(request(&source, CHUNK, 16_384)?, &cx1, &mut dep)?;
    assert!(
        receipt.batch_ids.len() > 2,
        "the record bound must split c0"
    );
    assert_complete_once(&dep, &receipt, &bytes, &cx1)?;
    for batch in dep.ledger().batches() {
        assert!(fss_ledger::encode_batch(batch)?.len() <= bound as usize);
    }
    Ok(())
}

/// m06: a committed batch with a planned identifier but different content is a typed
/// `ImportPlanConflict`; nothing after it is appended (fss-2h5zq.23 round 3: "different ->
/// typed ImportPlanConflict").
#[test]
fn m06_foreign_batch_under_a_planned_id_is_an_import_plan_conflict() -> TestResult {
    let dir = fresh_dir("m06-conflict")?;
    let source = fixture(H264)?;
    let req = request(&source, CHUNK, KNOB)?;
    let hex = identity_hex(&req)?.ok_or("identity")?;
    let cx1 = cx("m06")?;
    let mut dep = open(&dir, standard())?;
    let payload = dep.stage_payload(b"foreign payload")?;
    dep.publisher_mut().verify_object(payload)?;
    let validity = fss_core::CaptureInterval::new(TimestampNs(0), TimestampNs(RECEIVE_NS))?;
    dep.append_batch(
        fss_core::BatchId::parse(format!("batch:file-import:{hex}:c0"))?,
        vec![EvidenceDelta {
            delta_id: "delta:foreign:c0".to_owned(),
            family: "sensor_capsule".to_owned(),
            object_id: ObjectId::parse("object:foreign:c0")?,
            prior_generation: None,
            new_generation: 1,
            validity,
            plane: Plane::Authority,
            payload_digest: payload,
            witness_digest: None,
            operation_id: None,
        }],
        vec![payload],
        &cx1,
    )?;
    let batches = dep.ledger().batches().len();
    match FileIngestAdapter::ingest(req, &cx1, &mut dep) {
        Err(FileIngestError::ImportPlanConflict { batch_id, .. })
            if batch_id.as_str() == format!("batch:file-import:{hex}:c0") => {}
        other => return Err(format!("expected ImportPlanConflict, got {other:?}").into()),
    }
    assert_eq!(
        dep.ledger().batches().len(),
        batches,
        "nothing appended after the conflict"
    );
    Ok(())
}

/// m07: an import whose root closure exceeds the manifest child bound is refused typed before
/// staging (part slots are not implemented; staged objects cannot be discarded), so the spool
/// and the ledger are untouched.
#[test]
fn m07_oversized_root_closure_is_refused_before_staging() -> TestResult {
    let dir = fresh_dir("m07-closure")?;
    let source = fixture(H264)?;
    let limits = DeploymentLimits {
        manifest_children_max: 8,
        ..DeploymentLimits::standard()
    };
    let cx1 = cx("m07")?;
    let mut dep = open(&dir, limits)?;
    let objects = dep.publisher().spool().object_count();
    match FileIngestAdapter::ingest(request(&source, CHUNK, KNOB)?, &cx1, &mut dep) {
        Err(FileIngestError::SpoolCapacityExceeded {
            limit: "import_root_closure",
            ..
        }) => {}
        other => return Err(format!("expected import_root_closure refusal, got {other:?}").into()),
    }
    assert_eq!(dep.publisher().spool().object_count(), objects);
    assert!(dep.ledger().batches().is_empty());
    Ok(())
}

/// m08: a zero batch knob is refused as invalid limits before anything is read.
#[test]
fn m08_zero_batch_knob_is_invalid() -> TestResult {
    let dir = fresh_dir("m08-zero")?;
    let cx1 = cx("m08")?;
    let mut dep = open(&dir, standard())?;
    match FileIngestAdapter::ingest(request(&fixture(H264)?, CHUNK, 0)?, &cx1, &mut dep) {
        Err(FileIngestError::InvalidLimits { detail }) if detail.contains("max_batch_deltas") => {
            Ok(())
        }
        other => Err(format!("expected InvalidLimits, got {other:?}").into()),
    }
}

// ---------------------------------------------------------------------------------------------
// Capacity
// ---------------------------------------------------------------------------------------------

/// Spool payload bytes an import of `request` occupies once fully staged (probe deployment).
fn staged_bytes(label: &str, req: &FileIngestRequest) -> Result<u64, Box<dyn std::error::Error>> {
    let dir = fresh_dir(label)?;
    let cx1 = cx(label)?;
    cx1.set_cancel_at_checkpoint_occurrence(STAGE_COMMIT_CAPSULES, 1);
    let mut dep = open(&dir, standard())?;
    let result = FileIngestAdapter::ingest(req.clone(), &cx1, &mut dep);
    expect_cancelled(label, &result, &cx1)?;
    Ok(dep.publisher().spool().occupied_bytes()?)
}

/// c01: the capacity check charges every object the import stages, including the import slot's
/// manifest body. Expected (fss-2h5zq.31 round 3: "no spool refusal may surface from a stage
/// call"): with total spool capacity one byte below the full staged footprint, the import is
/// refused typed (`max_total_bytes`) BEFORE staging, with the spool and the ledger unchanged.
#[test]
fn c01_capacity_charges_the_slot_manifest_before_staging() -> TestResult {
    let source = fixture(H264)?;
    let req = request(&source, CHUNK, KNOB)?;
    let full = staged_bytes("c01-probe", &req)?;
    let dir = fresh_dir("c01-tight")?;
    let limits = DeploymentLimits {
        spool_total_max_bytes: full - 1,
        ..DeploymentLimits::standard()
    };
    let cx1 = cx("c01")?;
    let mut dep = open(&dir, limits)?;
    let (bytes_before, objects_before) = (
        dep.publisher().spool().occupied_bytes()?,
        dep.publisher().spool().object_count(),
    );
    match FileIngestAdapter::ingest(req, &cx1, &mut dep) {
        Err(FileIngestError::SpoolCapacityExceeded {
            limit: "max_total_bytes",
            ..
        }) => {}
        other => {
            return Err(format!("expected a pre-stage capacity refusal, got {other:?}").into());
        }
    }
    assert_eq!(dep.publisher().spool().occupied_bytes()?, bytes_before);
    assert_eq!(dep.publisher().spool().object_count(), objects_before);
    assert!(dep.ledger().batches().is_empty());
    Ok(())
}

/// c02: re-importing an already-staged file succeeds even when the file is larger than the
/// remaining capacity (fss-2h5zq.23 round 3: only NEW bytes are charged).
#[test]
fn c02_resume_of_staged_import_needs_no_new_capacity() -> TestResult {
    let source = fixture(H264)?;
    let bytes = fs::read(&source)?;
    let req = request(&source, CHUNK, KNOB)?;
    let full = staged_bytes("c02-probe", &req)?;
    let file_len = bytes.len() as u64;
    let dir = fresh_dir("c02-tight")?;
    let limits = DeploymentLimits {
        spool_total_max_bytes: full + file_len / 2,
        ..DeploymentLimits::standard()
    };
    {
        let cx1 = cx("c02")?;
        cx1.set_cancel_at_checkpoint_occurrence(STAGE_COMMIT_CAPSULES, 1);
        let mut dep = open(&dir, limits)?;
        let result = FileIngestAdapter::ingest(req.clone(), &cx1, &mut dep);
        expect_cancelled("c02", &result, &cx1)?;
        let remaining = limits.spool_total_max_bytes - dep.publisher().spool().occupied_bytes()?;
        assert!(
            remaining < file_len,
            "precondition: remaining capacity below the file size"
        );
    }
    let cx2 = cx("c02-2")?;
    let mut dep = open(&dir, limits)?;
    let receipt = FileIngestAdapter::ingest(req, &cx2, &mut dep)?;
    assert_eq!(
        receipt.outcome,
        FileIngestOutcome::New,
        "no batch existed before"
    );
    assert_complete_once(&dep, &receipt, &bytes, &cx2)?;
    drop(dep);
    assert_clean_after_reopen(&dir, limits)
}

/// Spool objects of a fresh deployment, and the objects an import of `request` adds once fully
/// staged (probe deployment).
fn staged_objects(
    label: &str,
    req: &FileIngestRequest,
) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    let dir = fresh_dir(label)?;
    let cx1 = cx(label)?;
    cx1.set_cancel_at_checkpoint_occurrence(STAGE_COMMIT_CAPSULES, 1);
    let mut dep = open(&dir, standard())?;
    let before = dep.publisher().spool().object_count();
    let result = FileIngestAdapter::ingest(req.clone(), &cx1, &mut dep);
    expect_cancelled(label, &result, &cx1)?;
    Ok((before, dep.publisher().spool().object_count() - before))
}

/// c03 (fss-n62w2): the capacity check counts every NEW object the import stages against the
/// spool's `max_objects`. Expected: with room for one object fewer than the full staged
/// footprint (measured by a probe), the import is refused typed (`max_objects`, required = the
/// footprint, available = the bound) BEFORE staging, with the spool and the ledger unchanged;
/// with room for exactly the footprint the same import completes once. Deleting the
/// `max_objects` branch turns the first case into a spool refusal part way through staging.
#[test]
fn c03_object_count_capacity_is_checked_before_staging() -> TestResult {
    let source = fixture(H264)?;
    let req = request(&source, CHUNK, KNOB)?;
    let (base, added) = staged_objects("c03-probe", &req)?;
    assert!(added > 1, "precondition: the import stages several objects");
    let footprint = base + added;

    let dir = fresh_dir("c03-tight")?;
    let tight = DeploymentLimits {
        spool_max_objects: footprint - 1,
        ..DeploymentLimits::standard()
    };
    {
        let cx1 = cx("c03")?;
        let mut dep = open(&dir, tight)?;
        assert_eq!(dep.publisher().spool().object_count(), base);
        let bytes_before = dep.publisher().spool().occupied_bytes()?;
        match FileIngestAdapter::ingest(req.clone(), &cx1, &mut dep) {
            Err(FileIngestError::SpoolCapacityExceeded {
                limit: "max_objects",
                required,
                available,
            }) => {
                assert_eq!(required, footprint as u64);
                assert_eq!(available, (footprint - 1) as u64);
            }
            other => {
                return Err(
                    format!("expected a pre-stage max_objects refusal, got {other:?}").into(),
                );
            }
        }
        assert_eq!(dep.publisher().spool().object_count(), base);
        assert_eq!(dep.publisher().spool().occupied_bytes()?, bytes_before);
        assert!(dep.ledger().batches().is_empty());
    }

    let dir = fresh_dir("c03-exact")?;
    let exact = DeploymentLimits {
        spool_max_objects: footprint,
        ..DeploymentLimits::standard()
    };
    let cx2 = cx("c03-exact")?;
    let mut dep = open(&dir, exact)?;
    let receipt = FileIngestAdapter::ingest(req, &cx2, &mut dep)?;
    assert_eq!(receipt.outcome, FileIngestOutcome::New);
    assert_complete_once(&dep, &receipt, &fs::read(&source)?, &cx2)?;
    Ok(())
}

/// Spans of a completed import still match after a reopen (custody survives restarts).
#[test]
fn r01_spans_survive_reopen() -> TestResult {
    let dir = fresh_dir("r01-reopen")?;
    let source = fixture(H264)?;
    let bytes = fs::read(&source)?;
    let receipt = {
        let mut dep = open(&dir, standard())?;
        FileIngestAdapter::ingest(request(&source, CHUNK, KNOB)?, &cx("r01")?, &mut dep)?
    };
    let dep = open(&dir, standard())?;
    assert_spans_match(&receipt.manifest, &dep, &bytes)
}

/// a01: file import never certifies absence (file_adapter.rs "Time Truth Discipline"). Expected:
/// after a complete multi-batch import the canonical ledger holds ONLY the import's own families
/// (`file_import`, `sensor_capsule`, `file_import_manifest`, the slot's
/// `local_root_reachability`, and `acquisition_transition` if the acquisition session is wired),
/// so no `coverage_witness` or any other continuity/coverage delta exists, no capsule delta
/// carries a witness, and the receipt says `absence_certifiable: false`. This scans the ledger
/// the import wrote, not a fresh store that never saw it.
#[test]
fn a01_import_commits_no_coverage_or_continuity_authority() -> TestResult {
    const ALLOWED: [&str; 5] = [
        "file_import",
        "sensor_capsule",
        "file_import_manifest",
        "local_root_reachability",
        "acquisition_transition",
    ];
    let dir = fresh_dir("a01-absence")?;
    let source = fixture(H264)?;
    let cx1 = cx("a01")?;
    let mut dep = open(&dir, standard())?;
    let receipt = FileIngestAdapter::ingest(request(&source, CHUNK, KNOB)?, &cx1, &mut dep)?;
    assert!(!receipt.absence_certifiable);
    for batch in dep.ledger().batches() {
        for delta in &batch.deltas {
            assert!(
                ALLOWED.contains(&delta.family.as_str()),
                "unexpected family {} in {}",
                delta.family,
                batch.batch_id.as_str()
            );
            if delta.family == "sensor_capsule" {
                assert!(
                    delta.witness_digest.is_none(),
                    "a capsule carries no witness"
                );
            }
        }
    }
    // Every capsule's source digest is its custody span digest.
    for (capsule, span) in receipt.capsules.iter().zip(&receipt.manifest.segment_spans) {
        assert_eq!(capsule.source_digest, span.segment_sha256);
        assert_eq!(capsule.source_bytes, span.len);
    }
    Ok(())
}

/// r02: a revoked I/O authority cannot read. Expected (adapter_replay.rs: revocation finalizes
/// the shared lifecycle state, and `ingest` refuses a cancelled context before its first stat):
/// `CancellationRequested` at the stat stage, with nothing staged or appended.
#[test]
fn r02_revoked_authority_reads_nothing() -> TestResult {
    let dir = fresh_dir("r02-revoked")?;
    let mut dep = open(&dir, standard())?;
    let cx1 = cx("r02")?;
    cx1.io_authority().revoke();
    match FileIngestAdapter::ingest(request(&fixture(H264)?, CHUNK, KNOB)?, &cx1, &mut dep) {
        Err(FileIngestError::CancellationRequested { stage }) if stage.ends_with(":stat") => {}
        other => return Err(format!("expected a refusal at stat, got {other:?}").into()),
    }
    assert_eq!(dep.publisher().spool().object_count(), 0);
    assert!(dep.ledger().batches().is_empty());
    Ok(())
}

/// s01 (fss-4dcwe, foreign half): the resume path reuses a visible slot root only when it is
/// exactly this plan's root (rows f13/f17/f18 cover the own-root resume). Expected: a slot
/// `fi-<id>` that already holds a DIFFERENT root is refused with `SlotConflict` before any stage
/// or append, so no batch of the import identity is committed and the foreign root is untouched.
#[test]
fn s01_foreign_root_in_the_import_slot_is_refused() -> TestResult {
    let dir = fresh_dir("s01-foreign")?;
    let req = request(&fixture(H264)?, CHUNK, KNOB)?;
    let hex = identity_hex(&req)?.ok_or("identity")?;
    let slot = SlotName::parse(&format!("fi-{hex}"))?;
    let cx1 = cx("s01")?;
    let mut dep = open(&dir, standard())?;
    let payload = dep.stage_payload(b"foreign slot content")?;
    dep.publisher_mut().verify_object(payload)?;
    let foreign = fss_object::ObjectManifest::new(slot.as_str(), vec![payload], None)?;
    let validity = fss_core::CaptureInterval::new(TimestampNs(0), TimestampNs(RECEIVE_NS))?;
    dep.publish_and_commit(&slot, &foreign, validity, &cx1)?;
    let batches = dep.ledger().batches().len();
    match FileIngestAdapter::ingest(req, &cx1, &mut dep) {
        Err(FileIngestError::LocalPublication(
            fss_publication::LocalPublicationError::SlotConflict { existing, .. },
        )) if existing == foreign.root() => {}
        other => return Err(format!("expected SlotConflict, got {other:?}").into()),
    }
    assert_eq!(dep.ledger().batches().len(), batches, "nothing appended");
    assert_eq!(view(&dep, &hex).capsule_batches.len(), 0);
    assert_eq!(
        dep.publisher().root(&slot).map(|r| r.root),
        Some(foreign.root()),
        "the foreign root is untouched"
    );
    Ok(())
}
