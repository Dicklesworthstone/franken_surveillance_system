#![forbid(unsafe_code)]
mod archive_support;
use archive_support::*;
use fss_publication::{LocalRootPublisher, NeverCancel, PublishCancellation, PublishCutPoint};
use fss_reference::rtsp::recording_archive::*;
use std::cell::Cell;

fn drive_ready(w: &mut RecordingArchiveWriter<'_>, now: &mut u64) -> TestResult {
    for _ in 0..80 {
        let out = w.step(*now, &NeverCancel)?; *now += 1;
        if matches!(out, ArchiveWriteProgress::Ready { .. }) { return Ok(()); }
    }
    Err("writer did not reach bounded ready state".into())
}
fn drive_finished(w: &mut RecordingArchiveWriter<'_>, now: &mut u64) -> TestResult {
    for _ in 0..80 {
        let out = w.step(*now, &NeverCancel)?; *now += 1;
        if matches!(out, ArchiveWriteProgress::Finished { .. }) { return Ok(()); }
    }
    Err("writer did not finish final page".into())
}
fn must_refuse(value: Result<ArchiveAdmission, ArchiveWriteRefusal>) -> Result<ArchiveWriteRefusal, Error> {
    match value { Err(refusal) => Ok(refusal), Ok(_) => Err("unexpected archive admission".into()) }
}
struct Stop;
impl PublishCancellation for Stop { fn cancel_requested(&self, _: PublishCutPoint) -> bool { true } }
struct AfterCalls(Cell<usize>);
impl PublishCancellation for AfterCalls {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        let n = self.0.get(); self.0.set(n + 1); n >= 3
    }
}
#[test]
fn automatic_full_pages_and_final_partial_page_survive_restart_and_query() -> TestResult {
    let (path, mut p) = owner("writer_pages")?; let ns = namespace()?; let mut now = 0;
    let limits = ArchiveLimits { windows_per_page: 2, ..ArchiveLimits::default() };
    let mut w = RecordingArchiveWriter::open(&mut p, ns.clone(), limits, now, 1000, &NeverCancel)?;
    for ordinal in 0..3 {
        let recording = window(1 + ordinal as u64 * 3, ordinal as u64 * 3600)?;
        let bytes = recording.byte_len();
        assert_eq!(w.offer(recording, bytes, now)?.ordinal, ordinal);
        drive_ready(&mut w, &mut now)?;
    }
    assert_eq!(w.snapshot().windows().len(), 3); assert_eq!(w.snapshot().indexed_windows(), 2);
    w.finish(); drive_finished(&mut w, &mut now)?;
    assert!(matches!(w.step(now, &NeverCancel)?, ArchiveWriteProgress::Exhausted));
    let retired = w.retire(); assert!(retired.pending.is_none());
    assert_eq!(retired.snapshot.pages().len(), 2); assert_eq!(retired.snapshot.indexed_windows(), 3);
    let expected = retired.snapshot.digest()?;
    drop(p);
    let p = LocalRootPublisher::open(path, owner_limits())?;
    let s = ArchiveSnapshot::load(&p, ns, limits, &NeverCancel)?;
    assert_eq!(s.digest()?, expected);
    let mut read = ArchiveRead::new(&p, &s, 0..10800, ArchiveQueryLimits::default(), 1000)?;
    for i in 0..3 { assert!(matches!(read.step(i, &NeverCancel)?, ArchiveReadProgress::Window { ordinal, .. } if ordinal == i as usize)); }
    assert!(matches!(read.step(3, &NeverCancel)?, ArchiveReadProgress::Complete(r) if r.windows == 3 && r.unindexed.is_empty()));
    Ok(())
}
#[test]
fn backpressure_returns_exact_unconsumed_recording_without_advancing_ordinal() -> TestResult {
    let (_, mut p) = owner("writer_pressure")?; let mut now = 0;
    let mut w = RecordingArchiveWriter::open(&mut p, namespace()?, ArchiveLimits::default(), 0, 1000, &NeverCancel)?;
    let a = window(1, 0)?; let b = window(3, 3600)?; let b_root = b.manifest().root();
    let bytes = a.byte_len(); w.offer(a, bytes, now)?;
    let bytes = b.byte_len();
    let refusal = must_refuse(w.offer(b, bytes, now))?;
    assert!(matches!(refusal.reason, ArchiveError::Backpressure)); assert_eq!(refusal.recording.manifest().root(), b_root);
    drive_ready(&mut w, &mut now)?;
    assert_eq!(w.offer(refusal.recording, bytes, now)?.ordinal, 1);
    drive_ready(&mut w, &mut now)?;
    w.finish(); drive_finished(&mut w, &mut now)?;
    assert!(w.retire().pending.is_none());
    Ok(())
}
#[test]
fn cancellation_during_child_staging_retains_exact_plan_for_explicit_retry() -> TestResult {
    let (_, mut p) = owner("writer_stage_cancel")?;
    let mut w = RecordingArchiveWriter::open(&mut p, namespace()?, ArchiveLimits::default(), 0, 1000, &NeverCancel)?;
    let a = window(1, 0)?; let root = a.manifest().root(); let bytes = a.byte_len(); w.offer(a, bytes, 0)?;
    assert!(w.step(0, &AfterCalls(Cell::new(0))).is_err());
    assert_eq!(w.pending().ok_or("pending originals lost")?.manifest().root(), root);
    assert!(w.snapshot().windows().is_empty());
    assert!(matches!(w.step(1, &NeverCancel), Err(ArchiveError::Blocked)));
    w.retry(1, 1000)?;
    assert!(matches!(w.step(1, &NeverCancel)?, ArchiveWriteProgress::WindowDurable { ordinal: 0, receipt } if receipt.root == root));
    assert_eq!(w.snapshot().windows().len(), 1);
    assert!(w.retire().pending.is_none());
    Ok(())
}
#[test]
fn durable_tail_is_indexed_on_restart_before_new_capture_is_admitted() -> TestResult {
    let (path, mut p) = owner("writer_tail_restart")?; let ns = namespace()?;
    {
        let mut w = RecordingArchiveWriter::open(&mut p, ns.clone(), ArchiveLimits::default(), 0, 1000, &NeverCancel)?;
        let a = window(1, 0)?; let bytes = a.byte_len(); w.offer(a, bytes, 0)?;
        assert!(matches!(w.step(0, &NeverCancel)?, ArchiveWriteProgress::WindowDurable { .. }));
        assert!(matches!(w.step(1, &Stop), Err(ArchiveError::Cancelled)));
        let retained = w.retire(); assert_eq!(retained.snapshot.unindexed_windows().len(), 1);
    }
    drop(p);
    let mut p = LocalRootPublisher::open(path, owner_limits())?;
    let mut w = RecordingArchiveWriter::open(&mut p, ns, ArchiveLimits::default(), 0, 1000, &NeverCancel)?;
    let b = window(3, 3600)?; let bytes = b.byte_len();
    let refused = must_refuse(w.offer(b, bytes, 0))?;
    assert!(matches!(refused.reason, ArchiveError::Backpressure));
    let mut now = 0; drive_ready(&mut w, &mut now)?;
    assert_eq!(w.snapshot().indexed_windows(), 1);
    assert_eq!(w.offer(refused.recording, bytes, now)?.ordinal, 1);
    w.finish(); drive_finished(&mut w, &mut now)?;
    assert_eq!(w.retire().snapshot.indexed_windows(), 2);
    Ok(())
}
#[test]
fn ambiguous_window_rename_keeps_originals_and_reopen_does_not_duplicate_them() -> TestResult {
    let (path, mut p) = owner("writer_window_crash")?; let ns = namespace()?;
    p.inject_crash_at(PublishCutPoint::AfterRootRename);
    let mut w = RecordingArchiveWriter::open(&mut p, ns.clone(), ArchiveLimits::default(), 0, 1000, &NeverCancel)?;
    let a = window(1, 0)?; let root = a.manifest().root(); let bytes = a.byte_len(); w.offer(a, bytes, 0)?;
    assert!(w.step(0, &NeverCancel).is_err()); assert!(w.retry(1, 1000).is_err());
    let retained = w.retire(); assert_eq!(retained.pending.as_ref().ok_or("lost originals")?.manifest().root(), root);
    drop(p);
    let mut p = LocalRootPublisher::open(path, owner_limits())?;
    let mut w = RecordingArchiveWriter::open(&mut p, ns, ArchiveLimits::default(), 0, 1000, &NeverCancel)?;
    let mut now = 0; drive_ready(&mut w, &mut now)?;
    assert_eq!(w.snapshot().indexed_windows(), 1); assert_eq!(w.snapshot().windows()[0].root(), root);
    let refusal = must_refuse(w.offer(retained.pending.ok_or("pending")?, bytes, now))?;
    assert!(matches!(refusal.reason, ArchiveError::Duplicate)); assert_eq!(refusal.recording.manifest().root(), root);
    assert_eq!(w.retire().snapshot.windows().len(), 1);
    Ok(())
}
#[test]
fn every_catalog_crash_cutpoint_preserves_durable_windows_and_recovery_distinctions() -> TestResult {
    for (index, cut) in [PublishCutPoint::AfterChildrenVerified, PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite, PublishCutPoint::AfterRootRename].into_iter().enumerate() {
        let (path, mut p) = owner(&format!("writer_page_crash_{index}"))?; let ns = namespace()?;
        let a = window(1, 0)?;
        publish_window(&mut p, &ns.window_slot(0)?, &a)?;
        p.inject_crash_at(cut);
        let mut w = RecordingArchiveWriter::open(&mut p, ns.clone(), ArchiveLimits::default(), 0, 1000, &NeverCancel)?;
        let mut failed = false;
        for now in 0..12 {
            if w.step(now, &NeverCancel).is_err() { failed = true; break; }
        }
        assert!(failed); let retained = w.retire();
        assert_eq!(retained.snapshot.windows().len(), 1); assert_eq!(retained.snapshot.indexed_windows(), 0);
        let expected_page = retained.prepared_page.ok_or("lost immutable page")?.manifest().root();
        drop(p);
        let mut p = LocalRootPublisher::open(path, owner_limits())?;
        if cut == PublishCutPoint::AfterRootTempWrite {
            assert!(matches!(ArchiveSnapshot::load(&p, ns, ArchiveLimits::default(), &NeverCancel), Err(ArchiveError::RecoveryRequired)));
            continue;
        }
        let mut recovered = RecordingArchiveWriter::open(&mut p, ns, ArchiveLimits::default(), 0, 1000, &NeverCancel)?;
        let mut now = 0; drive_ready(&mut recovered, &mut now)?;
        assert_eq!(recovered.snapshot().indexed_windows(), 1);
        assert_eq!(recovered.snapshot().pages()[0].catalog().manifest().root(), expected_page);
        assert!(recovered.retire().pending.is_none());
    }
    Ok(())
}
#[test]
fn deadline_and_clock_reversal_do_not_consume_pending_media() -> TestResult {
    let (_, mut p) = owner("writer_deadline")?;
    let mut w = RecordingArchiveWriter::open(&mut p, namespace()?, ArchiveLimits::default(), 5, 10, &NeverCancel)?;
    let a = window(1, 0)?; let bytes = a.byte_len(); let root = a.manifest().root(); w.offer(a, bytes, 5)?;
    assert!(matches!(w.step(4, &NeverCancel), Err(ArchiveError::ClockReversed)));
    assert!(matches!(w.step(10, &NeverCancel), Err(ArchiveError::Deadline)));
    assert_eq!(w.pending().ok_or("pending")?.manifest().root(), root);
    w.retry(11, 100)?;
    assert!(matches!(w.step(11, &NeverCancel)?, ArchiveWriteProgress::WindowDurable { receipt, .. } if receipt.root == root));
    assert!(w.retire().pending.is_none());
    Ok(())
}
#[test]
fn capacity_and_reservation_refusals_never_evict_old_evidence() -> TestResult {
    let (_, mut p) = owner("writer_quota")?;
    let limits = ArchiveLimits { max_windows: 1, windows_per_page: 2, ..ArchiveLimits::default() };
    let mut w = RecordingArchiveWriter::open(&mut p, namespace()?, limits, 0, 1000, &NeverCancel)?;
    let a = window(1, 0)?; let bytes = a.byte_len();
    let refused = must_refuse(w.offer(a, bytes - 1, 0))?;
    assert!(matches!(refused.reason, ArchiveError::Limit)); assert!(w.snapshot().windows().is_empty());
    w.offer(refused.recording, bytes, 0)?; let mut now = 0; drive_ready(&mut w, &mut now)?;
    let b = window(3, 3600)?; let bytes = b.byte_len();
    assert!(matches!(must_refuse(w.offer(b, bytes, now))?.reason, ArchiveError::Limit));
    w.finish(); drive_finished(&mut w, &mut now)?;
    assert_eq!(w.retire().snapshot.indexed_windows(), 1);
    Ok(())
}
#[test]
fn corrupt_namespace_root_is_not_reinterpreted_as_a_shorter_archive() -> TestResult {
    let (path, mut p) = owner("writer_corrupt_root")?; let ns = namespace()?; let a = window(1, 0)?;
    let slot = ns.window_slot(0)?; publish_window(&mut p, &slot, &a)?;
    drop(p);
    std::fs::write(path.join("roots").join(format!("{slot}.root")), b"corrupt fixture root record")?;
    let p = LocalRootPublisher::open(path, owner_limits())?;
    assert!(matches!(ArchiveSnapshot::load(&p, ns, ArchiveLimits::default(), &NeverCancel), Err(ArchiveError::RecoveryRequired)));
    Ok(())
}
