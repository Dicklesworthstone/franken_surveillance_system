#![forbid(unsafe_code)]
//! Real local storage/cut-point contracts; authored tests are not pass receipts.
mod recording_support;
use recording_support::*;
use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalPublicationState, LocalRootPublisher,
    NeverCancel, PublishCancellation, PublishCutPoint, PublishOutcome, SlotName};
use fss_reference::rtsp::recording::{PreparedRecording, RecordingRole};
use fss_reference::rtsp::recording::local::{RecordingIoError, RecordingProgress, RecordingPublication, load_recording};
use std::path::{Path, PathBuf};

type TestResult = Result<(), Error>;
fn fresh(name: &str) -> Result<PathBuf, Error> {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("recording_publication_contract").join(name);
    match std::fs::remove_dir_all(&path) {
        Ok(()) => {}, Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}, Err(e) => return Err(e.into()),
    }
    Ok(path)
}
fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(8, 16, 8, 64, SpoolLimits::new(64, 4 * 1024 * 1024, 1024 * 1024, 64))
}
fn slot() -> Result<SlotName, Error> { Ok(SlotName::parse("recording-001")?) }
fn stage(plan: &PreparedRecording, publisher: &mut LocalRootPublisher) -> Result<(), Error> {
    let mut job = RecordingPublication::new(plan, publisher, slot()?, plan.byte_len(), 100)?;
    for at in 0..4 { assert!(matches!(job.step(at, &NeverCancel)?, RecordingProgress::ChildStaged { .. })); }
    Ok(())
}
fn publish(plan: &PreparedRecording, publisher: &mut LocalRootPublisher) -> Result<PublishOutcome, Error> {
    let mut job = RecordingPublication::new(plan, publisher, slot()?, plan.byte_len(), 100)?;
    for at in 0..5 {
        if let RecordingProgress::Published(receipt) = job.step(at, &NeverCancel)? {
            assert_eq!(receipt.claims.local, LocalPublicationState::Durable);
            assert_eq!(receipt.root, plan.manifest().root()); return Ok(receipt.outcome);
        }
    }
    Err("no root receipt after five bounded steps".into())
}
struct CancelAt(PublishCutPoint);
impl PublishCancellation for CancelAt {
    fn cancel_requested(&self, point: PublishCutPoint) -> bool { self.0 == point }
}

#[test]
fn source_is_staged_first_and_no_root_is_visible_after_children() -> TestResult {
    let plan = fixture(1, true)?.prepare()?;
    let mut p = LocalRootPublisher::open(fresh("source_first")?, limits())?;
    {
        let mut job = RecordingPublication::new(&plan, &mut p, slot()?, plan.byte_len(), 100)?;
        assert!(matches!(job.step(0, &NeverCancel)?, RecordingProgress::ChildStaged { role: RecordingRole::Source, remaining: 3, .. }));
        for at in 1..4 { job.step(at, &NeverCancel)?; }
    }
    assert!(p.root(&slot()?).is_none());
    assert!(matches!(load_recording(&p, &slot()?, plan.manifest().root(), &scope()?, &NeverCancel), Err(RecordingIoError::NotDurable)));
    assert_eq!(publish(&plan, &mut p)?, PublishOutcome::Published); Ok(())
}
#[test]
fn reopen_recovers_source_media_and_canonical_scope_without_remux() -> TestResult {
    let path = fresh("reopen")?; let plan = fixture(1, true)?.prepare()?;
    { let mut p = LocalRootPublisher::open(&path, limits())?; publish(&plan, &mut p)?; }
    let p = LocalRootPublisher::open(&path, limits())?;
    let recovered = load_recording(&p, &slot()?, plan.manifest().root(), &scope()?, &NeverCancel)?;
    assert_eq!(recovered.objects().media, plan.objects().media);
    assert_eq!(recovered.objects().source, plan.objects().source);
    assert_eq!(recovered.objects().index, plan.objects().index);
    assert_eq!(recovered.summary(), plan.summary()); Ok(())
}
#[test]
fn every_completed_child_stage_survives_process_loss_without_partial_root() -> TestResult {
    let plan = fixture(1, false)?.prepare()?;
    for cut in 0..=4 {
        let path = fresh(&format!("child_cut_{cut}"))?;
        {
            let mut p = LocalRootPublisher::open(&path, limits())?;
            let mut job = RecordingPublication::new(&plan, &mut p, slot()?, plan.byte_len(), 100)?;
            for at in 0..cut { job.step(at, &NeverCancel)?; }
        }
        let mut reopened = LocalRootPublisher::open(&path, limits())?;
        assert!(reopened.root(&slot()?).is_none());
        assert_eq!(publish(&plan, &mut reopened)?, PublishOutcome::Published);
        load_recording(&reopened, &slot()?, plan.manifest().root(), &scope()?, &NeverCancel)?;
    }
    Ok(())
}
#[test]
fn lost_final_receipt_reconciles_to_already_published() -> TestResult {
    let path = fresh("lost_receipt")?; let plan = fixture(1, false)?.prepare()?;
    { let mut p = LocalRootPublisher::open(&path, limits())?; publish(&plan, &mut p)?; }
    let mut p = LocalRootPublisher::open(&path, limits())?;
    assert_eq!(publish(&plan, &mut p)?, PublishOutcome::AlreadyPublished);
    assert_eq!(p.visible_roots().count(), 1); Ok(())
}
#[test]
fn all_root_cut_points_preserve_visible_staged_and_blocked_distinctions() -> TestResult {
    let plan = fixture(1, false)?.prepare()?;
    for (ordinal, cut) in [PublishCutPoint::AfterChildrenVerified, PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite, PublishCutPoint::AfterRootRename].into_iter().enumerate() {
        let path = fresh(&format!("root_cut_{ordinal}"))?;
        {
            let mut p = LocalRootPublisher::open(&path, limits())?;
            stage(&plan, &mut p)?; p.inject_crash_at(cut);
            let mut job = RecordingPublication::new(&plan, &mut p, slot()?, plan.byte_len(), 100)?;
            for at in 0..4 { job.step(at, &NeverCancel)?; }
            assert!(job.step(4, &NeverCancel).is_err());
        }
        let mut p = LocalRootPublisher::open(&path, limits())?;
        match cut {
            PublishCutPoint::AfterRootRename => {
                assert_eq!(publish(&plan, &mut p)?, PublishOutcome::AlreadyPublished);
                load_recording(&p, &slot()?, plan.manifest().root(), &scope()?, &NeverCancel)?;
            }
            PublishCutPoint::AfterRootTempWrite => {
                // An orphan temp is a repair obligation, not permission to delete it.
                assert!(p.root(&slot()?).is_none()); assert!(!p.recovery_report().orphaned_temps.is_empty());
                assert!(publish(&plan, &mut p).is_err());
            }
            _ => { assert!(p.root(&slot()?).is_none()); assert_eq!(publish(&plan, &mut p)?, PublishOutcome::Published); }
        }
    }
    Ok(())
}
#[test]
fn cancellation_preserves_staged_source_without_a_published_root() -> TestResult {
    let plan = fixture(1, false)?.prepare()?;
    let mut p = LocalRootPublisher::open(fresh("cancel")?, limits())?;
    {
        let mut job = RecordingPublication::new(&plan, &mut p, slot()?, plan.byte_len(), 100)?;
        job.step(0, &NeverCancel)?;
        assert!(matches!(job.step(1, &CancelAt(PublishCutPoint::AfterChildrenVerified)), Err(RecordingIoError::Cancelled)));
        assert!(matches!(job.step(2, &NeverCancel), Err(RecordingIoError::Stopped)));
    }
    assert!(p.root(&slot()?).is_none());
    assert_eq!(p.spool().read(plan.children()[0].1)?, plan.objects().source); Ok(())
}
#[test]
fn cancellation_at_root_temp_cut_never_claims_publication() -> TestResult {
    let plan = fixture(1, false)?.prepare()?;
    let mut p = LocalRootPublisher::open(fresh("cancel_temp")?, limits())?;
    {
        let mut job = RecordingPublication::new(&plan, &mut p, slot()?, plan.byte_len(), 100)?;
        for at in 0..4 { job.step(at, &NeverCancel)?; }
        assert!(job.step(4, &CancelAt(PublishCutPoint::AfterRootTempWrite)).is_err());
    }
    assert!(p.root(&slot()?).is_none()); Ok(())
}
#[test]
fn budget_and_expired_deadline_fail_before_publication() -> TestResult {
    let plan = fixture(1, false)?.prepare()?;
    let mut p = LocalRootPublisher::open(fresh("budget")?, limits())?;
    assert!(RecordingPublication::new(&plan, &mut p, slot()?, plan.byte_len() - 1, 100).is_err());
    {
        let mut job = RecordingPublication::new(&plan, &mut p, slot()?, plan.byte_len(), 100)?;
        assert!(matches!(job.step(100, &NeverCancel), Err(RecordingIoError::Deadline)));
    }
    assert!(p.root(&slot()?).is_none()); Ok(())
}
#[test]
fn clock_reversal_does_not_consume_a_child() -> TestResult {
    let plan = fixture(1, false)?.prepare()?;
    let mut p = LocalRootPublisher::open(fresh("clock")?, limits())?;
    let mut job = RecordingPublication::new(&plan, &mut p, slot()?, plan.byte_len(), 100)?;
    job.step(10, &NeverCancel)?;
    assert!(matches!(job.step(9, &NeverCancel), Err(RecordingIoError::ClockReversed)));
    assert!(matches!(job.step(10, &NeverCancel)?, RecordingProgress::ChildStaged { role: RecordingRole::Initialization, .. })); Ok(())
}
#[test]
fn conflicting_recording_never_overwrites_an_existing_slot() -> TestResult {
    let mut f = fixture(1, false)?; let plan = f.prepare()?;
    let mut p = LocalRootPublisher::open(fresh("conflict")?, limits())?; publish(&plan, &mut p)?;
    f.packets[0].1 += 1; let other = f.prepare()?;
    assert!(matches!(RecordingPublication::new(&other, &mut p, slot()?, other.byte_len(), 100), Err(RecordingIoError::RootConflict)));
    assert_eq!(p.root(&slot()?).ok_or("lost root")?.root, plan.manifest().root()); Ok(())
}
#[test]
fn exact_root_is_required_and_corrupted_source_is_never_served() -> TestResult {
    let path = fresh("corrupt")?; let plan = fixture(1, false)?.prepare()?;
    let mut p = LocalRootPublisher::open(&path, limits())?; publish(&plan, &mut p)?;
    assert!(matches!(load_recording(&p, &slot()?, ContentDigest::sha256(b"wrong-root"), &scope()?, &NeverCancel), Err(RecordingIoError::RootConflict)));
    let text = plan.children()[0].1.to_text(); let hex = text.strip_prefix("sha256:").ok_or("not SHA256")?;
    let source_path = path.join("spool").join("objects").join(hex);
    let mut bytes = std::fs::read(&source_path)?;
    let last = bytes.last_mut().ok_or("empty object")?; *last ^= 1; std::fs::write(&source_path, bytes)?;
    assert!(load_recording(&p, &slot()?, plan.manifest().root(), &scope()?, &NeverCancel).is_err()); Ok(())
}
#[test]
fn completed_job_does_not_turn_into_cancellation_or_repeat_a_receipt() -> TestResult {
    let plan = fixture(1, false)?.prepare()?;
    let mut p = LocalRootPublisher::open(fresh("done")?, limits())?;
    let mut job = RecordingPublication::new(&plan, &mut p, slot()?, plan.byte_len(), 100)?;
    for at in 0..5 { job.step(at, &NeverCancel)?; }
    assert_eq!(job.step(200, &CancelAt(PublishCutPoint::AfterChildrenVerified))?, RecordingProgress::Complete); Ok(())
}
