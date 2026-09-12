#![forbid(unsafe_code)]
//! Regression tests for adversarial review 607 of the staging spool (FSS-017, fss-x4a.7.5).

use std::error::Error;
use std::fmt::Debug;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fss_core::{ContentDigest, DigestAlgorithm};
use fss_object::{
    FaultInjectingSpoolIo, SPOOL_HOLDS_DIR, SPOOL_HOLDS_MIGRATION_DIR, SPOOL_OBJECTS_DIR,
    SPOOL_STAGING_DIR, SpoolError, SpoolFaultPlan, SpoolIoCall, SpoolIoOperation, SpoolLimits,
    SpoolObjectState, StagePhase, StagingSpool, encode_spool_object,
};

type TestResult = Result<(), Box<dyn Error>>;

const PAYLOAD: &[u8] = b"review-607-capsule-payload";

fn digest() -> ContentDigest {
    ContentDigest::sha256(PAYLOAD)
}

fn fresh_root(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("staging_spool_review607")
        .join(test_name);
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(root)
}

fn roomy() -> SpoolLimits {
    SpoolLimits::new(64, 1 << 20, 4096, 64)
}

fn expect_err<T: Debug>(result: Result<T, SpoolError>) -> Result<SpoolError, Box<dyn Error>> {
    match result {
        Ok(value) => Err(format!("expected a spool error, got {value:?}").into()),
        Err(error) => Ok(error),
    }
}

fn hex(digest: ContentDigest) -> String {
    digest.to_text().trim_start_matches("sha256:").to_owned()
}

fn object_file(root: &Path, digest: ContentDigest) -> PathBuf {
    root.join(SPOOL_OBJECTS_DIR).join(hex(digest))
}

fn dir_names(dir: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

fn open_faulted(
    root: &Path,
    plan: SpoolFaultPlan,
) -> Result<(StagingSpool, Arc<FaultInjectingSpoolIo>), Box<dyn Error>> {
    let io = Arc::new(FaultInjectingSpoolIo::new(plan));
    let spool = StagingSpool::open_with_io(root, roomy(), io.clone())?;
    Ok((spool, io))
}

/// Counts the calls an open of `root` plus `prefix` make with no fault planned.
fn probe_calls(
    root: &Path,
    prefix: impl FnOnce(&mut StagingSpool) -> Result<(), SpoolError>,
) -> Result<Arc<FaultInjectingSpoolIo>, Box<dyn Error>> {
    let (mut spool, io) = open_faulted(root, SpoolFaultPlan::new())?;
    prefix(&mut spool)?;
    Ok(io)
}

/// Counts the calls one plain open of an existing `root` makes.
fn open_probe(root: &Path) -> Result<Arc<FaultInjectingSpoolIo>, Box<dyn Error>> {
    let io = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new()));
    drop(StagingSpool::open_with_io(root, roomy(), io.clone())?);
    Ok(io)
}

/// True when the instance refuses every operation until it is reopened.
fn is_poisoned(spool: &StagingSpool) -> bool {
    matches!(
        spool.read(ContentDigest::sha256(b"review-607-poison-probe")),
        Err(SpoolError::Poisoned)
    )
}

/// Leaves one orphaned staging file per payload, as a crash before the rename would.
fn make_orphans(root: &Path, payloads: &[&[u8]]) -> TestResult {
    for payload in payloads {
        let mut spool = StagingSpool::open(root, roomy())?;
        spool.inject_crash_after(StagePhase::AfterStagingWrite);
        expect_err(spool.stage_bytes(payload))?;
    }
    Ok(())
}

fn orphan_paths(spool: &StagingSpool) -> Vec<PathBuf> {
    spool
        .orphaned_staging()
        .map(|orphan| orphan.path.clone())
        .collect()
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Fail,
    FailAfterApplying,
}

impl Mode {
    const ALL: [Self; 2] = [Self::Fail, Self::FailAfterApplying];

    fn plan(self, plan: SpoolFaultPlan, call: SpoolIoCall, occurrence: u64) -> SpoolFaultPlan {
        match self {
            Self::Fail => plan.fail(call, occurrence, ErrorKind::Other),
            Self::FailAfterApplying => plan.fail_after_applying(call, occurrence, ErrorKind::Other),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Finding 1: reopen must enforce the object-count and byte bounds
// ---------------------------------------------------------------------------------------------

#[test]
fn f1_reopen_over_the_object_bound_fails_closed() -> TestResult {
    let root = fresh_root("f1_reopen_over_the_object_bound_fails_closed")?;
    {
        let mut spool = StagingSpool::open(&root, SpoolLimits::new(4, 1024, 64, 16))?;
        spool.stage_bytes(b"obj-1")?;
        spool.stage_bytes(b"obj-2")?;
        spool.stage_bytes(b"obj-3")?;
    }
    let error = expect_err(StagingSpool::open(&root, SpoolLimits::new(2, 1024, 64, 16)))?;
    assert_eq!(
        error,
        SpoolError::RecoveredOverCapacity {
            objects: 3,
            max_objects: 2,
            occupied_bytes: 15,
            max_total_bytes: 1024,
        }
    );
    // The same root still opens under bounds that admit it, unchanged.
    let spool = StagingSpool::open(&root, SpoolLimits::new(4, 1024, 64, 16))?;
    assert_eq!(spool.object_count(), 3);
    assert!(spool.recovery_report().is_clean());
    Ok(())
}

#[test]
fn f1_reopen_over_the_byte_quota_fails_closed() -> TestResult {
    let root = fresh_root("f1_reopen_over_the_byte_quota_fails_closed")?;
    {
        let mut spool = StagingSpool::open(&root, SpoolLimits::new(8, 15, 64, 16))?;
        spool.stage_bytes(b"obj-1")?;
        spool.stage_bytes(b"obj-2")?;
        spool.stage_bytes(b"obj-3")?;
        assert_eq!(spool.occupied_bytes()?, 15);
    }
    let error = expect_err(StagingSpool::open(&root, SpoolLimits::new(8, 14, 64, 16)))?;
    assert_eq!(
        error,
        SpoolError::RecoveredOverCapacity {
            objects: 3,
            max_objects: 8,
            occupied_bytes: 15,
            max_total_bytes: 14,
        }
    );
    // Exactly at the bound is admitted.
    let spool = StagingSpool::open(&root, SpoolLimits::new(8, 15, 64, 16))?;
    assert_eq!(spool.occupied_bytes()?, 15);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Finding 2: a discard whose durability or effect is unknown poisons the instance
// ---------------------------------------------------------------------------------------------

#[test]
fn f2_discard_directory_fsync_failure_poisons_the_instance() -> TestResult {
    let root = fresh_root("f2_discard_directory_fsync_failure_poisons_the_instance")?;
    let probe = probe_calls(&fresh_root("f2_discard_fsync_probe")?, |spool| {
        spool.stage(digest(), PAYLOAD).map(|_| ())
    })?;
    let plan = SpoolFaultPlan::new().fail(
        SpoolIoCall::SyncDirectory,
        probe.calls(SpoolIoCall::SyncDirectory) + 1,
        ErrorKind::Other,
    );
    let (mut spool, io) = open_faulted(&root, plan)?;
    spool.stage(digest(), PAYLOAD)?;
    let error = expect_err(spool.discard_staged(digest()))?;
    assert!(io.all_fired());
    assert_eq!(
        error,
        SpoolError::DiscardNotDurable {
            digest: digest(),
            kind: ErrorKind::Other,
        }
    );
    assert!(is_poisoned(&spool), "a non-durable discard must poison");
    assert_eq!(
        expect_err(spool.stage_bytes(b"another"))?,
        SpoolError::Poisoned
    );
    assert_eq!(
        expect_err(spool.discard_staged(digest()))?,
        SpoolError::Poisoned
    );
    drop(spool);
    let reopened = StagingSpool::open(&root, roomy())?;
    assert_eq!(reopened.object_count(), 0);
    assert_eq!(reopened.occupied_bytes()?, 0);
    Ok(())
}

#[test]
fn f2_discard_removal_with_unobservable_outcome_poisons_the_instance() -> TestResult {
    let root = fresh_root("f2_discard_removal_with_unobservable_outcome")?;
    let probe = probe_calls(&fresh_root("f2_discard_unobservable_probe")?, |spool| {
        spool.stage(digest(), PAYLOAD).map(|_| ())
    })?;
    // The removal happens but is reported failed, and the follow-up probe cannot see the name.
    let plan = SpoolFaultPlan::new()
        .fail_after_applying(
            SpoolIoCall::RemoveFile,
            probe.calls(SpoolIoCall::RemoveFile) + 1,
            ErrorKind::Other,
        )
        .fail(
            SpoolIoCall::SymlinkMetadata,
            probe.calls(SpoolIoCall::SymlinkMetadata) + 1,
            ErrorKind::Other,
        );
    let (mut spool, io) = open_faulted(&root, plan)?;
    spool.stage(digest(), PAYLOAD)?;
    let error = expect_err(spool.discard_staged(digest()))?;
    assert!(io.all_fired());
    assert!(!object_file(&root, digest()).exists());
    assert_eq!(
        error,
        SpoolError::DiscardIndeterminate {
            path: object_file(&root, digest()),
            operation: SpoolIoOperation::RemoveObject,
            kind: ErrorKind::Other,
        }
    );
    assert!(is_poisoned(&spool), "an unobservable removal must poison");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Finding 3: discarding orphans must not drain the in-memory list without durable removal
// ---------------------------------------------------------------------------------------------

#[test]
fn f3_orphan_discard_fsync_failure_poisons_and_never_reports_empty_success() -> TestResult {
    let root = fresh_root("f3_orphan_discard_fsync_failure")?;
    make_orphans(&root, &[b"orphan-one", b"orphan-two"])?;
    let baseline = open_probe(&root)?;
    let plan = SpoolFaultPlan::new().fail(
        SpoolIoCall::SyncDirectory,
        baseline.calls(SpoolIoCall::SyncDirectory) + 1,
        ErrorKind::Other,
    );
    let (mut spool, io) = open_faulted(&root, plan)?;
    assert_eq!(spool.orphaned_staging().count(), 2);
    let error = expect_err(spool.discard_orphaned_staging())?;
    assert!(io.all_fired());
    assert_eq!(
        error,
        SpoolError::DiscardIndeterminate {
            path: root.join(SPOOL_STAGING_DIR),
            operation: SpoolIoOperation::SyncDirectory,
            kind: ErrorKind::Other,
        }
    );
    assert!(is_poisoned(&spool));
    // A retry must never claim that nothing was left to remove.
    assert_eq!(
        expect_err(spool.discard_orphaned_staging())?,
        SpoolError::Poisoned
    );
    drop(spool);
    let reopened = StagingSpool::open(&root, roomy())?;
    assert_eq!(reopened.occupied_bytes()?, 0);
    assert!(reopened.recovery_report().is_clean());
    Ok(())
}

#[test]
fn f3_orphan_discard_partial_failure_fsyncs_the_completed_removals() -> TestResult {
    let root = fresh_root("f3_orphan_discard_partial_failure")?;
    make_orphans(&root, &[b"orphan-one", b"orphan-two"])?;
    let baseline = open_probe(&root)?;
    let plan = SpoolFaultPlan::new().fail(
        SpoolIoCall::RemoveFile,
        baseline.calls(SpoolIoCall::RemoveFile) + 2,
        ErrorKind::PermissionDenied,
    );
    let (mut spool, io) = open_faulted(&root, plan)?;
    let syncs_before = io.calls(SpoolIoCall::SyncDirectory);
    let error = expect_err(spool.discard_orphaned_staging())?;
    assert!(io.all_fired());
    assert!(
        matches!(
            error,
            SpoolError::Io {
                operation: SpoolIoOperation::RemoveStaging,
                kind: ErrorKind::PermissionDenied,
                ..
            }
        ),
        "{error:?}"
    );
    assert!(!is_poisoned(&spool));
    assert_eq!(spool.orphaned_staging().count(), 1);
    assert_eq!(
        io.calls(SpoolIoCall::SyncDirectory),
        syncs_before + 1,
        "the first removal was released from the quota, so it must be fsynced"
    );
    let live_orphans = orphan_paths(&spool);
    let live_bytes = spool.occupied_bytes()?;
    drop(spool);
    let reopened = StagingSpool::open(&root, roomy())?;
    assert_eq!(orphan_paths(&reopened), live_orphans);
    assert_eq!(reopened.occupied_bytes()?, live_bytes);
    Ok(())
}

#[test]
fn f3_orphan_removal_reported_failed_after_applying_is_reconciled() -> TestResult {
    let root = fresh_root("f3_orphan_removal_after_applying")?;
    make_orphans(&root, &[b"orphan-one"])?;
    let baseline = open_probe(&root)?;
    let plan = SpoolFaultPlan::new().fail_after_applying(
        SpoolIoCall::RemoveFile,
        baseline.calls(SpoolIoCall::RemoveFile) + 1,
        ErrorKind::Other,
    );
    let (mut spool, io) = open_faulted(&root, plan)?;
    let outcome = spool.discard_orphaned_staging();
    assert!(io.all_fired());
    assert!(dir_names(&root.join(SPOOL_STAGING_DIR))?.is_empty());
    // The file is observably gone, so the live instance must agree with a reopen.
    assert!(!is_poisoned(&spool), "{outcome:?}");
    assert_eq!(spool.orphaned_staging().count(), 0, "{outcome:?}");
    assert_eq!(spool.occupied_bytes()?, 0, "{outcome:?}");
    assert!(outcome.is_ok(), "{outcome:?}");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Finding 4: fault sweeps over both discard operations
// ---------------------------------------------------------------------------------------------

/// Checks one faulted `discard_staged` of the only object in the spool.
fn check_discard_staged_outcome(
    case: &str,
    root: &Path,
    spool: StagingSpool,
    outcome: Result<u64, SpoolError>,
) -> TestResult {
    let payload_len = PAYLOAD.len() as u64;
    let poisoned = is_poisoned(&spool);
    let on_disk = object_file(root, digest()).exists();
    match outcome {
        Ok(released) => {
            assert!(!poisoned, "{case}");
            assert_eq!(released, payload_len, "{case}");
            assert_eq!(spool.state(digest()), None, "{case}");
            assert_eq!(spool.occupied_bytes()?, 0, "{case}");
            assert!(!on_disk, "{case}");
        }
        Err(error) if poisoned => {
            assert!(
                matches!(
                    error,
                    SpoolError::DiscardNotDurable { .. } | SpoolError::DiscardIndeterminate { .. }
                ),
                "{case}: {error:?}"
            );
        }
        Err(SpoolError::Io { operation, .. }) => {
            // A settled failure changed nothing: the object is still indexed, charged and present.
            assert_eq!(operation, SpoolIoOperation::RemoveObject, "{case}");
            assert_eq!(
                spool.state(digest()),
                Some(SpoolObjectState::Staged),
                "{case}"
            );
            assert_eq!(spool.occupied_bytes()?, payload_len, "{case}");
            assert!(on_disk, "{case}");
        }
        Err(other) => return Err(format!("{case}: unpoisoned untyped outcome {other:?}").into()),
    }
    let live = (!poisoned).then(|| (spool.object_count(), spool.occupied_bytes()));
    drop(spool);
    let mut reopened = StagingSpool::open(root, roomy())?;
    assert!(reopened.recovery_report().is_clean(), "{case}");
    assert_eq!(reopened.object_count(), usize::from(on_disk), "{case}");
    if let Some((count, bytes)) = live {
        assert_eq!(reopened.object_count(), count, "{case}");
        assert_eq!(reopened.occupied_bytes()?, bytes?, "{case}");
    }
    if on_disk {
        assert_eq!(reopened.discard_staged(digest())?, payload_len, "{case}");
    }
    Ok(())
}

#[test]
fn f4_every_single_discard_staged_fault_is_typed_and_reconciles() -> TestResult {
    let name = "f4_discard_staged_sweep";
    let after_stage = probe_calls(&fresh_root(&format!("{name}_stage_probe"))?, |spool| {
        spool.stage(digest(), PAYLOAD).map(|_| ())
    })?;
    let after_discard = probe_calls(&fresh_root(&format!("{name}_discard_probe"))?, |spool| {
        spool.stage(digest(), PAYLOAD)?;
        spool.discard_staged(digest()).map(|_| ())
    })?;
    let mut cases = 0_usize;
    for mode in Mode::ALL {
        for call in SpoolIoCall::ALL {
            let before = after_stage.calls(call);
            for step in 1..=after_discard.calls(call) - before {
                cases += 1;
                let case = format!("{name}_{mode:?}_{call}_{step}");
                let root = fresh_root(&case)?;
                let plan = mode.plan(SpoolFaultPlan::new(), call, before + step);
                let (mut spool, io) = open_faulted(&root, plan)?;
                spool.stage(digest(), PAYLOAD)?;
                let outcome = spool.discard_staged(digest());
                assert!(io.all_fired(), "{case}: fault did not fire");
                check_discard_staged_outcome(&case, &root, spool, outcome)?;
            }
        }
    }
    // One removal and one directory fsync.
    assert_eq!(cases, 2 * 2);
    Ok(())
}

#[test]
fn f4_every_removal_fault_with_every_probe_fault_is_typed_and_reconciles() -> TestResult {
    let name = "f4_discard_staged_probe_sweep";
    let after_stage = probe_calls(&fresh_root(&format!("{name}_stage_probe"))?, |spool| {
        spool.stage(digest(), PAYLOAD).map(|_| ())
    })?;
    let removal = after_stage.calls(SpoolIoCall::RemoveFile) + 1;
    let probe = after_stage.calls(SpoolIoCall::SymlinkMetadata) + 1;
    for remove_mode in Mode::ALL {
        for probe_mode in Mode::ALL {
            let case = format!("{name}_{remove_mode:?}_{probe_mode:?}");
            let root = fresh_root(&case)?;
            let plan = remove_mode.plan(SpoolFaultPlan::new(), SpoolIoCall::RemoveFile, removal);
            let plan = probe_mode.plan(plan, SpoolIoCall::SymlinkMetadata, probe);
            let (mut spool, io) = open_faulted(&root, plan)?;
            spool.stage(digest(), PAYLOAD)?;
            let outcome = spool.discard_staged(digest());
            assert!(io.all_fired(), "{case}: fault did not fire");
            check_discard_staged_outcome(&case, &root, spool, outcome)?;
        }
    }
    Ok(())
}

#[test]
fn f4_every_single_orphan_discard_fault_is_typed_and_reconciles() -> TestResult {
    let name = "f4_orphan_discard_sweep";
    let payloads: [&[u8]; 2] = [b"orphan-one", b"orphan-two"];
    let template = fresh_root(&format!("{name}_template"))?;
    make_orphans(&template, &payloads)?;
    let after_open = open_probe(&template)?;
    let after_discard = probe_calls(&template, |spool| {
        spool.discard_orphaned_staging().map(|_| ())
    })?;
    let mut cases = 0_usize;
    for mode in Mode::ALL {
        for call in SpoolIoCall::ALL {
            let before = after_open.calls(call);
            for step in 1..=after_discard.calls(call) - before {
                cases += 1;
                let case = format!("{name}_{mode:?}_{call}_{step}");
                let root = fresh_root(&case)?;
                make_orphans(&root, &payloads)?;
                let plan = mode.plan(SpoolFaultPlan::new(), call, before + step);
                let (mut spool, io) = open_faulted(&root, plan)?;
                let initial = spool.occupied_bytes()?;
                let syncs_before = io.calls(SpoolIoCall::SyncDirectory);
                let outcome = spool.discard_orphaned_staging();
                assert!(io.all_fired(), "{case}: fault did not fire");
                let poisoned = is_poisoned(&spool);
                match &outcome {
                    Ok(receipt) => {
                        assert!(!poisoned, "{case}");
                        assert_eq!(receipt.removed, 2, "{case}");
                        assert_eq!(receipt.released_bytes, initial, "{case}");
                        assert_eq!(spool.occupied_bytes()?, 0, "{case}");
                    }
                    Err(error) if poisoned => {
                        assert!(
                            matches!(error, SpoolError::DiscardIndeterminate { .. }),
                            "{case}: {error:?}"
                        );
                    }
                    Err(SpoolError::Io { .. } | SpoolError::InvalidLayout { .. }) => {
                        assert!(
                            !matches!(call, SpoolIoCall::SyncDirectory),
                            "{case}: an unconfirmed fsync must poison"
                        );
                        if spool.orphaned_staging().count() < payloads.len() {
                            assert_eq!(
                                io.calls(SpoolIoCall::SyncDirectory),
                                syncs_before + 1,
                                "{case}: released removals must be fsynced"
                            );
                        }
                    }
                    Err(other) => {
                        return Err(format!("{case}: unpoisoned untyped outcome {other:?}").into());
                    }
                }
                let live = (!poisoned).then(|| (orphan_paths(&spool), spool.occupied_bytes()));
                drop(spool);
                let reopened = StagingSpool::open(&root, roomy())?;
                let on_disk = dir_names(&root.join(SPOOL_STAGING_DIR))?;
                assert_eq!(orphan_paths(&reopened).len(), on_disk.len(), "{case}");
                if let Some((paths, bytes)) = live {
                    assert_eq!(orphan_paths(&reopened), paths, "{case}");
                    assert_eq!(reopened.occupied_bytes()?, bytes?, "{case}");
                }
            }
        }
    }
    // Two inspections, two removals, one directory fsync.
    assert_eq!(cases, 2 * 5);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Finding 5: a verified object stays protected from discard across reopen
// ---------------------------------------------------------------------------------------------

#[test]
fn f5_verified_object_cannot_be_discarded_after_reopen() -> TestResult {
    let root = fresh_root("f5_verified_object_cannot_be_discarded_after_reopen")?;
    {
        let mut spool = StagingSpool::open(&root, roomy())?;
        spool.stage(digest(), PAYLOAD)?;
        assert_eq!(spool.verify(digest())?, SpoolObjectState::Verified);
    }
    let mut reopened = StagingSpool::open(&root, roomy())?;
    assert!(reopened.recovery_report().is_clean());
    assert_eq!(
        expect_err(reopened.discard_staged(digest()))?,
        SpoolError::VerificationHeld { digest: digest() }
    );
    assert!(object_file(&root, digest()).exists());
    assert_eq!(reopened.read(digest())?, PAYLOAD.to_vec());
    assert_eq!(reopened.occupied_bytes()?, PAYLOAD.len() as u64);
    drop(reopened);
    // The protection survives any number of reopens.
    let mut again = StagingSpool::open(&root, roomy())?;
    expect_err(again.discard_staged(digest()))?;
    assert!(object_file(&root, digest()).exists());
    Ok(())
}

#[test]
fn f5_never_verified_object_stays_discardable_after_reopen() -> TestResult {
    let root = fresh_root("f5_never_verified_object_stays_discardable_after_reopen")?;
    let other = ContentDigest::sha256(b"verified-neighbour");
    {
        let mut spool = StagingSpool::open(&root, roomy())?;
        spool.stage(digest(), PAYLOAD)?;
        spool.stage(other, b"verified-neighbour")?;
        spool.verify(other)?;
    }
    let mut reopened = StagingSpool::open(&root, roomy())?;
    assert_eq!(reopened.discard_staged(digest())?, PAYLOAD.len() as u64);
    assert!(!object_file(&root, digest()).exists());
    expect_err(reopened.discard_staged(other))?;
    Ok(())
}

#[test]
fn f5_objects_of_a_spool_without_holds_fail_closed_against_discard() -> TestResult {
    let root = fresh_root("f5_objects_of_a_spool_without_holds")?;
    {
        let mut spool = StagingSpool::open(&root, roomy())?;
        spool.stage(digest(), PAYLOAD)?;
    }
    // A spool written before verification holds existed has no hold directory: nothing on disk
    // says whether its objects were verified, so none of them may be discarded.
    match fs::remove_dir_all(root.join(SPOOL_HOLDS_DIR)) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut reopened = StagingSpool::open(&root, roomy())?;
    assert_eq!(reopened.recovery_report().admitted, vec![digest()]);
    assert!(reopened.recovery_report().is_clean());
    assert_eq!(
        expect_err(reopened.discard_staged(digest()))?,
        SpoolError::VerificationHeld { digest: digest() }
    );
    // The migration completed: holds are in place and no migration directory remains.
    assert_eq!(dir_names(&root.join(SPOOL_HOLDS_DIR))?, vec![hex(digest())]);
    assert!(!root.join(SPOOL_HOLDS_MIGRATION_DIR).exists());
    assert!(object_file(&root, digest()).exists());
    drop(reopened);
    let mut again = StagingSpool::open(&root, roomy())?;
    expect_err(again.discard_staged(digest()))?;
    assert!(object_file(&root, digest()).exists());
    Ok(())
}

#[test]
fn f5_verified_object_that_vanished_is_reported_corrupt_on_reopen() -> TestResult {
    let root = fresh_root("f5_verified_object_that_vanished")?;
    {
        let mut spool = StagingSpool::open(&root, roomy())?;
        spool.stage(digest(), PAYLOAD)?;
        spool.verify(digest())?;
    }
    fs::remove_file(object_file(&root, digest()))?;
    let reopened = StagingSpool::open(&root, roomy())?;
    assert!(!reopened.recovery_report().is_clean());
    assert_eq!(
        reopened.state(digest()),
        Some(SpoolObjectState::Corrupt(
            fss_object::CorruptionKind::Vanished
        ))
    );
    assert_eq!(reopened.occupied_bytes()?, 0);
    Ok(())
}

#[test]
fn f5_unconfirmed_hold_is_never_verified_and_blocks_discard_until_retried() -> TestResult {
    let root = fresh_root("f5_unconfirmed_hold")?;
    let probe = probe_calls(&fresh_root("f5_unconfirmed_hold_probe")?, |spool| {
        spool.stage(digest(), PAYLOAD).map(|_| ())
    })?;
    let plan = SpoolFaultPlan::new().fail_after_applying(
        SpoolIoCall::CreateNew,
        probe.calls(SpoolIoCall::CreateNew) + 1,
        ErrorKind::Other,
    );
    let (mut spool, io) = open_faulted(&root, plan)?;
    spool.stage(digest(), PAYLOAD)?;
    let outcome = spool.verify(digest());
    assert!(
        io.all_fired(),
        "verify must place a hold through the capability"
    );
    assert_eq!(
        expect_err(outcome)?,
        SpoolError::HoldIndeterminate {
            digest: digest(),
            kind: ErrorKind::Other,
        }
    );
    assert_eq!(spool.state(digest()), Some(SpoolObjectState::Staged));
    // The hold may be on disk, so the object must not be discardable.
    assert_eq!(
        expect_err(spool.discard_staged(digest()))?,
        SpoolError::VerificationHeld { digest: digest() }
    );
    assert!(object_file(&root, digest()).exists());
    assert_eq!(spool.verify(digest())?, SpoolObjectState::Verified);
    drop(spool);
    let mut reopened = StagingSpool::open(&root, roomy())?;
    expect_err(reopened.discard_staged(digest()))?;
    Ok(())
}

#[test]
fn f5_every_single_verify_fault_is_typed_and_never_unprotects() -> TestResult {
    let name = "f5_verify_sweep";
    let after_stage = probe_calls(&fresh_root(&format!("{name}_stage_probe"))?, |spool| {
        spool.stage(digest(), PAYLOAD).map(|_| ())
    })?;
    let after_verify = probe_calls(&fresh_root(&format!("{name}_verify_probe"))?, |spool| {
        spool.stage(digest(), PAYLOAD)?;
        spool.verify(digest()).map(|_| ())
    })?;
    let mut hold_calls = 0_u64;
    for mode in Mode::ALL {
        for call in SpoolIoCall::ALL {
            let before = after_stage.calls(call);
            for step in 1..=after_verify.calls(call) - before {
                let case = format!("{name}_{mode:?}_{call}_{step}");
                if matches!(
                    call,
                    SpoolIoCall::CreateNew | SpoolIoCall::SyncFile | SpoolIoCall::SyncDirectory
                ) {
                    hold_calls += 1;
                }
                let root = fresh_root(&case)?;
                let plan = mode.plan(SpoolFaultPlan::new(), call, before + step);
                let (mut spool, io) = open_faulted(&root, plan)?;
                spool.stage(digest(), PAYLOAD)?;
                let outcome = spool.verify(digest());
                assert!(io.all_fired(), "{case}: fault did not fire");
                assert!(!is_poisoned(&spool), "{case}");
                match outcome {
                    Ok(state) => assert_eq!(state, SpoolObjectState::Verified, "{case}"),
                    Err(error) => {
                        assert!(
                            matches!(
                                error,
                                SpoolError::HoldIndeterminate { .. } | SpoolError::Io { .. }
                            ),
                            "{case}: {error:?}"
                        );
                        assert_ne!(
                            spool.state(digest()),
                            Some(SpoolObjectState::Verified),
                            "{case}: {error:?}"
                        );
                    }
                }
                let verified = spool.state(digest()) == Some(SpoolObjectState::Verified);
                if verified {
                    expect_err(spool.discard_staged(digest()))?;
                }
                drop(spool);
                let mut reopened = StagingSpool::open(&root, roomy())?;
                if verified {
                    // Once verify reported Verified, the hold is durable.
                    expect_err(reopened.discard_staged(digest()))?;
                    assert!(object_file(&root, digest()).exists(), "{case}");
                }
            }
        }
    }
    assert!(
        hold_calls > 0,
        "verify must place a hold through the capability"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Finding 6: the envelope encoder returns typed errors, never an empty or mislabeled envelope
// ---------------------------------------------------------------------------------------------

#[test]
fn f6_encoder_returns_typed_errors_instead_of_empty_bytes() -> TestResult {
    // A BLAKE3 digest would otherwise be written under the envelope's SHA-256 tag.
    let blake3 = ContentDigest::new(DigestAlgorithm::Blake3, digest().bytes());
    assert_eq!(
        encode_spool_object(blake3, PAYLOAD),
        Err(SpoolError::UnsupportedAlgorithm(DigestAlgorithm::Blake3))
    );
    let wrong = ContentDigest::sha256(b"some-other-payload");
    assert_eq!(
        encode_spool_object(wrong, PAYLOAD),
        Err(SpoolError::DigestMismatch {
            declared: wrong,
            computed: digest(),
        })
    );
    // The encoder is exactly the envelope `stage` writes.
    let root = fresh_root("f6_encoder_matches_the_staged_envelope")?;
    let mut spool = StagingSpool::open(&root, roomy())?;
    spool.stage(digest(), PAYLOAD)?;
    assert_eq!(
        encode_spool_object(digest(), PAYLOAD)?,
        fs::read(object_file(&root, digest()))?
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Finding 7: corruption found in session is charged exactly as a reopen charges it
// ---------------------------------------------------------------------------------------------

#[test]
fn f7_in_session_corruption_is_charged_as_a_reopen_charges_it() -> TestResult {
    let root = fresh_root("f7_in_session_corruption_charge")?;
    let mut spool = StagingSpool::open(&root, roomy())?;
    spool.stage(digest(), PAYLOAD)?;
    let other = spool.stage_bytes(b"untouched-neighbour")?;
    {
        let mut file = OpenOptions::new()
            .append(true)
            .open(object_file(&root, digest()))?;
        file.write_all(b"appended-garbage")?;
        file.sync_all()?;
    }
    let error = expect_err(spool.verify(digest()))?;
    assert!(matches!(error, SpoolError::Corrupt { .. }), "{error:?}");
    let live = spool.occupied_bytes()?;
    let file_len = fs::metadata(object_file(&root, digest()))?.len();
    assert_eq!(live, file_len + other.payload_len);
    drop(spool);
    let reopened = StagingSpool::open(&root, roomy())?;
    assert_eq!(reopened.occupied_bytes()?, live);
    Ok(())
}

#[test]
fn f7_in_session_truncation_is_charged_as_a_reopen_charges_it() -> TestResult {
    let root = fresh_root("f7_in_session_truncation_charge")?;
    let mut spool = StagingSpool::open(&root, roomy())?;
    spool.stage(digest(), PAYLOAD)?;
    OpenOptions::new()
        .write(true)
        .open(object_file(&root, digest()))?
        .set_len(10)?;
    let error = expect_err(spool.stage(digest(), PAYLOAD))?;
    assert!(matches!(error, SpoolError::Corrupt { .. }), "{error:?}");
    assert_eq!(spool.occupied_bytes()?, 10);
    drop(spool);
    let reopened = StagingSpool::open(&root, roomy())?;
    assert_eq!(reopened.occupied_bytes()?, 10);
    Ok(())
}
