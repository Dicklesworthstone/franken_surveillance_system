#![forbid(unsafe_code)]
//! Deterministic I/O fault injection for the staging spool (FSS-017, fss-x4a.7.5).
//!
//! Every test drives the spool through `FaultInjectingSpoolIo`, fails one exact filesystem call,
//! asserts the exact typed outcome, and then reopens the same root with the host capability to
//! prove the failed instance's accounting matched what is actually on disk. Occurrence numbers
//! are derived from a plan-free probe run on a separate fresh root, never hard-coded, so a change
//! in how many calls `open` makes cannot silently retarget a fault.

use std::error::Error;
use std::fmt::Debug;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fss_core::ContentDigest;
use fss_object::{
    FaultInjectingSpoolIo, ObjectError, OrphanedStaging, SPOOL_OBJECT_HEADER_LEN,
    SPOOL_OBJECTS_DIR, SPOOL_STAGING_DIR, SpoolError, SpoolFaultPlan, SpoolIoCall,
    SpoolIoOperation, SpoolLimits, SpoolObjectState, StageOutcome, StagePhase, StagingSpool,
    VerifiedObjectCatalog,
};

type TestResult = Result<(), Box<dyn Error>>;

const HEADER: u64 = SPOOL_OBJECT_HEADER_LEN as u64;
const PAYLOAD: &[u8] = b"fault-injected-capsule-payload";

fn payload_len() -> u64 {
    PAYLOAD.len() as u64
}

fn digest() -> ContentDigest {
    ContentDigest::sha256(PAYLOAD)
}

/// Returns a not-yet-existing directory owned by exactly one test, named after that test.
fn fresh_root(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("staging_spool_io_faults")
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

fn staging_relative(digest: ContentDigest, attempt: u32) -> PathBuf {
    Path::new(SPOOL_STAGING_DIR).join(format!("{}.{attempt}.tmp", hex(digest)))
}

fn staging_file(root: &Path, digest: ContentDigest, attempt: u32) -> PathBuf {
    root.join(staging_relative(digest, attempt))
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

/// Counts the calls a fresh-root open plus `prefix` make, on a separate probe root.
fn probe_calls(
    probe_name: &str,
    prefix: impl FnOnce(&mut StagingSpool) -> Result<(), SpoolError>,
) -> Result<Arc<FaultInjectingSpoolIo>, Box<dyn Error>> {
    let root = fresh_root(probe_name)?;
    let (mut spool, io) = open_faulted(&root, SpoolFaultPlan::new())?;
    prefix(&mut spool)?;
    Ok(io)
}

fn open_calls(test_name: &str) -> Result<Arc<FaultInjectingSpoolIo>, Box<dyn Error>> {
    probe_calls(&format!("{test_name}_probe"), |_| Ok(()))
}

// ---------------------------------------------------------------------------------------------
// Shared outcome checks
// ---------------------------------------------------------------------------------------------

/// Checks a failed pre-rename ingest: nothing admitted, the in-session orphan list is exactly the
/// staging directory, the failed instance's quota equals a host reopen's, and a retry succeeds.
/// Returns the orphans the failed instance reported.
fn assert_nothing_admitted(
    root: &Path,
    spool: StagingSpool,
) -> Result<Vec<OrphanedStaging>, Box<dyn Error>> {
    let digest = digest();
    assert_eq!(spool.state(digest), None);
    assert_eq!(spool.object_count(), 0);
    assert!(!object_file(root, digest).exists());
    assert!(dir_names(&root.join(SPOOL_OBJECTS_DIR))?.is_empty());
    assert_eq!(expect_err(spool.read(digest))?, SpoolError::Missing(digest));
    assert_eq!(
        spool.require_verified(digest),
        Err(ObjectError::Missing(digest))
    );

    let orphans: Vec<OrphanedStaging> = spool.orphaned_staging().cloned().collect();
    let mut orphan_names: Vec<String> = orphans
        .iter()
        .filter_map(|orphan| orphan.path.file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    orphan_names.sort();
    assert_eq!(dir_names(&root.join(SPOOL_STAGING_DIR))?, orphan_names);
    let orphan_bytes: u64 = orphans.iter().map(|orphan| orphan.bytes).sum();
    assert_eq!(spool.occupied_bytes()?, orphan_bytes);
    drop(spool);

    let mut reopened = StagingSpool::open(root, roomy())?;
    let report = reopened.recovery_report().clone();
    assert!(report.admitted.is_empty());
    assert!(report.corrupt.is_empty());
    assert!(report.foreign.is_empty());
    assert_eq!(report.orphaned_staging, orphans);
    assert_eq!(reopened.occupied_bytes()?, orphan_bytes);

    assert_eq!(
        reopened.stage(digest, PAYLOAD)?.outcome,
        StageOutcome::NewlyStaged
    );
    assert_eq!(reopened.read(digest)?, PAYLOAD.to_vec());
    assert_eq!(reopened.verify(digest)?, SpoolObjectState::Verified);
    assert_eq!(reopened.occupied_bytes()?, orphan_bytes + payload_len());
    assert_eq!(
        reopened.discard_orphaned_staging()?.released_bytes,
        orphan_bytes
    );
    assert_eq!(reopened.occupied_bytes()?, payload_len());
    Ok(orphans)
}

/// Runs one ingest under `plan` and checks a pre-rename failure end to end.
fn run_pre_rename_failure(
    test_name: &str,
    plan: SpoolFaultPlan,
    expected: impl FnOnce(&Path) -> SpoolError,
) -> Result<(Arc<FaultInjectingSpoolIo>, Vec<OrphanedStaging>), Box<dyn Error>> {
    let root = fresh_root(test_name)?;
    let (mut spool, io) = open_faulted(&root, plan)?;
    assert_eq!(expect_err(spool.stage(digest(), PAYLOAD))?, expected(&root));
    assert!(io.all_fired(), "{test_name}: planned fault did not fire");
    let orphans = assert_nothing_admitted(&root, spool)?;
    Ok((io, orphans))
}

/// Checks an indeterminate ingest: the instance is poisoned and never reports the object as
/// staged or verified, its quota equals a host reopen's, and the reopen admits it as `Staged`.
fn assert_indeterminate_then_reconciled(root: &Path, mut spool: StagingSpool) -> TestResult {
    let digest = digest();
    assert_eq!(spool.state(digest), None);
    assert_eq!(spool.object_count(), 0);
    assert_eq!(expect_err(spool.read(digest))?, SpoolError::Poisoned);
    assert_eq!(expect_err(spool.verify(digest))?, SpoolError::Poisoned);
    assert_eq!(
        expect_err(spool.stage(digest, PAYLOAD))?,
        SpoolError::Poisoned
    );
    assert_eq!(
        spool.require_verified(digest),
        Err(ObjectError::Unavailable(digest))
    );
    assert!(dir_names(&root.join(SPOOL_STAGING_DIR))?.is_empty());
    assert!(object_file(root, digest).exists());
    let in_session = spool.occupied_bytes()?;
    drop(spool);

    let mut reopened = StagingSpool::open(root, roomy())?;
    assert!(reopened.recovery_report().is_clean());
    assert_eq!(reopened.recovery_report().admitted, vec![digest]);
    assert_eq!(reopened.state(digest), Some(SpoolObjectState::Staged));
    assert_eq!(reopened.occupied_bytes()?, in_session);
    assert_eq!(
        reopened.require_verified(digest),
        Err(ObjectError::NotVerified(digest))
    );
    assert_eq!(reopened.read(digest)?, PAYLOAD.to_vec());
    assert_eq!(
        reopened.stage(digest, PAYLOAD)?.outcome,
        StageOutcome::AlreadyPresent
    );
    Ok(())
}

fn run_indeterminate(test_name: &str, plan: SpoolFaultPlan, expected: SpoolError) -> TestResult {
    let root = fresh_root(test_name)?;
    let (mut spool, io) = open_faulted(&root, plan)?;
    assert_eq!(expect_err(spool.stage(digest(), PAYLOAD))?, expected);
    assert!(io.all_fired(), "{test_name}: planned fault did not fire");
    assert_indeterminate_then_reconciled(&root, spool)
}

// ---------------------------------------------------------------------------------------------
// Ingest: one failure per step, before the rename
// ---------------------------------------------------------------------------------------------

#[test]
fn staging_create_failure_admits_nothing() -> TestResult {
    let name = "staging_create_failure_admits_nothing";
    let base = open_calls(name)?;
    let plan = SpoolFaultPlan::new().fail(
        SpoolIoCall::CreateNew,
        base.calls(SpoolIoCall::CreateNew) + 1,
        ErrorKind::PermissionDenied,
    );
    let (io, orphans) = run_pre_rename_failure(name, plan, |root| SpoolError::Io {
        operation: SpoolIoOperation::CreateStaging,
        path: staging_file(root, digest(), 0),
        kind: ErrorKind::PermissionDenied,
    })?;
    assert!(orphans.is_empty());
    assert_eq!(io.calls(SpoolIoCall::Write), 0);
    Ok(())
}

#[test]
fn staging_write_failure_admits_nothing_and_removes_the_temp() -> TestResult {
    let name = "staging_write_failure_admits_nothing_and_removes_the_temp";
    let plan = SpoolFaultPlan::new().fail(SpoolIoCall::Write, 1, ErrorKind::StorageFull);
    let (io, orphans) = run_pre_rename_failure(name, plan, |root| SpoolError::Io {
        operation: SpoolIoOperation::WriteStaging,
        path: staging_file(root, digest(), 0),
        kind: ErrorKind::StorageFull,
    })?;
    assert!(orphans.is_empty());
    assert_eq!(io.calls(SpoolIoCall::SyncFile), 0);
    assert_eq!(io.calls(SpoolIoCall::Rename), 0);
    assert_eq!(io.calls(SpoolIoCall::RemoveFile), 1);
    Ok(())
}

#[test]
fn torn_staging_write_admits_nothing() -> TestResult {
    let name = "torn_staging_write_admits_nothing";
    // The bytes land, then the write reports failure.
    let plan = SpoolFaultPlan::new().fail_after_applying(SpoolIoCall::Write, 1, ErrorKind::Other);
    let (_, orphans) = run_pre_rename_failure(name, plan, |root| SpoolError::Io {
        operation: SpoolIoOperation::WriteStaging,
        path: staging_file(root, digest(), 0),
        kind: ErrorKind::Other,
    })?;
    assert!(orphans.is_empty());
    Ok(())
}

#[test]
fn staging_fsync_failure_admits_nothing() -> TestResult {
    let name = "staging_fsync_failure_admits_nothing";
    let plan = SpoolFaultPlan::new().fail(SpoolIoCall::SyncFile, 1, ErrorKind::Other);
    let (io, orphans) = run_pre_rename_failure(name, plan, |root| SpoolError::Io {
        operation: SpoolIoOperation::SyncStaging,
        path: staging_file(root, digest(), 0),
        kind: ErrorKind::Other,
    })?;
    assert!(orphans.is_empty());
    assert_eq!(io.calls(SpoolIoCall::OpenRead), 0);
    assert_eq!(io.calls(SpoolIoCall::Rename), 0);
    Ok(())
}

#[test]
fn readback_inspect_failure_admits_nothing() -> TestResult {
    let name = "readback_inspect_failure_admits_nothing";
    let base = open_calls(name)?;
    // Stage inspects the object name first, then the staging file during read-back.
    let plan = SpoolFaultPlan::new().fail(
        SpoolIoCall::SymlinkMetadata,
        base.calls(SpoolIoCall::SymlinkMetadata) + 2,
        ErrorKind::PermissionDenied,
    );
    let (io, orphans) = run_pre_rename_failure(name, plan, |root| SpoolError::Io {
        operation: SpoolIoOperation::Inspect,
        path: staging_file(root, digest(), 0),
        kind: ErrorKind::PermissionDenied,
    })?;
    assert!(orphans.is_empty());
    assert_eq!(io.calls(SpoolIoCall::SyncFile), 1);
    assert_eq!(io.calls(SpoolIoCall::Rename), 0);
    Ok(())
}

#[test]
fn readback_open_failure_admits_nothing() -> TestResult {
    let name = "readback_open_failure_admits_nothing";
    let base = open_calls(name)?;
    let plan = SpoolFaultPlan::new().fail(
        SpoolIoCall::OpenRead,
        base.calls(SpoolIoCall::OpenRead) + 1,
        ErrorKind::PermissionDenied,
    );
    let (io, orphans) = run_pre_rename_failure(name, plan, |root| SpoolError::Io {
        operation: SpoolIoOperation::ReadObject,
        path: staging_file(root, digest(), 0),
        kind: ErrorKind::PermissionDenied,
    })?;
    assert!(orphans.is_empty());
    assert_eq!(io.calls(SpoolIoCall::Rename), 0);
    Ok(())
}

#[test]
fn readback_read_failure_admits_nothing() -> TestResult {
    let name = "readback_read_failure_admits_nothing";
    let base = open_calls(name)?;
    let plan = SpoolFaultPlan::new().fail(
        SpoolIoCall::Read,
        base.calls(SpoolIoCall::Read) + 1,
        ErrorKind::InvalidData,
    );
    let (io, orphans) = run_pre_rename_failure(name, plan, |root| SpoolError::Io {
        operation: SpoolIoOperation::ReadObject,
        path: staging_file(root, digest(), 0),
        kind: ErrorKind::InvalidData,
    })?;
    assert!(orphans.is_empty());
    assert_eq!(io.calls(SpoolIoCall::Rename), 0);
    Ok(())
}

#[test]
fn rename_failure_admits_nothing() -> TestResult {
    let name = "rename_failure_admits_nothing";
    let plan = SpoolFaultPlan::new().fail(SpoolIoCall::Rename, 1, ErrorKind::PermissionDenied);
    let (io, orphans) = run_pre_rename_failure(name, plan, |root| SpoolError::Io {
        operation: SpoolIoOperation::Rename,
        path: object_file(root, digest()),
        kind: ErrorKind::PermissionDenied,
    })?;
    assert!(orphans.is_empty());
    assert_eq!(io.calls(SpoolIoCall::RemoveFile), 1);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Cleanup failure: the temp file cannot be removed
// ---------------------------------------------------------------------------------------------

#[test]
fn cleanup_remove_failure_reports_and_charges_the_orphan() -> TestResult {
    let name = "cleanup_remove_failure_reports_and_charges_the_orphan";
    let plan = SpoolFaultPlan::new()
        .fail(SpoolIoCall::SyncFile, 1, ErrorKind::Other)
        .fail(SpoolIoCall::RemoveFile, 1, ErrorKind::PermissionDenied);
    let (_, orphans) = run_pre_rename_failure(name, plan, |root| SpoolError::Io {
        operation: SpoolIoOperation::SyncStaging,
        path: staging_file(root, digest(), 0),
        kind: ErrorKind::Other,
    })?;
    // The failed instance reports exactly what a reopen finds, and charges it.
    assert_eq!(
        orphans,
        vec![OrphanedStaging {
            path: staging_relative(digest(), 0),
            bytes: HEADER + payload_len(),
            claimed_digest: digest(),
        }]
    );
    Ok(())
}

#[test]
fn cleanup_failure_leaves_the_instance_usable_and_exact() -> TestResult {
    let root = fresh_root("cleanup_failure_leaves_the_instance_usable_and_exact")?;
    let plan = SpoolFaultPlan::new()
        .fail(SpoolIoCall::Rename, 1, ErrorKind::PermissionDenied)
        .fail(SpoolIoCall::RemoveFile, 1, ErrorKind::PermissionDenied);
    let (mut spool, io) = open_faulted(&root, plan)?;
    assert_eq!(
        expect_err(spool.stage(digest(), PAYLOAD))?,
        SpoolError::Io {
            operation: SpoolIoOperation::Rename,
            path: object_file(&root, digest()),
            kind: ErrorKind::PermissionDenied,
        }
    );
    assert!(io.all_fired());
    let orphan_len = HEADER + payload_len();
    assert_eq!(spool.occupied_bytes()?, orphan_len);

    // The same instance retries under the next staging name and still accounts exactly.
    assert_eq!(
        spool.stage(digest(), PAYLOAD)?.outcome,
        StageOutcome::NewlyStaged
    );
    assert_eq!(spool.occupied_bytes()?, orphan_len + payload_len());
    let discard = spool.discard_orphaned_staging()?;
    assert_eq!(discard.removed, 1);
    assert_eq!(discard.released_bytes, orphan_len);
    assert_eq!(spool.occupied_bytes()?, payload_len());
    assert!(dir_names(&root.join(SPOOL_STAGING_DIR))?.is_empty());
    drop(spool);

    let reopened = StagingSpool::open(&root, roomy())?;
    assert!(reopened.recovery_report().is_clean());
    assert_eq!(reopened.occupied_bytes()?, payload_len());
    Ok(())
}

#[test]
fn discard_remove_failure_keeps_the_orphan_charged() -> TestResult {
    let root = fresh_root("discard_remove_failure_keeps_the_orphan_charged")?;
    {
        let mut spool = StagingSpool::open(&root, roomy())?;
        spool.inject_crash_after(StagePhase::AfterStagingWrite);
        expect_err(spool.stage(digest(), PAYLOAD))?;
    }
    let orphan_len = HEADER + payload_len();
    let plan = SpoolFaultPlan::new().fail(SpoolIoCall::RemoveFile, 1, ErrorKind::PermissionDenied);
    let (mut spool, io) = open_faulted(&root, plan)?;
    assert_eq!(spool.occupied_bytes()?, orphan_len);
    assert_eq!(
        expect_err(spool.discard_orphaned_staging())?,
        SpoolError::Io {
            operation: SpoolIoOperation::RemoveStaging,
            path: staging_file(&root, digest(), 0),
            kind: ErrorKind::PermissionDenied,
        }
    );
    assert!(io.all_fired());
    assert_eq!(spool.orphaned_staging().count(), 1);
    assert_eq!(spool.occupied_bytes()?, orphan_len);
    assert!(staging_file(&root, digest(), 0).exists());

    let discard = spool.discard_orphaned_staging()?;
    assert_eq!(discard.removed, 1);
    assert_eq!(discard.released_bytes, orphan_len);
    assert_eq!(spool.occupied_bytes()?, 0);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Ingest: failures at or after the rename are indeterminate, never Verified
// ---------------------------------------------------------------------------------------------

#[test]
fn rename_reported_failed_after_applying_is_indeterminate() -> TestResult {
    run_indeterminate(
        "rename_reported_failed_after_applying_is_indeterminate",
        SpoolFaultPlan::new().fail_after_applying(SpoolIoCall::Rename, 1, ErrorKind::Other),
        SpoolError::StageIndeterminate {
            digest: digest(),
            operation: SpoolIoOperation::Rename,
            kind: ErrorKind::Other,
        },
    )
}

#[test]
fn objects_directory_fsync_failure_is_indeterminate_never_verified() -> TestResult {
    let name = "objects_directory_fsync_failure_is_indeterminate_never_verified";
    let base = open_calls(name)?;
    run_indeterminate(
        name,
        SpoolFaultPlan::new().fail(
            SpoolIoCall::SyncDirectory,
            base.calls(SpoolIoCall::SyncDirectory) + 1,
            ErrorKind::Other,
        ),
        SpoolError::StageIndeterminate {
            digest: digest(),
            operation: SpoolIoOperation::SyncDirectory,
            kind: ErrorKind::Other,
        },
    )
}

#[test]
fn staging_directory_fsync_failure_is_indeterminate_never_verified() -> TestResult {
    let name = "staging_directory_fsync_failure_is_indeterminate_never_verified";
    let base = open_calls(name)?;
    run_indeterminate(
        name,
        SpoolFaultPlan::new().fail(
            SpoolIoCall::SyncDirectory,
            base.calls(SpoolIoCall::SyncDirectory) + 2,
            ErrorKind::StorageFull,
        ),
        SpoolError::StageIndeterminate {
            digest: digest(),
            operation: SpoolIoOperation::SyncDirectory,
            kind: ErrorKind::StorageFull,
        },
    )
}

// ---------------------------------------------------------------------------------------------
// Short writes
// ---------------------------------------------------------------------------------------------

#[test]
fn zero_byte_write_is_a_typed_short_write() -> TestResult {
    let name = "zero_byte_write_is_a_typed_short_write";
    let plan = SpoolFaultPlan::new().short_write(1, 0);
    let (io, orphans) = run_pre_rename_failure(name, plan, |root| SpoolError::ShortWrite {
        path: staging_file(root, digest(), 0),
        written: 0,
        expected: HEADER + payload_len(),
    })?;
    assert!(orphans.is_empty());
    assert_eq!(io.calls(SpoolIoCall::SyncFile), 0);
    Ok(())
}

#[test]
fn write_that_stalls_after_a_partial_write_is_a_typed_short_write() -> TestResult {
    let name = "write_that_stalls_after_a_partial_write_is_a_typed_short_write";
    let plan = SpoolFaultPlan::new().short_write(1, 7).short_write(2, 0);
    let (io, orphans) = run_pre_rename_failure(name, plan, |root| SpoolError::ShortWrite {
        path: staging_file(root, digest(), 0),
        written: 7,
        expected: HEADER + payload_len(),
    })?;
    assert!(orphans.is_empty());
    assert_eq!(io.calls(SpoolIoCall::Write), 2);
    Ok(())
}

#[test]
fn partial_writes_are_resumed_and_read_back() -> TestResult {
    let root = fresh_root("partial_writes_are_resumed_and_read_back")?;
    let plan = SpoolFaultPlan::new().short_write(1, 5).short_write(2, 1);
    let (mut spool, io) = open_faulted(&root, plan)?;
    let receipt = spool.stage(digest(), PAYLOAD)?;
    assert_eq!(receipt.outcome, StageOutcome::NewlyStaged);
    assert_eq!(receipt.state, SpoolObjectState::Staged);
    assert!(io.all_fired());
    assert_eq!(io.calls(SpoolIoCall::Write), 3);
    assert_eq!(
        fs::metadata(object_file(&root, digest()))?.len(),
        HEADER + payload_len()
    );
    assert_eq!(spool.read(digest())?, PAYLOAD.to_vec());
    assert_eq!(spool.occupied_bytes()?, payload_len());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Read path
// ---------------------------------------------------------------------------------------------

#[test]
fn read_path_io_failures_are_typed_and_never_mark_corrupt() -> TestResult {
    let name = "read_path_io_failures_are_typed_and_never_mark_corrupt";
    let base = probe_calls(&format!("{name}_probe"), |spool| {
        spool.stage(digest(), PAYLOAD)?;
        spool.verify(digest())?;
        Ok(())
    })?;
    let inspect = base.calls(SpoolIoCall::SymlinkMetadata);
    let open = base.calls(SpoolIoCall::OpenRead);
    let read = base.calls(SpoolIoCall::Read);
    let plan = SpoolFaultPlan::new()
        // `read`: inspecting the object fails.
        .fail(
            SpoolIoCall::SymlinkMetadata,
            inspect + 1,
            ErrorKind::PermissionDenied,
        )
        // `verify`: opening the object fails.
        .fail(SpoolIoCall::OpenRead, open + 1, ErrorKind::PermissionDenied)
        // `require_verified`: reading the object fails.
        .fail(SpoolIoCall::Read, read + 1, ErrorKind::Other)
        // idempotent re-stage: reading the stored object fails.
        .fail(SpoolIoCall::Read, read + 2, ErrorKind::InvalidData);

    let root = fresh_root(name)?;
    let (mut spool, io) = open_faulted(&root, plan)?;
    spool.stage(digest(), PAYLOAD)?;
    assert_eq!(spool.verify(digest())?, SpoolObjectState::Verified);
    let path = object_file(&root, digest());

    assert_eq!(
        expect_err(spool.read(digest()))?,
        SpoolError::Io {
            operation: SpoolIoOperation::Inspect,
            path: path.clone(),
            kind: ErrorKind::PermissionDenied,
        }
    );
    assert_eq!(spool.state(digest()), Some(SpoolObjectState::Verified));

    assert_eq!(
        expect_err(spool.verify(digest()))?,
        SpoolError::Io {
            operation: SpoolIoOperation::ReadObject,
            path: path.clone(),
            kind: ErrorKind::PermissionDenied,
        }
    );
    // An I/O failure is not evidence of corruption.
    assert_eq!(spool.state(digest()), Some(SpoolObjectState::Verified));

    assert_eq!(
        spool.require_verified(digest()),
        Err(ObjectError::Unavailable(digest()))
    );

    assert_eq!(
        expect_err(spool.stage(digest(), PAYLOAD))?,
        SpoolError::Io {
            operation: SpoolIoOperation::ReadObject,
            path,
            kind: ErrorKind::InvalidData,
        }
    );
    assert!(io.all_fired());

    // Transient failures leave the instance live and the accounting untouched.
    assert_eq!(spool.state(digest()), Some(SpoolObjectState::Verified));
    assert_eq!(spool.object_count(), 1);
    assert_eq!(spool.occupied_bytes()?, payload_len());
    assert_eq!(spool.read(digest())?, PAYLOAD.to_vec());
    spool.require_verified(digest())?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Exhaustive single-fault sweeps
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Mode {
    Fail,
    FailAfterApplying,
}

impl Mode {
    fn plan(self, call: SpoolIoCall, occurrence: u64) -> SpoolFaultPlan {
        match self {
            Self::Fail => SpoolFaultPlan::new().fail(call, occurrence, ErrorKind::Other),
            Self::FailAfterApplying => {
                SpoolFaultPlan::new().fail_after_applying(call, occurrence, ErrorKind::Other)
            }
        }
    }
}

#[test]
fn every_single_ingest_fault_is_typed_and_reconciles_exactly() -> TestResult {
    let name = "every_single_ingest_fault";
    let after_open = open_calls(name)?;
    let after_stage = probe_calls(&format!("{name}_stage_probe"), |spool| {
        spool.stage(digest(), PAYLOAD).map(|_| ())
    })?;
    let mut cases = 0_usize;
    let mut passed_through = Vec::new();
    for mode in [Mode::Fail, Mode::FailAfterApplying] {
        for call in SpoolIoCall::ALL {
            let before = after_open.calls(call);
            let during_stage = after_stage.calls(call) - before;
            for step in 1..=during_stage {
                cases += 1;
                let case = format!("{name}_{mode:?}_{call}_{step}");
                let root = fresh_root(&case)?;
                let (mut spool, io) = open_faulted(&root, mode.plan(call, before + step))?;
                let outcome = spool.stage(digest(), PAYLOAD);
                assert!(io.all_fired(), "{case}: fault did not fire");
                match outcome {
                    // An applied call whose host result is already an error passes that error
                    // through unchanged; only the "object name is absent" probe tolerates one.
                    Ok(receipt) => {
                        assert!(matches!(mode, Mode::FailAfterApplying), "{case}");
                        assert_eq!(receipt.outcome, StageOutcome::NewlyStaged, "{case}");
                        assert_eq!(receipt.state, SpoolObjectState::Staged, "{case}");
                        let occupied = spool.occupied_bytes()?;
                        drop(spool);
                        let reopened = StagingSpool::open(&root, roomy())?;
                        assert!(reopened.recovery_report().is_clean(), "{case}");
                        assert_eq!(
                            reopened.recovery_report().admitted,
                            vec![digest()],
                            "{case}"
                        );
                        assert_eq!(reopened.occupied_bytes()?, occupied, "{case}");
                        passed_through.push(format!("{mode:?}_{call}_{step}"));
                    }
                    Err(SpoolError::StageIndeterminate { digest: named, .. }) => {
                        assert_eq!(named, digest(), "{case}");
                        assert_indeterminate_then_reconciled(&root, spool)?;
                    }
                    Err(SpoolError::Io { .. } | SpoolError::ShortWrite { .. }) => {
                        assert_nothing_admitted(&root, spool)?;
                    }
                    Err(other) => return Err(format!("{case}: untyped outcome {other:?}").into()),
                }
            }
        }
    }
    // Two inspections, create, write, file fsync, open, read, rename, two directory fsyncs.
    assert_eq!(cases, 2 * 10);
    assert_eq!(
        passed_through,
        vec![String::from("FailAfterApplying_symlink_metadata_1")]
    );
    Ok(())
}

#[test]
fn every_single_open_fault_fails_closed_without_changing_recovery() -> TestResult {
    let root = fresh_root("every_single_open_fault")?;
    let other = ContentDigest::sha256(b"interrupted-object");
    {
        let mut spool = StagingSpool::open(&root, roomy())?;
        spool.stage(digest(), PAYLOAD)?;
        spool.inject_crash_after(StagePhase::AfterStagingWrite);
        expect_err(spool.stage_bytes(b"interrupted-object"))?;
    }
    let counter = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new()));
    let baseline = {
        let spool = StagingSpool::open_with_io(&root, roomy(), counter.clone())?;
        assert_eq!(spool.recovery_report().admitted, vec![digest()]);
        assert_eq!(spool.recovery_report().orphaned_staging.len(), 1);
        assert_eq!(
            spool.recovery_report().orphaned_staging[0].claimed_digest,
            other
        );
        (spool.recovery_report().clone(), spool.occupied_bytes()?)
    };

    for mode in [Mode::Fail, Mode::FailAfterApplying] {
        for call in SpoolIoCall::ALL {
            for step in 1..=counter.calls(call) {
                let case = format!("{mode:?}_{call}_{step}");
                let io = Arc::new(FaultInjectingSpoolIo::new(mode.plan(call, step)));
                match StagingSpool::open_with_io(&root, roomy(), io.clone()) {
                    Err(SpoolError::Io { .. }) => {}
                    Ok(spool) => {
                        // Only an "applied" call whose host result was already an error the
                        // spool tolerates (such as creating an existing directory) can succeed.
                        assert!(matches!(mode, Mode::FailAfterApplying), "{case}");
                        assert_eq!(spool.recovery_report(), &baseline.0, "{case}");
                        assert_eq!(spool.occupied_bytes()?, baseline.1, "{case}");
                    }
                    Err(other) => return Err(format!("{case}: untyped outcome {other:?}").into()),
                }
                let reopened = StagingSpool::open(&root, roomy())?;
                assert_eq!(reopened.recovery_report(), &baseline.0, "{case}");
                assert_eq!(reopened.occupied_bytes()?, baseline.1, "{case}");
            }
        }
    }
    Ok(())
}
