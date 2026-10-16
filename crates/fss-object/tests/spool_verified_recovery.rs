#![forbid(unsafe_code)]
//! Fresh recovery checks are session-local; durable holds are not byte certificates.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_object::{
    CorruptionKind, FaultInjectingSpoolIo, ObjectError, SpoolError, SpoolFaultPlan, SpoolIoCall,
    SpoolLimits, SpoolObjectState, StagingSpool, VerifiedObjectCatalog,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> io::Result<Self> {
        for _ in 0..16 {
            let ordinal = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "fss-fresh-recovery-{}-{ordinal}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "fixture namespace exhausted",
        ))
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        // Only this fixture's successfully created directory reaches the guard.
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn limits() -> SpoolLimits {
    SpoolLimits::new(32, 1024 * 1024, 4096, 64)
}

fn corrupt_payload(path: &Path) -> io::Result<()> {
    let mut encoded = fs::read(path)?;
    let last = encoded
        .last_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty fixture envelope"))?;
    *last ^= 1;
    fs::write(path, encoded)
}

#[test]
fn only_freshly_rehashed_held_objects_are_promoted() -> TestResult {
    let directory = TempDirectory::new()?;
    let mut spool = StagingSpool::open(&directory.0, limits())?;
    let held = spool.stage_bytes(b"previously verified media")?.digest;
    spool.verify(held)?;
    let unheld = spool.stage_bytes(b"staged but not verified")?.digest;
    drop(spool);
    let ordinary = StagingSpool::open(&directory.0, limits())?;
    assert_eq!(ordinary.state(held), Some(SpoolObjectState::Staged));
    assert_eq!(ordinary.state(unheld), Some(SpoolObjectState::Staged));
    let report = ordinary.recovery_report().clone();
    drop(ordinary);

    let io = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new()));
    let recovered =
        StagingSpool::open_with_verified_recovery(&directory.0, limits(), io.clone())?;
    assert_eq!(io.calls(SpoolIoCall::Read), 2, "one fresh read per object");
    assert_eq!(recovered.recovery_report(), &report);
    assert_eq!(recovered.state(held), Some(SpoolObjectState::Verified));
    assert_eq!(recovered.state(unheld), Some(SpoolObjectState::Staged));
    assert_eq!(
        recovered.require_verified(unheld),
        Err(ObjectError::NotVerified(unheld)),
    );
    recovered.require_verified(held)?;
    assert_eq!(io.calls(SpoolIoCall::Read), 3);
    assert_eq!(recovered.read(held)?, b"previously verified media");
    assert_eq!(io.calls(SpoolIoCall::Read), 4);
    drop(recovered);
    let ordinary = StagingSpool::open(&directory.0, limits())?;
    assert_eq!(ordinary.state(held), Some(SpoolObjectState::Staged));
    Ok(())
}

#[test]
fn a_persistent_hold_never_hides_same_length_corruption_on_reopen() -> TestResult {
    let directory = TempDirectory::new()?;
    let mut spool = StagingSpool::open(&directory.0, limits())?;
    let digest = spool.stage_bytes(b"unaltered original media")?.digest;
    spool.verify(digest)?;
    let path = spool.object_path(digest);
    drop(spool);
    corrupt_payload(&path)?;

    let io = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new()));
    let spool = StagingSpool::open_with_verified_recovery(&directory.0, limits(), io.clone())?;
    assert_eq!(io.calls(SpoolIoCall::Read), 1);
    assert!(matches!(spool.state(digest), Some(SpoolObjectState::Corrupt(_))));
    assert!(spool.recovery_report().corrupt.iter().any(|entry| entry.digest == digest));
    assert_eq!(spool.require_verified(digest), Err(ObjectError::Corrupt(digest)));
    assert!(matches!(
        spool.read(digest),
        Err(SpoolError::Corrupt { digest: actual, .. }) if actual == digest
    ));
    Ok(())
}

#[test]
fn a_hold_for_a_vanished_object_remains_corrupt() -> TestResult {
    let directory = TempDirectory::new()?;
    let mut spool = StagingSpool::open(&directory.0, limits())?;
    let digest = spool.stage_bytes(b"held object")?.digest;
    spool.verify(digest)?;
    let path = spool.object_path(digest);
    drop(spool);
    fs::remove_file(path)?;

    let io = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new()));
    let spool = StagingSpool::open_with_verified_recovery(&directory.0, limits(), io)?;
    assert_eq!(
        spool.state(digest),
        Some(SpoolObjectState::Corrupt(CorruptionKind::Vanished)),
    );
    assert_eq!(spool.require_verified(digest), Err(ObjectError::Corrupt(digest)));
    Ok(())
}

#[test]
fn mutations_after_recovery_are_rejected_by_reads_and_authority_checks() -> TestResult {
    let directory = TempDirectory::new()?;
    let mut spool = StagingSpool::open(&directory.0, limits())?;
    let digest = spool.stage_bytes(b"intact at recovery time")?.digest;
    spool.verify(digest)?;
    drop(spool);

    let io = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new()));
    let mut spool = StagingSpool::open_with_verified_recovery(&directory.0, limits(), io)?;
    assert_eq!(spool.state(digest), Some(SpoolObjectState::Verified));
    corrupt_payload(&spool.object_path(digest))?;
    assert_eq!(spool.require_verified(digest), Err(ObjectError::Corrupt(digest)));
    assert!(matches!(
        spool.read(digest),
        Err(SpoolError::Corrupt { digest: actual, .. }) if actual == digest
    ));
    assert!(matches!(
        spool.verify(digest),
        Err(SpoolError::Corrupt { digest: actual, .. }) if actual == digest
    ));
    assert!(matches!(spool.state(digest), Some(SpoolObjectState::Corrupt(_))));
    Ok(())
}

#[test]
fn recovery_io_failure_never_promotes_objects_and_releases_the_lock() -> TestResult {
    let directory = TempDirectory::new()?;
    let mut spool = StagingSpool::open(&directory.0, limits())?;
    let digest = spool.stage_bytes(b"must actually be read")?.digest;
    spool.verify(digest)?;
    drop(spool);

    let io = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new().fail(
        SpoolIoCall::Read,
        1,
        io::ErrorKind::PermissionDenied,
    )));
    assert!(matches!(
        StagingSpool::open_with_verified_recovery(&directory.0, limits(), io.clone()),
        Err(SpoolError::Io { kind: io::ErrorKind::PermissionDenied, .. }),
    ));
    assert!(io.all_fired());
    // A failed constructor must release its exclusive lock before returning.
    let reopened = StagingSpool::open(&directory.0, limits())?;
    assert_eq!(reopened.state(digest), Some(SpoolObjectState::Staged));
    Ok(())
}
