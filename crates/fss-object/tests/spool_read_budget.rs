#![forbid(unsafe_code)]
//! Aggregate object-read admission cannot reset on another source, retry or verification path.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::ContentDigest;
use fss_object::{
    CorruptionKind, FaultInjectingSpoolIo, HostSpoolIo, RecordingSpoolIo, SPOOL_OBJECT_HEADER_LEN,
    SpoolError, SpoolFaultPlan, SpoolIoCall, SpoolLimits, SpoolReadBudgetUsage, StagingSpool,
    VerifiedObjectCatalog,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> io::Result<Self> {
        for _ in 0..16 {
            let ordinal = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "fss-spool-read-budget-{}-{ordinal}",
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
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn limits() -> SpoolLimits {
    SpoolLimits::new(32, 1024 * 1024, 4096, 64)
}

fn reservation(payload: &[u8]) -> u64 {
    (SPOOL_OBJECT_HEADER_LEN + payload.len() + 1) as u64
}

#[test]
fn ordinary_reads_are_unchanged_until_a_cap_is_explicitly_installed() -> TestResult {
    let directory = TempDirectory::new()?;
    let mut spool = StagingSpool::open(&directory.0, limits())?;
    let payload = b"retained source";
    let digest = spool.stage_bytes(payload)?.digest;
    for _ in 0..3 {
        assert_eq!(spool.read(digest)?, payload);
    }
    assert_eq!(spool.read_budget_usage(), SpoolReadBudgetUsage::default());
    let usage = spool.tighten_read_budget(reservation(payload), 1)?;
    assert_eq!(
        usage.used_bytes, 0,
        "opening and earlier reads are separate"
    );
    assert_eq!(usage.used_read_attempts, 0);
    assert_eq!(spool.read(digest)?, payload);
    assert_eq!(spool.read_budget_usage().remaining_bytes, Some(0));
    Ok(())
}

#[test]
fn reads_missing_objects_and_verification_share_the_same_allowance() -> TestResult {
    let directory = TempDirectory::new()?;
    let io = Arc::new(RecordingSpoolIo::new(Arc::new(HostSpoolIo)));
    let mut spool = StagingSpool::open_with_io(&directory.0, limits(), io.clone())?;
    let payload = b"exact evidence";
    let digest = spool.stage_bytes(payload)?.digest;
    let calls_before = io.call_count(SpoolIoCall::Read);
    let unit = reservation(payload);
    spool.tighten_read_budget(3 * unit, 4)?;
    assert!(matches!(
        spool.read(ContentDigest::sha256(b"not retained")),
        Err(SpoolError::Missing(_))
    ));
    assert_eq!(spool.read_bounded(digest, payload.len())?, payload);
    spool.verify(digest)?;
    spool.require_verified(digest)?;
    assert_eq!(
        spool.read_budget_usage(),
        SpoolReadBudgetUsage {
            used_bytes: 3 * unit,
            used_read_attempts: 4,
            remaining_bytes: Some(0),
            remaining_read_attempts: Some(0),
        },
    );
    assert!(matches!(
        spool.read(digest),
        Err(SpoolError::ReadBudgetExceeded {
            resource: "indexed_read_attempts",
            ..
        })
    ));
    assert_eq!(io.call_count(SpoolIoCall::Read), calls_before + 3);
    Ok(())
}

#[test]
fn exhausted_byte_budget_refuses_before_any_object_file_access() -> TestResult {
    let directory = TempDirectory::new()?;
    let io = Arc::new(RecordingSpoolIo::new(Arc::new(HostSpoolIo)));
    let mut spool = StagingSpool::open_with_io(&directory.0, limits(), io.clone())?;
    let digest = spool.stage_bytes(b"source")?.digest;
    spool.tighten_read_budget(0, 1)?;
    let calls_before = io.calls().len();
    assert!(matches!(
        spool.read(digest),
        Err(SpoolError::ReadBudgetExceeded {
            resource: "stored_object_read_bytes",
            current: 0,
            maximum: 0,
            ..
        })
    ));
    assert_eq!(io.calls().len(), calls_before);
    assert_eq!(spool.read_budget_usage().used_bytes, 0);
    assert_eq!(spool.read_budget_usage().used_read_attempts, 1);
    Ok(())
}

#[test]
fn widening_or_reinstalling_a_cap_cannot_refill_consumed_work() -> TestResult {
    let directory = TempDirectory::new()?;
    let io = Arc::new(RecordingSpoolIo::new(Arc::new(HostSpoolIo)));
    let mut spool = StagingSpool::open_with_io(&directory.0, limits(), io.clone())?;
    let payload = b"same digest on every retry";
    let digest = spool.stage_bytes(payload)?.digest;
    let unit = reservation(payload);
    spool.tighten_read_budget(3 * unit, 3)?;
    spool.read(digest)?;
    let before = spool.read_budget_usage();
    assert_eq!(spool.tighten_read_budget(9 * unit, 9)?, before);
    spool.read(digest)?;
    assert!(matches!(
        spool.tighten_read_budget(unit, 1),
        Err(SpoolError::ReadBudgetExceeded { .. })
    ));
    let after = spool.read_budget_usage();
    assert_eq!(after.used_bytes, 2 * unit);
    assert_eq!(after.used_read_attempts, 2);
    assert_eq!(after.remaining_bytes, Some(0));
    assert_eq!(after.remaining_read_attempts, Some(0));
    assert!(spool.tighten_read_budget(u64::MAX, u64::MAX).is_err());
    assert_eq!(spool.read_budget_usage(), after);
    let calls_before = io.calls().len();
    assert!(spool.read(digest).is_err());
    assert_eq!(io.calls().len(), calls_before);
    Ok(())
}

#[test]
fn a_failed_physical_read_keeps_its_reservation_before_retry() -> TestResult {
    let directory = TempDirectory::new()?;
    let payload = b"source whose first serving read fails";
    let mut spool = StagingSpool::open(&directory.0, limits())?;
    let digest = spool.stage_bytes(payload)?.digest;
    drop(spool);

    // Recovery reads this one object once. The next read fails after admission.
    let io = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new().fail(
        SpoolIoCall::Read,
        2,
        io::ErrorKind::Other,
    )));
    let mut spool = StagingSpool::open_with_io(&directory.0, limits(), io.clone())?;
    assert_eq!(io.calls(SpoolIoCall::Read), 1);
    let unit = reservation(payload);
    spool.tighten_read_budget(2 * unit, 3)?;
    assert!(matches!(spool.read(digest), Err(SpoolError::Io { .. })));
    assert_eq!(spool.read_budget_usage().used_bytes, unit);
    assert_eq!(spool.read(digest)?, payload);
    assert!(matches!(
        spool.read(digest),
        Err(SpoolError::ReadBudgetExceeded {
            resource: "stored_object_read_bytes",
            ..
        })
    ));
    assert_eq!(spool.read_budget_usage().used_bytes, 2 * unit);
    assert_eq!(spool.read_budget_usage().used_read_attempts, 3);
    assert_eq!(io.calls(SpoolIoCall::Read), 3);
    assert!(io.all_fired());
    Ok(())
}

#[test]
fn a_smaller_per_read_ceiling_remains_a_refusal_without_poisoning_custody() -> TestResult {
    let directory = TempDirectory::new()?;
    let mut spool = StagingSpool::open(&directory.0, limits())?;
    let payload = b"source that exceeds a three-byte read";
    let digest = spool.stage_bytes(payload)?.digest;
    let state = spool.state(digest);
    let unit = reservation(payload);
    spool.tighten_read_budget(2 * unit, 2)?;
    assert!(matches!(
        spool.read_bounded(digest, 3),
        Err(SpoolError::Corrupt {
            kind: CorruptionKind::DeclaredLengthExceedsLimit { maximum: 3, .. },
            ..
        })
    ));
    assert_eq!(spool.read_budget_usage().used_bytes, reservation(b"123"));
    assert_eq!(spool.state(digest), state);
    assert_eq!(spool.read(digest)?, payload);
    assert_eq!(
        spool.read_budget_usage().used_bytes,
        unit + reservation(b"123"),
    );
    Ok(())
}

#[test]
fn an_oversized_replacement_cannot_widen_an_admitted_physical_read() -> TestResult {
    let directory = TempDirectory::new()?;
    let mut spool = StagingSpool::open(&directory.0, limits())?;
    let payload = b"small original";
    let digest = spool.stage_bytes(payload)?.digest;
    let path = spool.object_path(digest);
    let mut encoded = fs::read(&path)?;
    encoded.extend_from_slice(&[1_u8; 8192]);
    fs::write(path, encoded)?;
    let unit = reservation(payload);
    spool.tighten_read_budget(unit, 1)?;
    assert!(matches!(
        spool.read(digest),
        Err(SpoolError::Corrupt {
            kind: CorruptionKind::TrailingBytes { actual_len, .. },
            ..
        }) if actual_len == unit
    ));
    assert_eq!(spool.read_budget_usage().used_bytes, unit);
    assert_eq!(spool.read_budget_usage().remaining_bytes, Some(0));
    Ok(())
}

#[test]
fn concurrent_borrowed_readers_cannot_spend_the_same_remaining_bytes() -> TestResult {
    let directory = TempDirectory::new()?;
    let io = Arc::new(RecordingSpoolIo::new(Arc::new(HostSpoolIo)));
    let mut spool = StagingSpool::open_with_io(&directory.0, limits(), io.clone())?;
    let payload = b"one immutable object, many consumers";
    let digest = spool.stage_bytes(payload)?.digest;
    let unit = reservation(payload);
    spool.tighten_read_budget(4 * unit, 8)?;
    let calls_before = io.call_count(SpoolIoCall::Read);
    let successful = std::thread::scope(|scope| {
        let readers: Vec<_> = (0..8).map(|_| scope.spawn(|| spool.read(digest))).collect();
        readers
            .into_iter()
            .map(|reader| match reader.join() {
                Ok(Ok(bytes)) => {
                    assert_eq!(bytes, payload);
                    1
                }
                Ok(Err(SpoolError::ReadBudgetExceeded { .. })) => 0,
                other => panic!("unexpected read result: {other:?}"),
            })
            .sum::<usize>()
    });
    assert_eq!(successful, 4);
    assert_eq!(spool.read_budget_usage().used_bytes, 4 * unit);
    assert_eq!(spool.read_budget_usage().used_read_attempts, 8);
    assert_eq!(io.call_count(SpoolIoCall::Read), calls_before + 4);
    Ok(())
}
