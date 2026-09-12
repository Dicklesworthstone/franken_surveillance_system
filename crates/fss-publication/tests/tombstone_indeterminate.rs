#![forbid(unsafe_code)]
//! Tests for tombstone rename indeterminate handling and dual error preservation on cleanup failure.
//!
//! Covers fss-3epod:
//! 1. Tombstone rename fail-after-apply triggers rollback (remove + fsync). On rollback failure,
//!    it records a durable indeterminate marker, poisons the publisher, and returns typed
//!    [`LocalPublicationError::TombstoneVisibilityIndeterminate`].
//! 2. When rolling back successfully, nothing is recorded and the plain rename error is returned.
//! 3. On reopen, an indeterminate tombstone marker causes open to fail closed with CorruptTombstone,
//!    while an unparsable marker is classified as foreign.
//! 4. Temporary cleanup failures preserve both original and cleanup errors via
//!    [`LocalPublicationError::CleanupFailed`].

use std::error::Error;
use std::fmt::Debug;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fss_core::{ContentDigest, Generation, ObjectId, TombstoneReason, TombstoneRecord};
use fss_object::{FaultInjectingSpoolIo, ObjectManifest, SpoolFaultPlan, SpoolIoCall, SpoolLimits};
use fss_publication::{
    LOCAL_TOMBSTONES_DIR, LocalIoOperation, LocalPublicationError, LocalPublicationGuidance,
    LocalPublicationLimits, LocalRootPublisher, ROOT_INDETERMINATE_SUFFIX, SlotName,
    TOMBSTONE_RECORD_SUFFIX, TombstoneOutcome, tombstone_record_bytes,
};

type TestResult = Result<(), Box<dyn Error>>;

fn fresh_root(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("tombstone_indeterminate")
        .join(test_name);
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(root)
}

fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(8, 16, 8, 64, SpoolLimits::new(64, 1 << 20, 4096, 64))
}

fn expect_err<T: Debug>(
    result: Result<T, LocalPublicationError>,
) -> Result<LocalPublicationError, Box<dyn Error>> {
    match result {
        Ok(value) => Err(format!("expected a publication error, got {value:?}").into()),
        Err(error) => Ok(error),
    }
}

fn stage_tombstone_fixture(
    publisher: &mut LocalRootPublisher,
) -> Result<(ContentDigest, TombstoneRecord), Box<dyn Error>> {
    let payload = publisher.stage_object(b"payload-data-to-tombstone")?;
    let witness = publisher.stage_object(b"deletion-witness-authorization")?;
    let record = TombstoneRecord::new(
        ObjectId::parse("object:payload:1")?,
        Generation(2),
        Generation(1),
        TombstoneReason::Deleted,
        Some(witness),
        payload,
    )?;
    Ok((payload, record))
}

fn tombstone_file(root: &Path, digest: ContentDigest) -> PathBuf {
    let stem = digest.to_text().replacen(':', "-", 1);
    root.join(LOCAL_TOMBSTONES_DIR)
        .join(format!("{stem}{TOMBSTONE_RECORD_SUFFIX}"))
}

fn tombstone_marker_relative(digest: ContentDigest) -> PathBuf {
    let stem = digest.to_text().replacen(':', "-", 1);
    PathBuf::from(LOCAL_TOMBSTONES_DIR).join(format!(
        "{stem}{TOMBSTONE_RECORD_SUFFIX}{ROOT_INDETERMINATE_SUFFIX}"
    ))
}

struct TombstoneCommitCalls {
    tombstone_rename: u64,
    first_remove: u64,
    first_sync_after_rename: u64,
    first_create_after_rename: u64,
}

fn probe_tombstone_commit_calls(test_name: &str) -> Result<TombstoneCommitCalls, Box<dyn Error>> {
    let root = fresh_root(&format!("{test_name}_probe"))?;
    let io = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new()));
    let mut publisher = LocalRootPublisher::open_with_io(&root, limits(), io.clone())?;
    let (_payload, record) = stage_tombstone_fixture(&mut publisher)?;
    let removes_before = io.calls(SpoolIoCall::RemoveFile);
    let renames_before = io.calls(SpoolIoCall::Rename);
    let outcome = publisher.record_tombstone(record)?;
    assert_eq!(outcome, TombstoneOutcome::Recorded);
    assert_eq!(
        io.calls(SpoolIoCall::RemoveFile),
        removes_before,
        "a clean record_tombstone removes nothing"
    );
    let tombstone_rename = io.calls(SpoolIoCall::Rename);
    assert!(
        tombstone_rename > renames_before,
        "the tombstone rename is the last rename of record_tombstone"
    );
    Ok(TombstoneCommitCalls {
        tombstone_rename,
        first_remove: removes_before + 1,
        first_sync_after_rename: io.calls(SpoolIoCall::SyncDirectory),
        first_create_after_rename: io.calls(SpoolIoCall::CreateNew) + 1,
    })
}

fn open_faulted(
    root: &Path,
    plan: SpoolFaultPlan,
) -> Result<(LocalRootPublisher, Arc<FaultInjectingSpoolIo>), Box<dyn Error>> {
    let io = Arc::new(FaultInjectingSpoolIo::new(plan));
    let publisher = LocalRootPublisher::open_with_io(root, limits(), io.clone())?;
    Ok((publisher, io))
}

/// Item 1: The tombstone rename took effect but reported failure, and removing the record failed.
/// The caller must receive typed TombstoneVisibilityIndeterminate, the instance is poisoned,
/// an indeterminate marker is durable, and reopen fails closed.
#[test]
fn applied_tombstone_rename_with_failed_rollback_remove_is_indeterminate() -> TestResult {
    let name = "applied_tombstone_rename_with_failed_rollback_remove_is_indeterminate";
    let calls = probe_tombstone_commit_calls(name)?;
    let root = fresh_root(name)?;
    let plan = SpoolFaultPlan::new()
        .fail_after_applying(
            SpoolIoCall::Rename,
            calls.tombstone_rename,
            io::ErrorKind::Other,
        )
        .fail(
            SpoolIoCall::RemoveFile,
            calls.first_remove,
            io::ErrorKind::PermissionDenied,
        );
    let (mut publisher, io) = open_faulted(&root, plan)?;
    let (payload, record) = stage_tombstone_fixture(&mut publisher)?;

    let error = expect_err(publisher.record_tombstone(record.clone()))?;
    assert!(io.all_fired(), "both planned faults must fire");
    let target_path = tombstone_file(&root, payload);
    assert!(
        target_path.exists(),
        "the rename took effect and its rollback failed: the record is visible on disk"
    );
    assert_eq!(
        error,
        LocalPublicationError::TombstoneVisibilityIndeterminate {
            object: payload,
            path: target_path,
            rename_kind: io::ErrorKind::Other,
            rollback_operation: LocalIoOperation::RemoveRecord,
            rollback_kind: io::ErrorKind::PermissionDenied,
            marker_kind: None,
        }
    );
    assert_eq!(
        error.code(),
        "ERR-PUBLICATION-LOCAL-TOMBSTONE-VISIBILITY-INDETERMINATE-001"
    );
    assert_eq!(
        error.guidance(),
        LocalPublicationGuidance::ReopenAndReconcile
    );
    assert!(publisher.is_poisoned());
    assert!(!publisher.tombstones().any(|t| *t == payload));

    let marker_path = root.join(tombstone_marker_relative(payload));
    assert!(marker_path.exists());
    assert_eq!(
        fs::read(&marker_path)?,
        tombstone_record_bytes(&record)?,
        "the marker holds the attempted tombstone record"
    );
    drop(publisher);

    let reopen_err = expect_err(LocalRootPublisher::open(&root, limits()))?;
    assert_eq!(
        reopen_err,
        LocalPublicationError::CorruptTombstone {
            path: tombstone_marker_relative(payload),
        }
    );
    Ok(())
}

/// Item 1: The tombstone rename took effect, rollback removed the record, but directory fsync failed.
#[test]
fn applied_tombstone_rename_with_unsynced_rollback_is_indeterminate() -> TestResult {
    let name = "applied_tombstone_rename_with_unsynced_rollback_is_indeterminate";
    let calls = probe_tombstone_commit_calls(name)?;
    let root = fresh_root(name)?;
    let plan = SpoolFaultPlan::new()
        .fail_after_applying(
            SpoolIoCall::Rename,
            calls.tombstone_rename,
            io::ErrorKind::Other,
        )
        .fail(
            SpoolIoCall::SyncDirectory,
            calls.first_sync_after_rename,
            io::ErrorKind::Other,
        );
    let (mut publisher, io) = open_faulted(&root, plan)?;
    let (payload, record) = stage_tombstone_fixture(&mut publisher)?;

    let error = expect_err(publisher.record_tombstone(record))?;
    assert!(io.all_fired(), "both planned faults must fire");
    assert_eq!(
        error,
        LocalPublicationError::TombstoneVisibilityIndeterminate {
            object: payload,
            path: tombstone_file(&root, payload),
            rename_kind: io::ErrorKind::Other,
            rollback_operation: LocalIoOperation::SyncDirectory,
            rollback_kind: io::ErrorKind::Other,
            marker_kind: None,
        }
    );
    assert!(publisher.is_poisoned());
    drop(publisher);

    let reopen_err = expect_err(LocalRootPublisher::open(&root, limits()))?;
    assert_eq!(
        reopen_err,
        LocalPublicationError::CorruptTombstone {
            path: tombstone_marker_relative(payload),
        }
    );
    Ok(())
}

/// Item 1: The indeterminate marker itself cannot be recorded; reports marker_kind failure.
#[test]
fn indeterminate_tombstone_whose_marker_cannot_be_recorded_reports_the_marker_failure() -> TestResult
{
    let name = "indeterminate_tombstone_whose_marker_cannot_be_recorded_reports_the_marker_failure";
    let calls = probe_tombstone_commit_calls(name)?;
    let root = fresh_root(name)?;
    let plan = SpoolFaultPlan::new()
        .fail_after_applying(
            SpoolIoCall::Rename,
            calls.tombstone_rename,
            io::ErrorKind::Other,
        )
        .fail(
            SpoolIoCall::RemoveFile,
            calls.first_remove,
            io::ErrorKind::PermissionDenied,
        )
        .fail(
            SpoolIoCall::CreateNew,
            calls.first_create_after_rename,
            io::ErrorKind::StorageFull,
        );
    let (mut publisher, io) = open_faulted(&root, plan)?;
    let (payload, record) = stage_tombstone_fixture(&mut publisher)?;

    let error = expect_err(publisher.record_tombstone(record))?;
    assert!(io.all_fired(), "all three planned faults must fire");
    assert_eq!(
        error,
        LocalPublicationError::TombstoneVisibilityIndeterminate {
            object: payload,
            path: tombstone_file(&root, payload),
            rename_kind: io::ErrorKind::Other,
            rollback_operation: LocalIoOperation::RemoveRecord,
            rollback_kind: io::ErrorKind::PermissionDenied,
            marker_kind: Some(io::ErrorKind::StorageFull),
        }
    );
    assert!(publisher.is_poisoned());
    assert!(!root.join(tombstone_marker_relative(payload)).exists());
    Ok(())
}

/// Item 1 Guard: When rollback remove + sync both succeed, plain Rename error is returned and publisher is usable.
#[test]
fn applied_tombstone_rename_with_durable_rollback_records_nothing() -> TestResult {
    let name = "applied_tombstone_rename_with_durable_rollback_records_nothing";
    let calls = probe_tombstone_commit_calls(name)?;
    let root = fresh_root(name)?;
    let plan = SpoolFaultPlan::new().fail_after_applying(
        SpoolIoCall::Rename,
        calls.tombstone_rename,
        io::ErrorKind::Other,
    );
    let (mut publisher, io) = open_faulted(&root, plan)?;
    let (payload, record) = stage_tombstone_fixture(&mut publisher)?;

    let error = expect_err(publisher.record_tombstone(record))?;
    assert!(io.all_fired());
    assert_eq!(
        error,
        LocalPublicationError::Io {
            operation: LocalIoOperation::Rename,
            path: tombstone_file(&root, payload),
            kind: io::ErrorKind::Other,
        }
    );
    assert!(!publisher.is_poisoned());
    assert!(!tombstone_file(&root, payload).exists());
    assert!(!root.join(tombstone_marker_relative(payload)).exists());
    drop(publisher);

    let reopened = LocalRootPublisher::open(&root, limits())?;
    assert!(reopened.recovery_report().tombstones.is_empty());
    assert!(reopened.recovery_report().broken_roots.is_empty());
    assert!(reopened.recovery_report().orphaned_temps.is_empty());
    Ok(())
}

/// An indeterminate marker that does not parse as a valid digest is foreign.
#[test]
fn unparsable_tombstone_indeterminate_marker_is_foreign() -> TestResult {
    let root = fresh_root("unparsable_tombstone_indeterminate_marker_is_foreign")?;
    drop(LocalRootPublisher::open(&root, limits())?);
    let name = format!("Bad-Digest{TOMBSTONE_RECORD_SUFFIX}{ROOT_INDETERMINATE_SUFFIX}");
    fs::write(root.join(LOCAL_TOMBSTONES_DIR).join(&name), b"x")?;
    let reopened = LocalRootPublisher::open(&root, limits())?;
    let report = reopened.recovery_report();
    assert_eq!(
        report.foreign,
        vec![PathBuf::from(LOCAL_TOMBSTONES_DIR).join(name)]
    );
    assert!(report.tombstones.is_empty());
    Ok(())
}

/// Item 2: A cleanup failure carries both the original error and the cleanup error.
#[test]
fn cleanup_failure_carries_both_original_and_cleanup_errors() -> TestResult {
    let root = fresh_root("cleanup_failure_carries_both_original_and_cleanup_errors")?;
    let io = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new().fail(
        SpoolIoCall::RemoveFile,
        1,
        io::ErrorKind::PermissionDenied,
    )));
    let mut publisher = LocalRootPublisher::open_with_io(&root, limits(), io.clone())?;
    let leaf = publisher.stage_object(b"test-leaf")?;
    let manifest = ObjectManifest::new("clip", [leaf], None)?;
    let slot = SlotName::parse("slot-test")?;
    let target_path = root.join("roots").join(format!("{slot}.root"));

    // Pre-create file at target_path after open so publish encounters InvalidLayout before rename
    fs::write(&target_path, b"unindexed")?;

    let error = expect_err(publisher.publish(&slot, &manifest))?;
    assert!(io.all_fired(), "cleanup fault must fire");
    match &error {
        LocalPublicationError::CleanupFailed { original, cleanup } => {
            assert_eq!(
                **original,
                LocalPublicationError::InvalidLayout { path: target_path }
            );
            match &**cleanup {
                LocalPublicationError::Io {
                    operation, kind, ..
                } => {
                    assert_eq!(*operation, LocalIoOperation::RemoveTemp);
                    assert_eq!(*kind, io::ErrorKind::PermissionDenied);
                }
                other => return Err(format!("expected Io remove_temp, got {other:?}").into()),
            }
        }
        other => return Err(format!("expected CleanupFailed, got {other:?}").into()),
    }
    assert_eq!(error.code(), "ERR-PUBLICATION-LOCAL-CLEANUP-001");
    assert_eq!(error.guidance(), LocalPublicationGuidance::RepairStorage);
    assert!(error.source().is_some());
    Ok(())
}
