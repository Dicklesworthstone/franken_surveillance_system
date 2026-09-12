#![forbid(unsafe_code)]
//! Gate-scan remediation tests for fss-x4a.7.6 (FSS-018 root-last local manifest publication).
//!
//! A root rename that the filesystem reports failed may still have taken effect. These tests use
//! the deterministic `FaultInjectingSpoolIo` (`fail_after_applying` on the root rename, plus a
//! failure of the rollback that follows it) to prove that such an outcome is never flattened
//! into a plain rename error: it is the typed
//! [`LocalPublicationError::RootVisibilityIndeterminate`], the instance is poisoned, the slot is
//! marked on disk, and a reopen never reports the slot as cleanly published. Every fault
//! occurrence number comes from a plan-free probe run of the same steps, never a hard-coded
//! count.

use std::error::Error;
use std::fmt::Debug;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{FaultInjectingSpoolIo, ObjectManifest, SpoolFaultPlan, SpoolIoCall, SpoolLimits};
use fss_publication::{
    BrokenRoot, BrokenRootReason, LOCAL_ROOTS_DIR, LedgeredRootPublisher, LocalIoOperation,
    LocalPublicationError, LocalPublicationGuidance, LocalPublicationLimits, LocalRootPublisher,
    ROOT_INDETERMINATE_SUFFIX, ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX, RootLedgerState, SlotName,
    root_record_bytes,
};

type TestResult = Result<(), Box<dyn Error>>;

const SLOT: &str = "event-0001";
const INDETERMINATE_CODE: &str = "ERR-PUBLICATION-LOCAL-ROOT-VISIBILITY-INDETERMINATE-001";

fn fresh_root(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("root_publication_gate")
        .join(test_name);
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(root)
}

/// A journal path in its own existing directory, outside the publication root.
fn fresh_journal(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = fresh_root(&format!("{test_name}_journal"))?;
    fs::create_dir_all(&dir)?;
    Ok(dir.join("journal"))
}

fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(8, 16, 8, 64, SpoolLimits::new(64, 1 << 20, 4096, 64))
}

fn slot() -> Result<SlotName, Box<dyn Error>> {
    Ok(SlotName::parse(SLOT)?)
}

fn root_file(root: &Path) -> PathBuf {
    root.join(LOCAL_ROOTS_DIR)
        .join(format!("{SLOT}{ROOT_RECORD_SUFFIX}"))
}

fn root_temp(root: &Path) -> PathBuf {
    root.join(LOCAL_ROOTS_DIR)
        .join(format!("{SLOT}{ROOT_RECORD_SUFFIX}{ROOT_TEMP_SUFFIX}"))
}

fn marker_relative() -> PathBuf {
    PathBuf::from(LOCAL_ROOTS_DIR).join(format!(
        "{SLOT}{ROOT_RECORD_SUFFIX}{ROOT_INDETERMINATE_SUFFIX}"
    ))
}

fn expect_err<T: Debug>(
    result: Result<T, LocalPublicationError>,
) -> Result<LocalPublicationError, Box<dyn Error>> {
    match result {
        Ok(value) => Err(format!("expected a publication error, got {value:?}").into()),
        Err(error) => Ok(error),
    }
}

fn stage_fixture(publisher: &mut LocalRootPublisher) -> Result<ObjectManifest, Box<dyn Error>> {
    let first = publisher.stage_object(b"clip-segment-0001")?;
    let second = publisher.stage_object(b"clip-segment-0002")?;
    let metadata = publisher.stage_object(b"event-metadata-v1")?;
    Ok(ObjectManifest::new(
        "event_archive",
        [first, second],
        Some(metadata),
    )?)
}

/// Occurrence numbers, per call kind, of the root-commit calls a fault run aims at.
struct CommitCalls {
    /// The root rename of the publish call.
    /// The root hard link of the publish call.
    root_commit: u64,
    /// The first `remove_file` after the publish call starts (the rollback of the root record).
    first_remove: u64,
    /// The first `sync_directory` after the root commit.
    first_sync_after_rename: u64,
    /// The first `create_new` after the root commit.
    first_create_after_rename: u64,
}

/// Derives [`CommitCalls`] from a plan-free run of open + fixture staging + one publish.
fn probe_commit_calls(test_name: &str) -> Result<CommitCalls, Box<dyn Error>> {
    let root = fresh_root(&format!("{test_name}_probe"))?;
    let io = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new()));
    let mut publisher = LocalRootPublisher::open_with_io(&root, limits(), io.clone())?;
    let manifest = stage_fixture(&mut publisher)?;
    let removes_before = io.calls(SpoolIoCall::RemoveFile);
    let links_before = io.calls(SpoolIoCall::HardLink);
    publisher.publish(&slot()?, &manifest)?;
    assert_eq!(
        io.calls(SpoolIoCall::RemoveFile),
        removes_before + 1,
        "a clean publish unlinks the temporary file after hard linking"
    );
    let root_commit = io.calls(SpoolIoCall::HardLink);
    assert!(
        root_commit > links_before,
        "the root hard_link is the commit point of a publish call"
    );
    Ok(CommitCalls {
        root_commit,
        first_remove: removes_before + 1,
        // The roots-directory fsync is the last fsync of a clean publish and the first after
        // its commit; a failed commit reaches the same occurrence with its next fsync.
        first_sync_after_rename: io.calls(SpoolIoCall::SyncDirectory),
        // A clean publish creates nothing after the commit.
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

/// Checks the in-process view after an indeterminate root rename: typed, poisoned, refused.
fn assert_in_process_indeterminate(
    publisher: &mut LocalRootPublisher,
    error: &LocalPublicationError,
    manifest: &ObjectManifest,
) -> TestResult {
    let slot_name = slot()?;
    assert!(
        !matches!(
            error,
            LocalPublicationError::Io {
                operation: LocalIoOperation::Rename,
                ..
            }
        ),
        "a possibly visible root must never be reported as a plain rename failure: {error:?}"
    );
    assert_eq!(error.code(), INDETERMINATE_CODE, "{error:?}");
    assert_eq!(
        error.guidance(),
        LocalPublicationGuidance::ReopenAndReconcile
    );
    assert!(error.to_string().starts_with(INDETERMINATE_CODE));
    assert!(publisher.is_poisoned());
    assert!(publisher.is_broken_slot(&slot_name));
    assert_eq!(
        publisher.broken_slots().cloned().collect::<Vec<_>>(),
        vec![slot_name.clone()]
    );
    assert!(
        publisher.root(&slot_name).is_none(),
        "an indeterminate root is neither claimed visible nor durable"
    );
    assert_eq!(
        expect_err(publisher.publish(&slot_name, manifest))?,
        LocalPublicationError::Poisoned
    );
    Ok(())
}

/// Reopens `root` with the host filesystem and requires that the slot is reported broken with
/// [`BrokenRootReason::VisibilityIndeterminate`], locally and through the ledger linkage.
fn assert_reopen_reports_indeterminate(
    root: &Path,
    journal: &Path,
    manifest: &ObjectManifest,
    record_present: bool,
) -> TestResult {
    let slot_name = slot()?;
    assert_eq!(root_file(root).exists(), record_present);
    let mut reopened = LocalRootPublisher::open(root, limits())?;
    assert!(
        reopened.root(&slot_name).is_none(),
        "a slot whose visibility is indeterminate must not be admitted: {:?}",
        reopened.root(&slot_name)
    );
    assert!(reopened.is_broken_slot(&slot_name));
    let report = reopened.recovery_report().clone();
    assert!(
        !report.is_clean(),
        "an indeterminate slot must be surfaced by recovery: {report:?}"
    );
    assert!(report.roots.is_empty(), "{report:?}");
    assert_eq!(
        report.broken_roots,
        vec![BrokenRoot {
            path: marker_relative(),
            reason: BrokenRootReason::VisibilityIndeterminate { record_present },
        }]
    );
    assert!(
        report.foreign.is_empty(),
        "the marker is part of the layout, not foreign: {report:?}"
    );
    assert_eq!(
        expect_err(reopened.publish(&slot_name, manifest))?,
        LocalPublicationError::BrokenSlot {
            slot: slot_name.clone()
        }
    );

    let mut ledger =
        DurableReferenceLedger::open(journal, "site:one", IncompleteTailPolicy::Reject)?;
    let coordinator = LedgeredRootPublisher::new(&mut reopened, &mut ledger);
    assert_eq!(
        coordinator.state(&slot_name)?,
        RootLedgerState::BrokenLocalRoot,
        "an indeterminate slot is neither absent nor pending ledger"
    );
    let reconciliation = coordinator.reconcile()?;
    assert_eq!(reconciliation.broken, vec![slot_name]);
    assert!(reconciliation.pending.is_empty());
    assert!(!reconciliation.is_clean());
    Ok(())
}

/// G1: the rename took effect although it was reported failed, and removing the now-visible
/// record failed too. The caller must receive a typed indeterminate error, never `Io::Rename`.
#[test]
fn applied_root_rename_with_failed_rollback_remove_is_indeterminate() -> TestResult {
    let name = "applied_root_rename_with_failed_rollback_remove_is_indeterminate";
    let calls = probe_commit_calls(name)?;
    let root = fresh_root(name)?;
    let journal = fresh_journal(name)?;
    let plan = SpoolFaultPlan::new()
        .fail_after_applying(
            SpoolIoCall::HardLink,
            calls.root_commit,
            io::ErrorKind::Other,
        )
        .fail(
            SpoolIoCall::RemoveFile,
            calls.first_remove,
            io::ErrorKind::PermissionDenied,
        );
    let (mut publisher, io) = open_faulted(&root, plan)?;
    let manifest = stage_fixture(&mut publisher)?;

    let error = expect_err(publisher.publish(&slot()?, &manifest))?;
    assert!(io.all_fired(), "both planned faults must fire");
    assert!(
        root_file(&root).exists(),
        "the rename took effect and its rollback failed: the record is visible on disk"
    );
    assert_eq!(
        error,
        LocalPublicationError::RootVisibilityIndeterminate {
            slot: slot()?,
            path: root_file(&root),
            rename_kind: io::ErrorKind::Other,
            rollback_operation: LocalIoOperation::RemoveRecord,
            rollback_kind: io::ErrorKind::PermissionDenied,
            marker_kind: None,
        }
    );
    assert_in_process_indeterminate(&mut publisher, &error, &manifest)?;
    assert_eq!(
        fs::read(root.join(marker_relative()))?,
        root_record_bytes(&slot()?, manifest.root(), 3)?,
        "the marker holds the attempted root record"
    );
    drop(publisher);

    assert_reopen_reports_indeterminate(&root, &journal, &manifest, true)
}

/// G1: the rename took effect, the rollback removed the record, but the roots-directory fsync
/// that makes the removal durable failed; a crash could resurrect the record.
#[test]
fn applied_root_rename_with_unsynced_rollback_is_indeterminate() -> TestResult {
    let name = "applied_root_rename_with_unsynced_rollback_is_indeterminate";
    let calls = probe_commit_calls(name)?;
    let root = fresh_root(name)?;
    let journal = fresh_journal(name)?;
    let plan = SpoolFaultPlan::new()
        .fail_after_applying(
            SpoolIoCall::HardLink,
            calls.root_commit,
            io::ErrorKind::Other,
        )
        .fail(
            SpoolIoCall::SyncDirectory,
            calls.first_sync_after_rename,
            io::ErrorKind::Other,
        );
    let (mut publisher, io) = open_faulted(&root, plan)?;
    let manifest = stage_fixture(&mut publisher)?;

    let error = expect_err(publisher.publish(&slot()?, &manifest))?;
    assert!(io.all_fired(), "both planned faults must fire");
    assert_eq!(
        error,
        LocalPublicationError::RootVisibilityIndeterminate {
            slot: slot()?,
            path: root_file(&root),
            rename_kind: io::ErrorKind::Other,
            rollback_operation: LocalIoOperation::SyncDirectory,
            rollback_kind: io::ErrorKind::Other,
            marker_kind: None,
        }
    );
    assert_in_process_indeterminate(&mut publisher, &error, &manifest)?;
    drop(publisher);

    assert_reopen_reports_indeterminate(&root, &journal, &manifest, false)
}

/// G1: the indeterminate marker itself cannot be created; the error must say so rather than
/// imply that a reopen will surface the slot.
#[test]
fn indeterminate_root_whose_marker_cannot_be_recorded_reports_the_marker_failure() -> TestResult {
    let name = "indeterminate_root_whose_marker_cannot_be_recorded_reports_the_marker_failure";
    let calls = probe_commit_calls(name)?;
    let root = fresh_root(name)?;
    let plan = SpoolFaultPlan::new()
        .fail_after_applying(
            SpoolIoCall::HardLink,
            calls.root_commit,
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
    let manifest = stage_fixture(&mut publisher)?;

    let error = expect_err(publisher.publish(&slot()?, &manifest))?;
    assert!(io.all_fired(), "all three planned faults must fire");
    assert_eq!(
        error,
        LocalPublicationError::RootVisibilityIndeterminate {
            slot: slot()?,
            path: root_file(&root),
            rename_kind: io::ErrorKind::Other,
            rollback_operation: LocalIoOperation::RemoveRecord,
            rollback_kind: io::ErrorKind::PermissionDenied,
            marker_kind: Some(io::ErrorKind::StorageFull),
        }
    );
    assert_in_process_indeterminate(&mut publisher, &error, &manifest)?;
    assert!(!root.join(marker_relative()).exists());
    Ok(())
}

/// Guard: a rename reported failed after taking effect whose rollback removal and fsync both
/// succeed leaves nothing visible; the plain rename error is then exact, and the instance stays
/// usable.
#[test]
fn applied_root_rename_with_durable_rollback_publishes_nothing() -> TestResult {
    let name = "applied_root_rename_with_durable_rollback_publishes_nothing";
    let calls = probe_commit_calls(name)?;
    let root = fresh_root(name)?;
    let plan = SpoolFaultPlan::new().fail_after_applying(
        SpoolIoCall::HardLink,
        calls.root_commit,
        io::ErrorKind::Other,
    );
    let (mut publisher, io) = open_faulted(&root, plan)?;
    let manifest = stage_fixture(&mut publisher)?;

    let error = expect_err(publisher.publish(&slot()?, &manifest))?;
    assert!(io.all_fired());
    assert_eq!(
        error,
        LocalPublicationError::Io {
            operation: LocalIoOperation::Rename,
            path: root_file(&root),
            kind: io::ErrorKind::Other,
        }
    );
    assert!(!publisher.is_poisoned());
    assert!(!publisher.is_broken_slot(&slot()?));
    assert!(publisher.root(&slot()?).is_none());
    assert!(!root_file(&root).exists());
    assert!(!root_temp(&root).exists());
    assert!(!root.join(marker_relative()).exists());
    drop(publisher);

    let reopened = LocalRootPublisher::open(&root, limits())?;
    assert!(reopened.recovery_report().roots.is_empty());
    assert!(reopened.recovery_report().broken_roots.is_empty());
    assert!(reopened.recovery_report().orphaned_temps.is_empty());
    Ok(())
}

/// A marker whose name does not parse as a slot is foreign, never silently admitted or dropped.
#[test]
fn unparsable_indeterminate_marker_is_foreign() -> TestResult {
    let root = fresh_root("unparsable_indeterminate_marker_is_foreign")?;
    drop(LocalRootPublisher::open(&root, limits())?);
    let name = format!("Bad Slot{ROOT_RECORD_SUFFIX}{ROOT_INDETERMINATE_SUFFIX}");
    fs::write(root.join(LOCAL_ROOTS_DIR).join(&name), b"x")?;
    let reopened = LocalRootPublisher::open(&root, limits())?;
    let report = reopened.recovery_report();
    assert_eq!(
        report.foreign,
        vec![PathBuf::from(LOCAL_ROOTS_DIR).join(name)]
    );
    assert!(report.broken_roots.is_empty());
    Ok(())
}
