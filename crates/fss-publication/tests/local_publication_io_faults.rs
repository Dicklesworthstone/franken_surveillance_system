#![forbid(unsafe_code)]
//! Failure paths of the root commit point (FSS-018, fss-x4a.7.6).
//!
//! A failed rename of the root temporary record and a failed roots-directory fsync after the
//! rename are injected as typed I/O errors (not crashes) through the test-only constructor
//! [`LocalRootPublisher::open_with_injected_io_fault`]. Every test owns one real directory under
//! `CARGO_TARGET_TMPDIR`, named after the test.

use std::error::Error;
use std::fmt::Debug;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use fss_core::ContentDigest;
use fss_object::{ObjectManifest, SpoolLimits, SpoolObjectState};
use fss_publication::{
    BlockReason, InjectedIoFault, IoFaultPoint, LOCAL_ROOTS_DIR, LocalIoOperation,
    LocalPublicationError, LocalPublicationGuidance, LocalPublicationLimits, LocalPublicationState,
    LocalRootPublisher, PublicationTransition, PublishOutcome, ROOT_RECORD_SUFFIX,
    ROOT_TEMP_SUFFIX, ReferenceRole, SlotName, VisibleRoot, root_record_bytes,
};

type TestResult = Result<(), Box<dyn Error>>;

fn fresh_root(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("local_publication_io_faults")
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

fn slot(name: &str) -> Result<SlotName, Box<dyn Error>> {
    Ok(SlotName::parse(name)?)
}

fn root_file(root: &Path, slot_name: &str) -> PathBuf {
    root.join(LOCAL_ROOTS_DIR)
        .join(format!("{slot_name}{ROOT_RECORD_SUFFIX}"))
}

fn root_temp(root: &Path, slot_name: &str) -> PathBuf {
    root.join(LOCAL_ROOTS_DIR)
        .join(format!("{slot_name}{ROOT_RECORD_SUFFIX}{ROOT_TEMP_SUFFIX}"))
}

fn dir_names(dir: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

fn expect_err<T: Debug>(
    result: Result<T, LocalPublicationError>,
) -> Result<LocalPublicationError, Box<dyn Error>> {
    match result {
        Ok(value) => Err(format!("expected a publication error, got {value:?}").into()),
        Err(error) => Ok(error),
    }
}

/// Stages two children and a metadata object and returns them with their manifest.
fn stage_fixture(
    publisher: &mut LocalRootPublisher,
) -> Result<(Vec<ContentDigest>, ObjectManifest), Box<dyn Error>> {
    let first = publisher.stage_object(b"clip-segment-0001")?;
    let second = publisher.stage_object(b"clip-segment-0002")?;
    let metadata = publisher.stage_object(b"event-metadata-v1")?;
    let manifest = ObjectManifest::new("event_archive", [first, second], Some(metadata))?;
    Ok((vec![first, second, metadata], manifest))
}

const FULL_TRANSITIONS: [PublicationTransition; 5] = [
    PublicationTransition::ChildrenVerified,
    PublicationTransition::ManifestBodyStaged,
    PublicationTransition::RootTempWritten,
    PublicationTransition::RootRenamed,
    PublicationTransition::RootDirectorySynced,
];

fn log_scenario(scenario: &str, detail: &str) {
    eprintln!(
        "{{\"suite\":\"local_publication_io_faults\",\"scenario\":\"{scenario}\",\"detail\":\"{detail}\",\"repro\":\"cargo +nightly-2026-08-31 test -p fss-publication --test local_publication_io_faults {scenario}\"}}"
    );
}

// ---------------------------------------------------------------------------------------------
// Failed rename of the root temporary record
// ---------------------------------------------------------------------------------------------

#[test]
fn failed_root_rename_leaves_nothing_visible_and_reopen_reconciles() -> TestResult {
    let root = fresh_root("failed_root_rename_leaves_nothing_visible_and_reopen_reconciles")?;
    let slot_name = slot("event-0001")?;
    let fault = InjectedIoFault::new(IoFaultPoint::RootRename, io::ErrorKind::PermissionDenied);
    let mut publisher = LocalRootPublisher::open_with_injected_io_fault(&root, limits(), fault)?;
    let (children, manifest) = stage_fixture(&mut publisher)?;

    let error = expect_err(publisher.publish(&slot_name, &manifest))?;
    assert_eq!(
        error,
        LocalPublicationError::Io {
            operation: LocalIoOperation::Rename,
            path: root_file(&root, "event-0001"),
            kind: io::ErrorKind::PermissionDenied,
        }
    );
    assert_eq!(error.code(), "ERR-PUBLICATION-LOCAL-IO-001");
    assert_eq!(error.guidance(), LocalPublicationGuidance::RepairStorage);
    assert!(
        !publisher.is_poisoned(),
        "a failed rename changed no visibility; the instance stays usable"
    );
    assert!(publisher.root(&slot_name).is_none());
    assert_eq!(publisher.visible_roots().count(), 0);
    assert!(
        dir_names(&root.join(LOCAL_ROOTS_DIR))?.is_empty(),
        "neither a root record nor its temporary may remain after a failed rename"
    );
    assert_eq!(
        publisher.spool().state(manifest.root()),
        Some(SpoolObjectState::Verified),
        "the manifest body is custody in the spool, not visibility"
    );
    drop(publisher);

    let mut reopened = LocalRootPublisher::open(&root, limits())?;
    let report = reopened.recovery_report().clone();
    assert!(report.roots.is_empty());
    assert!(report.broken_roots.is_empty());
    assert!(report.orphaned_temps.is_empty());
    let mut unreferenced = children.clone();
    unreferenced.push(manifest.root());
    unreferenced.sort_unstable();
    assert_eq!(report.unreferenced_objects, unreferenced);
    assert!(reopened.root(&slot_name).is_none());

    for digest in &children {
        reopened.verify_object(*digest)?;
    }
    let receipt = reopened.publish(&slot_name, &manifest)?;
    assert_eq!(receipt.outcome, PublishOutcome::Published);
    assert_eq!(receipt.claims.local, LocalPublicationState::Durable);
    assert_eq!(receipt.transitions, FULL_TRANSITIONS.to_vec());
    drop(reopened);

    let settled = LocalRootPublisher::open(&root, limits())?;
    let report = settled.recovery_report();
    assert!(
        report.is_clean(),
        "unexpected recovery findings: {report:?}"
    );
    assert_eq!(report.roots.len(), 1);
    assert_eq!(report.roots[0].state, LocalPublicationState::Durable);
    log_scenario(
        "failed_root_rename_leaves_nothing_visible_and_reopen_reconciles",
        "fault=root_rename visible=0 reopened_roots=0 retried=durable",
    );
    Ok(())
}

#[test]
fn failed_root_rename_fault_is_one_shot_and_the_instance_can_retry() -> TestResult {
    let root = fresh_root("failed_root_rename_fault_is_one_shot_and_the_instance_can_retry")?;
    let slot_name = slot("event-0001")?;
    let fault = InjectedIoFault::new(IoFaultPoint::RootRename, io::ErrorKind::Other);
    let mut publisher = LocalRootPublisher::open_with_injected_io_fault(&root, limits(), fault)?;
    let (_, manifest) = stage_fixture(&mut publisher)?;

    assert!(matches!(
        expect_err(publisher.publish(&slot_name, &manifest))?,
        LocalPublicationError::Io {
            operation: LocalIoOperation::Rename,
            kind: io::ErrorKind::Other,
            ..
        }
    ));
    let receipt = publisher.publish(&slot_name, &manifest)?;
    assert_eq!(receipt.outcome, PublishOutcome::Published);
    assert_eq!(receipt.claims.local, LocalPublicationState::Durable);
    assert_eq!(receipt.transitions, FULL_TRANSITIONS.to_vec());
    assert_eq!(
        dir_names(&root.join(LOCAL_ROOTS_DIR))?,
        vec!["event-0001.root".to_owned()]
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Failed roots-directory fsync after the rename
// ---------------------------------------------------------------------------------------------

#[test]
fn failed_directory_fsync_after_rename_is_visible_never_durable() -> TestResult {
    let root = fresh_root("failed_directory_fsync_after_rename_is_visible_never_durable")?;
    let slot_name = slot("event-0001")?;
    let fault = InjectedIoFault::new(IoFaultPoint::RootDirectorySync, io::ErrorKind::Other);
    let mut publisher = LocalRootPublisher::open_with_injected_io_fault(&root, limits(), fault)?;
    let (_, manifest) = stage_fixture(&mut publisher)?;
    let record = root_record_bytes(&slot_name, manifest.root(), 3)?;

    let error = expect_err(publisher.publish(&slot_name, &manifest))?;
    assert_eq!(
        error,
        LocalPublicationError::Indeterminate {
            path: root_file(&root, "event-0001"),
            kind: io::ErrorKind::Other,
        }
    );
    assert_eq!(error.code(), "ERR-PUBLICATION-LOCAL-INDETERMINATE-001");
    assert_eq!(
        error.guidance(),
        LocalPublicationGuidance::ReopenAndReconcile
    );
    assert!(publisher.is_poisoned());

    let visible = publisher
        .root(&slot_name)
        .ok_or("a renamed root must be reported, not hidden")?;
    assert_eq!(
        visible.state,
        LocalPublicationState::Visible,
        "a root whose directory fsync failed must never be claimed durable"
    );
    assert_eq!(visible.root, manifest.root());
    assert_eq!(visible.record_digest, ContentDigest::sha256(&record));
    assert!(
        publisher
            .visible_roots()
            .all(|root_entry| root_entry.state != LocalPublicationState::Durable)
    );
    assert_eq!(fs::read(root_file(&root, "event-0001"))?, record);
    assert!(!root_temp(&root, "event-0001").exists());

    // The poisoned instance refuses every mutation until it is reopened.
    assert_eq!(
        expect_err(publisher.publish(&slot_name, &manifest))?,
        LocalPublicationError::Poisoned
    );
    assert_eq!(
        expect_err(publisher.stage_object(b"after-indeterminate"))?,
        LocalPublicationError::Poisoned
    );
    assert_eq!(
        expect_err(publisher.discard_orphaned_temps())?,
        LocalPublicationError::Poisoned
    );
    drop(publisher);

    let mut reopened = LocalRootPublisher::open(&root, limits())?;
    let report = reopened.recovery_report().clone();
    assert!(
        report.is_clean(),
        "unexpected recovery findings: {report:?}"
    );
    assert_eq!(
        report.roots,
        vec![VisibleRoot {
            slot: slot_name.clone(),
            root: manifest.root(),
            record_digest: ContentDigest::sha256(&record),
            child_count: 3,
            state: LocalPublicationState::Durable,
        }],
        "reopen re-verifies the closure and fsyncs the roots directory before claiming durable"
    );
    let again = reopened.publish(&slot_name, &manifest)?;
    assert_eq!(again.outcome, PublishOutcome::AlreadyPublished);
    assert_eq!(again.claims.local, LocalPublicationState::Durable);
    log_scenario(
        "failed_directory_fsync_after_rename_is_visible_never_durable",
        "fault=root_directory_sync in_process=visible poisoned=true reopened=durable",
    );
    Ok(())
}

#[test]
fn directory_fsync_fault_fires_only_when_the_rename_is_reached() -> TestResult {
    let root = fresh_root("directory_fsync_fault_fires_only_when_the_rename_is_reached")?;
    let fault = InjectedIoFault::new(IoFaultPoint::RootDirectorySync, io::ErrorKind::Other);
    let mut publisher = LocalRootPublisher::open_with_injected_io_fault(&root, limits(), fault)?;
    let (children, manifest) = stage_fixture(&mut publisher)?;
    let first = children.first().copied().ok_or("fixture has children")?;
    let missing = ContentDigest::sha256(b"never-staged");
    let blocked = ObjectManifest::new("event_archive", [first, missing], None)?;

    // A publish that fails before the rename neither consumes the fault nor poisons.
    assert_eq!(
        expect_err(publisher.publish(&slot("event-0000")?, &blocked))?,
        LocalPublicationError::ReferenceBlocked {
            object: missing,
            role: ReferenceRole::Child,
            reason: BlockReason::Missing,
        }
    );
    assert!(!publisher.is_poisoned());
    assert!(dir_names(&root.join(LOCAL_ROOTS_DIR))?.is_empty());

    let slot_name = slot("event-0001")?;
    assert!(matches!(
        expect_err(publisher.publish(&slot_name, &manifest))?,
        LocalPublicationError::Indeterminate { .. }
    ));
    assert_eq!(
        publisher
            .root(&slot_name)
            .ok_or("renamed root must be reported")?
            .state,
        LocalPublicationState::Visible
    );
    Ok(())
}
