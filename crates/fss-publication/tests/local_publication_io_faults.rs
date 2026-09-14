#![forbid(unsafe_code)]
//! Failure paths of the root commit point (FSS-018, fss-x4a.7.6).
//!
//! A failed rename of the root temporary record and a failed roots-directory fsync after the
//! rename are injected as typed I/O errors (not crashes) through the test-only constructor
//! [`LocalRootPublisher::open_with_injected_io_fault`]. Every test owns one real directory under
//! `CARGO_TARGET_TMPDIR`, named after the test.
//!
//! Interrupted root-record writes (fss-x4a.7.5) are injected through the other test seam,
//! [`LocalRootPublisher::open_with_io`] with a `FaultInjectingSpoolIo`, whose write occurrence
//! numbers are derived from a plan-free probe run, never hard-coded.

use std::error::Error;
use std::fmt::Debug;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fss_core::ContentDigest;
use fss_object::{
    FaultInjectingSpoolIo, MAX_INTERRUPTED_ATTEMPTS, ObjectManifest, SpoolFaultPlan, SpoolIoCall,
    SpoolLimits, SpoolObjectState,
};
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

// ---------------------------------------------------------------------------------------------
// Interrupted root-record writes (bounded EINTR retry)
// ---------------------------------------------------------------------------------------------

/// Consecutive interrupted attempts at one offset that fail a root-record write.
fn interrupt_bound() -> u64 {
    u64::from(MAX_INTERRUPTED_ATTEMPTS)
}

fn open_faulted(
    root: &Path,
    plan: SpoolFaultPlan,
) -> Result<(LocalRootPublisher, Arc<FaultInjectingSpoolIo>), Box<dyn Error>> {
    let io = Arc::new(FaultInjectingSpoolIo::new(plan));
    let publisher = LocalRootPublisher::open_with_io(root, limits(), io.clone())?;
    Ok((publisher, io))
}

/// Occurrence number of the root temporary record's first write, from a plan-free probe run of
/// open + fixture staging + one publish on a separate root.
fn root_temp_write_occurrence(test_name: &str) -> Result<u64, Box<dyn Error>> {
    let root = fresh_root(&format!("{test_name}_probe"))?;
    let (mut publisher, io) = open_faulted(&root, SpoolFaultPlan::new())?;
    let (_, manifest) = stage_fixture(&mut publisher)?;
    let before_publish = io.calls(SpoolIoCall::Write);
    publisher.publish(&slot("event-0001")?, &manifest)?;
    let after_publish = io.calls(SpoolIoCall::Write);
    assert_eq!(
        after_publish,
        before_publish + 2,
        "publish writes the manifest body into the spool, then the root temporary record"
    );
    Ok(after_publish)
}

/// Checks a publish that retried interrupted root-record writes: the record is exact, Durable,
/// has no temporary left, and a host reopen admits exactly it.
fn assert_published_exactly(
    root: &Path,
    publisher: LocalRootPublisher,
    slot_name: &SlotName,
    manifest: &ObjectManifest,
) -> TestResult {
    let record = root_record_bytes(slot_name, manifest.root(), 3)?;
    let visible = publisher
        .root(slot_name)
        .ok_or("a published root must be visible")?;
    assert_eq!(visible.state, LocalPublicationState::Durable);
    assert_eq!(visible.record_digest, ContentDigest::sha256(&record));
    assert_eq!(fs::read(root_file(root, "event-0001"))?, record);
    assert!(!root_temp(root, "event-0001").exists());
    drop(publisher);

    let reopened = LocalRootPublisher::open(root, limits())?;
    let report = reopened.recovery_report();
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
        }]
    );
    Ok(())
}

#[test]
fn interrupted_root_record_writes_below_the_bound_publish_durable() -> TestResult {
    let name = "interrupted_root_record_writes_below_the_bound_publish_durable";
    let temp_write = root_temp_write_occurrence(name)?;
    let interruptions = interrupt_bound() - 1;
    let root = fresh_root(name)?;
    let slot_name = slot("event-0001")?;
    let plan = SpoolFaultPlan::new().interrupted(SpoolIoCall::Write, temp_write, interruptions);
    let (mut publisher, io) = open_faulted(&root, plan)?;
    let (_, manifest) = stage_fixture(&mut publisher)?;

    let receipt = publisher.publish(&slot_name, &manifest)?;
    assert_eq!(receipt.outcome, PublishOutcome::Published);
    assert_eq!(receipt.claims.local, LocalPublicationState::Durable);
    assert_eq!(receipt.transitions, FULL_TRANSITIONS.to_vec());
    assert!(io.all_fired());
    assert_eq!(io.calls(SpoolIoCall::Write), temp_write + interruptions);
    assert!(!publisher.is_poisoned());
    assert_published_exactly(&root, publisher, &slot_name, &manifest)?;
    log_scenario(
        name,
        "fault=root_temp_write_interrupted times=bound-1 retried=durable",
    );
    Ok(())
}

#[test]
fn interrupted_root_record_writes_at_the_bound_fail_typed_and_publish_nothing() -> TestResult {
    let name = "interrupted_root_record_writes_at_the_bound_fail_typed_and_publish_nothing";
    let temp_write = root_temp_write_occurrence(name)?;
    let root = fresh_root(name)?;
    let slot_name = slot("event-0001")?;
    let plan = SpoolFaultPlan::new().interrupted(SpoolIoCall::Write, temp_write, interrupt_bound());
    let (mut publisher, io) = open_faulted(&root, plan)?;
    let (children, manifest) = stage_fixture(&mut publisher)?;

    let error = expect_err(publisher.publish(&slot_name, &manifest))?;
    assert_eq!(
        error,
        LocalPublicationError::Io {
            operation: LocalIoOperation::WriteTemp,
            path: root_temp(&root, "event-0001"),
            kind: io::ErrorKind::Interrupted,
        }
    );
    assert_eq!(error.code(), "ERR-PUBLICATION-LOCAL-IO-001");
    assert!(
        error.to_string().contains("write_temp"),
        "the error must name the operation: {error}"
    );
    assert!(io.all_fired());
    assert_eq!(
        io.calls(SpoolIoCall::Write),
        temp_write + interrupt_bound() - 1,
        "the record write must stop at the bound, never retry past it"
    );
    assert!(!publisher.is_poisoned());
    assert!(publisher.root(&slot_name).is_none());
    assert_eq!(publisher.visible_roots().count(), 0);
    assert!(
        dir_names(&root.join(LOCAL_ROOTS_DIR))?.is_empty(),
        "neither a root record nor its temporary may remain after an interrupted write"
    );
    assert_eq!(
        publisher.spool().state(manifest.root()),
        Some(SpoolObjectState::Verified),
        "the manifest body is custody in the spool, not visibility"
    );
    assert_eq!(publisher.spool().orphaned_staging().count(), 0);
    let in_session_bytes = publisher.spool().occupied_bytes()?;
    drop(publisher);

    let mut reopened = LocalRootPublisher::open(&root, limits())?;
    let report = reopened.recovery_report().clone();
    assert!(report.roots.is_empty());
    assert!(report.broken_roots.is_empty());
    assert!(report.orphaned_temps.is_empty());
    let mut unreferenced = children;
    unreferenced.push(manifest.root());
    unreferenced.sort_unstable();
    assert_eq!(report.unreferenced_objects, unreferenced);
    assert_eq!(reopened.spool().occupied_bytes()?, in_session_bytes);
    assert_eq!(reopened.spool().orphaned_staging().count(), 0);

    for digest in &unreferenced {
        reopened.verify_object(*digest)?;
    }
    let receipt = reopened.publish(&slot_name, &manifest)?;
    assert_eq!(receipt.outcome, PublishOutcome::Published);
    assert_eq!(receipt.claims.local, LocalPublicationState::Durable);
    assert_published_exactly(&root, reopened, &slot_name, &manifest)?;
    log_scenario(
        name,
        "fault=root_temp_write_interrupted times=bound visible=0 reopened_roots=0 retried=durable",
    );
    Ok(())
}

#[test]
fn interrupted_root_record_write_resumes_at_the_partial_write_offset() -> TestResult {
    let name = "interrupted_root_record_write_resumes_at_the_partial_write_offset";
    let temp_write = root_temp_write_occurrence(name)?;
    let bound = interrupt_bound();
    let root = fresh_root(name)?;
    let slot_name = slot("event-0001")?;
    // 5 bytes land; bound-1 interruptions at offset 5; 3 more land; bound-1 interruptions at
    // offset 8; the final write lands the rest. Progress resets the per-offset count.
    let plan = SpoolFaultPlan::new()
        .short_write(temp_write, 5)
        .interrupted(SpoolIoCall::Write, temp_write + 1, bound - 1)
        .short_write(temp_write + bound, 3)
        .interrupted(SpoolIoCall::Write, temp_write + bound + 1, bound - 1);
    let (mut publisher, io) = open_faulted(&root, plan)?;
    let (_, manifest) = stage_fixture(&mut publisher)?;

    let receipt = publisher.publish(&slot_name, &manifest)?;
    assert_eq!(receipt.outcome, PublishOutcome::Published);
    assert_eq!(receipt.claims.local, LocalPublicationState::Durable);
    assert!(io.all_fired());
    assert_eq!(io.calls(SpoolIoCall::Write), temp_write + 2 * bound);
    assert_published_exactly(&root, publisher, &slot_name, &manifest)?;
    log_scenario(
        name,
        "fault=root_temp_partial_write_then_interrupted resumed=exact durable=true",
    );
    Ok(())
}

#[test]
fn interrupted_root_record_write_after_a_partial_write_is_bounded_at_that_offset() -> TestResult {
    let name = "interrupted_root_record_write_after_a_partial_write_is_bounded_at_that_offset";
    let temp_write = root_temp_write_occurrence(name)?;
    let bound = interrupt_bound();
    let root = fresh_root(name)?;
    let slot_name = slot("event-0001")?;
    let plan = SpoolFaultPlan::new()
        .short_write(temp_write, 5)
        .interrupted(SpoolIoCall::Write, temp_write + 1, bound);
    let (mut publisher, io) = open_faulted(&root, plan)?;
    let (_, manifest) = stage_fixture(&mut publisher)?;

    assert_eq!(
        expect_err(publisher.publish(&slot_name, &manifest))?,
        LocalPublicationError::Io {
            operation: LocalIoOperation::WriteTemp,
            path: root_temp(&root, "event-0001"),
            kind: io::ErrorKind::Interrupted,
        }
    );
    assert!(io.all_fired());
    assert_eq!(io.calls(SpoolIoCall::Write), temp_write + bound);
    assert!(!publisher.is_poisoned());
    assert_eq!(publisher.visible_roots().count(), 0);
    assert!(dir_names(&root.join(LOCAL_ROOTS_DIR))?.is_empty());

    let receipt = publisher.publish(&slot_name, &manifest)?;
    assert_eq!(receipt.claims.local, LocalPublicationState::Durable);
    assert_published_exactly(&root, publisher, &slot_name, &manifest)
}

// ---------------------------------------------------------------------------------------------
// Bounded directory scan (fss-2h5zq.9)
// ---------------------------------------------------------------------------------------------

/// Past `max_scan_entries` the roots scan stops at the first extra entry and reports only a lower
/// bound, `at_least: maximum + 1`. It never lists the rest of the directory: the number of
/// directory-entry reads is the same for a slightly and a heavily overfull roots directory.
#[test]
fn roots_scan_stops_at_bound_plus_one_regardless_of_directory_size() -> TestResult {
    let mut entry_reads = Vec::new();
    for extra in [4_usize, 40] {
        let root = fresh_root(&format!("roots_scan_stops_at_bound_plus_one_{extra}"))?;
        drop(LocalRootPublisher::open(&root, limits())?);
        let roots_dir = root.join(LOCAL_ROOTS_DIR);
        for index in 0..(64 + extra) {
            fs::write(roots_dir.join(format!("junk-{index:04}")), b"x")?;
        }
        let io = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new()));
        let error = expect_err(LocalRootPublisher::open_with_io(
            &root,
            limits(),
            io.clone(),
        ))?;
        assert_eq!(
            error,
            LocalPublicationError::EntryLimit {
                directory: roots_dir,
                maximum: 64,
                at_least: 65,
            }
        );
        entry_reads.push(io.calls(SpoolIoCall::NextDirEntry));
        log_scenario(
            "roots_scan_stops_at_bound_plus_one_regardless_of_directory_size",
            &format!("extra={extra}"),
        );
    }
    assert_eq!(
        entry_reads[0], entry_reads[1],
        "the roots scan must stop at bound + 1 whatever the directory size"
    );
    Ok(())
}
