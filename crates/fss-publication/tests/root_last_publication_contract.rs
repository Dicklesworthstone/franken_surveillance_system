#![forbid(unsafe_code)]
//! Contract tests for root-last local manifest publication over the staging spool (FSS-018,
//! fss-x4a.7.6).
//!
//! Every test owns one real directory under `CARGO_TARGET_TMPDIR`, named after the test, so no
//! shared counter or ambient state participates in naming. Each scenario emits one bounded,
//! secret-free structured log line with its scenario name, seed, transitions, and outcome.

use std::cell::RefCell;
use std::error::Error;
use std::fmt::Debug;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, Generation, ObjectId, TombstoneReason, TombstoneRecord};
use fss_object::{
    MAX_MANIFEST_CHILDREN, ObjectError, ObjectManifest, SPOOL_OBJECTS_DIR, SpoolLimits,
    SpoolObjectState, TombstoneRecord as ObjectTombstoneRecord,
};
use fss_publication::{
    BlockReason, BrokenRootReason, CapacityResource, ClaimStatus, LOCAL_LOCK_FILE,
    LOCAL_PUBLICATION_ERROR_CODES, LOCAL_ROOT_RECORD_DOMAIN, LOCAL_ROOT_RECORD_FORMAT_VERSION,
    LOCAL_ROOTS_DIR, LOCAL_SPOOL_DIR, LOCAL_TOMBSTONES_DIR, LocalLimitViolation,
    LocalPublicationError, LocalPublicationGuidance, LocalPublicationLimits, LocalPublicationState,
    LocalRootPublisher, MAX_LOCAL_ROOTS, MAX_SLOT_NAME_BYTES, PublicationTransition,
    PublishCancellation, PublishCutPoint, PublishOutcome, ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX,
    ReferenceRole, SlotName, SlotViolation, TombstoneOutcome, root_record_bytes,
};

type TestResult = Result<(), Box<dyn Error>>;

const SEED: u64 = 0x0018_7006;

/// Returns a not-yet-existing directory owned by exactly one test, named after that test.
fn fresh_root(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("root_last_publication_contract")
        .join(test_name);
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(root)
}

fn limits(max_roots: usize, max_children: usize, max_tombstones: usize) -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        max_roots,
        max_children,
        max_tombstones,
        64,
        SpoolLimits::new(64, 1 << 20, 4096, 64),
    )
}

fn roomy() -> LocalPublicationLimits {
    limits(8, 16, 8)
}

fn expect_err<T: Debug>(
    result: Result<T, LocalPublicationError>,
) -> Result<LocalPublicationError, Box<dyn Error>> {
    match result {
        Ok(value) => Err(format!("expected a publication error, got {value:?}").into()),
        Err(error) => Ok(error),
    }
}

fn slot(name: &str) -> Result<SlotName, Box<dyn Error>> {
    Ok(SlotName::parse(name)?)
}

fn hex(digest: ContentDigest) -> String {
    digest.to_text().trim_start_matches("sha256:").to_owned()
}

fn root_file(root: &Path, slot_name: &str) -> PathBuf {
    root.join(LOCAL_ROOTS_DIR)
        .join(format!("{slot_name}{ROOT_RECORD_SUFFIX}"))
}

fn root_temp(root: &Path, slot_name: &str) -> PathBuf {
    root.join(LOCAL_ROOTS_DIR)
        .join(format!("{slot_name}{ROOT_RECORD_SUFFIX}{ROOT_TEMP_SUFFIX}"))
}

fn object_file(root: &Path, digest: ContentDigest) -> PathBuf {
    root.join(LOCAL_SPOOL_DIR)
        .join(SPOOL_OBJECTS_DIR)
        .join(hex(digest))
}

fn dir_names(dir: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

fn flip_last_byte(path: &Path) -> TestResult {
    let mut bytes = fs::read(path)?;
    let last = bytes.last_mut().ok_or("cannot corrupt an empty file")?;
    *last ^= 0x01;
    fs::write(path, bytes)?;
    Ok(())
}

fn log_scenario(scenario: &str, detail: &str) {
    eprintln!(
        "{{\"suite\":\"root_last_publication_contract\",\"scenario\":\"{scenario}\",\"seed\":{SEED},\"detail\":\"{detail}\",\"repro\":\"cargo +nightly-2026-08-31 test -p fss-publication --test root_last_publication_contract {scenario}\"}}"
    );
}

/// Two leaf children plus a typed metadata object, all staged and verified in the spool.
struct Fixture {
    publisher: LocalRootPublisher,
    first: ContentDigest,
    second: ContentDigest,
    metadata: ContentDigest,
    manifest: ObjectManifest,
}

fn fixture(root: &Path, limits: LocalPublicationLimits) -> Result<Fixture, Box<dyn Error>> {
    let mut publisher = LocalRootPublisher::open(root, limits)?;
    let first = publisher.stage_object(b"clip-segment-0001")?;
    let second = publisher.stage_object(b"clip-segment-0002")?;
    let metadata = publisher.stage_object(b"event-metadata-v1")?;
    let manifest = ObjectManifest::new("event_archive", [first, second], Some(metadata))?;
    Ok(Fixture {
        publisher,
        first,
        second,
        metadata,
        manifest,
    })
}

fn sorted(mut digests: Vec<ContentDigest>) -> Vec<ContentDigest> {
    digests.sort_unstable();
    digests
}

fn tombstone_for(
    object: ContentDigest,
    witness: Option<ContentDigest>,
    reason: TombstoneReason,
) -> Result<TombstoneRecord, Box<dyn Error>> {
    Ok(TombstoneRecord::new(
        ObjectId::parse("object:clip-segment:1")?,
        Generation(2),
        Generation(1),
        reason,
        witness,
        object,
    )?)
}

struct CancelAt {
    point: Option<PublishCutPoint>,
    asked: RefCell<Vec<PublishCutPoint>>,
}

impl CancelAt {
    fn new(point: Option<PublishCutPoint>) -> Self {
        Self {
            point,
            asked: RefCell::new(Vec::new()),
        }
    }
}

impl PublishCancellation for CancelAt {
    fn cancel_requested(&self, point: PublishCutPoint) -> bool {
        self.asked.borrow_mut().push(point);
        self.point == Some(point)
    }
}

// ---------------------------------------------------------------------------------------------
// Success path and state lattice
// ---------------------------------------------------------------------------------------------

#[test]
fn publish_makes_root_durable_and_claims_nothing_beyond_local() -> TestResult {
    let root = fresh_root("publish_makes_root_durable_and_claims_nothing_beyond_local")?;
    let Fixture {
        mut publisher,
        first,
        second,
        metadata,
        manifest,
    } = fixture(&root, roomy())?;
    let slot_name = slot("event-0001")?;

    let receipt = publisher.publish(&slot_name, &manifest)?;
    assert_eq!(receipt.slot, slot_name);
    assert_eq!(receipt.root, manifest.root());
    assert_eq!(receipt.child_count, 3);
    assert_eq!(receipt.closure_object_count, 4);
    assert_eq!(receipt.outcome, PublishOutcome::Published);
    assert_eq!(receipt.claims.local, LocalPublicationState::Durable);
    assert_eq!(receipt.claims.replicated, ClaimStatus::NotClaimed);
    assert_eq!(receipt.claims.protected, ClaimStatus::NotClaimed);
    assert_eq!(receipt.claims.retrievable, ClaimStatus::NotClaimed);
    assert_eq!(
        receipt.transitions,
        vec![
            PublicationTransition::ChildrenVerified,
            PublicationTransition::ManifestBodyStaged,
            PublicationTransition::RootTempWritten,
            PublicationTransition::RootRenamed,
            PublicationTransition::RootDirectorySynced,
        ]
    );

    let visible = publisher
        .root(&slot_name)
        .ok_or("published slot is not visible")?;
    assert_eq!(visible.root, manifest.root());
    assert_eq!(visible.state, LocalPublicationState::Durable);
    assert_eq!(visible.record_digest, receipt.record_digest);
    assert_eq!(
        publisher.spool().state(manifest.root()),
        Some(SpoolObjectState::Verified)
    );
    assert_eq!(
        dir_names(&root.join(LOCAL_ROOTS_DIR))?,
        vec!["event-0001.root".to_owned()]
    );
    drop(publisher);

    let reopened = LocalRootPublisher::open(&root, roomy())?;
    let report = reopened.recovery_report();
    assert!(
        report.is_clean(),
        "unexpected recovery findings: {report:?}"
    );
    assert_eq!(report.roots.len(), 1);
    assert_eq!(report.roots[0].slot, slot_name);
    assert_eq!(report.roots[0].root, manifest.root());
    assert_eq!(report.roots[0].state, LocalPublicationState::Durable);
    assert!(report.unreferenced_objects.is_empty());
    for digest in [first, second, metadata, manifest.root()] {
        assert_eq!(
            reopened.spool().state(digest),
            Some(SpoolObjectState::Verified)
        );
    }
    log_scenario(
        "publish_makes_root_durable_and_claims_nothing_beyond_local",
        "published=durable replicated=not_claimed protected=not_claimed retrievable=not_claimed",
    );
    Ok(())
}

#[test]
fn root_record_encoding_is_hand_audited() -> TestResult {
    let root = fresh_root("root_record_encoding_is_hand_audited")?;
    let Fixture {
        mut publisher,
        manifest,
        ..
    } = fixture(&root, roomy())?;
    let slot_name = slot("event-0001")?;
    let receipt = publisher.publish(&slot_name, &manifest)?;

    let mut body = Vec::new();
    let domain = LOCAL_ROOT_RECORD_DOMAIN.as_bytes();
    body.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    body.extend_from_slice(domain);
    body.extend_from_slice(&LOCAL_ROOT_RECORD_FORMAT_VERSION.to_be_bytes());
    body.extend_from_slice(&10_u64.to_be_bytes());
    body.extend_from_slice(b"event-0001");
    body.push(1);
    body.extend_from_slice(&manifest.root().bytes());
    body.extend_from_slice(&3_u64.to_be_bytes());
    let checksum = ContentDigest::sha256(&body);
    let mut expected = body;
    expected.push(1);
    expected.extend_from_slice(&checksum.bytes());

    assert_eq!(LOCAL_ROOT_RECORD_DOMAIN, "fss.local_root_record.v1");
    assert_eq!(LOCAL_ROOT_RECORD_FORMAT_VERSION, 1);
    assert_eq!(root_record_bytes(&slot_name, manifest.root(), 3)?, expected);
    assert_eq!(fs::read(root_file(&root, "event-0001"))?, expected);
    assert_eq!(receipt.record_digest, ContentDigest::sha256(&expected));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Crash cut points
// ---------------------------------------------------------------------------------------------

#[test]
fn crash_after_object_writes_leaves_nothing_visible() -> TestResult {
    let root = fresh_root("crash_after_object_writes_leaves_nothing_visible")?;
    let Fixture {
        mut publisher,
        first,
        second,
        metadata,
        manifest,
    } = fixture(&root, roomy())?;
    let slot_name = slot("event-0001")?;

    publisher.inject_crash_at(PublishCutPoint::AfterChildrenVerified);
    let error = expect_err(publisher.publish(&slot_name, &manifest))?;
    assert_eq!(
        error,
        LocalPublicationError::InjectedCrash {
            point: PublishCutPoint::AfterChildrenVerified
        }
    );
    assert!(publisher.is_poisoned());
    assert!(publisher.root(&slot_name).is_none());
    assert_eq!(
        expect_err(publisher.publish(&slot_name, &manifest))?,
        LocalPublicationError::Poisoned
    );
    assert_eq!(publisher.spool().state(manifest.root()), None);
    drop(publisher);

    assert!(dir_names(&root.join(LOCAL_ROOTS_DIR))?.is_empty());
    let reopened = LocalRootPublisher::open(&root, roomy())?;
    let report = reopened.recovery_report();
    assert!(report.roots.is_empty());
    assert!(reopened.root(&slot_name).is_none());
    assert_eq!(
        report.unreferenced_objects,
        sorted(vec![first, second, metadata])
    );
    assert!(!report.is_clean());
    log_scenario(
        "crash_after_object_writes_leaves_nothing_visible",
        "cut=after_children_verified visible=0 unreferenced=3",
    );
    Ok(())
}

#[test]
fn crash_after_manifest_body_before_rename_leaves_nothing_visible() -> TestResult {
    let root = fresh_root("crash_after_manifest_body_before_rename_leaves_nothing_visible")?;
    let Fixture {
        mut publisher,
        first,
        second,
        metadata,
        manifest,
    } = fixture(&root, roomy())?;
    let slot_name = slot("event-0001")?;

    publisher.inject_crash_at(PublishCutPoint::AfterManifestBody);
    let error = expect_err(publisher.publish(&slot_name, &manifest))?;
    assert_eq!(
        error,
        LocalPublicationError::InjectedCrash {
            point: PublishCutPoint::AfterManifestBody
        }
    );
    assert_eq!(
        publisher.spool().state(manifest.root()),
        Some(SpoolObjectState::Verified),
        "manifest body is staged and verified but must not be visible"
    );
    assert!(publisher.root(&slot_name).is_none());
    drop(publisher);

    assert!(dir_names(&root.join(LOCAL_ROOTS_DIR))?.is_empty());
    let reopened = LocalRootPublisher::open(&root, roomy())?;
    let report = reopened.recovery_report();
    assert!(report.roots.is_empty());
    assert!(report.orphaned_temps.is_empty());
    assert_eq!(
        report.unreferenced_objects,
        sorted(vec![first, second, metadata, manifest.root()])
    );
    Ok(())
}

#[test]
fn crash_after_root_temp_write_before_rename_leaves_nothing_visible() -> TestResult {
    let root = fresh_root("crash_after_root_temp_write_before_rename_leaves_nothing_visible")?;
    let Fixture {
        mut publisher,
        first,
        second,
        metadata,
        manifest,
    } = fixture(&root, roomy())?;
    let slot_name = slot("event-0001")?;

    publisher.inject_crash_at(PublishCutPoint::AfterRootTempWrite);
    let error = expect_err(publisher.publish(&slot_name, &manifest))?;
    assert_eq!(
        error,
        LocalPublicationError::InjectedCrash {
            point: PublishCutPoint::AfterRootTempWrite
        }
    );
    assert!(publisher.root(&slot_name).is_none());
    drop(publisher);

    assert!(root_temp(&root, "event-0001").is_file());
    assert!(!root_file(&root, "event-0001").exists());

    let mut reopened = LocalRootPublisher::open(&root, roomy())?;
    let report = reopened.recovery_report().clone();
    assert!(report.roots.is_empty());
    assert!(reopened.root(&slot_name).is_none());
    assert_eq!(
        report.orphaned_temps,
        vec![PathBuf::from(LOCAL_ROOTS_DIR).join("event-0001.root.tmp")]
    );
    assert_eq!(
        report.unreferenced_objects,
        sorted(vec![first, second, metadata, manifest.root()])
    );

    // The orphaned temp blocks the slot until it is explicitly discarded; it is never promoted.
    let blocked = expect_err(reopened.publish(&slot_name, &manifest))?;
    assert_eq!(
        blocked,
        LocalPublicationError::OrphanedTemp {
            path: PathBuf::from(LOCAL_ROOTS_DIR).join("event-0001.root.tmp")
        }
    );
    assert_eq!(blocked.guidance(), LocalPublicationGuidance::DiscardOrphans);
    assert!(reopened.root(&slot_name).is_none());

    // Reopened children are only Staged; publishing requires fresh verification proof.
    assert_eq!(reopened.discard_orphaned_temps()?, 1);
    let unverified = expect_err(reopened.publish(&slot_name, &manifest))?;
    assert!(matches!(
        unverified,
        LocalPublicationError::ReferenceBlocked {
            reason: BlockReason::NotVerified,
            ..
        }
    ));
    for digest in [first, second, metadata] {
        reopened.verify_object(digest)?;
    }
    let receipt = reopened.publish(&slot_name, &manifest)?;
    assert_eq!(receipt.claims.local, LocalPublicationState::Durable);
    log_scenario(
        "crash_after_root_temp_write_before_rename_leaves_nothing_visible",
        "cut=after_root_temp_write visible=0 orphaned_temps=1 recovered=durable",
    );
    Ok(())
}

#[test]
fn crash_after_rename_before_directory_fsync_is_visible_not_durable() -> TestResult {
    let root = fresh_root("crash_after_rename_before_directory_fsync_is_visible_not_durable")?;
    let Fixture {
        mut publisher,
        manifest,
        ..
    } = fixture(&root, roomy())?;
    let slot_name = slot("event-0001")?;

    publisher.inject_crash_at(PublishCutPoint::AfterRootRename);
    let error = expect_err(publisher.publish(&slot_name, &manifest))?;
    assert_eq!(
        error,
        LocalPublicationError::InjectedCrash {
            point: PublishCutPoint::AfterRootRename
        }
    );
    assert_eq!(
        error.guidance(),
        LocalPublicationGuidance::ReopenAndReconcile
    );
    let visible = publisher
        .root(&slot_name)
        .ok_or("renamed root must be reported visible")?;
    assert_eq!(
        visible.state,
        LocalPublicationState::Visible,
        "a root whose directory fsync never ran must not be claimed durable"
    );
    assert!(publisher.is_poisoned());
    drop(publisher);

    let reopened = LocalRootPublisher::open(&root, roomy())?;
    let report = reopened.recovery_report();
    assert_eq!(report.roots.len(), 1);
    assert_eq!(report.roots[0].root, manifest.root());
    assert_eq!(
        report.roots[0].state,
        LocalPublicationState::Durable,
        "reopen re-verifies the closure and fsyncs the root directory before claiming durable"
    );
    assert!(report.unreferenced_objects.is_empty());
    log_scenario(
        "crash_after_rename_before_directory_fsync_is_visible_not_durable",
        "cut=after_root_rename in_process=visible reopened=durable",
    );
    Ok(())
}

#[test]
fn cancellation_before_rename_never_publishes() -> TestResult {
    for (index, point) in [
        PublishCutPoint::AfterChildrenVerified,
        PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite,
    ]
    .into_iter()
    .enumerate()
    {
        let root = fresh_root(&format!(
            "cancellation_before_rename_never_publishes_{index}"
        ))?;
        let Fixture {
            mut publisher,
            manifest,
            ..
        } = fixture(&root, roomy())?;
        let slot_name = slot("event-0001")?;
        let cancel = CancelAt::new(Some(point));
        let error = expect_err(publisher.publish_cancellable(&slot_name, &manifest, &cancel))?;
        assert_eq!(error, LocalPublicationError::Cancelled { point });
        assert_eq!(
            error.guidance(),
            LocalPublicationGuidance::RetryIdempotently
        );
        assert!(!publisher.is_poisoned());
        assert!(publisher.root(&slot_name).is_none());
        assert!(dir_names(&root.join(LOCAL_ROOTS_DIR))?.is_empty());

        let receipt = publisher.publish(&slot_name, &manifest)?;
        assert_eq!(receipt.outcome, PublishOutcome::Published);
    }

    let root = fresh_root("cancellation_before_rename_never_publishes_probe")?;
    let Fixture {
        mut publisher,
        manifest,
        ..
    } = fixture(&root, roomy())?;
    let probe = CancelAt::new(None);
    publisher.publish_cancellable(&slot("event-0001")?, &manifest, &probe)?;
    assert_eq!(
        *probe.asked.borrow(),
        vec![
            PublishCutPoint::AfterChildrenVerified,
            PublishCutPoint::AfterManifestBody,
            PublishCutPoint::AfterRootTempWrite,
        ],
        "cancellation is never consulted after the rename commit point"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Blocked references
// ---------------------------------------------------------------------------------------------

#[test]
fn missing_reference_blocks_publication_naming_the_object() -> TestResult {
    let root = fresh_root("missing_reference_blocks_publication_naming_the_object")?;
    let Fixture {
        mut publisher,
        first,
        ..
    } = fixture(&root, roomy())?;
    let missing = ContentDigest::sha256(b"never-staged");
    let manifest = ObjectManifest::new("event_archive", [first, missing], None)?;
    let objects_before = publisher.spool().object_count();

    let error = expect_err(publisher.publish(&slot("event-0001")?, &manifest))?;
    assert_eq!(
        error,
        LocalPublicationError::ReferenceBlocked {
            object: missing,
            role: ReferenceRole::Child,
            reason: BlockReason::Missing,
        }
    );
    assert_eq!(error.code(), "ERR-PUBLICATION-PARTIAL-001");
    assert_eq!(
        error.guidance(),
        LocalPublicationGuidance::StageAndVerifyReferences
    );
    assert_eq!(publisher.spool().object_count(), objects_before);
    assert_eq!(publisher.spool().state(manifest.root()), None);
    assert!(dir_names(&root.join(LOCAL_ROOTS_DIR))?.is_empty());
    assert!(!publisher.is_poisoned());
    log_scenario(
        "missing_reference_blocks_publication_naming_the_object",
        "outcome=ERR-PUBLICATION-PARTIAL-001 visible=0",
    );
    Ok(())
}

#[test]
fn corrupt_reference_blocks_publication_naming_the_object() -> TestResult {
    let root = fresh_root("corrupt_reference_blocks_publication_naming_the_object")?;
    let Fixture {
        mut publisher,
        metadata,
        manifest,
        ..
    } = fixture(&root, roomy())?;
    flip_last_byte(&object_file(&root, metadata))?;

    let error = expect_err(publisher.publish(&slot("event-0001")?, &manifest))?;
    assert_eq!(
        error,
        LocalPublicationError::ReferenceBlocked {
            object: metadata,
            role: ReferenceRole::Metadata,
            reason: BlockReason::Corrupt,
        }
    );
    assert_eq!(error.code(), "ERR-PUBLICATION-LOCAL-CORRUPT-REFERENCE-001");
    assert_eq!(error.guidance(), LocalPublicationGuidance::RepairCustody);
    assert!(dir_names(&root.join(LOCAL_ROOTS_DIR))?.is_empty());
    assert_eq!(publisher.spool().state(manifest.root()), None);
    Ok(())
}

#[test]
fn tombstoned_reference_blocks_publication_and_survives_reopen() -> TestResult {
    let root = fresh_root("tombstoned_reference_blocks_publication_and_survives_reopen")?;
    let Fixture {
        mut publisher,
        first,
        second,
        metadata,
        manifest,
    } = fixture(&root, roomy())?;
    let witness = publisher.stage_object(b"owner-deletion-authorization")?;

    let no_authority = tombstone_for(second, None, TombstoneReason::Deleted)?;
    assert_eq!(
        expect_err(publisher.record_tombstone(no_authority))?,
        LocalPublicationError::MissingDeletionAuthority { object: second }
    );
    let unverified_witness = ContentDigest::sha256(b"unstaged-witness");
    assert_eq!(
        expect_err(publisher.record_tombstone(tombstone_for(
            second,
            Some(unverified_witness),
            TombstoneReason::Deleted
        )?))?,
        LocalPublicationError::ReferenceBlocked {
            object: unverified_witness,
            role: ReferenceRole::DeletionWitness,
            reason: BlockReason::Missing,
        }
    );

    let record = tombstone_for(second, Some(witness), TombstoneReason::Deleted)?;
    assert_eq!(
        publisher.record_tombstone(record.clone())?,
        TombstoneOutcome::Recorded
    );
    assert_eq!(
        publisher.record_tombstone(record.clone())?,
        TombstoneOutcome::AlreadyRecorded
    );
    assert_eq!(
        expect_err(publisher.record_tombstone(tombstone_for(
            second,
            Some(witness),
            TombstoneReason::Revoked
        )?))?,
        LocalPublicationError::TombstoneConflict { object: second }
    );

    let error = expect_err(publisher.publish(&slot("event-0001")?, &manifest))?;
    assert_eq!(
        error,
        LocalPublicationError::ReferenceBlocked {
            object: second,
            role: ReferenceRole::Child,
            reason: BlockReason::Tombstoned,
        }
    );
    assert_eq!(
        error.code(),
        "ERR-PUBLICATION-LOCAL-TOMBSTONED-REFERENCE-001"
    );
    drop(publisher);

    let mut reopened = LocalRootPublisher::open(&root, roomy())?;
    assert_eq!(reopened.recovery_report().tombstones, vec![second]);
    for digest in [first, second, metadata] {
        reopened.verify_object(digest)?;
    }
    assert_eq!(
        expect_err(reopened.publish(&slot("event-0001")?, &manifest))?,
        LocalPublicationError::ReferenceBlocked {
            object: second,
            role: ReferenceRole::Child,
            reason: BlockReason::Tombstoned,
        }
    );
    log_scenario(
        "tombstoned_reference_blocks_publication_and_survives_reopen",
        "outcome=ERR-PUBLICATION-LOCAL-TOMBSTONED-REFERENCE-001 durable_tombstones=1",
    );
    Ok(())
}

#[test]
fn tombstoning_an_object_reachable_from_a_visible_root_is_refused() -> TestResult {
    let root = fresh_root("tombstoning_an_object_reachable_from_a_visible_root_is_refused")?;
    let Fixture {
        mut publisher,
        first,
        manifest,
        ..
    } = fixture(&root, roomy())?;
    let witness = publisher.stage_object(b"owner-deletion-authorization")?;
    let slot_name = slot("event-0001")?;
    publisher.publish(&slot_name, &manifest)?;

    for object in [first, manifest.root()] {
        let error = expect_err(publisher.record_tombstone(tombstone_for(
            object,
            Some(witness),
            TombstoneReason::Deleted,
        )?))?;
        assert_eq!(
            error,
            LocalPublicationError::TombstoneBlockedByVisibleRoot {
                object,
                slot: slot_name.clone(),
            }
        );
    }
    assert!(dir_names(&root.join(LOCAL_TOMBSTONES_DIR))?.is_empty());
    assert_eq!(
        publisher
            .root(&slot_name)
            .ok_or("root must remain visible")?
            .state,
        LocalPublicationState::Durable
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Idempotence and conflicts
// ---------------------------------------------------------------------------------------------

#[test]
fn republishing_the_same_root_is_idempotent() -> TestResult {
    let root = fresh_root("republishing_the_same_root_is_idempotent")?;
    let Fixture {
        mut publisher,
        manifest,
        ..
    } = fixture(&root, roomy())?;
    let slot_name = slot("event-0001")?;
    let first = publisher.publish(&slot_name, &manifest)?;
    let record_before = fs::read(root_file(&root, "event-0001"))?;
    let objects_before = publisher.spool().object_count();

    let second = publisher.publish(&slot_name, &manifest)?;
    assert_eq!(second.outcome, PublishOutcome::AlreadyPublished);
    assert_eq!(second.root, first.root);
    assert_eq!(second.record_digest, first.record_digest);
    assert_eq!(second.claims, first.claims);
    assert_eq!(
        second.transitions,
        vec![PublicationTransition::ExistingRootReverified]
    );
    assert_eq!(fs::read(root_file(&root, "event-0001"))?, record_before);
    assert_eq!(publisher.spool().object_count(), objects_before);
    drop(publisher);

    let mut reopened = LocalRootPublisher::open(&root, roomy())?;
    let third = reopened.publish(&slot_name, &manifest)?;
    assert_eq!(third.outcome, PublishOutcome::AlreadyPublished);
    assert_eq!(third.record_digest, first.record_digest);
    Ok(())
}

#[test]
fn different_root_for_same_slot_is_a_typed_conflict() -> TestResult {
    let root = fresh_root("different_root_for_same_slot_is_a_typed_conflict")?;
    let Fixture {
        mut publisher,
        first,
        manifest,
        ..
    } = fixture(&root, roomy())?;
    let slot_name = slot("event-0001")?;
    publisher.publish(&slot_name, &manifest)?;
    let record_before = fs::read(root_file(&root, "event-0001"))?;

    let rival = ObjectManifest::new("event_archive", [first], None)?;
    let error = expect_err(publisher.publish(&slot_name, &rival))?;
    assert_eq!(
        error,
        LocalPublicationError::SlotConflict {
            slot: slot_name.clone(),
            existing: manifest.root(),
            requested: rival.root(),
        }
    );
    assert_eq!(error.code(), "ERR-PUBLICATION-LOCAL-SLOT-CONFLICT-001");
    assert_eq!(error.guidance(), LocalPublicationGuidance::RejectInput);
    assert_eq!(fs::read(root_file(&root, "event-0001"))?, record_before);
    assert_eq!(
        publisher
            .root(&slot_name)
            .ok_or("existing root must remain")?
            .root,
        manifest.root()
    );
    assert_eq!(publisher.spool().state(rival.root()), None);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Bounds at exactly the bound and bound + 1
// ---------------------------------------------------------------------------------------------

#[test]
fn slot_name_bound_and_grammar() -> TestResult {
    let at_bound = "a".repeat(MAX_SLOT_NAME_BYTES);
    assert_eq!(SlotName::parse(&at_bound)?.as_str(), at_bound);
    let over = "a".repeat(MAX_SLOT_NAME_BYTES + 1);
    assert_eq!(
        SlotName::parse(&over),
        Err(SlotViolation::TooLong {
            length: MAX_SLOT_NAME_BYTES + 1,
            maximum: MAX_SLOT_NAME_BYTES,
        })
    );
    assert_eq!(SlotName::parse(""), Err(SlotViolation::Empty));
    for (text, index) in [
        ("Event", 0),
        ("event.root", 5),
        ("a/b", 1),
        ("-leading", 0),
        ("_leading", 0),
        ("sp ace", 2),
    ] {
        assert_eq!(
            SlotName::parse(text),
            Err(SlotViolation::InvalidByte { index }),
            "{text}"
        );
    }
    let error = LocalPublicationError::from(SlotViolation::Empty);
    assert_eq!(error.code(), "ERR-PUBLICATION-LOCAL-SLOT-INVALID-001");

    let root = fresh_root("slot_name_bound_and_grammar")?;
    let Fixture {
        mut publisher,
        manifest,
        ..
    } = fixture(&root, roomy())?;
    let longest = SlotName::parse(&at_bound)?;
    publisher.publish(&longest, &manifest)?;
    drop(publisher);
    let reopened = LocalRootPublisher::open(&root, roomy())?;
    assert!(reopened.root(&longest).is_some());
    Ok(())
}

#[test]
fn root_capacity_at_bound_and_bound_plus_one() -> TestResult {
    let root = fresh_root("root_capacity_at_bound_and_bound_plus_one")?;
    let Fixture {
        mut publisher,
        first,
        second,
        metadata,
        ..
    } = fixture(&root, limits(2, 16, 8))?;
    let one = ObjectManifest::new("event_archive", [first], None)?;
    let two = ObjectManifest::new("event_archive", [second], None)?;
    let three = ObjectManifest::new("event_archive", [metadata], None)?;
    publisher.publish(&slot("slot-1")?, &one)?;
    publisher.publish(&slot("slot-2")?, &two)?;
    let error = expect_err(publisher.publish(&slot("slot-3")?, &three))?;
    assert_eq!(
        error,
        LocalPublicationError::Capacity {
            resource: CapacityResource::Roots,
            current: 2,
            maximum: 2,
        }
    );
    assert_eq!(error.code(), "ERR-PUBLICATION-LOCAL-CAPACITY-001");
    assert_eq!(publisher.spool().state(three.root()), None);
    // Idempotent republish at capacity still succeeds: it adds no root.
    assert_eq!(
        publisher.publish(&slot("slot-2")?, &two)?.outcome,
        PublishOutcome::AlreadyPublished
    );
    drop(publisher);

    // A spool already holding more roots than the configured bound refuses to open.
    assert_eq!(
        expect_err(LocalRootPublisher::open(&root, limits(1, 16, 8)))?,
        LocalPublicationError::Capacity {
            resource: CapacityResource::Roots,
            current: 2,
            maximum: 1,
        }
    );
    let reopened = LocalRootPublisher::open(&root, limits(2, 16, 8))?;
    assert_eq!(reopened.visible_roots().count(), 2);
    Ok(())
}

#[test]
fn manifest_child_bound_at_bound_and_bound_plus_one() -> TestResult {
    let root = fresh_root("manifest_child_bound_at_bound_and_bound_plus_one")?;
    let mut publisher = LocalRootPublisher::open(&root, limits(8, 4, 8))?;
    let mut children = Vec::new();
    for index in 0..5_u8 {
        children.push(publisher.stage_object(&[b'c', index])?);
    }
    let at_bound = ObjectManifest::new("event_archive", children[..4].iter().copied(), None)?;
    assert_eq!(
        publisher
            .publish(&slot("at-bound")?, &at_bound)?
            .child_count,
        4
    );
    let over = ObjectManifest::new("event_archive", children.iter().copied(), None)?;
    let error = expect_err(publisher.publish(&slot("over-bound")?, &over))?;
    assert_eq!(
        error,
        LocalPublicationError::ManifestChildBound {
            count: 5,
            maximum: 4,
        }
    );
    assert_eq!(error.code(), "ERR-PUBLICATION-LOCAL-BOUND-001");
    assert_eq!(publisher.spool().state(over.root()), None);

    let spool = SpoolLimits::new(64, 1 << 20, 4096, 64);
    LocalPublicationLimits::new(8, MAX_MANIFEST_CHILDREN, 8, 64, spool).validate()?;
    assert_eq!(
        LocalPublicationLimits::new(8, MAX_MANIFEST_CHILDREN + 1, 8, 64, spool).validate(),
        Err(LocalPublicationError::InvalidLimits(
            LocalLimitViolation::ChildBoundAboveFormatMaximum {
                requested: MAX_MANIFEST_CHILDREN + 1,
                maximum: MAX_MANIFEST_CHILDREN,
            }
        ))
    );
    LocalPublicationLimits::new(MAX_LOCAL_ROOTS, 4, 8, MAX_LOCAL_ROOTS, spool).validate()?;
    assert_eq!(
        LocalPublicationLimits::new(MAX_LOCAL_ROOTS + 1, 4, 8, MAX_LOCAL_ROOTS + 1, spool)
            .validate(),
        Err(LocalPublicationError::InvalidLimits(
            LocalLimitViolation::RootBoundAboveMaximum {
                requested: MAX_LOCAL_ROOTS + 1,
                maximum: MAX_LOCAL_ROOTS,
            }
        ))
    );
    assert_eq!(
        LocalPublicationLimits::new(8, 0, 8, 64, spool).validate(),
        Err(LocalPublicationError::InvalidLimits(
            LocalLimitViolation::ZeroBound
        ))
    );
    assert_eq!(
        LocalPublicationLimits::new(8, 4, 8, 7, spool).validate(),
        Err(LocalPublicationError::InvalidLimits(
            LocalLimitViolation::ScanBoundBelowEntryBound {
                max_scan_entries: 7,
                required: 8,
            }
        ))
    );
    Ok(())
}

#[test]
fn tombstone_capacity_at_bound_and_bound_plus_one() -> TestResult {
    let root = fresh_root("tombstone_capacity_at_bound_and_bound_plus_one")?;
    let Fixture {
        mut publisher,
        first,
        second,
        ..
    } = fixture(&root, limits(8, 16, 1))?;
    let witness = publisher.stage_object(b"owner-deletion-authorization")?;
    publisher.record_tombstone(tombstone_for(
        first,
        Some(witness),
        TombstoneReason::Deleted,
    )?)?;
    assert_eq!(
        expect_err(publisher.record_tombstone(tombstone_for(
            second,
            Some(witness),
            TombstoneReason::Deleted
        )?))?,
        LocalPublicationError::Capacity {
            resource: CapacityResource::Tombstones,
            current: 1,
            maximum: 1,
        }
    );
    assert_eq!(dir_names(&root.join(LOCAL_TOMBSTONES_DIR))?.len(), 1);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Reopen classification, locking, determinism, and registry agreement
// ---------------------------------------------------------------------------------------------

#[test]
fn broken_root_records_are_reported_and_never_admitted() -> TestResult {
    let root = fresh_root("broken_root_records_are_reported_and_never_admitted")?;
    let Fixture {
        mut publisher,
        first,
        second,
        manifest,
        ..
    } = fixture(&root, roomy())?;
    let other = ObjectManifest::new("event_archive", [second], None)?;
    publisher.publish(&slot("checksum")?, &manifest)?;
    publisher.publish(&slot("child")?, &other)?;
    let renamed_manifest = ObjectManifest::new("event_archive", [first], None)?;
    publisher.publish(&slot("renamed")?, &renamed_manifest)?;
    drop(publisher);

    flip_last_byte(&root_file(&root, "checksum"))?;
    flip_last_byte(&object_file(&root, second))?;
    fs::rename(root_file(&root, "renamed"), root_file(&root, "moved"))?;
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(root.join(LOCAL_ROOTS_DIR).join("notes.txt"))?
        .write_all(b"foreign")?;

    let mut reopened = LocalRootPublisher::open(&root, roomy())?;
    let report = reopened.recovery_report().clone();
    assert!(report.roots.is_empty(), "no broken root may be admitted");
    let reasons: Vec<_> = report
        .broken_roots
        .iter()
        .map(|broken| (broken.path.clone(), broken.reason.clone()))
        .collect();
    assert_eq!(
        reasons,
        vec![
            (
                PathBuf::from(LOCAL_ROOTS_DIR).join("checksum.root"),
                BrokenRootReason::ChecksumMismatch
            ),
            (
                PathBuf::from(LOCAL_ROOTS_DIR).join("child.root"),
                BrokenRootReason::ReferenceBlocked {
                    object: second,
                    role: ReferenceRole::Child,
                    reason: BlockReason::Corrupt,
                }
            ),
            (
                PathBuf::from(LOCAL_ROOTS_DIR).join("moved.root"),
                BrokenRootReason::SlotMismatch
            ),
        ]
    );
    assert_eq!(
        report.foreign,
        vec![PathBuf::from(LOCAL_ROOTS_DIR).join("notes.txt")]
    );
    let error = expect_err(reopened.publish(&slot("checksum")?, &manifest))?;
    assert_eq!(
        error,
        LocalPublicationError::BrokenSlot {
            slot: slot("checksum")?
        }
    );
    assert_eq!(error.code(), "ERR-PUBLICATION-LOCAL-BROKEN-ROOT-001");
    Ok(())
}

#[test]
fn unsupported_record_version_is_broken_not_admitted() -> TestResult {
    let root = fresh_root("unsupported_record_version_is_broken_not_admitted")?;
    let Fixture {
        mut publisher,
        manifest,
        ..
    } = fixture(&root, roomy())?;
    publisher.publish(&slot("event-0001")?, &manifest)?;
    drop(publisher);

    let path = root_file(&root, "event-0001");
    let bytes = fs::read(&path)?;
    let version_at = 8 + LOCAL_ROOT_RECORD_DOMAIN.len();
    let mut body = bytes[..bytes.len() - 33].to_vec();
    body[version_at..version_at + 8].copy_from_slice(&2_u64.to_be_bytes());
    let checksum = ContentDigest::sha256(&body);
    body.push(1);
    body.extend_from_slice(&checksum.bytes());
    fs::write(&path, body)?;

    let reopened = LocalRootPublisher::open(&root, roomy())?;
    let report = reopened.recovery_report();
    assert!(report.roots.is_empty());
    assert_eq!(
        report.broken_roots[0].reason,
        BrokenRootReason::UnsupportedVersion { version: 2 }
    );
    Ok(())
}

#[test]
fn second_owner_is_refused_while_the_lock_is_held() -> TestResult {
    let root = fresh_root("second_owner_is_refused_while_the_lock_is_held")?;
    let publisher = LocalRootPublisher::open(&root, roomy())?;
    let error = expect_err(LocalRootPublisher::open(&root, roomy()))?;
    assert_eq!(
        error,
        LocalPublicationError::Locked {
            path: root.join(LOCAL_LOCK_FILE)
        }
    );
    drop(publisher);
    LocalRootPublisher::open(&root, roomy())?;
    Ok(())
}

fn deterministic_run(root: &Path) -> Result<(String, Vec<u8>, String), Box<dyn Error>> {
    let Fixture {
        mut publisher,
        first,
        second,
        metadata,
        manifest,
    } = fixture(root, roomy())?;
    let witness = publisher.stage_object(b"owner-deletion-authorization")?;
    let spare = publisher.stage_object(b"spare-object")?;
    let child_manifest = ObjectManifest::new("event_clip", [first, second], None)?;
    let receipts = vec![
        publisher.publish(&slot("event-b")?, &manifest)?,
        publisher.publish(&slot("event-a")?, &child_manifest)?,
        publisher.publish(&slot("event-b")?, &manifest)?,
    ];
    publisher.record_tombstone(tombstone_for(
        spare,
        Some(witness),
        TombstoneReason::Expired,
    )?)?;
    let _ = metadata;
    drop(publisher);
    let record = fs::read(root_file(root, "event-b"))?;
    let reopened = LocalRootPublisher::open(root, roomy())?;
    Ok((
        format!("{receipts:?}"),
        record,
        format!("{:?}", reopened.recovery_report()),
    ))
}

#[test]
fn output_is_deterministic_across_runs() -> TestResult {
    let left = deterministic_run(&fresh_root("output_is_deterministic_across_runs_left")?)?;
    let right = deterministic_run(&fresh_root("output_is_deterministic_across_runs_right")?)?;
    assert_eq!(left, right);
    let fingerprint = ContentDigest::sha256(format!("{}|{}", left.0, left.2).as_bytes());
    log_scenario(
        "output_is_deterministic_across_runs",
        &format!("fingerprint={fingerprint}"),
    );
    Ok(())
}

#[test]
fn every_error_code_is_registered() -> TestResult {
    let registry = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../registries/ERRORS.md"),
    )?;
    for code in LOCAL_PUBLICATION_ERROR_CODES {
        assert!(
            registry.contains(&format!("| `{code}` |")),
            "{code} is not registered in registries/ERRORS.md"
        );
    }
    let domains = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../registries/DIGEST_DOMAINS.md"),
    )?;
    assert!(domains.contains(&format!("| `{LOCAL_ROOT_RECORD_DOMAIN}` |")));
    assert!(domains.contains("| `fss.local_tombstone_record.v1` |"));
    Ok(())
}

#[test]
fn object_crate_tombstone_type_is_the_core_record() -> TestResult {
    // The publication tombstone gate consumes the same record type the object store retains.
    let witness = ContentDigest::sha256(b"w");
    let record: ObjectTombstoneRecord = tombstone_for(
        ContentDigest::sha256(b"x"),
        Some(witness),
        TombstoneReason::Deleted,
    )?;
    assert_eq!(record.witness_digest, Some(witness));
    let error = ObjectError::Tombstoned(record.payload_digest);
    assert_eq!(BlockReason::from(error), BlockReason::Tombstoned);
    Ok(())
}
