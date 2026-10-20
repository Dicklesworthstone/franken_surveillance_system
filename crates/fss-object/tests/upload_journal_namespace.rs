#![forbid(unsafe_code)]
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
//! Actual disk custody, explicit legacy migration and read-only operator authority.

mod multipart_support;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, OperationId, RegionId, RegionKind, RegionTree,
    RuntimeGrant, TimestampNs,
};
use fss_object::multipart::{
    MultipartError, MultipartPhase, MultipartRecovery, UploadJournal, UploadJournalPin,
};
use fss_object::planner::{ChunkPolicy, MIN_PART_SIZE};
use fss_object::upload_journal::{
    FileUploadJournal, LegacyJournalAdoption, UPLOAD_JOURNAL_RECORD_DOMAIN, UploadJournalLimits,
    inspect_upload_journal,
};
use fss_object::uploader::StagedUpload;
use fss_object::{
    FaultInjectingSpoolIo, HostSpoolIo, SPOOL_LOCK_FILE, SPOOL_STAGING_DIR, SpoolFaultPlan,
    SpoolIoCall, SpoolLimits, StagingSpool,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::grant::GrantSet;

use multipart_support::{MemoryTransport, RESOURCE, Test, property, spec};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        for _ in 0..16 {
            let path = std::env::temp_dir().join(format!(
                "fss-upload-namespace-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
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
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn limits() -> UploadJournalLimits {
    UploadJournalLimits {
        max_records: 64,
        max_checkpoint_bytes: 16 * 1024,
        max_total_bytes: 512 * 1024,
        max_read_bytes: 2 * 1024 * 1024,
    }
}
fn local_budget() -> BudgetVector {
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 8 * 1024 * 1024;
    budget.storage_operations = 100_000;
    budget
}
fn local_authority(
    grant: RuntimeGrant,
    resource: &str,
    original_owner: bool,
) -> Result<(AuthorityCx, RegionTree), Box<dyn std::error::Error>> {
    let budget = local_budget();
    let mut request = spec("operation:namespace-upload", budget)?;
    request.capabilities = vec![grant.as_str().to_owned()];
    if !original_owner {
        request.principal = "principal:independent-inspector".into();
    }
    let (mut authority, tree) = AuthorityCx::root(
        request,
        RegionId::new("region:inspection")?,
        RegionKind::Process,
        budget,
        TimestampNs(0),
    )?;
    authority.narrow_grants(
        GrantSet::empty().with_scope(grant, BTreeSet::from([resource.to_owned()])),
    )?;
    Ok((authority, tree))
}
fn seed(
    root: &Path,
    active: bool,
) -> Result<(FileUploadJournal, UploadJournalPin), Box<dyn std::error::Error>> {
    let mut journal = FileUploadJournal::create(root, limits(), Arc::new(HostSpoolIo))?;
    let (_root, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport::default();
    let mut allowance = BudgetVector::ZERO;
    allowance.bytes = 32;
    allowance.network_bytes = 32;
    allowance.storage_operations = 12;
    let mut owner = StagedUpload::stage(
        &mut parent,
        &mut tree,
        &mut transport,
        OperationId::parse("operation:namespace-upload")?,
        3,
        ChunkPolicy {
            part_size: MIN_PART_SIZE,
        },
        ContentDigest::sha256(b"namespace-manifest"),
        spec("operation:namespace-upload", allowance)?,
        RESOURCE,
        TimestampNs(1),
    )?;
    let minimum = owner.attach_journal(&tree, TimestampNs(1), &mut journal)?;
    if active {
        owner.start(&tree, TimestampNs(2))?;
        owner.upload_part(&tree, TimestampNs(3), 0, b"abc")?;
    }
    drop(owner);
    Ok((journal, minimum))
}
fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}
fn snapshot(root: &Path) -> io::Result<BTreeMap<PathBuf, Vec<u8>>> {
    let mut entries = BTreeMap::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            for (path, bytes) in snapshot(&entry.path())? {
                entries.insert(PathBuf::from(entry.file_name()).join(path), bytes);
            }
        } else {
            entries.insert(PathBuf::from(entry.file_name()), fs::read(entry.path())?);
        }
    }
    Ok(entries)
}
fn legacy(root: &Path, checkpoint: &[u8]) -> Result<UploadJournalPin, Box<dyn std::error::Error>> {
    let mut spool = StagingSpool::open(root, SpoolLimits::new(64, 512 * 1024, 32 * 1024, 144))?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text(UPLOAD_JOURNAL_RECORD_DOMAIN);
    encoder.u64(1);
    encoder.bool(false);
    encoder.bytes(checkpoint);
    let record = encoder.finish_checked()?;
    let digest = ContentDigest::sha256(&record);
    spool.stage_bytes(&record)?;
    spool.verify(digest)?;
    Ok(UploadJournalPin {
        sequence: 1,
        root: digest,
    })
}

#[test]
fn copied_directory_cannot_create_an_independent_writer_for_the_same_intent() -> Test {
    let directory = Directory::new()?;
    let original = directory.0.join("original");
    let copied = directory.0.join("copied");
    let (journal, minimum) = seed(&original, false)?;
    copy_tree(&original, &copied)?;
    assert!(matches!(
        FileUploadJournal::open(&copied, limits(), Arc::new(HostSpoolIo), minimum),
        Err(MultipartError::JournalNamespaceMismatch)
    ));
    let (mut reader, tree) = local_authority(RuntimeGrant::ObserveStatus, RESOURCE, false)?;
    assert!(matches!(
        inspect_upload_journal(
            &copied,
            limits(),
            minimum,
            RESOURCE,
            &mut reader,
            &tree,
            TimestampNs(4)
        ),
        Err(MultipartError::JournalNamespaceMismatch)
    ));
    assert_eq!(journal.head(), Some(minimum));
    drop(journal);
    let reopened = FileUploadJournal::open(&original, limits(), Arc::new(HostSpoolIo), minimum)?;
    assert_eq!(reopened.head(), Some(minimum));
    Ok(())
}

#[test]
fn cold_reopen_rejects_replaced_lock_and_renamed_root() -> Test {
    for replace_lock in [false, true] {
        let directory = Directory::new()?;
        let root = directory.0.join("original");
        let (journal, minimum) = seed(&root, false)?;
        drop(journal);
        let reopen_path = if replace_lock {
            fs::rename(root.join(SPOOL_LOCK_FILE), directory.0.join("old-lock"))?;
            fs::write(root.join(SPOOL_LOCK_FILE), [])?;
            root
        } else {
            let moved = directory.0.join("moved");
            fs::rename(root, &moved)?;
            moved
        };
        assert!(matches!(
            FileUploadJournal::open(reopen_path, limits(), Arc::new(HostSpoolIo), minimum),
            Err(MultipartError::JournalNamespaceMismatch)
        ));
    }
    Ok(())
}

#[test]
fn inspection_reads_a_live_writer_without_mutation_or_provider_tokens_and_meters_work() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("journal");
    let (journal, minimum) = seed(&root, true)?;
    let before = snapshot(&root)?;
    let historical = MultipartRecovery::read(&journal, minimum)?.consumed();
    let (mut reader, tree) = local_authority(RuntimeGrant::ObserveStatus, RESOURCE, false)?;
    let report = inspect_upload_journal(
        &root,
        limits(),
        minimum,
        RESOURCE,
        &mut reader,
        &tree,
        TimestampNs(4),
    )?;
    assert_eq!(report.phase(), MultipartPhase::Uploading);
    assert_eq!(report.confirmed_parts(), 1);
    assert_eq!(report.total_parts(), 1);
    assert_eq!(report.consumed(), historical);
    assert_eq!(report.head(), journal.head().ok_or("head missing")?);
    assert!(report.namespace_binding_verified());
    assert!(!report.legacy_read_only());
    assert!(!report.locally_settled());
    assert!(reader.budget().consumed().bytes > 0);
    assert!(reader.budget().consumed().storage_operations > 0);
    assert_eq!(reader.budget().consumed().network_bytes, 0);
    let debug = format!("{report:?}");
    assert!(!debug.contains("provider-upload-0"));
    assert!(!debug.contains("opaque-provider-token"));
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn inspection_refuses_wrong_tree_scope_resource_expired_authority_and_regressed_time() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("journal");
    let (journal, minimum) = seed(&root, true)?;
    let (mut reader, tree) = local_authority(RuntimeGrant::ObserveStatus, RESOURCE, false)?;
    let (_other, unrelated) = local_authority(RuntimeGrant::ObserveStatus, RESOURCE, false)?;
    assert!(
        inspect_upload_journal(
            &root,
            limits(),
            minimum,
            RESOURCE,
            &mut reader,
            &unrelated,
            TimestampNs(4)
        )
        .is_err()
    );
    assert_eq!(*reader.budget().consumed(), BudgetVector::ZERO);
    assert!(
        inspect_upload_journal(
            &root,
            limits(),
            minimum,
            "archive:other",
            &mut reader,
            &tree,
            TimestampNs(4)
        )
        .is_err()
    );
    assert_eq!(*reader.budget().consumed(), BudgetVector::ZERO);
    let (mut wrong_target, wrong_tree) =
        local_authority(RuntimeGrant::ObserveStatus, "archive:other", false)?;
    assert!(matches!(
        inspect_upload_journal(
            &root,
            limits(),
            minimum,
            "archive:other",
            &mut wrong_target,
            &wrong_tree,
            TimestampNs(4)
        ),
        Err(MultipartError::OwnerMismatch)
    ));
    assert!(matches!(
        inspect_upload_journal(
            &root,
            limits(),
            minimum,
            RESOURCE,
            &mut reader,
            &tree,
            TimestampNs(2)
        ),
        Err(MultipartError::ClockRegression)
    ));
    let budget = local_budget();
    let mut request = spec("operation:expired-inspection", budget)?;
    request.capabilities = vec![RuntimeGrant::ObserveStatus.as_str().into()];
    request.deadline = Some(TimestampNs(4));
    let (mut expired, expired_tree) = AuthorityCx::root(
        request,
        RegionId::new("region:expired")?,
        RegionKind::Process,
        budget,
        TimestampNs(0),
    )?;
    assert!(
        inspect_upload_journal(
            &root,
            limits(),
            minimum,
            RESOURCE,
            &mut expired,
            &expired_tree,
            TimestampNs(4)
        )
        .is_err()
    );
    assert_eq!(*expired.budget().consumed(), BudgetVector::ZERO);
    drop(journal);
    Ok(())
}

#[test]
fn inspection_obeys_record_read_and_actual_authority_byte_caps() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("journal");
    let (_journal, minimum) = seed(&root, true)?;
    for choice in 0..3 {
        let (mut reader, tree) = local_authority(RuntimeGrant::ObserveStatus, RESOURCE, false)?;
        let mut bound = limits();
        if choice == 0 {
            bound.max_records = 1;
        }
        if choice == 1 {
            bound.max_read_bytes = 1;
        }
        if choice == 2 {
            let mut spend = BudgetVector::ZERO;
            spend.bytes = reader.budget().remaining().bytes;
            reader.budget_mut(&tree)?.spend_vector(&spend)?;
        }
        assert!(
            inspect_upload_journal(
                &root,
                bound,
                minimum,
                RESOURCE,
                &mut reader,
                &tree,
                TimestampNs(4)
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn v1_history_is_read_only_until_original_owner_explicitly_adopts_its_namespace() -> Test {
    let directory = Directory::new()?;
    let source = directory.0.join("source");
    let (seeded, _) = seed(&source, false)?;
    let checkpoint = seeded.latest().ok_or("checkpoint missing")?.to_vec();
    drop(seeded);
    let root = directory.0.join("legacy");
    let minimum = legacy(&root, &checkpoint)?;
    assert!(matches!(
        FileUploadJournal::open(&root, limits(), Arc::new(HostSpoolIo), minimum),
        Err(MultipartError::UnboundJournal)
    ));
    let (mut reader, tree) = local_authority(RuntimeGrant::ObserveStatus, RESOURCE, false)?;
    let report = inspect_upload_journal(
        &root,
        limits(),
        minimum,
        RESOURCE,
        &mut reader,
        &tree,
        TimestampNs(4),
    )?;
    assert!(report.legacy_read_only());
    assert!(!report.namespace_binding_verified());
    let request = LegacyJournalAdoption {
        minimum,
        namespace: report.namespace_binding(),
        resource: RESOURCE.into(),
    };
    let (mut wrong_owner, wrong_tree) =
        local_authority(RuntimeGrant::LedgerAppend, RESOURCE, false)?;
    assert!(matches!(
        FileUploadJournal::adopt_legacy(
            &root,
            limits(),
            Arc::new(HostSpoolIo),
            &request,
            &mut wrong_owner,
            &wrong_tree,
            TimestampNs(4)
        ),
        Err(MultipartError::OwnerMismatch)
    ));
    let (mut owner, owner_tree) = local_authority(RuntimeGrant::LedgerAppend, RESOURCE, true)?;
    let adopted = FileUploadJournal::adopt_legacy(
        &root,
        limits(),
        Arc::new(HostSpoolIo),
        &request,
        &mut owner,
        &owner_tree,
        TimestampNs(4),
    )?;
    let head = adopted.head().ok_or("adoption head missing")?;
    assert_eq!(head.sequence, 2);
    assert!(adopted.contains(minimum));
    assert_eq!(adopted.latest(), Some(checkpoint.as_slice()));
    drop(adopted);
    let reopened = FileUploadJournal::open(&root, limits(), Arc::new(HostSpoolIo), minimum)?;
    assert_eq!(reopened.head(), Some(head));
    drop(reopened);
    let report = inspect_upload_journal(
        &root,
        limits(),
        minimum,
        RESOURCE,
        &mut reader,
        &tree,
        TimestampNs(4),
    )?;
    assert!(report.namespace_binding_verified());
    assert!(!report.legacy_read_only());
    assert_eq!(report.observed_at(), TimestampNs(1));
    Ok(())
}

#[test]
fn legacy_adoption_requires_the_independent_pin_and_inspected_exact_namespace() -> Test {
    let directory = Directory::new()?;
    let (seeded, _) = seed(&directory.0.join("source"), false)?;
    let checkpoint = seeded.latest().ok_or("checkpoint missing")?.to_vec();
    drop(seeded);
    let original = directory.0.join("legacy");
    let copied = directory.0.join("copied");
    let minimum = legacy(&original, &checkpoint)?;
    let (mut reader, tree) = local_authority(RuntimeGrant::ObserveStatus, RESOURCE, false)?;
    let report = inspect_upload_journal(
        &original,
        limits(),
        minimum,
        RESOURCE,
        &mut reader,
        &tree,
        TimestampNs(4),
    )?;
    copy_tree(&original, &copied)?;
    let (mut owner, owner_tree) = local_authority(RuntimeGrant::LedgerAppend, RESOURCE, true)?;
    let request = LegacyJournalAdoption {
        minimum,
        namespace: report.namespace_binding(),
        resource: RESOURCE.into(),
    };
    assert!(matches!(
        FileUploadJournal::adopt_legacy(
            &copied,
            limits(),
            Arc::new(HostSpoolIo),
            &request,
            &mut owner,
            &owner_tree,
            TimestampNs(4)
        ),
        Err(MultipartError::JournalNamespaceMismatch)
    ));
    let wrong = LegacyJournalAdoption {
        minimum: UploadJournalPin {
            sequence: 1,
            root: ContentDigest::sha256(b"wrong independent pin"),
        },
        ..request
    };
    assert!(
        FileUploadJournal::adopt_legacy(
            &original,
            limits(),
            Arc::new(HostSpoolIo),
            &wrong,
            &mut owner,
            &owner_tree,
            TimestampNs(4)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn lost_adoption_ack_is_resolved_by_cold_reopen_without_erasing_the_legacy_prefix() -> Test {
    let directory = Directory::new()?;
    let (seeded, _) = seed(&directory.0.join("source"), false)?;
    let checkpoint = seeded.latest().ok_or("checkpoint missing")?.to_vec();
    drop(seeded);
    let root = directory.0.join("legacy");
    let minimum = legacy(&root, &checkpoint)?;
    let (mut reader, tree) = local_authority(RuntimeGrant::ObserveStatus, RESOURCE, false)?;
    let report = inspect_upload_journal(
        &root,
        limits(),
        minimum,
        RESOURCE,
        &mut reader,
        &tree,
        TimestampNs(4),
    )?;
    let request = LegacyJournalAdoption {
        minimum,
        namespace: report.namespace_binding(),
        resource: RESOURCE.into(),
    };
    let (mut owner, owner_tree) = local_authority(RuntimeGrant::LedgerAppend, RESOURCE, true)?;
    let failing = Arc::new(FaultInjectingSpoolIo::new(
        SpoolFaultPlan::new().fail_after_applying(SpoolIoCall::Rename, 1, io::ErrorKind::Other),
    ));
    assert!(
        FileUploadJournal::adopt_legacy(
            &root,
            limits(),
            failing.clone(),
            &request,
            &mut owner,
            &owner_tree,
            TimestampNs(4)
        )
        .is_err()
    );
    assert!(failing.all_fired());
    let recovered = FileUploadJournal::open(&root, limits(), Arc::new(HostSpoolIo), minimum)?;
    assert_eq!(
        recovered.head().ok_or("recovered head missing")?.sequence,
        2
    );
    assert!(recovered.contains(minimum));
    assert_eq!(recovered.latest(), Some(checkpoint.as_slice()));
    Ok(())
}

#[test]
fn torn_staging_is_retained_and_reported_without_becoming_a_checkpoint() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("journal");
    let (journal, minimum) = seed(&root, false)?;
    drop(journal);
    let digest = ContentDigest::sha256(b"uncommitted record").to_string();
    let name = format!(
        "{}.0.tmp",
        digest.strip_prefix("sha256:").ok_or("SHA prefix missing")?
    );
    let torn = root.join(SPOOL_STAGING_DIR).join(name);
    fs::write(&torn, b"torn checkpoint")?;
    let (mut reader, tree) = local_authority(RuntimeGrant::ObserveStatus, RESOURCE, false)?;
    let report = inspect_upload_journal(
        &root,
        limits(),
        minimum,
        RESOURCE,
        &mut reader,
        &tree,
        TimestampNs(4),
    )?;
    assert_eq!(report.orphaned_staging_count(), 1);
    assert_eq!(report.records(), 1);
    assert_eq!(report.head(), minimum);
    assert_eq!(fs::read(torn)?, b"torn checkpoint");
    Ok(())
}
