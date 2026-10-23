#![forbid(unsafe_code)]
#![cfg(unix)]
//! Actual disk restart, namespace, capacity, and ambiguous-write contracts.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, EffectState, IdempotencyKey, ObligationState,
    OperationId, RegionId, RegionKind, RegionTree, RootAuthoritySpec, RuntimeGrant, TimestampNs,
};
use fss_object::effect_journal::{
    EFFECT_JOURNAL_RECORD_DOMAIN, EffectJournalLimits, FileEffectJournal,
};
use fss_object::{
    FaultInjectingSpoolIo, HostSpoolIo, SPOOL_HOLDS_DIR, SPOOL_LOCK_FILE, SPOOL_OBJECTS_DIR,
    SPOOL_STAGING_DIR, SpoolFaultPlan, SpoolIoCall, SpoolLimits, StagingSpool,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::effect::{
    CommitApproval, EffectCoordError, EffectCoordinator, PrepareSpec, Reconciliation,
};
use fss_runtime::effect_journal::{EffectJournalPin, EffectJournalStore, EffectPersistenceError};
use fss_runtime::lease::LeaseRegistry;

type Test = Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let parent = fs::canonicalize(std::env::temp_dir())?;
        for _ in 0..16 {
            let path = parent.join(format!(
                "fss-effect-journal-{}-{}",
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
            "test directory exhausted",
        ))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn limits() -> EffectJournalLimits {
    EffectJournalLimits {
        max_records: 8,
        max_record_bytes: 1024,
        max_total_bytes: 64 * 1024,
        max_read_bytes: 1024 * 1024,
    }
}

fn seed(root: &Path) -> Result<(FileEffectJournal, EffectJournalPin), Box<dyn std::error::Error>> {
    let mut journal = FileEffectJournal::create(root, limits(), Arc::new(HostSpoolIo))?;
    let pin = journal.append(None, b"preparation")?;
    Ok((journal, pin))
}

fn object_path(root: &Path, digest: ContentDigest) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let text = digest.to_string();
    Ok(root
        .join(SPOOL_OBJECTS_DIR)
        .join(text.strip_prefix("sha256:").ok_or("SHA prefix missing")?))
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

#[test]
fn cold_open_preserves_every_record_and_accepts_a_minimum_prefix() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("history");
    let (mut journal, first) = seed(&root)?;
    let second = journal.append(Some(first), b"committed")?;
    let third = journal.append(Some(second), b"committed")?;
    assert_ne!(
        second.root, third.root,
        "equal payloads at different sequences retain distinct custody"
    );
    let original_namespace = journal.namespace_binding();
    drop(journal);
    let mut reopened = FileEffectJournal::open(&root, limits(), Arc::new(HostSpoolIo), first)?;
    assert_eq!(reopened.head(), Some(third));
    assert!(reopened.contains(first) && reopened.contains(second));
    assert_eq!(reopened.namespace_binding(), original_namespace);
    assert_eq!(
        reopened.records(),
        [
            b"preparation".to_vec(),
            b"committed".to_vec(),
            b"committed".to_vec()
        ]
    );
    let fourth = reopened.append(Some(third), b"observed")?;
    assert_eq!(fourth.sequence, 4);
    Ok(())
}

#[test]
fn stale_head_and_capacity_refusals_do_not_poison_or_write() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("history");
    let (mut journal, first) = seed(&root)?;
    assert!(matches!(
        journal.append(None, b"stale"),
        Err(EffectPersistenceError::PinMismatch)
    ));
    assert!(matches!(
        journal.reserve_capacity(usize::MAX, 1),
        Err(EffectPersistenceError::Capacity)
    ));
    assert!(matches!(
        journal.append(Some(first), &[0; 1025]),
        Err(EffectPersistenceError::Capacity)
    ));
    assert_eq!(journal.head(), Some(first));
    assert_eq!(journal.records().len(), 1);
    assert!(!journal.is_poisoned());
    assert_eq!(fs::read_dir(root.join(SPOOL_OBJECTS_DIR))?.count(), 1);
    journal.append(Some(first), b"next")?;
    Ok(())
}

#[test]
fn independent_pin_rejects_rollback_and_unknown_history() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("history");
    let (mut journal, first) = seed(&root)?;
    let second = journal.append(Some(first), b"committed")?;
    drop(journal);
    let second_path = object_path(&root, second.root)?;
    fs::remove_file(&second_path)?;
    // A coherent older snapshot loses both the new object and its verification hold.
    // Keeping the hold instead exercises vanished-object corruption before pin validation.
    fs::remove_file(
        root.join(SPOOL_HOLDS_DIR)
            .join(second_path.file_name().ok_or("object name missing")?),
    )?;
    assert!(matches!(
        FileEffectJournal::open(&root, limits(), Arc::new(HostSpoolIo), second),
        Err(EffectPersistenceError::PinMismatch)
    ));
    let unknown = EffectJournalPin {
        sequence: 1,
        root: ContentDigest::sha256(b"other history"),
    };
    assert!(matches!(
        FileEffectJournal::open(&root, limits(), Arc::new(HostSpoolIo), unknown),
        Err(EffectPersistenceError::PinMismatch)
    ));
    assert!(!directory.0.join("missing").exists());
    assert!(
        FileEffectJournal::open(
            directory.0.join("missing"),
            limits(),
            Arc::new(HostSpoolIo),
            first
        )
        .is_err()
    );
    assert!(!directory.0.join("missing").exists());
    Ok(())
}

#[test]
fn exclusive_writer_and_original_namespace_survive_cold_open() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("history");
    let (journal, first) = seed(&root)?;
    assert!(FileEffectJournal::open(&root, limits(), Arc::new(HostSpoolIo), first).is_err());
    assert!(FileEffectJournal::create(&root, limits(), Arc::new(HostSpoolIo)).is_err());
    let copied = directory.0.join("copied");
    copy_tree(&root, &copied)?;
    assert!(matches!(
        FileEffectJournal::open(&copied, limits(), Arc::new(HostSpoolIo), first),
        Err(EffectPersistenceError::InvalidHistory(_))
    ));
    drop(journal);
    assert!(FileEffectJournal::create(&root, limits(), Arc::new(HostSpoolIo)).is_err());
    let renamed = directory.0.join("renamed");
    fs::rename(&root, &renamed)?;
    assert!(matches!(
        FileEffectJournal::open(&renamed, limits(), Arc::new(HostSpoolIo), first),
        Err(EffectPersistenceError::InvalidHistory(_))
    ));
    Ok(())
}

#[test]
fn replaced_lock_and_mutated_head_poison_live_owners() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("lock-history");
    let (mut journal, first) = seed(&root)?;
    fs::rename(root.join(SPOOL_LOCK_FILE), directory.0.join("old-lock"))?;
    fs::write(root.join(SPOOL_LOCK_FILE), b"")?;
    assert!(journal.append(Some(first), b"never published").is_err());
    assert!(journal.is_poisoned());
    assert!(matches!(
        journal.append(Some(first), b"retry"),
        Err(EffectPersistenceError::Poisoned)
    ));

    let root = directory.0.join("corrupt-history");
    let (mut journal, first) = seed(&root)?;
    let path = object_path(&root, first.root)?;
    let mut bytes = fs::read(&path)?;
    let last = bytes.last_mut().ok_or("empty spool object")?;
    *last ^= 1;
    fs::write(&path, bytes)?;
    assert!(journal.append(Some(first), b"never published").is_err());
    assert!(journal.is_poisoned());
    assert_eq!(journal.records().len(), 1);
    drop(journal);
    assert!(FileEffectJournal::open(&root, limits(), Arc::new(HostSpoolIo), first).is_err());
    Ok(())
}

#[test]
fn missing_or_corrupt_non_tip_record_refuses_the_next_live_append() -> Test {
    let directory = Directory::new()?;
    for corrupt in [false, true] {
        let root = directory.0.join(if corrupt {
            "corrupt-prefix"
        } else {
            "missing-prefix"
        });
        let (mut journal, first) = seed(&root)?;
        let second = journal.append(Some(first), b"later acknowledged record")?;
        let path = object_path(&root, first.root)?;
        if corrupt {
            let mut bytes = fs::read(&path)?;
            *bytes.last_mut().ok_or("empty spool object")? ^= 1;
            fs::write(path, bytes)?;
        } else {
            fs::remove_file(path)?;
        }
        assert!(
            journal
                .append(Some(second), b"must not authorize dispatch")
                .is_err()
        );
        assert!(journal.is_poisoned());
        assert_eq!(journal.head(), Some(second));
        assert_eq!(journal.records().len(), 2);
        assert!(matches!(
            journal.append(Some(second), b"unsafe retry"),
            Err(EffectPersistenceError::Poisoned)
        ));
    }
    Ok(())
}

#[test]
fn extra_live_object_refuses_append_even_when_all_pinned_bytes_are_intact() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("history");
    let (mut journal, first) = seed(&root)?;
    fs::copy(
        object_path(&root, first.root)?,
        root.join(SPOOL_OBJECTS_DIR).join("unindexed-record"),
    )?;
    assert!(matches!(
        journal.append(Some(first), b"must not authorize dispatch"),
        Err(EffectPersistenceError::InvalidHistory(_))
    ));
    assert!(journal.is_poisoned());
    assert_eq!(journal.head(), Some(first));
    assert_eq!(journal.records().len(), 1);
    Ok(())
}

#[test]
fn ambiguous_rename_is_never_retried_and_cold_open_finds_committed_record() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("history");
    let (journal, first) = seed(&root)?;
    drop(journal);
    let failing = Arc::new(FaultInjectingSpoolIo::new(
        SpoolFaultPlan::new().fail_after_applying(SpoolIoCall::Rename, 1, io::ErrorKind::Other),
    ));
    let mut journal = FileEffectJournal::open(&root, limits(), failing.clone(), first)?;
    assert!(
        journal
            .append(Some(first), b"committed but acknowledgement lost")
            .is_err()
    );
    assert!(failing.all_fired());
    assert!(journal.is_poisoned());
    assert_eq!(journal.head(), Some(first));
    assert_eq!(journal.records().len(), 1);
    assert!(matches!(
        journal.append(Some(first), b"unsafe retry"),
        Err(EffectPersistenceError::Poisoned)
    ));
    drop(journal);
    let recovered = FileEffectJournal::open(&root, limits(), Arc::new(HostSpoolIo), first)?;
    assert_eq!(
        recovered.records(),
        [
            b"preparation".to_vec(),
            b"committed but acknowledgement lost".to_vec()
        ]
    );
    assert_eq!(recovered.head().ok_or("missing recovered tip")?.sequence, 2);
    Ok(())
}

#[test]
fn torn_staging_is_retained_but_never_replayed_as_a_record() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("history");
    let (journal, first) = seed(&root)?;
    drop(journal);
    let digest = ContentDigest::sha256(b"incomplete record").to_string();
    let name = format!(
        "{}.0.tmp",
        digest.strip_prefix("sha256:").ok_or("SHA prefix missing")?
    );
    let torn = root.join(SPOOL_STAGING_DIR).join(name);
    fs::write(&torn, b"incomplete effect record")?;
    let recovered = FileEffectJournal::open(&root, limits(), Arc::new(HostSpoolIo), first)?;
    assert_eq!(recovered.orphaned_staging_count(), 1);
    assert_eq!(recovered.records().len(), 1);
    assert_eq!(recovered.head(), Some(first));
    assert_eq!(fs::read(&torn)?, b"incomplete effect record");
    Ok(())
}

#[test]
fn recovery_refuses_forks_missing_predecessors_and_exhausted_read_budget() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("fork");
    let (journal, first) = seed(&root)?;
    let namespace = journal.namespace_binding();
    drop(journal);
    let mut encoder = CanonicalEncoder::new();
    encoder.text(EFFECT_JOURNAL_RECORD_DOMAIN);
    encoder.digest(namespace);
    encoder.u64(1);
    encoder.bool(false);
    encoder.bytes(b"competing preparation");
    let bytes = encoder.finish_checked()?;
    let mut spool = StagingSpool::open(&root, SpoolLimits::new(8, 64 * 1024, 2048, 64))?;
    spool.stage_bytes(&bytes)?;
    drop(spool);
    assert!(matches!(
        FileEffectJournal::open(&root, limits(), Arc::new(HostSpoolIo), first),
        Err(EffectPersistenceError::InvalidHistory(_))
    ));

    let root = directory.0.join("gap");
    let (mut journal, first) = seed(&root)?;
    let second = journal.append(Some(first), b"committed")?;
    drop(journal);
    let mut tiny = limits();
    tiny.max_read_bytes = 1;
    assert!(FileEffectJournal::open(&root, tiny, Arc::new(HostSpoolIo), first).is_err());
    fs::remove_file(object_path(&root, first.root)?)?;
    assert!(matches!(
        FileEffectJournal::open(&root, limits(), Arc::new(HostSpoolIo), second),
        Err(EffectPersistenceError::InvalidHistory(_))
    ));
    Ok(())
}

#[test]
fn symlinked_root_is_refused_before_initialization() -> Test {
    let directory = Directory::new()?;
    let actual = directory.0.join("actual");
    fs::create_dir(&actual)?;
    let alias = directory.0.join("alias");
    std::os::unix::fs::symlink(&actual, &alias)?;
    assert!(FileEffectJournal::create(&alias, limits(), Arc::new(HostSpoolIo)).is_err());
    assert_eq!(fs::read_dir(&actual)?.count(), 0);
    Ok(())
}

fn runtime_scope() -> Result<(AuthorityCx, RegionTree), Box<dyn std::error::Error>> {
    let budgets = BudgetVector::builder()
        .tokens(128)
        .bytes(8192)
        .cpu_millis(1000)
        .build()?;
    Ok(AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:file-effect-recovery".into(),
            operation_id: OperationId::parse("operation:file-effect-owner")?,
            principal: "principal:local-operator".into(),
            capabilities: [RuntimeGrant::PtzPrepare, RuntimeGrant::PtzCommit]
                .iter()
                .map(|grant| grant.as_str().to_owned())
                .collect(),
            deadline: None,
            priority: 10,
            budgets,
            privacy_scope: "privacy:local".into(),
            retention_scope: "retention:approved".into(),
            anchor_universe: ContentDigest::sha256(b"file-effect fixture anchor"),
            generation: 1,
        },
        RegionId::new("region:file-effect-owner")?,
        RegionKind::Process,
        budgets,
        TimestampNs(1),
    )?)
}

#[test]
fn real_file_commit_ack_loss_recovers_for_reconciliation_without_dispatch() -> Test {
    let directory = Directory::new()?;
    let root = directory.0.join("runtime-history");
    let limits = EffectJournalLimits {
        max_records: 5,
        max_record_bytes: 64 * 1024,
        max_total_bytes: 2 * 1024 * 1024,
        max_read_bytes: 8 * 1024 * 1024,
    };
    // The second rename is the commit record. Its durable name exists, but the caller receives
    // an error instead of acknowledgement, so no runtime dispatch token may escape.
    let failing = Arc::new(FaultInjectingSpoolIo::new(
        SpoolFaultPlan::new().fail_after_applying(SpoolIoCall::Rename, 2, io::ErrorKind::Other),
    ));
    let store = FileEffectJournal::create(&root, limits, failing.clone())?;
    let mut coordinator = EffectCoordinator::with_journal(Box::new(store))?;
    let (authority, mut tree) = runtime_scope()?;
    let mut leases = LeaseRegistry::new();
    let resource = "device:ptz:file-recovery-fixture";
    let fence = leases
        .acquire(resource, authority.region().as_str(), None, TimestampNs(2))?
        .fence;
    let operation = OperationId::parse("operation:file-recovery-effect")?;
    let precondition = ContentDigest::sha256(b"approved camera generation");
    let prepared = coordinator.prepare(
        &authority,
        &mut tree,
        &mut leases,
        PrepareSpec {
            operation: &operation,
            idempotency_key: IdempotencyKey::parse(operation.as_str())?,
            request_digest: ContentDigest::sha256(b"approved camera pose"),
            precondition_digest: precondition,
            resource,
            fence,
            prepare_grant: RuntimeGrant::PtzPrepare,
            commit_grant: RuntimeGrant::PtzCommit,
            terminal_predicate: "camera reached approved pose",
        },
        TimestampNs(3),
    )?;
    let prepared_digest = prepared.digest();
    let minimum = coordinator
        .durable_pin()
        .ok_or("preparation was not durable")?;
    let refusal = coordinator
        .commit(
            &authority,
            &tree,
            &mut leases,
            prepared,
            TimestampNs(4),
            CommitApproval {
                prepared_digest,
                current_precondition_digest: precondition,
            },
        )
        .expect_err("lost commit acknowledgement cannot return a dispatch token");
    assert!(matches!(
        refusal.error(),
        EffectCoordError::Persistence { .. }
    ));
    assert!(failing.all_fired());
    assert!(coordinator.persistence_needs_recovery());
    assert_eq!(coordinator.durable_pin(), Some(minimum));
    drop(refusal);
    drop(coordinator);
    drop(leases);
    drop(tree);
    drop(authority);

    let store = FileEffectJournal::open(&root, limits, Arc::new(HostSpoolIo), minimum)?;
    assert_eq!(store.head().ok_or("missing cold tip")?.sequence, 2);
    let mut recovered = EffectCoordinator::recover(Box::new(store), minimum)?;
    assert!(recovered.is_reconciliation_only());
    let (authority, mut tree) = runtime_scope()?;
    let handle = recovered.adopt_recovered(
        &authority,
        &mut tree,
        &operation,
        prepared_digest,
        TimestampNs(5),
    )?;
    assert_eq!(recovered.state(&handle)?, EffectState::Committed);
    let mut fresh_leases = LeaseRegistry::new();
    let refusal = recovered
        .commit(
            &authority,
            &tree,
            &mut fresh_leases,
            handle.clone(),
            TimestampNs(6),
            CommitApproval {
                prepared_digest,
                current_precondition_digest: precondition,
            },
        )
        .expect_err("cold history never recreates dispatch permission");
    assert!(matches!(
        refusal.error(),
        EffectCoordError::RecoveryOnly { .. }
    ));
    // Exactly five slots must preserve this legal cold-recovery path after the
    // unacknowledged commitment; saved history cannot recreate adapter acceptance.
    recovered.reconcile(
        &mut tree,
        &authority,
        &handle,
        Reconciliation::Indeterminate("commit acknowledgement lost; independently query provider"),
        TimestampNs(6),
    )?;
    let proof = ContentDigest::sha256(b"independently checked camera pose");
    recovered.reconcile(
        &mut tree,
        &authority,
        &handle,
        Reconciliation::Observed(proof),
        TimestampNs(7),
    )?;
    recovered.reconcile(
        &mut tree,
        &authority,
        &handle,
        Reconciliation::Verified(proof),
        TimestampNs(8),
    )?;
    assert_eq!(
        tree.get(authority.region())?.obligations[handle.obligation()].state,
        ObligationState::Verified
    );
    let terminal = recovered
        .durable_pin()
        .ok_or("terminal receipt was not durable")?;
    assert_eq!(
        terminal.sequence, 5,
        "the reserved settlement path fits exactly"
    );
    drop(recovered);

    let store = FileEffectJournal::open(&root, limits, Arc::new(HostSpoolIo), terminal)?;
    let recovered = EffectCoordinator::recover(Box::new(store), terminal)?;
    assert_eq!(
        recovered
            .journal()
            .operation(&operation)
            .ok_or("missing terminal operation")?
            .state,
        EffectState::Verified
    );
    assert_eq!(recovered.durable_pin(), Some(terminal));
    Ok(())
}
