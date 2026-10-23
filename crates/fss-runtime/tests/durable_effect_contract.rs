#![forbid(unsafe_code)]
//! Crashes cannot turn a saved preparation or receipt into a second dispatch permit.

use std::error::Error;
use std::sync::{Arc, Mutex};

use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, EffectState, IdempotencyKey, ObligationState,
    OperationId, RegionId, RegionKind, RegionTree, RootAuthoritySpec, RuntimeGrant, TimestampNs,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::effect::{
    CommitApproval, EffectCoordError, EffectCoordinator, PrepareSpec, PreparedEffect,
    Reconciliation,
};
use fss_runtime::effect_journal::{EffectJournalPin, EffectJournalStore, EffectPersistenceError};
use fss_runtime::lease::LeaseRegistry;

type Test<T = ()> = Result<T, Box<dyn Error>>;
const RESOURCE: &str = "device:ptz:durable-fixture";

#[derive(Clone, Copy, Debug, Default)]
enum Fault {
    #[default]
    None,
    BeforeAppend,
    AfterAppend,
    WrongReceipt,
}

#[derive(Debug, Default)]
struct Disk {
    records: Vec<Vec<u8>>,
    pins: Vec<EffectJournalPin>,
    fault: Fault,
    limit: Option<usize>,
}

#[derive(Debug)]
struct MemoryStore {
    disk: Arc<Mutex<Disk>>,
    records: Vec<Vec<u8>>,
    pins: Vec<EffectJournalPin>,
}

impl MemoryStore {
    fn open(disk: &Arc<Mutex<Disk>>) -> Self {
        let saved = disk.lock().expect("test disk lock");
        Self {
            disk: disk.clone(),
            records: saved.records.clone(),
            pins: saved.pins.clone(),
        }
    }
}

impl EffectJournalStore for MemoryStore {
    fn head(&self) -> Option<EffectJournalPin> {
        self.pins.last().copied()
    }
    fn records(&self) -> &[Vec<u8>] {
        &self.records
    }
    fn contains(&self, pin: EffectJournalPin) -> bool {
        self.pins.contains(&pin)
    }

    fn reserve_capacity(
        &mut self,
        additional_records: usize,
        _: usize,
    ) -> Result<(), EffectPersistenceError> {
        let disk = self.disk.lock().expect("test disk lock");
        if disk
            .limit
            .is_some_and(|limit| self.records.len() + additional_records > limit)
        {
            return Err(EffectPersistenceError::Capacity);
        }
        Ok(())
    }

    fn append(
        &mut self,
        expected: Option<EffectJournalPin>,
        record: &[u8],
    ) -> Result<EffectJournalPin, EffectPersistenceError> {
        let mut disk = self.disk.lock().expect("test disk lock");
        if expected != disk.pins.last().copied() || expected != self.head() {
            return Err(EffectPersistenceError::PinMismatch);
        }
        let fault = std::mem::take(&mut disk.fault);
        if matches!(fault, Fault::BeforeAppend) {
            return Err(EffectPersistenceError::Storage(
                "injected before append".into(),
            ));
        }
        let sequence = disk.records.len() as u64 + 1;
        let mut encoder = CanonicalEncoder::new();
        encoder.u64(sequence);
        if let Some(previous) = expected {
            encoder.digest(previous.root);
        }
        encoder.bytes(record);
        let root = ContentDigest::sha256(&encoder.finish_checked().expect("test encoding"));
        let pin = EffectJournalPin { sequence, root };
        disk.records.push(record.to_vec());
        disk.pins.push(pin);
        self.records.push(record.to_vec());
        self.pins.push(pin);
        if matches!(fault, Fault::AfterAppend) {
            return Err(EffectPersistenceError::Storage(
                "injected after durable append".into(),
            ));
        }
        if matches!(fault, Fault::WrongReceipt) {
            return Ok(EffectJournalPin {
                sequence: sequence + 1,
                root,
            });
        }
        Ok(pin)
    }
}

fn digest(value: &[u8]) -> ContentDigest {
    ContentDigest::sha256(value)
}

fn scope(principal: &str, grants: &[RuntimeGrant]) -> Test<(AuthorityCx, RegionTree)> {
    let budgets = BudgetVector::builder()
        .tokens(128)
        .bytes(8192)
        .cpu_millis(1000)
        .build()?;
    Ok(AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:durable-effect".into(),
            operation_id: OperationId::parse("operation:durable-owner")?,
            principal: principal.into(),
            capabilities: grants
                .iter()
                .map(|grant| grant.as_str().to_owned())
                .collect(),
            deadline: None,
            priority: 10,
            budgets,
            privacy_scope: "privacy:local".into(),
            retention_scope: "retention:approved".into(),
            anchor_universe: digest(b"durable fixture anchor"),
            generation: 1,
        },
        RegionId::new("region:durable-owner")?,
        RegionKind::Process,
        budgets,
        TimestampNs(1),
    )?)
}

fn request(operation: &OperationId, fence: u64) -> Test<PrepareSpec<'_>> {
    Ok(PrepareSpec {
        operation,
        idempotency_key: IdempotencyKey::parse(operation.as_str())?,
        request_digest: digest(operation.as_str().as_bytes()),
        precondition_digest: digest(b"approved device generation"),
        resource: RESOURCE,
        fence,
        prepare_grant: RuntimeGrant::PtzPrepare,
        commit_grant: RuntimeGrant::PtzCommit,
        terminal_predicate: "camera reached approved pose",
    })
}

fn approval(prepared: &PreparedEffect) -> CommitApproval {
    CommitApproval {
        prepared_digest: prepared.digest(),
        current_precondition_digest: digest(b"approved device generation"),
    }
}

struct Fixture {
    disk: Arc<Mutex<Disk>>,
    owner: EffectCoordinator,
    authority: AuthorityCx,
    tree: RegionTree,
    leases: LeaseRegistry,
    fence: u64,
}

impl Fixture {
    fn new() -> Test<Self> {
        let disk = Arc::new(Mutex::new(Disk::default()));
        let (authority, tree) = scope(
            "principal:owner",
            &[RuntimeGrant::PtzPrepare, RuntimeGrant::PtzCommit],
        )?;
        let mut leases = LeaseRegistry::new();
        let fence = leases
            .acquire(RESOURCE, authority.region().as_str(), None, TimestampNs(2))?
            .fence;
        let owner = EffectCoordinator::with_journal(Box::new(MemoryStore::open(&disk)))?;
        Ok(Self {
            disk,
            owner,
            authority,
            tree,
            leases,
            fence,
        })
    }

    fn prepare(&mut self, name: &str) -> Test<PreparedEffect> {
        let operation = OperationId::parse(format!("operation:{name}"))?;
        Ok(self.owner.prepare(
            &self.authority,
            &mut self.tree,
            &mut self.leases,
            request(&operation, self.fence)?,
            TimestampNs(3),
        )?)
    }

    fn recover(
        &self,
        minimum: EffectJournalPin,
    ) -> Test<(EffectCoordinator, AuthorityCx, RegionTree)> {
        let owner = EffectCoordinator::recover(Box::new(MemoryStore::open(&self.disk)), minimum)?;
        let (authority, tree) = scope(
            "principal:owner",
            &[RuntimeGrant::PtzPrepare, RuntimeGrant::PtzCommit],
        )?;
        Ok((owner, authority, tree))
    }
}

#[test]
fn cold_recovery_reconciles_exact_outcome_without_reissuing_dispatch() -> Test {
    let mut f = Fixture::new()?;
    let prepared = f.prepare("restart")?;
    let minimum = f.owner.durable_pin().expect("prepared is durable");
    let original_digest = prepared.digest();
    let operation = prepared.operation().clone();
    let approved = approval(&prepared);
    let mut committed = f.owner.commit(
        &f.authority,
        &f.tree,
        &mut f.leases,
        prepared,
        TimestampNs(4),
        approved,
    )?;
    f.owner.adapter_accepted(
        &mut committed,
        Some(digest(b"adapter exchange")),
        TimestampNs(5),
    )?;
    let committed = f.owner.indeterminate(
        &mut f.tree,
        &f.authority,
        committed,
        Some("provider reply lost; query status"),
        TimestampNs(6),
    )?;
    let before = f.owner.journal().clone();
    drop(committed);
    let (mut recovered, authority, mut tree) = f.recover(minimum)?;
    assert_eq!(recovered.journal(), &before);
    assert!(recovered.is_reconciliation_only());
    assert!(recovered.prepared(&operation).is_none());
    assert_eq!(
        recovered.retained_preparation_digest(&operation),
        Some(original_digest)
    );
    let handle = recovered.adopt_recovered(
        &authority,
        &mut tree,
        &operation,
        original_digest,
        TimestampNs(7),
    )?;
    let node = tree.get(authority.region())?;
    assert_eq!(
        node.obligations[handle.obligation()].state,
        ObligationState::Indeterminate
    );
    assert_eq!(
        node.reconciliation_obligations[handle.obligation()],
        "provider reply lost; query status"
    );
    let refused = recovered
        .commit(
            &authority,
            &tree,
            &mut f.leases,
            handle.clone(),
            TimestampNs(8),
            approval(&handle),
        )
        .expect_err("no recovered handle grants dispatch");
    assert!(matches!(
        refused.error(),
        EffectCoordError::RecoveryOnly { .. }
    ));
    let another = OperationId::parse("operation:cannot-dispatch-new")?;
    assert!(matches!(
        recovered.prepare(
            &authority,
            &mut tree,
            &mut f.leases,
            request(&another, f.fence)?,
            TimestampNs(8)
        ),
        Err(EffectCoordError::RecoveryOnly { .. })
    ));
    let proof = digest(b"independently obtained provider outcome");
    recovered.reconcile(
        &mut tree,
        &authority,
        &handle,
        Reconciliation::Observed(proof),
        TimestampNs(8),
    )?;
    assert!(
        recovered
            .reconcile(
                &mut tree,
                &authority,
                &handle,
                Reconciliation::Verified(digest(b"wrong proof")),
                TimestampNs(9)
            )
            .is_err()
    );
    recovered.reconcile(
        &mut tree,
        &authority,
        &handle,
        Reconciliation::Verified(proof),
        TimestampNs(9),
    )?;
    let settled_pin = recovered.durable_pin();
    recovered.reconcile(
        &mut tree,
        &authority,
        &handle,
        Reconciliation::Verified(proof),
        TimestampNs(10),
    )?;
    assert_eq!(
        recovered.durable_pin(),
        settled_pin,
        "exact retry does not append"
    );
    assert_eq!(
        tree.get(authority.region())?.obligations[handle.obligation()].state,
        ObligationState::Verified
    );
    let again = EffectCoordinator::recover(Box::new(MemoryStore::open(&f.disk)), minimum)?;
    assert_eq!(
        again.journal(),
        recovered.journal(),
        "terminal receipt survives a second restart"
    );
    Ok(())
}

#[test]
fn every_ambiguous_commit_refuses_a_permit_and_freezes_the_live_owner() -> Test {
    for fault in [Fault::BeforeAppend, Fault::AfterAppend, Fault::WrongReceipt] {
        let mut f = Fixture::new()?;
        let prepared = f.prepare("ambiguous")?;
        let operation = prepared.operation().clone();
        let expected = prepared.digest();
        let minimum = f.owner.durable_pin().expect("preparation pin");
        let before = f.owner.journal().clone();
        f.disk.lock().expect("disk lock").fault = fault;
        let approved = approval(&prepared);
        let refused = f
            .owner
            .commit(
                &f.authority,
                &f.tree,
                &mut f.leases,
                prepared,
                TimestampNs(4),
                approved,
            )
            .expect_err("ambiguous append cannot return a dispatch permit");
        assert!(matches!(
            refused.error(),
            EffectCoordError::Persistence { .. }
        ));
        assert!(f.owner.persistence_needs_recovery());
        assert_eq!(f.owner.journal(), &before);
        assert_eq!(f.owner.durable_pin(), Some(minimum));
        let handle = refused.into_token();
        let refused = f
            .owner
            .commit(
                &f.authority,
                &f.tree,
                &mut f.leases,
                handle.clone(),
                TimestampNs(5),
                approval(&handle),
            )
            .expect_err("retry cannot dispatch under ambiguous storage");
        assert!(matches!(
            refused.error(),
            EffectCoordError::Persistence {
                error: EffectPersistenceError::Poisoned,
                ..
            }
        ));
        let (mut recovered, authority, mut tree) = f.recover(minimum)?;
        let handle = recovered.adopt_recovered(
            &authority,
            &mut tree,
            &operation,
            expected,
            TimestampNs(5),
        )?;
        if matches!(fault, Fault::BeforeAppend) {
            assert_eq!(recovered.state(&handle)?, EffectState::Prepared);
            recovered.cancel_prepared(
                &mut tree,
                &authority,
                handle,
                digest(b"cancel without dispatch"),
                TimestampNs(6),
            )?;
        } else {
            assert_eq!(recovered.state(&handle)?, EffectState::Committed);
            recovered.reconcile(
                &mut tree,
                &authority,
                &handle,
                Reconciliation::Failed {
                    proof: digest(b"provider independently confirms no execution"),
                    reason: "not dispatched",
                },
                TimestampNs(6),
            )?;
        }
    }
    Ok(())
}

#[test]
fn failed_terminal_append_preserves_obligation_until_cold_reconciliation() -> Test {
    let mut f = Fixture::new()?;
    let prepared = f.prepare("terminal-write")?;
    let operation = prepared.operation().clone();
    let expected = prepared.digest();
    let approved = approval(&prepared);
    let mut committed = f.owner.commit(
        &f.authority,
        &f.tree,
        &mut f.leases,
        prepared,
        TimestampNs(4),
        approved,
    )?;
    let proof = digest(b"observed pose");
    f.owner.observed(&mut committed, proof, TimestampNs(5))?;
    let minimum = f.owner.durable_pin().expect("observed pin");
    let before = f.owner.journal().clone();
    f.disk.lock().expect("disk lock").fault = Fault::AfterAppend;
    assert!(
        f.owner
            .verified(&mut f.tree, &f.authority, committed, proof, TimestampNs(6))
            .is_err()
    );
    assert_eq!(f.owner.journal(), &before);
    assert_eq!(
        f.tree
            .get(f.authority.region())?
            .obligations
            .values()
            .next()
            .expect("obligation")
            .state,
        ObligationState::Pending
    );
    let (mut recovered, authority, mut tree) = f.recover(minimum)?;
    let handle =
        recovered.adopt_recovered(&authority, &mut tree, &operation, expected, TimestampNs(7))?;
    assert_eq!(recovered.state(&handle)?, EffectState::Verified);
    assert_eq!(
        tree.get(authority.region())?.obligations[handle.obligation()].state,
        ObligationState::Verified
    );
    Ok(())
}

#[test]
fn new_work_cannot_spend_another_operations_terminal_capacity() -> Test {
    let mut f = Fixture::new()?;
    let prepared = f.prepare("reserved")?;
    f.disk.lock().expect("disk lock").limit = Some(3);
    let approved = approval(&prepared);
    let refusal = f
        .owner
        .commit(
            &f.authority,
            &f.tree,
            &mut f.leases,
            prepared,
            TimestampNs(4),
            approved,
        )
        .expect_err("commit needs retained observation and verification space");
    assert!(matches!(
        refusal.error(),
        EffectCoordError::Persistence {
            error: EffectPersistenceError::Capacity,
            ..
        }
    ));
    assert!(
        !f.owner.persistence_needs_recovery(),
        "preflight refusal wrote nothing"
    );
    let prepared = refusal.into_token();
    f.disk.lock().expect("disk lock").limit = Some(4);
    let approved = approval(&prepared);
    let mut committed = f.owner.commit(
        &f.authority,
        &f.tree,
        &mut f.leases,
        prepared,
        TimestampNs(4),
        approved,
    )?;
    assert!(f.prepare("capacity-thief").is_err());
    assert_eq!(f.owner.journal().operations().count(), 1);
    let proof = digest(b"provider outcome");
    f.owner.observed(&mut committed, proof, TimestampNs(5))?;
    f.owner
        .verified(&mut f.tree, &f.authority, committed, proof, TimestampNs(6))?;
    assert_eq!(f.owner.durable_pin().expect("terminal pin").sequence, 4);
    Ok(())
}

#[test]
fn recovery_requires_pinned_history_exact_digest_and_nonwidening_authority() -> Test {
    let mut f = Fixture::new()?;
    let prepared = f.prepare("authority")?;
    let operation = prepared.operation().clone();
    let minimum = f.owner.durable_pin().expect("preparation pin");
    assert!(EffectCoordinator::with_journal(Box::new(MemoryStore::open(&f.disk))).is_err());
    assert!(matches!(
        EffectCoordinator::recover(
            Box::new(MemoryStore::open(&f.disk)),
            EffectJournalPin {
                sequence: minimum.sequence,
                root: digest(b"foreign history")
            }
        ),
        Err(EffectPersistenceError::PinMismatch)
    ));
    let (mut recovered, authority, mut tree) = f.recover(minimum)?;
    assert!(
        recovered
            .adopt_recovered(
                &authority,
                &mut tree,
                &operation,
                digest(b"unrelated preparation"),
                TimestampNs(4)
            )
            .is_err()
    );
    assert!(tree.get(authority.region())?.obligations.is_empty());
    let (wrong, mut wrong_tree) = scope(
        "principal:other",
        &[RuntimeGrant::PtzPrepare, RuntimeGrant::PtzCommit],
    )?;
    assert!(matches!(
        recovered.adopt_recovered(
            &wrong,
            &mut wrong_tree,
            &operation,
            prepared.digest(),
            TimestampNs(4)
        ),
        Err(EffectCoordError::WrongAuthority { .. })
    ));
    let (wider, mut wider_tree) = scope(
        "principal:owner",
        &[
            RuntimeGrant::PtzPrepare,
            RuntimeGrant::PtzCommit,
            RuntimeGrant::AlertCommit,
        ],
    )?;
    assert!(matches!(
        recovered.adopt_recovered(
            &wider,
            &mut wider_tree,
            &operation,
            prepared.digest(),
            TimestampNs(4)
        ),
        Err(EffectCoordError::WrongAuthority { .. })
    ));
    let (narrower, mut narrower_tree) = scope("principal:owner", &[RuntimeGrant::PtzPrepare])?;
    let handle = recovered.adopt_recovered(
        &narrower,
        &mut narrower_tree,
        &operation,
        prepared.digest(),
        TimestampNs(4),
    )?;
    recovered.cancel_prepared(
        &mut narrower_tree,
        &narrower,
        handle,
        digest(b"cancel old preparation"),
        TimestampNs(5),
    )?;
    let again = EffectCoordinator::recover(Box::new(MemoryStore::open(&f.disk)), minimum)?;
    assert_eq!(
        again
            .journal()
            .operation(&operation)
            .expect("cancelled receipt")
            .state,
        EffectState::Cancelled
    );
    Ok(())
}

#[test]
fn canonical_replay_rejects_corruption_reordering_and_trailing_bytes() -> Test {
    let mut f = Fixture::new()?;
    let prepared = f.prepare("tamper")?;
    let approved = approval(&prepared);
    let _committed = f.owner.commit(
        &f.authority,
        &f.tree,
        &mut f.leases,
        prepared,
        TimestampNs(4),
        approved,
    )?;
    for attack in 0..3 {
        // Deliberately hostile store bypasses its storage checksum, exercising
        // independent runtime semantic validation rather than only envelope hashes.
        let mut store = MemoryStore::open(&f.disk);
        let pin = store.head().expect("commit pin");
        match attack {
            0 => store.records[0].push(0),
            1 => store.records.swap(0, 1),
            _ => store.records[1][0] ^= 0xff,
        }
        assert!(matches!(
            EffectCoordinator::recover(Box::new(store), pin),
            Err(EffectPersistenceError::InvalidHistory(_))
        ));
    }
    Ok(())
}

#[test]
fn tree_registration_refusal_precedes_any_durable_preparation() -> Test {
    let mut f = Fixture::new()?;
    let operation = OperationId::parse("operation:blocked")?;
    // A foreign obligation has taken the exact ID, without taking this operation.
    // Both registration paths must reject it before a durable prepare is published.
    let existing = fss_runtime::obligation::new_obligation(
        format!("obligation:{operation}:terminal"),
        OperationId::parse("operation:foreign")?,
        "another obligation",
    )?;
    f.authority.register_obligation(&mut f.tree, existing)?;
    assert!(
        f.owner
            .prepare(
                &f.authority,
                &mut f.tree,
                &mut f.leases,
                request(&operation, f.fence)?,
                TimestampNs(3)
            )
            .is_err()
    );
    assert_eq!(f.owner.durable_pin(), None);
    assert!(f.owner.journal().operation(&operation).is_none());
    assert!(f.disk.lock().expect("disk lock").records.is_empty());
    assert!(!f.owner.persistence_needs_recovery());
    Ok(())
}
