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
use fss_runtime::effect_journal::{
    EffectJournalPin, EffectJournalStore, EffectPersistenceError, EffectPinRetainer,
    PinRetainedEffectJournal,
    keeper::{JournalPinRetainer, RootAnchoredJournalPinRetainer},
};
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

#[derive(Clone, Copy, Debug, Default)]
enum RetainFault {
    #[default]
    None,
    BeforeWrite,
    AfterWrite,
    OmitWrite,
}

#[derive(Debug, Default)]
struct RetainedPins {
    pin: Option<EffectJournalPin>,
    fault: RetainFault,
    full: bool,
}

#[derive(Debug)]
struct MemoryPinRetainer(Arc<Mutex<RetainedPins>>);

impl EffectPinRetainer for MemoryPinRetainer {
    fn retained_pin(&mut self) -> Result<Option<EffectJournalPin>, EffectPersistenceError> {
        Ok(self.0.lock().expect("retainer lock").pin)
    }

    fn reserve_capacity(&mut self, _: usize) -> Result<(), EffectPersistenceError> {
        if self.0.lock().expect("retainer lock").full {
            return Err(EffectPersistenceError::Capacity);
        }
        Ok(())
    }

    fn verify_effect_history(
        &mut self,
        journal: &dyn EffectJournalStore,
    ) -> Result<(), EffectPersistenceError> {
        if self
            .retained_pin()?
            .is_some_and(|pin| !journal.contains(pin))
        {
            return Err(EffectPersistenceError::PinMismatch);
        }
        Ok(())
    }

    fn retain(
        &mut self,
        expected: Option<EffectJournalPin>,
        next: EffectJournalPin,
    ) -> Result<(), EffectPersistenceError> {
        let mut pins = self.0.lock().expect("retainer lock");
        if pins.pin != expected {
            return Err(EffectPersistenceError::PinMismatch);
        }
        let fault = std::mem::take(&mut pins.fault);
        if matches!(fault, RetainFault::BeforeWrite) {
            return Err(EffectPersistenceError::Storage("before retention".into()));
        }
        if !matches!(fault, RetainFault::OmitWrite) {
            pins.pin = Some(next);
        }
        if matches!(fault, RetainFault::AfterWrite) {
            return Err(EffectPersistenceError::Storage("after retention".into()));
        }
        Ok(())
    }
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

fn retained_fixture() -> Test<(Fixture, Arc<Mutex<RetainedPins>>)> {
    let mut fixture = Fixture::new()?;
    let pins = Arc::new(Mutex::new(RetainedPins::default()));
    let journal = PinRetainedEffectJournal::new(
        Box::new(MemoryStore::open(&fixture.disk)),
        Box::new(MemoryPinRetainer(pins.clone())),
    )?;
    fixture.owner = EffectCoordinator::with_journal(Box::new(journal))?;
    Ok((fixture, pins))
}

fn root_anchored_fixture() -> Test<(
    Fixture,
    Arc<Mutex<Disk>>,
    Arc<Mutex<RetainedPins>>,
    EffectJournalPin,
)> {
    let mut fixture = Fixture::new()?;
    let keeper_disk = Arc::new(Mutex::new(Disk::default()));
    let root_pins = Arc::new(Mutex::new(RetainedPins::default()));
    let (keeper, bootstrap) = JournalPinRetainer::create(
        Box::new(MemoryStore::open(&keeper_disk)),
        digest(b"root anchored fixture"),
    )?;
    let mut root = MemoryPinRetainer(root_pins.clone());
    root.retain(None, bootstrap)?;
    let keeper = RootAnchoredJournalPinRetainer::new(keeper, Box::new(root))?;
    let journal = PinRetainedEffectJournal::new(
        Box::new(MemoryStore::open(&fixture.disk)),
        Box::new(keeper),
    )?;
    fixture.owner = EffectCoordinator::with_journal(Box::new(journal))?;
    Ok((fixture, keeper_disk, root_pins, bootstrap))
}

#[test]
fn root_anchored_keeper_requires_the_exact_bootstrap_and_advances_it() -> Test {
    let disk = Arc::new(Mutex::new(Disk::default()));
    let (keeper, _) = JournalPinRetainer::create(
        Box::new(MemoryStore::open(&disk)),
        digest(b"missing root fixture"),
    )?;
    let missing = Arc::new(Mutex::new(RetainedPins::default()));
    assert!(matches!(
        RootAnchoredJournalPinRetainer::new(keeper, Box::new(MemoryPinRetainer(missing))),
        Err(EffectPersistenceError::PinMismatch)
    ));

    let (mut fixture, keeper_disk, root, bootstrap) = root_anchored_fixture()?;
    let prepared = fixture.prepare("root-anchored-success")?;
    let prepared_anchor = root.lock().expect("root lock").pin.expect("root pin");
    assert_eq!(prepared_anchor.sequence, bootstrap.sequence + 1);
    assert_eq!(
        keeper_disk.lock().expect("keeper lock").pins.last(),
        Some(&prepared_anchor)
    );
    let approved = approval(&prepared);
    let _permit = fixture.owner.commit(
        &fixture.authority,
        &fixture.tree,
        &mut fixture.leases,
        prepared,
        TimestampNs(4),
        approved,
    )?;
    let committed_anchor = root.lock().expect("root lock").pin.expect("root pin");
    assert_eq!(committed_anchor.sequence, prepared_anchor.sequence + 1);
    assert_eq!(
        keeper_disk.lock().expect("keeper lock").pins.last(),
        Some(&committed_anchor)
    );
    Ok(())
}

#[test]
fn root_capacity_refusal_precedes_all_effect_and_keeper_writes() -> Test {
    let (mut fixture, keeper_disk, root, bootstrap) = root_anchored_fixture()?;
    root.lock().expect("root lock").full = true;
    assert!(fixture.prepare("root-capacity").is_err());
    assert!(fixture.disk.lock().expect("effect lock").records.is_empty());
    assert_eq!(keeper_disk.lock().expect("keeper lock").records.len(), 1);
    assert_eq!(root.lock().expect("root lock").pin, Some(bootstrap));
    assert!(!fixture.owner.persistence_needs_recovery());
    root.lock().expect("root lock").full = false;
    let _prepared = fixture.prepare("root-capacity")?;
    assert_eq!(
        root.lock()
            .expect("root lock")
            .pin
            .expect("root pin")
            .sequence,
        bootstrap.sequence + 1
    );
    Ok(())
}

#[test]
fn ambiguous_root_retention_never_grants_a_dispatch_permit() -> Test {
    for fault in [
        RetainFault::BeforeWrite,
        RetainFault::AfterWrite,
        RetainFault::OmitWrite,
    ] {
        let (mut fixture, keeper_disk, root, bootstrap) = root_anchored_fixture()?;
        let prepared = fixture.prepare("root-anchored-ambiguity")?;
        let minimum = fixture.owner.durable_pin().expect("prepared effect pin");
        root.lock().expect("root lock").fault = fault;
        let approved = approval(&prepared);
        let result = fixture.owner.commit(
            &fixture.authority,
            &fixture.tree,
            &mut fixture.leases,
            prepared,
            TimestampNs(4),
            approved,
        );
        assert!(matches!(
            result.expect_err("root failure cannot dispatch").error(),
            EffectCoordError::Persistence { .. }
        ));
        assert!(fixture.owner.persistence_needs_recovery());
        fixture.owner = EffectCoordinator::new();
        let keeper = JournalPinRetainer::reopen(
            Box::new(MemoryStore::open(&keeper_disk)),
            digest(b"root anchored fixture"),
            bootstrap,
        )?;
        let rebound =
            RootAnchoredJournalPinRetainer::new(keeper, Box::new(MemoryPinRetainer(root.clone())));
        if matches!(fault, RetainFault::AfterWrite) {
            let journal = PinRetainedEffectJournal::for_reconciliation(
                Box::new(MemoryStore::open(&fixture.disk)),
                Box::new(rebound?),
            )?;
            let recovered = EffectCoordinator::recover(Box::new(journal), minimum)?;
            assert!(recovered.is_reconciliation_only());
        } else {
            assert!(matches!(rebound, Err(EffectPersistenceError::PinMismatch)));
        }
    }
    Ok(())
}

#[test]
fn retained_store_direct_append_reserves_both_domains_before_writing() -> Test {
    let disk = Arc::new(Mutex::new(Disk::default()));
    let pins = Arc::new(Mutex::new(RetainedPins {
        full: true,
        ..RetainedPins::default()
    }));
    let mut journal = PinRetainedEffectJournal::new(
        Box::new(MemoryStore::open(&disk)),
        Box::new(MemoryPinRetainer(pins.clone())),
    )?;
    assert_eq!(
        journal.append(None, b"preparation"),
        Err(EffectPersistenceError::Capacity)
    );
    assert!(disk.lock().expect("disk lock").records.is_empty());
    pins.lock().expect("retainer lock").full = false;
    let pin = journal.append(None, b"preparation")?;
    assert_eq!(pins.lock().expect("retainer lock").pin, Some(pin));
    Ok(())
}

#[test]
fn matching_retained_history_reopens_only_for_reconciliation() -> Test {
    let (mut fixture, pins) = retained_fixture()?;
    let prepared = fixture.prepare("retained-recovery")?;
    let operation = prepared.operation().clone();
    let preparation = prepared.digest();
    let minimum = pins
        .lock()
        .expect("retainer lock")
        .pin
        .expect("prepared pin");
    fixture.owner = EffectCoordinator::new();
    let journal = PinRetainedEffectJournal::for_reconciliation(
        Box::new(MemoryStore::open(&fixture.disk)),
        Box::new(MemoryPinRetainer(pins.clone())),
    )?;
    let mut recovered = EffectCoordinator::recover(Box::new(journal), minimum)?;
    assert!(recovered.is_reconciliation_only());
    let (authority, mut tree) = scope(
        "principal:owner",
        &[RuntimeGrant::PtzPrepare, RuntimeGrant::PtzCommit],
    )?;
    let handle = recovered.adopt_recovered(
        &authority,
        &mut tree,
        &operation,
        preparation,
        TimestampNs(5),
    )?;
    let result = recovered.commit(
        &authority,
        &tree,
        &mut fixture.leases,
        handle.clone(),
        TimestampNs(6),
        approval(&handle),
    );
    assert!(matches!(
        result
            .expect_err("recovered history cannot dispatch")
            .error(),
        EffectCoordError::RecoveryOnly { .. }
    ));
    recovered.cancel_prepared(
        &mut tree,
        &authority,
        handle,
        digest(b"independent cancellation evidence"),
        TimestampNs(7),
    )?;
    assert_eq!(
        pins.lock().expect("retainer lock").pin,
        recovered.durable_pin()
    );
    assert_ne!(recovered.durable_pin(), Some(minimum));
    Ok(())
}

#[test]
fn retained_reconciliation_rejects_a_missing_checkpoint() -> Test {
    let (mut fixture, pins) = retained_fixture()?;
    let _prepared = fixture.prepare("retained-mismatch")?;
    fixture.owner = EffectCoordinator::new();
    pins.lock().expect("retainer lock").pin = None;
    let result = PinRetainedEffectJournal::for_reconciliation(
        Box::new(MemoryStore::open(&fixture.disk)),
        Box::new(MemoryPinRetainer(pins)),
    );
    assert!(matches!(result, Err(EffectPersistenceError::PinMismatch)));
    Ok(())
}

#[test]
fn retained_checkpoint_advances_before_each_effect_transition_is_acknowledged() -> Test {
    let (mut fixture, pins) = retained_fixture()?;
    let prepared = fixture.prepare("retained-success")?;
    let first = fixture.owner.durable_pin().expect("prepared pin");
    assert_eq!(pins.lock().expect("retainer lock").pin, Some(first));
    let approved = approval(&prepared);
    let _permit = fixture.owner.commit(
        &fixture.authority,
        &fixture.tree,
        &mut fixture.leases,
        prepared,
        TimestampNs(4),
        approved,
    )?;
    let second = fixture.owner.durable_pin().expect("committed pin");
    assert_eq!(second.sequence, first.sequence + 1);
    assert_eq!(pins.lock().expect("retainer lock").pin, Some(second));
    Ok(())
}

#[test]
fn retention_ambiguity_refuses_dispatch_and_recovery_cannot_issue_a_permit() -> Test {
    for fault in [
        RetainFault::BeforeWrite,
        RetainFault::AfterWrite,
        RetainFault::OmitWrite,
    ] {
        let (mut fixture, pins) = retained_fixture()?;
        let prepared = fixture.prepare("retention-ambiguity")?;
        let minimum = pins
            .lock()
            .expect("retainer lock")
            .pin
            .expect("prepared pin");
        let operation = prepared.operation().clone();
        let original_digest = prepared.digest();
        pins.lock().expect("retainer lock").fault = fault;
        let approved = approval(&prepared);
        let refused = fixture
            .owner
            .commit(
                &fixture.authority,
                &fixture.tree,
                &mut fixture.leases,
                prepared,
                TimestampNs(4),
                approved,
            )
            .expect_err("unconfirmed retention cannot grant a dispatch permit");
        assert!(matches!(
            refused.error(),
            EffectCoordError::Persistence { .. }
        ));
        assert!(fixture.owner.persistence_needs_recovery());
        let handle = refused.into_token();
        let retry = fixture.owner.commit(
            &fixture.authority,
            &fixture.tree,
            &mut fixture.leases,
            handle.clone(),
            TimestampNs(5),
            approval(&handle),
        );
        assert!(matches!(
            retry.expect_err("owner fenced").error(),
            EffectCoordError::Persistence {
                error: EffectPersistenceError::Poisoned,
                ..
            }
        ));
        let (mut recovered, authority, mut tree) = fixture.recover(minimum)?;
        assert!(recovered.is_reconciliation_only());
        let handle = recovered.adopt_recovered(
            &authority,
            &mut tree,
            &operation,
            original_digest,
            TimestampNs(6),
        )?;
        assert_eq!(recovered.state(&handle)?, EffectState::Committed);
        let result = recovered.commit(
            &authority,
            &tree,
            &mut fixture.leases,
            handle.clone(),
            TimestampNs(7),
            approval(&handle),
        );
        assert!(matches!(
            result.expect_err("recovery cannot dispatch").error(),
            EffectCoordError::RecoveryOnly { .. }
        ));
    }
    Ok(())
}

#[test]
fn stale_or_full_pin_custody_refuses_before_dispatch() -> Test {
    let (mut fixture, pins) = retained_fixture()?;
    pins.lock().expect("retainer lock").full = true;
    assert!(fixture.prepare("retainer-full").is_err());
    assert!(fixture.disk.lock().expect("disk lock").records.is_empty());
    assert!(!fixture.owner.persistence_needs_recovery());
    pins.lock().expect("retainer lock").full = false;
    let prepared = fixture.prepare("retainer-full")?;
    pins.lock().expect("retainer lock").pin = None;
    let approved = approval(&prepared);
    let result = fixture.owner.commit(
        &fixture.authority,
        &fixture.tree,
        &mut fixture.leases,
        prepared,
        TimestampNs(4),
        approved,
    );
    assert!(matches!(
        result.expect_err("changed pin is fenced").error(),
        EffectCoordError::Persistence { .. }
    ));
    assert_eq!(fixture.disk.lock().expect("disk lock").records.len(), 1);
    assert!(fixture.owner.persistence_needs_recovery());
    Ok(())
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
    f.owner
        .adapter_accepted(&mut committed, None, TimestampNs(5))?;
    let proof = digest(b"observed pose");
    f.owner.observed(&mut committed, proof, TimestampNs(6))?;
    let minimum = f.owner.durable_pin().expect("observed pin");
    let before = f.owner.journal().clone();
    f.disk.lock().expect("disk lock").fault = Fault::AfterAppend;
    assert!(
        f.owner
            .verified(&mut f.tree, &f.authority, committed, proof, TimestampNs(7))
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
        recovered.adopt_recovered(&authority, &mut tree, &operation, expected, TimestampNs(8))?;
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
    f.disk.lock().expect("disk lock").limit = Some(4);
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
        .expect_err("commit needs acceptance, observation and verification space");
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
    assert_eq!(f.owner.state(&prepared)?, EffectState::Prepared);
    assert_eq!(f.owner.durable_pin().expect("preparation pin").sequence, 1);
    assert_eq!(f.disk.lock().expect("disk lock").records.len(), 1);
    f.disk.lock().expect("disk lock").limit = Some(5);
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
    f.owner
        .adapter_accepted(&mut committed, None, TimestampNs(5))?;
    let proof = digest(b"provider outcome");
    f.owner.observed(&mut committed, proof, TimestampNs(6))?;
    f.owner
        .verified(&mut f.tree, &f.authority, committed, proof, TimestampNs(7))?;
    assert_eq!(f.owner.durable_pin().expect("terminal pin").sequence, 5);
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
