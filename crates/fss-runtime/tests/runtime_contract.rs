//! Contract tests for the FSS-021 slice-1 runtime core: cancellation
//! lifecycle (four-valued outcomes incl. Indeterminate on non-cooperative
//! work), budget ledgers, obligation leak oracle, and authority scoping
//! rules (kind legality + no silent budget widening).

use fss_runtime::budget::{Budget, BudgetExhausted, BudgetLedger};
use fss_runtime::cancellation::{CancelOutcome, CancellationLifecycle, DrainStep};

// ---------- cancellation ----------

#[test]
fn cooperative_drain_ends_cancelled() {
    let mut lc = CancellationLifecycle::new(["w2".to_string(), "w1".to_string()], 1_000);
    assert!(!lc.is_requested());
    lc.request(10);
    lc.begin_drain(20);
    assert!(lc.is_requested());
    // Deterministic sorted pending list.
    match lc.drive(30) {
        DrainStep::Pending(ids) => assert_eq!(ids, vec!["w1", "w2"]),
        other => panic!("expected pending, got {other:?}"),
    }
    lc.worker_done("w1").expect("w1 done");
    lc.worker_done("w2").expect("w2 done");
    assert_eq!(lc.outcome(), Some(&CancelOutcome::Cancelled));
    assert!(CancelOutcome::Cancelled.is_terminal_clean());
}

#[test]
fn non_cooperative_work_ends_indeterminate_with_stranded_names() {
    let mut lc = CancellationLifecycle::new(["stuck".to_string(), "also-stuck".to_string()], 500);
    lc.request(10);
    lc.begin_drain(100);
    let step = lc.drive(601);
    match step {
        DrainStep::Finalized(CancelOutcome::Indeterminate { reason }) => {
            assert!(reason.contains("stuck"), "{reason}");
            assert!(reason.contains("also-stuck"), "{reason}");
        }
        other => panic!("expected Indeterminate, got {other:?}"),
    }
    // Never silently cancelled, never faked complete.
    assert!(!lc.outcome().expect("final").is_terminal_clean());
}

#[test]
fn duplicate_or_unknown_worker_reports_are_typed_errors() {
    let mut lc = CancellationLifecycle::new(["w1".to_string()], 1_000);
    lc.request(1);
    lc.begin_drain(2);
    assert!(lc.worker_done("ghost").is_err(), "unknown id must refuse");
    lc.worker_done("w1").expect("w1 done");
    assert!(lc.worker_done("w1").is_err(), "duplicate report must refuse");
}

#[test]
fn natural_completion_and_failure_are_distinct_outcomes() {
    let mut a = CancellationLifecycle::new(["w".to_string()], 1_000);
    a.work_completed();
    assert_eq!(a.outcome(), Some(&CancelOutcome::Completed));
    let mut b = CancellationLifecycle::new(["w".to_string()], 1_000);
    b.request(1);
    b.begin_drain(2);
    b.work_failed("sensor fault");
    assert_eq!(
        b.outcome(),
        Some(&CancelOutcome::Failed {
            reason: "sensor fault".to_string()
        })
    );
}

#[test]
fn request_is_idempotent_and_never_rewinds() {
    let mut lc = CancellationLifecycle::new(["w".to_string()], 1_000);
    lc.request(10);
    lc.begin_drain(20);
    lc.request(30); // absorbed: the window must not rewind
    lc.worker_done("w").expect("done");
    assert_eq!(lc.outcome(), Some(&CancelOutcome::Cancelled));
}

// ---------- budget ----------

#[test]
fn budget_spends_and_refuses_typed_overdraft() {
    let mut ledger = BudgetLedger::new(Budget::new(10, 100, 1_000));
    ledger.spend_work(4).expect("spend work");
    ledger.spend_bytes(50).expect("spend bytes");
    ledger.spend_wall(500).expect("spend wall");
    assert_eq!(ledger.remaining(), Budget::new(6, 50, 500));
    assert!(matches!(
        ledger.spend_work(7),
        Err(BudgetExhausted::WorkUnits {
            remaining: 6,
            requested: 7
        })
    ));
    assert!(matches!(
        ledger.spend_bytes(51),
        Err(BudgetExhausted::Bytes { .. })
    ));
    assert!(matches!(
        ledger.spend_wall(501),
        Err(BudgetExhausted::WallNs { .. })
    ));
    // A refused spend never decrements.
    assert_eq!(ledger.remaining(), Budget::new(6, 50, 500));
}

#[test]
fn zero_budget_refuses_any_spend() {
    let mut ledger = BudgetLedger::new(Budget::zero());
    assert!(ledger.spend_work(1).is_err());
    assert!(ledger.remaining().is_exhausted());
}

// ---------- obligations (facade over fss-core's tree-owned machinery) ----------

#[test]
fn obligation_construction_and_terminal_mapping() {
    use fss_core::{ObligationId, OperationId};
    use fss_runtime::obligation::{new_obligation, ObligationState, ObligationTerminal, leaked_in};

    let op = OperationId::parse("op:test").expect("op id");
    let o1 = new_obligation("obl:one", op.clone(), "all staged bytes published").expect("build");
    let o2 = new_obligation("obl:two", op, "all child roots visible").expect("build");
    assert_eq!(o1.state, ObligationState::Pending);
    assert_eq!(o1.obligation_id, ObligationId::parse("obl:one").expect("id"));

    // The leak oracle reads pending state only.
    let leaks = leaked_in([o1.clone(), o2.clone()]);
    assert_eq!(leaks.len(), 2);
    assert_eq!(leaks[0].id, "obl:one");

    // Terminal mapping: the four-valued vocabulary maps onto the tree's
    // canonical states.
    assert_eq!(ObligationTerminal::Completed.to_state(), ObligationState::Verified);
    assert_eq!(ObligationTerminal::Drained.to_state(), ObligationState::Cancelled);
    assert_eq!(ObligationTerminal::Failed.to_state(), ObligationState::Failed);
    assert_eq!(ObligationTerminal::Indeterminate.to_state(), ObligationState::Indeterminate);

    // Terminated obligations drop out of the leak set.
    let mut done = o1.clone();
    done.state = ObligationState::Verified;
    let leaks = leaked_in([done, o2]);
    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].id, "obl:two");
}

// ---------- authority lifecycle (FSS-021 public surface) ----------

#[test]
fn authority_lifecycle_end_to_end() {
    use fss_core::{ContentDigest, ObligationId, OperationId, RegionId, RegionKind, RootAuthoritySpec, TimestampNs};
    use fss_runtime::authority::AuthorityCx;
    use fss_runtime::budget::Budget;
    use fss_runtime::obligation::{new_obligation, ObligationTerminal};

    let spec = RootAuthoritySpec {
        trace_id: "trace:test".to_string(),
        operation_id: OperationId::parse("op:test").expect("op"),
        principal: "principal:test".to_string(),
        capabilities: Vec::new(),
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::builder()
            .bytes(1024)
            .storage_operations(64)
            .build()
            .expect("budget vector"),
        privacy_scope: "privacy:test".to_string(),
        retention_scope: "retention:test".to_string(),
        anchor_universe: ContentDigest::sha256(b"test-universe"),
        generation: 1,
    };
    let (root, mut tree) = AuthorityCx::root(
        spec,
        RegionId::new("region:process").expect("region"),
        RegionKind::Process,
        Budget::new(100, 1_000, 10_000),
        TimestampNs(1_000),
    )
    .expect("root");

    // Scope down legally: child kind legal + budget within parent.
    let child = root.scope_down(
        &mut tree,
        RegionId::new("region:capture").expect("child region"),
        RegionKind::Property, // process → property is the legal narrowing
        Budget::new(50, 500, 5_000),
        RootAuthoritySpec {
            trace_id: "trace:test".to_string(), // narrowing: trace_id is inherited
            operation_id: OperationId::parse("op:child").expect("op"),
            principal: "principal:test".to_string(),
            capabilities: Vec::new(),
            deadline: None,
            priority: 10,
            budgets: fss_core::BudgetVector::builder()
                .bytes(512)
                .storage_operations(32)
                .build()
                .expect("budget vector"),
            privacy_scope: "privacy:test".to_string(),
            retention_scope: "retention:test".to_string(),
            anchor_universe: ContentDigest::sha256(b"test-universe"),
            generation: 1,
        },
        TimestampNs(2_000),
    );
    let mut child = child.expect("scope down");
    assert_eq!(child.region().as_str(), "region:capture");
    assert_eq!(child.budget().remaining(), Budget::new(50, 500, 5_000));

    // Obligation lifecycle through the tree: register → leak visible → resolve.
    let ob = new_obligation(
        "obl:capture-drain",
        OperationId::parse("op:child").expect("op"),
        "capture ring drained",
    ).expect("obligation");
    child.register_obligation(&mut tree, ob).expect("register");
    assert_eq!(child.leaked_obligations(&tree).len(), 1);
    child.resolve_obligation(
        &mut tree,
        &ObligationId::parse("obl:capture-drain").expect("id"),
        ObligationTerminal::Completed,
        Some(ContentDigest::sha256(b"proof")),
        None,
    ).expect("resolve");
    assert!(child.finalize_report(&tree).is_empty());

    // Budget: spend within bounds, overdraft refused.
    child.budget_mut().spend_work(50).expect("spend");
    assert!(child.budget_mut().spend_bytes(501).is_err());

    // Cancellation cascades: request on root, child chain sees it.
    root.request_cancellation();
    assert!(root.is_cancel_requested());
    assert!(child.is_cancel_requested(), "cancellation must cascade through the chain");
}

#[test]
fn scope_down_refuses_illegal_kind_and_budget_widening() {
    use fss_core::{ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec, TimestampNs};
    use fss_runtime::authority::AuthorityCx;
    use fss_runtime::budget::Budget;

    let spec = RootAuthoritySpec {
        trace_id: "trace:test".to_string(),
        operation_id: OperationId::parse("op:test").expect("op"),
        principal: "principal:test".to_string(),
        capabilities: Vec::new(),
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::builder()
            .bytes(1024)
            .storage_operations(64)
            .build()
            .expect("budget vector"),
        privacy_scope: "privacy:test".to_string(),
        retention_scope: "retention:test".to_string(),
        anchor_universe: ContentDigest::sha256(b"test-universe"),
        generation: 1,
    };
    let (root, mut tree) = AuthorityCx::root(
        spec,
        RegionId::new("region:process").expect("region"),
        RegionKind::Process,
        Budget::new(10, 100, 1_000),
        TimestampNs(1_000),
    )
    .expect("root");

    // Kind legality: Process admits only Property children.
    let bad_kind = root.scope_down(
        &mut tree,
        RegionId::new("region:bad").expect("child"),
        RegionKind::AdapterSession, // not a legal Process child
        Budget::new(1, 1, 1),
        RootAuthoritySpec {
            trace_id: "trace:bad".to_string(),
            operation_id: OperationId::parse("op:bad").expect("op"),
            principal: "principal:test".to_string(),
            capabilities: Vec::new(),
            deadline: None,
            priority: 10,
            budgets: fss_core::BudgetVector::builder()
                .bytes(64)
                .storage_operations(8)
                .build()
                .expect("budget vector"),
            privacy_scope: "privacy:test".to_string(),
            retention_scope: "retention:test".to_string(),
            anchor_universe: ContentDigest::sha256(b"test-universe"),
            generation: 1,
        },
        TimestampNs(2_000),
    );
    assert!(bad_kind.is_err(), "illegal child kind must refuse");

    // Budget widening: child asks more than the parent has left.
    let r = root.scope_down(
        &mut tree,
        RegionId::new("region:greedy").expect("child"),
        RegionKind::Property,
        Budget::new(11, 100, 1_000), // work_units 11 > parent 10
        RootAuthoritySpec {
            trace_id: "trace:greedy".to_string(),
            operation_id: OperationId::parse("op:greedy").expect("op"),
            principal: "principal:test".to_string(),
            capabilities: Vec::new(),
            deadline: None,
            priority: 10,
            budgets: fss_core::BudgetVector::builder()
                .bytes(512)
                .storage_operations(32)
                .build()
                .expect("budget vector"),
            privacy_scope: "privacy:test".to_string(),
            retention_scope: "retention:test".to_string(),
            anchor_universe: ContentDigest::sha256(b"test-universe"),
            generation: 1,
        },
        TimestampNs(2_000),
    );
    assert!(r.is_err(), "budget widening must refuse");
}
