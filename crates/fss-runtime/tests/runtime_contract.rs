//! Contract tests for the FSS-021 slice-1 runtime core: cancellation
//! lifecycle (four-valued outcomes incl. Indeterminate on non-cooperative
//! work), budget ledgers, obligation leak oracle, and authority scoping
//! rules (kind legality + no silent budget widening).

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
    use fss_core::BudgetDimension;
    use fss_runtime::budget::BudgetLedger;

    let limit = fss_core::BudgetVector::builder()
        .bytes(1_000)
        .tokens(100)
        .cpu_millis(10_000)
        .build()
        .expect("limit");
    let mut ledger = BudgetLedger::new(limit);
    ledger.spend(BudgetDimension::Bytes, 400).expect("spend");
    ledger.spend(BudgetDimension::Tokens, 100).expect("spend all");
    let err = ledger.spend(BudgetDimension::Tokens, 1).expect_err("overdraft");
    assert_eq!(
        err,
        fss_runtime::budget::LedgerError::Overdraft {
            dimension: BudgetDimension::Tokens,
            requested: 1,
            remaining: 0,
        }
    );
    // Refund restores headroom; pressure reflects utilization.
    ledger.refund(BudgetDimension::Tokens, 50);
    ledger.spend(BudgetDimension::Tokens, 50).expect("re-spend");
    assert_eq!(ledger.utilization(BudgetDimension::Tokens), Some(1.0));
    assert_eq!(ledger.pressure(), fss_core::ResourcePressure::Critical);
    assert_eq!(ledger.utilization(BudgetDimension::Bytes), Some(0.4));
}

#[test]
fn pressure_ladder_tracks_max_utilization() {
    use fss_core::BudgetDimension;
    use fss_runtime::budget::BudgetLedger;

    let limit = fss_core::BudgetVector::builder()
        .bytes(100)
        .tokens(100)
        .build()
        .expect("limit");
    let mut ledger = BudgetLedger::new(limit);
    assert_eq!(ledger.pressure(), fss_core::ResourcePressure::Nominal);
    ledger.spend(BudgetDimension::Bytes, 49).expect("spend");
    assert_eq!(ledger.pressure(), fss_core::ResourcePressure::Nominal);
    ledger.spend(BudgetDimension::Bytes, 1).expect("spend");
    assert_eq!(ledger.pressure(), fss_core::ResourcePressure::Elevated);
    ledger.spend(BudgetDimension::Tokens, 85).expect("spend");
    assert_eq!(ledger.pressure(), fss_core::ResourcePressure::Constrained);
    ledger.spend(BudgetDimension::Tokens, 14).expect("spend");
    assert_eq!(ledger.pressure(), fss_core::ResourcePressure::Critical);
}

#[test]
fn vector_spend_is_atomic_across_dimensions() {
    use fss_runtime::budget::BudgetLedger;

    let limit = fss_core::BudgetVector::builder()
        .bytes(10)
        .tokens(10)
        .build()
        .expect("limit");
    let mut ledger = BudgetLedger::new(limit);
    let delta = fss_core::BudgetVector::builder()
        .bytes(5)
        .tokens(50) // overdraft in tokens
        .build()
        .expect("delta");
    assert!(ledger.spend_vector(&delta).is_err());
    // Nothing committed: bytes must not have been debited.
    assert_eq!(ledger.utilization(fss_core::BudgetDimension::Bytes), Some(0.0));
}

#[test]
fn zero_budget_refuses_any_spend() {
    use fss_core::BudgetDimension;
    use fss_runtime::budget::BudgetLedger;

    let mut ledger = BudgetLedger::new(fss_core::BudgetVector::ZERO);
    let err = ledger.spend(BudgetDimension::Bytes, 1).expect_err("zero limit");
    assert_eq!(
        err,
        fss_runtime::budget::LedgerError::Overdraft {
            dimension: BudgetDimension::Bytes,
            requested: 1,
            remaining: 0,
        }
    );
    // Unmetered dimension reports no utilization and never drives pressure.
    assert_eq!(ledger.utilization(BudgetDimension::Bytes), None);
    assert_eq!(ledger.pressure(), fss_core::ResourcePressure::Nominal);
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
    let (mut root, mut tree) = AuthorityCx::root(
        spec,
        RegionId::new("region:process").expect("region"),
        RegionKind::Process,
        fss_core::BudgetVector::builder()
            .tokens(100)
            .bytes(1_000)
            .cpu_millis(10_000)
            .build()
            .expect("budget"),
        TimestampNs(1_000),
    )
    .expect("root");

    // Scope down legally: child kind legal + budget within parent.
    let child = root.scope_down(
        &mut tree,
        RegionId::new("region:property").expect("child region"),
        RegionKind::Property, // process → property is the legal narrowing
        fss_core::BudgetVector::builder()
            .tokens(50)
            .bytes(500)
            .cpu_millis(5_000)
            .build()
            .expect("budget"),
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
    assert_eq!(child.region().as_str(), "region:property");
    assert_eq!(child.budget().remaining().bytes, 500);
    // Reservation debited the parent: 100 - 50 tokens remain.
    assert_eq!(root.budget().remaining().tokens, 50);

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
    use fss_core::BudgetDimension;
    child.budget_mut().spend(BudgetDimension::Tokens, 50).expect("spend");
    assert!(child.budget_mut().spend(BudgetDimension::Bytes, 501).is_err());

    // Cancellation cascades: request on root, child chain sees it.
    root.request_cancellation();
    assert!(root.is_cancel_requested());
    assert!(child.is_cancel_requested(), "cancellation must cascade through the chain");
}

#[test]
fn scope_down_refuses_illegal_kind_and_budget_widening() {
    use fss_core::{ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec, TimestampNs};
    use fss_runtime::authority::AuthorityCx;

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
    let (mut root, mut tree) = AuthorityCx::root(
        spec,
        RegionId::new("region:process").expect("region"),
        RegionKind::Process,
        fss_core::BudgetVector::builder()
            .tokens(10)
            .bytes(100)
            .cpu_millis(1_000)
            .build()
            .expect("budget"),
        TimestampNs(1_000),
    )
    .expect("root");

    // Kind legality: Process admits only Property children.
    let bad_kind = root.scope_down(
        &mut tree,
        RegionId::new("region:bad").expect("child"),
        RegionKind::AdapterSession, // not a legal Process child
        fss_core::BudgetVector::builder()
            .tokens(1)
            .bytes(1)
            .cpu_millis(1)
            .build()
            .expect("budget"),
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
        fss_core::BudgetVector::builder()
            .tokens(11) // exceeds the parent's 10
            .bytes(100)
            .cpu_millis(1_000)
            .build()
            .expect("budget"),
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

#[test]
fn tree_wide_leak_oracle_reports_counts_and_inv006_coverage() {
    use fss_core::{BudgetVector, ContentDigest, ObligationId, OperationId, RegionId, RegionKind, RootAuthoritySpec, TimestampNs};
    use fss_runtime::authority::AuthorityCx;
    use fss_runtime::obligation::{new_obligation, tree_report, ObligationState, ObligationTerminal};

    let spec = RootAuthoritySpec {
        trace_id: "trace:oracle".to_string(),
        operation_id: OperationId::parse("op:root").expect("op"),
        principal: "principal:test".to_string(),
        capabilities: Vec::new(),
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(1024).build().expect("bv"),
        privacy_scope: "privacy:test".to_string(),
        retention_scope: "retention:test".to_string(),
        anchor_universe: ContentDigest::sha256(b"oracle-universe"),
        generation: 1,
    };
    let (root, mut tree) = AuthorityCx::root(
        spec,
        RegionId::new("region:process").expect("region"),
        RegionKind::Process,
        BudgetVector::builder().tokens(100).bytes(1_000).build().expect("budget"),
        TimestampNs(1_000),
    )
    .expect("root");

    // Register three obligations on the root region: resolve one Verified,
    // leave one Pending (a leak), resolve one Indeterminate WITHOUT a note
    // (INV-006 hazard — the oracle must surface it).
    let mk = |id: &str| {
        new_obligation(id, OperationId::parse("op:root").expect("op"), "predicate")
            .expect("obligation")
    };
    root.register_obligation(&mut tree, mk("obl:done")).expect("r1");
    root.register_obligation(&mut tree, mk("obl:leak")).expect("r2");
    root.register_obligation(&mut tree, mk("obl:unknown")).expect("r3");
    root.resolve_obligation(
        &mut tree,
        &ObligationId::parse("obl:done").expect("id"),
        ObligationTerminal::Completed,
        Some(ContentDigest::sha256(b"proof")),
        None,
    )
    .expect("resolve done");
    // Indeterminate resolution through the tree requires a reconciliation
    // note (INV-006). Verify the tree enforces it...
    let refused = tree.resolve_obligation(
        &RegionId::new("region:process").expect("region"),
        &ObligationId::parse("obl:unknown").expect("id"),
        ObligationState::Indeterminate,
        None,
        None,
    );
    assert!(refused.is_err(), "Indeterminate without a note must refuse");
    // ...and with a note it lands.
    tree.resolve_obligation(
        &RegionId::new("region:process").expect("region"),
        &ObligationId::parse("obl:unknown").expect("id"),
        ObligationState::Indeterminate,
        None,
        Some("network partition before ack; reconcile on reconnect"),
    )
    .expect("resolve with note");

    let report = tree_report(&tree);
    assert_eq!(report.len(), 1);
    let root_report = &report[0];
    assert_eq!(root_report.region, "region:process");
    assert_eq!(root_report.counts, [1, 1, 0, 1, 0]); // pending, verified, failed, indeterminate, cancelled
    assert_eq!(root_report.leaked.len(), 1);
    assert_eq!(root_report.leaked[0].id, "obl:leak");
    assert_eq!(root_report.indeterminate_with_note, vec!["obl:unknown".to_string()]);
    assert!(root_report.indeterminate_without_note.is_empty());
}

// ---------- capability grants and resource scopes (FSS-025) ----------

fn test_spec(trace: &str, op: &str, caps: Vec<String>) -> fss_core::RootAuthoritySpec {
    fss_core::RootAuthoritySpec {
        trace_id: trace.to_string(),
        operation_id: fss_core::OperationId::parse(op).expect("op"),
        principal: "principal:test".to_string(),
        capabilities: caps,
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::builder().bytes(1024).build().expect("bv"),
        privacy_scope: "privacy:test".to_string(),
        retention_scope: "retention:test".to_string(),
        anchor_universe: fss_core::ContentDigest::sha256(b"grant-universe"),
        generation: 1,
    }
}

#[test]
fn grant_enforcement_and_resource_scopes() {
    use fss_core::RuntimeGrant;
    use fss_runtime::grant::{GrantError, GrantSet};

    // Unregistered capability strings are refused at construction.
    let bad = test_spec("trace:g", "op:g", vec!["NOT-A-REAL-CAP".to_string()]);
    let refused = fss_runtime::authority::AuthorityCx::root(
        bad,
        fss_core::RegionId::new("region:p").expect("r"),
        fss_core::RegionKind::Process,
        fss_core::BudgetVector::ZERO,
        fss_core::TimestampNs(1),
    );
    assert!(matches!(
        refused.err(),
        Some(fss_runtime::authority::AuthorityError::Grant(
            GrantError::UnregisteredCapability { .. }
        ))
    ));

    // A held grant passes; a missing grant fails closed and names itself.
    let (auth, _t) = fss_runtime::authority::AuthorityCx::root(
        test_spec("trace:g2", "op:g2", vec!["CAP-ALERT-COMMIT-001".to_string()]),
        fss_core::RegionId::new("region:p2").expect("r"),
        fss_core::RegionKind::Process,
        fss_core::BudgetVector::ZERO,
        fss_core::TimestampNs(1),
    )
    .expect("root");
    auth.require_grant(RuntimeGrant::AlertCommit).expect("held");
    let missing = auth.require_grant(RuntimeGrant::PtzCommit).expect_err("missing");
    assert_eq!(missing, GrantError::MissingGrant { grant: RuntimeGrant::PtzCommit });

    // Resource scopes: scoped grant admits in-scope resources only.
    let grants = GrantSet::empty().with_scope(
        RuntimeGrant::AdapterNet,
        ["cam:porch".to_string()].into_iter().collect(),
    );
    grants
        .require_grant_for(RuntimeGrant::AdapterNet, "cam:porch")
        .expect("in scope");
    let outside = grants
        .require_grant_for(RuntimeGrant::AdapterNet, "cam:garage")
        .expect_err("outside scope");
    assert_eq!(
        outside,
        GrantError::OutsideScope {
            grant: RuntimeGrant::AdapterNet,
            resource: "cam:garage".to_string(),
        }
    );
}

#[test]
fn scope_down_never_widens_grants_or_scopes() {
    use fss_core::RuntimeGrant;
    use fss_runtime::grant::{GrantError, GrantSet};

    let parent = GrantSet::empty().with_scope(
        RuntimeGrant::AdapterNet,
        ["cam:a".to_string(), "cam:b".to_string()].into_iter().collect(),
    );

    // Child holding a grant the parent lacks: refuse. (Built through the
    // real authority-string path — no test-only mutation hooks.)
    let child_extra = GrantSet::from_authority(
        &fss_core::ContextAuthority::new_root(test_spec(
            "trace:c",
            "op:c",
            vec![
                "CAP-ADAPTER-NET-001".to_string(),
                "CAP-PTZ-COMMIT-001".to_string(),
            ],
        ))
        .expect("child authority"),
    )
    .expect("child grants");
    assert!(matches!(
        parent.verify_narrowed_by(&child_extra),
        Err(GrantError::Widening { .. })
    ));

    // Child narrowing scope to a subset: legal.
    let child_narrower = GrantSet::empty().with_scope(
        RuntimeGrant::AdapterNet,
        ["cam:a".to_string()].into_iter().collect(),
    );
    parent.verify_narrowed_by(&child_narrower).expect("narrower scope is legal");

    // Child unscoped where parent is scoped: refuse (widening).
    let child_unscoped = GrantSet::from_authority(
        &fss_core::ContextAuthority::new_root(test_spec(
            "trace:c2",
            "op:c2",
            vec!["CAP-ADAPTER-NET-001".to_string()],
        ))
        .expect("child authority"),
    )
    .expect("unscoped child grants");
    assert!(matches!(
        parent.verify_narrowed_by(&child_unscoped),
        Err(GrantError::Widening { .. })
    ));

    // Child superset scope: refuse.
    let child_super = GrantSet::empty().with_scope(
        RuntimeGrant::AdapterNet,
        ["cam:a".to_string(), "cam:b".to_string(), "cam:c".to_string()]
            .into_iter()
            .collect(),
    );
    assert!(matches!(
        parent.verify_narrowed_by(&child_super),
        Err(GrantError::Widening { .. })
    ));
}

// ---------- leases, epochs, fencing (FSS-026) ----------

#[test]
fn lease_exclusivity_takeover_and_renewal() {
    use fss_core::TimestampNs;
    use fss_runtime::lease::{LeaseError, LeaseRegistry, LeaseState};

    let mut reg = LeaseRegistry::new();
    let a = reg
        .acquire("stream:porch", "region:adapter-a", Some(1_000), TimestampNs(100))
        .expect("first acquire");
    assert_eq!(a.fence, 1);
    assert_eq!(a.state, LeaseState::Active);

    // Second holder refused with the holder named.
    let err = reg
        .acquire("stream:porch", "region:adapter-b", Some(1_000), TimestampNs(200))
        .expect_err("held");
    assert!(matches!(err, LeaseError::Held { holder, .. } if holder == "region:adapter-a"));

    // Renewal extends the same lease without changing the fence.
    reg.renew(&a.id, 5_000, TimestampNs(300)).expect("renew");
    assert_eq!(reg.current_fence("stream:porch"), Some(1));

    // Fence check passes while active.
    reg.check_fence("stream:porch", 1, TimestampNs(400)).expect("fence ok");

    // After expiry, the old holder's fence fails and a takeover succeeds with
    // a fresh token.
    let err = reg
        .check_fence("stream:porch", 1, TimestampNs(10_000))
        .expect_err("expired");
    assert!(matches!(err, LeaseError::LeaseExpired { .. }));
    let b = reg
        .acquire("stream:porch", "region:adapter-b", Some(1_000), TimestampNs(10_100))
        .expect("takeover after expiry");
    assert_eq!(b.fence, 2);
    // The zombie's token is permanently stale.
    let err = reg
        .check_fence("stream:porch", 1, TimestampNs(10_200))
        .expect_err("stale");
    assert_eq!(
        err,
        LeaseError::StaleFence {
            resource: "stream:porch".to_string(),
            presented: 1,
            current: 2,
        }
    );
}

#[test]
fn release_and_revoke_are_terminal_for_fence_use() {
    use fss_core::TimestampNs;
    use fss_runtime::lease::{LeaseError, LeaseRegistry, LeaseState};

    let mut reg = LeaseRegistry::new();
    let a = reg
        .acquire("device:ptz", "region:r1", None, TimestampNs(0))
        .expect("acquire");
    reg.release(&a.id).expect("release");
    let err = reg.check_fence("device:ptz", a.fence, TimestampNs(1)).expect_err("released");
    assert!(matches!(err, LeaseError::NotActive { state: LeaseState::Released, .. }));

    // Revocation advances the fence: the revoked token reports StaleFence.
    let b = reg.acquire("device:ptz", "region:r2", None, TimestampNs(2)).expect("re-acquire");
    reg.revoke(&b.id).expect("revoke");
    let err = reg.check_fence("device:ptz", b.fence, TimestampNs(3)).expect_err("revoked");
    assert!(matches!(err, LeaseError::StaleFence { presented, .. } if presented == b.fence));

    // Double-release and unknown leases are typed refusals.
    assert!(matches!(
        reg.release(&a.id),
        Err(LeaseError::NotActive { state: LeaseState::Released, .. })
    ));
    assert!(matches!(
        reg.renew("lease:nope:99", 1, TimestampNs(4)),
        Err(LeaseError::UnknownLease { .. })
    ));
    assert!(matches!(
        reg.check_fence("resource:never", 7, TimestampNs(5)),
        Err(LeaseError::NoFence { .. })
    ));
}

// ---------- two-phase effect coordinator (FSS-027) ----------

fn effect_authority(caps: Vec<String>) -> (fss_runtime::authority::AuthorityCx, fss_core::RegionTree) {
    fss_runtime::authority::AuthorityCx::root(
        test_spec("trace:fx", "op:fx", caps),
        fss_core::RegionId::new("region:fx").expect("r"),
        fss_core::RegionKind::Process,
        fss_core::BudgetVector::builder().tokens(64).bytes(4096).build().expect("bv"),
        fss_core::TimestampNs(1),
    )
    .expect("root")
}

#[test]
fn effect_happy_path_prepare_commit_observe_verify() {
    use fss_core::{ContentDigest, OperationId, RuntimeGrant, TimestampNs};
    use fss_runtime::effect::EffectCoordinator;
    use fss_runtime::lease::LeaseRegistry;

    let (auth, mut tree) = effect_authority(vec![
        "CAP-PTZ-PREPARE-001".to_string(),
        "CAP-PTZ-COMMIT-001".to_string(),
    ]);
    let mut leases = LeaseRegistry::new();
    let lease = leases
        .acquire("device:ptz:porch", "region:fx", Some(10_000), TimestampNs(100))
        .expect("lease");

    let prepared = EffectCoordinator::prepare(
        &auth,
        &mut tree,
        &leases,
        OperationId::parse("op:ptz-1").expect("op"),
        "device:ptz:porch",
        lease.fence,
        RuntimeGrant::PtzPrepare,
        RuntimeGrant::PtzCommit,
        "camera panned to preset 3",
    )
    .expect("prepare");
    assert_eq!(prepared.state(), fss_core::EffectState::Prepared);
    // Obligation registered and pending: the leak oracle sees it.
    assert_eq!(auth.leaked_obligations(&tree).len(), 1);

    let mut committed = EffectCoordinator::commit(&auth, &mut leases, prepared, TimestampNs(200))
        .expect("commit");
    assert_eq!(committed.state(), fss_core::EffectState::Committed);

    EffectCoordinator::adapter_accepted(&mut committed).expect("accepted");
    EffectCoordinator::observed(&mut committed).expect("observed");
    EffectCoordinator::verified(&mut tree, &auth, committed, ContentDigest::sha256(b"preset-3-proof"))
        .expect("verified");
    // Obligation terminal: no leaks remain.
    assert!(auth.finalize_report(&tree).is_empty());
}

#[test]
fn effect_commit_refused_on_stale_fence_and_missing_grant() {
    use fss_core::{OperationId, RuntimeGrant, TimestampNs};
    use fss_runtime::effect::{EffectCoordError, EffectCoordinator};
    use fss_runtime::lease::LeaseRegistry;

    let (auth, mut tree) = effect_authority(vec![
        "CAP-PTZ-PREPARE-001".to_string(),
        "CAP-PTZ-COMMIT-001".to_string(),
    ]);
    let mut leases = LeaseRegistry::new();
    let lease = leases
        .acquire("device:ptz:porch", "region:fx", None, TimestampNs(100))
        .expect("lease");
    let prepared = EffectCoordinator::prepare(
        &auth,
        &mut tree,
        &leases,
        OperationId::parse("op:ptz-2").expect("op"),
        "device:ptz:porch",
        lease.fence,
        RuntimeGrant::PtzPrepare,
        RuntimeGrant::PtzCommit,
        "predicate",
    )
    .expect("prepare");

    // Zombie: lease revoked between prepare and commit.
    leases.revoke(&lease.id).expect("revoke");
    let err = EffectCoordinator::commit(&auth, &mut leases, prepared, TimestampNs(200))
        .expect_err("stale fence must refuse commit");
    assert!(matches!(err, EffectCoordError::Fence { .. }));

    // Missing commit grant: prepare-only authority.
    let (auth2, mut tree2) = effect_authority(vec!["CAP-PTZ-PREPARE-001".to_string()]);
    let lease2 = leases
        .acquire("device:ptz:porch", "region:fx2", None, TimestampNs(300))
        .expect("lease2");
    let prepared2 = EffectCoordinator::prepare(
        &auth2,
        &mut tree2,
        &leases,
        OperationId::parse("op:ptz-3").expect("op"),
        "device:ptz:porch",
        lease2.fence,
        RuntimeGrant::PtzPrepare,
        RuntimeGrant::PtzCommit,
        "predicate",
    )
    .expect("prepare2");
    let err = EffectCoordinator::commit(&auth2, &mut leases, prepared2, TimestampNs(400))
        .expect_err("commit grant missing");
    assert!(matches!(err, EffectCoordError::Grant { .. }));
}

#[test]
fn effect_cancel_and_indeterminate_semantics() {
    use fss_core::{OperationId, RuntimeGrant, TimestampNs};
    use fss_runtime::effect::{EffectCoordError, EffectCoordinator};
    use fss_runtime::lease::LeaseRegistry;

    let (auth, mut tree) = effect_authority(vec![
        "CAP-ALERT-PREPARE-001".to_string(),
        "CAP-ALERT-COMMIT-001".to_string(),
    ]);
    let mut leases = LeaseRegistry::new();
    let lease = leases
        .acquire("webhook:ops", "region:fx", None, TimestampNs(0))
        .expect("lease");

    // Cancel before commit: obligation drains, no leak.
    let prepared = EffectCoordinator::prepare(
        &auth,
        &mut tree,
        &leases,
        OperationId::parse("op:alert-1").expect("op"),
        "webhook:ops",
        lease.fence,
        RuntimeGrant::AlertPrepare,
        RuntimeGrant::AlertCommit,
        "alert delivered",
    )
    .expect("prepare");
    EffectCoordinator::cancel_prepared(&mut tree, &auth, prepared).expect("cancel");
    assert!(auth.finalize_report(&tree).is_empty());

    // Indeterminate requires a reconciliation note (INV-006).
    let prepared2 = EffectCoordinator::prepare(
        &auth,
        &mut tree,
        &leases,
        OperationId::parse("op:alert-2").expect("op"),
        "webhook:ops",
        lease.fence,
        RuntimeGrant::AlertPrepare,
        RuntimeGrant::AlertCommit,
        "alert delivered",
    )
    .expect("prepare2");
    let committed2 = EffectCoordinator::commit(&auth, &mut leases, prepared2, TimestampNs(10))
        .expect("commit2");
    let err = EffectCoordinator::indeterminate(&mut tree, &auth, committed2, None)
        .expect_err("note required");
    assert!(matches!(err, EffectCoordError::IndeterminateWithoutNote { .. }));

    // With a note it lands; the tree-wide oracle reports note coverage.
    let prepared3 = EffectCoordinator::prepare(
        &auth,
        &mut tree,
        &leases,
        OperationId::parse("op:alert-3").expect("op"),
        "webhook:ops",
        lease.fence,
        RuntimeGrant::AlertPrepare,
        RuntimeGrant::AlertCommit,
        "alert delivered",
    )
    .expect("prepare3");
    let committed3 = EffectCoordinator::commit(&auth, &mut leases, prepared3, TimestampNs(20))
        .expect("commit3");
    EffectCoordinator::indeterminate(
        &mut tree,
        &auth,
        committed3,
        Some("webhook ack lost in partition; reconcile on reconnect"),
    )
    .expect("indeterminate with note");
    let report = fss_runtime::obligation::tree_report(&tree);
    let root = &report[0];
    assert_eq!(root.counts[3], 1, "one indeterminate obligation");
    assert_eq!(root.indeterminate_with_note, vec!["obligation:op:alert-3:terminal".to_string()]);
    assert!(root.indeterminate_without_note.is_empty());
}

#[test]
fn effect_illegal_transitions_are_typed_refusals() {
    use fss_core::{OperationId, RuntimeGrant, TimestampNs};
    use fss_runtime::effect::{EffectCoordError, EffectCoordinator};
    use fss_runtime::lease::LeaseRegistry;

    let (auth, mut tree) = effect_authority(vec![
        "CAP-PTZ-PREPARE-001".to_string(),
        "CAP-PTZ-COMMIT-001".to_string(),
    ]);
    let mut leases = LeaseRegistry::new();
    let lease = leases
        .acquire("device:ptz:x", "region:fx", None, TimestampNs(0))
        .expect("lease");
    let prepared = EffectCoordinator::prepare(
        &auth,
        &mut tree,
        &leases,
        OperationId::parse("op:ptz-9").expect("op"),
        "device:ptz:x",
        lease.fence,
        RuntimeGrant::PtzPrepare,
        RuntimeGrant::PtzCommit,
        "predicate",
    )
    .expect("prepare");
    let mut committed = EffectCoordinator::commit(&auth, &mut leases, prepared, TimestampNs(5))
        .expect("commit");
    // Committed → Verified directly is illegal (must pass through
    // AdapterAccepted → Observed).
    let err = EffectCoordinator::observed(&mut committed).expect_err("skip is illegal");
    assert!(matches!(err, EffectCoordError::IllegalTransition { .. }));
}
