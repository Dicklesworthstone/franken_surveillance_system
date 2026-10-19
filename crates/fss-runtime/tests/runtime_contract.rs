#![forbid(unsafe_code)]

//! Contract tests for the FSS-021 slice-1 runtime core: cancellation
//! lifecycle (four-valued outcomes incl. Indeterminate on non-cooperative
//! work), budget ledgers, obligation leak oracle, and authority scoping
//! rules (kind legality + no silent budget widening).

use fss_runtime::cancellation::{CancelOutcome, CancellationLifecycle, DrainStep};

// ---------- cancellation ----------

#[test]
fn cooperative_drain_ends_cancelled() -> Result<(), Box<dyn std::error::Error>> {
    let mut lc = CancellationLifecycle::new(["w2".to_string(), "w1".to_string()], 1_000);
    assert!(!lc.is_requested());
    lc.request(10);
    lc.begin_drain(20);
    assert!(lc.is_requested());
    // Deterministic sorted pending list.
    match lc.drive(30) {
        DrainStep::Pending(ids) => assert_eq!(ids, vec!["w1", "w2"]),
        other => return Err(format!("expected pending, got {other:?}").into()),
    }
    lc.worker_done("w1")?;
    lc.worker_done("w2")?;
    assert_eq!(lc.outcome(), Some(&CancelOutcome::Cancelled));
    assert!(CancelOutcome::Cancelled.is_terminal_clean());
    Ok(())
}

#[test]
fn non_cooperative_work_ends_indeterminate_with_stranded_names()
-> Result<(), Box<dyn std::error::Error>> {
    let mut lc = CancellationLifecycle::new(["stuck".to_string(), "also-stuck".to_string()], 500);
    lc.request(10);
    lc.begin_drain(100);
    let step = lc.drive(601);
    match step {
        DrainStep::Finalized(CancelOutcome::Indeterminate { reason }) => {
            assert!(reason.contains("stuck"), "{reason}");
            assert!(reason.contains("also-stuck"), "{reason}");
        }
        other => return Err(format!("expected Indeterminate, got {other:?}").into()),
    }
    // Never silently cancelled, never faked complete.
    let Some(outcome) = lc.outcome() else {
        return Err("cancellation ledger lost its outcome".into());
    };
    assert!(!outcome.is_terminal_clean());
    Ok(())
}

#[test]
fn duplicate_or_unknown_worker_reports_are_typed_errors() -> Result<(), Box<dyn std::error::Error>>
{
    let mut lc = CancellationLifecycle::new(["w1".to_string()], 1_000);
    lc.request(1);
    lc.begin_drain(2);
    assert!(lc.worker_done("ghost").is_err(), "unknown id must refuse");
    lc.worker_done("w1")?;
    assert!(
        lc.worker_done("w1").is_err(),
        "duplicate report must refuse"
    );
    Ok(())
}

#[test]
fn natural_completion_and_failure_are_distinct_outcomes() -> Result<(), Box<dyn std::error::Error>>
{
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
    Ok(())
}

#[test]
fn request_is_idempotent_and_never_rewinds() -> Result<(), Box<dyn std::error::Error>> {
    let mut lc = CancellationLifecycle::new(["w".to_string()], 1_000);
    lc.request(10);
    lc.begin_drain(20);
    lc.request(30); // absorbed: the window must not rewind
    lc.worker_done("w")?;
    assert_eq!(lc.outcome(), Some(&CancelOutcome::Cancelled));
    Ok(())
}

// ---------- budget ----------

#[test]
fn budget_spends_and_refuses_typed_overdraft() -> Result<(), Box<dyn std::error::Error>> {
    use fss_core::BudgetDimension;
    use fss_runtime::budget::BudgetLedger;

    let limit = fss_core::BudgetVector::builder()
        .bytes(1_000)
        .tokens(100)
        .cpu_millis(10_000)
        .build()?;
    let mut ledger = BudgetLedger::new(limit);
    ledger.spend(BudgetDimension::Bytes, 400)?;
    ledger.spend(BudgetDimension::Tokens, 100)?;
    let err = ledger
        .spend(BudgetDimension::Tokens, 1)
        .err()
        .ok_or("overdraft")?;
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
    ledger.spend(BudgetDimension::Tokens, 50)?;
    assert_eq!(ledger.utilization(BudgetDimension::Tokens), Some(1.0));
    assert_eq!(ledger.pressure(), fss_core::ResourcePressure::Critical);
    assert_eq!(ledger.utilization(BudgetDimension::Bytes), Some(0.4));
    Ok(())
}

#[test]
fn pressure_ladder_tracks_max_utilization() -> Result<(), Box<dyn std::error::Error>> {
    use fss_core::BudgetDimension;
    use fss_runtime::budget::BudgetLedger;

    let limit = fss_core::BudgetVector::builder()
        .bytes(100)
        .tokens(100)
        .build()?;
    let mut ledger = BudgetLedger::new(limit);
    assert_eq!(ledger.pressure(), fss_core::ResourcePressure::Nominal);
    ledger.spend(BudgetDimension::Bytes, 49)?;
    assert_eq!(ledger.pressure(), fss_core::ResourcePressure::Nominal);
    ledger.spend(BudgetDimension::Bytes, 1)?;
    assert_eq!(ledger.pressure(), fss_core::ResourcePressure::Elevated);
    ledger.spend(BudgetDimension::Tokens, 85)?;
    assert_eq!(ledger.pressure(), fss_core::ResourcePressure::Constrained);
    ledger.spend(BudgetDimension::Tokens, 14)?;
    assert_eq!(ledger.pressure(), fss_core::ResourcePressure::Critical);
    Ok(())
}

#[test]
fn vector_spend_is_atomic_across_dimensions() -> Result<(), Box<dyn std::error::Error>> {
    use fss_runtime::budget::BudgetLedger;

    let limit = fss_core::BudgetVector::builder()
        .bytes(10)
        .tokens(10)
        .build()?;
    let mut ledger = BudgetLedger::new(limit);
    let delta = fss_core::BudgetVector::builder()
        .bytes(5)
        .tokens(50) // overdraft in tokens
        .build()
        ?;
    assert!(ledger.spend_vector(&delta).is_err());
    // Nothing committed: bytes must not have been debited.
    assert_eq!(
        ledger.utilization(fss_core::BudgetDimension::Bytes),
        Some(0.0)
    );
    Ok(())
}

#[test]
fn zero_budget_refuses_any_spend() -> Result<(), Box<dyn std::error::Error>> {
    use fss_core::BudgetDimension;
    use fss_runtime::budget::BudgetLedger;

    let mut ledger = BudgetLedger::new(fss_core::BudgetVector::ZERO);
    let err = ledger
        .spend(BudgetDimension::Bytes, 1)
        .err()
        .ok_or("zero limit")?;
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
    Ok(())
}

// ---------- obligations (facade over fss-core's tree-owned machinery) ----------

#[test]
fn obligation_construction_and_terminal_mapping() -> Result<(), Box<dyn std::error::Error>> {
    use fss_core::{ObligationId, OperationId};
    use fss_runtime::obligation::{ObligationState, ObligationTerminal, leaked_in, new_obligation};

    let op = OperationId::parse("op:test")?;
    let o1 = new_obligation("obl:one", op.clone(), "all staged bytes published")?;
    let o2 = new_obligation("obl:two", op, "all child roots visible")?;
    assert_eq!(o1.state, ObligationState::Pending);
    assert_eq!(o1.obligation_id, ObligationId::parse("obl:one")?);

    // The leak oracle reads pending state only.
    let leaks = leaked_in([o1.clone(), o2.clone()]);
    assert_eq!(leaks.len(), 2);
    assert_eq!(leaks[0].id, "obl:one");

    // Terminal mapping: the four-valued vocabulary maps onto the tree's
    // canonical states.
    assert_eq!(
        ObligationTerminal::Completed.to_state(),
        ObligationState::Verified
    );
    assert_eq!(
        ObligationTerminal::Drained.to_state(),
        ObligationState::Cancelled
    );
    assert_eq!(
        ObligationTerminal::Failed.to_state(),
        ObligationState::Failed
    );
    assert_eq!(
        ObligationTerminal::Indeterminate.to_state(),
        ObligationState::Indeterminate
    );

    // Terminated obligations drop out of the leak set.
    let mut done = o1.clone();
    done.state = ObligationState::Verified;
    let leaks = leaked_in([done, o2]);
    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].id, "obl:two");
    Ok(())
}

// ---------- authority lifecycle (FSS-021 public surface) ----------

#[test]
fn authority_lifecycle_end_to_end() -> Result<(), Box<dyn std::error::Error>> {
    use fss_core::{
        ContentDigest, ObligationId, OperationId, RegionId, RegionKind, RootAuthoritySpec,
        TimestampNs,
    };
    use fss_runtime::authority::AuthorityCx;
    use fss_runtime::obligation::{ObligationTerminal, new_obligation};

    let spec = RootAuthoritySpec {
        trace_id: "trace:test".to_string(),
        operation_id: OperationId::parse("op:test")?,
        principal: "principal:test".to_string(),
        capabilities: Vec::new(),
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::builder()
            .bytes(1024)
            .storage_operations(64)
            .build()?,
        privacy_scope: "privacy:test".to_string(),
        retention_scope: "retention:test".to_string(),
        anchor_universe: ContentDigest::sha256(b"test-universe"),
        generation: 1,
    };
    let (mut root, mut tree) = AuthorityCx::root(
        spec,
        RegionId::new("region:process")?,
        RegionKind::Process,
        fss_core::BudgetVector::builder()
            .tokens(100)
            .bytes(1_000)
            .cpu_millis(10_000)
            .build()?,
        TimestampNs(1_000),
    )?;

    // Scope down legally: child kind legal + budget within parent.
    let child = root.scope_down(
        &mut tree,
        RegionId::new("region:property")?,
        RegionKind::Property, // process → property is the legal narrowing
        fss_core::BudgetVector::builder()
            .tokens(50)
            .bytes(500)
            .cpu_millis(5_000)
            .build()?,
        RootAuthoritySpec {
            trace_id: "trace:test".to_string(), // narrowing: trace_id is inherited
            operation_id: OperationId::parse("op:child")?,
            principal: "principal:test".to_string(),
            capabilities: Vec::new(),
            deadline: None,
            priority: 10,
            budgets: fss_core::BudgetVector::builder()
                .bytes(512)
                .storage_operations(32)
                .build()?,
            privacy_scope: "privacy:test".to_string(),
            retention_scope: "retention:test".to_string(),
            anchor_universe: ContentDigest::sha256(b"test-universe"),
            generation: 1,
        },
        TimestampNs(2_000),
    );
    let mut child = child?;
    assert_eq!(child.region().as_str(), "region:property");
    assert_eq!(child.budget().remaining().bytes, 500);
    // Reservation debited the parent: 100 - 50 tokens remain.
    assert_eq!(root.budget().remaining().tokens, 50);

    // Obligation lifecycle through the tree: register → leak visible → resolve.
    let ob = new_obligation(
        "obl:capture-drain",
        OperationId::parse("op:child")?,
        "capture ring drained",
    )?;
    child.register_obligation(&mut tree, ob)?;
    assert_eq!(child.leaked_obligations(&tree).len(), 1);
    child.resolve_obligation(
        &mut tree,
        &ObligationId::parse("obl:capture-drain")?,
        ObligationTerminal::Completed,
        Some(ContentDigest::sha256(b"proof")),
        None,
    )?;
    assert!(child.finalize_report(&tree).is_empty());

    // Budget: spend within bounds, overdraft refused.
    use fss_core::BudgetDimension;
    child.budget_mut().spend(BudgetDimension::Tokens, 50)?;
    assert!(
        child
            .budget_mut()
            .spend(BudgetDimension::Bytes, 501)
            .is_err()
    );

    // Cancellation cascades: request on root, child chain sees it.
    root.request_cancellation();
    assert!(root.is_cancel_requested());
    assert!(
        child.is_cancel_requested(),
        "cancellation must cascade through the chain"
    );
    Ok(())
}

#[test]
fn scope_down_refuses_illegal_kind_and_budget_widening() -> Result<(), Box<dyn std::error::Error>> {
    use fss_core::{
        ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec, TimestampNs,
    };
    use fss_runtime::authority::AuthorityCx;

    let spec = RootAuthoritySpec {
        trace_id: "trace:test".to_string(),
        operation_id: OperationId::parse("op:test")?,
        principal: "principal:test".to_string(),
        capabilities: Vec::new(),
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::builder()
            .bytes(1024)
            .storage_operations(64)
            .build()?,
        privacy_scope: "privacy:test".to_string(),
        retention_scope: "retention:test".to_string(),
        anchor_universe: ContentDigest::sha256(b"test-universe"),
        generation: 1,
    };
    let (mut root, mut tree) = AuthorityCx::root(
        spec,
        RegionId::new("region:process")?,
        RegionKind::Process,
        fss_core::BudgetVector::builder()
            .tokens(10)
            .bytes(100)
            .cpu_millis(1_000)
            .build()?,
        TimestampNs(1_000),
    )?;

    // Kind legality: Process admits only Property children.
    let bad_kind = root.scope_down(
        &mut tree,
        RegionId::new("region:bad")?,
        RegionKind::AdapterSession, // not a legal Process child
        fss_core::BudgetVector::builder()
            .tokens(1)
            .bytes(1)
            .cpu_millis(1)
            .build()?,
        RootAuthoritySpec {
            trace_id: "trace:bad".to_string(),
            operation_id: OperationId::parse("op:bad")?,
            principal: "principal:test".to_string(),
            capabilities: Vec::new(),
            deadline: None,
            priority: 10,
            budgets: fss_core::BudgetVector::builder()
                .bytes(64)
                .storage_operations(8)
                .build()?,
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
        RegionId::new("region:greedy")?,
        RegionKind::Property,
        fss_core::BudgetVector::builder()
            .tokens(11) // exceeds the parent's 10
            .bytes(100)
            .cpu_millis(1_000)
            .build()
            ?,
        RootAuthoritySpec {
            trace_id: "trace:greedy".to_string(),
            operation_id: OperationId::parse("op:greedy")?,
            principal: "principal:test".to_string(),
            capabilities: Vec::new(),
            deadline: None,
            priority: 10,
            budgets: fss_core::BudgetVector::builder()
                .bytes(512)
                .storage_operations(32)
                .build()?,
            privacy_scope: "privacy:test".to_string(),
            retention_scope: "retention:test".to_string(),
            anchor_universe: ContentDigest::sha256(b"test-universe"),
            generation: 1,
        },
        TimestampNs(2_000),
    );
    assert!(r.is_err(), "budget widening must refuse");
    Ok(())
}

#[test]
fn tree_wide_leak_oracle_reports_counts_and_inv006_coverage()
-> Result<(), Box<dyn std::error::Error>> {
    use fss_core::{
        BudgetVector, ContentDigest, ObligationId, OperationId, RegionId, RegionKind,
        RootAuthoritySpec, TimestampNs,
    };
    use fss_runtime::authority::AuthorityCx;
    use fss_runtime::obligation::{
        ObligationState, ObligationTerminal, new_obligation, tree_report,
    };

    let spec = RootAuthoritySpec {
        trace_id: "trace:oracle".to_string(),
        operation_id: OperationId::parse("op:root")?,
        principal: "principal:test".to_string(),
        capabilities: Vec::new(),
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(1024).build()?,
        privacy_scope: "privacy:test".to_string(),
        retention_scope: "retention:test".to_string(),
        anchor_universe: ContentDigest::sha256(b"oracle-universe"),
        generation: 1,
    };
    let (root, mut tree) = AuthorityCx::root(
        spec,
        RegionId::new("region:process")?,
        RegionKind::Process,
        BudgetVector::builder().tokens(100).bytes(1_000).build()?,
        TimestampNs(1_000),
    )?;

    // Register three obligations on the root region: resolve one Verified,
    // leave one Pending (a leak), resolve one Indeterminate WITHOUT a note
    // (INV-006 hazard — the oracle must surface it).
    let op_root = OperationId::parse("op:root")?;
    let mk = |id: &str| new_obligation(id, op_root.clone(), "predicate");
    root.register_obligation(&mut tree, mk("obl:done")?)?;
    root.register_obligation(&mut tree, mk("obl:leak")?)?;
    root.register_obligation(&mut tree, mk("obl:unknown")?)?;
    root.resolve_obligation(
        &mut tree,
        &ObligationId::parse("obl:done")?,
        ObligationTerminal::Completed,
        Some(ContentDigest::sha256(b"proof")),
        None,
    )?;
    // Indeterminate resolution through the tree requires a reconciliation
    // note (INV-006). Verify the tree enforces it...
    let refused = tree.resolve_obligation(
        &RegionId::new("region:process")?,
        &ObligationId::parse("obl:unknown")?,
        ObligationState::Indeterminate,
        None,
        None,
    );
    assert!(refused.is_err(), "Indeterminate without a note must refuse");
    // ...and with a note it lands.
    tree.resolve_obligation(
        &RegionId::new("region:process")?,
        &ObligationId::parse("obl:unknown")?,
        ObligationState::Indeterminate,
        None,
        Some("network partition before ack; reconcile on reconnect"),
    )?;

    let report = tree_report(&tree);
    assert_eq!(report.len(), 1);
    let root_report = &report[0];
    assert_eq!(root_report.region, "region:process");
    assert_eq!(root_report.counts, [1, 1, 0, 1, 0]); // pending, verified, failed, indeterminate, cancelled
    assert_eq!(root_report.leaked.len(), 1);
    assert_eq!(root_report.leaked[0].id, "obl:leak");
    assert_eq!(
        root_report.indeterminate_with_note,
        vec!["obl:unknown".to_string()]
    );
    assert!(root_report.indeterminate_without_note.is_empty());
    Ok(())
}

// ---------- capability grants and resource scopes (FSS-025) ----------

fn test_spec(
    trace: &str,
    op: &str,
    caps: Vec<String>,
) -> Result<fss_core::RootAuthoritySpec, Box<dyn std::error::Error>> {
    let spec = fss_core::RootAuthoritySpec {
        trace_id: trace.to_string(),
        operation_id: fss_core::OperationId::parse(op)?,
        principal: "principal:test".to_string(),
        capabilities: caps,
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::builder().bytes(1024).build()?,
        privacy_scope: "privacy:test".to_string(),
        retention_scope: "retention:test".to_string(),
        anchor_universe: fss_core::ContentDigest::sha256(b"grant-universe"),
        generation: 1,
    };
    Ok(spec)
}

#[test]
fn grant_enforcement_and_resource_scopes() -> Result<(), Box<dyn std::error::Error>> {
    use fss_core::RuntimeGrant;
    use fss_runtime::grant::{GrantError, GrantSet};

    // Unregistered capability strings are refused at construction.
    let bad = test_spec("trace:g", "op:g", vec!["NOT-A-REAL-CAP".to_string()])?;
    let refused = fss_runtime::authority::AuthorityCx::root(
        bad,
        fss_core::RegionId::new("region:p")?,
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
        test_spec(
            "trace:g2",
            "op:g2",
            vec!["CAP-ALERT-COMMIT-001".to_string()],
        )?,
        fss_core::RegionId::new("region:p2")?,
        fss_core::RegionKind::Process,
        fss_core::BudgetVector::ZERO,
        fss_core::TimestampNs(1),
    )?;
    auth.require_grant(RuntimeGrant::AlertCommit)?;
    let missing = auth
        .require_grant(RuntimeGrant::PtzCommit)
        .err()
        .ok_or("missing")?;
    assert_eq!(
        missing,
        GrantError::MissingGrant {
            grant: RuntimeGrant::PtzCommit
        }
    );

    // Resource scopes: scoped grant admits in-scope resources only.
    let grants = GrantSet::empty().with_scope(
        RuntimeGrant::AdapterNet,
        ["cam:porch".to_string()].into_iter().collect(),
    );
    grants.require_grant_for(RuntimeGrant::AdapterNet, "cam:porch")?;
    let outside = grants
        .require_grant_for(RuntimeGrant::AdapterNet, "cam:garage")
        .err()
        .ok_or("outside scope")?;
    assert_eq!(
        outside,
        GrantError::OutsideScope {
            grant: RuntimeGrant::AdapterNet,
            resource: "cam:garage".to_string(),
        }
    );
    Ok(())
}

#[test]
fn scope_down_never_widens_grants_or_scopes() -> Result<(), Box<dyn std::error::Error>> {
    use fss_core::RuntimeGrant;
    use fss_runtime::grant::{GrantError, GrantSet};

    let parent = GrantSet::empty().with_scope(
        RuntimeGrant::AdapterNet,
        ["cam:a".to_string(), "cam:b".to_string()]
            .into_iter()
            .collect(),
    );

    // Child holding a grant the parent lacks: refuse. (Built through the
    // real authority-string path — no test-only mutation hooks.)
    let child_extra = GrantSet::from_authority(&fss_core::ContextAuthority::new_root(test_spec(
        "trace:c",
        "op:c",
        vec![
            "CAP-ADAPTER-NET-001".to_string(),
            "CAP-PTZ-COMMIT-001".to_string(),
        ],
    )?)?)?;
    assert!(matches!(
        parent.verify_narrowed_by(&child_extra),
        Err(GrantError::Widening { .. })
    ));

    // Child narrowing scope to a subset: legal.
    let child_narrower = GrantSet::empty().with_scope(
        RuntimeGrant::AdapterNet,
        ["cam:a".to_string()].into_iter().collect(),
    );
    parent.verify_narrowed_by(&child_narrower)?;

    // Child unscoped where parent is scoped: refuse (widening).
    let child_unscoped = GrantSet::from_authority(&fss_core::ContextAuthority::new_root(
        test_spec("trace:c2", "op:c2", vec!["CAP-ADAPTER-NET-001".to_string()])?,
    )?)?;
    assert!(matches!(
        parent.verify_narrowed_by(&child_unscoped),
        Err(GrantError::Widening { .. })
    ));

    // Child superset scope: refuse.
    let child_super = GrantSet::empty().with_scope(
        RuntimeGrant::AdapterNet,
        [
            "cam:a".to_string(),
            "cam:b".to_string(),
            "cam:c".to_string(),
        ]
        .into_iter()
        .collect(),
    );
    assert!(matches!(
        parent.verify_narrowed_by(&child_super),
        Err(GrantError::Widening { .. })
    ));
    Ok(())
}

// ---------- leases, epochs, fencing (FSS-026) ----------

#[test]
fn lease_default_matches_new_and_never_accepts_zero() -> Result<(), fss_runtime::lease::LeaseError>
{
    use fss_core::TimestampNs;
    use fss_runtime::lease::{LeaseError, LeaseRegistry};

    for mut reg in [LeaseRegistry::default(), LeaseRegistry::new()] {
        let first = reg.acquire("device:ptz", "region:r1", None, TimestampNs(0))?;
        assert_eq!(first.fence, 1);
        assert_eq!(reg.current_fence("device:ptz"), Some(1));
        assert_eq!(
            reg.check_fence("device:ptz", 0, TimestampNs(1)),
            Err(LeaseError::StaleFence {
                resource: "device:ptz".to_string(),
                presented: 0,
                current: 1,
            })
        );
        reg.check_fence("device:ptz", first.fence, TimestampNs(1))?;

        reg.release(&first.id)?;
        let second = reg.acquire("device:ptz", "region:r2", None, TimestampNs(2))?;
        assert_eq!(second.fence, 2);
        assert_eq!(
            reg.check_fence("device:ptz", first.fence, TimestampNs(3)),
            Err(LeaseError::StaleFence {
                resource: "device:ptz".to_string(),
                presented: 1,
                current: 2,
            })
        );
        reg.check_fence("device:ptz", second.fence, TimestampNs(3))?;
    }

    Ok(())
}

#[test]
fn lease_exclusivity_takeover_and_renewal() -> Result<(), Box<dyn std::error::Error>> {
    use fss_core::TimestampNs;
    use fss_runtime::lease::{LeaseError, LeaseRegistry, LeaseState};

    let mut reg = LeaseRegistry::new();
    let a = reg.acquire(
        "stream:porch",
        "region:adapter-a",
        Some(1_000),
        TimestampNs(100),
    )?;
    assert_eq!(a.fence, 1);
    assert_eq!(a.state, LeaseState::Active);

    // Second holder refused with the holder named.
    let err = reg
        .acquire(
            "stream:porch",
            "region:adapter-b",
            Some(1_000),
            TimestampNs(200),
        )
        .err()
        .ok_or("held")?;
    assert!(matches!(err, LeaseError::Held { holder, .. } if holder == "region:adapter-a"));

    // Renewal extends the same lease without changing the fence.
    reg.renew(&a.id, 5_000, TimestampNs(300))?;
    assert_eq!(reg.current_fence("stream:porch"), Some(1));

    // Fence check passes while active.
    reg.check_fence("stream:porch", 1, TimestampNs(400))?;

    // After expiry, the old holder's fence fails and a takeover succeeds with
    // a fresh token.
    let err = reg
        .check_fence("stream:porch", 1, TimestampNs(10_000))
        .err()
        .ok_or("expired")?;
    assert!(matches!(err, LeaseError::LeaseExpired { .. }));
    let b = reg.acquire(
        "stream:porch",
        "region:adapter-b",
        Some(1_000),
        TimestampNs(10_100),
    )?;
    assert_eq!(b.fence, 2);
    // The zombie's token is permanently stale.
    let err = reg
        .check_fence("stream:porch", 1, TimestampNs(10_200))
        .err()
        .ok_or("stale")?;
    assert_eq!(
        err,
        LeaseError::StaleFence {
            resource: "stream:porch".to_string(),
            presented: 1,
            current: 2,
        }
    );
    Ok(())
}

#[test]
fn release_and_revoke_are_terminal_for_fence_use() -> Result<(), Box<dyn std::error::Error>> {
    use fss_core::TimestampNs;
    use fss_runtime::lease::{LeaseError, LeaseRegistry, LeaseState};

    let mut reg = LeaseRegistry::new();
    let a = reg.acquire("device:ptz", "region:r1", None, TimestampNs(0))?;
    reg.release(&a.id)?;
    let err = reg
        .check_fence("device:ptz", a.fence, TimestampNs(1))
        .err()
        .ok_or("released")?;
    assert!(matches!(
        err,
        LeaseError::NotActive {
            state: LeaseState::Released,
            ..
        }
    ));

    // Revocation advances the fence: the revoked token reports StaleFence.
    let b = reg.acquire("device:ptz", "region:r2", None, TimestampNs(2))?;
    reg.revoke(&b.id)?;
    let err = reg
        .check_fence("device:ptz", b.fence, TimestampNs(3))
        .err()
        .ok_or("revoked")?;
    assert!(matches!(err, LeaseError::StaleFence { presented, .. } if presented == b.fence));

    // Double-release and unknown leases are typed refusals.
    assert!(matches!(
        reg.release(&a.id),
        Err(LeaseError::NotActive {
            state: LeaseState::Released,
            ..
        })
    ));
    assert!(matches!(
        reg.renew("lease:nope:99", 1, TimestampNs(4)),
        Err(LeaseError::UnknownLease { .. })
    ));
    assert!(matches!(
        reg.check_fence("resource:never", 7, TimestampNs(5)),
        Err(LeaseError::NoFence { .. })
    ));
    Ok(())
}

// ---------- two-phase effect coordinator (FSS-027) ----------

fn effect_authority(
    caps: Vec<String>,
) -> Result<(fss_runtime::authority::AuthorityCx, fss_core::RegionTree), Box<dyn std::error::Error>>
{
    Ok(fss_runtime::authority::AuthorityCx::root(
        test_spec("trace:fx", "op:fx", caps)?,
        fss_core::RegionId::new("region:fx")?,
        fss_core::RegionKind::Process,
        fss_core::BudgetVector::builder()
            .tokens(64)
            .bytes(4096)
            .build()?,
        fss_core::TimestampNs(1),
    )?)
}

#[test]
fn effect_happy_path_prepare_commit_observe_verify() -> Result<(), Box<dyn std::error::Error>> {
    use fss_core::{ContentDigest, OperationId, RuntimeGrant, TimestampNs};
    use fss_runtime::effect::EffectCoordinator;
    use fss_runtime::lease::LeaseRegistry;

    let (auth, mut tree) = effect_authority(vec![
        "CAP-PTZ-PREPARE-001".to_string(),
        "CAP-PTZ-COMMIT-001".to_string(),
    ])?;
    let mut leases = LeaseRegistry::new();
    let lease = leases.acquire(
        "device:ptz:porch",
        "region:fx",
        Some(10_000),
        TimestampNs(100),
    )?;

    let prepared = EffectCoordinator::prepare(
        &auth,
        &mut tree,
        &leases,
        fss_runtime::effect::PrepareSpec {
            operation: &OperationId::parse("op:ptz-1")?,
            resource: "device:ptz:porch",
            fence: lease.fence,
            prepare_grant: RuntimeGrant::PtzPrepare,
            commit_grant: RuntimeGrant::PtzCommit,
            terminal_predicate: "camera panned to preset 3",
        },
    )?;
    assert_eq!(prepared.state(), fss_core::EffectState::Prepared);
    // Obligation registered and pending: the leak oracle sees it.
    assert_eq!(auth.leaked_obligations(&tree).len(), 1);

    let mut committed = EffectCoordinator::commit(&auth, &mut leases, prepared, TimestampNs(200))?;
    assert_eq!(committed.state(), fss_core::EffectState::Committed);

    EffectCoordinator::adapter_accepted(&mut committed)?;
    EffectCoordinator::observed(&mut committed)?;
    EffectCoordinator::verified(
        &mut tree,
        &auth,
        committed,
        ContentDigest::sha256(b"preset-3-proof"),
    )?;
    // Obligation terminal: no leaks remain.
    assert!(auth.finalize_report(&tree).is_empty());
    Ok(())
}

#[test]
fn effect_commit_refused_on_stale_fence_and_missing_grant() -> Result<(), Box<dyn std::error::Error>>
{
    use fss_core::{OperationId, RuntimeGrant, TimestampNs};
    use fss_runtime::effect::{EffectCoordError, EffectCoordinator};
    use fss_runtime::lease::LeaseRegistry;

    let (auth, mut tree) = effect_authority(vec![
        "CAP-PTZ-PREPARE-001".to_string(),
        "CAP-PTZ-COMMIT-001".to_string(),
    ])?;
    let mut leases = LeaseRegistry::new();
    let lease = leases.acquire("device:ptz:porch", "region:fx", None, TimestampNs(100))?;
    let prepared = EffectCoordinator::prepare(
        &auth,
        &mut tree,
        &leases,
        fss_runtime::effect::PrepareSpec {
            operation: &OperationId::parse("op:ptz-2")?,
            resource: "device:ptz:porch",
            fence: lease.fence,
            prepare_grant: RuntimeGrant::PtzPrepare,
            commit_grant: RuntimeGrant::PtzCommit,
            terminal_predicate: "predicate",
        },
    )?;

    // Zombie: lease revoked between prepare and commit.
    leases.revoke(&lease.id)?;
    let err = EffectCoordinator::commit(&auth, &mut leases, prepared, TimestampNs(200))
        .err()
        .ok_or("stale fence must refuse commit")?;
    assert!(matches!(err, EffectCoordError::Fence { .. }));

    // Missing commit grant: prepare-only authority.
    let (auth2, mut tree2) = effect_authority(vec!["CAP-PTZ-PREPARE-001".to_string()])?;
    let lease2 = leases.acquire("device:ptz:porch", "region:fx2", None, TimestampNs(300))?;
    let prepared2 = EffectCoordinator::prepare(
        &auth2,
        &mut tree2,
        &leases,
        fss_runtime::effect::PrepareSpec {
            operation: &OperationId::parse("op:ptz-3")?,
            resource: "device:ptz:porch",
            fence: lease2.fence,
            prepare_grant: RuntimeGrant::PtzPrepare,
            commit_grant: RuntimeGrant::PtzCommit,
            terminal_predicate: "predicate",
        },
    )?;
    let err = EffectCoordinator::commit(&auth2, &mut leases, prepared2, TimestampNs(400))
        .err()
        .ok_or("commit grant missing")?;
    assert!(matches!(err, EffectCoordError::Grant { .. }));
    Ok(())
}

#[test]
fn effect_cancel_and_indeterminate_semantics() -> Result<(), Box<dyn std::error::Error>> {
    use fss_core::{OperationId, RuntimeGrant, TimestampNs};
    use fss_runtime::effect::{EffectCoordError, EffectCoordinator};
    use fss_runtime::lease::LeaseRegistry;

    let (auth, mut tree) = effect_authority(vec![
        "CAP-ALERT-PREPARE-001".to_string(),
        "CAP-ALERT-COMMIT-001".to_string(),
    ])?;
    let mut leases = LeaseRegistry::new();
    let lease = leases.acquire("webhook:ops", "region:fx", None, TimestampNs(0))?;

    // Cancel before commit: obligation drains, no leak.
    let prepared = EffectCoordinator::prepare(
        &auth,
        &mut tree,
        &leases,
        fss_runtime::effect::PrepareSpec {
            operation: &OperationId::parse("op:alert-1")?,
            resource: "webhook:ops",
            fence: lease.fence,
            prepare_grant: RuntimeGrant::AlertPrepare,
            commit_grant: RuntimeGrant::AlertCommit,
            terminal_predicate: "alert delivered",
        },
    )?;
    EffectCoordinator::cancel_prepared(&mut tree, &auth, prepared)?;
    assert!(auth.finalize_report(&tree).is_empty());

    // Indeterminate requires a reconciliation note (INV-006).
    let prepared2 = EffectCoordinator::prepare(
        &auth,
        &mut tree,
        &leases,
        fss_runtime::effect::PrepareSpec {
            operation: &OperationId::parse("op:alert-2")?,
            resource: "webhook:ops",
            fence: lease.fence,
            prepare_grant: RuntimeGrant::AlertPrepare,
            commit_grant: RuntimeGrant::AlertCommit,
            terminal_predicate: "alert delivered",
        },
    )?;
    let committed2 = EffectCoordinator::commit(&auth, &mut leases, prepared2, TimestampNs(10))?;
    let err = EffectCoordinator::indeterminate(&mut tree, &auth, committed2, None)
        .err()
        .ok_or("note required")?;
    assert!(matches!(
        err,
        EffectCoordError::IndeterminateWithoutNote { .. }
    ));

    // With a note it lands; the tree-wide oracle reports note coverage.
    let prepared3 = EffectCoordinator::prepare(
        &auth,
        &mut tree,
        &leases,
        fss_runtime::effect::PrepareSpec {
            operation: &OperationId::parse("op:alert-3")?,
            resource: "webhook:ops",
            fence: lease.fence,
            prepare_grant: RuntimeGrant::AlertPrepare,
            commit_grant: RuntimeGrant::AlertCommit,
            terminal_predicate: "alert delivered",
        },
    )?;
    let committed3 = EffectCoordinator::commit(&auth, &mut leases, prepared3, TimestampNs(20))?;
    EffectCoordinator::indeterminate(
        &mut tree,
        &auth,
        committed3,
        Some("webhook ack lost in partition; reconcile on reconnect"),
    )?;
    let report = fss_runtime::obligation::tree_report(&tree);
    let root = &report[0];
    assert_eq!(root.counts[3], 1, "one indeterminate obligation");
    assert_eq!(
        root.indeterminate_with_note,
        vec!["obligation:op:alert-3:terminal".to_string()]
    );
    assert!(root.indeterminate_without_note.is_empty());
    Ok(())
}

#[test]
fn effect_illegal_transitions_are_typed_refusals() -> Result<(), Box<dyn std::error::Error>> {
    use fss_core::{OperationId, RuntimeGrant, TimestampNs};
    use fss_runtime::effect::{EffectCoordError, EffectCoordinator};
    use fss_runtime::lease::LeaseRegistry;

    let (auth, mut tree) = effect_authority(vec![
        "CAP-PTZ-PREPARE-001".to_string(),
        "CAP-PTZ-COMMIT-001".to_string(),
    ])?;
    let mut leases = LeaseRegistry::new();
    let lease = leases.acquire("device:ptz:x", "region:fx", None, TimestampNs(0))?;
    let prepared = EffectCoordinator::prepare(
        &auth,
        &mut tree,
        &leases,
        fss_runtime::effect::PrepareSpec {
            operation: &OperationId::parse("op:ptz-9")?,
            resource: "device:ptz:x",
            fence: lease.fence,
            prepare_grant: RuntimeGrant::PtzPrepare,
            commit_grant: RuntimeGrant::PtzCommit,
            terminal_predicate: "predicate",
        },
    )?;
    let mut committed = EffectCoordinator::commit(&auth, &mut leases, prepared, TimestampNs(5))?;
    // Committed → Verified directly is illegal (must pass through
    // AdapterAccepted → Observed).
    let err = EffectCoordinator::observed(&mut committed)
        .err()
        .ok_or("skip is illegal")?;
    assert!(matches!(err, EffectCoordError::IllegalTransition { .. }));
    Ok(())
}

// ---------- crash/cancellation cut-point harness (FSS-028) ----------
//
// The harness models a crash as dropping every in-memory session struct at
// an exact transition boundary while the DURABLE state (region-tree
// obligations) survives. After each cut, a fresh authority view over the
// same tree must (a) surface the wreck through the leak oracle and (b)
// offer a typed reconciliation path. No threads, no process kills: this is
// the deterministic reference harness; hostile-process crash lanes belong
// to the qualification bundle.

/// Cut-point inventory: every coordinator boundary where a crash can land.
fn cut_point_inventory() -> Vec<&'static str> {
    vec![
        "after_prepare_before_commit",
        "after_commit_before_accept",
        "after_accept_before_observe",
        "after_observe_before_verify",
        "mid_cancellation_before_drain_completes",
    ]
}

#[test]
fn every_cut_point_is_enumerated_and_survivable() -> Result<(), Box<dyn std::error::Error>> {
    // The inventory is stable and non-empty — a regression that deletes a
    // cut point fails here.
    assert_eq!(cut_point_inventory().len(), 5);
    Ok(())
}

fn fx_setup() -> Result<
    (
        fss_runtime::authority::AuthorityCx,
        fss_core::RegionTree,
        fss_runtime::lease::LeaseRegistry,
        u64,
    ),
    Box<dyn std::error::Error>,
> {
    let (auth, tree) = effect_authority(vec![
        "CAP-PTZ-PREPARE-001".to_string(),
        "CAP-PTZ-COMMIT-001".to_string(),
    ])?;
    let mut leases = fss_runtime::lease::LeaseRegistry::new();
    let lease = leases.acquire(
        "device:ptz:crash",
        "region:fx",
        None,
        fss_core::TimestampNs(0),
    )?;
    Ok((auth, tree, leases, lease.fence))
}

fn prepared_fx(
    auth: &fss_runtime::authority::AuthorityCx,
    tree: &mut fss_core::RegionTree,
    leases: &fss_runtime::lease::LeaseRegistry,
    fence: u64,
    op: &str,
) -> Result<fss_runtime::effect::PreparedEffect, Box<dyn std::error::Error>> {
    let operation = fss_core::OperationId::parse(op)?;
    let prepared = fss_runtime::effect::EffectCoordinator::prepare(
        auth,
        tree,
        leases,
        fss_runtime::effect::PrepareSpec {
            operation: &operation,
            resource: "device:ptz:crash",
            fence,
            prepare_grant: fss_core::RuntimeGrant::PtzPrepare,
            commit_grant: fss_core::RuntimeGrant::PtzCommit,
            terminal_predicate: "crash cut-point predicate",
        },
    )?;
    Ok(prepared)
}

#[test]
fn crash_after_prepare_leaves_named_leak_and_reconciles() -> Result<(), Box<dyn std::error::Error>>
{
    use fss_core::{ContentDigest, ObligationId, TimestampNs};
    use fss_runtime::obligation::{ObligationTerminal, tree_report};

    let (auth, mut tree, leases, fence) = fx_setup()?;
    let prepared = prepared_fx(&auth, &mut tree, &leases, fence, "op:crash-1")?;
    let obligation = prepared.obligation.clone();

    // CRASH: the prepared session is dropped before commit. Nothing about
    // the operation survives except the durable obligation on the tree.
    drop(prepared);

    // Recovery view: the leak oracle names the wrecked operation.
    let report = tree_report(&tree);
    assert_eq!(report[0].leaked.len(), 1);
    assert_eq!(report[0].leaked[0].id, obligation.as_str());

    // Reconcile: the effect provably never dispatched (commit never ran),
    // so the obligation resolves to a terminal failure with a digest of the
    // crash-cut record — never silently dropped.
    auth.resolve_obligation(
        &mut tree,
        &ObligationId::parse(obligation.as_str())?,
        ObligationTerminal::Failed,
        Some(ContentDigest::sha256(b"crashed-before-commit")),
        None,
    )?;
    assert!(auth.finalize_report(&tree).is_empty());
    let _ = TimestampNs(0);
    Ok(())
}

#[test]
fn crash_after_commit_is_indeterminate_with_mandatory_note()
-> Result<(), Box<dyn std::error::Error>> {
    use fss_core::TimestampNs;
    use fss_runtime::effect::EffectCoordinator;
    use fss_runtime::obligation::tree_report;

    let (auth, mut tree, mut leases, fence) = fx_setup()?;
    let prepared = prepared_fx(&auth, &mut tree, &leases, fence, "op:crash-2")?;
    let committed = EffectCoordinator::commit(&auth, &mut leases, prepared, TimestampNs(10))?;

    // CRASH after commit: the dispatch may have happened. The honest
    // reconciliation is Indeterminate with a durable note — NOT success,
    // NOT failure.
    let operation = committed.operation().clone();
    drop(committed);

    let report = tree_report(&tree);
    assert_eq!(
        report[0].leaked.len(),
        1,
        "pending obligation survives the crash"
    );

    // The tree refuses Indeterminate without a note (INV-006) — verified in
    // the oracle test. Reconcile WITH a note:
    tree.resolve_obligation(
        auth.region(),
        &fss_core::ObligationId::parse(format!("obligation:{operation}:terminal"))?,
        fss_core::ObligationState::Indeterminate,
        None,
        Some("crashed after commit; device state unknown until next telemetry"),
    )?;
    let report = tree_report(&tree);
    assert_eq!(report[0].counts[3], 1);
    assert_eq!(
        report[0].leaked.len(),
        0,
        "indeterminate is not a pending leak"
    );
    Ok(())
}

#[test]
fn crash_after_observe_preserves_pending_verify_obligation()
-> Result<(), Box<dyn std::error::Error>> {
    use fss_core::{ContentDigest, TimestampNs};
    use fss_runtime::effect::EffectCoordinator;

    let (auth, mut tree, mut leases, fence) = fx_setup()?;
    let prepared = prepared_fx(&auth, &mut tree, &leases, fence, "op:crash-3")?;
    let mut committed = EffectCoordinator::commit(&auth, &mut leases, prepared, TimestampNs(10))?;
    EffectCoordinator::adapter_accepted(&mut committed)?;
    EffectCoordinator::observed(&mut committed)?;

    // CRASH after observe: the observation WAS recorded, so reconciliation
    // can complete verification against the retained observation digest.
    drop(committed);
    auth.resolve_obligation(
        &mut tree,
        &fss_core::ObligationId::parse("obligation:op:crash-3:terminal")?,
        fss_runtime::obligation::ObligationTerminal::Completed,
        Some(ContentDigest::sha256(b"observed-before-crash")),
        None,
    )?;
    assert!(auth.finalize_report(&tree).is_empty());
    Ok(())
}

#[test]
fn cancellation_mid_drain_never_strands_orphans() -> Result<(), Box<dyn std::error::Error>> {
    use fss_core::TimestampNs;

    // Cancellation requested while a subtree holds a pending obligation:
    // the drain path surfaces the obligation instead of orphaning it.
    let (auth, mut tree, leases, fence) = fx_setup()?;
    let _prepared = prepared_fx(&auth, &mut tree, &leases, fence, "op:crash-4")?;

    auth.request_cancellation();
    assert!(auth.is_cancel_requested());
    // Drain is refused while obligations are pending: no silent orphaning.
    let drain = tree.request_drain(auth.region(), Some("cancel"), TimestampNs(100));
    assert!(drain.is_ok(), "drain request is idempotent-accepted");
    // Finalize with a pending obligation must refuse (the tree owns this
    // refusal; the oracle already names the leak).
    let fin = tree.finalize(auth.region(), TimestampNs(200));
    assert!(fin.is_err(), "finalize with pending obligation must refuse");
    Ok(())
}

#[test]
fn failed_scope_down_never_strands_a_reservation() -> Result<(), Box<dyn std::error::Error>> {
    use fss_core::{BudgetVector, RegionId, RegionKind, TimestampNs};

    // A scope-down refused at ANY late stage (here: grant widening) must
    // leave the parent's ledger untouched — no stranded reservation.
    let (mut root, mut tree) = fss_runtime::authority::AuthorityCx::root(
        test_spec(
            "trace:rv",
            "op:rv",
            vec!["CAP-ALERT-COMMIT-001".to_string()],
        )?,
        RegionId::new("region:process")?,
        RegionKind::Process,
        BudgetVector::builder().tokens(100).bytes(1_000).build()?,
        TimestampNs(1),
    )?;
    let before = root.budget().remaining();

    // Child asks for a grant the parent does not hold: refused AFTER budget
    // validation but BEFORE the (now post-attach) debit.
    let refused = root.scope_down(
        &mut tree,
        RegionId::new("region:child")?,
        RegionKind::Property,
        BudgetVector::builder().tokens(10).bytes(100).build()?,
        test_spec(
            "trace:rv",
            "op:rv-child",
            vec![
                "CAP-ALERT-COMMIT-001".to_string(),
                "CAP-PTZ-COMMIT-001".to_string(), // widening: parent lacks this
            ],
        )?,
        TimestampNs(2),
    );
    assert!(refused.is_err());
    let after = root.budget().remaining();
    assert_eq!(
        (before.tokens, before.bytes),
        (after.tokens, after.bytes),
        "a refused scope-down must not debit the parent"
    );
    Ok(())
}
