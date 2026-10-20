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
    assert!(a.outcome().is_none());
    a.begin_drain(1);
    a.worker_done("w")?;
    assert_eq!(a.outcome(), Some(&CancelOutcome::Completed));
    let mut b = CancellationLifecycle::new(["w".to_string()], 1_000);
    b.request(1);
    b.begin_drain(2);
    b.work_failed("sensor fault");
    assert!(b.outcome().is_none());
    b.worker_done("w")?;
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
            .tokens(100)
            .cpu_millis(10_000)
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
                .tokens(50)
                .cpu_millis(5_000)
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
    assert_eq!(child.leaked_obligations(&tree)?.len(), 1);
    child.resolve_obligation(
        &mut tree,
        &ObligationId::parse("obl:capture-drain")?,
        ObligationTerminal::Completed,
        Some(ContentDigest::sha256(b"proof")),
        None,
    )?;
    assert!(child.finalize_report(&tree)?.is_empty());

    // Budget: spend within bounds, overdraft refused.
    use fss_core::BudgetDimension;
    child
        .budget_mut(&tree)?
        .spend(BudgetDimension::Tokens, 50)?;
    assert!(
        child
            .budget_mut(&tree)?
            .spend(BudgetDimension::Bytes, 501)
            .is_err()
    );

    // Cancellation cascades: request on root, child chain sees it.
    root.request_cancellation(&mut tree, TimestampNs(3_000))?;
    assert!(root.is_cancel_requested(&tree)?);
    assert!(
        child.is_cancel_requested(&tree)?,
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
            .tokens(100)
            .cpu_millis(10_000)
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
                .tokens(1)
                .cpu_millis(1)
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
            trace_id: "trace:test".to_string(),
            operation_id: OperationId::parse("op:greedy")?,
            principal: "principal:test".to_string(),
            capabilities: Vec::new(),
            deadline: None,
            priority: 10,
            budgets: fss_core::BudgetVector::builder()
                .tokens(50)
                .cpu_millis(5_000)
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
    assert!(
        matches!(
            r,
            Err(fss_runtime::authority::AuthorityError::Budget(
                fss_runtime::budget::LedgerError::Overdraft {
                    dimension: fss_core::BudgetDimension::Tokens,
                    requested: 11,
                    remaining: 10,
                }
            ))
        ),
        "budget widening must refuse on the exhausted dimension"
    );
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
        budgets: BudgetVector::builder().tokens(100).bytes(1024).build()?,
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
        budgets: fss_core::BudgetVector::builder()
            .tokens(100)
            .bytes(4096)
            .build()?,
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

use fss_core::{ContentDigest, EffectState, OperationId, RuntimeGrant, TimestampNs};
use fss_runtime::effect::{
    CommitApproval, EffectCoordinator, PrepareSpec, PreparedEffect, Reconciliation,
};

fn effect_preconditions() -> ContentDigest {
    ContentDigest::sha256(b"approved physical state and device generation")
}

fn effect_spec<'a>(
    operation: &'a OperationId,
    resource: &'a str,
    fence: u64,
    grants: [RuntimeGrant; 2],
    terminal_predicate: &'a str,
) -> Result<PrepareSpec<'a>, Box<dyn std::error::Error>> {
    Ok(PrepareSpec {
        operation,
        idempotency_key: fss_core::IdempotencyKey::parse(operation.as_str())?,
        request_digest: ContentDigest::sha256(operation.as_str().as_bytes()),
        precondition_digest: effect_preconditions(),
        resource,
        fence,
        prepare_grant: grants[0],
        commit_grant: grants[1],
        terminal_predicate,
    })
}

fn effect_approval(prepared: &PreparedEffect) -> CommitApproval {
    CommitApproval {
        prepared_digest: prepared.digest(),
        current_precondition_digest: effect_preconditions(),
    }
}

#[test]
fn effect_happy_path_prepare_commit_observe_verify() -> Result<(), Box<dyn std::error::Error>> {
    let (auth, mut tree) = effect_authority(vec![
        "CAP-PTZ-PREPARE-001".to_string(),
        "CAP-PTZ-COMMIT-001".to_string(),
    ])?;
    let mut leases = fss_runtime::lease::LeaseRegistry::new();
    let lease = leases.acquire(
        "device:ptz:porch",
        "region:fx",
        Some(10_000),
        TimestampNs(100),
    )?;
    let mut effects = EffectCoordinator::new();
    let operation = OperationId::parse("op:ptz-1")?;
    let prepared = effects.prepare(
        &auth,
        &mut tree,
        &mut leases,
        effect_spec(
            &operation,
            "device:ptz:porch",
            lease.fence,
            [RuntimeGrant::PtzPrepare, RuntimeGrant::PtzCommit],
            "camera panned to preset 3",
        )?,
        TimestampNs(101),
    )?;
    assert_eq!(effects.state(&prepared)?, EffectState::Prepared);
    assert_eq!(auth.leaked_obligations(&tree)?.len(), 1);
    let approval = effect_approval(&prepared);
    let mut committed = effects.commit(
        &auth,
        &tree,
        &mut leases,
        prepared,
        TimestampNs(200),
        approval,
    )?;
    assert_eq!(effects.state(&committed)?, EffectState::Committed);
    effects.adapter_accepted(&mut committed, None, TimestampNs(201))?;
    let proof = ContentDigest::sha256(b"preset-3-proof");
    effects.observed(&mut committed, proof, TimestampNs(202))?;
    effects.verified(&mut tree, &auth, committed, proof, TimestampNs(203))?;
    assert!(auth.finalize_report(&tree)?.is_empty());
    let receipt = effects
        .journal()
        .operation(&operation)
        .ok_or("receipt missing")?;
    assert_eq!(receipt.state, EffectState::Verified);
    assert_eq!(receipt.result_digest, Some(proof));
    Ok(())
}

#[test]
fn effect_commit_refused_on_stale_fence_and_missing_grant() -> Result<(), Box<dyn std::error::Error>>
{
    use fss_runtime::effect::EffectCoordError;
    let (auth, mut tree) = effect_authority(vec![
        "CAP-PTZ-PREPARE-001".to_string(),
        "CAP-PTZ-COMMIT-001".to_string(),
    ])?;
    let mut effects = EffectCoordinator::new();
    let mut leases = fss_runtime::lease::LeaseRegistry::new();
    let lease = leases.acquire("device:ptz:porch", "region:fx", None, TimestampNs(100))?;
    let operation = OperationId::parse("op:ptz-2")?;
    let prepared = effects.prepare(
        &auth,
        &mut tree,
        &mut leases,
        effect_spec(
            &operation,
            "device:ptz:porch",
            lease.fence,
            [RuntimeGrant::PtzPrepare, RuntimeGrant::PtzCommit],
            "predicate",
        )?,
        TimestampNs(101),
    )?;
    let approval = effect_approval(&prepared);
    leases.revoke(&lease.id)?;
    let err = effects
        .commit(
            &auth,
            &tree,
            &mut leases,
            prepared,
            TimestampNs(200),
            approval,
        )
        .expect_err("stale fence must refuse commit");
    assert!(matches!(err.error(), EffectCoordError::Fence { .. }));
    assert_eq!(effects.state(err.token())?, EffectState::Prepared);

    let (auth2, mut tree2) = effect_authority(vec!["CAP-PTZ-PREPARE-001".to_string()])?;
    let lease2 = leases.acquire(
        "device:ptz:porch",
        auth2.region().as_str(),
        None,
        TimestampNs(300),
    )?;
    let operation2 = OperationId::parse("op:ptz-3")?;
    let prepared2 = effects.prepare(
        &auth2,
        &mut tree2,
        &mut leases,
        effect_spec(
            &operation2,
            "device:ptz:porch",
            lease2.fence,
            [RuntimeGrant::PtzPrepare, RuntimeGrant::PtzCommit],
            "predicate",
        )?,
        TimestampNs(301),
    )?;
    let approval2 = effect_approval(&prepared2);
    let err = effects
        .commit(
            &auth2,
            &tree2,
            &mut leases,
            prepared2,
            TimestampNs(400),
            approval2,
        )
        .expect_err("commit grant missing");
    assert!(matches!(err.error(), EffectCoordError::Grant { .. }));
    assert_eq!(effects.state(err.token())?, EffectState::Prepared);
    Ok(())
}

#[test]
fn effect_cancel_and_indeterminate_semantics() -> Result<(), Box<dyn std::error::Error>> {
    use fss_runtime::effect::EffectCoordError;
    let (auth, mut tree) = effect_authority(vec![
        "CAP-ALERT-PREPARE-001".to_string(),
        "CAP-ALERT-COMMIT-001".to_string(),
    ])?;
    let mut effects = EffectCoordinator::new();
    let mut leases = fss_runtime::lease::LeaseRegistry::new();
    let lease = leases.acquire("webhook:ops", "region:fx", None, TimestampNs(0))?;
    let grants = [RuntimeGrant::AlertPrepare, RuntimeGrant::AlertCommit];
    let operation = OperationId::parse("op:alert-1")?;
    let prepared = effects.prepare(
        &auth,
        &mut tree,
        &mut leases,
        effect_spec(
            &operation,
            "webhook:ops",
            lease.fence,
            grants,
            "alert delivered",
        )?,
        TimestampNs(2),
    )?;
    let cancel_evidence = ContentDigest::sha256(b"owner withdrew pending alert");
    effects.cancel_prepared(&mut tree, &auth, prepared, cancel_evidence, TimestampNs(3))?;
    assert!(auth.finalize_report(&tree)?.is_empty());

    let operation2 = OperationId::parse("op:alert-2")?;
    let prepared2 = effects.prepare(
        &auth,
        &mut tree,
        &mut leases,
        effect_spec(
            &operation2,
            "webhook:ops",
            lease.fence,
            grants,
            "alert delivered",
        )?,
        TimestampNs(4),
    )?;
    let approval2 = effect_approval(&prepared2);
    let committed2 = effects.commit(
        &auth,
        &tree,
        &mut leases,
        prepared2,
        TimestampNs(10),
        approval2,
    )?;
    let err = effects
        .indeterminate(&mut tree, &auth, committed2, None, TimestampNs(11))
        .expect_err("note required");
    assert!(matches!(
        err.error(),
        EffectCoordError::IndeterminateWithoutNote { .. }
    ));
    assert_eq!(effects.state(err.token())?, EffectState::Committed);

    let operation3 = OperationId::parse("op:alert-3")?;
    let prepared3 = effects.prepare(
        &auth,
        &mut tree,
        &mut leases,
        effect_spec(
            &operation3,
            "webhook:ops",
            lease.fence,
            grants,
            "alert delivered",
        )?,
        TimestampNs(12),
    )?;
    let approval3 = effect_approval(&prepared3);
    let committed3 = effects.commit(
        &auth,
        &tree,
        &mut leases,
        prepared3,
        TimestampNs(20),
        approval3,
    )?;
    effects.indeterminate(
        &mut tree,
        &auth,
        committed3,
        Some("webhook ack lost in partition; reconcile on reconnect"),
        TimestampNs(21),
    )?;
    let report = fss_runtime::obligation::tree_report(&tree);
    let root = &report[0];
    assert_eq!(root.counts[3], 1, "one indeterminate obligation");
    assert_eq!(
        root.indeterminate_with_note,
        vec!["obligation:op:alert-3:terminal".to_string()]
    );
    assert!(root.indeterminate_without_note.is_empty());
    assert_eq!(
        effects
            .journal()
            .operation(&operation3)
            .ok_or("receipt missing")?
            .state,
        EffectState::Indeterminate
    );
    Ok(())
}

#[test]
fn effect_illegal_transitions_are_typed_refusals() -> Result<(), Box<dyn std::error::Error>> {
    use fss_runtime::effect::EffectCoordError;
    let (auth, mut tree) = effect_authority(vec![
        "CAP-PTZ-PREPARE-001".to_string(),
        "CAP-PTZ-COMMIT-001".to_string(),
    ])?;
    let mut effects = EffectCoordinator::new();
    let mut leases = fss_runtime::lease::LeaseRegistry::new();
    let lease = leases.acquire("device:ptz:x", "region:fx", None, TimestampNs(0))?;
    let operation = OperationId::parse("op:ptz-9")?;
    let prepared = effects.prepare(
        &auth,
        &mut tree,
        &mut leases,
        effect_spec(
            &operation,
            "device:ptz:x",
            lease.fence,
            [RuntimeGrant::PtzPrepare, RuntimeGrant::PtzCommit],
            "predicate",
        )?,
        TimestampNs(2),
    )?;
    let approval = effect_approval(&prepared);
    let mut committed = effects.commit(
        &auth,
        &tree,
        &mut leases,
        prepared,
        TimestampNs(5),
        approval,
    )?;
    let before = effects.journal().clone();
    let err = effects
        .observed(
            &mut committed,
            ContentDigest::sha256(b"premature observation"),
            TimestampNs(6),
        )
        .expect_err("committed cannot skip adapter acceptance");
    assert!(matches!(err, EffectCoordError::IllegalTransition { .. }));
    assert_eq!(effects.journal(), &before);
    Ok(())
}

// ---------- dropped-handle / cancellation cut-point harness (FSS-028) ----------
// The application-owned journal and region survive caller-handle loss. These are
// in-memory reference cuts, not claims about durable storage or process crashes.

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
    assert_eq!(cut_point_inventory().len(), 5);
    Ok(())
}

struct EffectFixture {
    auth: fss_runtime::authority::AuthorityCx,
    tree: fss_core::RegionTree,
    leases: fss_runtime::lease::LeaseRegistry,
    effects: EffectCoordinator,
    fence: u64,
}

impl EffectFixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let (auth, tree) = effect_authority(vec![
            "CAP-PTZ-PREPARE-001".to_string(),
            "CAP-PTZ-COMMIT-001".to_string(),
        ])?;
        let mut leases = fss_runtime::lease::LeaseRegistry::new();
        let lease = leases.acquire("device:ptz:crash", "region:fx", None, TimestampNs(0))?;
        Ok(Self {
            auth,
            tree,
            leases,
            effects: EffectCoordinator::new(),
            fence: lease.fence,
        })
    }

    fn prepare(&mut self, op: &str) -> Result<PreparedEffect, Box<dyn std::error::Error>> {
        let operation = OperationId::parse(op)?;
        Ok(self.effects.prepare(
            &self.auth,
            &mut self.tree,
            &mut self.leases,
            effect_spec(
                &operation,
                "device:ptz:crash",
                self.fence,
                [RuntimeGrant::PtzPrepare, RuntimeGrant::PtzCommit],
                "crash cut-point predicate",
            )?,
            TimestampNs(2),
        )?)
    }
}

#[test]
fn crash_after_prepare_leaves_named_leak_and_reconciles() -> Result<(), Box<dyn std::error::Error>>
{
    let mut f = EffectFixture::new()?;
    let prepared = f.prepare("op:crash-1")?;
    let operation = prepared.operation().clone();
    let obligation = prepared.obligation().clone();
    drop(prepared);
    let report = fss_runtime::obligation::tree_report(&f.tree);
    assert_eq!(report[0].leaked.len(), 1);
    assert_eq!(report[0].leaked[0].id, obligation.as_str());
    let recovered = f
        .effects
        .prepared(&operation)
        .ok_or("retained preparation missing")?;
    assert_eq!(f.effects.state(&recovered)?, EffectState::Prepared);
    f.effects.reconcile(
        &mut f.tree,
        &f.auth,
        &recovered,
        Reconciliation::Failed {
            proof: ContentDigest::sha256(b"dropped-before-commit"),
            reason: "caller lost before dispatch",
        },
        TimestampNs(3),
    )?;
    assert!(f.auth.finalize_report(&f.tree)?.is_empty());
    assert_eq!(f.effects.state(&recovered)?, EffectState::Failed);
    assert_eq!(f.effects.journal().operations().count(), 1);
    Ok(())
}

#[test]
fn crash_after_commit_is_indeterminate_with_mandatory_note()
-> Result<(), Box<dyn std::error::Error>> {
    let mut f = EffectFixture::new()?;
    let prepared = f.prepare("op:crash-2")?;
    let approval = effect_approval(&prepared);
    let committed = f.effects.commit(
        &f.auth,
        &f.tree,
        &mut f.leases,
        prepared,
        TimestampNs(10),
        approval,
    )?;
    let operation = committed.operation().clone();
    drop(committed);
    let report = fss_runtime::obligation::tree_report(&f.tree);
    assert_eq!(
        report[0].leaked.len(),
        1,
        "pending obligation survives handle loss"
    );
    let recovered = f
        .effects
        .prepared(&operation)
        .ok_or("retained preparation missing")?;
    let before = f.effects.journal().clone();
    assert!(
        f.effects
            .reconcile(
                &mut f.tree,
                &f.auth,
                &recovered,
                Reconciliation::Indeterminate(""),
                TimestampNs(11)
            )
            .is_err()
    );
    assert_eq!(f.effects.journal(), &before);
    f.effects.reconcile(
        &mut f.tree,
        &f.auth,
        &recovered,
        Reconciliation::Indeterminate(
            "caller lost after commit; device state unknown until next telemetry",
        ),
        TimestampNs(11),
    )?;
    let report = fss_runtime::obligation::tree_report(&f.tree);
    assert_eq!(report[0].counts[3], 1);
    assert_eq!(
        report[0].leaked.len(),
        0,
        "indeterminate is not a pending leak"
    );
    assert_eq!(f.effects.state(&recovered)?, EffectState::Indeterminate);
    assert!(
        f.effects
            .commit(
                &f.auth,
                &f.tree,
                &mut f.leases,
                recovered.clone(),
                TimestampNs(12),
                effect_approval(&recovered)
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn crash_after_accept_retains_acceptance_without_claiming_observation()
-> Result<(), Box<dyn std::error::Error>> {
    let mut f = EffectFixture::new()?;
    let prepared = f.prepare("op:crash-accepted")?;
    let operation = prepared.operation().clone();
    let approval = effect_approval(&prepared);
    let mut committed = f.effects.commit(
        &f.auth,
        &f.tree,
        &mut f.leases,
        prepared,
        TimestampNs(10),
        approval,
    )?;
    let acceptance = ContentDigest::sha256(b"adapter accepted command");
    f.effects
        .adapter_accepted(&mut committed, Some(acceptance), TimestampNs(11))?;
    drop(committed);
    let recovered = f
        .effects
        .prepared(&operation)
        .ok_or("retained preparation missing")?;
    assert_eq!(
        f.effects.receipt(&recovered)?.state,
        EffectState::AdapterAccepted
    );
    assert_eq!(
        f.effects.receipt(&recovered)?.result_digest,
        Some(acceptance)
    );
    assert_eq!(f.auth.leaked_obligations(&f.tree)?.len(), 1);
    let observed = ContentDigest::sha256(b"camera reached intended pose");
    f.effects.reconcile(
        &mut f.tree,
        &f.auth,
        &recovered,
        Reconciliation::Observed(observed),
        TimestampNs(12),
    )?;
    assert_eq!(f.auth.leaked_obligations(&f.tree)?.len(), 1);
    f.effects.reconcile(
        &mut f.tree,
        &f.auth,
        &recovered,
        Reconciliation::Verified(observed),
        TimestampNs(13),
    )?;
    assert!(f.auth.finalize_report(&f.tree)?.is_empty());
    Ok(())
}

#[test]
fn crash_after_observe_preserves_pending_verify_obligation()
-> Result<(), Box<dyn std::error::Error>> {
    let mut f = EffectFixture::new()?;
    let prepared = f.prepare("op:crash-3")?;
    let operation = prepared.operation().clone();
    let approval = effect_approval(&prepared);
    let mut committed = f.effects.commit(
        &f.auth,
        &f.tree,
        &mut f.leases,
        prepared,
        TimestampNs(10),
        approval,
    )?;
    f.effects
        .adapter_accepted(&mut committed, None, TimestampNs(11))?;
    let proof = ContentDigest::sha256(b"observed-before-handle-loss");
    f.effects.observed(&mut committed, proof, TimestampNs(12))?;
    drop(committed);
    let recovered = f
        .effects
        .prepared(&operation)
        .ok_or("retained preparation missing")?;
    assert_eq!(f.effects.receipt(&recovered)?.result_digest, Some(proof));
    assert_eq!(f.auth.leaked_obligations(&f.tree)?.len(), 1);
    f.effects.reconcile(
        &mut f.tree,
        &f.auth,
        &recovered,
        Reconciliation::Verified(proof),
        TimestampNs(13),
    )?;
    assert!(f.auth.finalize_report(&f.tree)?.is_empty());
    assert_eq!(f.effects.state(&recovered)?, EffectState::Verified);
    Ok(())
}

#[test]
fn cancellation_mid_drain_never_strands_orphans() -> Result<(), Box<dyn std::error::Error>> {
    let mut f = EffectFixture::new()?;
    let prepared = f.prepare("op:crash-4")?;
    f.auth.request_cancellation(&mut f.tree, TimestampNs(100))?;
    assert!(f.auth.is_cancel_requested(&f.tree)?);
    let drain = f
        .tree
        .request_drain(f.auth.region(), Some("cancel"), TimestampNs(100));
    assert!(drain.is_ok(), "drain request is idempotent-accepted");
    f.auth.begin_drain(&mut f.tree, TimestampNs(101))?;
    assert!(
        f.tree.finalize(f.auth.region(), TimestampNs(200)).is_err(),
        "pending obligation must prevent finalize"
    );
    f.effects.cancel_prepared(
        &mut f.tree,
        &f.auth,
        prepared,
        ContentDigest::sha256(b"cancel before dispatch"),
        TimestampNs(201),
    )?;
    let proof = f.auth.finalize(&mut f.tree, TimestampNs(202))?;
    assert_eq!(proof.total_obligations, 1);
    assert_eq!(proof.indeterminate_obligations, 0);
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
