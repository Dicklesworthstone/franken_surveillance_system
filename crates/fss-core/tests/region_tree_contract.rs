#![forbid(unsafe_code)]
//! Contract tests for runtime region ownership tree, context authority,
//! closure semantics, and formal invariants (FSS-021 / RUNTIME-REGION-TREE-001).
//!
//! Ref: FORMAL-001, INV-006, ERR-QUIESCENCE-001, ERR-AUTH-DENIED-001.

use std::error::Error;

use fss_core::region::*;
use fss_core::{
    BudgetQuantitiesSpec, BudgetQuantity, BudgetVector, ContentDigest, ContractError,
    ERR_AUTH_DENIED_001, IdempotencyKey, Obligation, ObligationId, ObligationState, OperationId,
    TimestampNs,
};

// Helper: build a baseline root context authority
fn test_root_authority() -> Result<ContextAuthority, Box<dyn Error>> {
    Ok(ContextAuthority::new_root(test_root_spec()?)?)
}

// Helper: build the baseline root authority spec so tests can derive variants from it
fn test_root_spec() -> Result<RootAuthoritySpec, Box<dyn Error>> {
    let budget = BudgetVector::from_quantities(BudgetQuantitiesSpec {
        latency_ms: 10_000,
        tokens: 5_000,
        bytes: 1_000_000,
        model_calls: 100,
        cpu_millis: 5_000,
        accelerator_millis: 1_000,
        energy_millijoules: 50_000,
        network_bytes: 500_000,
        storage_operations: 200,
        privacy_exposure: BudgetQuantity::ZERO,
        operator_attention_seconds: BudgetQuantity::ZERO,
    });

    Ok(RootAuthoritySpec {
        trace_id: "trace-root-001".to_string(),
        operation_id: OperationId::parse("op-root-001")?,
        principal: "principal-system".to_string(),
        capabilities: vec![
            "camera:read".to_string(),
            "camera:control".to_string(),
            "event:publish".to_string(),
            "alert:dispatch".to_string(),
        ],
        deadline: Some(TimestampNs(1_000_000_000)),
        priority: 10,
        budgets: budget,
        privacy_scope: "privacy-internal".to_string(),
        retention_scope: "retention-30d".to_string(),
        anchor_universe: ContentDigest::sha256(b"test-anchor-universe"),
        generation: 1,
    })
}

// Helper: drive a drain-requested region through Draining, Finalizing and Closed
fn drain_and_finalize(
    tree: &mut RegionTree,
    id: &RegionId,
    now: TimestampNs,
) -> Result<QuiescenceProof, RegionError> {
    tree.begin_drain(id, now)?;
    tree.finalize(id, now)
}

// Helper: tree with a process root and one property region
fn tree_with_property(
    auth: &ContextAuthority,
) -> Result<(RegionTree, RegionId, RegionId), Box<dyn Error>> {
    let now = TimestampNs(100);
    let mut tree = RegionTree::new(RegionId::new("proc-root")?, auth.clone(), now)?;
    let root_id = tree.root_id().clone();
    let prop_id = RegionId::new("prop-1")?;
    tree.attach_child(
        &root_id,
        prop_id.clone(),
        RegionKind::Property,
        auth.clone(),
        now,
    )?;
    Ok((tree, root_id, prop_id))
}

// Helper: build a dummy obligation
fn test_obligation(id_str: &str, state: ObligationState) -> Result<Obligation, Box<dyn Error>> {
    Ok(Obligation {
        obligation_id: ObligationId::parse(id_str)?,
        operation_id: OperationId::parse("op-test")?,
        terminal_predicate: "test.terminal.predicate".to_string(),
        state,
        proof_digest: None,
    })
}

// ===========================================================================
// 1. Hierarchy and Multiplicity Tests
// ===========================================================================

#[test]
fn test_normative_tree_topology_and_instantiation() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);

    let mut tree = RegionTree::new(RegionId::new("proc-01")?, auth.clone(), now)?;
    assert_eq!(tree.region_count(), 1);

    let root_id = tree.root_id().clone();
    let prop_id = RegionId::new("prop-01")?;
    tree.attach_child(
        &root_id,
        prop_id.clone(),
        RegionKind::Property,
        auth.clone(),
        now,
    )?;
    assert_eq!(tree.region_count(), 2);

    let ledger_id = RegionId::new("prop-01-ledger")?;
    tree.attach_child(&prop_id, ledger_id, RegionKind::Ledger, auth.clone(), now)?;

    let obj_id = RegionId::new("prop-01-object")?;
    tree.attach_child(&prop_id, obj_id, RegionKind::ObjectStore, auth.clone(), now)?;

    let proj_id = RegionId::new("prop-01-proj")?;
    tree.attach_child(&prop_id, proj_id, RegionKind::Projection, auth.clone(), now)?;

    let ops_id = RegionId::new("prop-01-ops")?;
    tree.attach_child(&prop_id, ops_id, RegionKind::Operations, auth.clone(), now)?;

    let sensor_id = RegionId::new("sensor-cam-01")?;
    tree.attach_child(
        &prop_id,
        sensor_id.clone(),
        RegionKind::Sensor,
        auth.clone(),
        now,
    )?;

    let sensor_children = [
        ("sensor-cam-01-adapter", RegionKind::AdapterSession),
        ("sensor-cam-01-receive", RegionKind::Receive),
        ("sensor-cam-01-continuity", RegionKind::Continuity),
        ("sensor-cam-01-media", RegionKind::Media),
        ("sensor-cam-01-analysis", RegionKind::Analysis),
        ("sensor-cam-01-archive", RegionKind::Archive),
    ];

    for (c_name, c_kind) in sensor_children {
        tree.attach_child(
            &sensor_id,
            RegionId::new(c_name)?,
            c_kind,
            auth.clone(),
            now,
        )?;
    }

    let event_id = RegionId::new("event-cross-01")?;
    tree.attach_child(
        &prop_id,
        event_id.clone(),
        RegionKind::Event,
        auth.clone(),
        now,
    )?;

    let event_children = [
        ("event-01-window", RegionKind::EvidenceWindow),
        ("event-01-assoc", RegionKind::Association),
        ("event-01-policy", RegionKind::Policy),
        ("event-01-alert", RegionKind::AlertObligation),
    ];

    for (c_name, c_kind) in event_children {
        tree.attach_child(&event_id, RegionId::new(c_name)?, c_kind, auth.clone(), now)?;
    }

    for m_idx in 0..3 {
        let m_id = RegionId::new(format!("event-01-model-{}", m_idx))?;
        tree.attach_child(&event_id, m_id, RegionKind::ModelCall, auth.clone(), now)?;
    }

    assert!(tree.validate_topology().is_ok());
    assert_eq!(tree.region_count(), 2 + 4 + 1 + 6 + 1 + 4 + 3);
    Ok(())
}

#[test]
fn test_planted_negative_illegal_parentage() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);

    let mut tree = RegionTree::new(RegionId::new("proc-root")?, auth.clone(), now)?;
    let root_id = tree.root_id().clone();
    let prop_id = RegionId::new("prop-root")?;
    tree.attach_child(
        &root_id,
        prop_id.clone(),
        RegionKind::Property,
        auth.clone(),
        now,
    )?;

    let res = tree.attach_child(
        &prop_id,
        RegionId::new("prop-nested")?,
        RegionKind::Property,
        auth.clone(),
        now,
    );
    assert_eq!(
        res,
        Err(RegionError::IllegalParentage {
            parent_kind: RegionKind::Property,
            child_kind: RegionKind::Property,
        })
    );

    let res = tree.attach_child(
        &prop_id,
        RegionId::new("adapter-orphan")?,
        RegionKind::AdapterSession,
        auth.clone(),
        now,
    );
    assert_eq!(
        res,
        Err(RegionError::IllegalParentage {
            parent_kind: RegionKind::Property,
            child_kind: RegionKind::AdapterSession,
        })
    );

    let res = tree.attach_child(
        &prop_id,
        RegionId::new("proc-child")?,
        RegionKind::Process,
        auth.clone(),
        now,
    );
    assert_eq!(
        res,
        Err(RegionError::RootCannotHaveParent(RegionId::new(
            "proc-child"
        )?))
    );

    let ledger_id = RegionId::new("prop-ledger")?;
    tree.attach_child(
        &prop_id,
        ledger_id.clone(),
        RegionKind::Ledger,
        auth.clone(),
        now,
    )?;

    let res = tree.attach_child(
        &ledger_id,
        RegionId::new("ledger-child")?,
        RegionKind::Receive,
        auth.clone(),
        now,
    );
    assert_eq!(
        res,
        Err(RegionError::LeafRegionCannotHaveChildren {
            parent_kind: RegionKind::Ledger,
        })
    );
    Ok(())
}

#[test]
fn test_planted_negative_multiplicity_exceeded() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);

    let mut tree = RegionTree::new(RegionId::new("proc-main")?, auth.clone(), now)?;
    let root_id = tree.root_id().clone();
    let prop_id = RegionId::new("prop-main")?;
    tree.attach_child(
        &root_id,
        prop_id.clone(),
        RegionKind::Property,
        auth.clone(),
        now,
    )?;

    let res = tree.attach_child(
        &root_id,
        RegionId::new("prop-second")?,
        RegionKind::Property,
        auth.clone(),
        now,
    );
    assert_eq!(
        res,
        Err(RegionError::MultiplicityExceeded {
            parent_kind: RegionKind::Process,
            child_kind: RegionKind::Property,
            max: 1,
        })
    );

    tree.attach_child(
        &prop_id,
        RegionId::new("prop-ledger-1")?,
        RegionKind::Ledger,
        auth.clone(),
        now,
    )?;

    let res = tree.attach_child(
        &prop_id,
        RegionId::new("prop-ledger-2")?,
        RegionKind::Ledger,
        auth.clone(),
        now,
    );
    assert_eq!(
        res,
        Err(RegionError::MultiplicityExceeded {
            parent_kind: RegionKind::Property,
            child_kind: RegionKind::Ledger,
            max: 1,
        })
    );

    tree.attach_child(
        &prop_id,
        RegionId::new("prop-object-1")?,
        RegionKind::ObjectStore,
        auth.clone(),
        now,
    )?;

    let res = tree.attach_child(
        &prop_id,
        RegionId::new("prop-object-2")?,
        RegionKind::ObjectStore,
        auth.clone(),
        now,
    );
    assert_eq!(
        res,
        Err(RegionError::MultiplicityExceeded {
            parent_kind: RegionKind::Property,
            child_kind: RegionKind::ObjectStore,
            max: 1,
        })
    );
    Ok(())
}

#[test]
fn test_planted_negative_single_owner_violation() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);

    let mut tree = RegionTree::new(RegionId::new("proc-owner")?, auth.clone(), now)?;
    let root_id = tree.root_id().clone();
    let prop_id = RegionId::new("prop-owner")?;
    tree.attach_child(
        &root_id,
        prop_id.clone(),
        RegionKind::Property,
        auth.clone(),
        now,
    )?;

    let sensor_1 = RegionId::new("sensor-1")?;
    let sensor_2 = RegionId::new("sensor-2")?;

    tree.attach_child(
        &prop_id,
        sensor_1.clone(),
        RegionKind::Sensor,
        auth.clone(),
        now,
    )?;
    tree.attach_child(
        &prop_id,
        sensor_2.clone(),
        RegionKind::Sensor,
        auth.clone(),
        now,
    )?;

    let adapter_id = RegionId::new("adapter-01")?;
    tree.attach_child(
        &sensor_1,
        adapter_id.clone(),
        RegionKind::AdapterSession,
        auth.clone(),
        now,
    )?;

    let res = tree.attach_child(
        &sensor_2,
        adapter_id.clone(),
        RegionKind::AdapterSession,
        auth.clone(),
        now,
    );
    assert_eq!(
        res,
        Err(RegionError::SingleOwnerViolation {
            child: adapter_id.clone(),
            current_owner: sensor_1.clone(),
            attempted_owner: sensor_2.clone(),
        })
    );
    assert_eq!(tree.get(&adapter_id)?.parent_id, Some(sensor_1));
    assert!(tree.get(&sensor_2)?.children.is_empty());
    Ok(())
}

// ===========================================================================
// 2. Closure Protocol & Formal Invariants (FORMAL-001, INV-006)
// ===========================================================================

#[test]
fn test_closure_protocol_request_drain_finalize_success() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);

    let mut tree = RegionTree::new(RegionId::new("proc-root")?, auth.clone(), now)?;
    let root_id = tree.root_id().clone();
    let prop_id = RegionId::new("prop-site")?;
    tree.attach_child(
        &root_id,
        prop_id.clone(),
        RegionKind::Property,
        auth.clone(),
        now,
    )?;

    let sensor_id = RegionId::new("sensor-site")?;
    tree.attach_child(
        &prop_id,
        sensor_id.clone(),
        RegionKind::Sensor,
        auth.clone(),
        now,
    )?;

    let media_id = RegionId::new("sensor-media")?;
    tree.attach_child(
        &sensor_id,
        media_id.clone(),
        RegionKind::Media,
        auth.clone(),
        now,
    )?;

    let task_id = TaskId::new("task-decode-frame-01")?;
    tree.register_task(&media_id, task_id.clone(), now)?;
    let receipt =
        tree.complete_task(&media_id, &task_id, TaskOutcome::Success, TimestampNs(120))?;
    assert_eq!(receipt.registered_at, now);
    assert_eq!(receipt.completed_at, TimestampNs(120));

    tree.request_drain(&root_id, Some("normal shutdown"), TimestampNs(200))?;

    assert_eq!(tree.get(&media_id)?.state, RegionState::DrainRequested);
    assert_eq!(tree.get(&sensor_id)?.state, RegionState::DrainRequested);
    assert_eq!(tree.get(&prop_id)?.state, RegionState::DrainRequested);
    assert_eq!(tree.get(&root_id)?.state, RegionState::DrainRequested);

    tree.begin_drain(&media_id, TimestampNs(210))?;
    assert_eq!(tree.get(&media_id)?.state, RegionState::Draining);

    let leaf_proof = tree.finalize(&media_id, TimestampNs(220))?;
    assert_eq!(tree.get(&media_id)?.state, RegionState::Closed);
    assert_eq!(leaf_proof.region_id, media_id);
    assert_eq!(leaf_proof.total_tasks, 1);

    tree.begin_drain(&sensor_id, TimestampNs(230))?;
    let sensor_proof = tree.finalize(&sensor_id, TimestampNs(240))?;
    assert_eq!(tree.get(&sensor_id)?.state, RegionState::Closed);
    assert_eq!(sensor_proof.region_id, sensor_id);

    tree.begin_drain(&prop_id, TimestampNs(250))?;
    let prop_proof = tree.finalize(&prop_id, TimestampNs(260))?;
    assert_eq!(tree.get(&prop_id)?.state, RegionState::Closed);
    assert_eq!(prop_proof.region_id, prop_id);

    tree.begin_drain(&root_id, TimestampNs(270))?;
    let root_proof = tree.finalize(&root_id, TimestampNs(280))?;
    assert_eq!(tree.get(&root_id)?.state, RegionState::Closed);
    assert_eq!(&root_proof.region_id, &root_id);
    Ok(())
}

#[test]
fn test_planted_negative_formal001_parent_finalize_blocked_by_active_child()
-> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);

    let mut tree = RegionTree::new(RegionId::new("proc-root")?, auth.clone(), now)?;
    let root_id = tree.root_id().clone();
    let prop_id = RegionId::new("prop-site")?;
    tree.attach_child(
        &root_id,
        prop_id.clone(),
        RegionKind::Property,
        auth.clone(),
        now,
    )?;

    let sensor_id = RegionId::new("sensor-site")?;
    tree.attach_child(
        &prop_id,
        sensor_id.clone(),
        RegionKind::Sensor,
        auth.clone(),
        now,
    )?;

    tree.request_drain(&root_id, Some("shutdown"), now)?;
    tree.begin_drain(&prop_id, TimestampNs(150))?;

    let res = tree.finalize(&prop_id, TimestampNs(200));
    assert_eq!(
        res,
        Err(RegionError::ChildNotDrained {
            parent_id: prop_id.clone(),
            live_child_id: sensor_id.clone(),
            child_state: RegionState::DrainRequested,
        })
    );

    let err = match res {
        Err(e) => e,
        Ok(_) => return Err("expected error".into()),
    };
    assert_eq!(err.stable_code(), ERR_QUIESCENCE_001);
    Ok(())
}

#[test]
fn test_planted_negative_formal001_closure_blocked_by_pending_obligation()
-> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);

    let mut tree = RegionTree::new(RegionId::new("proc-root")?, auth.clone(), now)?;
    let root_id = tree.root_id().clone();
    let prop_id = RegionId::new("prop-site")?;
    tree.attach_child(
        &root_id,
        prop_id.clone(),
        RegionKind::Property,
        auth.clone(),
        now,
    )?;

    let ops_id = RegionId::new("prop-ops")?;
    tree.attach_child(
        &prop_id,
        ops_id.clone(),
        RegionKind::Operations,
        auth.clone(),
        now,
    )?;

    let ob = test_obligation("ob-alert-01", ObligationState::Pending)?;
    tree.register_obligation(&ops_id, ob)?;

    tree.request_drain(&ops_id, Some("drain"), now)?;
    tree.begin_drain(&ops_id, TimestampNs(150))?;

    let res = tree.finalize(&ops_id, TimestampNs(200));
    assert_eq!(
        res,
        Err(RegionError::LiveObligationsRemaining {
            region_id: ops_id.clone(),
            pending_count: 1,
        })
    );

    let ob_id = ObligationId::parse("ob-alert-01")?;
    tree.resolve_obligation(
        &ops_id,
        &ob_id,
        ObligationState::Verified,
        Some(ContentDigest::sha256(b"proof")),
        None,
    )?;

    let proof = tree.finalize(&ops_id, TimestampNs(220))?;
    assert_eq!(proof.total_obligations, 1);
    assert_eq!(proof.indeterminate_obligations, 0);
    Ok(())
}

#[test]
fn test_inv006_indeterminate_obligation_requires_durable_reconciliation()
-> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);

    let mut tree = RegionTree::new(RegionId::new("proc-root")?, auth.clone(), now)?;
    let root_id = tree.root_id().clone();
    let prop_id = RegionId::new("prop-site")?;
    tree.attach_child(
        &root_id,
        prop_id.clone(),
        RegionKind::Property,
        auth.clone(),
        now,
    )?;

    let ops_id = RegionId::new("prop-ops")?;
    tree.attach_child(
        &prop_id,
        ops_id.clone(),
        RegionKind::Operations,
        auth.clone(),
        now,
    )?;

    let ob_id = ObligationId::parse("ob-indeterminate-01")?;
    let ob = Obligation {
        obligation_id: ob_id.clone(),
        operation_id: OperationId::parse("op-dispatch")?,
        terminal_predicate: "alert.dispatch.verified".to_string(),
        state: ObligationState::Pending,
        proof_digest: None,
    };
    tree.register_obligation(&ops_id, ob)?;

    let res = tree.resolve_obligation(&ops_id, &ob_id, ObligationState::Indeterminate, None, None);
    assert_eq!(
        res,
        Err(RegionError::MissingReconciliationObligation(ob_id.clone()))
    );

    tree.resolve_obligation(
        &ops_id,
        &ob_id,
        ObligationState::Indeterminate,
        None,
        Some("Durable reconciliation required on gateway restart: check external provider webhook log"),
    )?;

    tree.request_drain(&ops_id, Some("drain"), TimestampNs(170))?;
    tree.begin_drain(&ops_id, TimestampNs(175))?;
    let proof = tree.finalize(&ops_id, TimestampNs(180))?;

    assert_eq!(proof.indeterminate_obligations, 1);
    assert_eq!(proof.total_obligations, 1);
    Ok(())
}

#[test]
fn test_planted_negative_invalid_state_transitions() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);

    let mut tree = RegionTree::new(RegionId::new("proc-root")?, auth.clone(), now)?;
    let root_id = tree.root_id().clone();
    let prop_id = RegionId::new("prop-site")?;
    tree.attach_child(
        &root_id,
        prop_id.clone(),
        RegionKind::Property,
        auth.clone(),
        now,
    )?;

    let ops_id = RegionId::new("prop-ops")?;
    tree.attach_child(
        &prop_id,
        ops_id.clone(),
        RegionKind::Operations,
        auth.clone(),
        now,
    )?;

    let res = tree.finalize(&ops_id, TimestampNs(150));
    assert_eq!(
        res,
        Err(RegionError::InvalidStateTransition {
            region_id: ops_id.clone(),
            current: RegionState::Active,
            attempted: RegionState::Finalizing,
        })
    );

    tree.request_drain(&ops_id, None, TimestampNs(160))?;
    let res = tree.finalize(&ops_id, TimestampNs(165));
    assert_eq!(
        res,
        Err(RegionError::InvalidStateTransition {
            region_id: ops_id.clone(),
            current: RegionState::DrainRequested,
            attempted: RegionState::Finalizing,
        })
    );
    tree.begin_drain(&ops_id, TimestampNs(168))?;
    tree.finalize(&ops_id, TimestampNs(170))?;
    assert_eq!(tree.get(&ops_id)?.state, RegionState::Closed);

    let res = tree.finalize(&ops_id, TimestampNs(180));
    assert_eq!(
        res,
        Err(RegionError::InvalidStateTransition {
            region_id: ops_id.clone(),
            current: RegionState::Closed,
            attempted: RegionState::Finalizing,
        })
    );

    let res = tree.request_drain(&ops_id, None, TimestampNs(190));
    assert_eq!(
        res,
        Err(RegionError::InvalidStateTransition {
            region_id: ops_id,
            current: RegionState::Closed,
            attempted: RegionState::DrainRequested,
        })
    );
    Ok(())
}

// ===========================================================================
// 3. Orphan Work Detection
// ===========================================================================

#[test]
fn test_planted_negative_orphan_work_detection() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);

    let mut tree = RegionTree::new(RegionId::new("proc-root")?, auth.clone(), now)?;
    let root_id = tree.root_id().clone();
    let prop_id = RegionId::new("prop-site")?;
    tree.attach_child(
        &root_id,
        prop_id.clone(),
        RegionKind::Property,
        auth.clone(),
        now,
    )?;

    let ops_id = RegionId::new("prop-ops")?;
    tree.attach_child(
        &prop_id,
        ops_id.clone(),
        RegionKind::Operations,
        auth.clone(),
        now,
    )?;

    tree.request_drain(&ops_id, Some("draining"), TimestampNs(110))?;

    let res = tree.register_task(&ops_id, TaskId::new("orphan-task-01")?, TimestampNs(120));
    assert_eq!(
        res,
        Err(RegionError::OrphanWork {
            region_id: ops_id.clone(),
            state: RegionState::DrainRequested,
        })
    );

    let ob = test_obligation("ob-orphan-01", ObligationState::Pending)?;
    let res = tree.register_obligation(&ops_id, ob);
    assert_eq!(
        res,
        Err(RegionError::OrphanWork {
            region_id: ops_id.clone(),
            state: RegionState::DrainRequested,
        })
    );

    tree.begin_drain(&ops_id, TimestampNs(130))?;
    tree.finalize(&ops_id, TimestampNs(140))?;

    let res = tree.register_task(&ops_id, TaskId::new("orphan-task-02")?, TimestampNs(150));
    assert_eq!(
        res,
        Err(RegionError::OrphanWork {
            region_id: ops_id,
            state: RegionState::Closed,
        })
    );
    Ok(())
}

// ===========================================================================
// 4. Context Authority Monotone Narrowing
// ===========================================================================

#[test]
fn test_context_authority_valid_monotone_narrowing() -> Result<(), Box<dyn Error>> {
    let root = test_root_authority()?;

    let child_budget = BudgetVector::from_quantities(BudgetQuantitiesSpec {
        latency_ms: 5_000,
        tokens: 1_000,
        bytes: 500_000,
        model_calls: 10,
        cpu_millis: 1_000,
        accelerator_millis: 200,
        energy_millijoules: 10_000,
        network_bytes: 100_000,
        storage_operations: 50,
        privacy_exposure: BudgetQuantity::ZERO,
        operator_attention_seconds: BudgetQuantity::ZERO,
    });

    let spec = ContextNarrowingSpec {
        operation_id: OperationId::parse("op-child-01")?,
        capabilities: vec!["camera:read".to_string()],
        deadline: Some(TimestampNs(500_000_000)),
        priority: 20,
        budgets: child_budget,
        privacy_scope: "privacy-internal".to_string(),
        retention_scope: "retention-7d".to_string(),
        lease_fence: Some(1),
        idempotency_key: Some(IdempotencyKey::parse("idem-child-01")?),
        lab_controls: None,
    };

    let child_auth = root.narrow(spec)?;
    assert_eq!(child_auth.capabilities(), &["camera:read".to_string()]);
    assert_eq!(child_auth.deadline, Some(TimestampNs(500_000_000)));
    assert_eq!(child_auth.priority, 20);
    assert_eq!(child_auth.budgets, child_budget);
    Ok(())
}

#[test]
fn test_planted_negative_authority_broadening() -> Result<(), Box<dyn Error>> {
    let root = test_root_authority()?;

    let spec = ContextNarrowingSpec {
        operation_id: OperationId::parse("op-child-02")?,
        capabilities: vec!["camera:read".to_string(), "super:admin".to_string()],
        deadline: Some(TimestampNs(500_000_000)),
        priority: 20,
        budgets: root.budgets,
        privacy_scope: "privacy-internal".to_string(),
        retention_scope: "retention-30d".to_string(),
        lease_fence: None,
        idempotency_key: None,
        lab_controls: None,
    };
    let res = root.narrow(spec);
    assert_eq!(res, Err(RegionError::AuthorityBroadened("capabilities")));
    let err = match res {
        Err(e) => e,
        Ok(_) => return Err("expected error".into()),
    };
    assert_eq!(err.stable_code(), ERR_AUTH_DENIED_001);

    let spec = ContextNarrowingSpec {
        operation_id: OperationId::parse("op-child-03")?,
        capabilities: vec!["camera:read".to_string()],
        deadline: Some(TimestampNs(2_000_000_000)),
        priority: 20,
        budgets: root.budgets,
        privacy_scope: "privacy-internal".to_string(),
        retention_scope: "retention-30d".to_string(),
        lease_fence: None,
        idempotency_key: None,
        lab_controls: None,
    };
    let res = root.narrow(spec);
    assert_eq!(res, Err(RegionError::AuthorityBroadened("deadline")));

    let spec = ContextNarrowingSpec {
        operation_id: OperationId::parse("op-child-04")?,
        capabilities: vec!["camera:read".to_string()],
        deadline: None,
        priority: 20,
        budgets: root.budgets,
        privacy_scope: "privacy-internal".to_string(),
        retention_scope: "retention-30d".to_string(),
        lease_fence: None,
        idempotency_key: None,
        lab_controls: None,
    };
    let res = root.narrow(spec);
    assert_eq!(res, Err(RegionError::AuthorityBroadened("deadline")));

    let spec = ContextNarrowingSpec {
        operation_id: OperationId::parse("op-child-05")?,
        capabilities: vec!["camera:read".to_string()],
        deadline: Some(TimestampNs(500_000_000)),
        priority: 5,
        budgets: root.budgets,
        privacy_scope: "privacy-internal".to_string(),
        retention_scope: "retention-30d".to_string(),
        lease_fence: None,
        idempotency_key: None,
        lab_controls: None,
    };
    let res = root.narrow(spec);
    assert_eq!(res, Err(RegionError::AuthorityBroadened("priority")));

    let oversized_budget = BudgetVector::from_quantities(BudgetQuantitiesSpec {
        latency_ms: 10_000,
        tokens: 99_999,
        bytes: 1_000_000,
        model_calls: 100,
        cpu_millis: 5_000,
        accelerator_millis: 1_000,
        energy_millijoules: 50_000,
        network_bytes: 500_000,
        storage_operations: 200,
        privacy_exposure: BudgetQuantity::ZERO,
        operator_attention_seconds: BudgetQuantity::ZERO,
    });
    let spec = ContextNarrowingSpec {
        operation_id: OperationId::parse("op-child-06")?,
        capabilities: vec!["camera:read".to_string()],
        deadline: Some(TimestampNs(500_000_000)),
        priority: 20,
        budgets: oversized_budget,
        privacy_scope: "privacy-internal".to_string(),
        retention_scope: "retention-30d".to_string(),
        lease_fence: None,
        idempotency_key: None,
        lab_controls: None,
    };
    let res = root.narrow(spec);
    assert_eq!(res, Err(RegionError::AuthorityBroadened("budgets")));
    Ok(())
}

// ===========================================================================
// 5. Capacity Bounds: Tested at Bound and Bound+1
// ===========================================================================

#[test]
fn test_bounds_children_per_region() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);

    let mut tree = RegionTree::new(RegionId::new("proc-bound")?, auth.clone(), now)?;
    let root_id = tree.root_id().clone();
    let prop_id = RegionId::new("prop-bound")?;
    tree.attach_child(
        &root_id,
        prop_id.clone(),
        RegionKind::Property,
        auth.clone(),
        now,
    )?;

    for i in 0..MAX_SENSOR_REGIONS {
        let sid = RegionId::new(format!("sensor-{:03}", i))?;
        tree.attach_child(&prop_id, sid, RegionKind::Sensor, auth.clone(), now)?;
    }

    let sid_overflow = RegionId::new("sensor-overflow")?;
    let res = tree.attach_child(
        &prop_id,
        sid_overflow,
        RegionKind::Sensor,
        auth.clone(),
        now,
    );
    assert_eq!(
        res,
        Err(RegionError::MultiplicityExceeded {
            parent_kind: RegionKind::Property,
            child_kind: RegionKind::Sensor,
            max: MAX_SENSOR_REGIONS,
        })
    );
    Ok(())
}

#[test]
fn test_bounds_tasks_per_region() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);

    let mut tree = RegionTree::new(RegionId::new("proc-tasks")?, auth.clone(), now)?;
    let root_id = tree.root_id().clone();

    for i in 0..MAX_TASKS_PER_REGION {
        let tid = TaskId::new(format!("task-{:03}", i))?;
        tree.register_task(&root_id, tid, now)?;
    }

    let tid_overflow = TaskId::new("task-overflow")?;
    let res = tree.register_task(&root_id, tid_overflow, now);
    assert_eq!(res, Err(RegionError::CapacityExceeded("tasks")));
    Ok(())
}

#[test]
fn test_bounds_obligations_per_region() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);

    let mut tree = RegionTree::new(RegionId::new("proc-obs")?, auth.clone(), now)?;
    let root_id = tree.root_id().clone();

    for i in 0..MAX_OBLIGATIONS_PER_REGION {
        let ob = test_obligation(&format!("ob-{:03}", i), ObligationState::Pending)?;
        tree.register_obligation(&root_id, ob)?;
    }

    let ob_overflow = test_obligation("ob-overflow", ObligationState::Pending)?;
    let res = tree.register_obligation(&root_id, ob_overflow);
    assert_eq!(res, Err(RegionError::CapacityExceeded("obligations")));
    Ok(())
}

#[test]
fn test_bounds_identifier_length() -> Result<(), Box<dyn Error>> {
    let valid_128 = "a".repeat(128);
    assert!(RegionId::new(&valid_128).is_ok());

    let invalid_129 = "a".repeat(129);
    assert!(matches!(
        RegionId::new(&invalid_129),
        Err(RegionError::InvalidIdentifier(_))
    ));

    assert!(matches!(
        RegionId::new(""),
        Err(RegionError::InvalidIdentifier(_))
    ));
    Ok(())
}

// ===========================================================================
// 6. Machine-Checkable Topology Fixture
// ===========================================================================

#[test]
fn test_topology_fixture_serialization_and_instantiation() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(1_000);

    let fixture = TopologyFixture::standard_topology(2, 2, 2)?;
    assert_eq!(fixture.name, "standard_normative_topology");
    assert_eq!(fixture.version, 1);
    assert_eq!(fixture.nodes.len(), 34);

    let tree = fixture.instantiate(auth, now)?;
    assert_eq!(tree.region_count(), 34);
    assert!(tree.validate_topology().is_ok());
    Ok(())
}

// ===========================================================================
// 7. End-to-End Controlled Cut-Point Shutdown Scenario
// ===========================================================================

#[test]
fn test_e2e_controlled_cutpoint_shutdown_with_structured_log() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let start_time = TimestampNs(1_000_000);

    let fixture = TopologyFixture::standard_topology(1, 1, 1)?;
    let mut tree = fixture.instantiate(auth, start_time)?;

    let media_id = RegionId::new("sensor_00.media")?;
    let model_id = RegionId::new("event_00.model_call_00")?;
    let alert_id = RegionId::new("event_00.alert_obligation")?;

    let frame_task = TaskId::new("frame-ingest-42")?;
    tree.register_task(&media_id, frame_task.clone(), start_time)?;

    let model_task = TaskId::new("model-infer-42")?;
    tree.register_task(&model_id, model_task.clone(), start_time)?;

    let alert_ob_id = ObligationId::parse("ob-alert-dispatch-42")?;
    let alert_ob = Obligation {
        obligation_id: alert_ob_id.clone(),
        operation_id: OperationId::parse("op-alert-42")?,
        terminal_predicate: "alert.dispatched.carrier".to_string(),
        state: ObligationState::Pending,
        proof_digest: None,
    };
    tree.register_obligation(&alert_id, alert_ob)?;

    let event_id = RegionId::new("property.site_01.event_00")?;
    tree.request_drain(
        &event_id,
        Some("operator cancellation cut point"),
        TimestampNs(1_100_000),
    )?;

    tree.complete_task(
        &model_id,
        &model_task,
        TaskOutcome::Cancelled,
        TimestampNs(1_150_000),
    )?;
    let model_proof = drain_and_finalize(&mut tree, &model_id, TimestampNs(1_160_000))?;
    assert_eq!(model_proof.total_tasks, 1);

    tree.resolve_obligation(
        &alert_id,
        &alert_ob_id,
        ObligationState::Cancelled,
        Some(ContentDigest::sha256(b"cancelled-proof")),
        None,
    )?;
    let alert_proof = drain_and_finalize(&mut tree, &alert_id, TimestampNs(1_180_000))?;
    assert_eq!(alert_proof.total_obligations, 1);

    drain_and_finalize(
        &mut tree,
        &RegionId::new("event_00.evidence_window")?,
        TimestampNs(1_190_000),
    )?;
    drain_and_finalize(
        &mut tree,
        &RegionId::new("event_00.association")?,
        TimestampNs(1_190_000),
    )?;
    drain_and_finalize(
        &mut tree,
        &RegionId::new("event_00.policy")?,
        TimestampNs(1_190_000),
    )?;

    let event_proof = drain_and_finalize(&mut tree, &event_id, TimestampNs(1_200_000))?;
    assert_eq!(tree.get(&event_id)?.state, RegionState::Closed);
    assert_eq!(event_proof.region_id, event_id);

    let sensor_id = RegionId::new("property.site_01.sensor_00")?;
    tree.request_drain(
        &sensor_id,
        Some("sensor shutdown cut point"),
        TimestampNs(1_210_000),
    )?;

    tree.complete_task(
        &media_id,
        &frame_task,
        TaskOutcome::Success,
        TimestampNs(1_220_000),
    )?;
    drain_and_finalize(&mut tree, &media_id, TimestampNs(1_230_000))?;

    drain_and_finalize(
        &mut tree,
        &RegionId::new("sensor_00.adapter_session")?,
        TimestampNs(1_240_000),
    )?;
    drain_and_finalize(
        &mut tree,
        &RegionId::new("sensor_00.receive")?,
        TimestampNs(1_240_000),
    )?;
    drain_and_finalize(
        &mut tree,
        &RegionId::new("sensor_00.continuity")?,
        TimestampNs(1_240_000),
    )?;
    drain_and_finalize(
        &mut tree,
        &RegionId::new("sensor_00.analysis")?,
        TimestampNs(1_240_000),
    )?;
    drain_and_finalize(
        &mut tree,
        &RegionId::new("sensor_00.archive")?,
        TimestampNs(1_240_000),
    )?;

    drain_and_finalize(&mut tree, &sensor_id, TimestampNs(1_250_000))?;

    let prop_id = RegionId::new("property.site_01")?;
    tree.request_drain(&prop_id, Some("property drain"), TimestampNs(1_260_000))?;

    drain_and_finalize(
        &mut tree,
        &RegionId::new("property.site_01.ledger")?,
        TimestampNs(1_270_000),
    )?;
    drain_and_finalize(
        &mut tree,
        &RegionId::new("property.site_01.object_store")?,
        TimestampNs(1_270_000),
    )?;
    drain_and_finalize(
        &mut tree,
        &RegionId::new("property.site_01.projection")?,
        TimestampNs(1_270_000),
    )?;
    drain_and_finalize(
        &mut tree,
        &RegionId::new("property.site_01.operations")?,
        TimestampNs(1_270_000),
    )?;

    drain_and_finalize(&mut tree, &prop_id, TimestampNs(1_280_000))?;

    let root_id = tree.root_id().clone();
    tree.request_drain(&root_id, Some("process shutdown"), TimestampNs(1_290_000))?;
    let root_proof = drain_and_finalize(&mut tree, &root_id, TimestampNs(1_300_000))?;

    assert_eq!(tree.get(&root_id)?.state, RegionState::Closed);
    assert_eq!(&root_proof.region_id, &root_id);

    // Review-523 F6: parent proofs aggregate their whole subtree.
    assert_eq!(event_proof.total_tasks, 1);
    assert_eq!(event_proof.total_obligations, 1);
    assert_eq!(root_proof.total_tasks, 2);
    assert_eq!(root_proof.total_obligations, 1);
    assert_eq!(root_proof.indeterminate_obligations, 0);

    assert_ne!(root_proof.proof_digest, ContentDigest::sha256(b""));
    assert_ne!(event_proof.proof_digest, ContentDigest::sha256(b""));
    Ok(())
}

// ===========================================================================
// 8. Review-523 Remediation
// ===========================================================================

// F2: the transition table is the strict linear closure protocol.
#[test]
fn test_review523_f2_transition_table_is_strict_linear_protocol() -> Result<(), Box<dyn Error>> {
    let states = [
        RegionState::Active,
        RegionState::DrainRequested,
        RegionState::Draining,
        RegionState::Finalizing,
        RegionState::Closed,
    ];
    let allowed = [
        (RegionState::Active, RegionState::DrainRequested),
        (RegionState::DrainRequested, RegionState::Draining),
        (RegionState::Draining, RegionState::Finalizing),
        (RegionState::Finalizing, RegionState::Closed),
    ];
    for from in states {
        for to in states {
            assert_eq!(
                from.can_transition_to(to),
                allowed.contains(&(from, to)),
                "transition {from:?} -> {to:?}"
            );
        }
    }
    Ok(())
}

// F2: finalize cannot skip Draining.
#[test]
fn test_review523_f2_finalize_rejects_drain_requested_without_draining()
-> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let (mut tree, _root_id, prop_id) = tree_with_property(&auth)?;

    tree.request_drain(&prop_id, Some("drain"), TimestampNs(200))?;
    assert_eq!(tree.get(&prop_id)?.state, RegionState::DrainRequested);

    let res = tree.finalize(&prop_id, TimestampNs(210));
    assert_eq!(
        res,
        Err(RegionError::InvalidStateTransition {
            region_id: prop_id.clone(),
            current: RegionState::DrainRequested,
            attempted: RegionState::Finalizing,
        })
    );
    assert_eq!(tree.get(&prop_id)?.state, RegionState::DrainRequested);
    Ok(())
}

// F2: begin_drain cannot skip DrainRequested (children would never be notified).
#[test]
fn test_review523_f2_begin_drain_rejects_active_without_request() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let (mut tree, _root_id, prop_id) = tree_with_property(&auth)?;

    let res = tree.begin_drain(&prop_id, TimestampNs(200));
    assert_eq!(
        res,
        Err(RegionError::InvalidStateTransition {
            region_id: prop_id.clone(),
            current: RegionState::Active,
            attempted: RegionState::Draining,
        })
    );
    assert_eq!(tree.get(&prop_id)?.state, RegionState::Active);
    assert_eq!(tree.get(&prop_id)?.drain_requested_at, None);

    tree.request_drain(&prop_id, None, TimestampNs(210))?;
    tree.begin_drain(&prop_id, TimestampNs(220))?;
    let res = tree.begin_drain(&prop_id, TimestampNs(230));
    assert_eq!(
        res,
        Err(RegionError::InvalidStateTransition {
            region_id: prop_id,
            current: RegionState::Draining,
            attempted: RegionState::Draining,
        })
    );
    Ok(())
}

// F2: Finalizing is a reachable, observable state that rejects new work.
#[test]
fn test_review523_f2_finalizing_is_reachable_and_observable() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let (mut tree, _root_id, prop_id) = tree_with_property(&auth)?;
    let ops_id = RegionId::new("prop-ops")?;
    tree.attach_child(
        &prop_id,
        ops_id.clone(),
        RegionKind::Operations,
        auth.clone(),
        TimestampNs(100),
    )?;

    tree.request_drain(&ops_id, Some("drain"), TimestampNs(200))?;
    let res = tree.begin_finalize(&ops_id, TimestampNs(205));
    assert_eq!(
        res,
        Err(RegionError::InvalidStateTransition {
            region_id: ops_id.clone(),
            current: RegionState::DrainRequested,
            attempted: RegionState::Finalizing,
        })
    );

    tree.begin_drain(&ops_id, TimestampNs(210))?;
    tree.begin_finalize(&ops_id, TimestampNs(220))?;
    assert_eq!(tree.get(&ops_id)?.state, RegionState::Finalizing);

    let res = tree.register_task(&ops_id, TaskId::new("late-task")?, TimestampNs(221));
    assert_eq!(
        res,
        Err(RegionError::OrphanWork {
            region_id: ops_id.clone(),
            state: RegionState::Finalizing,
        })
    );
    let res = tree.register_obligation(
        &ops_id,
        test_obligation("ob-late", ObligationState::Pending)?,
    );
    assert_eq!(
        res,
        Err(RegionError::OrphanWork {
            region_id: ops_id.clone(),
            state: RegionState::Finalizing,
        })
    );
    let res = tree.request_drain(&ops_id, None, TimestampNs(222));
    assert_eq!(
        res,
        Err(RegionError::InvalidStateTransition {
            region_id: ops_id.clone(),
            current: RegionState::Finalizing,
            attempted: RegionState::DrainRequested,
        })
    );
    let res = tree.begin_drain(&ops_id, TimestampNs(223));
    assert_eq!(
        res,
        Err(RegionError::InvalidStateTransition {
            region_id: ops_id.clone(),
            current: RegionState::Finalizing,
            attempted: RegionState::Draining,
        })
    );
    let res = tree.begin_finalize(&ops_id, TimestampNs(224));
    assert_eq!(
        res,
        Err(RegionError::InvalidStateTransition {
            region_id: ops_id.clone(),
            current: RegionState::Finalizing,
            attempted: RegionState::Finalizing,
        })
    );

    let proof = tree.finalize(&ops_id, TimestampNs(230))?;
    assert_eq!(tree.get(&ops_id)?.state, RegionState::Closed);
    assert_eq!(proof.closed_at, TimestampNs(230));
    Ok(())
}

// F2: begin_finalize verifies quiescence before entering Finalizing.
#[test]
fn test_review523_f2_begin_finalize_requires_quiescence() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let (mut tree, root_id, prop_id) = tree_with_property(&auth)?;
    let ledger_id = RegionId::new("prop-ledger")?;
    tree.attach_child(
        &prop_id,
        ledger_id.clone(),
        RegionKind::Ledger,
        auth.clone(),
        TimestampNs(100),
    )?;

    tree.request_drain(&root_id, None, TimestampNs(200))?;
    tree.begin_drain(&prop_id, TimestampNs(210))?;
    let res = tree.begin_finalize(&prop_id, TimestampNs(220));
    assert_eq!(
        res,
        Err(RegionError::ChildNotDrained {
            parent_id: prop_id.clone(),
            live_child_id: ledger_id,
            child_state: RegionState::DrainRequested,
        })
    );
    assert_eq!(tree.get(&prop_id)?.state, RegionState::Draining);
    Ok(())
}

// F3: an unreconciled indeterminate obligation blocks closure (INV-006).
#[test]
fn test_review523_f3_finalize_rejects_unreconciled_indeterminate_obligation()
-> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let (mut tree, _root_id, prop_id) = tree_with_property(&auth)?;

    let ob_id = ObligationId::parse("ob-indeterminate-01")?;
    let ob = test_obligation("ob-indeterminate-01", ObligationState::Indeterminate)?;
    tree.register_obligation(&prop_id, ob)?;

    tree.request_drain(&prop_id, Some("drain"), TimestampNs(200))?;
    tree.begin_drain(&prop_id, TimestampNs(210))?;

    let expected = RegionError::UnreconciledIndeterminateObligation {
        region_id: prop_id.clone(),
        obligation_id: ob_id.clone(),
    };
    let res = tree.finalize(&prop_id, TimestampNs(220));
    assert_eq!(res, Err(expected.clone()));
    assert_eq!(
        tree.begin_finalize(&prop_id, TimestampNs(215)),
        Err(expected.clone())
    );
    assert_eq!(expected.stable_code(), ERR_QUIESCENCE_001);
    assert_eq!(tree.get(&prop_id)?.state, RegionState::Draining);

    tree.resolve_obligation(
        &prop_id,
        &ob_id,
        ObligationState::Indeterminate,
        None,
        Some("reconcile against provider delivery ledger on restart"),
    )?;
    let proof = tree.finalize(&prop_id, TimestampNs(230))?;
    assert_eq!(proof.indeterminate_obligations, 1);
    assert_eq!(tree.get(&prop_id)?.state, RegionState::Closed);
    Ok(())
}

// F3: a blank reconciliation note is not a durable reconciliation record.
#[test]
fn test_review523_f3_blank_reconciliation_note_is_rejected() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let (mut tree, _root_id, prop_id) = tree_with_property(&auth)?;

    let ob_id = ObligationId::parse("ob-blank-note")?;
    tree.register_obligation(
        &prop_id,
        test_obligation("ob-blank-note", ObligationState::Pending)?,
    )?;

    for note in ["", "   "] {
        let res = tree.resolve_obligation(
            &prop_id,
            &ob_id,
            ObligationState::Indeterminate,
            None,
            Some(note),
        );
        assert_eq!(
            res,
            Err(RegionError::MissingReconciliationObligation(ob_id.clone()))
        );
    }
    assert!(tree.get(&prop_id)?.reconciliation_obligations.is_empty());
    Ok(())
}

// F4: same-parent re-attach is a duplicate; the root can never gain an owner.
#[test]
fn test_review523_f4_reattach_same_parent_and_root_ownership() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);
    let (mut tree, root_id, prop_id) = tree_with_property(&auth)?;
    let sensor_1 = RegionId::new("sensor-1")?;
    tree.attach_child(
        &prop_id,
        sensor_1.clone(),
        RegionKind::Sensor,
        auth.clone(),
        now,
    )?;
    let adapter_id = RegionId::new("adapter-1")?;
    tree.attach_child(
        &sensor_1,
        adapter_id.clone(),
        RegionKind::AdapterSession,
        auth.clone(),
        now,
    )?;

    let res = tree.attach_child(
        &sensor_1,
        adapter_id.clone(),
        RegionKind::AdapterSession,
        auth.clone(),
        now,
    );
    assert_eq!(res, Err(RegionError::DuplicateRegion(adapter_id)));

    let res = tree.attach_child(
        &sensor_1,
        root_id.clone(),
        RegionKind::Receive,
        auth.clone(),
        now,
    );
    assert_eq!(res, Err(RegionError::RootCannotHaveParent(root_id)));
    assert_eq!(tree.region_count(), 4);
    Ok(())
}

// F5: generation continuity between parent and child authority.
#[test]
fn test_review523_f5_attach_child_rejects_generation_mismatch() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);
    let mut tree = RegionTree::new(RegionId::new("proc-root")?, auth.clone(), now)?;
    let root_id = tree.root_id().clone();

    let mut mismatched_auth = auth.clone();
    mismatched_auth.generation = 999;

    let res = tree.attach_child(
        &root_id,
        RegionId::new("prop-1")?,
        RegionKind::Property,
        mismatched_auth,
        now,
    );
    assert_eq!(
        res,
        Err(RegionError::GenerationMismatch {
            expected: 1,
            actual: 999,
        })
    );
    assert_eq!(tree.region_count(), 1);
    Ok(())
}

// F5: anchor-universe continuity between parent and child authority.
#[test]
fn test_review523_f5_attach_child_rejects_anchor_mismatch() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);
    let mut tree = RegionTree::new(RegionId::new("proc-root")?, auth.clone(), now)?;
    let root_id = tree.root_id().clone();

    let mut mismatched_auth = auth.clone();
    mismatched_auth.anchor_universe = ContentDigest::sha256(b"foreign-anchor-universe");

    let res = tree.attach_child(
        &root_id,
        RegionId::new("prop-1")?,
        RegionKind::Property,
        mismatched_auth,
        now,
    );
    assert_eq!(
        res,
        Err(RegionError::AnchorMismatch {
            expected: auth.anchor_universe,
            actual: ContentDigest::sha256(b"foreign-anchor-universe"),
        })
    );
    assert_eq!(tree.region_count(), 1);
    Ok(())
}

// F5: a fabricated child authority that broadens any dimension is rejected.
#[test]
fn test_review523_f5_attach_child_rejects_broadened_authority() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);
    let mut tree = RegionTree::new(RegionId::new("proc-root")?, auth.clone(), now)?;
    let root_id = tree.root_id().clone();
    let prop_id = RegionId::new("prop-1")?;

    let mut extra_caps_spec = test_root_spec()?;
    extra_caps_spec.capabilities.push("super:admin".to_string());
    let extra_caps = ContextAuthority::new_root(extra_caps_spec)?;

    let mut higher_priority = auth.clone();
    higher_priority.priority = 0;

    let mut unbounded_deadline = auth.clone();
    unbounded_deadline.deadline = None;

    let mut later_deadline = auth.clone();
    later_deadline.deadline = Some(TimestampNs(2_000_000_000));

    let mut bigger_budget_spec = test_root_spec()?;
    bigger_budget_spec.budgets = BudgetVector::from_quantities(BudgetQuantitiesSpec {
        latency_ms: 10_000,
        tokens: 99_999,
        bytes: 1_000_000,
        model_calls: 100,
        cpu_millis: 5_000,
        accelerator_millis: 1_000,
        energy_millijoules: 50_000,
        network_bytes: 500_000,
        storage_operations: 200,
        privacy_exposure: BudgetQuantity::ZERO,
        operator_attention_seconds: BudgetQuantity::ZERO,
    });
    let bigger_budget = ContextAuthority::new_root(bigger_budget_spec)?;

    let mut other_principal = auth.clone();
    other_principal.principal = "principal-intruder".to_string();

    let mut other_trace = auth.clone();
    other_trace.trace_id = "trace-forged-001".to_string();

    let mut cancelled_parent_auth = auth.clone();
    cancelled_parent_auth.cancellation_reason = Some("operator stop".to_string());

    let cases = [
        (extra_caps, "capabilities"),
        (higher_priority, "priority"),
        (unbounded_deadline, "deadline"),
        (later_deadline, "deadline"),
        (bigger_budget, "budgets"),
        (other_principal, "principal"),
        (other_trace, "trace_id"),
    ];
    for (child_auth, field) in cases {
        let res = tree.attach_child(
            &root_id,
            prop_id.clone(),
            RegionKind::Property,
            child_auth,
            now,
        );
        assert_eq!(res, Err(RegionError::AuthorityBroadened(field)), "{field}");
        assert_eq!(tree.region_count(), 1, "{field}");
    }

    // A child cannot shed its parent's cancellation reason.
    assert_eq!(
        auth.verify_narrowing_of(&cancelled_parent_auth),
        Err(RegionError::AuthorityBroadened("cancellation_reason"))
    );
    Ok(())
}

// F5: narrowing is checked against the direct parent, not just the root.
#[test]
fn test_review523_f5_attach_child_checks_direct_parent_authority() -> Result<(), Box<dyn Error>> {
    let root_auth = test_root_authority()?;
    let now = TimestampNs(100);
    let mut tree = RegionTree::new(RegionId::new("proc-root")?, root_auth.clone(), now)?;
    let root_id = tree.root_id().clone();

    let narrow_budget = BudgetVector::from_quantities(BudgetQuantitiesSpec {
        latency_ms: 5_000,
        tokens: 1_000,
        bytes: 500_000,
        model_calls: 10,
        cpu_millis: 1_000,
        accelerator_millis: 200,
        energy_millijoules: 10_000,
        network_bytes: 100_000,
        storage_operations: 50,
        privacy_exposure: BudgetQuantity::ZERO,
        operator_attention_seconds: BudgetQuantity::ZERO,
    });
    let prop_auth = root_auth.narrow(ContextNarrowingSpec {
        operation_id: OperationId::parse("op-prop")?,
        capabilities: vec!["camera:read".to_string(), "event:publish".to_string()],
        deadline: Some(TimestampNs(500_000_000)),
        priority: 20,
        budgets: narrow_budget,
        privacy_scope: "privacy-internal".to_string(),
        retention_scope: "retention-30d".to_string(),
        lease_fence: None,
        idempotency_key: None,
        lab_controls: None,
    })?;
    prop_auth.verify_narrowing_of(&root_auth)?;

    let prop_id = RegionId::new("prop-1")?;
    tree.attach_child(
        &root_id,
        prop_id.clone(),
        RegionKind::Property,
        prop_auth.clone(),
        now,
    )?;

    // Root authority is broader than the property's narrowed authority.
    let res = tree.attach_child(
        &prop_id,
        RegionId::new("sensor-root-auth")?,
        RegionKind::Sensor,
        root_auth.clone(),
        now,
    );
    assert_eq!(res, Err(RegionError::AuthorityBroadened("capabilities")));
    assert_eq!(
        root_auth.verify_narrowing_of(&prop_auth),
        Err(RegionError::AuthorityBroadened("capabilities"))
    );

    // Equal authority is a (non-strict) narrowing.
    tree.attach_child(
        &prop_id,
        RegionId::new("sensor-equal-auth")?,
        RegionKind::Sensor,
        prop_auth.clone(),
        now,
    )?;

    let sensor_auth = prop_auth.narrow(ContextNarrowingSpec {
        operation_id: OperationId::parse("op-sensor")?,
        capabilities: vec!["camera:read".to_string()],
        deadline: Some(TimestampNs(400_000_000)),
        priority: 30,
        budgets: narrow_budget,
        privacy_scope: "privacy-internal".to_string(),
        retention_scope: "retention-7d".to_string(),
        lease_fence: Some(7),
        idempotency_key: None,
        lab_controls: None,
    })?;
    tree.attach_child(
        &prop_id,
        RegionId::new("sensor-narrow-auth")?,
        RegionKind::Sensor,
        sensor_auth,
        now,
    )?;
    assert_eq!(tree.region_count(), 4);
    Ok(())
}

// F6: quiescence proofs aggregate the whole subtree.
#[test]
fn test_review523_f6_quiescence_proof_aggregates_whole_subtree() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);
    let (mut tree, root_id, prop_id) = tree_with_property(&auth)?;
    let sensor_id = RegionId::new("sensor-1")?;
    let media_id = RegionId::new("sensor-1-media")?;
    let ops_id = RegionId::new("prop-ops")?;
    tree.attach_child(
        &prop_id,
        sensor_id.clone(),
        RegionKind::Sensor,
        auth.clone(),
        now,
    )?;
    tree.attach_child(
        &sensor_id,
        media_id.clone(),
        RegionKind::Media,
        auth.clone(),
        now,
    )?;
    tree.attach_child(
        &prop_id,
        ops_id.clone(),
        RegionKind::Operations,
        auth.clone(),
        now,
    )?;

    for (region, task, outcome) in [
        (&media_id, "task-media-1", TaskOutcome::Success),
        (&media_id, "task-media-2", TaskOutcome::Cancelled),
        (&sensor_id, "task-sensor-1", TaskOutcome::Success),
    ] {
        let tid = TaskId::new(task)?;
        tree.register_task(region, tid.clone(), now)?;
        tree.complete_task(region, &tid, outcome, TimestampNs(110))?;
    }

    let media_ob = ObligationId::parse("ob-media-upload")?;
    tree.register_obligation(
        &media_id,
        test_obligation("ob-media-upload", ObligationState::Pending)?,
    )?;
    tree.resolve_obligation(
        &media_id,
        &media_ob,
        ObligationState::Indeterminate,
        None,
        Some("reconcile multipart upload against object store listing"),
    )?;
    let ops_ob = ObligationId::parse("ob-ops-audit")?;
    tree.register_obligation(
        &ops_id,
        test_obligation("ob-ops-audit", ObligationState::Pending)?,
    )?;
    tree.resolve_obligation(
        &ops_id,
        &ops_ob,
        ObligationState::Verified,
        Some(ContentDigest::sha256(b"audit-proof")),
        None,
    )?;

    tree.request_drain(&root_id, Some("shutdown"), TimestampNs(200))?;
    let media_proof = drain_and_finalize(&mut tree, &media_id, TimestampNs(210))?;
    let sensor_proof = drain_and_finalize(&mut tree, &sensor_id, TimestampNs(220))?;
    let ops_proof = drain_and_finalize(&mut tree, &ops_id, TimestampNs(230))?;
    let prop_proof = drain_and_finalize(&mut tree, &prop_id, TimestampNs(240))?;
    let root_proof = drain_and_finalize(&mut tree, &root_id, TimestampNs(250))?;

    let counts = |p: &QuiescenceProof| {
        (
            p.total_tasks,
            p.total_obligations,
            p.indeterminate_obligations,
        )
    };
    assert_eq!(counts(&media_proof), (2, 1, 1));
    assert_eq!(counts(&sensor_proof), (3, 1, 1));
    assert_eq!(counts(&ops_proof), (0, 1, 0));
    assert_eq!(counts(&prop_proof), (3, 2, 1));
    assert_eq!(counts(&root_proof), (3, 2, 1));
    assert_eq!(
        root_proof.proof_digest,
        QuiescenceProof::compute_digest(
            &root_id,
            RegionKind::Process,
            None,
            TimestampNs(250),
            3,
            2,
            1,
        )
    );
    Ok(())
}

// F7: MAX_CHILDREN_PER_REGION at bound and bound+1.
#[test]
fn test_review523_f7_bounds_children_per_region_at_bound_and_bound_plus_one()
-> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);
    let (mut tree, _root_id, prop_id) = tree_with_property(&auth)?;

    for i in 0..MAX_SENSOR_REGIONS {
        let id = RegionId::new(format!("sensor-{i:02}"))?;
        tree.attach_child(&prop_id, id, RegionKind::Sensor, auth.clone(), now)?;
    }
    for i in 0..MAX_EVENT_REGIONS {
        let id = RegionId::new(format!("event-{i:02}"))?;
        tree.attach_child(&prop_id, id, RegionKind::Event, auth.clone(), now)?;
    }
    assert_eq!(
        MAX_SENSOR_REGIONS + MAX_EVENT_REGIONS,
        MAX_CHILDREN_PER_REGION
    );
    assert_eq!(tree.get(&prop_id)?.children.len(), MAX_CHILDREN_PER_REGION);

    // Ledger multiplicity (1) is not reached; only the per-region child bound applies.
    let res = tree.attach_child(
        &prop_id,
        RegionId::new("prop-ledger")?,
        RegionKind::Ledger,
        auth.clone(),
        now,
    );
    assert_eq!(
        res,
        Err(RegionError::CapacityExceeded("children_per_region"))
    );
    assert_eq!(tree.get(&prop_id)?.children.len(), MAX_CHILDREN_PER_REGION);
    Ok(())
}

// F7: MAX_REGIONS_IN_TREE at bound and bound+1.
#[test]
fn test_review523_f7_bounds_regions_in_tree_at_bound_and_bound_plus_one()
-> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);
    let (mut tree, _root_id, prop_id) = tree_with_property(&auth)?;

    let sensor_children = [
        ("adapter", RegionKind::AdapterSession),
        ("receive", RegionKind::Receive),
        ("continuity", RegionKind::Continuity),
        ("media", RegionKind::Media),
        ("analysis", RegionKind::Analysis),
        ("archive", RegionKind::Archive),
    ];
    for s in 0..MAX_SENSOR_REGIONS {
        let sid = RegionId::new(format!("sensor-{s:02}"))?;
        tree.attach_child(&prop_id, sid.clone(), RegionKind::Sensor, auth.clone(), now)?;
        for (name, kind) in sensor_children {
            let cid = RegionId::new(format!("sensor-{s:02}-{name}"))?;
            tree.attach_child(&sid, cid, kind, auth.clone(), now)?;
        }
    }
    let mut e = 0;
    while tree.region_count() < MAX_REGIONS_IN_TREE {
        let eid = RegionId::new(format!("event-{e:02}"))?;
        tree.attach_child(&prop_id, eid, RegionKind::Event, auth.clone(), now)?;
        e += 1;
    }
    assert_eq!(tree.region_count(), MAX_REGIONS_IN_TREE);
    assert!(e < MAX_EVENT_REGIONS);

    let res = tree.attach_child(
        &prop_id,
        RegionId::new(format!("event-{e:02}"))?,
        RegionKind::Event,
        auth.clone(),
        now,
    );
    assert_eq!(res, Err(RegionError::CapacityExceeded("tree_regions")));
    assert_eq!(tree.region_count(), MAX_REGIONS_IN_TREE);
    tree.validate_topology()?;
    Ok(())
}

// F7: MAX_CAPABILITIES_PER_CONTEXT at bound and bound+1 (root construction and narrowing).
#[test]
fn test_review523_f7_bounds_capabilities_per_context_at_bound_and_bound_plus_one()
-> Result<(), Box<dyn Error>> {
    let caps = |n: usize| -> Vec<String> { (0..n).map(|i| format!("cap:{i:03}")).collect() };

    let mut spec = test_root_spec()?;
    spec.capabilities = caps(MAX_CAPABILITIES_PER_CONTEXT);
    let full = ContextAuthority::new_root(spec)?;
    assert_eq!(full.capabilities().len(), MAX_CAPABILITIES_PER_CONTEXT);

    let mut spec = test_root_spec()?;
    spec.capabilities = caps(MAX_CAPABILITIES_PER_CONTEXT + 1);
    assert_eq!(
        ContextAuthority::new_root(spec),
        Err(RegionError::CapacityExceeded("capabilities"))
    );

    // Duplicates do not count toward the bound.
    let mut spec = test_root_spec()?;
    let mut dup = caps(MAX_CAPABILITIES_PER_CONTEXT);
    dup.push("cap:000".to_string());
    spec.capabilities = dup;
    assert_eq!(
        ContextAuthority::new_root(spec)?.capabilities().len(),
        MAX_CAPABILITIES_PER_CONTEXT
    );

    let narrowing = |c: Vec<String>| -> Result<ContextNarrowingSpec, Box<dyn Error>> {
        Ok(ContextNarrowingSpec {
            operation_id: OperationId::parse("op-caps")?,
            capabilities: c,
            deadline: full.deadline,
            priority: full.priority,
            budgets: full.budgets,
            privacy_scope: "privacy-internal".to_string(),
            retention_scope: "retention-30d".to_string(),
            lease_fence: None,
            idempotency_key: None,
            lab_controls: None,
        })
    };
    let child = full.narrow(narrowing(caps(MAX_CAPABILITIES_PER_CONTEXT))?)?;
    assert_eq!(child.capabilities().len(), MAX_CAPABILITIES_PER_CONTEXT);
    child.verify_narrowing_of(&full)?;
    assert_eq!(
        full.narrow(narrowing(caps(MAX_CAPABILITIES_PER_CONTEXT + 1))?),
        Err(RegionError::CapacityExceeded("capabilities"))
    );
    Ok(())
}

// F7: MAX_EVENT_REGIONS and MAX_MODEL_CALL_REGIONS at bound and bound+1.
#[test]
fn test_review523_f7_bounds_event_and_model_call_multiplicity() -> Result<(), Box<dyn Error>> {
    let auth = test_root_authority()?;
    let now = TimestampNs(100);
    let (mut tree, _root_id, prop_id) = tree_with_property(&auth)?;

    for i in 0..MAX_EVENT_REGIONS {
        let id = RegionId::new(format!("event-{i:02}"))?;
        tree.attach_child(&prop_id, id, RegionKind::Event, auth.clone(), now)?;
    }
    let res = tree.attach_child(
        &prop_id,
        RegionId::new("event-overflow")?,
        RegionKind::Event,
        auth.clone(),
        now,
    );
    assert_eq!(
        res,
        Err(RegionError::MultiplicityExceeded {
            parent_kind: RegionKind::Property,
            child_kind: RegionKind::Event,
            max: MAX_EVENT_REGIONS,
        })
    );

    let event_id = RegionId::new("event-00")?;
    for i in 0..MAX_MODEL_CALL_REGIONS {
        let id = RegionId::new(format!("event-00-model-{i:02}"))?;
        tree.attach_child(&event_id, id, RegionKind::ModelCall, auth.clone(), now)?;
    }
    let res = tree.attach_child(
        &event_id,
        RegionId::new("event-00-model-overflow")?,
        RegionKind::ModelCall,
        auth.clone(),
        now,
    );
    assert_eq!(
        res,
        Err(RegionError::MultiplicityExceeded {
            parent_kind: RegionKind::Event,
            child_kind: RegionKind::ModelCall,
            max: MAX_MODEL_CALL_REGIONS,
        })
    );
    Ok(())
}

// F8: contract errors keep their specific variant and remain the error source.
#[test]
fn test_review523_f8_contract_errors_preserve_specific_variant() -> Result<(), Box<dyn Error>> {
    let cases = [
        ContractError::DigestMismatch,
        ContractError::UnknownClockBasis(7),
        ContractError::BudgetExhausted,
        ContractError::InvalidIdentifier,
    ];
    for err in cases {
        let region_err = RegionError::from(err.clone());
        assert_eq!(region_err, RegionError::Contract(err.clone()));
        assert!(region_err.to_string().contains(&err.to_string()));
        assert_eq!(
            Error::source(&region_err).map(ToString::to_string),
            Some(err.to_string())
        );
    }
    assert_ne!(
        RegionError::from(ContractError::DigestMismatch),
        RegionError::from(ContractError::BudgetExhausted)
    );
    Ok(())
}
