#![forbid(unsafe_code)]
//! Contract tests for runtime region ownership tree, context authority,
//! closure semantics, and formal invariants (FSS-021 / RUNTIME-REGION-TREE-001).
//!
//! Ref: FORMAL-001, INV-006, ERR-QUIESCENCE-001, ERR-AUTH-DENIED-001.

use std::error::Error;

use fss_core::region::*;
use fss_core::{
    BudgetQuantitiesSpec, BudgetQuantity, BudgetVector, ContentDigest, ERR_AUTH_DENIED_001,
    IdempotencyKey, Obligation, ObligationId, ObligationState, OperationId, TimestampNs,
};

// Helper: build a baseline root context authority
fn test_root_authority() -> Result<ContextAuthority, Box<dyn Error>> {
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

    let auth = ContextAuthority::new_root(RootAuthoritySpec {
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
    })?;
    Ok(auth)
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
    assert_eq!(res, Err(RegionError::DuplicateRegion(adapter_id)));
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
    let model_proof = tree.finalize(&model_id, TimestampNs(1_160_000))?;
    assert_eq!(model_proof.total_tasks, 1);

    tree.resolve_obligation(
        &alert_id,
        &alert_ob_id,
        ObligationState::Cancelled,
        Some(ContentDigest::sha256(b"cancelled-proof")),
        None,
    )?;
    let alert_proof = tree.finalize(&alert_id, TimestampNs(1_180_000))?;
    assert_eq!(alert_proof.total_obligations, 1);

    tree.finalize(
        &RegionId::new("event_00.evidence_window")?,
        TimestampNs(1_190_000),
    )?;
    tree.finalize(
        &RegionId::new("event_00.association")?,
        TimestampNs(1_190_000),
    )?;
    tree.finalize(&RegionId::new("event_00.policy")?, TimestampNs(1_190_000))?;

    let event_proof = tree.finalize(&event_id, TimestampNs(1_200_000))?;
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
    tree.finalize(&media_id, TimestampNs(1_230_000))?;

    tree.finalize(
        &RegionId::new("sensor_00.adapter_session")?,
        TimestampNs(1_240_000),
    )?;
    tree.finalize(&RegionId::new("sensor_00.receive")?, TimestampNs(1_240_000))?;
    tree.finalize(
        &RegionId::new("sensor_00.continuity")?,
        TimestampNs(1_240_000),
    )?;
    tree.finalize(
        &RegionId::new("sensor_00.analysis")?,
        TimestampNs(1_240_000),
    )?;
    tree.finalize(&RegionId::new("sensor_00.archive")?, TimestampNs(1_240_000))?;

    tree.finalize(&sensor_id, TimestampNs(1_250_000))?;

    let prop_id = RegionId::new("property.site_01")?;
    tree.request_drain(&prop_id, Some("property drain"), TimestampNs(1_260_000))?;

    tree.finalize(
        &RegionId::new("property.site_01.ledger")?,
        TimestampNs(1_270_000),
    )?;
    tree.finalize(
        &RegionId::new("property.site_01.object_store")?,
        TimestampNs(1_270_000),
    )?;
    tree.finalize(
        &RegionId::new("property.site_01.projection")?,
        TimestampNs(1_270_000),
    )?;
    tree.finalize(
        &RegionId::new("property.site_01.operations")?,
        TimestampNs(1_270_000),
    )?;

    tree.finalize(&prop_id, TimestampNs(1_280_000))?;

    let root_id = tree.root_id().clone();
    tree.request_drain(&root_id, Some("process shutdown"), TimestampNs(1_290_000))?;
    let root_proof = tree.finalize(&root_id, TimestampNs(1_300_000))?;

    assert_eq!(tree.get(&root_id)?.state, RegionState::Closed);
    assert_eq!(&root_proof.region_id, &root_id);

    assert_ne!(root_proof.proof_digest, ContentDigest::sha256(b""));
    assert_ne!(event_proof.proof_digest, ContentDigest::sha256(b""));
    Ok(())
}
