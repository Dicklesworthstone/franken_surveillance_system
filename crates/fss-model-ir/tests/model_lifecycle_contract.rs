#![forbid(unsafe_code)]
//! FSS-074 (`fss-x4a.14.5`) contract, property, fault, cancellation, crash-replay,
//! and end-to-end test suite for model qualification, shadow evaluation, authorized
//! two-phase activation, atomic reader snapshots (`FORMAL-007`), rollback,
//! quarantine, revocation, and anti-rollback enforcement.
//!
//! Emits structured `CAPLOG` records compatible with `scripts/e2e/lib.sh` and
//! `scripts/e2e/validate_log.py` (strictly zero secret-like keys, bounded size).

use std::error::Error;

use fss_core::effect::EffectAuthority;
use fss_core::{
    ContentDigest, ContractError, Generation, ModelGeneration, OperationId, ResourcePressure,
    TimestampNs,
};
use fss_model_ir::canonical::compute_model_ir_digest;
use fss_model_ir::graph::ModelIrGraph;
use fss_model_ir::invocation::{
    InputBinding, KernelAdmission, ModelInvocationSpec, execute, execute_with_admission, prepare,
};
use fss_model_ir::lifecycle::{
    LifecycleError, LifecycleJournalEntry, LifecyclePolicy, ModelGenerationDescriptor,
    ModelGenerationStage, ModelLifecycleManager, PendingTransitionState, QualificationReport,
    ReconciliationObservation, ShadowOutcome, TransitionKind, TransitionRequest,
    VerificationEvidence,
};
use fss_model_ir::node::GraphNode;
use fss_model_ir::op::OpCode;
use fss_model_ir::port::TensorPort;
use fss_model_ir::quotas::{InvocationQuota, InvocationQuotaLedger, MemoryAdmission};
use fss_tensor::{DType, Shape};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn emit_caplog(step: &str, verdict: bool, digest: ContentDigest, detail: &str) {
    let observed = if verdict { detail } else { "failed" };
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"exit\":{},\"verdict\":\"{}\",\"expected\":\"{detail}\",\"observed\":\"{observed}\",\"digest\":\"{}\"}}",
        if verdict { 0 } else { 1 },
        if verdict { "pass" } else { "fail" },
        digest.to_text(),
    );
}

fn port(name: &str, gen_num: u64) -> TestResult<TensorPort> {
    Ok(TensorPort::new(
        name,
        DType::F32,
        Shape::new(vec![4])?,
        Generation::from_u64(gen_num),
    )?)
}

fn build_detector_graph(
    graph_id: &str,
    gen_num: u64,
    with_sigmoid: bool,
) -> TestResult<ModelIrGraph> {
    let add = GraphNode::new(
        "n-add",
        OpCode::Add,
        "add",
        vec!["x".to_owned(), "y".to_owned()],
        vec!["sum".to_owned()],
        Default::default(),
    )?;
    let last_op = if with_sigmoid {
        GraphNode::new(
            "n-act",
            OpCode::Sigmoid,
            "sigmoid",
            vec!["sum".to_owned()],
            vec!["out".to_owned()],
            Default::default(),
        )?
    } else {
        GraphNode::new(
            "n-act",
            OpCode::Relu,
            "relu",
            vec!["sum".to_owned()],
            vec!["out".to_owned()],
            Default::default(),
        )?
    };
    Ok(
        ModelIrGraph::builder(graph_id, Generation::from_u64(gen_num))
            .add_input(port("x", gen_num)?)
            .add_input(port("y", gen_num)?)
            .add_output(port("out", gen_num)?)
            .add_node(add)
            .add_node(last_op)
            .build_and_validate()?,
    )
}

fn descriptor_for(
    gen_name: &str,
    order: u64,
    graph: &ModelIrGraph,
) -> TestResult<ModelGenerationDescriptor> {
    Ok(ModelGenerationDescriptor {
        generation: ModelGeneration::parse(gen_name)?,
        sequence_order: order,
        model_root: ContentDigest::sha256(format!("pkg:{gen_name}:{order}").as_bytes()),
        ir_digest: compute_model_ir_digest(graph)?,
        ir_generation: graph.generation(),
        preprocess_generation: Generation::from_u64(order),
        calibration_generation: Some(Generation::from_u64(order)),
        license_policy_digest: ContentDigest::sha256(b"license:apache2:owner-private-site"),
        use_profile: "owner_private_site".to_owned(),
        device_generation: "device:cpu-x86_64-v1".to_owned(),
        kernel_generation: "kernel:scalar-ref-v1".to_owned(),
        numeric_contract: "numeric:bit-exact-f32-v1".to_owned(),
    })
}

fn invocation_spec(desc: &ModelGenerationDescriptor, seed: &[u8]) -> ModelInvocationSpec {
    ModelInvocationSpec {
        model_root: desc.model_root,
        preprocess_generation: desc.preprocess_generation,
        calibration_generation: desc.calibration_generation,
        inputs: vec![
            InputBinding {
                name: "x".to_owned(),
                digest: ContentDigest::sha256(seed),
                generation: desc.ir_generation,
                declared_bytes: Some(16),
            },
            InputBinding {
                name: "y".to_owned(),
                digest: ContentDigest::sha256(b"input-y-fixed"),
                generation: desc.ir_generation,
                declared_bytes: Some(16),
            },
        ],
        max_nodes: 32,
    }
}

fn verified_evidence(label: &str) -> VerificationEvidence {
    VerificationEvidence {
        package_verification_digest: ContentDigest::sha256(label.as_bytes()),
        license_approved: true,
        profile_approved: true,
        offline_only_verified: true,
    }
}

fn passing_qualification(label: &str) -> QualificationReport {
    QualificationReport {
        suite_digest: ContentDigest::sha256(format!("suite:{label}").as_bytes()),
        contract_basis_digest: ContentDigest::sha256(b"basis:fss.v1"),
        passed_cases: 12,
        failed_cases: 0,
        abstained_cases: 0,
        quarantined_cases: 0,
        max_observed_pressure: ResourcePressure::Nominal,
    }
}

fn auth(cap: &str, fence: u64) -> TestResult<EffectAuthority> {
    Ok(EffectAuthority::new("operator:alice", cap, Some(fence))?)
}

fn basis() -> ContentDigest {
    ContentDigest::sha256(b"contract_basis:fss.v1")
}

/// Helper: stage -> verify -> qualify -> start_shadow -> 1 matched shadow run.
fn prepare_shadowed_candidate(
    mgr: &mut ModelLifecycleManager,
    desc: &ModelGenerationDescriptor,
    graph: &ModelIrGraph,
    baseline_receipt: Option<&fss_model_ir::invocation::ModelReceipt>,
    t0: i128,
) -> TestResult {
    mgr.stage_generation(desc.clone(), TimestampNs(t0))?;
    mgr.verify_generation(
        &desc.generation,
        graph,
        verified_evidence(desc.generation.as_str()),
        TimestampNs(t0 + 1),
    )?;
    let qual = mgr.qualify_generation(
        &desc.generation,
        passing_qualification(desc.generation.as_str()),
        TimestampNs(t0 + 2),
    )?;
    assert!(!qual.grants_activation_authority);
    mgr.start_shadow(&desc.generation, TimestampNs(t0 + 3))?;
    let spec = invocation_spec(desc, b"shadow-input-1");
    let receipt = execute(graph, &prepare(graph, &spec)?)?;
    let outcome = mgr.record_shadow_run(
        &desc.generation,
        &receipt,
        baseline_receipt,
        TimestampNs(t0 + 4),
    )?;
    assert_eq!(outcome, ShadowOutcome::Matched);
    Ok(())
}

#[test]
fn full_vertical_lifecycle_atomic_snapshots_and_rollback() -> TestResult {
    let mut mgr = ModelLifecycleManager::new(LifecyclePolicy::default())?;
    let g1 = build_detector_graph("graph:detector", 1, false)?;
    let g2 = build_detector_graph("graph:detector", 2, false)?;
    let d1 = descriptor_for("model:detector:v1", 1, &g1)?;
    let d2 = descriptor_for("model:detector:v2", 2, &g2)?;

    // Idempotent re-staging of identical descriptor works; conflicting descriptor is refused.
    let dig1 = mgr.stage_generation(d1.clone(), TimestampNs(10))?;
    assert_eq!(mgr.stage_generation(d1.clone(), TimestampNs(11))?, dig1);
    let mut conflicting = d1.clone();
    conflicting.model_root = ContentDigest::sha256(b"forged-weights");
    assert!(matches!(
        mgr.stage_generation(conflicting, TimestampNs(12)),
        Err(LifecycleError::GenerationConflict { .. })
    ));

    // Verify -> Qualify -> Shadow -> Prepare Activation -> Commit Activation for v1.
    mgr.verify_generation(
        &d1.generation,
        &g1,
        verified_evidence("v1"),
        TimestampNs(13),
    )?;
    let q1 =
        mgr.qualify_generation(&d1.generation, passing_qualification("v1"), TimestampNs(14))?;
    assert!(!q1.grants_activation_authority);
    // Cannot activate directly from Qualified while require_shadow_before_activate is true.
    assert!(matches!(
        mgr.prepare_activation(
            TransitionRequest {
                operation_id: OperationId::parse("op:act-v1-early")?,
                target_generation: d1.generation.clone(),
                contract_basis_digest: basis(),
                authority: auth("model:activate", 1)?,
            },
            ResourcePressure::Nominal,
            false,
            TimestampNs(15),
        ),
        Err(LifecycleError::InvalidStage {
            current: ModelGenerationStage::Qualified,
            ..
        })
    ));

    mgr.start_shadow(&d1.generation, TimestampNs(16))?;
    // Shadowing with 0 samples still blocks activation.
    let ev_zero = mgr.shadow_decision_evidence(&d1.generation)?;
    assert!(!ev_zero.shadow_gate_satisfied);
    assert!(!ev_zero.grants_activation_authority);
    assert!(matches!(
        mgr.prepare_activation(
            TransitionRequest {
                operation_id: OperationId::parse("op:act-v1-0samples")?,
                target_generation: d1.generation.clone(),
                contract_basis_digest: basis(),
                authority: auth("model:activate", 1)?,
            },
            ResourcePressure::Nominal,
            false,
            TimestampNs(17),
        ),
        Err(LifecycleError::ShadowGateNotMet { .. })
    ));

    // Execute real FSS-072/FSS-073 quota-metered invocation for shadow evidence.
    let mut quota = InvocationQuotaLedger::new(
        InvocationQuota {
            max_invocations: 10,
            max_total_nodes: 100,
        },
        MemoryAdmission::NominalOnly,
    );
    let s1 = invocation_spec(&d1, b"frame-001");
    let p1 = quota.prepare(&g1, &s1, ResourcePressure::Nominal)?;
    let r1 = quota.execute_and_debit(&g1, &p1, TimestampNs(18))?;
    assert_eq!(
        mgr.record_shadow_run(&d1.generation, &r1, None, TimestampNs(19))?,
        ShadowOutcome::Matched
    );
    let ev_ready = mgr.shadow_decision_evidence(&d1.generation)?;
    assert!(ev_ready.shadow_gate_satisfied);
    assert!(!ev_ready.grants_activation_authority);
    assert!(mgr.reader_snapshot().is_none(), "shadow never activates");

    // Two-phase activation for v1.
    let prep1 = mgr.prepare_activation(
        TransitionRequest {
            operation_id: OperationId::parse("op:act-v1")?,
            target_generation: d1.generation.clone(),
            contract_basis_digest: basis(),
            authority: auth("model:activate", 1)?,
        },
        ResourcePressure::Nominal,
        false,
        TimestampNs(20),
    )?;
    assert!(
        mgr.reader_snapshot().is_none(),
        "prepare must not mutate reader snapshot"
    );
    let rec1 = mgr.commit_transition(prep1.plan_digest, 0, false, TimestampNs(21))?;
    assert_eq!(rec1.snapshot.activation_epoch, 1);
    assert_eq!(rec1.snapshot.active, d1);
    assert_eq!(rec1.snapshot.rollback_target, None);

    // FORMAL-007: Reader A pins snapshot at epoch 1 BEFORE v2 activates.
    let reader_a_snap = mgr
        .reader_snapshot()
        .ok_or("active snapshot missing after v1 commit")?;
    assert!(mgr.is_snapshot_current(&reader_a_snap));

    // Stage/verify/qualify/shadow v2 against v1 baseline on the exact same input -> Matched.
    let base_shadow_spec = invocation_spec(&d1, b"shadow-input-1");
    let base_r1 = execute(&g1, &prepare(&g1, &base_shadow_spec)?)?;
    prepare_shadowed_candidate(&mut mgr, &d2, &g2, Some(&base_r1), 30)?;

    // Activate v2 atomically -> epoch 2; v1 becomes RetainedRollback.
    let prep2 = mgr.prepare_activation(
        TransitionRequest {
            operation_id: OperationId::parse("op:act-v2")?,
            target_generation: d2.generation.clone(),
            contract_basis_digest: basis(),
            authority: auth("model:activate", 2)?,
        },
        ResourcePressure::Elevated,
        false,
        TimestampNs(40),
    )?;
    let rec2 = mgr.commit_transition(prep2.plan_digest, 1, false, TimestampNs(41))?;
    assert_eq!(rec2.snapshot.activation_epoch, 2);
    assert_eq!(rec2.snapshot.active, d2);
    assert_eq!(rec2.snapshot.rollback_target, Some(d1.generation.clone()));
    assert_eq!(
        mgr.record(&d1.generation).map(|r| r.stage),
        Some(ModelGenerationStage::RetainedRollback)
    );

    // FORMAL-007 proof: Reader A's immutable snapshot is untouched (still epoch 1, v1)
    // and cleanly detects staleness, while Reader B sees atomic epoch 2 (v2).
    assert_eq!(reader_a_snap.activation_epoch, 1);
    assert_eq!(reader_a_snap.active, d1);
    assert!(!mgr.is_snapshot_current(&reader_a_snap));
    let reader_b_snap = mgr.reader_snapshot().ok_or("epoch 2 snapshot missing")?;
    assert!(mgr.is_snapshot_current(&reader_b_snap));
    assert_eq!(reader_b_snap.active, d2);

    // Rollback retention floor prevents retiring v1 while it is the sole rollback target.
    assert!(matches!(
        mgr.retire_generation(&d1.generation, auth("model:retire", 2)?, TimestampNs(42)),
        Err(LifecycleError::RetirementBlocked { .. })
    ));

    // Rollback to v1 succeeds even under Critical pressure (safety recovery control).
    let prep_rb = mgr.prepare_rollback(
        OperationId::parse("op:rb-v1")?,
        None,
        basis(),
        auth("model:rollback", 3)?,
        false,
        TimestampNs(50),
    )?;
    assert_eq!(prep_rb.kind, TransitionKind::Rollback);
    assert_eq!(prep_rb.target_generation, d1.generation);
    let rec_rb = mgr.commit_transition(prep_rb.plan_digest, 2, false, TimestampNs(51))?;
    assert_eq!(rec_rb.snapshot.activation_epoch, 3);
    assert_eq!(rec_rb.snapshot.active, d1);
    assert_eq!(rec_rb.snapshot.rollback_target, Some(d2.generation.clone()));
    assert_eq!(
        mgr.record(&d2.generation).map(|r| r.stage),
        Some(ModelGenerationStage::RetainedRollback)
    );
    assert!(!mgr.is_snapshot_current(&reader_b_snap));

    emit_caplog(
        "full_vertical_lifecycle_atomic_snapshots_and_rollback",
        true,
        mgr.state_digest(),
        "epoch=3_active=v1_rollback=v2",
    );
    Ok(())
}

#[test]
fn forbidden_latest_offline_license_ir_tamper_and_authority_refusals() -> TestResult {
    let mut mgr = ModelLifecycleManager::new(LifecyclePolicy::default())?;
    let g1 = build_detector_graph("graph:guard", 1, false)?;
    let g_tampered = build_detector_graph("graph:guard", 1, true)?;

    // Reject floating "latest" aliases in every form (INV-044 / ADR-0004):
    // short/uppercase/slash spellings are refused with InvalidIdentifier at parse,
    // while syntactically well-formed strings carrying a "latest" token are refused
    // fail-closed with ContractError::LatestNotResolvable at ModelGeneration::parse
    // (with defense-in-depth inside ModelLifecycleManager::stage_generation).
    for invalid_syntax in ["latest", "LATEST", "model/detector/latest"] {
        assert!(
            matches!(
                ModelGeneration::parse(invalid_syntax),
                Err(ContractError::InvalidIdentifier | ContractError::LatestNotResolvable)
            ),
            "invalid ModelGeneration syntax '{invalid_syntax}' must be rejected at parse"
        );
    }
    for alias in [
        "model:detector:latest",
        "model:latest:v1",
        "model:detector-latest",
        "detector.latest",
    ] {
        assert_eq!(
            ModelGeneration::parse(alias),
            Err(ContractError::LatestNotResolvable),
            "floating alias '{alias}' must be refused with LatestNotResolvable"
        );
    }

    let d1 = descriptor_for("model:guard:v1", 1, &g1)?;
    mgr.stage_generation(d1.clone(), TimestampNs(2))?;

    // Online/unapproved-license/unapproved-profile/tampered-IR all refused cleanly.
    let mut online_ev = verified_evidence("online");
    online_ev.offline_only_verified = false;
    assert!(matches!(
        mgr.verify_generation(&d1.generation, &g1, online_ev, TimestampNs(3)),
        Err(LifecycleError::VerificationFailed { .. })
    ));
    let mut no_lic = verified_evidence("no-lic");
    no_lic.license_approved = false;
    assert!(matches!(
        mgr.verify_generation(&d1.generation, &g1, no_lic, TimestampNs(4)),
        Err(LifecycleError::VerificationFailed { .. })
    ));
    assert!(matches!(
        mgr.verify_generation(
            &d1.generation,
            &g_tampered,
            verified_evidence("tamper"),
            TimestampNs(5)
        ),
        Err(LifecycleError::VerificationFailed { .. })
    ));
    assert_eq!(
        mgr.record(&d1.generation).map(|r| r.stage),
        Some(ModelGenerationStage::Staged),
        "failed verifications must never advance stage"
    );

    // Qualify -> shadow -> test wrong capability, stale lease fence, clock regression, pressure refusal.
    mgr.verify_generation(&d1.generation, &g1, verified_evidence("ok"), TimestampNs(6))?;
    mgr.qualify_generation(&d1.generation, passing_qualification("ok"), TimestampNs(7))?;
    mgr.start_shadow(&d1.generation, TimestampNs(8))?;
    let r1 = execute(&g1, &prepare(&g1, &invocation_spec(&d1, b"s"))?)?;
    mgr.record_shadow_run(&d1.generation, &r1, None, TimestampNs(9))?;

    // Clock regression refused.
    assert!(matches!(
        mgr.prepare_activation(
            TransitionRequest {
                operation_id: OperationId::parse("op:clock")?,
                target_generation: d1.generation.clone(),
                contract_basis_digest: basis(),
                authority: auth("model:activate", 5)?,
            },
            ResourcePressure::Nominal,
            false,
            TimestampNs(8),
        ),
        Err(LifecycleError::ClockRegression { .. })
    ));

    // Wrong capability refused.
    assert!(matches!(
        mgr.prepare_activation(
            TransitionRequest {
                operation_id: OperationId::parse("op:wrong-cap")?,
                target_generation: d1.generation.clone(),
                contract_basis_digest: basis(),
                authority: auth("model:rollback", 5)?,
            },
            ResourcePressure::Nominal,
            false,
            TimestampNs(10),
        ),
        Err(LifecycleError::AuthorityRefused { .. })
    ));

    // Constrained & Critical pressure refused under default RefuseConstrained policy.
    for pressure in [ResourcePressure::Constrained, ResourcePressure::Critical] {
        assert!(matches!(
            mgr.prepare_activation(
                TransitionRequest {
                    operation_id: OperationId::parse("op:pressure")?,
                    target_generation: d1.generation.clone(),
                    contract_basis_digest: basis(),
                    authority: auth("model:activate", 5)?,
                },
                pressure,
                false,
                TimestampNs(11),
            ),
            Err(LifecycleError::PressureRefused { pressure: p, .. }) if p == pressure
        ));
    }

    // Prepare with fence 5, cancel cleanly, then verify stale fence 4 is refused.
    let prep = mgr.prepare_activation(
        TransitionRequest {
            operation_id: OperationId::parse("op:fence-5")?,
            target_generation: d1.generation.clone(),
            contract_basis_digest: basis(),
            authority: auth("model:activate", 5)?,
        },
        ResourcePressure::Nominal,
        false,
        TimestampNs(12),
    )?;
    mgr.cancel_prepared_transition(prep.plan_digest, TimestampNs(13))?;
    assert!(mgr.pending_transition().is_none());
    assert!(matches!(
        mgr.prepare_activation(
            TransitionRequest {
                operation_id: OperationId::parse("op:fence-4")?,
                target_generation: d1.generation.clone(),
                contract_basis_digest: basis(),
                authority: auth("model:activate", 4)?,
            },
            ResourcePressure::Nominal,
            false,
            TimestampNs(14),
        ),
        Err(LifecycleError::AuthorityRefused { .. })
    ));

    emit_caplog(
        "forbidden_latest_offline_license_ir_tamper_and_authority_refusals",
        true,
        mgr.state_digest(),
        "all_negative_guards_enforced",
    );
    Ok(())
}

#[test]
fn shadow_divergence_abstention_quarantine_and_stale_receipts() -> TestResult {
    let mut mgr = ModelLifecycleManager::new(LifecyclePolicy::default())?;
    let g_base = build_detector_graph("graph:shadow", 1, false)?;
    let g_div = build_detector_graph("graph:shadow", 2, true)?; // Sigmoid != Relu -> diverges
    let d_base = descriptor_for("model:shadow:v1", 1, &g_base)?;
    let d_div = descriptor_for("model:shadow:v2", 2, &g_div)?;

    prepare_shadowed_candidate(&mut mgr, &d_base, &g_base, None, 10)?;
    let p_base = mgr.prepare_activation(
        TransitionRequest {
            operation_id: OperationId::parse("op:act-base")?,
            target_generation: d_base.generation.clone(),
            contract_basis_digest: basis(),
            authority: auth("model:activate", 1)?,
        },
        ResourcePressure::Nominal,
        false,
        TimestampNs(20),
    )?;
    mgr.commit_transition(p_base.plan_digest, 0, false, TimestampNs(21))?;

    mgr.stage_generation(d_div.clone(), TimestampNs(30))?;
    mgr.verify_generation(
        &d_div.generation,
        &g_div,
        verified_evidence("v2"),
        TimestampNs(31),
    )?;
    mgr.qualify_generation(
        &d_div.generation,
        passing_qualification("v2"),
        TimestampNs(32),
    )?;
    mgr.start_shadow(&d_div.generation, TimestampNs(33))?;

    // Stale receipt from v1 supplied to v2 shadow is refused.
    let base_receipt = execute(
        &g_base,
        &prepare(&g_base, &invocation_spec(&d_base, b"in"))?,
    )?;
    assert!(matches!(
        mgr.record_shadow_run(
            &d_div.generation,
            &base_receipt,
            Some(&base_receipt),
            TimestampNs(34)
        ),
        Err(LifecycleError::StaleGenerationReceipt { .. })
    ));

    // Real divergence between v2 (Sigmoid) and v1 (Relu) is recorded honestly & blocks activation.
    let div_receipt = execute(&g_div, &prepare(&g_div, &invocation_spec(&d_div, b"in"))?)?;
    let out_div = mgr.record_shadow_run(
        &d_div.generation,
        &div_receipt,
        Some(&base_receipt),
        TimestampNs(35),
    )?;
    assert!(matches!(out_div, ShadowOutcome::Diverged { .. }));

    // Real abstention (excluding Sigmoid from KernelAdmission) is recorded honestly.
    let abst_admission = KernelAdmission::admit_all().exclude_op(OpCode::Sigmoid.stable_id());
    let abst_receipt = execute_with_admission(
        &g_div,
        &prepare(&g_div, &invocation_spec(&d_div, b"in2"))?,
        &abst_admission,
    )?;
    let out_abst = mgr.record_shadow_run(
        &d_div.generation,
        &abst_receipt,
        Some(&base_receipt),
        TimestampNs(36),
    )?;
    assert!(matches!(out_abst, ShadowOutcome::CandidateAbstained { .. }));

    let ev = mgr.shadow_decision_evidence(&d_div.generation)?;
    assert!(!ev.shadow_gate_satisfied);
    assert_eq!(ev.summary.diverged_runs, 1);
    assert_eq!(ev.summary.abstained_runs, 1);
    assert_eq!(ev.divergence_ppm, 500_000);
    assert_eq!(ev.abstention_ppm, 500_000);
    assert!(matches!(
        mgr.prepare_activation(
            TransitionRequest {
                operation_id: OperationId::parse("op:act-div")?,
                target_generation: d_div.generation.clone(),
                contract_basis_digest: basis(),
                authority: auth("model:activate", 2)?,
            },
            ResourcePressure::Nominal,
            false,
            TimestampNs(37),
        ),
        Err(LifecycleError::ShadowGateNotMet { .. })
    ));

    // Quarantined shadow receipt triggers automatic quarantine of v2 while v1 stays active.
    let mut bad_receipt = div_receipt;
    bad_receipt.outcome = fss_model_ir::invocation::InvocationOutcome::Quarantined {
        reason: "nan output detected".to_owned(),
    };
    let out_q = mgr.record_shadow_run(&d_div.generation, &bad_receipt, None, TimestampNs(38))?;
    assert!(matches!(out_q, ShadowOutcome::CandidateQuarantined { .. }));
    assert_eq!(
        mgr.record(&d_div.generation).map(|r| r.stage),
        Some(ModelGenerationStage::Quarantined)
    );
    assert_eq!(
        mgr.reader_snapshot().map(|s| s.active.generation),
        Some(d_base.generation)
    );

    emit_caplog(
        "shadow_divergence_abstention_quarantine_and_stale_receipts",
        true,
        mgr.state_digest(),
        "diverged_abstained_quarantined_honest",
    );
    Ok(())
}

#[test]
fn cancellation_indeterminate_reconciliation_and_crash_replay_parity() -> TestResult {
    let mut mgr = ModelLifecycleManager::new(LifecyclePolicy::default())?;
    let g1 = build_detector_graph("graph:crash", 1, false)?;
    let g2 = build_detector_graph("graph:crash", 2, false)?;
    let d1 = descriptor_for("model:crash:v1", 1, &g1)?;
    let d2 = descriptor_for("model:crash:v2", 2, &g2)?;

    prepare_shadowed_candidate(&mut mgr, &d1, &g1, None, 10)?;
    prepare_shadowed_candidate(&mut mgr, &d2, &g2, None, 20)?;

    // Cancellation at prepare leaves zero state mutation.
    assert!(matches!(
        mgr.prepare_activation(
            TransitionRequest {
                operation_id: OperationId::parse("op:cancel-prep")?,
                target_generation: d1.generation.clone(),
                contract_basis_digest: basis(),
                authority: auth("model:activate", 1)?,
            },
            ResourcePressure::Nominal,
            true,
            TimestampNs(30),
        ),
        Err(LifecycleError::Cancelled { .. })
    ));
    assert!(mgr.pending_transition().is_none());

    // Cancellation at commit drains cleanly and cancels the pending plan.
    let p_cancel = mgr.prepare_activation(
        TransitionRequest {
            operation_id: OperationId::parse("op:cancel-commit")?,
            target_generation: d1.generation.clone(),
            contract_basis_digest: basis(),
            authority: auth("model:activate", 1)?,
        },
        ResourcePressure::Nominal,
        false,
        TimestampNs(31),
    )?;
    assert!(matches!(
        mgr.commit_transition(p_cancel.plan_digest, 0, true, TimestampNs(32)),
        Err(LifecycleError::Cancelled { .. })
    ));
    assert!(mgr.pending_transition().is_none());
    assert!(mgr.reader_snapshot().is_none());

    // Indeterminate commit (lost ACK) blocks conflicting prepares and cannot be cancelled;
    // survives crash/restart journal replay byte-identically; settles via reconciliation.
    let p_indet = mgr.prepare_activation(
        TransitionRequest {
            operation_id: OperationId::parse("op:indet-v1")?,
            target_generation: d1.generation.clone(),
            contract_basis_digest: basis(),
            authority: auth("model:activate", 2)?,
        },
        ResourcePressure::Nominal,
        false,
        TimestampNs(40),
    )?;
    mgr.mark_transition_indeterminate(
        p_indet.plan_digest,
        "commit ack lost before supervisor reply",
        TimestampNs(41),
    )?;
    assert!(matches!(
        mgr.pending_transition().map(|p| &p.state),
        Some(PendingTransitionState::Indeterminate { .. })
    ));
    assert!(matches!(
        mgr.cancel_prepared_transition(p_indet.plan_digest, TimestampNs(42)),
        Err(LifecycleError::PendingTransitionActive {
            indeterminate: true,
            ..
        })
    ));
    assert!(matches!(
        mgr.prepare_activation(
            TransitionRequest {
                operation_id: OperationId::parse("op:blocked-v2")?,
                target_generation: d2.generation.clone(),
                contract_basis_digest: basis(),
                authority: auth("model:activate", 3)?,
            },
            ResourcePressure::Nominal,
            false,
            TimestampNs(43),
        ),
        Err(LifecycleError::PendingTransitionActive {
            indeterminate: true,
            ..
        })
    ));

    // Crash/restart simulation: encode every journal entry to canonical bytes, decode, replay.
    let encoded: Vec<Vec<u8>> = mgr
        .journal()
        .iter()
        .map(LifecycleJournalEntry::to_canonical_bytes)
        .collect::<Result<_, _>>()?;
    let decoded: Vec<LifecycleJournalEntry> = encoded
        .iter()
        .map(|b| LifecycleJournalEntry::from_canonical_bytes(b))
        .collect::<Result<_, _>>()?;
    let mut restarted =
        ModelLifecycleManager::replay_journal(LifecyclePolicy::default(), &decoded)?;
    assert_eq!(restarted.state_digest(), mgr.state_digest());
    assert_eq!(restarted.pending_transition(), mgr.pending_transition());

    // Reconcile as ConfirmedNotCommitted on original -> stays inactive, allows retry.
    let rec_not = mgr.reconcile_indeterminate(
        p_indet.plan_digest,
        ReconciliationObservation::ConfirmedNotCommitted {
            evidence_digest: ContentDigest::sha256(b"proof:not-applied"),
        },
        TimestampNs(50),
    )?;
    assert!(rec_not.committed.is_none());
    assert!(mgr.reader_snapshot().is_none());

    // Reconcile as ConfirmedCommitted on restarted -> atomically activates v1 at epoch 1.
    let rec_yes = restarted.reconcile_indeterminate(
        p_indet.plan_digest,
        ReconciliationObservation::ConfirmedCommitted {
            evidence_digest: ContentDigest::sha256(b"proof:applied"),
        },
        TimestampNs(50),
    )?;
    let committed = rec_yes.committed.ok_or("expected committed receipt")?;
    assert_eq!(committed.snapshot.activation_epoch, 1);
    assert_eq!(committed.snapshot.active, d1);

    // Tampered journal entry is refused fail-closed on decode & replay.
    let mut tampered_bytes = encoded[0].clone();
    let last = tampered_bytes.len().saturating_sub(1);
    tampered_bytes[last] ^= 0x5A;
    assert!(matches!(
        LifecycleJournalEntry::from_canonical_bytes(&tampered_bytes),
        Err(LifecycleError::JournalCorrupt { .. })
    ));
    let mut truncated_reorder = decoded.clone();
    truncated_reorder.swap(0, 1);
    assert!(matches!(
        ModelLifecycleManager::replay_journal(LifecyclePolicy::default(), &truncated_reorder),
        Err(LifecycleError::JournalCorrupt { .. })
    ));

    emit_caplog(
        "cancellation_indeterminate_reconciliation_and_crash_replay_parity",
        true,
        restarted.state_digest(),
        "cancel_indet_replay_verified",
    );
    Ok(())
}

#[test]
fn active_quarantine_revocation_anti_rollback_and_retirement_tombstones() -> TestResult {
    let mut mgr = ModelLifecycleManager::new(LifecyclePolicy::default())?;
    let g1 = build_detector_graph("graph:sec", 1, false)?;
    let g2 = build_detector_graph("graph:sec", 2, false)?;
    let g3 = build_detector_graph("graph:sec", 3, false)?;
    let d1 = descriptor_for("model:sec:v1", 1, &g1)?;
    let d2 = descriptor_for("model:sec:v2", 2, &g2)?;
    let d3 = descriptor_for("model:sec:v3", 3, &g3)?;

    prepare_shadowed_candidate(&mut mgr, &d1, &g1, None, 10)?;
    let p1 = mgr.prepare_activation(
        TransitionRequest {
            operation_id: OperationId::parse("op:sec-v1")?,
            target_generation: d1.generation.clone(),
            contract_basis_digest: basis(),
            authority: auth("model:activate", 1)?,
        },
        ResourcePressure::Nominal,
        false,
        TimestampNs(20),
    )?;
    mgr.commit_transition(p1.plan_digest, 0, false, TimestampNs(21))?;

    prepare_shadowed_candidate(&mut mgr, &d2, &g2, None, 30)?;
    let p2 = mgr.prepare_activation(
        TransitionRequest {
            operation_id: OperationId::parse("op:sec-v2")?,
            target_generation: d2.generation.clone(),
            contract_basis_digest: basis(),
            authority: auth("model:activate", 2)?,
        },
        ResourcePressure::Nominal,
        false,
        TimestampNs(40),
    )?;
    mgr.commit_transition(p2.plan_digest, 1, false, TimestampNs(41))?;

    prepare_shadowed_candidate(&mut mgr, &d3, &g3, None, 50)?;
    let p3 = mgr.prepare_activation(
        TransitionRequest {
            operation_id: OperationId::parse("op:sec-v3")?,
            target_generation: d3.generation.clone(),
            contract_basis_digest: basis(),
            authority: auth("model:activate", 3)?,
        },
        ResourcePressure::Nominal,
        false,
        TimestampNs(60),
    )?;
    mgr.commit_transition(p3.plan_digest, 2, false, TimestampNs(61))?;
    assert_eq!(
        mgr.rollback_stack(),
        &[d1.generation.clone(), d2.generation.clone()]
    );

    // Quarantining active v3 fails closed (active_snapshot becomes None) and reports v2 as fallback,
    // without silently activating v2 until explicit rollback authority commits.
    let fallback = mgr.quarantine_generation(
        &d3.generation,
        "runtime OOM fault in detector host",
        TimestampNs(70),
    )?;
    assert_eq!(fallback, Some(d2.generation.clone()));
    assert!(
        mgr.reader_snapshot().is_none(),
        "active quarantine must fail closed"
    );

    // Revoking v1 with anti-rollback floor bump raises min_allowed_sequence_order to 2.
    let new_floor = mgr.revoke_generation(
        &d1.generation,
        auth("model:revoke", 4)?,
        "CVE in v1 calibration table",
        true,
        TimestampNs(75),
    )?;
    assert_eq!(new_floor, 2);
    assert_eq!(
        mgr.record(&d1.generation).map(|r| r.stage),
        Some(ModelGenerationStage::Revoked)
    );
    // Revoked generation cannot be re-staged or rolled back to.
    assert!(matches!(
        mgr.stage_generation(d1.clone(), TimestampNs(76)),
        Err(LifecycleError::GenerationConflict { .. })
    ));
    assert!(matches!(
        mgr.prepare_rollback(
            OperationId::parse("op:rb-revoked")?,
            Some(d1.generation.clone()),
            basis(),
            auth("model:rollback", 5)?,
            false,
            TimestampNs(77),
        ),
        Err(LifecycleError::InvalidStage {
            current: ModelGenerationStage::Revoked,
            ..
        })
    ));

    // Rollback to v2 succeeds; then retiring quarantined v3 succeeds and becomes a permanent tombstone.
    let p_rb = mgr.prepare_rollback(
        OperationId::parse("op:rb-v2")?,
        None,
        basis(),
        auth("model:rollback", 5)?,
        false,
        TimestampNs(80),
    )?;
    assert_eq!(p_rb.target_generation, d2.generation);
    let rb_receipt = mgr.commit_transition(p_rb.plan_digest, 3, false, TimestampNs(81))?;
    assert_eq!(rb_receipt.snapshot.activation_epoch, 4);
    assert_eq!(rb_receipt.snapshot.active, d2);

    mgr.retire_generation(&d3.generation, auth("model:retire", 6)?, TimestampNs(85))?;
    assert_eq!(
        mgr.record(&d3.generation).map(|r| r.stage),
        Some(ModelGenerationStage::Retired)
    );
    assert!(matches!(
        mgr.stage_generation(d3, TimestampNs(86)),
        Err(LifecycleError::GenerationConflict { .. })
    ));

    // Deterministic replay over the full security/quarantine/revocation/retirement history.
    let replayed =
        ModelLifecycleManager::replay_journal(LifecyclePolicy::default(), mgr.journal())?;
    assert_eq!(replayed.state_digest(), mgr.state_digest());
    assert_eq!(replayed.reader_snapshot(), mgr.reader_snapshot());
    assert_eq!(replayed.min_allowed_sequence_order(), 2);
    assert_eq!(replayed.metrics().activations, 3);
    assert_eq!(replayed.metrics().rollbacks, 1);
    assert_eq!(replayed.metrics().quarantines, 1);
    assert_eq!(replayed.metrics().revocations, 1);
    assert_eq!(replayed.metrics().retirements, 1);

    emit_caplog(
        "active_quarantine_revocation_anti_rollback_and_retirement_tombstones",
        true,
        mgr.state_digest(),
        "epoch=4_floor=2_tombstones_permanent",
    );
    Ok(())
}
