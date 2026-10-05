#![forbid(unsafe_code)]
//! Crate-internal tests for the two alert recovery transitions `fss-lab crash-matrix` found
//! missing (fss-2h5zq.15):
//!
//! - fss-51xqy: a cooperative cancellation at [`ReferenceDeployment::dispatch_alert`] drains the
//!   still-prepared operation to a terminal cancellation whose evidence the situation guard
//!   verifies, and a tampered or unrelated cooperative proof is refused.
//! - fss-mc9c4: a `Committed` operation with no provider record becomes `Indeterminate` with
//!   reason `restart_reconciliation_pending_observation` on reopen and in `reconcile_alert`; an
//!   operation whose provider record exists keeps the existing reconcile path.
//!
//! Neither transition ever dispatches: every test checks the provider's message and failure
//! counts. No-Claim: an in-process stop and a dropped handle stand in for process death.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::{
    BudgetVector, CapsuleId, CaptureInterval, ContentDigest, ContextAuthority, ContractBasis,
    ContractBasisRegistryBytes, ContractError, EffectState, EventId, HandoffId, IdempotencyKey,
    IndeterminateEffectReason, LedgerAnchor, MissionId, ObligationId, ObligationState, OperationId,
    PrincipalId, ProbabilityInterval, RootAuthoritySpec, SensorId, SessionId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};

use crate::reference_deployment::{STAGE_DISPATCH_ALERT, STAGE_PUBLISH_ROOT};
use crate::{
    ADP_REPLAY_ROW_ID, ALERT_COOPERATIVE_CANCEL_REASON, ALERT_COOPERATIVE_CANCEL_STAGES,
    CAPABILITY_EFFECT_RECONCILE, DeliveryPlan, DurableEffectError, MockModelScript, MockModelSpec,
    MockSemanticLabel, PrepareAlertParams, RESTART_RECONCILIATION_PENDING_OBSERVATION,
    ReferenceAlertPlan, ReferenceDeployment, ReferenceError, ReferenceEventReceipt,
    ReferenceModelObservation, ReferencePolicyDecision, ReferenceProviderBehavior,
    ReferenceSituation, ReferenceSituationRequest, ReplayCx, ReplayIoAuthority, VirtualCameraSpec,
    alert_cancel_proof, alert_cooperative_cancel_proof, execute_mock_model, run_reference_capture,
};

type TestResult = Result<(), Box<dyn Error>>;

const SITE: &str = "site:alert-recovery";
const T_PREPARE: i128 = 1_700_000_000;
const T_COMMIT: i128 = 1_700_000_010;
const T_OUTCOME: i128 = 1_700_000_020;
const T_SITUATION: i128 = 1_800_000_000;

fn test_cx(label: &str) -> Result<ReplayCx, Box<dyn Error>> {
    let spec = RootAuthoritySpec {
        trace_id: format!("trace:alert-recovery-{label}"),
        operation_id: OperationId::parse(format!("operation:alert-recovery-{label}"))?,
        principal: format!("operator:alert-recovery-{label}"),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"alert-recovery-anchor-universe"),
        generation: 1,
    };
    let root_auth = ContextAuthority::new_root(spec)?;
    let scratch_root = std::env::temp_dir().join(format!(
        "fss-alert-recovery-cx-{label}-{}",
        std::process::id()
    ));
    let io = ReplayIoAuthority::from_context_authority(&root_auth, scratch_root)?;
    Ok(ReplayCx::new(io))
}

fn fresh_root(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root =
        std::env::temp_dir().join(format!("fss-alert-recovery-{tag}-{}", std::process::id()));
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(root)
}

/// A policy decision corroborated by two independent virtual cameras, with its model receipts
/// staged in the deployment spool so the deployment can publish the event.
fn corroborated_decision(
    dep: &mut ReferenceDeployment,
    tag: &str,
    cx: &ReplayCx,
) -> Result<ReferencePolicyDecision, Box<dyn Error>> {
    let captures_path = std::env::temp_dir().join(format!(
        "fss-alert-recovery-captures-{tag}-{}.journal",
        std::process::id()
    ));
    match fs::remove_file(&captures_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut captures = DurableReferenceLedger::open(
        &captures_path,
        "site:alert-recovery-captures",
        IncompleteTailPolicy::Reject,
    )?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut observations = Vec::new();
    for (name, seed) in [("alpha", 111), ("beta", 222)] {
        let spec = VirtualCameraSpec {
            capture_id: CapsuleId::parse(format!("capture:cam:{name}"))?,
            sensor_id: SensorId::parse(format!("sensor:cam:{name}"))?,
            seed,
            packet_count: 2,
            packet_bytes: 32,
            start_ns: 10_000,
            period_ns: 1_000_000,
            uncertainty_ns: 1_000,
        };
        let capture = run_reference_capture(
            &spec,
            &DeliveryPlan::identity(spec.packet_count)?,
            &mut objects,
            &mut captures,
        )?;
        let model = MockModelSpec::new(
            format!("mock:cam:{name}:v1"),
            MockModelScript::Fixed {
                label: MockSemanticLabel::PersonLike,
                probability: ProbabilityInterval::new(0.99, 1.0)?,
            },
        )?;
        let result = execute_mock_model(&model, &capture, &mut objects)?;
        observations.push(ReferenceModelObservation::new(
            result,
            format!("power:cam:{name}"),
            CaptureInterval::new(TimestampNs(10_000), TimestampNs(20_000))?,
        )?);
    }
    let decision = dep.evaluate_policy(
        EventId::parse("event:unknown-presence:alert-recovery")?,
        observations,
        cx,
    )?;
    for receipt in &decision.event.model_receipts {
        let staged = dep.stage_payload(objects.read_verified(*receipt)?)?;
        assert_eq!(staged, *receipt);
    }
    drop(captures);
    fs::remove_file(&captures_path)?;
    Ok(decision)
}

/// A deployment holding one durably prepared alert, never committed.
struct Prepared {
    root: PathBuf,
    dep: ReferenceDeployment,
    decision: ReferencePolicyDecision,
    event_receipt: ReferenceEventReceipt,
    plan: ReferenceAlertPlan,
}

fn prepared(tag: &str) -> Result<Prepared, Box<dyn Error>> {
    let root = fresh_root(tag)?;
    let cx = test_cx(&format!("{tag}-setup"))?;
    let mut dep = ReferenceDeployment::open(&root, SITE, &cx)?;
    let decision = corroborated_decision(&mut dep, tag, &cx)?;
    let event_receipt = dep.publish_event(&decision, &cx)?;
    let plan = {
        let (effects, ledger) = dep.effects_and_ledger();
        effects.prepare_alert(PrepareAlertParams {
            decision: &decision,
            event_receipt: &event_receipt,
            authority: ledger,
            operation_id: OperationId::parse("op:alert:recovery:1")?,
            idempotency_key: IdempotencyKey::parse("idemp:alert:recovery:1")?,
            obligation_id: ObligationId::parse("ob:alert:recovery:1")?,
            channel: "simulated-channel".to_owned(),
            now: TimestampNs(T_PREPARE),
        })?
    };
    Ok(Prepared {
        root,
        dep,
        decision,
        event_receipt,
        plan,
    })
}

fn situation_request<'a>(
    decision: &'a ReferencePolicyDecision,
    event_receipt: &'a ReferenceEventReceipt,
    plan: &'a ReferenceAlertPlan,
) -> Result<ReferenceSituationRequest<'a>, Box<dyn Error>> {
    Ok(ReferenceSituationRequest {
        mission_id: MissionId::parse("mission:alert-recovery")?,
        session_id: SessionId::parse("session:alert-recovery")?,
        principal_id: PrincipalId::parse("principal:alert-recovery")?,
        objective_id: "objective:alert-recovery".to_owned(),
        revision: 1,
        contract_basis: ContractBasis::from_registry_bytes(
            ContractBasisRegistryBytes::new(
                b"schemas",
                b"operations",
                b"views",
                b"capabilities",
                b"errors",
                b"costs",
                "fss-reference:test",
            )
            .with_accepted_nightly("nightly-2026-08-31"),
        ),
        previous_anchor: None,
        predecessor_publication: None,
        decision,
        event_receipt,
        alert_plan: Some(plan),
        alert_outcome: None,
        coverage_witness: None,
        coverage_record: None,
        available_capabilities: [
            "capability:alert.prepare".to_owned(),
            "capability:alert.commit".to_owned(),
            CAPABILITY_EFFECT_RECONCILE.to_owned(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>(),
        created_at: TimestampNs(T_SITUATION),
    })
}

fn compile(fixture: &Prepared, label: &str) -> Result<ReferenceSituation, ReferenceError> {
    let cx = test_cx(label).map_err(|_| ReferenceError::InvalidSpec("test_cx"))?;
    let request = situation_request(&fixture.decision, &fixture.event_receipt, &fixture.plan)
        .map_err(|_| ReferenceError::InvalidSpec("situation_request"))?;
    fixture.dep.compile_situation(request, &cx)
}

fn provider_effects(dep: &ReferenceDeployment) -> usize {
    dep.alert_provider().message_count() + dep.alert_provider().failure_count()
}

fn state_of(dep: &ReferenceDeployment, plan: &ReferenceAlertPlan) -> Option<EffectState> {
    dep.effects()
        .operation(&plan.intent.operation_id)
        .map(|operation| operation.state)
}

fn obligation_of(dep: &ReferenceDeployment, plan: &ReferenceAlertPlan) -> Option<ObligationState> {
    dep.effects()
        .obligation(&plan.obligation_id)
        .map(|obligation| obligation.state)
}

fn projects_local_state(situation: &ReferenceSituation, plan: &ReferenceAlertPlan, state: &str) {
    let line = format!(
        "Local operation {} is {state}.",
        plan.intent.operation_id.as_str()
    );
    assert!(
        situation.capsule.frame.now.contains(&line),
        "missing `{line}` in {:?}",
        situation.capsule.frame.now
    );
}

fn assert_unverifiable(verdict: &Result<ReferenceSituation, ReferenceError>, case: &str) {
    assert!(
        matches!(
            verdict,
            Err(ReferenceError::UnverifiableCancellationEvidence { operation_id, .. })
                if operation_id.as_str() == "op:alert:recovery:1"
        ),
        "{case}: {:?}",
        verdict.as_ref().map(|_| "compiled")
    );
}

// ------------------------------------------------------------------ fss-51xqy cooperative cancel

#[test]
fn cooperative_cancel_at_dispatch_alert_drains_the_prepared_alert_to_a_verified_cancellation()
-> TestResult {
    let mut fixture = prepared("coop-cancel")?;
    assert_eq!(
        state_of(&fixture.dep, &fixture.plan),
        Some(EffectState::Prepared)
    );
    assert_eq!(
        obligation_of(&fixture.dep, &fixture.plan),
        Some(ObligationState::Pending)
    );

    let cx = test_cx("coop-cancel-dispatch")?;
    cx.request_cancellation();
    let verdict = fixture.dep.dispatch_alert(
        &fixture.plan,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(T_COMMIT),
        TimestampNs(T_OUTCOME),
        &cx,
    );
    assert!(
        matches!(
            verdict,
            Err(ReferenceError::CancellationRequested {
                stage: STAGE_DISPATCH_ALERT
            })
        ),
        "{verdict:?}"
    );
    // request -> drain -> finalize completed, and the provider was never called.
    assert!(cx.is_drain_completed());
    assert_eq!(provider_effects(&fixture.dep), 0);

    // The obligation is terminal: cancelled before any commitment, with the cooperative reason
    // and the cancellation proof the journal bound over the prepared record.
    let receipt = fixture
        .dep
        .effects()
        .operation(&fixture.plan.intent.operation_id)
        .ok_or("operation missing")?
        .clone();
    assert_eq!(receipt.state, EffectState::Cancelled);
    assert_eq!(receipt.committed_at, None);
    assert_eq!(receipt.updated_at, TimestampNs(T_COMMIT));
    assert_eq!(
        receipt.error_code.as_deref(),
        Some(ALERT_COOPERATIVE_CANCEL_REASON)
    );
    let prepared_record = fixture
        .dep
        .effects()
        .effect_journal()
        .prepared_record(&fixture.plan.intent.operation_id)?;
    assert_eq!(
        receipt.result_digest,
        Some(crate::alert::alert_cooperative_cancellation_proof(
            &prepared_record,
            &fixture.plan.authority_anchor,
            STAGE_DISPATCH_ALERT,
        ))
    );
    assert_eq!(
        obligation_of(&fixture.dep, &fixture.plan),
        Some(ObligationState::Cancelled)
    );

    // The situation guard verifies the cancellation and projects it as cancelled; the handoff
    // seals over it.
    let situation = compile(&fixture, "coop-cancel-situation")?;
    projects_local_state(&situation, &fixture.plan, "cancelled");
    let seal_cx = test_cx("coop-cancel-seal")?;
    let handoff = fixture.dep.seal_handoff(
        &situation,
        HandoffId::parse("handoff:alert-recovery:coop-cancel")?,
        TimestampNs(T_SITUATION),
        TimestampNs(T_SITUATION + 3_600_000_000_000),
        &seal_cx,
    )?;
    assert_ne!(handoff.handoff_root, ContentDigest::sha256(b""));

    // Reopen: the terminal cancellation replays exactly, restart reconciliation has nothing to
    // do, and a dispatch on an active context is refused before the provider is touched.
    let last_root = fixture.dep.effects().last_root();
    drop(fixture.dep);
    let cx = test_cx("coop-cancel-reopen")?;
    fixture.dep = ReferenceDeployment::reopen(&fixture.root, SITE, &cx)?;
    assert!(fixture.dep.restart_reclassified().is_empty());
    assert_eq!(fixture.dep.effects().last_root(), last_root);
    assert_eq!(
        obligation_of(&fixture.dep, &fixture.plan),
        Some(ObligationState::Cancelled)
    );
    let redispatch = fixture.dep.dispatch_alert(
        &fixture.plan,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(T_COMMIT + 100),
        TimestampNs(T_OUTCOME + 100),
        &cx,
    );
    assert!(
        matches!(
            &redispatch,
            Err(ReferenceError::DurableEffect(boxed))
                if matches!(**boxed, DurableEffectError::Contract(ContractError::InvalidEffectTransition))
        ),
        "{redispatch:?}"
    );
    assert_eq!(provider_effects(&fixture.dep), 0);
    let situation = compile(&fixture, "coop-cancel-situation-reopened")?;
    projects_local_state(&situation, &fixture.plan, "cancelled");

    drop(fixture.dep);
    fs::remove_dir_all(&fixture.root)?;
    Ok(())
}

#[test]
fn cooperative_cancel_never_touches_an_operation_past_prepared() -> TestResult {
    let mut fixture = prepared("coop-cancel-committed")?;
    let operation_id = fixture.plan.intent.operation_id.clone();
    fixture.dep.effects_mut().transition(
        &operation_id,
        EffectState::Committed,
        TimestampNs(T_COMMIT),
        None,
        None,
    )?;
    let root_before = fixture.dep.effects().last_root();
    let cx = test_cx("coop-cancel-committed-dispatch")?;
    cx.request_cancellation();
    let verdict = fixture.dep.dispatch_alert(
        &fixture.plan,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(T_COMMIT + 1),
        TimestampNs(T_OUTCOME),
        &cx,
    );
    assert!(
        matches!(
            verdict,
            Err(ReferenceError::CancellationRequested {
                stage: STAGE_DISPATCH_ALERT
            })
        ),
        "{verdict:?}"
    );
    assert!(cx.is_drain_completed());
    // A committed operation is never cancelled: nothing was written and nothing dispatched.
    assert_eq!(fixture.dep.effects().last_root(), root_before);
    assert_eq!(
        state_of(&fixture.dep, &fixture.plan),
        Some(EffectState::Committed)
    );
    assert_eq!(provider_effects(&fixture.dep), 0);
    drop(fixture.dep);
    fs::remove_dir_all(&fixture.root)?;
    Ok(())
}

#[test]
fn tampered_or_unrelated_cooperative_cancel_proofs_are_refused_by_the_guard() -> TestResult {
    let operation = OperationId::parse("op:alert:recovery:1")?;
    let other_operation = OperationId::parse("op:alert:recovery:other")?;
    assert_eq!(ALERT_COOPERATIVE_CANCEL_STAGES, &[STAGE_DISPATCH_ALERT]);

    // (case, evidence builder, reason, admitted)
    type Evidence = fn(&OperationId, &OperationId, &LedgerAnchor) -> ContentDigest;
    let cases: [(&str, Evidence, &str, bool); 7] = [
        (
            "control: cooperative proof at the registered stage",
            |op, _, anchor| alert_cooperative_cancel_proof(op, anchor, STAGE_DISPATCH_ALERT),
            ALERT_COOPERATIVE_CANCEL_REASON,
            true,
        ),
        (
            "tampered digest",
            |_, _, _| ContentDigest::sha256(b"tampered cooperative cancel proof"),
            ALERT_COOPERATIVE_CANCEL_REASON,
            false,
        ),
        (
            "proof of another operation",
            |_, other, anchor| alert_cooperative_cancel_proof(other, anchor, STAGE_DISPATCH_ALERT),
            ALERT_COOPERATIVE_CANCEL_REASON,
            false,
        ),
        (
            "unregistered cooperative stage",
            |op, _, anchor| alert_cooperative_cancel_proof(op, anchor, STAGE_PUBLISH_ROOT),
            ALERT_COOPERATIVE_CANCEL_REASON,
            false,
        ),
        (
            "anchor the ledger never published as the prepared anchor",
            |op, _, _| {
                alert_cooperative_cancel_proof(
                    op,
                    &LedgerAnchor::genesis(SITE),
                    STAGE_DISPATCH_ALERT,
                )
            },
            ALERT_COOPERATIVE_CANCEL_REASON,
            false,
        ),
        (
            "cooperative proof under another reason",
            |op, _, anchor| alert_cooperative_cancel_proof(op, anchor, STAGE_DISPATCH_ALERT),
            "stale_event_authority",
            false,
        ),
        (
            "undisplaced stale-authority proof under the cooperative reason",
            |op, _, anchor| alert_cancel_proof(op, anchor, anchor),
            ALERT_COOPERATIVE_CANCEL_REASON,
            false,
        ),
    ];
    for (index, (case, evidence, reason, admitted)) in cases.into_iter().enumerate() {
        let mut fixture = prepared(&format!("coop-proof-{index}"))?;
        let evidence = evidence(&operation, &other_operation, &fixture.plan.authority_anchor);
        fixture.dep.effects_mut().cancel(
            &operation,
            TimestampNs(T_COMMIT),
            evidence,
            Some(reason.to_owned()),
        )?;
        assert_eq!(
            obligation_of(&fixture.dep, &fixture.plan),
            Some(ObligationState::Cancelled),
            "{case}"
        );
        let verdict = compile(&fixture, &format!("coop-proof-{index}-situation"));
        if admitted {
            let situation = verdict.map_err(|error| format!("{case}: {error:?}"))?;
            projects_local_state(&situation, &fixture.plan, "cancelled");
        } else {
            assert_unverifiable(&verdict, case);
        }
        assert_eq!(provider_effects(&fixture.dep), 0, "{case}");
        drop(fixture.dep);
        fs::remove_dir_all(&fixture.root)?;
    }
    Ok(())
}

#[test]
fn cooperative_cancel_proof_binding_is_recomputed_from_the_prepared_record() -> TestResult {
    let fixture = prepared("coop-proof-binding")?;
    let prepared_record = fixture
        .dep
        .effects()
        .effect_journal()
        .prepared_record(&fixture.plan.intent.operation_id)?;
    let ledger = fixture.dep.ledger();
    let anchor = &fixture.plan.authority_anchor;
    let proof = crate::alert::alert_cooperative_cancellation_proof(
        &prepared_record,
        anchor,
        STAGE_DISPATCH_ALERT,
    );
    let bound = |proof, reason| {
        crate::alert::alert_cooperative_cancellation_is_bound(
            proof,
            reason,
            &prepared_record,
            &fixture.plan,
            ledger,
        )
    };
    assert!(bound(proof, Some(ALERT_COOPERATIVE_CANCEL_REASON)));
    assert!(!bound(proof, None));
    assert!(!bound(proof, Some("stale_event_authority")));
    // The bare evidence is not the proof: the proof binds the whole prepared record.
    assert!(!bound(
        alert_cooperative_cancel_proof(
            &fixture.plan.intent.operation_id,
            anchor,
            STAGE_DISPATCH_ALERT
        ),
        Some(ALERT_COOPERATIVE_CANCEL_REASON)
    ));
    // A prepared record at another time is another record.
    let mut later = prepared_record.clone();
    later.prepared_at = TimestampNs(T_PREPARE + 1);
    assert!(!bound(
        crate::alert::alert_cooperative_cancellation_proof(&later, anchor, STAGE_DISPATCH_ALERT),
        Some(ALERT_COOPERATIVE_CANCEL_REASON)
    ));
    drop(fixture.dep);
    fs::remove_dir_all(&fixture.root)?;
    Ok(())
}

// ------------------------------------------------------------- fss-mc9c4 restart reconciliation

/// Prepares, commits through the journal exactly as dispatch does before calling the provider,
/// then drops the deployment: the in-process stand-in for a kill between commit and dispatch.
fn committed_then_killed(tag: &str) -> Result<Prepared, Box<dyn Error>> {
    let mut fixture = prepared(tag)?;
    let operation_id = fixture.plan.intent.operation_id.clone();
    fixture.dep.effects_mut().transition(
        &operation_id,
        EffectState::Committed,
        TimestampNs(T_COMMIT),
        None,
        None,
    )?;
    assert_eq!(
        obligation_of(&fixture.dep, &fixture.plan),
        Some(ObligationState::Pending)
    );
    Ok(fixture)
}

#[test]
fn restart_reclassifies_a_committed_operation_without_provider_record_as_indeterminate()
-> TestResult {
    let mut fixture = committed_then_killed("restart-committed")?;
    drop(fixture.dep);

    let cx = test_cx("restart-committed-reopen")?;
    fixture.dep = ReferenceDeployment::reopen(&fixture.root, SITE, &cx)?;
    assert_eq!(
        fixture.dep.restart_reclassified(),
        std::slice::from_ref(&fixture.plan.intent.operation_id)
    );
    let receipt = fixture
        .dep
        .effects()
        .operation(&fixture.plan.intent.operation_id)
        .ok_or("operation missing")?
        .clone();
    assert_eq!(receipt.state, EffectState::Indeterminate);
    assert_eq!(receipt.committed_at, Some(TimestampNs(T_COMMIT)));
    // Deterministic: the instant after the committed record, derived from the journal alone.
    assert_eq!(receipt.updated_at, TimestampNs(T_COMMIT + 1));
    assert_eq!(
        receipt.error_code.as_deref(),
        Some(RESTART_RECONCILIATION_PENDING_OBSERVATION)
    );
    assert_eq!(
        receipt.indeterminate_reason,
        Some(IndeterminateEffectReason::Recorded(
            RESTART_RECONCILIATION_PENDING_OBSERVATION.to_owned()
        ))
    );
    assert_eq!(
        obligation_of(&fixture.dep, &fixture.plan),
        Some(ObligationState::Indeterminate)
    );
    assert_eq!(provider_effects(&fixture.dep), 0);

    // Idempotent: a second reopen finds nothing committed and writes nothing.
    let last_root = fixture.dep.effects().last_root();
    drop(fixture.dep);
    fixture.dep = ReferenceDeployment::reopen(&fixture.root, SITE, &cx)?;
    assert!(fixture.dep.restart_reclassified().is_empty());
    assert_eq!(fixture.dep.effects().last_root(), last_root);

    // Never re-dispatched: dispatch requires reconciliation, and reconcile with no provider
    // record leaves the indeterminate operation as it is.
    let redispatch = fixture.dep.dispatch_alert(
        &fixture.plan,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(T_COMMIT + 100),
        TimestampNs(T_OUTCOME + 100),
        &cx,
    );
    assert!(
        matches!(
            &redispatch,
            Err(ReferenceError::DurableEffect(boxed))
                if matches!(**boxed, DurableEffectError::Contract(ContractError::ReconciliationRequired))
        ),
        "{redispatch:?}"
    );
    let provider = fixture.dep.alert_provider().clone();
    let reconciled = fixture.dep.effects_mut().reconcile_alert(
        &fixture.plan,
        TimestampNs(T_OUTCOME + 200),
        &provider,
    )?;
    assert_eq!(reconciled, None);
    assert_eq!(fixture.dep.effects().last_root(), last_root);
    assert_eq!(provider_effects(&fixture.dep), 0);

    // The situation projects the explicit indeterminate state.
    let situation = compile(&fixture, "restart-committed-situation")?;
    projects_local_state(&situation, &fixture.plan, "indeterminate");

    drop(fixture.dep);
    fs::remove_dir_all(&fixture.root)?;
    Ok(())
}

#[test]
fn restart_reclassification_is_deterministic_across_fresh_roots() -> TestResult {
    let mut receipts = Vec::new();
    for tag in ["restart-det-a", "restart-det-b"] {
        let mut fixture = committed_then_killed(tag)?;
        drop(fixture.dep);
        let cx = test_cx(&format!("{tag}-reopen"))?;
        fixture.dep = ReferenceDeployment::reopen(&fixture.root, SITE, &cx)?;
        receipts.push(
            fixture
                .dep
                .effects()
                .operation(&fixture.plan.intent.operation_id)
                .ok_or("operation missing")?
                .receipt_digest(),
        );
        drop(fixture.dep);
        fs::remove_dir_all(&fixture.root)?;
    }
    assert_eq!(receipts.first(), receipts.get(1));
    Ok(())
}

#[test]
fn reconcile_alert_marks_a_committed_operation_without_provider_record_indeterminate() -> TestResult
{
    let mut fixture = committed_then_killed("reconcile-committed")?;
    let provider = fixture.dep.alert_provider().clone();
    let reconciled = fixture
        .dep
        .effects_mut()
        .reconcile_alert(&fixture.plan, TimestampNs(T_OUTCOME), &provider)?
        .ok_or("reconcile_alert left the committed operation pending")?;
    assert_eq!(reconciled.state, EffectState::Indeterminate);
    assert_eq!(reconciled.updated_at, TimestampNs(T_OUTCOME));
    assert_eq!(
        reconciled.error_code.as_deref(),
        Some(RESTART_RECONCILIATION_PENDING_OBSERVATION)
    );
    assert_eq!(
        obligation_of(&fixture.dep, &fixture.plan),
        Some(ObligationState::Indeterminate)
    );
    // Idempotent, and the provider was never called.
    let last_root = fixture.dep.effects().last_root();
    assert_eq!(
        fixture.dep.effects_mut().reconcile_alert(
            &fixture.plan,
            TimestampNs(T_OUTCOME + 1),
            &provider
        )?,
        None
    );
    assert_eq!(fixture.dep.effects().last_root(), last_root);
    let again = fixture
        .dep
        .effects_mut()
        .reclassify_committed_without_provider_record(&provider)?;
    assert!(again.is_empty());
    assert_eq!(provider_effects(&fixture.dep), 0);
    drop(fixture.dep);
    fs::remove_dir_all(&fixture.root)?;
    Ok(())
}

#[test]
fn a_committed_operation_with_a_delivery_record_keeps_the_existing_reconcile_path() -> TestResult {
    let mut fixture = committed_then_killed("record-delivered")?;
    // The provider delivered before the process stopped (same process: its record survives).
    let _ = fixture
        .dep
        .alert_provider_mut()
        .dispatch(&fixture.plan.intent, ReferenceProviderBehavior::Deliver);
    let provider = fixture.dep.alert_provider().clone();
    let proof = provider
        .lookup(&fixture.plan.intent)?
        .ok_or("delivery record missing")?
        .receipt_digest();

    // Restart reclassification leaves an operation whose provider record exists untouched.
    let last_root = fixture.dep.effects().last_root();
    let reclassified = fixture
        .dep
        .effects_mut()
        .reclassify_committed_without_provider_record(&provider)?;
    assert!(reclassified.is_empty());
    assert_eq!(fixture.dep.effects().last_root(), last_root);
    assert_eq!(
        state_of(&fixture.dep, &fixture.plan),
        Some(EffectState::Committed)
    );

    // The existing Committed branch: indeterminate, observed, verified with the provider proof.
    let reconciled = fixture
        .dep
        .effects_mut()
        .reconcile_alert(&fixture.plan, TimestampNs(T_OUTCOME), &provider)?
        .ok_or("reconcile_alert dropped the delivery record")?;
    assert_eq!(reconciled.state, EffectState::Verified);
    assert_eq!(reconciled.result_digest, Some(proof));
    assert_eq!(reconciled.updated_at, TimestampNs(T_OUTCOME + 2));
    assert_eq!(
        obligation_of(&fixture.dep, &fixture.plan),
        Some(ObligationState::Verified)
    );
    // Exactly the one delivery: reconciliation never dispatches.
    assert_eq!(fixture.dep.alert_provider().message_count(), 1);
    assert_eq!(fixture.dep.alert_provider().failure_count(), 0);
    drop(fixture.dep);
    fs::remove_dir_all(&fixture.root)?;
    Ok(())
}

#[test]
fn a_committed_operation_with_a_failure_record_keeps_the_existing_reconcile_path() -> TestResult {
    let mut fixture = committed_then_killed("record-failed")?;
    let _ = fixture.dep.alert_provider_mut().dispatch(
        &fixture.plan.intent,
        ReferenceProviderBehavior::FailBeforeDelivery,
    );
    let provider = fixture.dep.alert_provider().clone();
    let failure = provider
        .lookup_failure(&fixture.plan.intent)?
        .ok_or("failure record missing")?;
    let reclassified = fixture
        .dep
        .effects_mut()
        .reclassify_committed_without_provider_record(&provider)?;
    assert!(reclassified.is_empty());
    assert_eq!(
        state_of(&fixture.dep, &fixture.plan),
        Some(EffectState::Committed)
    );
    let reconciled = fixture
        .dep
        .effects_mut()
        .reconcile_alert(&fixture.plan, TimestampNs(T_OUTCOME), &provider)?
        .ok_or("reconcile_alert dropped the failure record")?;
    assert_eq!(reconciled.state, EffectState::Failed);
    assert_eq!(reconciled.result_digest, Some(failure.receipt_digest()));
    assert_eq!(
        obligation_of(&fixture.dep, &fixture.plan),
        Some(ObligationState::Failed)
    );
    assert_eq!(fixture.dep.alert_provider().message_count(), 0);
    assert_eq!(fixture.dep.alert_provider().failure_count(), 1);
    drop(fixture.dep);
    fs::remove_dir_all(&fixture.root)?;
    Ok(())
}
