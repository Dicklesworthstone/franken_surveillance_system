use std::error::Error;
use std::fs;

use fss_core::{
    CapsuleId, CaptureInterval, Completeness, ContractBasis, ContractBasisRegistryBytes,
    EffectJournal, EffectState, EventId, IdempotencyKey, MissionId, ObligationId, OperationId,
    PrincipalId, ProbabilityInterval, SensorId, SessionId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};

use crate::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, PrepareAlertParams,
    ReferenceAlertPlan, ReferenceError, ReferenceEventReceipt, ReferenceModelObservation,
    ReferencePolicyDecision, ReferenceSituationRequest, VirtualCameraSpec,
    compile_reference_situation, compile_reference_situation_with_operation_receipt,
    evaluate_unknown_presence, execute_mock_model, prepare_reference_alert,
    publish_reference_event, run_reference_capture,
};

const CAPABILITY_EFFECT_RECONCILE: &str = "capability:effect.reconcile";
const EFFECT_STATUS_AFFORDANCE: &str = "affordance:alert:effect-status";

struct GuardHarness {
    path: std::path::PathBuf,
    objects: InMemoryObjectStore,
    authority: DurableReferenceLedger,
}

impl GuardHarness {
    fn new(name: &str) -> Result<Self, Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!(
            "fss-reference-situation-guard-{}-{name}.journal",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        Ok(Self {
            authority: DurableReferenceLedger::open(
                &path,
                format!("site:situation-guard:{name}"),
                IncompleteTailPolicy::Reject,
            )?,
            objects: InMemoryObjectStore::new(ObjectLimits::new(2048, 32 * 1024 * 1024)),
            path,
        })
    }

    fn corroborated(
        &mut self,
        name: &str,
    ) -> Result<(ReferencePolicyDecision, ReferenceEventReceipt), Box<dyn Error>> {
        let mut observations = Vec::new();
        for (index, domain) in ["power:alpha", "power:beta"].iter().enumerate() {
            let spec = VirtualCameraSpec {
                capture_id: CapsuleId::parse(format!("capture:situation-guard:{name}:{index}"))?,
                sensor_id: SensorId::parse(format!("sensor:situation-guard:{name}:{index}"))?,
                seed: 71 + index as u64,
                packet_count: 3,
                packet_bytes: 32,
                start_ns: 1_000_000 * index as i128,
                period_ns: 1_000_000,
                uncertainty_ns: 100,
            };
            let capture = run_reference_capture(
                &spec,
                &DeliveryPlan::identity(spec.packet_count)?,
                &mut self.objects,
                &mut self.authority,
            )?;
            let result = execute_mock_model(
                &MockModelSpec::new(
                    format!("mock:situation-guard:{name}:{index}:v1"),
                    MockModelScript::Fixed {
                        label: MockSemanticLabel::PersonLike,
                        probability: ProbabilityInterval::new(0.9, 1.0)?,
                    },
                )?,
                &capture,
                &mut self.objects,
            )?;
            let first = capture
                .source_packets
                .first()
                .ok_or(ReferenceError::InvalidSpec("source_packet_count"))?;
            let last = capture
                .source_packets
                .last()
                .ok_or(ReferenceError::InvalidSpec("source_packet_count"))?;
            observations.push(ReferenceModelObservation::new(
                result,
                *domain,
                CaptureInterval::new(first.capture.earliest, last.capture.latest)?,
            )?);
        }
        let decision = evaluate_unknown_presence(
            EventId::parse(format!("event:situation-guard:{name}"))?,
            observations,
        )?;
        let receipt = publish_reference_event(&decision, &mut self.objects, &mut self.authority)?;
        Ok((decision, receipt))
    }

    fn cleanup(self) {
        let path = self.path.clone();
        drop(self);
        let _ = fs::remove_file(path);
    }
}

fn request<'a>(
    decision: &'a ReferencePolicyDecision,
    receipt: &'a ReferenceEventReceipt,
    capabilities: &[&str],
) -> Result<ReferenceSituationRequest<'a>, fss_core::ContractError> {
    Ok(ReferenceSituationRequest {
        mission_id: MissionId::parse("mission:situation-guard:test")?,
        session_id: SessionId::parse("session:situation-guard:test")?,
        principal_id: PrincipalId::parse("principal:situation-guard:test")?,
        objective_id: "objective:protect-reference-boundary".to_owned(),
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
        decision,
        event_receipt: receipt,
        alert_plan: None,
        alert_outcome: None,
        coverage_witness: None,
        available_capabilities: capabilities
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        created_at: TimestampNs(1_000),
    })
}

fn prepare(
    decision: &ReferencePolicyDecision,
    receipt: &ReferenceEventReceipt,
    authority: &DurableReferenceLedger,
    journal: &mut EffectJournal,
    name: &str,
) -> Result<ReferenceAlertPlan, Box<dyn Error>> {
    Ok(prepare_reference_alert(
        PrepareAlertParams {
            decision,
            event_receipt: receipt,
            authority,
            operation_id: OperationId::parse(format!("operation:situation-guard:{name}"))?,
            idempotency_key: IdempotencyKey::parse(format!("idempotency:situation-guard:{name}"))?,
            obligation_id: ObligationId::parse(format!("obligation:situation-guard:{name}"))?,
            channel: "operator:oncall".to_owned(),
            now: TimestampNs(100),
        },
        journal,
    )?)
}

#[test]
fn plan_without_receipt_never_exposes_commit() -> Result<(), Box<dyn Error>> {
    let mut harness = GuardHarness::new("missing-receipt")?;
    let (decision, receipt) = harness.corroborated("missing-receipt")?;
    let mut journal = EffectJournal::new();
    let plan = prepare(
        &decision,
        &receipt,
        &harness.authority,
        &mut journal,
        "missing-receipt",
    )?;
    let mut projection_request = request(
        &decision,
        &receipt,
        &["capability:alert.commit", CAPABILITY_EFFECT_RECONCILE],
    )?;
    projection_request.alert_plan = Some(&plan);
    let situation = compile_reference_situation(projection_request, &harness.authority)?;

    assert!(
        situation
            .capsule
            .affordances
            .iter()
            .all(|affordance| affordance.operation != "commit")
    );
    assert_eq!(
        situation.capsule.frame.next,
        vec![EFFECT_STATUS_AFFORDANCE.to_owned()]
    );
    assert_eq!(situation.capsule.completeness, Completeness::Partial);
    harness.cleanup();
    Ok(())
}

#[test]
fn exact_prepared_receipt_preserves_commit() -> Result<(), Box<dyn Error>> {
    let mut harness = GuardHarness::new("prepared")?;
    let (decision, receipt) = harness.corroborated("prepared")?;
    let mut journal = EffectJournal::new();
    let plan = prepare(
        &decision,
        &receipt,
        &harness.authority,
        &mut journal,
        "prepared",
    )?;
    let operation_receipt = journal
        .operation(&plan.intent.operation_id)
        .ok_or(fss_core::ContractError::NotFound)?
        .clone();
    let mut projection_request = request(
        &decision,
        &receipt,
        &["capability:alert.commit", CAPABILITY_EFFECT_RECONCILE],
    )?;
    projection_request.alert_plan = Some(&plan);
    let situation = compile_reference_situation_with_operation_receipt(
        projection_request,
        &operation_receipt,
        &harness.authority,
    )?;

    assert_eq!(operation_receipt.state, EffectState::Prepared);
    assert!(
        situation
            .capsule
            .affordances
            .iter()
            .any(|affordance| affordance.operation == "commit")
    );
    assert!(
        situation
            .proof_roots
            .contains(&operation_receipt.receipt_digest())
    );
    harness.cleanup();
    Ok(())
}

#[test]
fn forged_prepared_receipt_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut harness = GuardHarness::new("forged")?;
    let (decision, receipt) = harness.corroborated("forged")?;
    let mut journal = EffectJournal::new();
    let plan = prepare(
        &decision,
        &receipt,
        &harness.authority,
        &mut journal,
        "forged",
    )?;
    let mut forged = journal
        .operation(&plan.intent.operation_id)
        .ok_or(fss_core::ContractError::NotFound)?
        .clone();
    forged.committed_at = Some(TimestampNs(101));
    let mut projection_request = request(
        &decision,
        &receipt,
        &["capability:alert.commit", CAPABILITY_EFFECT_RECONCILE],
    )?;
    projection_request.alert_plan = Some(&plan);

    assert!(matches!(
        compile_reference_situation_with_operation_receipt(
            projection_request,
            &forged,
            &harness.authority,
        ),
        Err(ReferenceError::InvalidSpec(
            "situation_operation_receipt_integrity"
        ))
    ));
    harness.cleanup();
    Ok(())
}

#[test]
fn committed_receipt_exposes_status_instead_of_commit() -> Result<(), Box<dyn Error>> {
    let mut harness = GuardHarness::new("committed")?;
    let (decision, receipt) = harness.corroborated("committed")?;
    let mut journal = EffectJournal::new();
    let plan = prepare(
        &decision,
        &receipt,
        &harness.authority,
        &mut journal,
        "committed",
    )?;
    let operation_receipt = journal
        .transition(
            &plan.intent.operation_id,
            EffectState::Committed,
            TimestampNs(101),
            None,
            None,
        )?
        .clone();
    let mut projection_request = request(
        &decision,
        &receipt,
        &["capability:alert.commit", CAPABILITY_EFFECT_RECONCILE],
    )?;
    projection_request.alert_plan = Some(&plan);
    let situation = compile_reference_situation_with_operation_receipt(
        projection_request,
        &operation_receipt,
        &harness.authority,
    )?;

    assert!(
        situation
            .capsule
            .affordances
            .iter()
            .all(|affordance| affordance.operation != "commit")
    );
    assert_eq!(
        situation.capsule.frame.next,
        vec![EFFECT_STATUS_AFFORDANCE.to_owned()]
    );
    assert!(
        situation
            .capsule
            .frame
            .at_risk
            .iter()
            .any(|statement| statement.contains("before any new dispatch"))
    );
    harness.cleanup();
    Ok(())
}

// fss-deir9 G1: the local-state cell records the local journal state, not a proved external
// outcome, so a non-terminal local receipt is never a terminal effect.

fn guard_projection_spec() -> Result<crate::ReferenceProjectionSpec, Box<dyn Error>> {
    Ok(crate::ReferenceProjectionSpec {
        view_id: "AVIEW-001".to_owned(),
        available_resources: fss_core::BudgetVector::builder()
            .latency_ms(10_000)
            .tokens(50_000)
            .bytes(2_000_000)
            .model_calls(10)
            .cpu_millis(10_000)
            .accelerator_millis(10_000)
            .energy_millijoules(1_000_000)
            .network_bytes(1_000_000)
            .storage_operations(10_000)
            .privacy_exposure(10.0)
            .operator_attention_seconds(1_000.0)
            .build()?,
        reserved_resources: fss_core::BudgetVector::builder()
            .latency_ms(100)
            .tokens(100)
            .bytes(1_000)
            .storage_operations(1)
            .build()?,
        pressure: fss_core::ResourcePressure::Nominal,
        degraded_dimensions: std::collections::BTreeSet::new(),
        target_tokens: 25_000,
    })
}

/// Drives the plan's operation through legal journal transitions into `state`.
fn receipt_in_state(
    journal: &mut EffectJournal,
    plan: &ReferenceAlertPlan,
    state: EffectState,
) -> Result<fss_core::OperationReceipt, Box<dyn Error>> {
    let observed = fss_core::ContentDigest::sha256(b"situation-guard-observation");
    let committed = (EffectState::Committed, None, None);
    let accepted = (EffectState::AdapterAccepted, None, None);
    let observation = (EffectState::Observed, Some(observed), None);
    let steps: Vec<(EffectState, Option<fss_core::ContentDigest>, Option<String>)> = match state {
        EffectState::Prepared => Vec::new(),
        EffectState::Committed => vec![committed],
        EffectState::AdapterAccepted => vec![committed, accepted],
        EffectState::Observed => vec![committed, accepted, observation],
        EffectState::Verified => vec![
            committed,
            accepted,
            observation,
            (EffectState::Verified, Some(observed), None),
        ],
        EffectState::Failed => vec![
            committed,
            (
                EffectState::Failed,
                Some(observed),
                Some("provider_rejected".to_owned()),
            ),
        ],
        EffectState::Indeterminate => vec![
            committed,
            (
                EffectState::Indeterminate,
                None,
                Some("provider_timeout".to_owned()),
            ),
        ],
        EffectState::Cancelled => vec![(EffectState::Cancelled, Some(observed), None)],
    };
    let mut now = 100;
    for (next, digest, error) in steps {
        now += 1;
        let _ = journal.transition(
            &plan.intent.operation_id,
            next,
            TimestampNs(now),
            digest,
            error,
        )?;
    }
    Ok(journal
        .operation(&plan.intent.operation_id)
        .ok_or(fss_core::ContractError::NotFound)?
        .clone())
}

/// Compares the plan-only publication with the publication bound to a local receipt in `state`
/// and no canonical outcome.
fn local_receipt_delta(state: EffectState) -> Result<fss_core::MeaningfulDelta, Box<dyn Error>> {
    let name = format!("local-{}", state.as_str().replace('_', "-"));
    local_receipt_delta_via(&name, |journal, plan| {
        let operation_receipt = receipt_in_state(journal, plan, state)?;
        assert_eq!(operation_receipt.state, state);
        Ok(operation_receipt)
    })
}

type ReceiptResult = Result<fss_core::OperationReceipt, Box<dyn Error>>;

/// Like [`local_receipt_delta`], with the local receipt produced by `build` from the prepared plan.
fn local_receipt_delta_via<F>(
    name: &str,
    build: F,
) -> Result<fss_core::MeaningfulDelta, Box<dyn Error>>
where
    F: FnOnce(&mut EffectJournal, &ReferenceAlertPlan) -> ReceiptResult,
{
    let mut harness = GuardHarness::new(name)?;
    let (decision, receipt) = harness.corroborated(name)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &receipt, &harness.authority, &mut journal, name)?;
    let operation_receipt = build(&mut journal, &plan)?;
    let capabilities = ["capability:alert.commit", CAPABILITY_EFFECT_RECONCILE];

    let mut basis_request = request(&decision, &receipt, &capabilities)?;
    basis_request.alert_plan = Some(&plan);
    let basis = crate::project_reference_situation(
        compile_reference_situation(basis_request, &harness.authority)?,
        &guard_projection_spec()?,
    )?;
    let mut result_request = request(&decision, &receipt, &capabilities)?;
    result_request.alert_plan = Some(&plan);
    let result = crate::project_reference_situation(
        compile_reference_situation_with_operation_receipt(
            result_request,
            &operation_receipt,
            &harness.authority,
        )?,
        &guard_projection_spec()?,
    )?;
    let delta = crate::classify_reference_meaningful_delta(&basis, &result)?;
    harness.cleanup();
    Ok(delta)
}

/// The reviewer's probe, extended to every operation state the guard accepts short of a terminal
/// one: the local receipt is effect uncertainty and never a terminal transition.
#[test]
fn non_terminal_local_receipt_without_outcome_is_effect_uncertainty_not_terminal()
-> Result<(), Box<dyn Error>> {
    for state in [
        EffectState::Prepared,
        EffectState::Committed,
        EffectState::AdapterAccepted,
        EffectState::Observed,
        EffectState::Indeterminate,
    ] {
        let delta = local_receipt_delta(state)?;
        assert!(
            !delta
                .classes
                .contains(&fss_core::MeaningfulDeltaClass::TerminalTransition),
            "{} local receipt without an outcome is not terminal: {:?}",
            state.as_str(),
            delta.classes
        );
        assert!(
            delta
                .classes
                .contains(&fss_core::MeaningfulDeltaClass::EffectUncertainty),
            "{} local receipt without an outcome is effect uncertainty: {:?}",
            state.as_str(),
            delta.classes
        );
        assert!(
            delta
                .effect_uncertainty_changes
                .iter()
                .any(|change| change.contains(":local-state")),
            "{} local receipt must name the local-state claim: {:?}",
            state.as_str(),
            delta.effect_uncertainty_changes
        );
        delta.validate()?;
    }
    Ok(())
}

/// Control: a terminal local receipt is a proved terminal postcondition.
#[test]
fn terminal_local_receipt_is_a_terminal_effect() -> Result<(), Box<dyn Error>> {
    for state in [
        EffectState::Verified,
        EffectState::Failed,
        EffectState::Cancelled,
    ] {
        let delta = local_receipt_delta(state)?;
        assert!(
            delta
                .classes
                .contains(&fss_core::MeaningfulDeltaClass::TerminalTransition),
            "{} local receipt is terminal: {:?}",
            state.as_str(),
            delta.classes
        );
        assert!(
            !delta
                .effect_uncertainty_changes
                .iter()
                .any(|change| change.contains(":local-state")),
            "{} local receipt carries no local-state uncertainty: {:?}",
            state.as_str(),
            delta.effect_uncertainty_changes
        );
        delta.validate()?;
    }
    Ok(())
}

// fss-deir9 F3/F4: the guard accepts exactly the receipts the effect journal produces.

/// The receipt the journal reaches through reconciliation: committed, indeterminate with a
/// reason, then observed and reconciled to verified, keeping the reason as provenance.
fn reconciled_verified_receipt(
    journal: &mut EffectJournal,
    plan: &ReferenceAlertPlan,
) -> ReceiptResult {
    let operation_id = &plan.intent.operation_id;
    let observed = fss_core::ContentDigest::sha256(b"situation-guard-reconciled-observation");
    let _ = journal.transition(
        operation_id,
        EffectState::Committed,
        TimestampNs(101),
        None,
        None,
    )?;
    let _ = journal.mark_indeterminate(operation_id, TimestampNs(102), "provider_timeout")?;
    let _ = journal.transition(
        operation_id,
        EffectState::Observed,
        TimestampNs(103),
        Some(observed),
        None,
    )?;
    let reconciled = journal
        .reconcile_verified(operation_id, observed, TimestampNs(104))?
        .clone();
    assert_eq!(reconciled.state, EffectState::Verified);
    assert_eq!(reconciled.error_code.as_deref(), Some("provider_timeout"));
    Ok(reconciled)
}

#[test]
fn reconciled_verified_receipt_compiles_to_a_terminal_effect() -> Result<(), Box<dyn Error>> {
    let delta = local_receipt_delta_via("reconciled-verified", reconciled_verified_receipt)?;
    assert!(
        delta
            .classes
            .contains(&fss_core::MeaningfulDeltaClass::TerminalTransition),
        "a reconciled verified receipt is terminal: {:?}",
        delta.classes
    );
    assert!(
        !delta
            .effect_uncertainty_changes
            .iter()
            .any(|change| change.contains(":local-state")),
        "a reconciled verified receipt carries no local-state uncertainty: {:?}",
        delta.effect_uncertainty_changes
    );
    delta.validate()?;
    Ok(())
}

#[test]
fn cancelled_receipt_must_carry_the_journal_cancellation_proof() -> Result<(), Box<dyn Error>> {
    let name = "cancelled-proofless";
    let mut harness = GuardHarness::new(name)?;
    let (decision, receipt) = harness.corroborated(name)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &receipt, &harness.authority, &mut journal, name)?;
    // The journal refuses to cancel without a cancellation proof digest ...
    let refused = journal.transition(
        &plan.intent.operation_id,
        EffectState::Cancelled,
        TimestampNs(101),
        None,
        None,
    );
    assert!(
        matches!(refused, Err(fss_core::ContractError::EvidenceRequired)),
        "{refused:?}"
    );
    // ... so the guard refuses the same digest-less receipt built by hand.
    let mut forged = journal
        .operation(&plan.intent.operation_id)
        .ok_or(fss_core::ContractError::NotFound)?
        .clone();
    forged.state = EffectState::Cancelled;
    forged.updated_at = TimestampNs(101);
    let mut projection_request = request(
        &decision,
        &receipt,
        &["capability:alert.commit", CAPABILITY_EFFECT_RECONCILE],
    )?;
    projection_request.alert_plan = Some(&plan);
    let compiled = compile_reference_situation_with_operation_receipt(
        projection_request,
        &forged,
        &harness.authority,
    );
    assert!(
        matches!(
            compiled,
            Err(ReferenceError::InvalidSpec(
                "situation_operation_receipt_integrity"
            ))
        ),
        "{compiled:?}"
    );
    harness.cleanup();
    Ok(())
}

#[test]
fn indeterminate_without_a_reason_is_refused_by_journal_and_guard() -> Result<(), Box<dyn Error>> {
    let name = "indeterminate-reasonless";
    let mut harness = GuardHarness::new(name)?;
    let (decision, receipt) = harness.corroborated(name)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &receipt, &harness.authority, &mut journal, name)?;
    let operation_id = &plan.intent.operation_id;
    let committed = journal
        .transition(
            operation_id,
            EffectState::Committed,
            TimestampNs(101),
            None,
            None,
        )?
        .clone();
    let validated = journal.validate_transition(
        operation_id,
        EffectState::Indeterminate,
        TimestampNs(102),
        None,
        None,
    );
    assert!(
        matches!(validated, Err(fss_core::ContractError::EvidenceRequired)),
        "validate_transition: {validated:?}"
    );
    let refused = journal.transition(
        operation_id,
        EffectState::Indeterminate,
        TimestampNs(102),
        None,
        None,
    );
    assert!(
        matches!(refused, Err(fss_core::ContractError::EvidenceRequired)),
        "transition: {refused:?}"
    );

    let capabilities = ["capability:alert.commit", CAPABILITY_EFFECT_RECONCILE];
    let mut forged = committed;
    forged.state = EffectState::Indeterminate;
    forged.updated_at = TimestampNs(102);
    let mut forged_request = request(&decision, &receipt, &capabilities)?;
    forged_request.alert_plan = Some(&plan);
    let compiled = compile_reference_situation_with_operation_receipt(
        forged_request,
        &forged,
        &harness.authority,
    );
    assert!(
        matches!(
            compiled,
            Err(ReferenceError::InvalidSpec(
                "situation_operation_receipt_integrity"
            ))
        ),
        "guard: {compiled:?}"
    );

    // With a reason both the journal and the guard accept the indeterminate receipt.
    let marked = journal
        .mark_indeterminate(operation_id, TimestampNs(102), "provider_timeout")?
        .clone();
    let mut marked_request = request(&decision, &receipt, &capabilities)?;
    marked_request.alert_plan = Some(&plan);
    let _ = compile_reference_situation_with_operation_receipt(
        marked_request,
        &marked,
        &harness.authority,
    )?;
    harness.cleanup();
    Ok(())
}
