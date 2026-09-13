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
        predecessor_publication: None,
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

pub(crate) fn guard_projection_spec() -> Result<crate::ReferenceProjectionSpec, Box<dyn Error>> {
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
    result_request.predecessor_publication = Some(basis.publication_digest);
    crate::record_reference_publication(&mut harness.authority, &basis)?;
    let result = crate::project_reference_situation(
        compile_reference_situation_with_operation_receipt(
            result_request,
            &operation_receipt,
            &harness.authority,
        )?,
        &guard_projection_spec()?,
    )?;
    crate::record_reference_publication(&mut harness.authority, &result)?;
    let delta = crate::classify_reference_meaningful_delta_in_lineage(
        &basis,
        &result,
        &harness.authority,
        None,
    )?;
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

/// Compiles a situation bound to a `Committed` local receipt with no canonical outcome, so its
/// `local-state` effect cell is `indeterminate`, and returns that cell's claim identity.
fn indeterminate_local_situation(
    name: &str,
) -> Result<(GuardHarness, crate::ReferenceSituation, String), Box<dyn Error>> {
    let mut harness = GuardHarness::new(name)?;
    let (decision, receipt) = harness.corroborated(name)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &receipt, &harness.authority, &mut journal, name)?;
    let operation_receipt = receipt_in_state(&mut journal, &plan, EffectState::Committed)?;
    let mut compile_request = request(
        &decision,
        &receipt,
        &["capability:alert.commit", CAPABILITY_EFFECT_RECONCILE],
    )?;
    compile_request.alert_plan = Some(&plan);
    let situation = compile_reference_situation_with_operation_receipt(
        compile_request,
        &operation_receipt,
        &harness.authority,
    )?;
    let claim_id = format!("claim:effect:operation:situation-guard:{name}:local-state");
    let cell = situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id == claim_id)
        .ok_or(ReferenceError::InvalidSpec("missing_local_state_cell"))?;
    assert_eq!(
        cell.knowledge_state,
        fss_core::KnowledgeState::Indeterminate
    );
    assert_eq!(
        situation.effect_cell_kind(&claim_id),
        Some(crate::EffectCellKind::LocalState)
    );
    situation.verify()?;
    Ok((harness, situation, claim_id))
}

/// Asserts that `situation` is refused with `expected` by situation `verify`, by projection, and
/// by publication `verify` once the tampered situation is swapped into a verified publication.
fn assert_effect_tamper_refused(
    genuine: &crate::ReferenceSituation,
    tampered: crate::ReferenceSituation,
    expected: &ReferenceError,
) -> Result<(), Box<dyn Error>> {
    let same = |result: &Result<_, ReferenceError>| {
        result
            .as_ref()
            .err()
            .is_some_and(|error: &ReferenceError| error.to_string() == expected.to_string())
    };
    let verified = tampered.verify();
    assert!(same(&verified), "situation verify: {verified:?}");
    let projected = crate::project_reference_situation(tampered.clone(), &guard_projection_spec()?)
        .map(|publication| publication.publication_digest);
    assert!(same(&projected), "projection: {projected:?}");
    let mut publication =
        crate::project_reference_situation(genuine.clone(), &guard_projection_spec()?)?;
    publication.situation = tampered;
    let published = publication.verify();
    assert!(same(&published), "publication verify: {published:?}");
    Ok(())
}

/// fss-6sph6: an indeterminate compiled effect cannot be dropped from the situation, so a
/// projection cannot lose the reconciliation obligation without a terminal proof.
#[test]
fn compiled_indeterminate_effect_cannot_be_dropped() -> Result<(), Box<dyn Error>> {
    let (harness, genuine, claim_id) = indeterminate_local_situation("drop-effect")?;
    let mut tampered = genuine.clone();
    tampered
        .capsule
        .frame
        .knowledge_cells
        .retain(|cell| cell.claim_id != claim_id);
    assert_effect_tamper_refused(
        &genuine,
        tampered,
        &ReferenceError::InvalidSpec("situation_effect_cell_dropped"),
    )?;
    harness.cleanup();
    Ok(())
}

/// fss-6sph6: an indeterminate compiled effect cannot be relabeled, neither as an unproved state
/// that would park it nor as `known` that would terminalize it.
#[test]
fn compiled_indeterminate_effect_cannot_be_relabeled() -> Result<(), Box<dyn Error>> {
    let (harness, genuine, claim_id) = indeterminate_local_situation("relabel-effect")?;
    for state in [
        fss_core::KnowledgeState::Unknown,
        fss_core::KnowledgeState::NotApplicable,
        fss_core::KnowledgeState::Known,
    ] {
        let mut tampered = genuine.clone();
        for cell in &mut tampered.capsule.frame.knowledge_cells {
            if cell.claim_id == claim_id {
                cell.knowledge_state = state;
                cell.state_basis = None;
            }
        }
        assert_effect_tamper_refused(
            &genuine,
            tampered,
            &ReferenceError::InvalidSpec("situation_effect_cell_relabeled"),
        )?;
    }
    harness.cleanup();
    Ok(())
}

/// fss-6sph6: a second cell under a bound effect claim cannot shadow the compiled one.
#[test]
fn compiled_effect_cannot_be_shadowed_by_a_duplicate_claim() -> Result<(), Box<dyn Error>> {
    let (harness, genuine, claim_id) = indeterminate_local_situation("shadow-effect")?;
    let mut tampered = genuine.clone();
    let mut shadow = tampered
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id == claim_id)
        .cloned()
        .ok_or(ReferenceError::InvalidSpec("missing_local_state_cell"))?;
    shadow.knowledge_state = fss_core::KnowledgeState::Known;
    shadow.state_basis = None;
    tampered.capsule.frame.knowledge_cells.push(shadow);
    assert_effect_tamper_refused(
        &genuine,
        tampered,
        &ReferenceError::InvalidSpec("situation_effect_cell_duplicated"),
    )?;
    harness.cleanup();
    Ok(())
}

/// fss-6sph6: a bound effect's evidence root cannot be dropped from the proof roots, which would
/// seal a handoff without the receipt it cites.
#[test]
fn compiled_effect_evidence_cannot_leave_the_proof_roots() -> Result<(), Box<dyn Error>> {
    let (harness, genuine, claim_id) = indeterminate_local_situation("root-effect")?;
    let evidence = genuine
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id == claim_id)
        .map(|cell| cell.evidence.clone())
        .ok_or(ReferenceError::InvalidSpec("missing_local_state_cell"))?;
    assert!(!evidence.is_empty());
    let mut tampered = genuine.clone();
    for root in &evidence {
        tampered.proof_roots.remove(root);
    }
    assert_effect_tamper_refused(
        &genuine,
        tampered,
        &ReferenceError::Contract(fss_core::ContractError::IncompletePublicationGraph),
    )?;
    harness.cleanup();
    Ok(())
}

/// Compiles a guarded situation for `plan`, bound to `operation_receipt` when one is given and
/// carrying the canonical `outcome` when one is given, before any projection.
fn guarded_situation(
    harness: &GuardHarness,
    decision: &ReferencePolicyDecision,
    receipt: &ReferenceEventReceipt,
    plan: &ReferenceAlertPlan,
    operation_receipt: Option<&fss_core::OperationReceipt>,
    outcome: Option<&crate::ReferenceAlertOutcomeReceipt>,
) -> Result<crate::ReferenceSituation, Box<dyn Error>> {
    guarded_situation_after(
        harness,
        decision,
        receipt,
        plan,
        operation_receipt,
        outcome,
        None,
    )
}

/// Like [`guarded_situation`], continuing the publication `predecessor` when one is given.
fn guarded_situation_after(
    harness: &GuardHarness,
    decision: &ReferencePolicyDecision,
    receipt: &ReferenceEventReceipt,
    plan: &ReferenceAlertPlan,
    operation_receipt: Option<&fss_core::OperationReceipt>,
    outcome: Option<&crate::ReferenceAlertOutcomeReceipt>,
    continues: Option<&crate::ReferenceSituationPublication>,
) -> Result<crate::ReferenceSituation, Box<dyn Error>> {
    let mut compile_request = request(
        decision,
        receipt,
        &["capability:alert.commit", CAPABILITY_EFFECT_RECONCILE],
    )?;
    compile_request.alert_plan = Some(plan);
    compile_request.alert_outcome = outcome;
    compile_request.predecessor_publication =
        continues.map(|predecessor| predecessor.publication_digest);
    Ok(match operation_receipt {
        Some(operation_receipt) => compile_reference_situation_with_operation_receipt(
            compile_request,
            operation_receipt,
            &harness.authority,
        )?,
        None => compile_reference_situation(compile_request, &harness.authority)?,
    })
}

/// Compiles and projects a guarded publication for `plan` (see [`guarded_situation`]).
fn guarded_publication(
    harness: &GuardHarness,
    decision: &ReferencePolicyDecision,
    receipt: &ReferenceEventReceipt,
    plan: &ReferenceAlertPlan,
    operation_receipt: Option<&fss_core::OperationReceipt>,
    outcome: Option<&crate::ReferenceAlertOutcomeReceipt>,
) -> Result<crate::ReferenceSituationPublication, Box<dyn Error>> {
    Ok(crate::project_reference_situation(
        guarded_situation(harness, decision, receipt, plan, operation_receipt, outcome)?,
        &guard_projection_spec()?,
    )?)
}

/// One real alert lifecycle: publications bound to the prepared and to the dispatched receipt
/// (compiled before the outcome exists), and the verified receipt with its published outcome.
struct Lifecycle {
    harness: GuardHarness,
    decision: ReferencePolicyDecision,
    receipt: ReferenceEventReceipt,
    plan: ReferenceAlertPlan,
    prepared: crate::ReferenceSituationPublication,
    dispatched: crate::ReferenceSituationPublication,
    dispatched_situation: crate::ReferenceSituation,
    verified_receipt: fss_core::OperationReceipt,
    outcome: crate::ReferenceAlertOutcomeReceipt,
}

impl Lifecycle {
    fn new(name: &str) -> Result<Self, Box<dyn Error>> {
        let mut harness = GuardHarness::new(name)?;
        let (decision, receipt) = harness.corroborated(name)?;
        let mut journal = EffectJournal::new();
        let plan = prepare(&decision, &receipt, &harness.authority, &mut journal, name)?;
        let current = |journal: &EffectJournal| {
            journal
                .operation(&plan.intent.operation_id)
                .cloned()
                .ok_or(fss_core::ContractError::NotFound)
        };
        let prepared_receipt = current(&journal)?;
        let prepared = guarded_publication(
            &harness,
            &decision,
            &receipt,
            &plan,
            Some(&prepared_receipt),
            None,
        )?;
        let mut provider = crate::ReferenceAlertProvider::with_provider_id(format!(
            "provider:test:situation-guard:{name}"
        ));
        let _ = crate::dispatch_reference_alert(
            &plan,
            crate::ReferenceProviderBehavior::Deliver,
            TimestampNs(101),
            TimestampNs(102),
            &mut journal,
            &mut provider,
        )?;
        let dispatched_receipt = current(&journal)?;
        let dispatched_situation = guarded_situation(
            &harness,
            &decision,
            &receipt,
            &plan,
            Some(&dispatched_receipt),
            None,
        )?;
        let dispatched = crate::project_reference_situation(
            dispatched_situation.clone(),
            &guard_projection_spec()?,
        )?;
        let provider_receipt = provider
            .lookup(&plan.intent)?
            .ok_or(ReferenceError::InvalidSpec("missing_provider_receipt"))?;
        let _ = crate::observe_reference_alert(
            &plan,
            provider_receipt.receipt_digest(),
            TimestampNs(103),
            &mut journal,
            &provider,
        )?;
        let _ = crate::verify_reference_alert(&plan, TimestampNs(104), &mut journal, &provider)?;
        let verified_receipt = current(&journal)?;
        let outcome = crate::publish_reference_alert_outcome(
            &plan,
            &journal,
            &mut harness.objects,
            &mut harness.authority,
            &provider,
        )?;
        Ok(Self {
            harness,
            decision,
            receipt,
            plan,
            prepared,
            dispatched,
            dispatched_situation,
            verified_receipt,
            outcome,
        })
    }

    /// The verified situation as compiled, before projection adds its roots.
    fn verified_situation(
        &self,
        with_receipt: bool,
    ) -> Result<crate::ReferenceSituation, Box<dyn Error>> {
        guarded_situation(
            &self.harness,
            &self.decision,
            &self.receipt,
            &self.plan,
            with_receipt.then_some(&self.verified_receipt),
            Some(&self.outcome),
        )
    }

    /// The verified publication continuing `predecessor`, bound to the verified local receipt when
    /// `with_receipt`.
    fn verified_after(
        &self,
        with_receipt: bool,
        predecessor: &crate::ReferenceSituationPublication,
    ) -> Result<crate::ReferenceSituationPublication, Box<dyn Error>> {
        Ok(crate::project_reference_situation(
            guarded_situation_after(
                &self.harness,
                &self.decision,
                &self.receipt,
                &self.plan,
                with_receipt.then_some(&self.verified_receipt),
                Some(&self.outcome),
                Some(predecessor),
            )?,
            &guard_projection_spec()?,
        )?)
    }

    /// The verified publication, bound to the verified local receipt when `with_receipt`.
    fn verified(
        &self,
        with_receipt: bool,
    ) -> Result<crate::ReferenceSituationPublication, Box<dyn Error>> {
        guarded_publication(
            &self.harness,
            &self.decision,
            &self.receipt,
            &self.plan,
            with_receipt.then_some(&self.verified_receipt),
            Some(&self.outcome),
        )
    }
}

fn mentions_local_state(changes: &[String]) -> bool {
    changes.iter().any(|change| change.contains(":local-state"))
}

/// fss-6sph6 F1: dropping the local-state cell of an operation that the outcome cell still proves,
/// with the same outcome, is neither a proved-effect alarm nor an invalidated premise.
#[test]
fn dropping_a_cell_of_a_still_proved_operation_is_not_an_alarm() -> Result<(), Box<dyn Error>> {
    let mut lifecycle = Lifecycle::new("f1-drop")?;
    let basis = lifecycle.verified(true)?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &basis)?;
    let result = lifecycle.verified_after(false, &basis)?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &result)?;
    let delta = crate::classify_reference_meaningful_delta_in_lineage(
        &basis,
        &result,
        &lifecycle.harness.authority,
        None,
    )?;
    // Both sides stay `Partial` for reasons unrelated to the effect, so coverage loss is judged by
    // what it names, not by its class.
    for class in [
        fss_core::MeaningfulDeltaClass::TerminalTransition,
        fss_core::MeaningfulDeltaClass::PlanInvalidation,
        fss_core::MeaningfulDeltaClass::EffectUncertainty,
    ] {
        assert!(!delta.classes.contains(&class), "{class:?} in {:?}", delta);
    }
    assert!(
        !mentions_local_state(&delta.invalidated_assumptions),
        "{delta:?}"
    );
    assert!(!mentions_local_state(&delta.coverage_changes), "{delta:?}");
    delta.validate()?;
    lifecycle.harness.cleanup();
    Ok(())
}

/// fss-6sph6 F1 mirror: adding a local-state cell to an operation the basis already proved is not
/// a second terminal transition.
#[test]
fn adding_a_cell_to_an_already_proved_operation_is_not_terminal() -> Result<(), Box<dyn Error>> {
    let mut lifecycle = Lifecycle::new("f1-add")?;
    let basis = lifecycle.verified(false)?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &basis)?;
    let result = lifecycle.verified_after(true, &basis)?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &result)?;
    let delta = crate::classify_reference_meaningful_delta_in_lineage(
        &basis,
        &result,
        &lifecycle.harness.authority,
        None,
    )?;
    for class in [
        fss_core::MeaningfulDeltaClass::TerminalTransition,
        fss_core::MeaningfulDeltaClass::EffectUncertainty,
    ] {
        assert!(!delta.classes.contains(&class), "{class:?} in {:?}", delta);
    }
    delta.validate()?;
    lifecycle.harness.cleanup();
    Ok(())
}

/// fss-6sph6 F1: an indeterminate local-state cell superseded by a proved outcome for the same
/// operation resolves it; the operation is terminal and nothing reports it as still uncertain.
#[test]
fn proved_outcome_resolves_the_indeterminate_local_cell_it_supersedes() -> Result<(), Box<dyn Error>>
{
    let mut lifecycle = Lifecycle::new("f1-resolve")?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &lifecycle.dispatched)?;
    let result = lifecycle.verified_after(false, &lifecycle.dispatched)?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &result)?;
    let delta = crate::classify_reference_meaningful_delta_in_lineage(
        &lifecycle.dispatched,
        &result,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(
        delta
            .classes
            .contains(&fss_core::MeaningfulDeltaClass::TerminalTransition),
        "{delta:?}"
    );
    assert!(
        delta.effect_uncertainty_changes.iter().any(|change| change
            .starts_with("effect uncertainty resolved: indeterminate effect ")
            && change.contains(":local-state")),
        "{delta:?}"
    );
    assert!(
        !delta
            .effect_uncertainty_changes
            .iter()
            .any(|change| change.starts_with("effect uncertainty remains: ")),
        "{delta:?}"
    );
    assert!(!mentions_local_state(&delta.coverage_changes), "{delta:?}");
    delta.validate()?;
    lifecycle.harness.cleanup();
    Ok(())
}

/// fss-6sph6 F1: an unproved (prepared) local-state cell superseded by a proved outcome for the
/// same operation is not reported as an unproved effect that disappeared.
#[test]
fn proved_outcome_supersedes_the_unproved_local_cell() -> Result<(), Box<dyn Error>> {
    let mut lifecycle = Lifecycle::new("f1-supersede")?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &lifecycle.prepared)?;
    let result = lifecycle.verified_after(false, &lifecycle.prepared)?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &result)?;
    let delta = crate::classify_reference_meaningful_delta_in_lineage(
        &lifecycle.prepared,
        &result,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(
        delta
            .classes
            .contains(&fss_core::MeaningfulDeltaClass::TerminalTransition),
        "{delta:?}"
    );
    assert!(
        !mentions_local_state(&delta.effect_uncertainty_changes),
        "{delta:?}"
    );
    assert!(!mentions_local_state(&delta.coverage_changes), "{delta:?}");
    delta.validate()?;
    lifecycle.harness.cleanup();
    Ok(())
}

/// fss-6sph6 F2: the same operation proved succeeded in the basis and failed in the result is a
/// contradiction of its terminal proof, never a near-silent material change.
#[test]
fn terminal_outcome_flip_of_one_operation_is_a_contradiction() -> Result<(), Box<dyn Error>> {
    let name = "f2-flip";
    let mut harness = GuardHarness::new(name)?;
    let (decision, receipt) = harness.corroborated(name)?;
    let mut verified_journal = EffectJournal::new();
    let mut failed_journal = EffectJournal::new();
    let plan = prepare(
        &decision,
        &receipt,
        &harness.authority,
        &mut verified_journal,
        name,
    )?;
    let failed_plan = prepare(
        &decision,
        &receipt,
        &harness.authority,
        &mut failed_journal,
        name,
    )?;
    assert_eq!(plan, failed_plan);
    let verified = receipt_in_state(&mut verified_journal, &plan, EffectState::Verified)?;
    let failed = receipt_in_state(&mut failed_journal, &plan, EffectState::Failed)?;
    let basis = guarded_publication(&harness, &decision, &receipt, &plan, Some(&verified), None)?;
    crate::record_reference_publication(&mut harness.authority, &basis)?;
    let result = crate::project_reference_situation(
        guarded_situation_after(
            &harness,
            &decision,
            &receipt,
            &plan,
            Some(&failed),
            None,
            Some(&basis),
        )?,
        &guard_projection_spec()?,
    )?;
    crate::record_reference_publication(&mut harness.authority, &result)?;
    let delta = crate::classify_reference_meaningful_delta_in_lineage(
        &basis,
        &result,
        &harness.authority,
        None,
    )?;
    let expected = format!(
        "effect outcome contradicted: operation {} was proved succeeded and is now proved failed",
        plan.intent.operation_id.as_str()
    );
    assert!(delta.silence_certificate.is_none(), "{delta:?}");
    for class in [
        fss_core::MeaningfulDeltaClass::Contradiction,
        fss_core::MeaningfulDeltaClass::EffectUncertainty,
    ] {
        assert!(
            delta.classes.contains(&class),
            "{class:?} missing: {delta:?}"
        );
    }
    assert!(
        delta.effect_uncertainty_changes.contains(&expected),
        "missing {expected:?} in {:?}",
        delta.effect_uncertainty_changes
    );
    assert!(
        !delta
            .classes
            .contains(&fss_core::MeaningfulDeltaClass::TerminalTransition),
        "{delta:?}"
    );
    delta.validate()?;
    harness.cleanup();
    Ok(())
}

/// Review probe P2: bindings are sealed to the situation they were compiled for. A verified outcome
/// cell transplanted into the prepared capsule, where commit is still exposed, and a mission
/// relabel of a compiled situation are both refused, so a terminal proof never sits beside a live
/// re-dispatch affordance (fss-6sph6).
#[test]
fn bound_effect_cells_are_sealed_to_their_situation() -> Result<(), Box<dyn Error>> {
    let lifecycle = Lifecycle::new("p2-seal")?;
    let verified = lifecycle.verified(false)?;
    let verified_situation = lifecycle.verified_situation(false)?;
    let prepared = &lifecycle.prepared;
    let is_commit = |affordance: &&fss_core::ActionAffordance| affordance.operation == "commit";
    assert!(
        !verified
            .situation
            .capsule
            .affordances
            .iter()
            .any(|a| is_commit(&a)),
        "{:?}",
        verified.situation.capsule.affordances
    );
    assert!(
        prepared
            .situation
            .capsule
            .affordances
            .iter()
            .filter(is_commit)
            .any(|affordance| affordance.class == fss_core::AffordanceClass::Conditional),
        "{:?}",
        prepared.situation.capsule.affordances
    );
    let expected = ReferenceError::InvalidSpec("situation_effect_binding_seal");

    let mut transplanted = verified_situation.clone();
    let outcome_cells: Vec<_> = transplanted
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .filter(|cell| cell.claim_id.starts_with("claim:effect:"))
        .cloned()
        .collect();
    assert!(!outcome_cells.is_empty());
    let mut capsule = prepared.situation.capsule.clone();
    capsule
        .frame
        .knowledge_cells
        .retain(|cell| !cell.claim_id.starts_with("claim:effect:"));
    capsule.frame.knowledge_cells.extend(outcome_cells);
    transplanted.capsule = capsule;
    transplanted
        .proof_roots
        .extend(prepared.situation.proof_roots.iter().copied());
    assert_effect_tamper_refused(&verified_situation, transplanted, &expected)?;

    let mut relabeled = verified_situation.clone();
    relabeled.capsule.mission_id = fss_core::MissionId::parse("mission:elsewhere")?;
    assert_effect_tamper_refused(&verified_situation, relabeled, &expected)?;
    lifecycle.harness.cleanup();
    Ok(())
}

/// Returns whether `result` is a refusal carrying exactly `expected`.
fn refused_with<T>(result: &Result<T, ReferenceError>, expected: &ReferenceError) -> bool {
    result
        .as_ref()
        .err()
        .is_some_and(|error| error.to_string() == expected.to_string())
}

/// Review probe RR4: a compiled situation rebuilt through the public constructor loses its seal.
/// Rebuilt without its bound indeterminate cell it is an unsealed hand-built situation, which no
/// handoff accepts and whose publication digest differs; rebuilt under another mission with the
/// cell kept, it is refused because the cell is no longer bound (fss-6sph6).
#[test]
fn rebuilt_situation_cannot_hand_off_or_keep_a_compiled_effect() -> Result<(), Box<dyn Error>> {
    let lifecycle = Lifecycle::new("rr4-rebuild")?;
    let genuine = &lifecycle.dispatched;
    assert!(genuine.situation.is_sealed());
    let local = genuine
        .situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id.ends_with(":local-state"))
        .cloned()
        .ok_or(ReferenceError::InvalidSpec("missing_local_state_cell"))?;
    assert_eq!(
        local.knowledge_state,
        fss_core::KnowledgeState::Indeterminate
    );
    let created_at = TimestampNs(1_001);
    let expires_at = TimestampNs(2_000);
    crate::seal_reference_handoff(
        &lifecycle.dispatched_situation,
        fss_core::HandoffId::parse("handoff:rr4:genuine")?,
        created_at,
        expires_at,
    )?;
    crate::seal_reference_publication_handoff(
        genuine,
        fss_core::HandoffId::parse("handoff:rr4:genuine-publication")?,
        created_at,
        expires_at,
    )?;

    let unsealed = ReferenceError::InvalidSpec("situation_handoff_unsealed");
    let mut capsule = genuine.situation.capsule.clone();
    capsule
        .frame
        .knowledge_cells
        .retain(|cell| cell.claim_id != local.claim_id);
    let stripped = crate::ReferenceSituation::new(capsule, genuine.situation.proof_roots.clone());
    assert!(!stripped.is_sealed());
    let handoff = crate::seal_reference_handoff(
        &stripped,
        fss_core::HandoffId::parse("handoff:rr4:strip")?,
        created_at,
        expires_at,
    );
    assert!(refused_with(&handoff, &unsealed), "{:?}", handoff.is_ok());
    let stripped_publication =
        crate::project_reference_situation(stripped, &guard_projection_spec()?)?;
    assert_ne!(
        stripped_publication.publication_digest,
        genuine.publication_digest
    );
    let handoff = crate::seal_reference_publication_handoff(
        &stripped_publication,
        fss_core::HandoffId::parse("handoff:rr4:strip-publication")?,
        created_at,
        expires_at,
    );
    assert!(refused_with(&handoff, &unsealed), "{:?}", handoff.is_ok());

    let unbound = ReferenceError::InvalidSpec("situation_effect_cell_unbound");
    let mut relabeled = genuine.situation.capsule.clone();
    relabeled.mission_id = MissionId::parse("mission:elsewhere")?;
    let relabeled =
        crate::ReferenceSituation::new(relabeled, genuine.situation.proof_roots.clone());
    let verified = relabeled.verify();
    assert!(refused_with(&verified, &unbound), "{verified:?}");
    let projected = crate::project_reference_situation(relabeled, &guard_projection_spec()?)
        .map(|publication| publication.publication_digest);
    assert!(refused_with(&projected, &unbound), "{projected:?}");
    lifecycle.harness.cleanup();
    Ok(())
}

/// Review probe RR5: the seal records the proof roots the compile path gathered, so replacing the
/// roots with the bound evidence plus a made-up digest, which would let a handoff drop the event
/// evidence, is refused (fss-6sph6).
#[test]
fn sealed_proof_roots_cannot_be_replaced() -> Result<(), Box<dyn Error>> {
    let lifecycle = Lifecycle::new("rr5-roots")?;
    let verified = lifecycle.verified_situation(true)?;
    let mut tampered = verified.clone();
    let mut roots: std::collections::BTreeSet<fss_core::ContentDigest> = tampered
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .filter(|cell| cell.claim_id.starts_with("claim:effect:"))
        .flat_map(|cell| cell.evidence.iter().copied())
        .collect();
    roots.insert(fss_core::ContentDigest::sha256(b"rr5-foreign-root"));
    assert!(tampered.proof_roots.difference(&roots).count() > 0);
    tampered.proof_roots = roots;
    assert_effect_tamper_refused(
        &verified,
        tampered,
        &ReferenceError::InvalidSpec("situation_sealed_proof_root_removed"),
    )?;
    lifecycle.harness.cleanup();
    Ok(())
}

/// Review probe RR6: the publication digest commits to the compile path's seal. A compiled
/// publication and the same capsule rebuilt unsealed never share a digest, so swapping the unsealed
/// situation into the sealed publication is refused; a rebuilt capsule that still carries a
/// compiled effect cell is refused outright (fss-6sph6).
#[test]
fn publication_digest_commits_to_the_seal() -> Result<(), Box<dyn Error>> {
    let name = "rr6-digest";
    let mut harness = GuardHarness::new(name)?;
    let (decision, receipt) = harness.corroborated(name)?;
    let compile_request = request(&decision, &receipt, &["capability:alert.prepare"])?;
    let genuine = crate::project_reference_situation(
        compile_reference_situation(compile_request, &harness.authority)?,
        &guard_projection_spec()?,
    )?;
    assert!(genuine.situation.is_sealed());
    // The seal holds even with no effect binding: editing the compiled capsule breaks it.
    let mut relabeled = genuine.situation.clone();
    relabeled.capsule.mission_id = MissionId::parse("mission:elsewhere")?;
    let verified = relabeled.verify();
    assert!(
        refused_with(
            &verified,
            &ReferenceError::InvalidSpec("situation_effect_binding_seal")
        ),
        "{verified:?}"
    );
    let rebuilt = crate::ReferenceSituation::new(
        genuine.situation.capsule.clone(),
        genuine.situation.proof_roots.clone(),
    );
    let rebuilt_publication =
        crate::project_reference_situation(rebuilt.clone(), &guard_projection_spec()?)?;
    assert_ne!(
        rebuilt_publication.publication_digest,
        genuine.publication_digest
    );
    let mut swapped = genuine.clone();
    swapped.situation = rebuilt;
    let verified = swapped.verify();
    assert!(
        refused_with(
            &verified,
            &ReferenceError::Contract(fss_core::ContractError::DigestMismatch)
        ),
        "{verified:?}"
    );
    harness.cleanup();

    let lifecycle = Lifecycle::new("rr6-prepared")?;
    let prepared = &lifecycle.prepared;
    let rebuilt = crate::ReferenceSituation::new(
        prepared.situation.capsule.clone(),
        prepared.situation.proof_roots.clone(),
    );
    let projected = crate::project_reference_situation(rebuilt, &guard_projection_spec()?)
        .map(|publication| publication.publication_digest);
    assert!(
        refused_with(
            &projected,
            &ReferenceError::InvalidSpec("situation_effect_cell_unbound")
        ),
        "{projected:?}"
    );
    lifecycle.harness.cleanup();
    Ok(())
}

/// Rebuilds `publication`'s capsule through the public constructor after `edit_capsule`, so the
/// result is unsealed, and projects it.
fn unsealed_rebuild(
    publication: &crate::ReferenceSituationPublication,
    edit_capsule: impl FnOnce(&mut fss_core::SituationCapsule),
) -> Result<crate::ReferenceSituationPublication, Box<dyn Error>> {
    let mut capsule = publication.situation.capsule.clone();
    edit_capsule(&mut capsule);
    let rebuilt =
        crate::ReferenceSituation::new(capsule, publication.situation.proof_roots.clone());
    Ok(crate::project_reference_situation(
        rebuilt,
        &guard_projection_spec()?,
    )?)
}

fn strip_effect_cells(capsule: &mut fss_core::SituationCapsule) {
    capsule
        .frame
        .knowledge_cells
        .retain(|cell| !cell.claim_id.starts_with("claim:effect:"));
}

/// Asserts that both bound routes refuse `publication` with the exact unsealed refusal: publishing
/// it as a bound publication, and a bound handoff from `genuine_bound` with its base publication
/// swapped for it and its bound digest recomputed.
fn assert_bound_routes_refuse(
    genuine_bound: &crate::BoundReferenceSituationPublication,
    publication: crate::ReferenceSituationPublication,
) -> Result<(), Box<dyn Error>> {
    let expected = crate::ReferenceContextBindingError::Reference(ReferenceError::InvalidSpec(
        "situation_bound_publication_unsealed",
    ))
    .to_string();
    let specs = crate::context_binding_tests::binding_specs(&publication)?;
    let published = crate::BoundReferenceSituationPublication::publish(publication.clone(), specs);
    assert_eq!(
        published.as_ref().err().map(ToString::to_string),
        Some(expected.clone()),
        "bound publish accepted: {}",
        published.is_ok()
    );
    let mut swapped = genuine_bound.clone();
    swapped.publication = publication;
    swapped.bound_publication_digest = swapped.computed_digest();
    let handoff = crate::seal_bound_reference_publication_handoff(
        &swapped,
        fss_core::HandoffId::parse("handoff:bound:swapped")?,
        TimestampNs(1_001),
        TimestampNs(2_000),
    );
    assert_eq!(
        handoff.as_ref().err().map(ToString::to_string),
        Some(expected),
        "bound handoff accepted: {}",
        handoff.is_ok()
    );
    Ok(())
}

/// Review round 4 F1: a dispatched situation stripped of its indeterminate local-state cell, the
/// same with the effect-status affordances dropped and the commit affordance restored, and a
/// prepared situation stripped of its effect cells are all unsealed rebuilds. The plain handoff
/// and both bound routes refuse each of them, so none can carry a live re-dispatch affordance to
/// another principal (fss-6sph6).
#[test]
fn bound_routes_refuse_unsealed_rebuilds() -> Result<(), Box<dyn Error>> {
    let lifecycle = Lifecycle::new("bound-rebuild")?;
    let dispatched = &lifecycle.dispatched;
    let prepared = &lifecycle.prepared;
    let genuine_bound = crate::BoundReferenceSituationPublication::publish(
        dispatched.clone(),
        crate::context_binding_tests::binding_specs(dispatched)?,
    )?;
    crate::seal_bound_reference_publication_handoff(
        &genuine_bound,
        fss_core::HandoffId::parse("handoff:bound:genuine")?,
        TimestampNs(1_001),
        TimestampNs(2_000),
    )?;

    let commit = prepared
        .situation
        .capsule
        .affordances
        .iter()
        .find(|affordance| affordance.operation == "commit")
        .cloned()
        .ok_or(ReferenceError::InvalidSpec("missing_commit_affordance"))?;
    let stripped = unsealed_rebuild(dispatched, strip_effect_cells)?;
    let restored = unsealed_rebuild(dispatched, |capsule| {
        strip_effect_cells(capsule);
        capsule.affordances.retain(|affordance| {
            affordance.affordance_id != EFFECT_STATUS_AFFORDANCE
                && affordance.affordance_id != "affordance:alert:reconcile"
        });
        capsule.affordances.push(commit);
        capsule
            .affordances
            .sort_by(|left, right| left.affordance_id.cmp(&right.affordance_id));
        capsule.frame.next = capsule
            .affordances
            .iter()
            .filter(|affordance| {
                matches!(
                    affordance.class,
                    fss_core::AffordanceClass::Robust
                        | fss_core::AffordanceClass::Conditional
                        | fss_core::AffordanceClass::Probe
                        | fss_core::AffordanceClass::Wait
                )
            })
            .map(|affordance| affordance.affordance_id.clone())
            .collect();
    })?;
    let prepared_stripped = unsealed_rebuild(prepared, strip_effect_cells)?;
    for rebuilt in [&restored, &prepared_stripped] {
        assert!(
            rebuilt
                .situation
                .capsule
                .affordances
                .iter()
                .any(|affordance| affordance.operation == "commit")
        );
    }
    let unsealed = ReferenceError::InvalidSpec("situation_handoff_unsealed");
    for (label, rebuilt) in [
        ("stripped", stripped),
        ("commit restored", restored),
        ("prepared stripped", prepared_stripped),
    ] {
        assert!(!rebuilt.situation.is_sealed(), "{label}");
        let handoff = crate::seal_reference_publication_handoff(
            &rebuilt,
            fss_core::HandoffId::parse("handoff:plain:rebuilt")?,
            TimestampNs(1_001),
            TimestampNs(2_000),
        );
        assert!(
            refused_with(&handoff, &unsealed),
            "{label}: {:?}",
            handoff.is_ok()
        );
        assert_bound_routes_refuse(&genuine_bound, rebuilt)?;
    }
    lifecycle.harness.cleanup();
    Ok(())
}

/// Round 5 N2: an unsealed rebuild that clears a compiled situation's obligations reports their
/// removal but never discharges them as a terminal transition; only a sealed result can.
#[test]
fn unsealed_rebuild_never_discharges_compiled_obligations() -> Result<(), Box<dyn Error>> {
    let mut lifecycle = Lifecycle::new("rebuild-discharge")?;
    let dispatched = &lifecycle.dispatched;
    assert!(!dispatched.situation.capsule.obligations.is_empty());
    let cleared = unsealed_rebuild(dispatched, |capsule| {
        strip_effect_cells(capsule);
        capsule.obligations.clear();
    })?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, dispatched)?;
    let delta = crate::classify_reference_meaningful_delta_in_lineage(
        dispatched,
        &cleared,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(
        delta
            .classes
            .contains(&fss_core::MeaningfulDeltaClass::Obligation),
        "{:?}",
        delta.classes
    );
    assert!(
        !delta
            .classes
            .contains(&fss_core::MeaningfulDeltaClass::TerminalTransition),
        "{:?}",
        delta.classes
    );
    delta.validate()?;
    lifecycle.harness.cleanup();
    Ok(())
}

/// Round 4 F6: an obligation-namespace cell injected into a compiled situation is refused by
/// verification, projection and publication verification alike; no compile path binds one.
#[test]
fn injected_obligation_cell_is_refused() -> Result<(), Box<dyn Error>> {
    let lifecycle = Lifecycle::new("inject-obligation")?;
    let genuine = &lifecycle.dispatched_situation;
    let root = fss_core::ContentDigest::sha256(b"injected-obligation-root");
    let mut tampered = genuine.clone();
    tampered
        .capsule
        .frame
        .knowledge_cells
        .push(fss_core::KnowledgeCell {
            claim_id: "claim:obligation:situation-guard:inject-obligation".to_owned(),
            statement: "The alert obligation was discharged.".to_owned(),
            knowledge_state: fss_core::KnowledgeState::Known,
            provenance: fss_core::ProvenanceClass::Observed,
            hypothesis: Some(fss_core::HypothesisDisposition::Resolved),
            evidence: vec![root],
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        });
    tampered.proof_roots.insert(root);
    assert_effect_tamper_refused(
        genuine,
        tampered,
        &ReferenceError::InvalidSpec("situation_obligation_cell_unbound"),
    )?;
    lifecycle.harness.cleanup();
    Ok(())
}

/// Review round 4 F4: a sealed publication's proof roots are exactly the sealed roots plus the
/// roots projection derived, and the publication digest covers them. A foreign root is refused as
/// a digest mismatch, and still refused once the digest is recomputed to match it (fss-6sph6).
#[test]
fn sealed_publication_proof_roots_are_exact() -> Result<(), Box<dyn Error>> {
    let lifecycle = Lifecycle::new("exact-roots")?;
    let genuine = lifecycle.verified(true)?;
    genuine.verify()?;
    let mut inserted = genuine.clone();
    assert!(
        inserted
            .situation
            .proof_roots
            .insert(fss_core::ContentDigest::sha256(b"round4-foreign-root"))
    );
    let verified = inserted.verify();
    assert!(
        refused_with(
            &verified,
            &ReferenceError::Contract(fss_core::ContractError::DigestMismatch)
        ),
        "{verified:?}"
    );
    inserted.publication_digest = inserted.computed_digest()?;
    assert_ne!(inserted.publication_digest, genuine.publication_digest);
    let verified = inserted.verify();
    assert!(
        refused_with(
            &verified,
            &ReferenceError::InvalidSpec("situation_publication_proof_roots")
        ),
        "{verified:?}"
    );
    lifecycle.harness.cleanup();
    Ok(())
}

/// Pinned v6 seal digest of the fixed compiled publication below.
const GOLDEN_SEAL_DIGEST: &str =
    "sha256:d8ead9a323506e641dd4d97226393c1cd4fe42cdc173c9e8eb4eb9d9c574a1ed";
/// Pinned v5 publication digest of the fixed compiled publication below.
const GOLDEN_PUBLICATION_DIGEST: &str =
    "sha256:6fc353116e4df3ebd37a28f924b44c30c285ca5856c5d543b6a51edc92d6196e";

/// Review round 4 F5: the seal digest and the v2 publication digest of a fixed compiled
/// publication are pinned, so any change to either encoding has to change these goldens on purpose.
#[test]
fn compiled_publication_digests_are_pinned() -> Result<(), Box<dyn Error>> {
    let name = "golden";
    let mut harness = GuardHarness::new(name)?;
    let (decision, receipt) = harness.corroborated(name)?;
    let compile_request = request(&decision, &receipt, &["capability:alert.prepare"])?;
    let publication = crate::project_reference_situation(
        compile_reference_situation(compile_request, &harness.authority)?,
        &guard_projection_spec()?,
    )?;
    let seal = publication
        .situation
        .seal_digest()
        .ok_or(ReferenceError::InvalidSpec("missing_seal"))?;
    assert_eq!(
        (seal.to_string(), publication.publication_digest.to_string()),
        (
            GOLDEN_SEAL_DIGEST.to_owned(),
            GOLDEN_PUBLICATION_DIGEST.to_owned()
        )
    );
    harness.cleanup();
    Ok(())
}

/// Round 5 N1: compile paths embed event and operation identities verbatim, and those may contain
/// `:` anywhere, so real lifecycles whose event and operation identities carry `::` or a trailing
/// `:` compile, verify, project and hand off (fss-6sph6).
#[test]
fn lifecycles_with_colon_heavy_ids_compile_and_verify() -> Result<(), Box<dyn Error>> {
    for name in ["zz4::edge", "zz4edge:"] {
        let lifecycle = Lifecycle::new(name)?;
        let event_id = format!("event:situation-guard:{name}");
        let operation_id = format!("operation:situation-guard:{name}");
        assert_eq!(
            lifecycle.decision.event.event_id.as_str(),
            event_id.as_str()
        );
        assert_eq!(
            lifecycle.plan.intent.operation_id.as_str(),
            operation_id.as_str()
        );
        let verified = lifecycle.verified(true)?;
        for publication in [&lifecycle.prepared, &lifecycle.dispatched, &verified] {
            publication.verify()?;
        }
        let claims: Vec<&str> = verified
            .situation
            .capsule
            .frame
            .knowledge_cells
            .iter()
            .map(|cell| cell.claim_id.as_str())
            .collect();
        assert!(
            claims
                .iter()
                .any(|claim| claim.starts_with(&format!("claim:event:{event_id}:"))),
            "{claims:?}"
        );
        assert!(
            claims
                .iter()
                .any(|claim| claim.starts_with(&format!("claim:effect:{operation_id}:"))),
            "{claims:?}"
        );
        crate::seal_reference_handoff(
            &lifecycle.dispatched_situation,
            fss_core::HandoffId::parse("handoff:colon-heavy")?,
            TimestampNs(1_001),
            TimestampNs(2_000),
        )?;
        lifecycle.harness.cleanup();
    }
    Ok(())
}

/// Round 5 N3: a sealed situation carries exactly the proof roots its compile path sealed. A
/// foreign root is refused by verification, projection and the situation handoff, and a projected
/// situation, whose projection roots belong only to its publication, cannot hand off on its own.
#[test]
fn sealed_situation_proof_roots_are_exact() -> Result<(), Box<dyn Error>> {
    let lifecycle = Lifecycle::new("situation-roots")?;
    let genuine = &lifecycle.dispatched_situation;
    genuine.verify()?;
    let foreign = ReferenceError::InvalidSpec("situation_foreign_proof_root");
    let handoff_id = fss_core::HandoffId::parse("handoff:situation-roots")?;
    crate::seal_reference_handoff(
        genuine,
        handoff_id.clone(),
        TimestampNs(1_001),
        TimestampNs(2_000),
    )?;

    let mut tampered = genuine.clone();
    assert!(
        tampered
            .proof_roots
            .insert(fss_core::ContentDigest::sha256(b"round5-foreign-root"))
    );
    let verified = tampered.verify();
    assert!(refused_with(&verified, &foreign), "{verified:?}");
    let handoff = crate::seal_reference_handoff(
        &tampered,
        handoff_id.clone(),
        TimestampNs(1_001),
        TimestampNs(2_000),
    );
    assert!(refused_with(&handoff, &foreign), "{:?}", handoff.is_ok());
    let projected = crate::project_reference_situation(tampered, &guard_projection_spec()?)
        .map(|publication| publication.publication_digest);
    assert!(refused_with(&projected, &foreign), "{projected:?}");

    let handoff = crate::seal_reference_handoff(
        &lifecycle.dispatched.situation,
        handoff_id,
        TimestampNs(1_001),
        TimestampNs(2_000),
    );
    assert!(refused_with(&handoff, &foreign), "{:?}", handoff.is_ok());
    lifecycle.harness.cleanup();
    Ok(())
}

/// Pinned v6 seal digest of the fixed compiled publication with effect bindings below.
const GOLDEN_BOUND_SEAL_DIGEST: &str =
    "sha256:2dd82f8e7855af0a0b13a2d9af92891e065826aa38c9898abdfe4c24272d130a";
/// Pinned v5 publication digest of the fixed compiled publication with effect bindings below.
const GOLDEN_BOUND_PUBLICATION_DIGEST: &str =
    "sha256:8ee1205c591ed1922a9e2d3684d97ff96b84c000be4d45a503dd82d7447c7a0b";

/// Round 5: pins the binding part of the seal encoding. The verified publication, bound to its
/// outcome and local-state cells, has a pinned seal digest and publication digest.
#[test]
fn bound_compiled_publication_digests_are_pinned() -> Result<(), Box<dyn Error>> {
    let lifecycle = Lifecycle::new("golden-bound")?;
    let publication = lifecycle.verified(true)?;
    let bound_kinds: Vec<_> = publication
        .situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .filter_map(|cell| publication.situation.effect_cell_kind(&cell.claim_id))
        .collect();
    assert_eq!(
        bound_kinds,
        vec![
            crate::EffectCellKind::LocalState,
            crate::EffectCellKind::Outcome
        ]
    );
    let seal = publication
        .situation
        .seal_digest()
        .ok_or(ReferenceError::InvalidSpec("missing_seal"))?;
    assert_eq!(
        (seal.to_string(), publication.publication_digest.to_string()),
        (
            GOLDEN_BOUND_SEAL_DIGEST.to_owned(),
            GOLDEN_BOUND_PUBLICATION_DIGEST.to_owned()
        )
    );
    lifecycle.harness.cleanup();
    Ok(())
}

/// Compiles and projects the situation of `decision` with no alert plan, continuing `predecessor`
/// when one is given.
fn planless_publication(
    harness: &GuardHarness,
    decision: &ReferencePolicyDecision,
    receipt: &ReferenceEventReceipt,
    predecessor: Option<&crate::ReferenceSituationPublication>,
) -> Result<crate::ReferenceSituationPublication, Box<dyn Error>> {
    let mut compile_request = request(
        decision,
        receipt,
        &["capability:alert.commit", CAPABILITY_EFFECT_RECONCILE],
    )?;
    compile_request.predecessor_publication =
        predecessor.map(|predecessor| predecessor.publication_digest);
    Ok(crate::project_reference_situation(
        compile_reference_situation(compile_request, &harness.authority)?,
        &guard_projection_spec()?,
    )?)
}

/// A durable effect journal at a fresh temporary path, for the journal-bound tests.
fn durable_journal(
    name: &str,
) -> Result<(crate::DurableEffectJournal, std::path::PathBuf), Box<dyn Error>> {
    let path = std::env::temp_dir().join(format!(
        "fss-reference-guard-journal-{}-{name}.journal",
        std::process::id()
    ));
    let _ = fs::remove_file(&path);
    let journal =
        crate::DurableEffectJournal::open(&path, fss_ledger::IncompleteTailPolicy::Reject)?;
    Ok((journal, path))
}

/// Prepares the alert plan for `decision` in the durable journal (the obligation opens there).
fn durable_prepare(
    journal: &mut crate::DurableEffectJournal,
    harness: &GuardHarness,
    decision: &ReferencePolicyDecision,
    receipt: &ReferenceEventReceipt,
    name: &str,
) -> Result<ReferenceAlertPlan, Box<dyn Error>> {
    Ok(journal.prepare_alert(PrepareAlertParams {
        decision,
        event_receipt: receipt,
        authority: &harness.authority,
        operation_id: OperationId::parse(format!("operation:situation-guard:{name}"))?,
        idempotency_key: IdempotencyKey::parse(format!("idempotency:situation-guard:{name}"))?,
        obligation_id: ObligationId::parse(format!("obligation:situation-guard:{name}"))?,
        channel: "operator:oncall".to_owned(),
        now: TimestampNs(100),
    })?)
}

/// Compiles against the durable journal (sealing its root) and projects.
fn durable_publication(
    harness: &GuardHarness,
    journal: &crate::DurableEffectJournal,
    decision: &ReferencePolicyDecision,
    receipt: &ReferenceEventReceipt,
    plan: Option<&ReferenceAlertPlan>,
    outcome: Option<&crate::ReferenceAlertOutcomeReceipt>,
    continues: Option<&crate::ReferenceSituationPublication>,
) -> Result<crate::ReferenceSituationPublication, Box<dyn Error>> {
    let mut compile_request = request(
        decision,
        receipt,
        &["capability:alert.commit", CAPABILITY_EFFECT_RECONCILE],
    )?;
    compile_request.alert_plan = plan;
    compile_request.alert_outcome = outcome;
    compile_request.predecessor_publication =
        continues.map(|predecessor| predecessor.publication_digest);
    Ok(crate::project_reference_situation(
        crate::compile_reference_situation_with_durable_journal(
            compile_request,
            journal,
            &harness.authority,
        )?,
        &guard_projection_spec()?,
    )?)
}

/// fss-mnlz1 M1 and R5-1: the same event compiled with its alert plan and then without it, against
/// the real durable journal, chained in the authority's lineage. The durable journal still holds
/// the plan's obligation open, so the journal-bound classifier refuses the discharge with the real
/// journal. Against an empty substitute journal whose history holds neither sealed root, without a
/// journal, and through the plain classifier, the removal is reported but never as terminal.
#[test]
fn obligation_removal_is_refused_while_the_journal_holds_it_open() -> Result<(), Box<dyn Error>> {
    let name = "r51-open";
    let mut harness = GuardHarness::new(name)?;
    let (decision, receipt) = harness.corroborated(name)?;
    let (mut journal, journal_path) = durable_journal(name)?;
    let plan = durable_prepare(&mut journal, &harness, &decision, &receipt, name)?;
    let with_plan = durable_publication(
        &harness,
        &journal,
        &decision,
        &receipt,
        Some(&plan),
        None,
        None,
    )?;
    assert_eq!(
        with_plan.situation.journal_root(),
        Some(journal.last_root())
    );
    crate::record_reference_publication(&mut harness.authority, &with_plan)?;
    let without_plan = durable_publication(
        &harness,
        &journal,
        &decision,
        &receipt,
        None,
        None,
        Some(&with_plan),
    )?;
    crate::record_reference_publication(&mut harness.authority, &without_plan)?;
    let removed = format!("obligation removed: {}", plan.obligation_id);
    let terminal = |delta: &fss_core::MeaningfulDelta| {
        delta
            .classes
            .contains(&fss_core::MeaningfulDeltaClass::TerminalTransition)
    };

    let open = crate::classify_reference_meaningful_delta_in_lineage(
        &with_plan,
        &without_plan,
        &harness.authority,
        Some(&journal),
    );
    assert!(
        matches!(
            open,
            Err(ReferenceError::InvalidSpec(
                "meaningful_delta_obligation_still_open"
            ))
        ),
        "{:?}",
        open.map(|delta| delta.classes)
    );
    // An empty substitute journal holds neither sealed root in its history: the discharge is
    // reported, never refused as an error and never terminal (fss-mnlz1 N3).
    let (substitute, substitute_path) = durable_journal("r51-substitute")?;
    let substituted = crate::classify_reference_meaningful_delta_in_lineage(
        &with_plan,
        &without_plan,
        &harness.authority,
        Some(&substitute),
    )?;
    assert!(
        !terminal(&substituted),
        "substitute: {:?}",
        substituted.classes
    );
    assert!(
        substituted.obligation_changes.contains(&removed),
        "substitute: {substituted:?}"
    );
    substituted.validate()?;
    for (label, delta) in [
        (
            "bound without journal",
            crate::classify_reference_meaningful_delta_in_lineage(
                &with_plan,
                &without_plan,
                &harness.authority,
                None,
            )?,
        ),
        (
            "plain",
            crate::classify_reference_meaningful_delta(&with_plan, &without_plan)?,
        ),
    ] {
        assert!(!terminal(&delta), "{label}: {:?}", delta.classes);
        assert!(
            delta.obligation_changes.contains(&removed),
            "{label}: {delta:?}"
        );
        assert!(delta.silence_certificate.is_none(), "{label}");
        delta.validate()?;
    }
    drop(substitute);
    let _ = fs::remove_file(substitute_path);
    drop(journal);
    let _ = fs::remove_file(journal_path);
    harness.cleanup();
    Ok(())
}

/// fss-mnlz1 R5-3 and M2: a stale basis cannot replay a terminal transition, and a publication has
/// one successor. The dispatched publication, its verified successor, and a later successor of that
/// are recorded in order: the first step is terminal, the second is not (the effect was already
/// proved), and the stale dispatched basis against the later successor is not terminal, because the
/// lineage records no such succession.
#[test]
fn stale_basis_replay_never_re_terminalizes() -> Result<(), Box<dyn Error>> {
    let mut lifecycle = Lifecycle::new("r53-stale")?;
    let first = &lifecycle.dispatched;
    crate::record_reference_publication(&mut lifecycle.harness.authority, first)?;
    let second = lifecycle.verified_after(false, first)?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &second)?;
    let third = lifecycle.verified_after(true, &second)?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &third)?;
    let terminal = |delta: &fss_core::MeaningfulDelta| {
        delta
            .classes
            .contains(&fss_core::MeaningfulDeltaClass::TerminalTransition)
    };
    let step = crate::classify_reference_meaningful_delta_in_lineage(
        first,
        &second,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(terminal(&step), "first step: {:?}", step.classes);
    let step = crate::classify_reference_meaningful_delta_in_lineage(
        &second,
        &third,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(!terminal(&step), "second step: {:?}", step.classes);
    let replay = crate::classify_reference_meaningful_delta_in_lineage(
        first,
        &third,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(!terminal(&replay), "stale replay: {:?}", replay.classes);
    assert!(
        replay
            .classes
            .contains(&fss_core::MeaningfulDeltaClass::MaterialState),
        "stale replay: {:?}",
        replay.classes
    );
    replay.validate()?;
    lifecycle.harness.cleanup();
    Ok(())
}

/// Returns whether `result` failed with exactly `expected`.
fn refused_boxed<T>(result: &Result<T, Box<dyn Error>>, expected: &ReferenceError) -> bool {
    result.as_ref().err().is_some_and(|error| {
        error
            .downcast_ref::<ReferenceError>()
            .is_some_and(|actual| actual.to_string() == expected.to_string())
    })
}

/// fss-mnlz1 M2 (the reviewer's two-children probe): two different successors of the dispatched
/// publication both compile while it is the latest, but the lineage records only the first; the
/// second is refused at record time, a third can no longer compile against the superseded
/// predecessor, and only the recorded child is a terminal successor.
#[test]
fn a_publication_has_one_successor() -> Result<(), Box<dyn Error>> {
    let mut lifecycle = Lifecycle::new("mnlz1-children")?;
    let parent = &lifecycle.dispatched;
    crate::record_reference_publication(&mut lifecycle.harness.authority, parent)?;
    let first_child = lifecycle.verified_after(true, parent)?;
    let second_child = lifecycle.verified_after(false, parent)?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &first_child)?;
    let recorded =
        crate::record_reference_publication(&mut lifecycle.harness.authority, &second_child)
            .map(|_| ());
    assert!(
        refused_with(
            &recorded,
            &ReferenceError::InvalidSpec("lineage_predecessor_not_latest")
        ),
        "{recorded:?}"
    );
    let third_child = lifecycle.verified_after(false, parent);
    assert!(
        refused_boxed(
            &third_child,
            &ReferenceError::InvalidSpec("situation_predecessor_not_latest")
        ),
        "{:?}",
        third_child.map(|publication| publication.publication_digest)
    );
    let terminal = |delta: &fss_core::MeaningfulDelta| {
        delta
            .classes
            .contains(&fss_core::MeaningfulDeltaClass::TerminalTransition)
    };
    let first = crate::classify_reference_meaningful_delta_in_lineage(
        parent,
        &first_child,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(terminal(&first), "{:?}", first.classes);
    let second = crate::classify_reference_meaningful_delta_in_lineage(
        parent,
        &second_child,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(!terminal(&second), "{:?}", second.classes);
    second.validate()?;
    lifecycle.harness.cleanup();
    Ok(())
}

/// fss-mnlz1 M3: compile validates a predecessor against the authority's publication lineage. A
/// made-up digest and another event's publication are refused as not the latest publication of
/// this subject; the subject's latest recorded publication is accepted.
#[test]
fn a_predecessor_must_be_the_subjects_latest_recorded_publication() -> Result<(), Box<dyn Error>> {
    let name = "mnlz1-predecessor";
    let mut harness = GuardHarness::new(name)?;
    let (decision, receipt) = harness.corroborated(name)?;
    let (other_decision, other_receipt) = harness.corroborated("mnlz1-other-event")?;
    let genesis = planless_publication(&harness, &decision, &receipt, None)?;
    crate::record_reference_publication(&mut harness.authority, &genesis)?;
    let other = planless_publication(&harness, &other_decision, &other_receipt, None)?;
    crate::record_reference_publication(&mut harness.authority, &other)?;

    let compile = |predecessor: fss_core::ContentDigest|
     -> Result<crate::ReferenceSituation, ReferenceError> {
        let mut compile_request = request(
            &decision,
            &receipt,
            &["capability:alert.commit", CAPABILITY_EFFECT_RECONCILE],
        )?;
        compile_request.predecessor_publication = Some(predecessor);
        compile_reference_situation(compile_request, &harness.authority)
    };
    let not_latest = ReferenceError::InvalidSpec("situation_predecessor_not_latest");
    let junk = compile(fss_core::ContentDigest::sha256(b"zz6-junk-predecessor")).map(|_| ());
    assert!(refused_with(&junk, &not_latest), "{junk:?}");
    let cross_event = compile(other.publication_digest).map(|_| ());
    assert!(refused_with(&cross_event, &not_latest), "{cross_event:?}");
    compile(genesis.publication_digest)?;
    harness.cleanup();
    Ok(())
}

/// fss-mnlz1 M1 positive control: once the durable journal closes the obligation (the alert is
/// dispatched, verified and its outcome published), the verified publication continuing the
/// prepared one discharges it as a terminal, critical transition that refuses to coalesce,
/// checked against the real journal whose root it sealed.
#[test]
fn durable_discharge_is_terminal_once_the_journal_closes_it() -> Result<(), Box<dyn Error>> {
    let name = "mnlz1-discharge";
    let mut harness = GuardHarness::new(name)?;
    let (decision, receipt) = harness.corroborated(name)?;
    let (mut journal, journal_path) = durable_journal(name)?;
    let plan = durable_prepare(&mut journal, &harness, &decision, &receipt, name)?;
    let prepared = durable_publication(
        &harness,
        &journal,
        &decision,
        &receipt,
        Some(&plan),
        None,
        None,
    )?;
    crate::record_reference_publication(&mut harness.authority, &prepared)?;
    let mut provider = crate::ReferenceAlertProvider::with_provider_id(format!(
        "provider:test:situation-guard:{name}"
    ));
    let _ = journal.dispatch_alert(
        &plan,
        crate::ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut provider,
    )?;
    let provider_receipt = provider
        .lookup(&plan.intent)?
        .ok_or(ReferenceError::InvalidSpec("missing_provider_receipt"))?;
    let _ = journal.observe_alert(
        &plan,
        provider_receipt.receipt_digest(),
        TimestampNs(103),
        &provider,
    )?;
    let _ = journal.verify_alert(&plan, TimestampNs(104), &provider)?;
    let outcome = journal.publish_alert_outcome(
        &plan,
        &mut harness.objects,
        &mut harness.authority,
        &provider,
    )?;
    let verified = durable_publication(
        &harness,
        &journal,
        &decision,
        &receipt,
        Some(&plan),
        Some(&outcome),
        Some(&prepared),
    )?;
    crate::record_reference_publication(&mut harness.authority, &verified)?;
    assert!(
        !verified
            .situation
            .capsule
            .obligations
            .contains(&plan.obligation_id)
    );
    let delta = crate::classify_reference_meaningful_delta_in_lineage(
        &prepared,
        &verified,
        &harness.authority,
        Some(&journal),
    )?;
    for class in [
        fss_core::MeaningfulDeltaClass::Obligation,
        fss_core::MeaningfulDeltaClass::TerminalTransition,
    ] {
        assert!(
            delta.classes.contains(&class),
            "{class:?}: {:?}",
            delta.classes
        );
    }
    assert_eq!(delta.priority, fss_core::DeltaPriority::Critical);
    assert!(delta.is_non_coalescible());
    // fss-mnlz1 N3: the journal advancing past both sealed roots (an unrelated alert prepared after
    // the verified compile) is accepted, not refused, and leaves the classification unchanged. The
    // verified outcome is terminal through the effect rule too, so that the discharge itself stays
    // terminal is pinned by `a_discharge_is_checked_against_a_prefix_of_the_journal_history`.
    let later = "mnlz1-discharge-later";
    let (later_decision, later_receipt) = harness.corroborated(later)?;
    let _ = durable_prepare(
        &mut journal,
        &harness,
        &later_decision,
        &later_receipt,
        later,
    )?;
    assert_ne!(verified.situation.journal_root(), Some(journal.last_root()));
    let advanced = crate::classify_reference_meaningful_delta_in_lineage(
        &prepared,
        &verified,
        &harness.authority,
        Some(&journal),
    )?;
    assert_eq!(advanced.classes, delta.classes);
    let next = crate::classify_reference_meaningful_delta(&verified, &verified)?;
    assert!(!delta.can_coalesce_with(&next)?);
    assert!(
        delta
            .coalesce(
                &next,
                "delta:coalesced",
                "continuation:coalesced",
                fss_core::ContentDigest::sha256(b"coalesced"),
            )
            .is_err()
    );
    delta.validate()?;
    drop(journal);
    let _ = fs::remove_file(journal_path);
    harness.cleanup();
    Ok(())
}

/// fss-mnlz1: the authority's publication lineage fails closed on a crash mid-record and replays
/// deterministically. A successor torn halfway through its record is refused on reopen under
/// `Reject`; under `Truncate` only the complete prefix replays, so the successor is absent (never
/// half-recorded), every reopen yields the same commitment, and the successor can then be recorded
/// again.
#[test]
fn lineage_fails_closed_on_a_torn_record_and_replays_deterministically()
-> Result<(), Box<dyn Error>> {
    let name = "mnlz1-torn";
    let mut lifecycle = Lifecycle::new(name)?;
    let parent = lifecycle.dispatched.clone();
    let subject = parent
        .situation
        .subject()
        .map(|(event, objective)| (event.clone(), objective.to_owned()))
        .ok_or(ReferenceError::InvalidSpec("missing_subject"))?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &parent)?;
    let child = lifecycle.verified_after(true, &parent)?;
    let path = lifecycle.harness.path.clone();
    let committed = fs::metadata(&path)?.len();
    let genesis_commitment = lifecycle.harness.authority.journal_root();
    crate::record_reference_publication(&mut lifecycle.harness.authority, &child)?;
    // Close the authority without removing it, then tear the child's record in half.
    drop(lifecycle);
    let full = fs::metadata(&path)?.len();
    assert!(full > committed + 1);
    fs::OpenOptions::new()
        .write(true)
        .open(&path)?
        .set_len(committed + (full - committed) / 2)?;

    let site = format!("site:situation-guard:{name}");
    let open = |policy| DurableReferenceLedger::open(&path, site.clone(), policy);
    assert!(open(IncompleteTailPolicy::Reject).is_err());
    let replayed = open(IncompleteTailPolicy::Truncate)?;
    assert_eq!(
        crate::latest_reference_publication(&replayed, &subject.0, &subject.1)?,
        Some(parent.publication_digest)
    );
    assert_eq!(replayed.journal_root(), genesis_commitment);
    drop(replayed);
    let mut again = open(IncompleteTailPolicy::Reject)?;
    assert_eq!(again.journal_root(), genesis_commitment);
    crate::record_reference_publication(&mut again, &child)?;
    assert_eq!(
        crate::latest_reference_publication(&again, &subject.0, &subject.1)?,
        Some(child.publication_digest)
    );
    drop(again);
    let _ = fs::remove_file(&path);
    Ok(())
}

/// Appends a raw lineage record of `publication`, continuing `predecessor`, to `ledger` through the
/// public ledger API, bypassing [`crate::record_reference_publication`]: what any holder of a
/// ledger can write.
fn append_raw_lineage(
    ledger: &mut DurableReferenceLedger,
    publication: &crate::ReferenceSituationPublication,
    predecessor: Option<fss_core::ContentDigest>,
    generations: (Option<u64>, u64),
) -> Result<(), Box<dyn Error>> {
    let (event_id, objective_id) = publication
        .situation
        .subject()
        .ok_or(ReferenceError::InvalidSpec("missing_subject"))?;
    let digest = publication.publication_digest;
    let delta = crate::situation_sections::lineage_delta(
        crate::situation_sections::lineage_object_id(event_id, objective_id)?,
        generations,
        digest,
        predecessor,
        publication.situation.capsule.created_at,
    )?;
    let batch = ledger.prepare_batch(
        fss_core::BatchId::parse(format!("batch:raw-lineage:{digest}"))?,
        vec![delta],
        [digest],
    )?;
    let _ = ledger.append(batch)?;
    Ok(())
}

/// fss-mnlz1 N2 (the reviewer's two-store probe): only the authority whose lineage compile reads
/// vouches for a successor. A second store is refused as a recorder, so compile sees no lineage it
/// holds. Raw lineage records of a rival child in a second store never make the rival terminal,
/// because that store never committed the authority anchors both publications sealed. A raw second
/// child appended to the authority itself does not extend the replayed lineage, so it vouches for
/// nothing while the recorded child stays the terminal successor and the latest publication.
#[test]
fn only_the_compiling_authority_lineage_vouches_for_a_successor() -> Result<(), Box<dyn Error>> {
    let name = "n2-two-stores";
    let mut lifecycle = Lifecycle::new(name)?;
    let parent = lifecycle.dispatched.clone();
    let terminal = |delta: &fss_core::MeaningfulDelta| {
        delta
            .classes
            .contains(&fss_core::MeaningfulDeltaClass::TerminalTransition)
    };
    let second_path = std::env::temp_dir().join(format!(
        "fss-reference-guard-second-store-{}.journal",
        std::process::id()
    ));
    let _ = fs::remove_file(&second_path);
    let mut second = DurableReferenceLedger::open(
        &second_path,
        format!("site:situation-guard:{name}"),
        IncompleteTailPolicy::Reject,
    )?;

    let foreign = crate::record_reference_publication(&mut second, &parent).map(|_| ());
    assert!(
        refused_with(
            &foreign,
            &ReferenceError::InvalidSpec("lineage_foreign_authority")
        ),
        "{foreign:?}"
    );
    let unrecorded = lifecycle.verified_after(true, &parent);
    assert!(
        refused_boxed(
            &unrecorded,
            &ReferenceError::InvalidSpec("situation_predecessor_not_latest")
        ),
        "{:?}",
        unrecorded.map(|publication| publication.publication_digest)
    );

    crate::record_reference_publication(&mut lifecycle.harness.authority, &parent)?;
    let child = lifecycle.verified_after(true, &parent)?;
    let rival = lifecycle.verified_after(false, &parent)?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &child)?;
    let genuine = crate::classify_reference_meaningful_delta_in_lineage(
        &parent,
        &child,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(terminal(&genuine), "{:?}", genuine.classes);

    append_raw_lineage(&mut second, &parent, None, (None, 1))?;
    append_raw_lineage(
        &mut second,
        &rival,
        Some(parent.publication_digest),
        (Some(1), 2),
    )?;
    let second_store =
        crate::classify_reference_meaningful_delta_in_lineage(&parent, &rival, &second, None)?;
    assert!(
        !terminal(&second_store),
        "second store: {:?}",
        second_store.classes
    );
    second_store.validate()?;

    let (event_id, objective_id) = rival
        .situation
        .subject()
        .ok_or(ReferenceError::InvalidSpec("missing_subject"))?;
    let generation = lifecycle
        .harness
        .authority
        .current()
        .objects
        .get(&crate::situation_sections::lineage_object_id(
            event_id,
            objective_id,
        )?)
        .map(|revision| revision.generation)
        .ok_or(ReferenceError::InvalidSpec("missing_lineage"))?;
    append_raw_lineage(
        &mut lifecycle.harness.authority,
        &rival,
        Some(parent.publication_digest),
        (
            Some(generation),
            generation
                .checked_add(1)
                .ok_or(ReferenceError::ArithmeticOverflow)?,
        ),
    )?;
    // The raw second child's witness is not the latest publication, so the replay skips it: it
    // vouches for nothing, and the recorded child stays the terminal successor and the latest
    // publication (fss-mnlz1 N2-D).
    let forged = crate::classify_reference_meaningful_delta_in_lineage(
        &parent,
        &rival,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(!terminal(&forged), "raw second child: {:?}", forged.classes);
    forged.validate()?;
    let recorded = crate::classify_reference_meaningful_delta_in_lineage(
        &parent,
        &child,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(
        terminal(&recorded),
        "recorded child: {:?}",
        recorded.classes
    );
    assert_eq!(
        crate::latest_reference_publication(&lifecycle.harness.authority, event_id, objective_id)?,
        Some(child.publication_digest)
    );
    drop(second);
    let _ = fs::remove_file(second_path);
    lifecycle.harness.cleanup();
    Ok(())
}

/// fss-mnlz1 N1 (the reviewer's fresh-journal probe): the successor that drops the plan's
/// obligation is compiled against another durable journal, one that never recorded the obligation
/// but has a committed record of its own. Checked against either journal the discharge is reported,
/// never terminal: the compile journal's history does not hold the result's root, and the other
/// journal's history does not hold the basis's.
#[test]
fn a_result_sealed_from_another_journal_never_discharges() -> Result<(), Box<dyn Error>> {
    let name = "n1-foreign-journal";
    let mut harness = GuardHarness::new(name)?;
    let (decision, receipt) = harness.corroborated(name)?;
    let (mut journal, journal_path) = durable_journal(name)?;
    let plan = durable_prepare(&mut journal, &harness, &decision, &receipt, name)?;
    let with_plan = durable_publication(
        &harness,
        &journal,
        &decision,
        &receipt,
        Some(&plan),
        None,
        None,
    )?;
    crate::record_reference_publication(&mut harness.authority, &with_plan)?;
    let (mut foreign, foreign_path) = durable_journal("n1-foreign-journal-other")?;
    let _ = foreign.prepare(
        fss_core::EffectIntent {
            operation_id: OperationId::parse("operation:situation-guard:n1-unrelated")?,
            idempotency_key: IdempotencyKey::parse("idempotency:situation-guard:n1-unrelated")?,
            effect_class: "alert.dispatch".to_owned(),
            request_digest: fss_core::ContentDigest::sha256(b"n1-unrelated-request"),
            precondition_digest: fss_core::ContentDigest::sha256(b"n1-unrelated-preconditions"),
        },
        ObligationId::parse("obligation:situation-guard:n1-unrelated")?,
        "the unrelated alert reaches a terminal outcome",
        TimestampNs(100),
    )?;
    assert!(foreign.obligation(&plan.obligation_id).is_none());
    let without_plan = durable_publication(
        &harness,
        &foreign,
        &decision,
        &receipt,
        None,
        None,
        Some(&with_plan),
    )?;
    assert_eq!(
        without_plan.situation.journal_root(),
        Some(foreign.last_root())
    );
    crate::record_reference_publication(&mut harness.authority, &without_plan)?;
    let removed = format!("obligation removed: {}", plan.obligation_id);
    for (label, checked) in [
        ("compile journal", &journal),
        ("result's journal", &foreign),
    ] {
        let delta = crate::classify_reference_meaningful_delta_in_lineage(
            &with_plan,
            &without_plan,
            &harness.authority,
            Some(checked),
        )?;
        assert!(
            !delta
                .classes
                .contains(&fss_core::MeaningfulDeltaClass::TerminalTransition),
            "{label}: {:?}",
            delta.classes
        );
        assert!(
            delta.obligation_changes.contains(&removed),
            "{label}: {delta:?}"
        );
        delta.validate()?;
    }
    drop(foreign);
    let _ = fs::remove_file(foreign_path);
    drop(journal);
    let _ = fs::remove_file(journal_path);
    harness.cleanup();
    Ok(())
}

/// Appends one raw write of the lineage object `object_id` to `ledger` through the public ledger
/// API, bypassing [`crate::record_reference_publication`]: `payload` under `family`, witnessing
/// `witness`, at the object's next generation.
fn append_raw_record(
    ledger: &mut DurableReferenceLedger,
    object_id: &fss_core::ObjectId,
    family: &str,
    payload: fss_core::ContentDigest,
    witness: Option<fss_core::ContentDigest>,
) -> Result<(), Box<dyn Error>> {
    let prior = ledger
        .current()
        .objects
        .get(object_id)
        .map(|revision| revision.generation);
    let next = match prior {
        Some(generation) => generation
            .checked_add(1)
            .ok_or(ReferenceError::ArithmeticOverflow)?,
        None => 1,
    };
    let mut delta = crate::situation_sections::lineage_delta(
        object_id.clone(),
        (prior, next),
        payload,
        witness,
        TimestampNs(1_000),
    )?;
    family.clone_into(&mut delta.family);
    delta.delta_id = format!("delta:raw-lineage:{payload}:{next}");
    let batch = ledger.prepare_batch(
        fss_core::BatchId::parse(format!("batch:raw-lineage:{payload}:{next}"))?,
        vec![delta],
        [payload],
    )?;
    let _ = ledger.append(batch)?;
    Ok(())
}

/// The lineage object of `publication`'s subject.
fn lineage_object_of(
    publication: &crate::ReferenceSituationPublication,
) -> Result<fss_core::ObjectId, Box<dyn Error>> {
    let (event_id, objective_id) = publication
        .situation
        .subject()
        .ok_or(ReferenceError::InvalidSpec("missing_subject"))?;
    Ok(crate::situation_sections::lineage_object_id(
        event_id,
        objective_id,
    )?)
}

/// The latest publication of `publication`'s subject in `authority`'s replayed lineage.
fn latest_of(
    authority: &DurableReferenceLedger,
    publication: &crate::ReferenceSituationPublication,
) -> Result<Option<fss_core::ContentDigest>, Box<dyn Error>> {
    let (event_id, objective_id) = publication
        .situation
        .subject()
        .ok_or(ReferenceError::InvalidSpec("missing_subject"))?;
    Ok(crate::latest_reference_publication(
        authority,
        event_id,
        objective_id,
    )?)
}

fn is_terminal(delta: &fss_core::MeaningfulDelta) -> bool {
    delta
        .classes
        .contains(&fss_core::MeaningfulDeltaClass::TerminalTransition)
}

/// fss-mnlz1 N2-D (the reviewer's freeze probe): one raw lineage batch naming a digest that is no
/// publication, witnessed by the parent at the next generation, never freezes the subject. The
/// replay skips it (its witness is not the latest publication), so the parent's recorded child
/// stays terminal and latest, and a successor of the child still compiles and records. A raw
/// record that does extend the latest publication cannot be told from a recorded step and becomes
/// the latest, but the lineage continues from it too.
#[test]
fn a_raw_lineage_batch_never_freezes_a_subject() -> Result<(), Box<dyn Error>> {
    let mut lifecycle = Lifecycle::new("n2d-freeze")?;
    let parent = lifecycle.dispatched.clone();
    crate::record_reference_publication(&mut lifecycle.harness.authority, &parent)?;
    let child = lifecycle.verified_after(false, &parent)?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &child)?;
    let object_id = lineage_object_of(&parent)?;

    append_raw_record(
        &mut lifecycle.harness.authority,
        &object_id,
        crate::situation_sections::LINEAGE_FAMILY,
        fss_core::ContentDigest::sha256(b"zz9-raw-rival-child"),
        Some(parent.publication_digest),
    )?;
    let delta = crate::classify_reference_meaningful_delta_in_lineage(
        &parent,
        &child,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(is_terminal(&delta), "{:?}", delta.classes);
    assert_eq!(
        latest_of(&lifecycle.harness.authority, &parent)?,
        Some(child.publication_digest)
    );
    let grandchild = lifecycle.verified_after(true, &child)?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &grandchild)?;
    assert_eq!(
        latest_of(&lifecycle.harness.authority, &parent)?,
        Some(grandchild.publication_digest)
    );

    let extension = fss_core::ContentDigest::sha256(b"zz9-raw-extension");
    append_raw_record(
        &mut lifecycle.harness.authority,
        &object_id,
        crate::situation_sections::LINEAGE_FAMILY,
        extension,
        Some(grandchild.publication_digest),
    )?;
    assert_eq!(
        latest_of(&lifecycle.harness.authority, &parent)?,
        Some(extension)
    );
    let mut compile_request = request(
        &lifecycle.decision,
        &lifecycle.receipt,
        &["capability:alert.commit", CAPABILITY_EFFECT_RECONCILE],
    )?;
    compile_request.alert_plan = Some(&lifecycle.plan);
    compile_request.alert_outcome = Some(&lifecycle.outcome);
    compile_request.predecessor_publication = Some(extension);
    let continued = crate::project_reference_situation(
        compile_reference_situation(compile_request, &lifecycle.harness.authority)?,
        &guard_projection_spec()?,
    )?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &continued)?;
    assert_eq!(
        latest_of(&lifecycle.harness.authority, &parent)?,
        Some(continued.publication_digest)
    );
    lifecycle.harness.cleanup();
    Ok(())
}

/// fss-mnlz1 Mu2: a raw record naming a publication the lineage already recorded is skipped even
/// when it witnesses the latest publication. Otherwise the loop would make the parent latest
/// again and let a raw second child of it through.
#[test]
fn a_raw_record_repeating_a_recorded_publication_is_skipped() -> Result<(), Box<dyn Error>> {
    let mut lifecycle = Lifecycle::new("mu2-loop")?;
    let parent = lifecycle.dispatched.clone();
    crate::record_reference_publication(&mut lifecycle.harness.authority, &parent)?;
    let child = lifecycle.verified_after(true, &parent)?;
    let rival = lifecycle.verified_after(false, &parent)?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &child)?;
    let object_id = lineage_object_of(&parent)?;
    append_raw_record(
        &mut lifecycle.harness.authority,
        &object_id,
        crate::situation_sections::LINEAGE_FAMILY,
        parent.publication_digest,
        Some(child.publication_digest),
    )?;
    append_raw_record(
        &mut lifecycle.harness.authority,
        &object_id,
        crate::situation_sections::LINEAGE_FAMILY,
        rival.publication_digest,
        Some(parent.publication_digest),
    )?;
    assert_eq!(
        latest_of(&lifecycle.harness.authority, &parent)?,
        Some(child.publication_digest)
    );
    let forged = crate::classify_reference_meaningful_delta_in_lineage(
        &parent,
        &rival,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(!is_terminal(&forged), "{:?}", forged.classes);
    let recorded = crate::classify_reference_meaningful_delta_in_lineage(
        &parent,
        &child,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(is_terminal(&recorded), "{:?}", recorded.classes);
    lifecycle.harness.cleanup();
    Ok(())
}

/// fss-mnlz1 Mu2: a write of the lineage object under another family is skipped even when it
/// witnesses the latest publication: it never becomes the latest publication, never vouches for
/// a successor, and never blocks the genuine one.
#[test]
fn a_raw_write_of_another_family_is_skipped() -> Result<(), Box<dyn Error>> {
    let mut lifecycle = Lifecycle::new("mu2-family")?;
    let parent = lifecycle.dispatched.clone();
    crate::record_reference_publication(&mut lifecycle.harness.authority, &parent)?;
    let child = lifecycle.verified_after(true, &parent)?;
    let rival = lifecycle.verified_after(false, &parent)?;
    append_raw_record(
        &mut lifecycle.harness.authority,
        &lineage_object_of(&parent)?,
        "situation_publication_lineage_forged",
        rival.publication_digest,
        Some(parent.publication_digest),
    )?;
    assert_eq!(
        latest_of(&lifecycle.harness.authority, &parent)?,
        Some(parent.publication_digest)
    );
    let forged = crate::classify_reference_meaningful_delta_in_lineage(
        &parent,
        &rival,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(!is_terminal(&forged), "{:?}", forged.classes);
    crate::record_reference_publication(&mut lifecycle.harness.authority, &child)?;
    let recorded = crate::classify_reference_meaningful_delta_in_lineage(
        &parent,
        &child,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(is_terminal(&recorded), "{:?}", recorded.classes);
    lifecycle.harness.cleanup();
    Ok(())
}

/// fss-mnlz1: a batch squatting the identity a lineage record would first try cannot block the
/// record, which takes the next unused identity.
#[test]
fn a_squatted_lineage_batch_identity_never_blocks_a_record() -> Result<(), Box<dyn Error>> {
    let mut lifecycle = Lifecycle::new("n2d-squat")?;
    let parent = lifecycle.dispatched.clone();
    crate::record_reference_publication(&mut lifecycle.harness.authority, &parent)?;
    let child = lifecycle.verified_after(true, &parent)?;
    let squat_root = fss_core::ContentDigest::sha256(b"zz9-squat");
    let squat = fss_core::EvidenceDelta {
        delta_id: "delta:raw-lineage:squat".to_owned(),
        family: "squat".to_owned(),
        object_id: fss_core::ObjectId::parse("object:raw-lineage:squat")?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval::new(TimestampNs(1_000), TimestampNs(1_000))?,
        plane: fss_core::Plane::Cognition,
        payload_digest: squat_root,
        witness_digest: None,
        operation_id: None,
    };
    let batch = lifecycle.harness.authority.prepare_batch(
        fss_core::BatchId::parse(format!(
            "batch:situation-lineage:{}:0",
            child.publication_digest
        ))?,
        vec![squat],
        [squat_root],
    )?;
    let _ = lifecycle.harness.authority.append(batch)?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &child)?;
    assert_eq!(
        latest_of(&lifecycle.harness.authority, &parent)?,
        Some(child.publication_digest)
    );
    let delta = crate::classify_reference_meaningful_delta_in_lineage(
        &parent,
        &child,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(is_terminal(&delta), "{:?}", delta.classes);
    lifecycle.harness.cleanup();
    Ok(())
}

/// fss-mnlz1 N1-T (the reviewer's byte-swap probe): the classifier checks the journal handle it is
/// given, not whatever file now sits at its path. The real journal holds the plan's obligation
/// pending; a fork of it is advanced (the alert dispatched, observed and verified) and the planless
/// result is compiled against the fork; then the fork's bytes are copied over the real file while
/// the real handle is still open. Classifying with the real handle is refused as an external
/// mutation of that journal, with exactly the handle's and the file's committed lengths.
#[test]
fn journal_bytes_swapped_under_the_handle_are_refused() -> Result<(), Box<dyn Error>> {
    let name = "n1t-swap";
    let mut harness = GuardHarness::new(name)?;
    let (decision, receipt) = harness.corroborated(name)?;
    let (mut journal, journal_path) = durable_journal(name)?;
    let plan = durable_prepare(&mut journal, &harness, &decision, &receipt, name)?;
    let with_plan = durable_publication(
        &harness,
        &journal,
        &decision,
        &receipt,
        Some(&plan),
        None,
        None,
    )?;
    crate::record_reference_publication(&mut harness.authority, &with_plan)?;

    let fork_path = std::env::temp_dir().join(format!(
        "fss-reference-guard-journal-fork-{}-{name}.journal",
        std::process::id()
    ));
    let _ = fs::remove_file(&fork_path);
    fs::copy(&journal_path, &fork_path)?;
    let mut fork = crate::DurableEffectJournal::open(&fork_path, IncompleteTailPolicy::Reject)?;
    let mut provider = crate::ReferenceAlertProvider::with_provider_id(format!(
        "provider:test:situation-guard:{name}"
    ));
    let _ = fork.dispatch_alert(
        &plan,
        crate::ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut provider,
    )?;
    let provider_receipt = provider
        .lookup(&plan.intent)?
        .ok_or(ReferenceError::InvalidSpec("missing_provider_receipt"))?;
    let _ = fork.observe_alert(
        &plan,
        provider_receipt.receipt_digest(),
        TimestampNs(103),
        &provider,
    )?;
    let _ = fork.verify_alert(&plan, TimestampNs(104), &provider)?;
    let without_plan = durable_publication(
        &harness,
        &fork,
        &decision,
        &receipt,
        None,
        None,
        Some(&with_plan),
    )?;
    crate::record_reference_publication(&mut harness.authority, &without_plan)?;
    drop(fork);
    assert_eq!(
        journal
            .obligation(&plan.obligation_id)
            .map(|obligation| obligation.state),
        Some(fss_core::ObligationState::Pending)
    );

    let expected = journal.committed_len();
    fs::copy(&fork_path, &journal_path)?;
    let observed = fs::metadata(&journal_path)?.len();
    assert_ne!(expected, observed);
    let swapped = crate::classify_reference_meaningful_delta_in_lineage(
        &with_plan,
        &without_plan,
        &harness.authority,
        Some(&journal),
    );
    assert!(
        matches!(
            &swapped,
            Err(ReferenceError::Publication(
                fss_publication::PublicationError::Ledger(
                    fss_ledger::DurableLedgerError::Journal(
                        fss_ledger::JournalError::ExternalMutation {
                            expected_len,
                            observed_len,
                            kind: fss_ledger::ExternalMutationKind::LengthDivergence,
                        }
                    )
                )
            )) if *expected_len == expected && *observed_len == observed
        ),
        "{:?}",
        swapped.map(|delta| delta.classes)
    );
    drop(journal);
    let _ = fs::remove_file(journal_path);
    let _ = fs::remove_file(fork_path);
    harness.cleanup();
    Ok(())
}

/// fss-mnlz1 (the reviewer's six-step replay probe): a raw lineage record that puts a stale sibling
/// back at the head of the lineage never lets the operation terminalize a second time. (1) The
/// prepared publication P is recorded; (2) after dispatch, a sibling S is compiled continuing P
/// while P is latest (the effect still indeterminate); (3) after the outcome is published, the
/// genuine child L continuing P is compiled and recorded, and P to L is terminal; (4) one raw
/// lineage record names S with L as witness, so S becomes the latest publication; (5) a genuine
/// next step G continuing S compiles and records; (6) S to G is refused as a step from a displaced
/// basis, because S's sealed predecessor is P but the lineage recorded it after L, rather than
/// reported as a silently downgraded delta (fss-mnlz1 R5-B). P to L stays the plain delta plus its
/// terminal transition.
#[test]
fn a_raw_record_never_makes_a_stale_sibling_a_terminal_basis() -> Result<(), Box<dyn Error>> {
    let name = "basis-in-place";
    let mut harness = GuardHarness::new(name)?;
    let (decision, receipt) = harness.corroborated(name)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &receipt, &harness.authority, &mut journal, name)?;
    let current = |journal: &EffectJournal| {
        journal
            .operation(&plan.intent.operation_id)
            .cloned()
            .ok_or(fss_core::ContractError::NotFound)
    };
    let spec = guard_projection_spec()?;

    // (1) The prepared publication P, recorded.
    let prepared = crate::project_reference_situation(
        guarded_situation_after(
            &harness,
            &decision,
            &receipt,
            &plan,
            Some(&current(&journal)?),
            None,
            None,
        )?,
        &spec,
    )?;
    crate::record_reference_publication(&mut harness.authority, &prepared)?;

    // (2) Dispatched: the sibling S continuing P, compiled while P is latest, not recorded.
    let mut provider = crate::ReferenceAlertProvider::with_provider_id(format!(
        "provider:test:situation-guard:{name}"
    ));
    let _ = crate::dispatch_reference_alert(
        &plan,
        crate::ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    )?;
    let sibling = crate::project_reference_situation(
        guarded_situation_after(
            &harness,
            &decision,
            &receipt,
            &plan,
            Some(&current(&journal)?),
            None,
            Some(&prepared),
        )?,
        &spec,
    )?;

    // (3) Observed, verified and published: the genuine child L continuing P, recorded; P to L is
    // terminal.
    let provider_receipt = provider
        .lookup(&plan.intent)?
        .ok_or(ReferenceError::InvalidSpec("missing_provider_receipt"))?;
    let _ = crate::observe_reference_alert(
        &plan,
        provider_receipt.receipt_digest(),
        TimestampNs(103),
        &mut journal,
        &provider,
    )?;
    let _ = crate::verify_reference_alert(&plan, TimestampNs(104), &mut journal, &provider)?;
    let outcome = crate::publish_reference_alert_outcome(
        &plan,
        &journal,
        &mut harness.objects,
        &mut harness.authority,
        &provider,
    )?;
    let child = crate::project_reference_situation(
        guarded_situation_after(
            &harness,
            &decision,
            &receipt,
            &plan,
            Some(&current(&journal)?),
            Some(&outcome),
            Some(&prepared),
        )?,
        &spec,
    )?;
    crate::record_reference_publication(&mut harness.authority, &child)?;
    let genuine = crate::classify_reference_meaningful_delta_in_lineage(
        &prepared,
        &child,
        &harness.authority,
        None,
    )?;
    let mut expected = crate::classify_reference_meaningful_delta(&prepared, &child)?.classes;
    expected.insert(fss_core::MeaningfulDeltaClass::TerminalTransition);
    assert_eq!(genuine.classes, expected);

    // (4) One raw lineage record names S with L as witness: S becomes the latest publication.
    append_raw_record(
        &mut harness.authority,
        &lineage_object_of(&prepared)?,
        crate::situation_sections::LINEAGE_FAMILY,
        sibling.publication_digest,
        Some(child.publication_digest),
    )?;
    assert_eq!(
        latest_of(&harness.authority, &prepared)?,
        Some(sibling.publication_digest)
    );

    // (5) A genuine next step G continuing S compiles and records.
    let next = crate::project_reference_situation(
        guarded_situation_after(
            &harness,
            &decision,
            &receipt,
            &plan,
            Some(&current(&journal)?),
            Some(&outcome),
            Some(&sibling),
        )?,
        &spec,
    )?;
    crate::record_reference_publication(&mut harness.authority, &next)?;

    // (6) S to G is refused as a step from a displaced basis: never terminal again, and never a
    // silently downgraded delta (fss-mnlz1 R5-B).
    let replayed = crate::classify_reference_meaningful_delta_in_lineage(
        &sibling,
        &next,
        &harness.authority,
        None,
    );
    assert!(
        matches!(
            replayed,
            Err(ReferenceError::InvalidSpec(
                "meaningful_delta_lineage_basis_displaced"
            ))
        ),
        "{:?}",
        replayed.map(|delta| delta.classes)
    );
    // The plain classifier, which never announces a terminal transition, still reports the change.
    let plain = crate::classify_reference_meaningful_delta(&sibling, &next)?;
    assert!(!is_terminal(&plain), "{:?}", plain.classes);
    plain.validate()?;
    // The recorded step P to L stays terminal after the raw record.
    let still = crate::classify_reference_meaningful_delta_in_lineage(
        &prepared,
        &child,
        &harness.authority,
        None,
    )?;
    assert_eq!(still.classes, expected);
    harness.cleanup();
    Ok(())
}

/// fss-mnlz1 R5-A (the reviewer's planless-step probe, no raw write): a planless publication in
/// the middle of the lineage never lets an operation terminalize a second time. P is recorded; the
/// outcome is published and L continuing P is recorded, and P to L is terminal. A planless X
/// continuing L is recorded; L to X drops the proved effect and is reported as effect uncertainty,
/// not terminal. G with the outcome continuing X is recorded; X to G is not terminal, and the
/// operation is reported as already proved on the lineage, since L, an earlier entry of the
/// lineage, first proved it.
#[test]
fn a_planless_step_never_lets_an_operation_terminalize_again() -> Result<(), Box<dyn Error>> {
    let mut lifecycle = Lifecycle::new("r5a-planless")?;
    let prepared = lifecycle.dispatched.clone();
    crate::record_reference_publication(&mut lifecycle.harness.authority, &prepared)?;
    let proved = lifecycle.verified_after(false, &prepared)?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &proved)?;
    let first = crate::classify_reference_meaningful_delta_in_lineage(
        &prepared,
        &proved,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(is_terminal(&first), "P to L: {:?}", first.classes);

    let planless = planless_publication(
        &lifecycle.harness,
        &lifecycle.decision,
        &lifecycle.receipt,
        Some(&proved),
    )?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &planless)?;
    let dropped = crate::classify_reference_meaningful_delta_in_lineage(
        &proved,
        &planless,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(!is_terminal(&dropped), "L to X: {:?}", dropped.classes);
    assert!(
        dropped
            .classes
            .contains(&fss_core::MeaningfulDeltaClass::EffectUncertainty),
        "L to X: {:?}",
        dropped.classes
    );

    let again = lifecycle.verified_after(true, &planless)?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &again)?;
    let replay = crate::classify_reference_meaningful_delta_in_lineage(
        &planless,
        &again,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(!is_terminal(&replay), "X to G: {:?}", replay.classes);
    let operation = lifecycle.plan.intent.operation_id.as_str();
    let already = format!(
        "effect already proved on the lineage: operation {operation} was first proved by publication {}",
        proved.publication_digest
    );
    assert_eq!(
        replay
            .effect_uncertainty_changes
            .iter()
            .filter(|change| **change == already)
            .count(),
        1,
        "{:?}",
        replay.effect_uncertainty_changes
    );
    assert!(
        replay
            .classes
            .contains(&fss_core::MeaningfulDeltaClass::EffectUncertainty),
        "X to G: {:?}",
        replay.classes
    );
    replay.validate()?;
    lifecycle.harness.cleanup();
    Ok(())
}

/// fss-mnlz1 R5-B (the reviewer's displaced-basis probe): P is recorded; a sibling S continuing P
/// is compiled while P is latest; after dispatch L continuing P is recorded; one raw lineage record
/// promotes S (witness L); the outcome is published and G continuing S is recorded. S to G would
/// be the effect's first-ever proof, so the bound classifier refuses it as a step from a displaced
/// basis rather than returning a plain delta that silently drops the terminal transition.
#[test]
fn a_displaced_basis_is_refused_not_silently_downgraded() -> Result<(), Box<dyn Error>> {
    let name = "r5b-displaced";
    let mut harness = GuardHarness::new(name)?;
    let (decision, receipt) = harness.corroborated(name)?;
    let mut journal = EffectJournal::new();
    let plan = prepare(&decision, &receipt, &harness.authority, &mut journal, name)?;
    let current = |journal: &EffectJournal| {
        journal
            .operation(&plan.intent.operation_id)
            .cloned()
            .ok_or(fss_core::ContractError::NotFound)
    };
    let spec = guard_projection_spec()?;
    let prepared = crate::project_reference_situation(
        guarded_situation_after(
            &harness,
            &decision,
            &receipt,
            &plan,
            Some(&current(&journal)?),
            None,
            None,
        )?,
        &spec,
    )?;
    crate::record_reference_publication(&mut harness.authority, &prepared)?;
    let sibling = crate::project_reference_situation(
        guarded_situation_after(
            &harness,
            &decision,
            &receipt,
            &plan,
            Some(&current(&journal)?),
            None,
            Some(&prepared),
        )?,
        &spec,
    )?;
    let mut provider = crate::ReferenceAlertProvider::with_provider_id(format!(
        "provider:test:situation-guard:{name}"
    ));
    let _ = crate::dispatch_reference_alert(
        &plan,
        crate::ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    )?;
    let child = crate::project_reference_situation(
        guarded_situation_after(
            &harness,
            &decision,
            &receipt,
            &plan,
            Some(&current(&journal)?),
            None,
            Some(&prepared),
        )?,
        &spec,
    )?;
    crate::record_reference_publication(&mut harness.authority, &child)?;
    append_raw_record(
        &mut harness.authority,
        &lineage_object_of(&prepared)?,
        crate::situation_sections::LINEAGE_FAMILY,
        sibling.publication_digest,
        Some(child.publication_digest),
    )?;
    assert_eq!(
        latest_of(&harness.authority, &prepared)?,
        Some(sibling.publication_digest)
    );
    let provider_receipt = provider
        .lookup(&plan.intent)?
        .ok_or(ReferenceError::InvalidSpec("missing_provider_receipt"))?;
    let _ = crate::observe_reference_alert(
        &plan,
        provider_receipt.receipt_digest(),
        TimestampNs(103),
        &mut journal,
        &provider,
    )?;
    let _ = crate::verify_reference_alert(&plan, TimestampNs(104), &mut journal, &provider)?;
    let outcome = crate::publish_reference_alert_outcome(
        &plan,
        &journal,
        &mut harness.objects,
        &mut harness.authority,
        &provider,
    )?;
    let next = crate::project_reference_situation(
        guarded_situation_after(
            &harness,
            &decision,
            &receipt,
            &plan,
            Some(&current(&journal)?),
            Some(&outcome),
            Some(&sibling),
        )?,
        &spec,
    )?;
    crate::record_reference_publication(&mut harness.authority, &next)?;
    let displaced = crate::classify_reference_meaningful_delta_in_lineage(
        &sibling,
        &next,
        &harness.authority,
        None,
    );
    assert!(
        matches!(
            displaced,
            Err(ReferenceError::InvalidSpec(
                "meaningful_delta_lineage_basis_displaced"
            ))
        ),
        "{:?}",
        displaced.map(|delta| delta.classes)
    );
    harness.cleanup();
    Ok(())
}

/// fss-mnlz1 R6-A (the reviewer's probe, ordinary API): a planless X continuing P, compiled right
/// after the outcome was published, does not make the first proof on the lineage look old. P is
/// recorded; X continuing P is recorded (P to X is not terminal); G with the outcome continuing X
/// is recorded, and X to G, the first lineage step that ever proves the effect, is terminal: its
/// classes are exactly the plain classifier's plus the terminal transition, with nothing reported
/// as already proved. The next step does not terminalize the operation again, so it terminalizes
/// exactly once along the lineage.
#[test]
fn the_first_proof_after_a_late_planless_basis_stays_terminal() -> Result<(), Box<dyn Error>> {
    let mut lifecycle = Lifecycle::new("r6a-first-proof")?;
    let prepared = lifecycle.dispatched.clone();
    crate::record_reference_publication(&mut lifecycle.harness.authority, &prepared)?;
    let planless = planless_publication(
        &lifecycle.harness,
        &lifecycle.decision,
        &lifecycle.receipt,
        Some(&prepared),
    )?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &planless)?;
    let dropped = crate::classify_reference_meaningful_delta_in_lineage(
        &prepared,
        &planless,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(!is_terminal(&dropped), "P to X: {:?}", dropped.classes);

    let proved = lifecycle.verified_after(false, &planless)?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &proved)?;
    let first = crate::classify_reference_meaningful_delta_in_lineage(
        &planless,
        &proved,
        &lifecycle.harness.authority,
        None,
    )?;
    let mut expected = crate::classify_reference_meaningful_delta(&planless, &proved)?.classes;
    expected.insert(fss_core::MeaningfulDeltaClass::TerminalTransition);
    assert_eq!(first.classes, expected);
    assert!(
        !first
            .effect_uncertainty_changes
            .iter()
            .any(|change| change.starts_with("effect already proved on the lineage")),
        "{:?}",
        first.effect_uncertainty_changes
    );
    first.validate()?;

    let next = lifecycle.verified_after(true, &proved)?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &next)?;
    let again = crate::classify_reference_meaningful_delta_in_lineage(
        &proved,
        &next,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(!is_terminal(&again), "G to next: {:?}", again.classes);
    lifecycle.harness.cleanup();
    Ok(())
}

/// fss-mnlz1: a raw proof marker written outside the batch that recorded the publication it names
/// never counts as an earlier proof. A marker naming the recorded planless X, appended on its own,
/// is skipped, so the first lineage step that proves the effect (X to G) stays terminal.
#[test]
fn a_raw_proof_marker_never_suppresses_a_first_proof() -> Result<(), Box<dyn Error>> {
    let mut lifecycle = Lifecycle::new("r6a-raw-marker")?;
    let prepared = lifecycle.dispatched.clone();
    crate::record_reference_publication(&mut lifecycle.harness.authority, &prepared)?;
    let planless = planless_publication(
        &lifecycle.harness,
        &lifecycle.decision,
        &lifecycle.receipt,
        Some(&prepared),
    )?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &planless)?;
    let (event_id, objective_id) = prepared
        .situation
        .subject()
        .ok_or(ReferenceError::InvalidSpec("missing_subject"))?;
    let marker = crate::situation_sections::lineage_proof_object_id(
        event_id,
        objective_id,
        lifecycle.plan.intent.operation_id.as_str(),
    )?;
    append_raw_record(
        &mut lifecycle.harness.authority,
        &marker,
        crate::situation_sections::LINEAGE_PROOF_FAMILY,
        planless.publication_digest,
        None,
    )?;
    let proved = lifecycle.verified_after(false, &planless)?;
    crate::record_reference_publication(&mut lifecycle.harness.authority, &proved)?;
    let first = crate::classify_reference_meaningful_delta_in_lineage(
        &planless,
        &proved,
        &lifecycle.harness.authority,
        None,
    )?;
    assert!(is_terminal(&first), "X to G: {:?}", first.classes);
    lifecycle.harness.cleanup();
    Ok(())
}
