use std::error::Error;
use std::fs;

use fss_core::{
    CapsuleId, CaptureInterval, Completeness, ContractBasis, EffectJournal, EffectState, EventId,
    IdempotencyKey, MissionId, ObligationId, OperationId, PrincipalId, ProbabilityInterval,
    SensorId, SessionId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};

use crate::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, ReferenceAlertPlan,
    ReferenceError, ReferenceEventReceipt, ReferenceModelObservation, ReferencePolicyDecision,
    ReferenceSituationRequest, VirtualCameraSpec, compile_reference_situation,
    compile_reference_situation_with_operation_receipt, evaluate_unknown_presence,
    execute_mock_model, prepare_reference_alert, publish_reference_event, run_reference_capture,
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
            b"schemas",
            b"operations",
            b"views",
            b"capabilities",
            b"errors",
            b"costs",
            "fss-reference:test",
            Some("nightly-2026-08-31".to_owned()),
        ),
        previous_anchor: None,
        decision,
        event_receipt: receipt,
        alert_plan: None,
        alert_outcome: None,
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
        decision,
        receipt,
        authority,
        OperationId::parse(format!("operation:situation-guard:{name}"))?,
        IdempotencyKey::parse(format!("idempotency:situation-guard:{name}"))?,
        ObligationId::parse(format!("obligation:situation-guard:{name}"))?,
        "operator:oncall",
        TimestampNs(100),
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
