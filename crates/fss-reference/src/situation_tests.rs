use std::collections::BTreeSet;
use std::error::Error;
use std::fs;

use fss_core::{
    AffordanceClass, CapsuleId, CaptureInterval, Completeness, ContractBasis, ContractError,
    EffectJournal, EventId, HandoffId, IdempotencyKey, KnowledgeState, MissionId, ObligationId,
    OperationId, PrincipalId, ProbabilityInterval, SensorId, SessionId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};

use crate::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, ReferenceAlertProvider,
    ReferenceError, ReferenceEventReceipt, ReferenceModelObservation, ReferencePolicyDecision,
    ReferenceProviderBehavior, ReferenceSituationRequest, VirtualCameraSpec,
    compile_reference_situation, dispatch_reference_alert, evaluate_unknown_presence,
    execute_mock_model, prepare_reference_alert, publish_reference_alert_outcome,
    publish_reference_event, run_reference_capture, seal_reference_handoff,
};

struct SituationHarness {
    path: std::path::PathBuf,
    objects: InMemoryObjectStore,
    authority: DurableReferenceLedger,
}

impl SituationHarness {
    fn new(name: &str) -> Result<Self, Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!(
            "fss-reference-situation-{}-{name}.journal",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        Ok(Self {
            authority: DurableReferenceLedger::open(
                &path,
                format!("site:situation:{name}"),
                IncompleteTailPolicy::Reject,
            )?,
            objects: InMemoryObjectStore::new(ObjectLimits::new(2048, 32 * 1024 * 1024)),
            path,
        })
    }

    fn observation(
        &mut self,
        test_name: &str,
        lane: &str,
        seed: u64,
        failure_domain: &str,
        label: MockSemanticLabel,
    ) -> Result<ReferenceModelObservation, Box<dyn Error>> {
        let spec = VirtualCameraSpec {
            capture_id: CapsuleId::parse(format!("capture:situation:{test_name}:{lane}"))?,
            sensor_id: SensorId::parse(format!("sensor:situation:{test_name}:{lane}"))?,
            seed,
            packet_count: 3,
            packet_bytes: 32,
            start_ns: i128::from(seed) * 10_000,
            period_ns: 1_000_000,
            uncertainty_ns: 100,
        };
        let capture = run_reference_capture(
            &spec,
            &DeliveryPlan::identity(spec.packet_count)?,
            &mut self.objects,
            &mut self.authority,
        )?;
        let model = MockModelSpec::new(
            format!("mock:situation:{test_name}:{lane}:v1"),
            MockModelScript::Fixed {
                label,
                probability: ProbabilityInterval::new(0.9, 1.0)?,
            },
        )?;
        let result = execute_mock_model(&model, &capture, &mut self.objects)?;
        let first = capture
            .source_packets
            .first()
            .ok_or(ReferenceError::InvalidSpec("source_packet_count"))?;
        let last = capture
            .source_packets
            .last()
            .ok_or(ReferenceError::InvalidSpec("source_packet_count"))?;
        Ok(ReferenceModelObservation::new(
            result,
            failure_domain,
            CaptureInterval::new(first.capture.earliest, last.capture.latest)?,
        )?)
    }

    fn publish_decision(
        &mut self,
        name: &str,
        labels: &[(MockSemanticLabel, &str)],
    ) -> Result<(ReferencePolicyDecision, ReferenceEventReceipt), Box<dyn Error>> {
        let mut observations = Vec::new();
        for (index, (label, domain)) in labels.iter().enumerate() {
            observations.push(self.observation(
                name,
                &format!("lane{index}"),
                41 + index as u64,
                domain,
                *label,
            )?);
        }
        let decision = evaluate_unknown_presence(
            EventId::parse(format!("event:situation:{name}"))?,
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

fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(
        b"schemas",
        b"operations",
        b"views",
        b"capabilities",
        b"errors",
        b"costs",
        "fss-reference:test",
        Some("nightly-2026-08-31".to_owned()),
    )
}

fn capabilities(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn request<'a>(
    decision: &'a ReferencePolicyDecision,
    event_receipt: &'a ReferenceEventReceipt,
    capabilities: BTreeSet<String>,
) -> Result<ReferenceSituationRequest<'a>, ContractError> {
    Ok(ReferenceSituationRequest {
        mission_id: MissionId::parse("mission:situation:test")?,
        session_id: SessionId::parse("session:situation:test")?,
        principal_id: PrincipalId::parse("principal:situation:test")?,
        objective_id: "objective:protect-reference-boundary".to_owned(),
        revision: 1,
        contract_basis: basis(),
        previous_anchor: None,
        decision,
        event_receipt,
        alert_plan: None,
        alert_outcome: None,
        available_capabilities: capabilities,
        created_at: TimestampNs(1_000),
    })
}

#[test]
fn corroborated_projection_is_deterministic_and_capability_explicit() -> Result<(), Box<dyn Error>>
{
    let mut harness = SituationHarness::new("deterministic")?;
    let (decision, event_receipt) = harness.publish_decision(
        "deterministic",
        &[
            (MockSemanticLabel::PersonLike, "power:alpha"),
            (MockSemanticLabel::PersonLike, "power:beta"),
        ],
    )?;
    let compile_request = request(
        &decision,
        &event_receipt,
        capabilities(&["capability:alert.prepare"]),
    )?;

    let first = compile_reference_situation(compile_request.clone(), &harness.authority)?;
    let second = compile_reference_situation(compile_request, &harness.authority)?;
    assert_eq!(first, second);
    assert_eq!(
        first.capsule.decision_fingerprint(),
        second.capsule.decision_fingerprint()
    );
    assert_eq!(first.capsule.completeness, Completeness::Bounded);
    assert_eq!(
        first.capsule.frame.next,
        vec!["affordance:alert:prepare".to_owned()]
    );
    assert_eq!(first.capsule.affordances[0].class, AffordanceClass::Robust);
    assert!(first.capsule.obligations.is_empty());
    first.verify()?;

    let unavailable = compile_reference_situation(
        request(&decision, &event_receipt, BTreeSet::new())?,
        &harness.authority,
    )?;
    assert_eq!(unavailable.capsule.completeness, Completeness::Partial);
    assert!(unavailable.capsule.frame.next.is_empty());
    assert_eq!(
        unavailable.capsule.affordances[0].class,
        AffordanceClass::Unavailable
    );
    assert!(
        unavailable.capsule.affordances[0]
            .rationale
            .contains("capability:alert.prepare")
    );

    harness.cleanup();
    Ok(())
}

#[test]
fn rejected_candidate_preserves_uncertified_absence_world() -> Result<(), Box<dyn Error>> {
    let mut harness = SituationHarness::new("rejected")?;
    let (decision, event_receipt) = harness.publish_decision(
        "rejected",
        &[(MockSemanticLabel::AnimalLike, "power:alpha")],
    )?;
    let situation = compile_reference_situation(
        request(
            &decision,
            &event_receipt,
            capabilities(&["capability:evidence.query", "capability:session.wait"]),
        )?,
        &harness.authority,
    )?;

    assert_eq!(situation.capsule.completeness, Completeness::Partial);
    assert!(
        situation
            .capsule
            .frame
            .unknown
            .iter()
            .any(|statement| statement.contains("physical absence remains unproved"))
    );
    let absence = situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id.ends_with(":absence-certification"))
        .ok_or(ReferenceError::InvalidSpec("missing_absence_cell"))?;
    assert_eq!(absence.knowledge_state, KnowledgeState::Unknown);
    assert!(
        situation
            .capsule
            .frame
            .world_envelope
            .adversarial_residuals
            .iter()
            .any(|world| world.protected && world.world_id.ends_with(":absence-uncertified"))
    );
    assert!(
        situation
            .capsule
            .affordances
            .iter()
            .all(|affordance| affordance.operation != "commit")
    );

    harness.cleanup();
    Ok(())
}

#[test]
fn lost_ack_projects_only_reconciliation_and_seals_root_closed_handoff()
-> Result<(), Box<dyn Error>> {
    let mut harness = SituationHarness::new("lost-ack")?;
    let (decision, event_receipt) = harness.publish_decision(
        "lost-ack",
        &[
            (MockSemanticLabel::PersonLike, "power:alpha"),
            (MockSemanticLabel::PersonLike, "power:beta"),
        ],
    )?;
    let mut journal = EffectJournal::new();
    let plan = prepare_reference_alert(
        &decision,
        &event_receipt,
        &harness.authority,
        OperationId::parse("operation:situation:lost-ack")?,
        IdempotencyKey::parse("idempotency:situation:lost-ack")?,
        ObligationId::parse("obligation:situation:lost-ack")?,
        "operator:oncall",
        TimestampNs(100),
        &mut journal,
    )?;
    let mut provider = ReferenceAlertProvider::new();
    let _ = dispatch_reference_alert(
        &plan,
        ReferenceProviderBehavior::LoseAckAfterDelivery,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    )?;
    let outcome = publish_reference_alert_outcome(
        &plan,
        &journal,
        &mut harness.objects,
        &mut harness.authority,
    )?;
    let mut compile_request = request(
        &decision,
        &event_receipt,
        capabilities(&["capability:effect.reconcile"]),
    )?;
    compile_request.alert_plan = Some(&plan);
    compile_request.alert_outcome = Some(&outcome);
    compile_request.previous_anchor = Some(event_receipt.authority_anchor.clone());
    let situation = compile_reference_situation(compile_request, &harness.authority)?;

    assert_eq!(
        situation.capsule.obligations,
        vec![ObligationId::parse("obligation:situation:lost-ack")?]
    );
    assert_eq!(
        situation.capsule.frame.next,
        vec!["affordance:alert:reconcile".to_owned()]
    );
    assert!(
        situation
            .capsule
            .frame
            .at_risk
            .iter()
            .any(|statement| statement.contains("must not be blindly resent"))
    );
    assert!(
        situation
            .capsule
            .affordances
            .iter()
            .all(|affordance| affordance.operation != "commit")
    );

    let handoff = seal_reference_handoff(
        &situation,
        HandoffId::parse("handoff:situation:lost-ack")?,
        TimestampNs(1_001),
        TimestampNs(2_000),
    )?;
    assert!(
        handoff
            .child_roots
            .contains(&situation.capsule.decision_fingerprint())
    );
    assert!(handoff.child_roots.contains(&outcome.outcome_root));
    handoff.verify()?;

    harness.cleanup();
    Ok(())
}

#[test]
fn canonical_effect_outcome_cannot_be_omitted_from_projection() -> Result<(), Box<dyn Error>> {
    let mut harness = SituationHarness::new("omission")?;
    let (decision, event_receipt) = harness.publish_decision(
        "omission",
        &[
            (MockSemanticLabel::PersonLike, "power:alpha"),
            (MockSemanticLabel::PersonLike, "power:beta"),
        ],
    )?;
    let mut journal = EffectJournal::new();
    let plan = prepare_reference_alert(
        &decision,
        &event_receipt,
        &harness.authority,
        OperationId::parse("operation:situation:omission")?,
        IdempotencyKey::parse("idempotency:situation:omission")?,
        ObligationId::parse("obligation:situation:omission")?,
        "operator:oncall",
        TimestampNs(100),
        &mut journal,
    )?;
    let mut provider = ReferenceAlertProvider::new();
    let _ = dispatch_reference_alert(
        &plan,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    )?;
    let _outcome = publish_reference_alert_outcome(
        &plan,
        &journal,
        &mut harness.objects,
        &mut harness.authority,
    )?;
    let mut compile_request = request(
        &decision,
        &event_receipt,
        capabilities(&["capability:alert.commit"]),
    )?;
    compile_request.alert_plan = Some(&plan);

    assert!(matches!(
        compile_reference_situation(compile_request, &harness.authority),
        Err(ReferenceError::InvalidSpec(
            "situation_effect_outcome_omitted"
        ))
    ));

    harness.cleanup();
    Ok(())
}

#[test]
fn stale_previous_anchor_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut harness = SituationHarness::new("stale")?;
    let (decision, event_receipt) =
        harness.publish_decision("stale", &[(MockSemanticLabel::AnimalLike, "power:alpha")])?;
    let mut compile_request = request(
        &decision,
        &event_receipt,
        capabilities(&["capability:evidence.query", "capability:session.wait"]),
    )?;
    compile_request.previous_anchor = Some(harness.authority.current().anchor.clone());
    assert!(matches!(
        compile_reference_situation(compile_request, &harness.authority),
        Err(ReferenceError::Contract(ContractError::StaleAnchor))
    ));

    harness.cleanup();
    Ok(())
}
