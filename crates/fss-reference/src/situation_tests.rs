use std::collections::BTreeSet;
use std::error::Error;
use std::fs;

use fss_core::{
    AffordanceClass, CapsuleId, CaptureInterval, Completeness, ContentDigest, ContractBasis,
    ContractBasisRegistryBytes, ContractError, EffectJournal, EventId, EventState,
    EvidenceEdgeRelation, HandoffId, HypothesisDisposition, IdempotencyKey, KnowledgeCell,
    KnowledgeCellParams, KnowledgeState, MissionId, ObligationId, OperationId, PrincipalId,
    ProbabilityInterval, ProvenanceClass, SensorId, SessionId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};

use crate::policy::ReferencePolicyAction;
use crate::situation::{
    physical_knowledge_state, physical_statement, policy_hypothesis, policy_statement,
    reconciliation_basis_for,
};
use crate::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, PrepareAlertParams,
    ReferenceAlertProvider, ReferenceError, ReferenceEventReceipt, ReferenceModelObservation,
    ReferencePolicyDecision, ReferenceProviderBehavior, ReferenceSituationRequest,
    VirtualCameraSpec, compile_reference_situation, dispatch_reference_alert,
    evaluate_unknown_presence, execute_mock_model, observe_reference_alert,
    prepare_reference_alert, publish_reference_alert_outcome, publish_reference_event,
    run_reference_capture, seal_reference_handoff, verify_reference_alert,
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
        predecessor_publication: None,
        decision,
        event_receipt,
        alert_plan: None,
        alert_outcome: None,
        coverage_witness: None,
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
        first.capsule.decision_fingerprint()?,
        second.capsule.decision_fingerprint()?
    );
    assert_eq!(first.capsule.completeness, Completeness::Bounded);
    assert_eq!(
        first.capsule.frame.next,
        vec!["affordance:alert:prepare".to_owned()]
    );
    assert_eq!(
        first.capsule.affordances[0].class,
        AffordanceClass::Conditional
    );
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
        .find(|cell| cell.claim_id().ends_with(":absence-certification"))
        .ok_or(ReferenceError::InvalidSpec("missing_absence_cell"))?;
    assert_eq!(absence.knowledge_state(), KnowledgeState::Unknown);
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
        PrepareAlertParams {
            decision: &decision,
            event_receipt: &event_receipt,
            authority: &harness.authority,
            operation_id: OperationId::parse("operation:situation:lost-ack")?,
            idempotency_key: IdempotencyKey::parse("idempotency:situation:lost-ack")?,
            obligation_id: ObligationId::parse("obligation:situation:lost-ack")?,
            channel: "operator:oncall".to_owned(),
            now: TimestampNs(100),
        },
        &mut journal,
    )?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:situation:lost_ack");
    let _ = dispatch_reference_alert(
        &plan,
        &harness.authority,
        &harness.objects,
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
        &provider,
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
            .contains(&situation.capsule.decision_fingerprint()?)
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
        PrepareAlertParams {
            decision: &decision,
            event_receipt: &event_receipt,
            authority: &harness.authority,
            operation_id: OperationId::parse("operation:situation:omission")?,
            idempotency_key: IdempotencyKey::parse("idempotency:situation:omission")?,
            obligation_id: ObligationId::parse("obligation:situation:omission")?,
            channel: "operator:oncall".to_owned(),
            now: TimestampNs(100),
        },
        &mut journal,
    )?;
    let mut provider = ReferenceAlertProvider::with_provider_id("provider:test:situation:omission");
    let _ = dispatch_reference_alert(
        &plan,
        &harness.authority,
        &harness.objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    )?;
    let provider_receipt = provider
        .lookup(&plan.intent)?
        .ok_or(ReferenceError::InvalidSpec("missing_provider_receipt"))?;
    let _ = observe_reference_alert(
        &plan,
        provider_receipt.receipt_digest(),
        TimestampNs(103),
        &mut journal,
        &provider,
    )?;
    let _ = verify_reference_alert(&plan, TimestampNs(104), &mut journal, &provider)?;
    let _outcome = publish_reference_alert_outcome(
        &plan,
        &journal,
        &mut harness.objects,
        &mut harness.authority,
        &provider,
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

#[test]
fn physical_knowledge_state_maps_every_event_state_explicitly() {
    let support = [ContentDigest::sha256(b"supporting-witness")];
    let contra = [ContentDigest::sha256(b"contradicting-witness")];
    let none: [ContentDigest; 0] = [];
    let cases: [(
        EventState,
        &[ContentDigest],
        &[ContentDigest],
        KnowledgeState,
    ); 16] = [
        // A candidate with no retained witness is not supported, so it cannot be estimated.
        (
            EventState::Hypothesized,
            &none,
            &none,
            KnowledgeState::Unknown,
        ),
        (
            EventState::Hypothesized,
            &support,
            &none,
            KnowledgeState::Unknown,
        ),
        (
            EventState::Witnessed,
            &support,
            &none,
            KnowledgeState::Estimated,
        ),
        (
            EventState::Corroborated,
            &support,
            &none,
            KnowledgeState::Known,
        ),
        // Post-corroboration lifecycle stages are policy/effect/resolution progress, not physical
        // evidence: estimated only while retained support exists, never upgraded to known.
        (
            EventState::Adjudicated,
            &support,
            &none,
            KnowledgeState::Estimated,
        ),
        (
            EventState::Adjudicated,
            &none,
            &none,
            KnowledgeState::Unknown,
        ),
        (
            EventState::Adjudicated,
            &none,
            &contra,
            KnowledgeState::Unknown,
        ),
        (
            EventState::AlertDelivered,
            &support,
            &none,
            KnowledgeState::Estimated,
        ),
        (
            EventState::AlertDelivered,
            &none,
            &none,
            KnowledgeState::Unknown,
        ),
        (
            EventState::Resolved,
            &support,
            &none,
            KnowledgeState::Estimated,
        ),
        (EventState::Resolved, &none, &none, KnowledgeState::Unknown),
        (
            EventState::Indeterminate,
            &support,
            &contra,
            KnowledgeState::Conflicted,
        ),
        (
            EventState::Indeterminate,
            &support,
            &none,
            KnowledgeState::Indeterminate,
        ),
        (
            EventState::Indeterminate,
            &none,
            &none,
            KnowledgeState::Indeterminate,
        ),
        // Rejection keeps retained contradicting roots alongside support: still conflicted.
        (
            EventState::Rejected,
            &support,
            &contra,
            KnowledgeState::Conflicted,
        ),
        (EventState::Rejected, &none, &none, KnowledgeState::Unknown),
    ];
    for (state, supporting, contradicting, expected) in cases {
        assert_eq!(
            physical_knowledge_state(state, supporting, contradicting),
            expected,
            "event state {} with {} supporting and {} contradicting roots",
            state.as_str(),
            supporting.len(),
            contradicting.len()
        );
    }
}

#[test]
fn physical_cell_mapping_is_pinned_for_every_evidence_mix() -> Result<(), Box<dyn Error>> {
    let support = [ContentDigest::sha256(b"supporting-witness")];
    let contra = [ContentDigest::sha256(b"contradicting-witness")];
    let none: [ContentDigest; 0] = [];
    let revision_root = ContentDigest::sha256(b"event-revision");
    let states: Vec<EventState> = (0..=u8::MAX)
        .filter_map(|tag| EventState::from_u8(tag).ok())
        .collect();
    if states.len() != 8 {
        return Err(format!("expected 8 decodable event states, found {}", states.len()).into());
    }
    for state in states {
        // (both ways, support only, contradiction only, neither). Exhaustive on purpose: a new
        // `EventState` must choose all four before this compiles. Without a supporting root no
        // state is estimated or known; indeterminate stays indeterminate rather than flattening to
        // unknown. No typed basis retires a contradiction, so evidence pointing both ways is
        // conflicted in every state.
        let (both_ways, support_only, contradiction_only, neither) = match state {
            // Unwitnessed support cannot yield an estimate (support only is unknown), but a retained
            // disagreement is still a disagreement: flattening it to unknown would hide it.
            EventState::Hypothesized => (
                KnowledgeState::Conflicted,
                KnowledgeState::Unknown,
                KnowledgeState::Unknown,
                KnowledgeState::Unknown,
            ),
            EventState::Witnessed
            | EventState::Adjudicated
            | EventState::AlertDelivered
            | EventState::Resolved => (
                KnowledgeState::Conflicted,
                KnowledgeState::Estimated,
                KnowledgeState::Unknown,
                KnowledgeState::Unknown,
            ),
            EventState::Corroborated => (
                KnowledgeState::Conflicted,
                KnowledgeState::Known,
                KnowledgeState::Unknown,
                KnowledgeState::Unknown,
            ),
            EventState::Indeterminate => (
                KnowledgeState::Conflicted,
                KnowledgeState::Indeterminate,
                KnowledgeState::Indeterminate,
                KnowledgeState::Indeterminate,
            ),
            EventState::Rejected => (
                KnowledgeState::Conflicted,
                KnowledgeState::Unknown,
                KnowledgeState::Unknown,
                KnowledgeState::Unknown,
            ),
        };
        let rows: [(&[ContentDigest], &[ContentDigest], KnowledgeState); 4] = [
            (&support, &contra, both_ways),
            (&support, &none, support_only),
            (&none, &contra, contradiction_only),
            (&none, &none, neither),
        ];
        for (supporting, contradicting, expected) in rows {
            let row = format!(
                "event state {} with {} supporting and {} contradicting roots",
                state.as_str(),
                supporting.len(),
                contradicting.len()
            );
            let actual = physical_knowledge_state(state, supporting, contradicting);
            if actual != expected {
                return Err(format!("{row}: expected {expected:?}, got {actual:?}").into());
            }
            // Build the cell exactly as `compile_reference_situation` does: the mapping must
            // yield a contract-valid cell.
            KnowledgeCell::new(KnowledgeCellParams {
                claim_id: format!("claim:event:{}:unknown-presence", state.as_str()),
                statement: physical_statement(state).to_owned(),
                knowledge_state: actual,
                provenance: ProvenanceClass::Derived,
                hypothesis: Some(policy_hypothesis(state)),
                evidence: supporting.to_vec(),
                contradictions: contradicting.to_vec(),
                valid_until: None,
                state_basis: reconciliation_basis_for(actual, revision_root),
            })
            .map_err(|error| format!("{row}: {actual:?} cell is invalid: {error}"))?;
        }
    }
    Ok(())
}

#[test]
fn compiled_physical_cell_is_conflicted_when_evidence_points_both_ways()
-> Result<(), Box<dyn Error>> {
    let mut harness = SituationHarness::new("conflicted-cell")?;
    let (decision, event_receipt) = harness.publish_decision(
        "conflicted-cell",
        &[
            (MockSemanticLabel::PersonLike, "power:alpha"),
            (MockSemanticLabel::AnimalLike, "power:beta"),
        ],
    )?;
    assert_eq!(decision.event.state, EventState::Indeterminate);
    let situation = compile_reference_situation(
        request(
            &decision,
            &event_receipt,
            capabilities(&["capability:evidence.query", "capability:session.wait"]),
        )?,
        &harness.authority,
    )?;
    let physical = situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id().ends_with(":unknown-presence"))
        .ok_or(ReferenceError::InvalidSpec("missing_physical_cell"))?;
    assert_eq!(physical.knowledge_state(), KnowledgeState::Conflicted);
    assert_eq!(physical.evidence().len(), 1);
    assert_eq!(physical.contradictions().len(), 1);

    harness.cleanup();
    Ok(())
}

const PHYSICAL_CORROBORATED: &str =
    "Independent failure domains support unknown-person presence in the retained interval.";
const PHYSICAL_WITNESSED: &str = "Unknown-person presence is supported by retained evidence but lacks independent corroboration.";
const PHYSICAL_INDETERMINATE: &str = "Unknown-person presence remains unresolved under retained supporting, contradictory, or degraded evidence.";
const PHYSICAL_REJECTED: &str =
    "The event candidate is rejected, but physical absence is not certified by this policy result.";
const PHYSICAL_BOUNDED: &str =
    "The physical event interpretation remains bounded by the retained lifecycle state.";
const POLICY_PREPARE: &str = "The reference policy independently corroborated unknown-person presence and exposed alert preparation as a separate affordance.";
const POLICY_WITNESSED_HOLD: &str = "The reference policy retained a witnessed candidate but withheld alert preparation pending independent corroboration.";
const POLICY_INDETERMINATE_HOLD: &str =
    "The reference policy retained an indeterminate candidate and withheld alert preparation.";
const POLICY_REJECTED_HOLD: &str = "The reference policy rejected this event candidate without asserting complete physical absence.";
const POLICY_NO_AUTHORITY: &str =
    "The reference policy retained the event lifecycle state without granting effect authority.";

/// Pinned projection of one event state. The match is exhaustive with no wildcard, so a new
/// `EventState` fails to compile here until its mapping is chosen deliberately.
fn pinned_projection(
    state: EventState,
) -> (
    HypothesisDisposition,
    &'static str,
    &'static str,
    &'static str,
) {
    // (hypothesis, physical statement, statement under Hold, statement under PrepareAlert)
    match state {
        EventState::Hypothesized => (
            HypothesisDisposition::Live,
            PHYSICAL_BOUNDED,
            POLICY_NO_AUTHORITY,
            POLICY_NO_AUTHORITY,
        ),
        EventState::Witnessed => (
            HypothesisDisposition::Supported,
            PHYSICAL_WITNESSED,
            POLICY_WITNESSED_HOLD,
            POLICY_NO_AUTHORITY,
        ),
        EventState::Corroborated => (
            HypothesisDisposition::Supported,
            PHYSICAL_CORROBORATED,
            POLICY_NO_AUTHORITY,
            POLICY_PREPARE,
        ),
        EventState::Adjudicated => (
            HypothesisDisposition::Live,
            PHYSICAL_BOUNDED,
            POLICY_NO_AUTHORITY,
            POLICY_NO_AUTHORITY,
        ),
        EventState::AlertDelivered => (
            HypothesisDisposition::Live,
            PHYSICAL_BOUNDED,
            POLICY_NO_AUTHORITY,
            POLICY_NO_AUTHORITY,
        ),
        EventState::Resolved => (
            HypothesisDisposition::Resolved,
            PHYSICAL_BOUNDED,
            POLICY_NO_AUTHORITY,
            POLICY_NO_AUTHORITY,
        ),
        // Unresolved evidence keeps the hypothesis open (live): never supported, never refuted,
        // and never granted effect authority.
        EventState::Indeterminate => (
            HypothesisDisposition::Live,
            PHYSICAL_INDETERMINATE,
            POLICY_INDETERMINATE_HOLD,
            POLICY_NO_AUTHORITY,
        ),
        EventState::Rejected => (
            HypothesisDisposition::Refuted,
            PHYSICAL_REJECTED,
            POLICY_REJECTED_HOLD,
            POLICY_NO_AUTHORITY,
        ),
    }
}

#[test]
fn event_state_projection_is_pinned_for_every_state() -> Result<(), Box<dyn Error>> {
    let states: Vec<EventState> = (0..=u8::MAX)
        .filter_map(|tag| EventState::from_u8(tag).ok())
        .collect();
    if states.len() != 8 {
        return Err(format!("expected 8 decodable event states, found {}", states.len()).into());
    }
    for state in states {
        let expected = pinned_projection(state);
        let actual = (
            policy_hypothesis(state),
            physical_statement(state),
            policy_statement(state, ReferencePolicyAction::Hold),
            policy_statement(state, ReferencePolicyAction::PrepareAlert),
        );
        if actual != expected {
            return Err(format!(
                "event state {} projection drifted: expected {expected:?}, got {actual:?}",
                state.as_str()
            )
            .into());
        }
    }
    Ok(())
}

// fss-deir9: a published alert outcome is recomputed from its own body before it is projected.

type VerifiedFixture = (
    SituationHarness,
    ReferencePolicyDecision,
    ReferenceEventReceipt,
    crate::ReferenceAlertPlan,
    crate::ReferenceAlertOutcomeReceipt,
);

/// Publishes a delivered-and-verified alert outcome and returns what compile needs.
fn verified_outcome_fixture(name: &str) -> Result<VerifiedFixture, Box<dyn Error>> {
    let mut harness = SituationHarness::new(name)?;
    let (decision, event_receipt) = harness.publish_decision(
        name,
        &[
            (MockSemanticLabel::PersonLike, "power:alpha"),
            (MockSemanticLabel::PersonLike, "power:beta"),
        ],
    )?;
    let mut journal = EffectJournal::new();
    let plan = prepare_reference_alert(
        PrepareAlertParams {
            decision: &decision,
            event_receipt: &event_receipt,
            authority: &harness.authority,
            operation_id: OperationId::parse(format!("operation:situation:{name}"))?,
            idempotency_key: IdempotencyKey::parse(format!("idempotency:situation:{name}"))?,
            obligation_id: ObligationId::parse(format!("obligation:situation:{name}"))?,
            channel: "operator:oncall".to_owned(),
            now: TimestampNs(100),
        },
        &mut journal,
    )?;
    let mut provider =
        ReferenceAlertProvider::with_provider_id(format!("provider:test:situation:{name}"));
    let _ = dispatch_reference_alert(
        &plan,
        &harness.authority,
        &harness.objects,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(101),
        TimestampNs(102),
        &mut journal,
        &mut provider,
    )?;
    let provider_receipt = provider
        .lookup(&plan.intent)?
        .ok_or(ReferenceError::InvalidSpec("missing_provider_receipt"))?;
    let _ = observe_reference_alert(
        &plan,
        provider_receipt.receipt_digest(),
        TimestampNs(103),
        &mut journal,
        &provider,
    )?;
    let _ = verify_reference_alert(&plan, TimestampNs(104), &mut journal, &provider)?;
    let outcome = publish_reference_alert_outcome(
        &plan,
        &journal,
        &mut harness.objects,
        &mut harness.authority,
        &provider,
    )?;
    Ok((harness, decision, event_receipt, plan, outcome))
}

/// A Verified (or Failed) receipt without its result digest is refused instead of publishing an
/// evidence-less `known` effect cell.
#[test]
fn terminal_effect_outcome_without_result_digest_is_refused() -> Result<(), Box<dyn Error>> {
    let (harness, decision, event_receipt, plan, outcome) = verified_outcome_fixture("digestless")?;
    assert_eq!(
        outcome.outcome.operation_receipt.state,
        fss_core::EffectState::Verified
    );
    for state in [
        fss_core::EffectState::Verified,
        fss_core::EffectState::Failed,
    ] {
        let mut tampered = outcome.clone();
        tampered.outcome.operation_receipt.state = state;
        tampered.outcome.operation_receipt.result_digest = None;
        let mut compile_request = request(
            &decision,
            &event_receipt,
            capabilities(&["capability:alert.commit"]),
        )?;
        compile_request.alert_plan = Some(&plan);
        compile_request.alert_outcome = Some(&tampered);
        compile_request.previous_anchor = Some(event_receipt.authority_anchor.clone());
        let compiled = compile_reference_situation(compile_request, &harness.authority);
        assert!(
            matches!(
                compiled,
                Err(ReferenceError::InvalidSpec("situation_effect_outcome"))
            ),
            "{state:?} without result digest: {compiled:?}"
        );
    }
    harness.cleanup();
    Ok(())
}

/// Second angle on the KSTATE-001 guard (fss-kdhh7): a terminal outcome whose result digest and
/// proof object digest are both dropped, with every caller-held digest re-derived to match, is
/// still refused as an effect outcome without a proved root. Without the guard the body would
/// reach the root recomputation and fail only as a digest mismatch.
#[test]
fn terminal_effect_outcome_without_result_digest_is_refused_even_when_rederived()
-> Result<(), Box<dyn Error>> {
    use fss_core::CanonicalEncode;

    let (harness, decision, event_receipt, plan, outcome) =
        verified_outcome_fixture("digestless-rederived")?;
    for state in [
        fss_core::EffectState::Failed,
        fss_core::EffectState::Verified,
    ] {
        let mut tampered = outcome.clone();
        tampered.outcome.operation_receipt.state = state;
        tampered.outcome.operation_receipt.result_digest = None;
        tampered.outcome.proof_object_digest = None;
        tampered.outcome.operation_object_digest =
            ContentDigest::sha256(&tampered.outcome.operation_receipt.canonical_bytes());
        tampered.outcome_object_digest = ContentDigest::sha256(&tampered.outcome.canonical_bytes());
        let mut compile_request = request(
            &decision,
            &event_receipt,
            capabilities(&["capability:alert.commit"]),
        )?;
        compile_request.alert_plan = Some(&plan);
        compile_request.alert_outcome = Some(&tampered);
        compile_request.previous_anchor = Some(event_receipt.authority_anchor.clone());
        let compiled = compile_reference_situation(compile_request, &harness.authority);
        assert!(
            matches!(
                compiled,
                Err(ReferenceError::InvalidSpec("situation_effect_outcome"))
            ),
            "{state:?} without result or proof digest, re-derived: {compiled:?}"
        );
    }
    harness.cleanup();
    Ok(())
}

/// `validate_request` binds the receipt to the ledger only through `outcome_root`, so the root must
/// be recomputed from the outcome body: an edited result digest is refused even when every digest
/// the caller holds is re-derived to match it.
#[test]
fn forged_result_digest_is_refused() -> Result<(), Box<dyn Error>> {
    use fss_core::CanonicalEncode;

    let (harness, decision, event_receipt, plan, outcome) = verified_outcome_fixture("forged")?;
    let forged = ContentDigest::sha256(b"forged-provider-proof");
    for rederive in [false, true] {
        let mut tampered = outcome.clone();
        tampered.outcome.operation_receipt.result_digest = Some(forged);
        if rederive {
            tampered.outcome.proof_object_digest = Some(forged);
            tampered.outcome.operation_object_digest =
                ContentDigest::sha256(&tampered.outcome.operation_receipt.canonical_bytes());
            tampered.outcome_object_digest =
                ContentDigest::sha256(&tampered.outcome.canonical_bytes());
        }
        let mut compile_request = request(
            &decision,
            &event_receipt,
            capabilities(&["capability:alert.commit"]),
        )?;
        compile_request.alert_plan = Some(&plan);
        compile_request.alert_outcome = Some(&tampered);
        compile_request.previous_anchor = Some(event_receipt.authority_anchor.clone());
        let compiled = compile_reference_situation(compile_request, &harness.authority);
        assert!(
            matches!(compiled, Err(ReferenceError::DigestMismatch)),
            "forged result digest (re-derived: {rederive}): {compiled:?}"
        );
    }
    // The genuine outcome still compiles, and its effect evidence is a retained proof root.
    let mut compile_request = request(
        &decision,
        &event_receipt,
        capabilities(&["capability:alert.commit"]),
    )?;
    compile_request.alert_plan = Some(&plan);
    compile_request.alert_outcome = Some(&outcome);
    compile_request.previous_anchor = Some(event_receipt.authority_anchor.clone());
    let situation = compile_reference_situation(compile_request, &harness.authority)?;
    let effect = situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id().starts_with("claim:effect:"))
        .ok_or(ReferenceError::InvalidSpec("missing_effect_cell"))?;
    assert_eq!(effect.knowledge_state(), KnowledgeState::Known);
    assert!(!effect.evidence().is_empty());
    assert!(
        effect
            .evidence()
            .iter()
            .all(|root| situation.proof_roots.contains(root)),
        "{:?}",
        effect.evidence()
    );
    harness.cleanup();
    Ok(())
}

/// fss-6sph6: the compile path binds a verified outcome cell with its typed kind, and a proved
/// outcome cannot be relabeled (for example from delivered to failed) or re-wrapped without that
/// binding.
#[test]
fn verified_outcome_cell_is_bound_and_cannot_be_relabeled() -> Result<(), Box<dyn Error>> {
    let (harness, decision, event_receipt, plan, outcome) = verified_outcome_fixture("bound")?;
    let mut compile_request = request(
        &decision,
        &event_receipt,
        capabilities(&["capability:alert.commit"]),
    )?;
    compile_request.alert_plan = Some(&plan);
    compile_request.alert_outcome = Some(&outcome);
    compile_request.previous_anchor = Some(event_receipt.authority_anchor.clone());
    let situation = compile_reference_situation(compile_request, &harness.authority)?;
    situation.verify()?;
    let claim_id = format!("claim:effect:{}:outcome", plan.intent.operation_id.as_str());
    assert_eq!(
        situation.effect_cell_kind(&claim_id),
        Some(crate::EffectCellKind::Outcome)
    );

    let mut relabeled = situation.clone();
    for cell in &mut relabeled.capsule.frame.knowledge_cells {
        if cell.claim_id() == claim_id {
            let mut params = cell.to_params();
            params.statement =
                "Alert delivery is terminally failed by retained non-delivery proof.".to_owned();
            *cell = KnowledgeCell::new(params)?;
        }
    }
    let refused = relabeled.verify();
    assert!(
        matches!(
            refused,
            Err(ReferenceError::InvalidSpec(
                "situation_effect_cell_relabeled"
            ))
        ),
        "{refused:?}"
    );

    let unbound =
        crate::ReferenceSituation::new(situation.capsule.clone(), situation.proof_roots.clone());
    assert_eq!(unbound.effect_cell_kind(&claim_id), None);
    let refused = unbound.verify();
    assert!(
        matches!(
            refused,
            Err(ReferenceError::InvalidSpec(
                "situation_effect_known_unbound"
            ))
        ),
        "{refused:?}"
    );
    harness.cleanup();
    Ok(())
}

#[test]
fn compiled_corroborated_cell_with_contradicting_edge_is_conflicted() -> Result<(), Box<dyn Error>>
{
    let mut harness = SituationHarness::new("corroborated-conflict")?;
    let (mut decision, _) = harness.publish_decision(
        "corroborated-conflict-policy",
        &[
            (MockSemanticLabel::PersonLike, "power:alpha"),
            (MockSemanticLabel::PersonLike, "power:beta"),
        ],
    )?;
    assert_eq!(decision.event.state, EventState::Corroborated);
    // Corroboration counts only supporting edges, so a retained Contradicts edge is admissible.
    let mut contradicting = decision
        .event
        .evidence
        .first()
        .ok_or(ReferenceError::InvalidSpec("missing_evidence"))?
        .clone();
    contradicting.digest = ContentDigest::sha256(b"corroborated-contradicting-witness");
    contradicting.failure_domain = "power:gamma".to_owned();
    contradicting.supports = false;
    contradicting.relation = EvidenceEdgeRelation::Contradicts;
    decision.event.evidence.push(contradicting);
    decision.event.event_id = EventId::parse("event:situation:corroborated-conflict")?;
    let event_receipt =
        publish_reference_event(&decision, &mut harness.objects, &mut harness.authority)?;

    let situation = compile_reference_situation(
        request(
            &decision,
            &event_receipt,
            capabilities(&["capability:alert.prepare"]),
        )?,
        &harness.authority,
    )?;
    let physical = situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id().ends_with(":unknown-presence"))
        .ok_or(ReferenceError::InvalidSpec("missing_physical_cell"))?;
    assert_eq!(physical.knowledge_state(), KnowledgeState::Conflicted);
    assert_eq!(physical.evidence().len(), 2);
    assert_eq!(physical.contradictions().len(), 1);

    harness.cleanup();
    Ok(())
}

#[test]
fn contradiction_only_witnessed_revision_is_refused_at_compile() -> Result<(), Box<dyn Error>> {
    let mut harness = SituationHarness::new("contradiction-only-witnessed")?;
    let (mut decision, clean_receipt) = harness.publish_decision(
        "contradiction-only-witnessed-policy",
        &[(MockSemanticLabel::PersonLike, "power:alpha")],
    )?;
    assert_eq!(decision.event.state, EventState::Witnessed);
    // The reviewer's probe: every edge flipped to Contradicts under a fresh event identity.
    for edge in &mut decision.event.evidence {
        edge.supports = false;
        edge.relation = EvidenceEdgeRelation::Contradicts;
    }
    decision.event.event_id = EventId::parse("event:situation:contradiction-only-witnessed")?;
    assert_eq!(
        decision.event.validate(),
        Err(ContractError::SupportingEvidenceRequired)
    );
    // Publication verifies, so the revision never becomes authority...
    let published =
        publish_reference_event(&decision, &mut harness.objects, &mut harness.authority);
    assert!(
        matches!(
            published,
            Err(ReferenceError::Contract(
                ContractError::SupportingEvidenceRequired
            ))
        ),
        "{published:?}"
    );
    // ...and compile refuses it before any receipt check, even against a real authority receipt.
    let event_receipt = clean_receipt;
    let compiled = compile_reference_situation(
        request(
            &decision,
            &event_receipt,
            capabilities(&["capability:evidence.query", "capability:session.wait"]),
        )?,
        &harness.authority,
    );
    assert!(
        matches!(
            compiled,
            Err(ReferenceError::Contract(
                ContractError::SupportingEvidenceRequired
            ))
        ),
        "{compiled:?}"
    );

    harness.cleanup();
    Ok(())
}

#[test]
fn neutral_only_witnessed_revision_is_refused_at_compile() -> Result<(), Box<dyn Error>> {
    let mut harness = SituationHarness::new("neutral-only-witnessed")?;
    let (mut decision, clean_receipt) = harness.publish_decision(
        "neutral-only-witnessed-policy",
        &[(MockSemanticLabel::PersonLike, "power:alpha")],
    )?;
    assert_eq!(decision.event.state, EventState::Witnessed);
    // A derivation edge carries no evidential direction, so it cannot witness the candidate.
    for edge in &mut decision.event.evidence {
        edge.supports = false;
        edge.relation = EvidenceEdgeRelation::DerivedFrom;
    }
    decision.event.event_id = EventId::parse("event:situation:neutral-only-witnessed")?;
    // Publication verifies, so the revision never becomes authority...
    let published =
        publish_reference_event(&decision, &mut harness.objects, &mut harness.authority);
    assert!(
        matches!(
            published,
            Err(ReferenceError::Contract(
                ContractError::SupportingEvidenceRequired
            ))
        ),
        "{published:?}"
    );
    // ...and compile refuses it before any receipt check, even against a real authority receipt.
    let event_receipt = clean_receipt;
    let compiled = compile_reference_situation(
        request(
            &decision,
            &event_receipt,
            capabilities(&["capability:evidence.query", "capability:session.wait"]),
        )?,
        &harness.authority,
    );
    assert!(
        matches!(
            compiled,
            Err(ReferenceError::Contract(
                ContractError::SupportingEvidenceRequired
            ))
        ),
        "{compiled:?}"
    );

    harness.cleanup();
    Ok(())
}

/// Compiles a decision from PersonLike on `power:alpha` plus `second` on `power:beta`.
fn compiled_situation(
    name: &str,
    second: MockSemanticLabel,
) -> Result<(ReferencePolicyDecision, crate::ReferenceSituation), Box<dyn Error>> {
    let mut harness = SituationHarness::new(name)?;
    let (decision, event_receipt) = harness.publish_decision(
        name,
        &[
            (MockSemanticLabel::PersonLike, "power:alpha"),
            (second, "power:beta"),
        ],
    )?;
    let situation = compile_reference_situation(
        request(
            &decision,
            &event_receipt,
            capabilities(&["capability:evidence.query", "capability:session.wait"]),
        )?,
        &harness.authority,
    )?;
    harness.cleanup();
    Ok((decision, situation))
}

fn cell_ending<'a>(
    situation: &'a crate::ReferenceSituation,
    suffix: &str,
) -> Option<&'a KnowledgeCell> {
    situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id().ends_with(suffix))
}

#[test]
fn unknown_finding_keeps_the_physical_cell_indeterminate_with_its_basis()
-> Result<(), Box<dyn Error>> {
    let (decision, situation) = compiled_situation("person-unknown", MockSemanticLabel::Unknown)?;
    assert_eq!(decision.event.state, EventState::Indeterminate);
    // An unknown finding is an abstention on presence: never counted as a contradiction.
    assert!(
        !decision
            .event
            .evidence
            .iter()
            .any(|edge| edge.relation == EvidenceEdgeRelation::Contradicts)
    );
    let physical = cell_ending(&situation, ":unknown-presence")
        .ok_or(ReferenceError::InvalidSpec("missing_physical_cell"))?;
    assert_eq!(physical.knowledge_state(), KnowledgeState::Indeterminate);
    assert!(physical.state_basis().is_some());
    assert_eq!(
        physical.state_basis(),
        reconciliation_basis_for(
            KnowledgeState::Indeterminate,
            decision.event.revision_digest()
        )
        .as_ref()
    );
    assert_eq!(physical.evidence().len(), 1);
    assert!(physical.contradictions().is_empty());
    // Nor is it a tamper report: no integrity claim and no tamper world.
    assert!(cell_ending(&situation, ":sensor-integrity").is_none());
    assert!(
        !situation
            .capsule
            .frame
            .world_envelope
            .world_ids()
            .iter()
            .any(|world| world.ends_with(":sensor-tamper"))
    );
    Ok(())
}

#[test]
fn tamper_finding_is_a_typed_integrity_risk_not_a_presence_contradiction()
-> Result<(), Box<dyn Error>> {
    let (decision, situation) = compiled_situation("person-tamper", MockSemanticLabel::TamperLike)?;
    assert_eq!(decision.event.state, EventState::Indeterminate);
    // The tamper finding is typed on the event edge and never counted against presence.
    let tamper_roots: Vec<_> = decision
        .event
        .evidence
        .iter()
        .filter(|edge| edge.relation == EvidenceEdgeRelation::SensorTamper && !edge.supports)
        .map(|edge| edge.digest)
        .collect();
    assert_eq!(tamper_roots.len(), 1);
    assert!(
        !decision
            .event
            .evidence
            .iter()
            .any(|edge| edge.counts_as_contradiction())
    );
    let physical = cell_ending(&situation, ":unknown-presence")
        .ok_or(ReferenceError::InvalidSpec("missing_physical_cell"))?;
    assert_eq!(physical.knowledge_state(), KnowledgeState::Indeterminate);
    assert!(physical.state_basis().is_some());
    assert!(physical.contradictions().is_empty());
    // Typed risk: a sensor-integrity claim contradicted by exactly the tamper roots.
    let integrity = cell_ending(&situation, ":sensor-integrity")
        .ok_or(ReferenceError::InvalidSpec("missing_integrity_cell"))?;
    assert_eq!(integrity.knowledge_state(), KnowledgeState::Unknown);
    assert_eq!(
        integrity.hypothesis(),
        Some(HypothesisDisposition::Disfavored)
    );
    assert!(integrity.evidence().is_empty());
    assert_eq!(integrity.contradictions(), tamper_roots);
    // A protected adversarial world names the tampered roots, and at_risk states the risk.
    let world = situation
        .capsule
        .frame
        .world_envelope
        .adversarial_residuals
        .iter()
        .find(|world| world.world_id.ends_with(":sensor-tamper"))
        .ok_or(ReferenceError::InvalidSpec("missing_tamper_world"))?;
    assert!(world.protected);
    assert!(world.consequence_severity >= 4);
    assert_eq!(world.evidence, tamper_roots);
    assert!(world.claim_ids.contains(integrity.claim_id()));
    assert!(
        situation
            .capsule
            .frame
            .at_risk
            .iter()
            .any(|risk| risk.starts_with("Sensor tamper is reported"))
    );
    Ok(())
}

/// fss-mnlz1 R5-2: a rejected event's publication, chained after the publication of another event
/// in the same mission, carries refuted-hypothesis cells, but a different subject: it never
/// terminalizes the other event's cells.
#[test]
fn another_events_rejection_never_terminalizes_this_event() -> Result<(), Box<dyn Error>> {
    let mut harness = SituationHarness::new("r52")?;
    let (corroborated, corroborated_receipt) = harness.publish_decision(
        "r52-corroborated",
        &[
            (MockSemanticLabel::PersonLike, "power:alpha"),
            (MockSemanticLabel::PersonLike, "power:beta"),
        ],
    )?;
    let (rejected, rejected_receipt) = harness.publish_decision(
        "r52-rejected",
        &[(MockSemanticLabel::AnimalLike, "power:alpha")],
    )?;
    assert_eq!(rejected.event.state, EventState::Rejected);
    let spec = crate::situation_guard_tests::guard_projection_spec()?;
    let basis = crate::project_reference_situation(
        compile_reference_situation(
            request(
                &corroborated,
                &corroborated_receipt,
                capabilities(&["capability:alert.prepare"]),
            )?,
            &harness.authority,
        )?,
        &spec,
    )?;
    crate::record_reference_publication(&mut harness.authority, &basis)?;
    // The lineage refuses another event's publication as a predecessor at compile time.
    let mut rejected_request = request(
        &rejected,
        &rejected_receipt,
        capabilities(&["capability:evidence.query", "capability:session.wait"]),
    )?;
    rejected_request.predecessor_publication = Some(basis.publication_digest);
    let chained = compile_reference_situation(rejected_request, &harness.authority);
    assert!(
        matches!(
            chained,
            Err(ReferenceError::InvalidSpec(
                "situation_predecessor_not_latest"
            ))
        ),
        "{:?}",
        chained.map(|situation| situation.capsule.capsule_id)
    );
    let result = crate::project_reference_situation(
        compile_reference_situation(
            request(
                &rejected,
                &rejected_receipt,
                capabilities(&["capability:evidence.query", "capability:session.wait"]),
            )?,
            &harness.authority,
        )?,
        &spec,
    )?;
    crate::record_reference_publication(&mut harness.authority, &result)?;
    assert!(
        result
            .situation
            .capsule
            .frame
            .knowledge_cells
            .iter()
            .any(|cell| cell.hypothesis() == Some(HypothesisDisposition::Refuted)),
        "{:?}",
        result.situation.capsule.frame.knowledge_cells
    );
    assert_ne!(basis.situation.subject(), result.situation.subject());
    let delta = crate::classify_reference_meaningful_delta_in_lineage(
        &basis,
        &result,
        &harness.authority,
        None,
    )?;
    assert!(
        !delta
            .classes
            .contains(&fss_core::MeaningfulDeltaClass::TerminalTransition),
        "{:?}",
        delta.classes
    );
    assert!(
        delta
            .classes
            .contains(&fss_core::MeaningfulDeltaClass::MaterialState),
        "{:?}",
        delta.classes
    );
    delta.validate()?;
    harness.cleanup();
    Ok(())
}
