#![forbid(unsafe_code)]
//! Verification of meaningful delta invariants: silence certificates under degraded coverage,
//! terminal transition non-coalescing, and plan invalidation on Estimated and Known premises.

use std::collections::BTreeSet;
use std::error::Error;

use fss_core::{
    ActionAffordance, AffordanceClass, BudgetVector, Completeness, ContentDigest, ContractBasis,
    ContractBasisRegistryBytes, ContractError, DeltaPriority, HypothesisDisposition, KnowledgeCell,
    KnowledgeState, LedgerAnchor, MeaningfulDeltaClass, MissionId, ObligationId, PrincipalId,
    ProvenanceClass, ResourcePressure, SessionId, SituationCapsule, SituationFrame, TimestampNs,
    WorldEnvelope,
};

use fss_reference::{
    ReferenceProjectionSpec, ReferenceSituation, ReferenceSituationPublication,
    classify_reference_meaningful_delta, project_reference_situation,
};

#[derive(Clone, Debug)]
struct Variant {
    sequence: u64,
    completeness: Completeness,
    coverage: BTreeSet<String>,
    premise_state: KnowledgeState,
    premise_contradictions: Vec<ContentDigest>,
    premise_hypothesis: Option<HypothesisDisposition>,
    include_affordance: bool,
    obligations: Vec<ObligationId>,
    effect_state: Option<KnowledgeState>,
    pressure: ResourcePressure,
    degraded_dimensions: BTreeSet<String>,
    mission_statement: String,
    custom_cells: Vec<KnowledgeCell>,
}

impl Variant {
    fn baseline() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            sequence: 1,
            completeness: Completeness::Complete,
            coverage: BTreeSet::from([
                "fss://coverage/alpha".to_owned(),
                "fss://coverage/beta".to_owned(),
            ]),
            premise_state: KnowledgeState::Known,
            premise_contradictions: Vec::new(),
            premise_hypothesis: None,
            include_affordance: true,
            obligations: Vec::new(),
            effect_state: None,
            pressure: ResourcePressure::Nominal,
            degraded_dimensions: BTreeSet::new(),
            mission_statement: "The reference mission remains active.".to_owned(),
            custom_cells: Vec::new(),
        })
    }
}

fn test_basis() -> ContractBasis {
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

fn publication(variant: &Variant) -> Result<ReferenceSituationPublication, Box<dyn Error>> {
    let mut anchor = LedgerAnchor::genesis("site:meaningful-delta");
    anchor.commit_sequence = variant.sequence;
    let evidence = ContentDigest::sha256(b"meaningful-delta-evidence");
    let world = fss_core::PossibleWorld {
        world_id: "world:meaningful-delta:protected".to_owned(),
        description: "A protected world remains decision-relevant.".to_owned(),
        claim_ids: BTreeSet::from(["claim:premise".to_owned()]),
        evidence: vec![evidence],
        consequence_severity: 5,
        protected: true,
    };
    let world_envelope = WorldEnvelope {
        envelope_id: format!("world-envelope:meaningful-delta:{}", variant.sequence),
        objective_id: "objective:meaningful-delta".to_owned(),
        anchor: anchor.clone(),
        nominal_claim_ids: BTreeSet::from(["claim:premise".to_owned()]),
        certified_core_claim_ids: BTreeSet::new(),
        alternatives: vec![world],
        adversarial_residuals: Vec::new(),
        common_invariants: BTreeSet::from(["invariant:no-blind-effect".to_owned()]),
        coverage_boundary_handles: variant.coverage.clone(),
    };
    let retained_worlds = world_envelope.world_ids();
    let affordances = if variant.include_affordance {
        vec![ActionAffordance {
            affordance_id: "affordance:meaningful-delta:investigate".to_owned(),
            operation: "investigate".to_owned(),
            target: "fss://event/meaningful-delta/evidence".to_owned(),
            rationale: "Acquire independent evidence.".to_owned(),
            class: AffordanceClass::Probe,
            supported_worlds: retained_worlds,
            unsafe_worlds: BTreeSet::new(),
            required_capabilities: BTreeSet::from(["capability:evidence.query".to_owned()]),
            cost: BudgetVector::builder()
                .latency_ms(100)
                .tokens(50)
                .bytes(1_024)
                .cpu_millis(10)
                .accelerator_millis(5)
                .energy_millijoules(20)
                .privacy_exposure(0.1)
                .build()?,
            reversible: true,
            branch_predicate: None,
        }]
    } else {
        Vec::new()
    };
    let mut knowledge_cells = vec![KnowledgeCell {
        claim_id: "claim:premise".to_owned(),
        statement: "The reference premise has the current typed state.".to_owned(),
        knowledge_state: variant.premise_state,
        provenance: ProvenanceClass::Derived,
        hypothesis: variant.premise_hypothesis,
        evidence: vec![evidence],
        contradictions: variant.premise_contradictions.clone(),
        valid_until: None,
    }];
    if let Some(effect_state) = variant.effect_state {
        knowledge_cells.push(KnowledgeCell {
            claim_id: "claim:effect:meaningful-delta:outcome".to_owned(),
            statement: match effect_state {
                KnowledgeState::Indeterminate => {
                    "The external effect may have happened and requires reconciliation."
                }
                KnowledgeState::Known => {
                    "Alert delivery is terminally verified by retained provider proof."
                }
                _ => "The external effect has another explicit typed state.",
            }
            .to_owned(),
            knowledge_state: effect_state,
            provenance: ProvenanceClass::Observed,
            hypothesis: None,
            evidence: vec![ContentDigest::sha256(b"effect-outcome")],
            contradictions: Vec::new(),
            valid_until: None,
        });
    }
    knowledge_cells.extend(variant.custom_cells.iter().cloned());
    knowledge_cells.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));

    let next = affordances
        .iter()
        .map(|affordance| affordance.affordance_id.clone())
        .collect();
    let frame = SituationFrame {
        frame_id: format!("frame:meaningful-delta:{}", variant.sequence),
        objective_id: "objective:meaningful-delta".to_owned(),
        anchor: anchor.clone(),
        world_envelope,
        knowledge_cells,
        now: vec![variant.mission_statement.clone()],
        changed: Vec::new(),
        why: vec!["The typed evidence frontier determines the available control.".to_owned()],
        unknown: Vec::new(),
        at_risk: Vec::new(),
        next,
        evidence_handles: BTreeSet::from([format!("fss://proof/{evidence}")]),
    };
    let capsule = SituationCapsule {
        capsule_id: format!("situation:meaningful-delta:{}", variant.sequence),
        revision: variant.sequence,
        contract_basis: test_basis(),
        mission_id: MissionId::parse("mission:meaningful-delta")?,
        session_id: SessionId::parse("session:meaningful-delta")?,
        principal_id: PrincipalId::parse("principal:meaningful-delta")?,
        anchor,
        previous_anchor: None,
        frame,
        obligations: variant.obligations.clone(),
        affordances,
        completeness: variant.completeness,
        created_at: TimestampNs(1_000 + i128::from(variant.sequence)),
    };
    capsule.validate()?;
    let situation = ReferenceSituation {
        capsule,
        proof_roots: BTreeSet::from([evidence]),
    };
    project_reference_situation(
        situation,
        &ReferenceProjectionSpec {
            view_id: "AVIEW-001".to_owned(),
            available_resources: BudgetVector::builder()
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
            reserved_resources: BudgetVector::builder()
                .latency_ms(100)
                .tokens(100)
                .bytes(1_000)
                .storage_operations(1)
                .build()?,
            pressure: variant.pressure,
            degraded_dimensions: variant.degraded_dimensions.clone(),
            target_tokens: 25_000,
        },
    )
    .map_err(|error| -> Box<dyn Error> { Box::new(error) })
}

/// F1: A silence certificate must never be issued under degraded coverage or coverage gaps.
#[test]
fn test_f1_silence_certificate_rejected_when_coverage_degraded() -> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.completeness = Completeness::Partial;

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.completeness = Completeness::Partial;

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta.silence_certificate.is_none(),
        "Silence certificate must not be issued during degraded coverage!"
    );
    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss),
        "Degraded-but-unchanged comparison must report CoverageLoss!"
    );
    assert_ne!(
        delta.classes,
        BTreeSet::from([MeaningfulDeltaClass::NoMeaningfulChange]),
        "NoMeaningfulChange must never certify silence during degraded coverage!"
    );
    assert!(
        delta.is_non_coalescible(),
        "CoverageLoss must be non-coalescible!"
    );
    delta.validate()?;
    Ok(())
}

/// F4: Terminal event transition (e.g. candidate rejection or resolution) emits TerminalTransition
/// and is non-coalescible, proven by a coalescing attempt that is rejected.
#[test]
fn test_f4_terminal_event_transition_is_non_coalescible() -> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.premise_hypothesis = Some(HypothesisDisposition::Supported);

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.premise_hypothesis = Some(HypothesisDisposition::Refuted);

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    let delta1 = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta1
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "Terminal event rejection must emit TerminalTransition!"
    );
    assert!(
        delta1.is_non_coalescible(),
        "Terminal transition must be non-coalescible!"
    );
    assert_eq!(delta1.priority, DeltaPriority::Critical);

    let mut v3 = Variant::baseline()?;
    v3.sequence = 3;
    v3.pressure = ResourcePressure::Elevated;
    let pub3 = publication(&v3)?;
    let delta2 = classify_reference_meaningful_delta(&pub2, &pub3)?;

    let can_coalesce = delta1.can_coalesce_with(&delta2)?;
    assert!(
        !can_coalesce,
        "TerminalTransition must never coalesce with subsequent deltas!"
    );
    let coalesce_result = delta1.coalesce(
        &delta2,
        "delta:coalesced",
        "continuation:coalesced",
        ContentDigest::sha256(b"coalesced"),
    );
    assert!(
        coalesce_result.is_err(),
        "Coalescing a terminal transition delta must fail!"
    );

    delta1.validate()?;
    Ok(())
}

/// F4: Obligation terminalization (active obligation resolved/removed) emits TerminalTransition.
#[test]
fn test_f4_obligation_terminalization_emits_terminal_transition() -> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.obligations = vec![ObligationId::parse("obligation:test:001")?];

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.obligations.clear();

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "Obligation terminalization must emit TerminalTransition!"
    );
    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::Obligation),
        "Obligation transition must emit Obligation class!"
    );
    assert!(
        delta.is_non_coalescible(),
        "Terminal obligation delta must be non-coalescible!"
    );
    delta.validate()?;
    Ok(())
}

/// F4: Effect terminalization emits TerminalTransition and is non-coalescible.
#[test]
fn test_f4_effect_terminalization_emits_terminal_transition() -> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.effect_state = Some(KnowledgeState::Indeterminate);

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.effect_state = Some(KnowledgeState::Known);

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "Effect terminalization must emit TerminalTransition!"
    );
    assert!(
        delta.is_non_coalescible(),
        "Effect terminal transition must be non-coalescible!"
    );
    delta.validate()?;
    Ok(())
}

/// F4: Mission terminalization (mission active -> concluded) emits TerminalTransition.
#[test]
fn test_f4_mission_terminalization_emits_terminal_transition() -> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.mission_statement = "The reference mission remains active.".to_owned();

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.mission_statement = "The reference mission has concluded.".to_owned();

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "Mission terminalization must emit TerminalTransition!"
    );
    assert!(
        delta.is_non_coalescible(),
        "Mission terminal transition must be non-coalescible!"
    );
    delta.validate()?;
    Ok(())
}

/// F5: Plan invalidation must be emitted when an Estimated premise degrades or disappears.
#[test]
fn test_f5_plan_invalidation_emitted_for_estimated_premise() -> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.premise_state = KnowledgeState::Estimated;

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.premise_state = KnowledgeState::Unknown;

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::PlanInvalidation),
        "Invalidation of an Estimated premise must emit PlanInvalidation!"
    );
    assert!(
        !delta.invalidated_assumptions.is_empty(),
        "Invalidated assumptions must not be empty!"
    );
    assert!(
        delta
            .invalidated_assumptions
            .iter()
            .any(|a| a.contains("estimated premise claim:premise became unknown")),
        "Invalidated assumption must describe the estimated premise transition!"
    );
    assert!(
        delta.is_non_coalescible(),
        "PlanInvalidation must be non-coalescible!"
    );
    delta.validate()?;
    Ok(())
}

/// F5: Plan invalidation must be emitted when a Known premise degrades to Estimated.
#[test]
fn test_f5_plan_invalidation_emitted_when_known_degrades_to_estimated() -> Result<(), Box<dyn Error>>
{
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.premise_state = KnowledgeState::Known;

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.premise_state = KnowledgeState::Estimated;

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    let delta = classify_reference_meaningful_delta(&pub1, &pub2)?;

    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::PlanInvalidation),
        "Degradation from Known to Estimated must emit PlanInvalidation!"
    );
    assert!(
        !delta.invalidated_assumptions.is_empty(),
        "Invalidated assumptions must not be empty!"
    );
    assert!(
        delta.is_non_coalescible(),
        "PlanInvalidation must be non-coalescible!"
    );
    delta.validate()?;
    Ok(())
}

/// Proven coalescing test: non-critical deltas coalesce, but any delta carrying
/// a terminal transition or plan invalidation is preserved and cannot be coalesced.
#[test]
fn test_coalescing_preserves_terminal_and_invalidation_deltas() -> Result<(), Box<dyn Error>> {
    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.pressure = ResourcePressure::Nominal;

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.pressure = ResourcePressure::Elevated;
    v2.degraded_dimensions = BTreeSet::from(["model_calls".to_owned()]);

    let mut v3 = Variant::baseline()?;
    v3.sequence = 3;
    v3.premise_hypothesis = Some(HypothesisDisposition::Refuted);

    let pub1 = publication(&v1)?;
    let pub2 = publication(&v2)?;
    let pub3 = publication(&v3)?;

    let delta_budget = classify_reference_meaningful_delta(&pub1, &pub2)?;
    let delta_terminal = classify_reference_meaningful_delta(&pub2, &pub3)?;

    assert!(!delta_budget.is_non_coalescible());
    assert!(delta_terminal.is_non_coalescible());

    assert_eq!(delta_budget.can_coalesce_with(&delta_terminal)?, false);
    assert_eq!(delta_terminal.can_coalesce_with(&delta_budget)?, false);

    let result = delta_budget.coalesce(
        &delta_terminal,
        "delta:coalesced",
        "continuation:coalesced",
        ContentDigest::sha256(b"coalesced"),
    );
    assert_eq!(result.unwrap_err(), ContractError::EvidenceRequired);

    Ok(())
}
