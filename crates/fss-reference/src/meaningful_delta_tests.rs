use std::collections::BTreeSet;
use std::error::Error;

use fss_core::{
    ActionAffordance, AffordanceClass, BudgetVector, Completeness, ContentDigest, ContractBasis,
    DeltaPriority, KnowledgeCell, KnowledgeState, LedgerAnchor, MeaningfulDeltaClass, MissionId,
    ObligationId, PrincipalId, ProvenanceClass, ResourcePressure, SessionId, SituationCapsule,
    SituationFrame, TimestampNs, WorldEnvelope,
};

use crate::{
    ReferenceProjectionSpec, ReferenceSituation, classify_reference_meaningful_delta,
    project_reference_situation,
};

#[derive(Clone, Debug)]
struct Variant {
    sequence: u64,
    completeness: Completeness,
    coverage: BTreeSet<String>,
    premise_state: KnowledgeState,
    premise_contradictions: Vec<ContentDigest>,
    include_affordance: bool,
    obligations: Vec<ObligationId>,
    effect_state: Option<KnowledgeState>,
    pressure: ResourcePressure,
    degraded_dimensions: BTreeSet<String>,
}

impl Variant {
    fn baseline() -> Result<Self, fss_core::ContractError> {
        Ok(Self {
            sequence: 1,
            completeness: Completeness::Complete,
            coverage: BTreeSet::from([
                "fss://coverage/alpha".to_owned(),
                "fss://coverage/beta".to_owned(),
            ]),
            premise_state: KnowledgeState::Known,
            premise_contradictions: Vec::new(),
            include_affordance: true,
            obligations: Vec::new(),
            effect_state: None,
            pressure: ResourcePressure::Nominal,
            degraded_dimensions: BTreeSet::new(),
        })
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

fn publication(variant: &Variant) -> Result<crate::ReferenceSituationPublication, Box<dyn Error>> {
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
            cost: BudgetVector {
                latency_ms: 100,
                tokens: 50,
                bytes: 1_024,
                cpu_millis: 10,
                accelerator_millis: 5,
                energy_millijoules: 20,
                privacy_exposure: 0.1,
                ..BudgetVector::default()
            },
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
        hypothesis: None,
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
                KnowledgeState::Known => "The external effect reached a retained terminal outcome.",
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
        now: vec!["The reference mission remains active.".to_owned()],
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
        contract_basis: basis(),
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
            available_resources: BudgetVector {
                latency_ms: 10_000,
                tokens: 50_000,
                bytes: 2_000_000,
                model_calls: 10,
                cpu_millis: 10_000,
                accelerator_millis: 10_000,
                energy_millijoules: 1_000_000,
                network_bytes: 1_000_000,
                storage_operations: 10_000,
                privacy_exposure: 10.0,
                operator_attention_seconds: 1_000.0,
            },
            reserved_resources: BudgetVector {
                latency_ms: 100,
                tokens: 100,
                bytes: 1_000,
                storage_operations: 1,
                ..BudgetVector::default()
            },
            pressure: variant.pressure,
            degraded_dimensions: variant.degraded_dimensions.clone(),
            target_tokens: 25_000,
        },
    )
    .map_err(|error| -> Box<dyn Error> { Box::new(error) })
}

#[test]
fn identical_publications_emit_proved_silence() -> Result<(), Box<dyn Error>> {
    let variant = Variant::baseline()?;
    let basis = publication(&variant)?;
    let result = publication(&variant)?;
    let delta = classify_reference_meaningful_delta(&basis, &result)?;

    assert_eq!(
        delta.classes,
        BTreeSet::from([MeaningfulDeltaClass::NoMeaningfulChange])
    );
    assert_eq!(delta.priority, DeltaPriority::Low);
    assert_eq!(
        delta
            .silence_certificate
            .as_ref()
            .map(|certificate| certificate.selection_witness),
        Some(delta.selection_witness)
    );
    delta.validate()?;
    Ok(())
}

#[test]
fn semantically_identical_successor_commit_emits_proved_silence() -> Result<(), Box<dyn Error>> {
    let basis = publication(&Variant::baseline()?)?;
    let mut successor = Variant::baseline()?;
    successor.sequence = 2;
    let result = publication(&successor)?;
    let delta = classify_reference_meaningful_delta(&basis, &result)?;

    assert_eq!(basis.situation.capsule.anchor.commit_sequence, 1);
    assert_eq!(result.situation.capsule.anchor.commit_sequence, 2);
    assert_eq!(
        delta.classes,
        BTreeSet::from([MeaningfulDeltaClass::NoMeaningfulChange])
    );
    assert_eq!(delta.priority, DeltaPriority::Low);
    delta.validate()?;
    Ok(())
}

#[test]
fn contradiction_invalidation_and_obligation_are_non_coalescible() -> Result<(), Box<dyn Error>> {
    let basis = publication(&Variant::baseline()?)?;
    let mut result_variant = Variant::baseline()?;
    result_variant.sequence = 2;
    result_variant.premise_state = KnowledgeState::Conflicted;
    result_variant.premise_contradictions = vec![ContentDigest::sha256(b"contradiction")];
    result_variant.include_affordance = false;
    result_variant.obligations = vec![ObligationId::parse("obligation:meaningful-delta")?];
    let result = publication(&result_variant)?;
    let delta = classify_reference_meaningful_delta(&basis, &result)?;

    for class in [
        MeaningfulDeltaClass::Contradiction,
        MeaningfulDeltaClass::PlanInvalidation,
        MeaningfulDeltaClass::Obligation,
    ] {
        assert!(delta.classes.contains(&class));
    }
    assert_eq!(delta.priority, DeltaPriority::Critical);
    assert!(delta.is_non_coalescible());
    assert_eq!(delta.coalesced_count, 0);
    assert_eq!(delta.omitted_count, 0);
    delta.validate()?;
    Ok(())
}

#[test]
fn coverage_loss_is_explicit_and_urgent() -> Result<(), Box<dyn Error>> {
    let basis = publication(&Variant::baseline()?)?;
    let mut result_variant = Variant::baseline()?;
    result_variant.sequence = 2;
    result_variant.completeness = Completeness::Partial;
    result_variant.coverage.remove("fss://coverage/beta");
    let result = publication(&result_variant)?;
    let delta = classify_reference_meaningful_delta(&basis, &result)?;

    assert!(delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss));
    assert_eq!(delta.priority, DeltaPriority::Critical);
    assert!(
        delta
            .coverage_changes
            .iter()
            .any(|change| change.contains("coverage handle lost"))
    );
    delta.validate()?;
    Ok(())
}

#[test]
fn effect_terminalization_preserves_uncertainty_transition() -> Result<(), Box<dyn Error>> {
    let mut basis_variant = Variant::baseline()?;
    basis_variant.effect_state = Some(KnowledgeState::Indeterminate);
    basis_variant.obligations = vec![ObligationId::parse("obligation:effect")?];
    let basis = publication(&basis_variant)?;
    let mut result_variant = basis_variant.clone();
    result_variant.sequence = 2;
    result_variant.effect_state = Some(KnowledgeState::Known);
    result_variant.obligations.clear();
    let result = publication(&result_variant)?;
    let delta = classify_reference_meaningful_delta(&basis, &result)?;

    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::EffectUncertainty)
    );
    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition)
    );
    assert!(delta.classes.contains(&MeaningfulDeltaClass::Obligation));
    assert_eq!(delta.priority, DeltaPriority::Critical);
    assert!(
        delta
            .effect_uncertainty_changes
            .iter()
            .any(|change| change.contains("resolved"))
    );
    delta.validate()?;
    Ok(())
}

#[test]
fn resource_only_change_is_not_laundered_into_material_world_state() -> Result<(), Box<dyn Error>> {
    let basis = publication(&Variant::baseline()?)?;
    let mut result_variant = Variant::baseline()?;
    result_variant.pressure = ResourcePressure::Elevated;
    result_variant.degraded_dimensions = BTreeSet::from(["model_calls".to_owned()]);
    let result = publication(&result_variant)?;
    let delta = classify_reference_meaningful_delta(&basis, &result)?;

    assert_eq!(
        delta.classes,
        BTreeSet::from([MeaningfulDeltaClass::BudgetPressure])
    );
    assert!(!delta.classes.contains(&MeaningfulDeltaClass::MaterialState));
    assert_eq!(delta.priority, DeltaPriority::Normal);
    delta.validate()?;
    Ok(())
}
