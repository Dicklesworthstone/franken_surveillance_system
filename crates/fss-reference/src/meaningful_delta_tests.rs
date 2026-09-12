use std::collections::BTreeSet;
use std::error::Error;

use fss_core::{
    ActionAffordance, AffordanceClass, BudgetVector, Completeness, ContentDigest, ContractBasis,
    ContractBasisRegistryBytes, DeltaPriority, Generation, HypothesisDisposition, KnowledgeCell,
    KnowledgeState, KnowledgeStateBasis, LedgerAnchor, MeaningfulDeltaClass, MissionId,
    ObligationId, PrincipalId, PrivacyGeneration, ProvenanceClass, ReconciliationBasis,
    RedactionMarker, RedactionReason, ResourcePressure, SessionId, SituationCapsule,
    SituationFrame, StaleBasis, TimestampNs, WorldEnvelope,
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
    effect_evidence: bool,
    effect_contradicted: bool,
    effect_hypothesis: Option<HypothesisDisposition>,
    effect_valid_until: Option<TimestampNs>,
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
            effect_evidence: true,
            effect_contradicted: false,
            effect_hypothesis: None,
            effect_valid_until: None,
            pressure: ResourcePressure::Nominal,
            degraded_dimensions: BTreeSet::new(),
        })
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

/// Typed state basis a fixture cell in `state` must carry so that it validates.
fn fixture_state_basis(
    state: KnowledgeState,
    root: ContentDigest,
) -> Result<Option<KnowledgeStateBasis>, fss_core::ContractError> {
    Ok(match state {
        KnowledgeState::Redacted => Some(KnowledgeStateBasis::Redaction(RedactionMarker {
            reason: RedactionReason::PrivacyProjection,
            privacy_generation: PrivacyGeneration::parse("privacy:projection:v1")?,
        })),
        KnowledgeState::Stale => Some(KnowledgeStateBasis::Stale(StaleBasis::OlderGeneration {
            valid_at: Generation::from_u64(1),
            current: Generation::from_u64(2),
        })),
        KnowledgeState::Indeterminate => Some(KnowledgeStateBasis::Reconciliation(
            ReconciliationBasis::occurred_or_not(root),
        )),
        _ => None,
    })
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
        hypothesis: None,
        evidence: vec![evidence],
        contradictions: variant.premise_contradictions.clone(),
        valid_until: None,
        state_basis: fixture_state_basis(variant.premise_state, evidence)?,
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
            hypothesis: variant.effect_hypothesis,
            evidence: if variant.effect_evidence {
                vec![ContentDigest::sha256(b"effect-outcome")]
            } else {
                Vec::new()
            },
            contradictions: if variant.effect_contradicted
                || effect_state == KnowledgeState::Conflicted
            {
                vec![ContentDigest::sha256(b"effect-contradiction")]
            } else {
                Vec::new()
            },
            valid_until: variant.effect_valid_until,
            state_basis: fixture_state_basis(
                effect_state,
                ContentDigest::sha256(b"effect-outcome"),
            )?,
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
        mission_state: None,
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
            .any(|change| change.starts_with("effect uncertainty resolved: "))
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

#[test]
fn redacted_premise_is_reported_as_degraded_epistemic_cell() -> Result<(), Box<dyn Error>> {
    let basis = publication(&Variant::baseline()?)?;
    let mut result_variant = Variant::baseline()?;
    result_variant.sequence = 2;
    result_variant.premise_state = KnowledgeState::Redacted;
    let result = publication(&result_variant)?;
    let delta = classify_reference_meaningful_delta(&basis, &result)?;

    assert!(delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss));
    assert!(
        !delta
            .classes
            .contains(&MeaningfulDeltaClass::NoMeaningfulChange)
    );
    assert!(delta.silence_certificate.is_none());
    assert!(delta.coverage_changes.iter().any(|change| {
        change.contains("epistemic cell degraded") && change.contains("claim:premise")
    }));
    delta.validate()?;
    Ok(())
}

#[test]
fn every_withheld_or_unestablished_state_is_reported_as_degraded() -> Result<(), Box<dyn Error>> {
    let basis = publication(&Variant::baseline()?)?;
    for state in [
        KnowledgeState::Unknown,
        KnowledgeState::Conflicted,
        KnowledgeState::Stale,
        KnowledgeState::NotObservable,
        KnowledgeState::Redacted,
        KnowledgeState::Indeterminate,
    ] {
        let mut result_variant = Variant::baseline()?;
        result_variant.sequence = 2;
        result_variant.premise_state = state;
        if state == KnowledgeState::Conflicted {
            result_variant.premise_contradictions = vec![ContentDigest::sha256(b"contradiction")];
        }
        let result = publication(&result_variant)?;
        let delta = classify_reference_meaningful_delta(&basis, &result)?;

        assert!(
            delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss),
            "{} premise must be reported as coverage loss",
            state.as_str()
        );
        assert!(
            delta.coverage_changes.iter().any(|change| {
                change.contains("epistemic cell degraded") && change.contains("claim:premise")
            }),
            "{} premise must be listed as a degraded epistemic cell",
            state.as_str()
        );
        delta.validate()?;
    }
    Ok(())
}

fn known_premise_delta(state: KnowledgeState) -> Result<fss_core::MeaningfulDelta, Box<dyn Error>> {
    let basis = publication(&Variant::baseline()?)?;
    let mut result_variant = Variant::baseline()?;
    result_variant.sequence = 2;
    result_variant.premise_state = state;
    if state == KnowledgeState::Conflicted {
        result_variant.premise_contradictions = vec![ContentDigest::sha256(b"contradiction")];
    }
    let result = publication(&result_variant)?;
    Ok(classify_reference_meaningful_delta(&basis, &result)?)
}

fn premise_invalidated(delta: &fss_core::MeaningfulDelta, state: KnowledgeState) -> bool {
    let expected = format!("known premise claim:premise became {}", state.as_str());
    delta
        .classes
        .contains(&MeaningfulDeltaClass::PlanInvalidation)
        && delta.invalidated_assumptions.contains(&expected)
}

#[test]
fn known_premise_becoming_redacted_is_an_invalidated_assumption() -> Result<(), Box<dyn Error>> {
    let delta = known_premise_delta(KnowledgeState::Redacted)?;

    assert!(
        premise_invalidated(&delta, KnowledgeState::Redacted),
        "Known->Redacted premise must be invalidated: {:?}",
        delta.invalidated_assumptions
    );
    // The separate degraded-cell path (fss-mfea7) still reports the withheld cell.
    assert!(delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss));
    assert_eq!(delta.priority, DeltaPriority::Critical);
    delta.validate()?;
    Ok(())
}

#[test]
fn known_premise_becoming_not_applicable_is_an_invalidated_assumption() -> Result<(), Box<dyn Error>>
{
    let delta = known_premise_delta(KnowledgeState::NotApplicable)?;

    assert!(
        premise_invalidated(&delta, KnowledgeState::NotApplicable),
        "Known->NotApplicable premise must be invalidated: {:?}",
        delta.invalidated_assumptions
    );
    assert_eq!(delta.priority, DeltaPriority::Critical);
    delta.validate()?;
    Ok(())
}

#[test]
fn every_state_that_cannot_authorize_an_irreversible_effect_invalidates_a_known_premise()
-> Result<(), Box<dyn Error>> {
    for state in [
        KnowledgeState::Estimated,
        KnowledgeState::Unknown,
        KnowledgeState::Conflicted,
        KnowledgeState::Stale,
        KnowledgeState::NotObservable,
        KnowledgeState::Indeterminate,
        KnowledgeState::Redacted,
        KnowledgeState::NotApplicable,
    ] {
        assert!(!state.may_authorize_irreversible_effect());
        let delta = known_premise_delta(state)?;
        assert!(
            premise_invalidated(&delta, state),
            "Known->{} premise must be invalidated: {:?}",
            state.as_str(),
            delta.invalidated_assumptions
        );
        delta.validate()?;
    }
    Ok(())
}

const EFFECT_CLAIM: &str = "claim:effect:meaningful-delta:outcome";

/// Compares a basis whose effect cell is `Indeterminate` with a result whose effect cell is
/// `successor` (`None` removes the cell), with the result cell further shaped by `configure`.
fn indeterminate_effect_delta(
    successor: Option<KnowledgeState>,
    configure: impl FnOnce(&mut Variant),
) -> Result<fss_core::MeaningfulDelta, Box<dyn Error>> {
    let mut basis_variant = Variant::baseline()?;
    basis_variant.effect_state = Some(KnowledgeState::Indeterminate);
    let basis = publication(&basis_variant)?;
    let mut result_variant = basis_variant.clone();
    result_variant.sequence = 2;
    result_variant.effect_state = successor;
    configure(&mut result_variant);
    let result = publication(&result_variant)?;
    Ok(classify_reference_meaningful_delta(&basis, &result)?)
}

const fn keep_effect_evidence(_: &mut Variant) {}

/// Asserts the delta keeps the basis-indeterminate effect unresolved: continued effect
/// uncertainty, never a resolution or terminal transition, and coverage loss exactly when the
/// successor withholds or fails to establish the outcome.
fn assert_effect_unresolved(
    delta: &fss_core::MeaningfulDelta,
    expected_change: &str,
    expected_coverage_change: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::EffectUncertainty),
        "{expected_change}: effect uncertainty must stay reported: {:?}",
        delta.classes
    );
    assert!(
        !delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "{expected_change}: an unproved effect is not a terminal transition: {:?}",
        delta.classes
    );
    assert!(
        !delta
            .effect_uncertainty_changes
            .iter()
            .any(|change| change.contains("resolved")),
        "{expected_change}: an unproved effect must not be reported as resolved: {:?}",
        delta.effect_uncertainty_changes
    );
    assert!(
        delta
            .effect_uncertainty_changes
            .iter()
            .any(|change| change == expected_change),
        "missing {expected_change:?} in {:?}",
        delta.effect_uncertainty_changes
    );
    match expected_coverage_change {
        Some(coverage_change) => {
            assert!(
                delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss),
                "{expected_change}: a degraded unproved effect is coverage loss: {:?}",
                delta.classes
            );
            assert!(
                delta
                    .coverage_changes
                    .iter()
                    .any(|change| change == coverage_change),
                "missing {coverage_change:?} in {:?}",
                delta.coverage_changes
            );
        }
        None => assert!(
            !delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss),
            "{expected_change}: a non-degraded successor is not coverage loss: {:?}",
            delta.coverage_changes
        ),
    }
    assert_eq!(delta.priority, DeltaPriority::Critical);
    assert!(delta.is_non_coalescible());
    delta.validate()?;
    Ok(())
}

fn became(state: KnowledgeState) -> String {
    format!(
        "effect uncertainty remains: indeterminate effect {EFFECT_CLAIM} became {} without a proved outcome",
        state.as_str()
    )
}

fn degraded_to(state: KnowledgeState) -> String {
    format!(
        "unproved effect {EFFECT_CLAIM} degraded from indeterminate to {}",
        state.as_str()
    )
}

fn assert_degraded_successor_unresolved(state: KnowledgeState) -> Result<(), Box<dyn Error>> {
    let delta = indeterminate_effect_delta(Some(state), keep_effect_evidence)?;
    assert_effect_unresolved(&delta, &became(state), Some(&degraded_to(state)))
}

#[test]
fn indeterminate_effect_becoming_estimated_stays_unresolved() -> Result<(), Box<dyn Error>> {
    // An effect parked as an estimate is lost coverage, not a quiet state (fss-hmfs5).
    assert_degraded_successor_unresolved(KnowledgeState::Estimated)
}

#[test]
fn indeterminate_effect_becoming_unknown_stays_unresolved() -> Result<(), Box<dyn Error>> {
    assert_degraded_successor_unresolved(KnowledgeState::Unknown)
}

#[test]
fn indeterminate_effect_becoming_conflicted_stays_unresolved() -> Result<(), Box<dyn Error>> {
    assert_degraded_successor_unresolved(KnowledgeState::Conflicted)
}

#[test]
fn indeterminate_effect_becoming_stale_stays_unresolved() -> Result<(), Box<dyn Error>> {
    assert_degraded_successor_unresolved(KnowledgeState::Stale)
}

#[test]
fn indeterminate_effect_becoming_not_observable_stays_unresolved() -> Result<(), Box<dyn Error>> {
    assert_degraded_successor_unresolved(KnowledgeState::NotObservable)
}

#[test]
fn indeterminate_effect_becoming_redacted_stays_unresolved() -> Result<(), Box<dyn Error>> {
    assert_degraded_successor_unresolved(KnowledgeState::Redacted)
}

#[test]
fn indeterminate_effect_becoming_not_applicable_stays_unresolved() -> Result<(), Box<dyn Error>> {
    // An effect parked as not applicable is lost coverage, not a quiet state (fss-hmfs5).
    assert_degraded_successor_unresolved(KnowledgeState::NotApplicable)
}

#[test]
fn indeterminate_effect_becoming_known_without_evidence_stays_unresolved()
-> Result<(), Box<dyn Error>> {
    let delta = indeterminate_effect_delta(Some(KnowledgeState::Known), |variant| {
        variant.effect_evidence = false;
    })?;
    assert_effect_unresolved(
        &delta,
        &became(KnowledgeState::Known),
        Some(&degraded_to(KnowledgeState::Known)),
    )
}

#[test]
fn indeterminate_effect_becoming_contradicted_known_stays_unresolved() -> Result<(), Box<dyn Error>>
{
    let delta = indeterminate_effect_delta(Some(KnowledgeState::Known), |variant| {
        variant.effect_contradicted = true;
    })?;
    assert_effect_unresolved(
        &delta,
        &became(KnowledgeState::Known),
        Some(&degraded_to(KnowledgeState::Known)),
    )
}

#[test]
fn removed_indeterminate_effect_is_coverage_loss_not_resolution() -> Result<(), Box<dyn Error>> {
    let delta = indeterminate_effect_delta(None, keep_effect_evidence)?;
    let expected_change = format!(
        "effect uncertainty remains: indeterminate effect {EFFECT_CLAIM} disappeared from the result frame without a proved outcome"
    );
    let expected_coverage = format!(
        "unproved effect {EFFECT_CLAIM} disappeared from the result frame while indeterminate"
    );
    assert_effect_unresolved(&delta, &expected_change, Some(&expected_coverage))
}

#[test]
fn indeterminate_effect_that_stays_indeterminate_is_neither_resolved_nor_terminal()
-> Result<(), Box<dyn Error>> {
    let delta =
        indeterminate_effect_delta(Some(KnowledgeState::Indeterminate), keep_effect_evidence)?;

    assert!(
        !delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition)
    );
    // The still-unproved effect stays reported as uncertain in every delta (fss-hmfs5).
    assert_eq!(
        delta.effect_uncertainty_changes,
        vec![still_unproved(KnowledgeState::Indeterminate)]
    );
    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::EffectUncertainty)
    );
    // The still-indeterminate cell stays a degraded epistemic cell (fss-mfea7).
    assert!(delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss));
    assert!(delta.coverage_changes.iter().any(|change| {
        change.contains("epistemic cell degraded") && change.contains(EFFECT_CLAIM)
    }));
    delta.validate()?;
    Ok(())
}

#[test]
fn estimated_and_not_applicable_stay_out_of_the_degraded_epistemic_set()
-> Result<(), Box<dyn Error>> {
    for state in [KnowledgeState::Estimated, KnowledgeState::NotApplicable] {
        let delta = known_premise_delta(state)?;

        assert!(
            !delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss),
            "{} premise must not be reported as coverage loss: {:?}",
            state.as_str(),
            delta.coverage_changes
        );
        assert!(
            !delta
                .coverage_changes
                .iter()
                .any(|change| change.contains("epistemic cell degraded")),
            "{} premise must not be listed as a degraded epistemic cell: {:?}",
            state.as_str(),
            delta.coverage_changes
        );
        // Leaving the degraded set does not hide the downgrade: it is an invalidated premise.
        assert!(premise_invalidated(&delta, state));
        delta.validate()?;
    }
    Ok(())
}

fn estimated_premise_delta(
    state: KnowledgeState,
) -> Result<fss_core::MeaningfulDelta, Box<dyn Error>> {
    let mut basis_variant = Variant::baseline()?;
    basis_variant.premise_state = KnowledgeState::Estimated;
    let basis = publication(&basis_variant)?;
    let mut result_variant = basis_variant.clone();
    result_variant.sequence = 2;
    result_variant.premise_state = state;
    let result = publication(&result_variant)?;
    Ok(classify_reference_meaningful_delta(&basis, &result)?)
}

#[test]
fn estimated_premise_becoming_redacted_is_an_invalidated_assumption() -> Result<(), Box<dyn Error>>
{
    let delta = estimated_premise_delta(KnowledgeState::Redacted)?;

    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::PlanInvalidation)
    );
    assert!(
        delta
            .invalidated_assumptions
            .contains(&"estimated premise claim:premise became redacted".to_owned()),
        "Estimated->Redacted premise must be invalidated: {:?}",
        delta.invalidated_assumptions
    );
    assert!(delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss));
    assert_eq!(delta.priority, DeltaPriority::Critical);
    delta.validate()?;
    Ok(())
}

#[test]
fn estimated_premise_staying_estimated_is_not_invalidated() -> Result<(), Box<dyn Error>> {
    let delta = estimated_premise_delta(KnowledgeState::Estimated)?;

    assert!(
        !delta
            .classes
            .contains(&MeaningfulDeltaClass::PlanInvalidation),
        "Estimated->Estimated must not invalidate the premise: {:?}",
        delta.invalidated_assumptions
    );
    assert!(delta.invalidated_assumptions.is_empty());
    assert!(!delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss));
    delta.validate()?;
    Ok(())
}

/// Validity end before every fixture capsule's `created_at` (`1_000 + sequence`), so a cell that
/// carries it is expired at both the basis and the result anchor.
const EXPIRED_VALIDITY: TimestampNs = TimestampNs(1);

const TERMINAL_HYPOTHESES: [HypothesisDisposition; 3] = [
    HypothesisDisposition::Refuted,
    HypothesisDisposition::Resolved,
    HypothesisDisposition::Superseded,
];

#[test]
fn indeterminate_effect_becoming_known_with_evidence_alone_is_terminal()
-> Result<(), Box<dyn Error>> {
    // No obligation is carried or removed and no other cell changes, so the retained outcome
    // evidence is the only thing that can terminalize this transition.
    let delta = indeterminate_effect_delta(Some(KnowledgeState::Known), keep_effect_evidence)?;

    assert!(delta.obligation_changes.is_empty());
    assert!(!delta.classes.contains(&MeaningfulDeltaClass::Obligation));
    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "Indeterminate->Known with a proved outcome is terminal: {:?}",
        delta.classes
    );
    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::EffectUncertainty)
    );
    assert_eq!(
        delta.effect_uncertainty_changes,
        vec![format!(
            "effect uncertainty resolved: {EFFECT_CLAIM} became known with retained outcome evidence"
        )]
    );
    assert_eq!(delta.priority, DeltaPriority::Critical);
    delta.validate()?;
    Ok(())
}

#[test]
fn indeterminate_effect_becoming_known_with_expired_validity_stays_unresolved()
-> Result<(), Box<dyn Error>> {
    let delta = indeterminate_effect_delta(Some(KnowledgeState::Known), |variant| {
        variant.effect_valid_until = Some(EXPIRED_VALIDITY);
    })?;
    assert_effect_unresolved(
        &delta,
        &became(KnowledgeState::Known),
        Some(&degraded_to(KnowledgeState::Known)),
    )
}

/// Asserts that a terminal hypothesis disposition on a basis-indeterminate effect cell whose
/// successor is `successor` never terminalizes the unproved effect.
fn assert_terminal_hypothesis_leaves_indeterminate_effect_open(
    successor: KnowledgeState,
) -> Result<(), Box<dyn Error>> {
    for hypothesis in TERMINAL_HYPOTHESES {
        let delta = indeterminate_effect_delta(Some(successor), |variant| {
            variant.effect_hypothesis = Some(hypothesis);
        })?;
        assert!(
            !delta
                .classes
                .contains(&MeaningfulDeltaClass::TerminalTransition),
            "indeterminate->{} with hypothesis {hypothesis:?} is not terminal: {:?}",
            successor.as_str(),
            delta.classes
        );
        assert!(
            !delta
                .effect_uncertainty_changes
                .iter()
                .any(|change| change.contains("resolved")),
            "indeterminate->{} with hypothesis {hypothesis:?} is not resolved: {:?}",
            successor.as_str(),
            delta.effect_uncertainty_changes
        );
        if successor != KnowledgeState::Indeterminate {
            assert!(
                delta
                    .classes
                    .contains(&MeaningfulDeltaClass::EffectUncertainty)
            );
            assert!(
                delta
                    .effect_uncertainty_changes
                    .contains(&became(successor)),
                "missing {:?} in {:?}",
                became(successor),
                delta.effect_uncertainty_changes
            );
        }
        assert_eq!(delta.priority, DeltaPriority::Critical);
        delta.validate()?;
    }
    Ok(())
}

#[test]
fn indeterminate_effect_becoming_unknown_with_terminal_hypothesis_is_not_terminal()
-> Result<(), Box<dyn Error>> {
    assert_terminal_hypothesis_leaves_indeterminate_effect_open(KnowledgeState::Unknown)
}

#[test]
fn indeterminate_effect_staying_indeterminate_with_terminal_hypothesis_is_not_terminal()
-> Result<(), Box<dyn Error>> {
    assert_terminal_hypothesis_leaves_indeterminate_effect_open(KnowledgeState::Indeterminate)
}

#[test]
fn indeterminate_effect_becoming_estimated_with_terminal_hypothesis_is_not_terminal()
-> Result<(), Box<dyn Error>> {
    assert_terminal_hypothesis_leaves_indeterminate_effect_open(KnowledgeState::Estimated)
}

// fss-deir9: every effect terminalization must pass the full irreversible-effect premise bar,
// whatever state (or absence) the basis carried.

/// Compares a basis whose effect cell is `prior` (`None` omits it) with a result whose effect
/// cell is `current` (`None` omits it), the result cell further shaped by `configure`.
fn effect_transition_delta(
    prior: Option<KnowledgeState>,
    current: Option<KnowledgeState>,
    configure: impl FnOnce(&mut Variant),
) -> Result<fss_core::MeaningfulDelta, Box<dyn Error>> {
    let mut basis_variant = Variant::baseline()?;
    basis_variant.effect_state = prior;
    let basis = publication(&basis_variant)?;
    let mut result_variant = basis_variant.clone();
    result_variant.sequence = 2;
    result_variant.effect_state = current;
    configure(&mut result_variant);
    let result = publication(&result_variant)?;
    Ok(classify_reference_meaningful_delta(&basis, &result)?)
}

const fn drop_effect_evidence(variant: &mut Variant) {
    variant.effect_evidence = false;
}

const fn contradict_effect(variant: &mut Variant) {
    variant.effect_contradicted = true;
}

const fn expire_effect(variant: &mut Variant) {
    variant.effect_valid_until = Some(EXPIRED_VALIDITY);
}

fn unproved_known_change() -> String {
    format!(
        "effect uncertainty remains: effect {EFFECT_CLAIM} is known without a proved terminal outcome"
    )
}

fn unproved_known_coverage() -> String {
    format!("unproved effect {EFFECT_CLAIM} is known without admissible terminal outcome evidence")
}

/// Asserts that a `known` effect cell failing the irreversible-effect premise bar is reported as
/// continued effect uncertainty and lost coverage, never as a terminal transition.
fn assert_unproved_known_effect_not_terminal(
    delta: &fss_core::MeaningfulDelta,
    context: &str,
) -> Result<(), Box<dyn Error>> {
    assert!(
        !delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "{context}: a known effect without a proved terminal outcome is not terminal: {:?}",
        delta.classes
    );
    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::EffectUncertainty),
        "{context}: the unproved effect must stay reported as uncertain: {:?}",
        delta.classes
    );
    assert!(
        delta
            .effect_uncertainty_changes
            .contains(&unproved_known_change()),
        "{context}: missing {:?} in {:?}",
        unproved_known_change(),
        delta.effect_uncertainty_changes
    );
    assert!(
        !delta
            .effect_uncertainty_changes
            .iter()
            .any(|change| change.contains("resolved")),
        "{context}: an unproved effect must not be reported as resolved: {:?}",
        delta.effect_uncertainty_changes
    );
    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss),
        "{context}: an unproved known effect is coverage loss: {:?}",
        delta.classes
    );
    assert!(
        delta.coverage_changes.contains(&unproved_known_coverage()),
        "{context}: missing {:?} in {:?}",
        unproved_known_coverage(),
        delta.coverage_changes
    );
    assert!(
        delta.coverage_changes.iter().any(|change| {
            change.contains("epistemic cell degraded") && change.contains(EFFECT_CLAIM)
        }),
        "{context}: the unproved effect must be listed as a degraded epistemic cell: {:?}",
        delta.coverage_changes
    );
    assert_eq!(delta.priority, DeltaPriority::Critical);
    assert!(delta.is_non_coalescible());
    delta.validate()?;
    Ok(())
}

#[test]
fn unknown_effect_becoming_known_without_evidence_is_not_terminal() -> Result<(), Box<dyn Error>> {
    let delta = effect_transition_delta(
        Some(KnowledgeState::Unknown),
        Some(KnowledgeState::Known),
        drop_effect_evidence,
    )?;
    assert_unproved_known_effect_not_terminal(&delta, "unknown->known without evidence")
}

#[test]
fn absent_effect_becoming_known_without_evidence_is_not_terminal() -> Result<(), Box<dyn Error>> {
    let delta = effect_transition_delta(None, Some(KnowledgeState::Known), drop_effect_evidence)?;
    assert_unproved_known_effect_not_terminal(&delta, "absent->known without evidence")
}

#[test]
fn stale_effect_becoming_known_without_evidence_is_not_terminal() -> Result<(), Box<dyn Error>> {
    let delta = effect_transition_delta(
        Some(KnowledgeState::Stale),
        Some(KnowledgeState::Known),
        drop_effect_evidence,
    )?;
    assert_unproved_known_effect_not_terminal(&delta, "stale->known without evidence")
}

#[test]
fn unknown_effect_becoming_contradicted_known_is_not_terminal() -> Result<(), Box<dyn Error>> {
    let delta = effect_transition_delta(
        Some(KnowledgeState::Unknown),
        Some(KnowledgeState::Known),
        contradict_effect,
    )?;
    assert_unproved_known_effect_not_terminal(&delta, "unknown->contradicted known")
}

#[test]
fn unknown_effect_becoming_known_with_expired_validity_is_not_terminal()
-> Result<(), Box<dyn Error>> {
    let delta = effect_transition_delta(
        Some(KnowledgeState::Unknown),
        Some(KnowledgeState::Known),
        expire_effect,
    )?;
    assert_unproved_known_effect_not_terminal(&delta, "unknown->known with expired validity")
}

#[test]
fn non_indeterminate_effect_with_terminal_hypothesis_is_not_terminal() -> Result<(), Box<dyn Error>>
{
    for prior in [
        None,
        Some(KnowledgeState::Unknown),
        Some(KnowledgeState::Stale),
    ] {
        for successor in [KnowledgeState::Unknown, KnowledgeState::Estimated] {
            for hypothesis in TERMINAL_HYPOTHESES {
                let delta = effect_transition_delta(prior, Some(successor), |variant| {
                    variant.effect_hypothesis = Some(hypothesis);
                })?;
                assert!(
                    !delta
                        .classes
                        .contains(&MeaningfulDeltaClass::TerminalTransition),
                    "{prior:?}->{} with hypothesis {hypothesis:?} is not terminal: {:?}",
                    successor.as_str(),
                    delta.classes
                );
                delta.validate()?;
            }
        }
    }
    Ok(())
}

#[test]
fn indeterminate_effect_laundered_through_unknown_never_terminalizes() -> Result<(), Box<dyn Error>>
{
    let mut first = Variant::baseline()?;
    first.effect_state = Some(KnowledgeState::Indeterminate);
    let mut second = first.clone();
    second.sequence = 2;
    second.effect_state = Some(KnowledgeState::Unknown);
    let mut third = second.clone();
    third.sequence = 3;
    third.effect_state = Some(KnowledgeState::Known);
    third.effect_evidence = false;
    let first = publication(&first)?;
    let second = publication(&second)?;
    let third = publication(&third)?;

    // Step one keeps the indeterminate effect open.
    let step_one = classify_reference_meaningful_delta(&first, &second)?;
    assert_effect_unresolved(
        &step_one,
        &became(KnowledgeState::Unknown),
        Some(&degraded_to(KnowledgeState::Unknown)),
    )?;
    // Step two cannot see the indeterminate history, so it must refuse on the premise bar alone.
    let step_two = classify_reference_meaningful_delta(&second, &third)?;
    assert_unproved_known_effect_not_terminal(&step_two, "laundering step unknown->known")?;
    // The end-to-end comparison agrees with the stepwise one.
    let end_to_end = classify_reference_meaningful_delta(&first, &third)?;
    assert_effect_unresolved(
        &end_to_end,
        &became(KnowledgeState::Known),
        Some(&degraded_to(KnowledgeState::Known)),
    )
}

#[test]
fn effect_with_proved_terminal_outcome_is_terminal_whatever_the_prior_state()
-> Result<(), Box<dyn Error>> {
    for prior in [
        None,
        Some(KnowledgeState::Unknown),
        Some(KnowledgeState::Stale),
    ] {
        let delta =
            effect_transition_delta(prior, Some(KnowledgeState::Known), keep_effect_evidence)?;
        assert!(
            delta
                .classes
                .contains(&MeaningfulDeltaClass::TerminalTransition),
            "{prior:?}->known with a proved outcome is terminal: {:?}",
            delta.classes
        );
        assert!(
            delta.effect_uncertainty_changes.is_empty(),
            "{prior:?}->known with a proved outcome carries no effect uncertainty: {:?}",
            delta.effect_uncertainty_changes
        );
        assert!(
            !delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss),
            "{prior:?}->known with a proved outcome is not coverage loss: {:?}",
            delta.coverage_changes
        );
        delta.validate()?;
    }
    Ok(())
}

// fss-hmfs5 rework: an unproved effect is reported in every delta, so it cannot be parked.

/// The report an effect whose outcome is still unproved carries in every delta.
fn still_unproved(state: KnowledgeState) -> String {
    format!(
        "effect uncertainty remains: effect {EFFECT_CLAIM} is {} without a proved outcome",
        state.as_str()
    )
}

/// Asserts that a delta whose result still carries an unproved effect in `state` is never
/// silence: the effect stays reported as uncertain and as a degraded epistemic cell.
fn assert_unproved_effect_still_reported(
    delta: &fss_core::MeaningfulDelta,
    state: KnowledgeState,
    context: &str,
) -> Result<(), Box<dyn Error>> {
    assert!(
        delta.silence_certificate.is_none(),
        "{context}: an unproved effect is never silence: {:?}",
        delta.classes
    );
    assert!(
        !delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "{context}: an unproved effect is not terminal: {:?}",
        delta.classes
    );
    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::EffectUncertainty),
        "{context}: the unproved effect must stay reported as uncertain: {:?}",
        delta.classes
    );
    assert!(
        delta
            .effect_uncertainty_changes
            .contains(&still_unproved(state)),
        "{context}: missing {:?} in {:?}",
        still_unproved(state),
        delta.effect_uncertainty_changes
    );
    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss),
        "{context}: an unproved effect is coverage loss: {:?}",
        delta.classes
    );
    assert!(
        delta.coverage_changes.iter().any(|change| {
            change.contains("epistemic cell degraded") && change.contains(EFFECT_CLAIM)
        }),
        "{context}: the unproved effect must be listed as a degraded epistemic cell: {:?}",
        delta.coverage_changes
    );
    assert_eq!(delta.priority, DeltaPriority::Critical);
    delta.validate()?;
    Ok(())
}

/// Parks a basis-indeterminate effect in `parked` and then republishes it unchanged, returning
/// the parking delta and the republication delta.
fn parked_effect_deltas(
    parked: KnowledgeState,
) -> Result<(fss_core::MeaningfulDelta, fss_core::MeaningfulDelta), Box<dyn Error>> {
    let mut first = Variant::baseline()?;
    first.effect_state = Some(KnowledgeState::Indeterminate);
    let mut second = first.clone();
    second.sequence = 2;
    second.effect_state = Some(parked);
    let mut third = second.clone();
    third.sequence = 3;
    let first = publication(&first)?;
    let second = publication(&second)?;
    let third = publication(&third)?;
    Ok((
        classify_reference_meaningful_delta(&first, &second)?,
        classify_reference_meaningful_delta(&second, &third)?,
    ))
}

#[test]
fn indeterminate_effect_parked_as_not_applicable_is_never_silent() -> Result<(), Box<dyn Error>> {
    let (parking, republished) = parked_effect_deltas(KnowledgeState::NotApplicable)?;
    assert_effect_unresolved(
        &parking,
        &became(KnowledgeState::NotApplicable),
        Some(&degraded_to(KnowledgeState::NotApplicable)),
    )?;
    assert_unproved_effect_still_reported(
        &republished,
        KnowledgeState::NotApplicable,
        "not_applicable effect republished",
    )
}

#[test]
fn indeterminate_effect_parked_as_estimated_is_never_silent() -> Result<(), Box<dyn Error>> {
    let (parking, republished) = parked_effect_deltas(KnowledgeState::Estimated)?;
    assert_effect_unresolved(
        &parking,
        &became(KnowledgeState::Estimated),
        Some(&degraded_to(KnowledgeState::Estimated)),
    )?;
    assert_unproved_effect_still_reported(
        &republished,
        KnowledgeState::Estimated,
        "estimated effect republished",
    )
}

#[test]
fn unproved_effect_stays_effect_uncertainty_in_every_delta() -> Result<(), Box<dyn Error>> {
    for (state, evidence) in [
        (KnowledgeState::Unknown, true),
        (KnowledgeState::Conflicted, true),
        (KnowledgeState::Stale, true),
        (KnowledgeState::NotObservable, true),
        (KnowledgeState::Redacted, true),
        (KnowledgeState::Estimated, true),
        (KnowledgeState::NotApplicable, true),
        (KnowledgeState::Indeterminate, true),
        (KnowledgeState::Known, false),
    ] {
        let mut basis_variant = Variant::baseline()?;
        basis_variant.effect_state = Some(state);
        basis_variant.effect_evidence = evidence;
        let basis = publication(&basis_variant)?;
        let mut result_variant = basis_variant.clone();
        result_variant.sequence = 2;
        let result = publication(&result_variant)?;
        let delta = classify_reference_meaningful_delta(&basis, &result)?;
        assert_unproved_effect_still_reported(
            &delta,
            state,
            &format!("unchanged {} effect", state.as_str()),
        )?;
    }
    Ok(())
}
