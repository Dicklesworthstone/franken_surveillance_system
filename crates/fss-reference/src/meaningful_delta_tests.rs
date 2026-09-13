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
    classify_reference_meaningful_delta_in_lineage, project_reference_situation,
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
    effect_evidence_retained: bool,
    effect_bound: bool,
    effect_terminal_state: fss_core::EffectState,
    effect_statement: Option<String>,
    predecessor: Option<ContentDigest>,
    journal_root: Option<ContentDigest>,
    created_at: Option<TimestampNs>,
    pressure: ResourcePressure,
    degraded_dimensions: BTreeSet<String>,
    extra_cells: Vec<KnowledgeCell>,
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
            effect_evidence_retained: true,
            effect_bound: true,
            effect_terminal_state: fss_core::EffectState::Verified,
            effect_statement: None,
            predecessor: None,
            journal_root: None,
            created_at: None,
            pressure: ResourcePressure::Nominal,
            degraded_dimensions: BTreeSet::new(),
            extra_cells: Vec::new(),
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
            statement: variant.effect_statement.clone().unwrap_or_else(|| {
                match effect_state {
                    KnowledgeState::Indeterminate => {
                        "The external effect may have happened and requires reconciliation."
                    }
                    // A compiled outcome cell states its terminal outcome, so a flipped outcome is a
                    // changed cell, as it is in real compilation.
                    KnowledgeState::Known
                        if variant.effect_terminal_state == fss_core::EffectState::Failed =>
                    {
                        "The external effect reached a retained failed outcome."
                    }
                    KnowledgeState::Known => {
                        "The external effect reached a retained terminal outcome."
                    }
                    _ => "The external effect has another explicit typed state.",
                }
                .to_owned()
            }),
            knowledge_state: effect_state,
            // PROV-001 refuses an observed cell asserting `known` without evidence, and a bound
            // effect cell whose evidence is not a retained proof root is refused at verify. An
            // evidence-less effect claim is therefore modeled as what it is: a provider claim
            // (PROV-006) that no retained proof supports, valid but never a proved outcome.
            provenance: if variant.effect_evidence {
                ProvenanceClass::Observed
            } else {
                ProvenanceClass::VendorClaimed
            },
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
    knowledge_cells.extend(variant.extra_cells.clone());
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
        created_at: variant
            .created_at
            .unwrap_or(TimestampNs(1_000 + i128::from(variant.sequence))),
        mission_state: None,
    };
    capsule.validate()?;
    // Situation compilation retains a published outcome's proof object as a proof root, so the
    // fixture retains the effect evidence too unless a test withholds it.
    let mut proof_roots = BTreeSet::from([evidence]);
    for cell in &variant.extra_cells {
        for ev in &cell.evidence {
            proof_roots.insert(*ev);
        }
    }
    if variant.effect_state.is_some() && variant.effect_evidence && variant.effect_evidence_retained
    {
        proof_roots.insert(ContentDigest::sha256(b"effect-outcome"));
    }
    let mut situation = ReferenceSituation::new(capsule, proof_roots);
    // The fixture stands in for a compile path that verified the effect outcome, unless a test
    // withholds the binding to plant a hand-built effect (fss-6sph6).
    if variant.effect_bound {
        let effect_cells: Vec<_> = situation
            .capsule
            .frame
            .knowledge_cells
            .iter()
            .filter(|cell| cell.claim_id == EFFECT_CLAIM)
            .cloned()
            .collect();
        let operation_id = fss_core::OperationId::parse("meaningful-delta")?;
        for cell in &effect_cells {
            // A `known` fixture cell stands for the terminal state the variant names; any other
            // state stands for a dispatched, unresolved operation.
            let state = if cell.knowledge_state == KnowledgeState::Known {
                variant.effect_terminal_state
            } else {
                fss_core::EffectState::Committed
            };
            situation.bind_effect_cell(
                crate::EffectCellKind::Outcome,
                &operation_id,
                state,
                cell,
            )?;
        }
    }
    // The fixture stands in for a compile path, which seals its subject and predecessor too.
    situation.set_lineage(
        fss_core::EventId::parse("event:meaningful-delta")?,
        "objective:meaningful-delta".to_owned(),
        variant.predecessor,
    );
    if let Some(journal_root) = variant.journal_root {
        situation.set_journal_root(journal_root);
    }
    situation.set_authority_anchor(fixture_authority_anchor()?);
    situation.seal_effect_bindings()?;
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
    let result = successor_of(&basis, &result_variant)?;
    let delta = bound_delta(&basis, &result)?;

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
    let result = successor_of(&basis, &result_variant)?;
    bound_delta(&basis, &result)
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
            "effect uncertainty resolved: {EFFECT_CLAIM} became known with retained succeeded outcome evidence"
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
    let result = successor_of(&basis, &result_variant)?;
    bound_delta(&basis, &result)
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
    let second = successor_of(&first, &second)?;
    let third = successor_of(&second, &third)?;
    let store = recorded(&[&first, &second, &third])?;

    // Step one keeps the indeterminate effect open.
    let step_one = bound(&store, &first, &second)?;
    assert_effect_unresolved(
        &step_one,
        &became(KnowledgeState::Unknown),
        Some(&degraded_to(KnowledgeState::Unknown)),
    )?;
    // Step two cannot see the indeterminate history, so it must refuse on the premise bar alone.
    let step_two = bound(&store, &second, &third)?;
    assert_unproved_known_effect_not_terminal(&step_two, "laundering step unknown->known")?;
    // The end-to-end comparison agrees with the stepwise one.
    let end_to_end = bound(&store, &first, &third)?;
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
    let second = successor_of(&first, &second)?;
    let third = successor_of(&second, &third)?;
    let store = recorded(&[&first, &second, &third])?;
    let deltas = (
        bound(&store, &first, &second)?,
        bound(&store, &second, &third)?,
    );
    store.cleanup();
    Ok(deltas)
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
        let result = successor_of(&basis, &result_variant)?;
        let delta = bound_delta(&basis, &result)?;
        assert_unproved_effect_still_reported(
            &delta,
            state,
            &format!("unchanged {} effect", state.as_str()),
        )?;
    }
    Ok(())
}

// fss-deir9 rework: removal, clock order, retained proof roots, and the pinned guards.

fn removed_line() -> String {
    format!(
        "effect uncertainty remains: effect {EFFECT_CLAIM} disappeared from the result frame without a proved outcome"
    )
}

fn removed_coverage(state: KnowledgeState) -> String {
    format!(
        "unproved effect {EFFECT_CLAIM} disappeared from the result frame while {}",
        state.as_str()
    )
}

/// Asserts that an unproved effect in `state` removed from the result is reported as effect
/// uncertainty and lost coverage, never as silence or a terminal transition.
fn assert_unproved_effect_removal_reported(
    delta: &fss_core::MeaningfulDelta,
    state: KnowledgeState,
    context: &str,
) -> Result<(), Box<dyn Error>> {
    assert!(
        delta.silence_certificate.is_none(),
        "{context}: removing an unproved effect is never silence: {:?}",
        delta.classes
    );
    assert!(
        !delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "{context}: removing an unproved effect is not terminal: {:?}",
        delta.classes
    );
    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::EffectUncertainty),
        "{context}: {:?}",
        delta.classes
    );
    assert!(
        delta.effect_uncertainty_changes.contains(&removed_line()),
        "{context}: missing {:?} in {:?}",
        removed_line(),
        delta.effect_uncertainty_changes
    );
    assert!(
        !delta
            .effect_uncertainty_changes
            .iter()
            .any(|change| change.contains("resolved")),
        "{context}: {:?}",
        delta.effect_uncertainty_changes
    );
    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss),
        "{context}: {:?}",
        delta.classes
    );
    assert!(
        delta.coverage_changes.contains(&removed_coverage(state)),
        "{context}: missing {:?} in {:?}",
        removed_coverage(state),
        delta.coverage_changes
    );
    assert_eq!(delta.priority, DeltaPriority::Critical);
    delta.validate()?;
    Ok(())
}

#[test]
fn unestablished_effect_removed_is_effect_uncertainty_not_silence() -> Result<(), Box<dyn Error>> {
    for (prior, evidence) in [
        (KnowledgeState::Unknown, true),
        (KnowledgeState::Stale, true),
        (KnowledgeState::Redacted, true),
        (KnowledgeState::NotObservable, true),
        (KnowledgeState::Conflicted, true),
        (KnowledgeState::NotApplicable, true),
        (KnowledgeState::Estimated, true),
        (KnowledgeState::Known, false),
    ] {
        let mut basis_variant = Variant::baseline()?;
        basis_variant.effect_state = Some(prior);
        basis_variant.effect_evidence = evidence;
        let basis = publication(&basis_variant)?;
        let mut result_variant = basis_variant.clone();
        result_variant.sequence = 2;
        result_variant.effect_state = None;
        let result = successor_of(&basis, &result_variant)?;
        let delta = bound_delta(&basis, &result)?;
        assert_unproved_effect_removal_reported(
            &delta,
            prior,
            &format!("{} effect removed", prior.as_str()),
        )?;
    }
    Ok(())
}

#[test]
fn indeterminate_effect_laundered_through_unknown_then_dropped_is_never_silent()
-> Result<(), Box<dyn Error>> {
    let mut first = Variant::baseline()?;
    first.effect_state = Some(KnowledgeState::Indeterminate);
    let mut second = first.clone();
    second.sequence = 2;
    second.effect_state = Some(KnowledgeState::Unknown);
    let mut third = second.clone();
    third.sequence = 3;
    third.effect_state = None;
    let first = publication(&first)?;
    let second = successor_of(&first, &second)?;
    let third = successor_of(&second, &third)?;
    let store = recorded(&[&first, &second, &third])?;

    let step_one = bound(&store, &first, &second)?;
    assert_effect_unresolved(
        &step_one,
        &became(KnowledgeState::Unknown),
        Some(&degraded_to(KnowledgeState::Unknown)),
    )?;
    // Step two cannot see the indeterminate history; the unproved basis cell alone must report it.
    let step_two = bound(&store, &second, &third)?;
    assert_unproved_effect_removal_reported(
        &step_two,
        KnowledgeState::Unknown,
        "laundering step unknown->absent",
    )?;
    let end_to_end = bound(&store, &first, &third)?;
    assert_effect_unresolved(
        &end_to_end,
        &format!(
            "effect uncertainty remains: indeterminate effect {EFFECT_CLAIM} disappeared from the result frame without a proved outcome"
        ),
        Some(&format!(
            "unproved effect {EFFECT_CLAIM} disappeared from the result frame while indeterminate"
        )),
    )
}

/// Asserts that a comparison was refused because the result clock runs before the basis clock.
fn assert_backdated_refused(
    comparison: Result<fss_core::MeaningfulDelta, Box<dyn Error>>,
    context: &str,
) -> Result<(), Box<dyn Error>> {
    match comparison {
        Ok(delta) => Err(format!(
            "{context}: a backdated result must be refused: {:?}",
            delta.classes
        )
        .into()),
        Err(error) => {
            assert!(
                matches!(
                    error.downcast_ref::<crate::ReferenceError>(),
                    Some(crate::ReferenceError::Contract(
                        fss_core::ContractError::InvalidAnchorSuccessor
                    ))
                ),
                "{context}: unexpected refusal {error}"
            );
            Ok(())
        }
    }
}

#[test]
fn backdated_result_created_at_is_refused() -> Result<(), Box<dyn Error>> {
    // The basis clock is 1_001; validity 1_001 is closed at the fixture result clock 1_002, and a
    // result back-dated to 500 must not re-open it.
    let terminal = effect_transition_delta(
        Some(KnowledgeState::Unknown),
        Some(KnowledgeState::Known),
        |variant| {
            variant.effect_valid_until = Some(TimestampNs(1_001));
            variant.created_at = Some(TimestampNs(500));
        },
    );
    assert_backdated_refused(terminal, "unknown->known back-dated")?;
    let resolution = indeterminate_effect_delta(Some(KnowledgeState::Known), |variant| {
        variant.effect_valid_until = Some(TimestampNs(1_001));
        variant.created_at = Some(TimestampNs(500));
    });
    assert_backdated_refused(resolution, "indeterminate->known back-dated")?;
    // A result at exactly the basis clock is still a successor, and validity 1_001 is open there.
    let same_clock = effect_transition_delta(
        Some(KnowledgeState::Unknown),
        Some(KnowledgeState::Known),
        |variant| {
            variant.effect_valid_until = Some(TimestampNs(1_001));
            variant.created_at = Some(TimestampNs(1_001));
        },
    )?;
    assert!(
        same_clock
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "{:?}",
        same_clock.classes
    );
    same_clock.validate()?;
    Ok(())
}

#[test]
fn validity_window_is_inclusive_at_the_result_anchor() -> Result<(), Box<dyn Error>> {
    let at_limit = effect_transition_delta(
        Some(KnowledgeState::Unknown),
        Some(KnowledgeState::Known),
        |variant| variant.effect_valid_until = Some(TimestampNs(1_002)),
    )?;
    assert!(
        at_limit
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "{:?}",
        at_limit.classes
    );
    let one_past = effect_transition_delta(
        Some(KnowledgeState::Unknown),
        Some(KnowledgeState::Known),
        |variant| variant.effect_valid_until = Some(TimestampNs(1_001)),
    )?;
    assert!(
        !one_past
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "{:?}",
        one_past.classes
    );
    Ok(())
}

/// Returns whether `result` is a refusal carrying exactly `expected`.
fn refused_with(
    result: &Result<crate::ReferenceSituationPublication, Box<dyn Error>>,
    expected: &crate::ReferenceError,
) -> bool {
    let Err(error) = result else {
        return false;
    };
    // `ReferenceError` has no `PartialEq`, so compare the stable rendered refusal.
    error
        .downcast_ref::<crate::ReferenceError>()
        .is_some_and(|actual| actual.to_string() == expected.to_string())
}

/// A bound effect cell whose evidence root is not among the proof roots would publish a proved
/// effect without its proof as a handoff child, whatever the basis carried for the effect. So
/// projection refuses to publish it, and classification refuses a publication whose retained root
/// was removed after projection (fss-6sph6 moved the fss-deir9 proof-root check from the proof bar
/// into verification).
#[test]
fn known_effect_whose_evidence_is_not_a_proof_root_is_refused() -> Result<(), Box<dyn Error>> {
    let expected =
        crate::ReferenceError::Contract(fss_core::ContractError::IncompletePublicationGraph);
    for prior in [
        None,
        Some(KnowledgeState::Unknown),
        Some(KnowledgeState::Indeterminate),
    ] {
        let mut basis_variant = Variant::baseline()?;
        basis_variant.effect_state = prior;
        let basis = publication(&basis_variant)?;
        let mut result_variant = basis_variant.clone();
        result_variant.sequence = 2;
        result_variant.effect_state = Some(KnowledgeState::Known);

        let mut unretained = result_variant.clone();
        unretained.effect_evidence_retained = false;
        let projected = publication(&unretained);
        assert!(
            refused_with(&projected, &expected),
            "prior {prior:?}: {:?}",
            projected.map(|publication| publication.publication_digest)
        );

        let mut result = publication(&result_variant)?;
        assert!(
            result
                .situation
                .proof_roots
                .remove(&ContentDigest::sha256(b"effect-outcome"))
        );
        let classified = classify_reference_meaningful_delta(&basis, &result);
        assert!(
            classified
                .as_ref()
                .err()
                .is_some_and(|error| error.to_string() == expected.to_string()),
            "prior {prior:?}: {:?}",
            classified.map(|delta| delta.classes)
        );
    }
    Ok(())
}

/// Guards the "basis did not already pass" condition: an effect that already carried a proved
/// outcome in the basis is not a new terminal transition.
#[test]
fn already_proved_effect_is_not_terminal_again() -> Result<(), Box<dyn Error>> {
    let unchanged = effect_transition_delta(
        Some(KnowledgeState::Known),
        Some(KnowledgeState::Known),
        keep_effect_evidence,
    )?;
    assert!(
        unchanged.silence_certificate.is_some(),
        "{:?}",
        unchanged.classes
    );
    let rehypothesised = effect_transition_delta(
        Some(KnowledgeState::Known),
        Some(KnowledgeState::Known),
        |variant| variant.effect_hypothesis = Some(HypothesisDisposition::Live),
    )?;
    assert!(
        !rehypothesised
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "{:?}",
        rehypothesised.classes
    );
    Ok(())
}

/// Second guard for a terminal hypothesis disposition re-admitted into effect terminalization.
#[test]
fn absent_effect_becoming_unproved_known_with_terminal_hypothesis_is_not_terminal()
-> Result<(), Box<dyn Error>> {
    for hypothesis in TERMINAL_HYPOTHESES {
        let delta = effect_transition_delta(None, Some(KnowledgeState::Known), |variant| {
            variant.effect_evidence = false;
            variant.effect_hypothesis = Some(hypothesis);
        })?;
        assert_unproved_known_effect_not_terminal(
            &delta,
            &format!("absent->unproved known with hypothesis {hypothesis:?}"),
        )?;
    }
    Ok(())
}

// fss-deir9 re-review: G3 (a removed proved effect) and G2 (the proof-root trust boundary).

#[test]
fn proved_effect_removed_is_an_effect_change_and_coverage_loss() -> Result<(), Box<dyn Error>> {
    let delta = effect_transition_delta(Some(KnowledgeState::Known), None, keep_effect_evidence)?;
    let expected_change = format!(
        "effect uncertainty added: proved effect {EFFECT_CLAIM} disappeared from the result frame"
    );
    let expected_coverage =
        format!("proved effect {EFFECT_CLAIM} disappeared from the result frame");
    assert!(delta.silence_certificate.is_none(), "{:?}", delta.classes);
    assert!(
        !delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "{:?}",
        delta.classes
    );
    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::EffectUncertainty),
        "{:?}",
        delta.classes
    );
    assert!(
        delta.effect_uncertainty_changes.contains(&expected_change),
        "missing {expected_change:?} in {:?}",
        delta.effect_uncertainty_changes
    );
    assert!(delta.classes.contains(&MeaningfulDeltaClass::CoverageLoss));
    assert!(
        delta.coverage_changes.contains(&expected_coverage),
        "missing {expected_coverage:?} in {:?}",
        delta.coverage_changes
    );
    // The existing premise path still reports the loss as an invalidated assumption.
    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::PlanInvalidation)
    );
    assert_eq!(delta.priority, DeltaPriority::Critical);
    delta.validate()?;
    Ok(())
}

/// The proof-root trust boundary is closed (fss-deir9 G2, fss-6sph6).
///
/// This test used to pin that a situation built by hand could make any digest a proof root, and a
/// `known` effect citing it cleared the proof bar. The effect evidence here is still an arbitrary
/// digest that no receipt produced, and the situation still lists it as a proof root, but no compile
/// path bound the cell to a verified outcome or receipt. So projection refuses it; so does
/// publication `verify`, when the unbound situation is swapped into an otherwise verified
/// publication; and so does classification.
#[test]
fn hand_built_proof_roots_are_refused_by_projection_and_classification()
-> Result<(), Box<dyn Error>> {
    let expected = crate::ReferenceError::InvalidSpec("situation_effect_known_unbound");
    let mut basis_variant = Variant::baseline()?;
    basis_variant.effect_state = None;
    let basis = publication(&basis_variant)?;
    let mut result_variant = basis_variant.clone();
    result_variant.sequence = 2;
    result_variant.effect_state = Some(KnowledgeState::Known);
    result_variant.effect_bound = false;

    // Route 1: projection of the hand-built situation.
    let projected = publication(&result_variant);
    assert!(
        refused_with(&projected, &expected),
        "{:?}",
        projected.map(|publication| publication.publication_digest)
    );

    // Route 2: the same capsule and proof roots, re-wrapped without the binding, inside an
    // otherwise verified publication. The publication digest commits to the seal, so the re-wrap
    // no longer matches it, and verification refuses the unbound effect before comparing digests.
    result_variant.effect_bound = true;
    let mut forged = publication(&result_variant)?;
    let arbitrary = ContentDigest::sha256(b"effect-outcome");
    assert!(forged.situation.proof_roots.contains(&arbitrary));
    forged.situation = ReferenceSituation::new(
        forged.situation.capsule.clone(),
        forged.situation.proof_roots.clone(),
    );
    assert_ne!(forged.computed_digest()?, forged.publication_digest);
    let verified = forged.verify();
    assert!(
        matches!(
            verified,
            Err(crate::ReferenceError::InvalidSpec(
                "situation_effect_known_unbound"
            ))
        ),
        "{verified:?}"
    );

    // Route 3: classification verifies both sides first.
    let classified = classify_reference_meaningful_delta(&basis, &forged);
    assert!(
        matches!(
            classified,
            Err(crate::ReferenceError::InvalidSpec(
                "situation_effect_known_unbound"
            ))
        ),
        "{:?}",
        classified.map(|delta| delta.classes)
    );
    Ok(())
}

/// fss-6sph6: the typed terminal outcome is part of the proof, so an otherwise identical proved
/// effect whose operation flips from succeeded to failed is a contradiction, never silence.
#[test]
fn proved_effect_whose_typed_outcome_flips_is_a_contradiction() -> Result<(), Box<dyn Error>> {
    let mut basis_variant = Variant::baseline()?;
    basis_variant.effect_state = Some(KnowledgeState::Known);
    let basis = publication(&basis_variant)?;
    let mut result_variant = basis_variant.clone();
    result_variant.sequence = 2;
    result_variant.effect_terminal_state = fss_core::EffectState::Failed;
    let result = successor_of(&basis, &result_variant)?;
    let delta = bound_delta(&basis, &result)?;
    let expected = "effect outcome contradicted: operation meaningful-delta was proved succeeded and is now proved failed";
    assert!(delta.silence_certificate.is_none(), "{:?}", delta.classes);
    assert!(
        delta.classes.contains(&MeaningfulDeltaClass::Contradiction),
        "{:?}",
        delta.classes
    );
    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::EffectUncertainty),
        "{:?}",
        delta.classes
    );
    assert!(
        delta
            .effect_uncertainty_changes
            .iter()
            .any(|change| change == expected),
        "missing {expected:?} in {:?}",
        delta.effect_uncertainty_changes
    );
    assert!(
        !delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "{:?}",
        delta.classes
    );
    delta.validate()?;
    Ok(())
}

/// fss-ko55q: world_semantic_digest hashes WorldEnvelope fields directly without
/// re-validating them, relying on classify_reference_meaningful_delta verifying both
/// publications first. Feeding an invalid envelope into either basis or result must
/// be refused by the verify() precondition, and a mutation that skips verify() must fail.
#[test]
fn classification_refuses_invalid_world_envelope_precondition() -> Result<(), Box<dyn Error>> {
    let basis_variant = Variant::baseline()?;
    let basis = publication(&basis_variant)?;
    let mut result_variant = basis_variant.clone();
    result_variant.sequence = 2;
    let mut result = publication(&result_variant)?;

    // Corrupt result envelope so WorldEnvelope::validate fails (unprotected adversarial residual).
    result
        .situation
        .capsule
        .frame
        .world_envelope
        .adversarial_residuals
        .push(fss_core::PossibleWorld {
            world_id: "world:invalid:result".to_owned(),
            description: "Unprotected residual violates envelope invariants.".to_owned(),
            claim_ids: BTreeSet::from(["claim:premise".to_owned()]),
            evidence: vec![ContentDigest::sha256(b"ev")],
            consequence_severity: 0,
            protected: false,
        });

    assert!(
        result
            .situation
            .capsule
            .frame
            .world_envelope
            .validate()
            .is_err(),
        "sanity check: corrupted envelope must fail WorldEnvelope::validate"
    );

    let classified_result_invalid = classify_reference_meaningful_delta(&basis, &result);
    assert!(
        matches!(
            classified_result_invalid,
            Err(crate::ReferenceError::Contract(
                fss_core::ContractError::EvidenceRequired
            ))
        ),
        "classification must fail when result has invalid envelope; got: {classified_result_invalid:?}"
    );

    // Corrupt basis envelope so WorldEnvelope::validate fails (empty world_id).
    let mut invalid_basis = basis.clone();
    invalid_basis
        .situation
        .capsule
        .frame
        .world_envelope
        .alternatives
        .push(fss_core::PossibleWorld {
            world_id: String::new(),
            description: "Empty world_id violates envelope invariants.".to_owned(),
            claim_ids: BTreeSet::from(["claim:premise".to_owned()]),
            evidence: vec![ContentDigest::sha256(b"ev")],
            consequence_severity: 1,
            protected: true,
        });

    assert!(
        invalid_basis
            .situation
            .capsule
            .frame
            .world_envelope
            .validate()
            .is_err(),
        "sanity check: corrupted basis envelope must fail WorldEnvelope::validate"
    );

    let valid_result = publication(&result_variant)?;
    let classified_basis_invalid =
        classify_reference_meaningful_delta(&invalid_basis, &valid_result);
    assert!(
        matches!(
            classified_basis_invalid,
            Err(crate::ReferenceError::Contract(
                fss_core::ContractError::EvidenceRequired
            ))
        ),
        "classification must fail when basis has invalid envelope; got: {classified_basis_invalid:?}"
    );

    Ok(())
}

/// Pins why the unproved-known fixtures carry vendor-claimed provenance: PROV-001 refuses an
/// observed effect cell asserting `known` without evidence, while the evidence-less provider claim
/// stays valid and is never a proved outcome.
#[test]
fn evidence_less_known_effect_is_refused_as_observed_and_unproved_as_vendor_claim()
-> Result<(), Box<dyn Error>> {
    let observed = KnowledgeCell {
        claim_id: EFFECT_CLAIM.to_owned(),
        statement: "The external effect reached a retained terminal outcome.".to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: Vec::new(),
        contradictions: Vec::new(),
        valid_until: None,
        state_basis: None,
    };
    assert_eq!(
        observed.validate(),
        Err(fss_core::ContractError::EvidenceRequired)
    );

    let mut variant = Variant::baseline()?;
    variant.effect_state = Some(KnowledgeState::Known);
    variant.effect_evidence = false;
    let projected = publication(&variant)?;
    let now = projected.situation.capsule.created_at;
    let effect = projected
        .situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id == EFFECT_CLAIM)
        .ok_or(crate::ReferenceError::InvalidSpec("missing_effect_cell"))?;
    assert_eq!(effect.provenance, ProvenanceClass::VendorClaimed);
    assert!(effect.evidence.is_empty());
    assert_eq!(effect.validate(), Ok(()));
    assert!(!effect.is_irreversible_effect_premise(now));
    Ok(())
}

/// A `known` effect cell binds only to a terminal operation state, and a non-`known` one only to a
/// non-terminal state, under exactly the claim identity of its kind and operation (fss-6sph6).
#[test]
fn effect_binding_requires_known_exactly_for_a_terminal_state() -> Result<(), Box<dyn Error>> {
    use fss_core::EffectState;

    let template = publication(&Variant::baseline()?)?;
    let operation_id = fss_core::OperationId::parse("meaningful-delta")?;
    let root = ContentDigest::sha256(b"effect-outcome");
    let cell = |claim_id: &str, state: KnowledgeState| -> Result<KnowledgeCell, Box<dyn Error>> {
        Ok(KnowledgeCell {
            claim_id: claim_id.to_owned(),
            statement: "The external effect has an explicit typed state.".to_owned(),
            knowledge_state: state,
            provenance: ProvenanceClass::Observed,
            hypothesis: None,
            evidence: vec![root],
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: fixture_state_basis(state, root)?,
        })
    };
    let fresh = || {
        ReferenceSituation::new(
            template.situation.capsule.clone(),
            template.situation.proof_roots.clone(),
        )
    };
    for (claim_id, cell_state, operation_state) in [
        (EFFECT_CLAIM, KnowledgeState::Known, EffectState::Committed),
        (EFFECT_CLAIM, KnowledgeState::Known, EffectState::Prepared),
        (
            EFFECT_CLAIM,
            KnowledgeState::Known,
            EffectState::Indeterminate,
        ),
        (
            EFFECT_CLAIM,
            KnowledgeState::Indeterminate,
            EffectState::Verified,
        ),
        (EFFECT_CLAIM, KnowledgeState::Unknown, EffectState::Failed),
        (
            EFFECT_CLAIM,
            KnowledgeState::Unknown,
            EffectState::Cancelled,
        ),
        (
            "claim:effect:meaningful-delta:local-state",
            KnowledgeState::Known,
            EffectState::Verified,
        ),
    ] {
        let mut situation = fresh();
        let bound = situation.bind_effect_cell(
            crate::EffectCellKind::Outcome,
            &operation_id,
            operation_state,
            &cell(claim_id, cell_state)?,
        );
        assert!(
            matches!(
                bound,
                Err(crate::ReferenceError::InvalidSpec(
                    "situation_effect_binding"
                ))
            ),
            "{claim_id} {cell_state:?} bound to {operation_state:?}: {bound:?}"
        );
        assert_eq!(situation.effect_cell_kind(claim_id), None);
    }
    for (cell_state, operation_state) in [
        (KnowledgeState::Known, EffectState::Verified),
        (KnowledgeState::Known, EffectState::Failed),
        (KnowledgeState::Indeterminate, EffectState::Committed),
        (KnowledgeState::Unknown, EffectState::Prepared),
    ] {
        let mut situation = fresh();
        situation.bind_effect_cell(
            crate::EffectCellKind::Outcome,
            &operation_id,
            operation_state,
            &cell(EFFECT_CLAIM, cell_state)?,
        )?;
        assert_eq!(
            situation.effect_cell_kind(EFFECT_CLAIM),
            Some(crate::EffectCellKind::Outcome)
        );
    }
    Ok(())
}

/// Nominal projection policy for publications re-projected by the review probes below.
fn nominal_spec() -> Result<ReferenceProjectionSpec, Box<dyn Error>> {
    Ok(ReferenceProjectionSpec {
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
        pressure: ResourcePressure::Nominal,
        degraded_dimensions: BTreeSet::new(),
        target_tokens: 25_000,
    })
}

/// The successor publication plus one hand-built `known` cell whose evidence the caller rooted
/// itself (review probe P5); sealed when `sealed`, as a compile path would seal it, with the
/// fixture subject and `predecessor` as its sealed predecessor.
fn publication_with_cell(
    claim_id: &str,
    hypothesis: Option<HypothesisDisposition>,
    sealed: bool,
    predecessor: Option<ContentDigest>,
) -> Result<crate::ReferenceSituationPublication, Box<dyn Error>> {
    let mut variant = Variant::baseline()?;
    variant.sequence = 2;
    let template = publication(&variant)?;
    let mut capsule = template.situation.capsule.clone();
    let root = ContentDigest::sha256(b"self-asserted");
    capsule.frame.knowledge_cells.push(KnowledgeCell {
        claim_id: claim_id.to_owned(),
        statement: "The external alert was delivered.".to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis,
        evidence: vec![root],
        contradictions: Vec::new(),
        valid_until: None,
        state_basis: None,
    });
    let mut roots = template.situation.proof_roots.clone();
    roots.insert(root);
    let mut situation = ReferenceSituation::new(capsule, roots);
    if sealed {
        situation.set_lineage(
            fss_core::EventId::parse("event:meaningful-delta")?,
            "objective:meaningful-delta".to_owned(),
            predecessor,
        );
        situation.set_authority_anchor(fixture_authority_anchor()?);
        situation.seal_effect_bindings()?;
    }
    Ok(project_reference_situation(situation, &nominal_spec()?)?)
}

/// The unsealed form of [`publication_with_cell`].
fn publication_with_self_rooted_cell(
    claim_id: &str,
    hypothesis: Option<HypothesisDisposition>,
) -> Result<crate::ReferenceSituationPublication, Box<dyn Error>> {
    publication_with_cell(claim_id, hypothesis, false, None)
}

/// `publication` rebuilt through the public constructor, so unsealed, after `edit_capsule`.
fn unsealed_copy(
    publication: &crate::ReferenceSituationPublication,
    edit_capsule: impl FnOnce(&mut SituationCapsule),
) -> Result<crate::ReferenceSituationPublication, Box<dyn Error>> {
    let mut capsule = publication.situation.capsule.clone();
    edit_capsule(&mut capsule);
    Ok(project_reference_situation(
        ReferenceSituation::new(capsule, publication.situation.proof_roots.clone()),
        &nominal_spec()?,
    )?)
}

/// The reserved namespaces are an exact allowlist: a reserved namespace with no tail is refused,
/// a namespace with a dangling `-` is refused by the grammar, and a `known` cell in the effect
/// namespace is refused as unbound whatever its tail. Look-alike and benign names near a reserved
/// one are ordinary claims and publish (round 5 retired the name heuristic; they cannot
/// terminalize anything unsealed), as do tails with empty segments (fss-6sph6).
#[test]
fn reserved_namespace_edges_are_refused_and_other_names_publish() -> Result<(), Box<dyn Error>> {
    let grammar = "situation_claim_id_grammar";
    for (claim_id, expected) in [
        ("claim:effect", "situation_reserved_claim_without_tail"),
        ("claim:obligation", "situation_reserved_claim_without_tail"),
        ("claim:effect-:x", grammar),
        ("claim:obligation-:x", grammar),
        ("claim:-effect:x", grammar),
        ("claim:-:x", grammar),
        ("claim::x", grammar),
        ("claim:effect:", "situation_effect_known_unbound"),
        (
            "claim:effect::meaningful-delta:outcome",
            "situation_effect_known_unbound",
        ),
    ] {
        let projected = publication_with_self_rooted_cell(claim_id, None);
        let expected = crate::ReferenceError::InvalidSpec(expected);
        assert!(
            refused_with(&projected, &expected),
            "{claim_id:?}: {:?}",
            projected.map(|publication| publication.publication_digest)
        );
    }
    for claim_id in [
        "claim:defect:x",
        "claim:affect:x",
        "claim:perfect:x",
        "claim:reflect:x",
        "claim:e-ffect:x",
        "claim:effects:x",
        "claim:door:",
        "claim:door::x",
        "claim:event:meaningful-delta:policy",
        "claim:cam1",
    ] {
        publication_with_self_rooted_cell(claim_id, None)?;
    }
    Ok(())
}

/// Review probes P5 and RR1: a claim identity outside the strict ASCII grammar is refused before any
/// namespace test, so no case, Unicode, spacing or invisible-character look-alike of a reserved
/// namespace reaches the event rule's terminal transition.
#[test]
fn claim_ids_outside_the_strict_ascii_grammar_are_refused() -> Result<(), Box<dyn Error>> {
    let expected = crate::ReferenceError::InvalidSpec("situation_claim_id_grammar");
    for claim_id in [
        "claim:Effect:meaningful-delta:outcome",
        "claim:EFFECT:meaningful-delta:outcome",
        "Claim:effect:meaningful-delta:outcome",
        "claim:Obligation:meaningful-delta",
        "claim:\u{0435}ffect:meaningful-delta:outcome",
        "claim:effect\u{FF1A}meaningful-delta:outcome",
        "claim\u{FF1A}effect:meaningful-delta:outcome",
        " claim:effect:meaningful-delta:outcome",
        "claim:effect :meaningful-delta:outcome",
        "claim:effect\u{200B}:meaningful-delta:outcome",
        "claim:obligat\u{0456}on:meaningful-delta",
        "claim: obligation:meaningful-delta",
        "claim:effect:meaningful-delta:outcome\n",
        "claim::meaningful-delta",
    ] {
        let projected =
            publication_with_self_rooted_cell(claim_id, Some(HypothesisDisposition::Resolved));
        assert!(
            refused_with(&projected, &expected),
            "{claim_id:?}: {:?}",
            projected.map(|publication| publication.publication_digest)
        );
    }
    Ok(())
}

/// Review probe P5: no compile path binds an obligation-namespace cell, and an obligation
/// terminalizes only through the typed obligation set, so a hand-built `claim:obligation:` cell,
/// `known` or resolved, is refused rather than classified.
#[test]
fn hand_built_obligation_cell_is_refused() -> Result<(), Box<dyn Error>> {
    let expected = crate::ReferenceError::InvalidSpec("situation_obligation_cell_unbound");
    for hypothesis in [None, Some(HypothesisDisposition::Resolved)] {
        let projected =
            publication_with_self_rooted_cell("claim:obligation:meaningful-delta", hypothesis);
        assert!(
            refused_with(&projected, &expected),
            "{hypothesis:?}: {:?}",
            projected.map(|publication| publication.publication_digest)
        );
    }
    Ok(())
}

/// Review probes P4 and RR4: a hand-built effect cell is refused in every state, not only `known`,
/// so a situation no compile path sealed cannot carry an indeterminate or otherwise unproved effect
/// that stands in for, or relabels, a compiled one.
#[test]
fn hand_built_effect_cell_in_any_state_is_refused() -> Result<(), Box<dyn Error>> {
    let expected = crate::ReferenceError::InvalidSpec("situation_effect_cell_unbound");
    for state in [
        KnowledgeState::Indeterminate,
        KnowledgeState::Unknown,
        KnowledgeState::Estimated,
        KnowledgeState::Stale,
        KnowledgeState::NotApplicable,
    ] {
        let mut variant = Variant::baseline()?;
        variant.effect_state = Some(state);
        variant.effect_bound = false;
        let projected = publication(&variant);
        assert!(
            refused_with(&projected, &expected),
            "{state:?}: {:?}",
            projected.map(|publication| publication.publication_digest)
        );
    }
    Ok(())
}

/// Round 4 F6: the event rule's own guard excludes effect and obligation cells, so neither can
/// drive a terminal transition through a hypothesis even if verification were bypassed.
#[test]
fn event_rule_never_applies_to_effect_or_obligation_cells() {
    let cell = |claim_id: &str| KnowledgeCell {
        claim_id: claim_id.to_owned(),
        statement: "The proposition was resolved.".to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: Some(HypothesisDisposition::Resolved),
        evidence: vec![ContentDigest::sha256(b"event-rule-root")],
        contradictions: Vec::new(),
        valid_until: None,
        state_basis: None,
    };
    assert!(!crate::meaningful_delta::event_rule_applies(&cell(
        "claim:obligation:meaningful-delta"
    )));
    assert!(!crate::meaningful_delta::event_rule_applies(&cell(
        EFFECT_CLAIM
    )));
    assert!(crate::meaningful_delta::event_rule_applies(&cell(
        "claim:event:meaningful-delta:policy"
    )));
}

/// The classifier reads an effect cell's typed state and binding, never its free text: a still
/// indeterminate effect whose statement claims delivery, success or resolution is neither resolved
/// nor terminal (restores the spoof coverage the hand-built planted negative lost in fss-6sph6).
#[test]
fn effect_statement_free_text_never_terminalizes() -> Result<(), Box<dyn Error>> {
    let mut basis_variant = Variant::baseline()?;
    basis_variant.effect_state = Some(KnowledgeState::Indeterminate);
    let basis = publication(&basis_variant)?;
    for statement in [
        "Alert delivery is terminally verified by retained provider proof.",
        "Alert delivery was resolved and succeeded.",
        "Alert delivery is unverified and not failed, pending adapter response.",
    ] {
        let mut result_variant = basis_variant.clone();
        result_variant.sequence = 2;
        result_variant.effect_statement = Some(statement.to_owned());
        let result = successor_of(&basis, &result_variant)?;
        let delta = bound_delta(&basis, &result)?;
        assert!(
            !delta
                .classes
                .contains(&MeaningfulDeltaClass::TerminalTransition),
            "{statement:?}: {:?}",
            delta.classes
        );
        assert!(
            delta
                .classes
                .contains(&MeaningfulDeltaClass::EffectUncertainty),
            "{statement:?}: {:?}",
            delta.classes
        );
        assert!(
            !delta
                .effect_uncertainty_changes
                .iter()
                .any(|change| change.starts_with("effect uncertainty resolved")),
            "{statement:?}: {:?}",
            delta.effect_uncertainty_changes
        );
        delta.validate()?;
    }
    Ok(())
}

/// Round 5 N2 and fss-mnlz1: an obligation discharge is never terminal without the durable effect
/// journal. An unsealed result, the plain classifier, and the lineage-bound classifier without a
/// journal all report the removal, never as a terminal transition and never as an error. The
/// journal-bound terminal discharge is pinned against a real durable journal in the guard tests
/// (`durable_discharge_is_terminal_once_the_journal_closes_it`).
#[test]
fn obligation_discharge_is_never_terminal_without_the_durable_journal() -> Result<(), Box<dyn Error>>
{
    let obligation = ObligationId::parse("obligation:meaningful-delta")?;
    let mut basis_variant = Variant::baseline()?;
    basis_variant.obligations = vec![obligation.clone()];
    let basis = publication(&basis_variant)?;
    let mut result_variant = basis_variant.clone();
    result_variant.sequence = 2;
    result_variant.obligations.clear();
    let sealed = successor_of(&basis, &result_variant)?;
    let unsealed = unsealed_copy(&sealed, |_| {})?;
    let removed = format!("obligation removed: {obligation}");
    let store = recorded(&[&basis, &sealed])?;
    for (label, delta) in [
        ("unsealed", bound(&store, &basis, &unsealed)?),
        (
            "plain",
            classify_reference_meaningful_delta(&basis, &sealed)?,
        ),
        ("bound without journal", bound(&store, &basis, &sealed)?),
    ] {
        assert!(
            delta.classes.contains(&MeaningfulDeltaClass::Obligation),
            "{label}: {:?}",
            delta.classes
        );
        assert!(
            delta.obligation_changes.contains(&removed),
            "{label}: {delta:?}"
        );
        assert!(
            !delta
                .classes
                .contains(&MeaningfulDeltaClass::TerminalTransition),
            "{label}: {:?}",
            delta.classes
        );
        assert!(delta.silence_certificate.is_none(), "{label}");
        delta.validate()?;
    }
    store.cleanup();
    Ok(())
}

/// Round 5 N2: no name reaches a terminal transition from an unsealed publication. Every
/// look-alike of a reserved namespace, and any ordinary name, with a resolved hypothesis publishes
/// as an ordinary claim and is reported as a hypothesis change, never as a terminal transition.
#[test]
fn unsealed_publications_never_terminalize_any_name() -> Result<(), Box<dyn Error>> {
    let basis = publication(&Variant::baseline()?)?;
    let store = recorded(&[&basis])?;
    for claim_id in [
        "claim:efffekkt:x",
        "claim:ef-fe-kt:x",
        "claim:0bl1gat10n:x",
        "claim:obl-1-gat-1-on:x",
        "claim:oblig:x",
        "claim:eff:x",
        "claim:alert-delivery",
        "claim:obligatory",
    ] {
        let result =
            publication_with_self_rooted_cell(claim_id, Some(HypothesisDisposition::Resolved))?;
        assert!(!result.situation.is_sealed());
        let delta = bound(&store, &basis, &result)?;
        assert!(
            !delta
                .classes
                .contains(&MeaningfulDeltaClass::TerminalTransition),
            "{claim_id}: {:?}",
            delta.classes
        );
        assert!(
            delta.classes.contains(&MeaningfulDeltaClass::Hypothesis),
            "{claim_id}: {:?}",
            delta.classes
        );
        delta.validate()?;
    }
    Ok(())
}

/// Round 5 N2 positive control: the same resolved hypothesis in a sealed result that continues the
/// sealed basis is an event terminal transition: critical, and refusing to coalesce with the next
/// delta.
#[test]
fn sealed_event_hypothesis_terminal_is_non_coalescible() -> Result<(), Box<dyn Error>> {
    let basis = publication(&Variant::baseline()?)?;
    let result = publication_with_cell(
        "claim:alert-delivery",
        Some(HypothesisDisposition::Resolved),
        true,
        Some(basis.publication_digest),
    )?;
    assert!(result.situation.is_sealed());
    let delta = bound_delta(&basis, &result)?;
    assert!(
        delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "{:?}",
        delta.classes
    );
    assert!(delta.is_non_coalescible());
    assert_eq!(delta.priority, DeltaPriority::Critical);
    let mut next_variant = Variant::baseline()?;
    next_variant.sequence = 3;
    next_variant.pressure = ResourcePressure::Elevated;
    let next =
        classify_reference_meaningful_delta(&result, &successor_of(&result, &next_variant)?)?;
    assert!(!delta.can_coalesce_with(&next)?);
    assert!(
        delta
            .coalesce(
                &next,
                "delta:coalesced",
                "continuation:coalesced",
                ContentDigest::sha256(b"coalesced"),
            )
            .is_err()
    );
    delta.validate()?;
    Ok(())
}

/// Round 5 N4: an unsealed basis cannot fake a discharge. A basis rebuilt with an invented
/// obligation, against the genuine sealed result, reports the removal but no terminal transition.
#[test]
fn unsealed_basis_cannot_fake_an_obligation_discharge() -> Result<(), Box<dyn Error>> {
    let genuine_basis = publication(&Variant::baseline()?)?;
    let invented = ObligationId::parse("obligation:zz:invented")?;
    let basis = unsealed_copy(&genuine_basis, |capsule| {
        capsule.obligations.push(invented.clone());
    })?;
    let mut result_variant = Variant::baseline()?;
    result_variant.sequence = 2;
    let result = publication(&result_variant)?;
    assert!(result.situation.is_sealed());
    let store = recorded(&[&result])?;
    let delta = bound(&store, &basis, &result)?;
    store.cleanup();
    assert!(
        delta
            .obligation_changes
            .contains(&format!("obligation removed: {invented}")),
        "{delta:?}"
    );
    assert!(
        !delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition),
        "{:?}",
        delta.classes
    );
    delta.validate()?;
    Ok(())
}

/// Round 5 N2: an effect terminalizes only between sealed publications. A proved effect in a
/// sealed result is terminal against the sealed basis it continues and not against that basis's
/// unsealed copy.
#[test]
fn effect_terminalization_needs_a_sealed_basis() -> Result<(), Box<dyn Error>> {
    let sealed_basis = publication(&Variant::baseline()?)?;
    let unsealed_basis = unsealed_copy(&sealed_basis, |_| {})?;
    let mut result_variant = Variant::baseline()?;
    result_variant.sequence = 2;
    result_variant.effect_state = Some(KnowledgeState::Known);
    let result = successor_of(&sealed_basis, &result_variant)?;
    let terminal = |delta: &fss_core::MeaningfulDelta| {
        delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition)
    };
    let store = recorded(&[&sealed_basis, &result])?;
    let delta = bound(&store, &sealed_basis, &result)?;
    assert!(terminal(&delta), "{:?}", delta.classes);
    let delta = bound(&store, &unsealed_basis, &result)?;
    store.cleanup();
    assert!(!terminal(&delta), "{:?}", delta.classes);
    delta.validate()?;
    Ok(())
}

/// `publication` rebuilt after `edit_capsule` and sealed, as a compile path would seal it, with
/// the fixture subject and `predecessor` as its sealed predecessor.
fn resealed_copy(
    publication: &crate::ReferenceSituationPublication,
    predecessor: Option<ContentDigest>,
    edit_capsule: impl FnOnce(&mut SituationCapsule),
) -> Result<crate::ReferenceSituationPublication, Box<dyn Error>> {
    let mut capsule = publication.situation.capsule.clone();
    edit_capsule(&mut capsule);
    let mut situation = ReferenceSituation::new(capsule, publication.situation.proof_roots.clone());
    situation.set_lineage(
        fss_core::EventId::parse("event:meaningful-delta")?,
        "objective:meaningful-delta".to_owned(),
        predecessor,
    );
    situation.set_authority_anchor(fixture_authority_anchor()?);
    situation.seal_effect_bindings()?;
    Ok(project_reference_situation(situation, &nominal_spec()?)?)
}

/// Round 5 R5-4: a mission terminal transition, through the typed `mission_state` or a
/// `claim:mission:` cell, needs both publications sealed like every other terminal transition.
/// Between sealed publications where the result continues the basis it is a critical,
/// non-coalescible terminal transition; with the result unsealed the change is reported but never
/// as terminal.
#[test]
fn mission_terminalization_needs_both_publications_sealed() -> Result<(), Box<dyn Error>> {
    let basis = publication(&Variant::baseline()?)?;
    let predecessor = Some(basis.publication_digest);
    let mut successor = Variant::baseline()?;
    successor.sequence = 2;
    let template = publication(&successor)?;
    let close = |capsule: &mut SituationCapsule| {
        capsule.mission_state = Some(fss_core::MissionLifecycleState::Closed);
    };
    let terminal = |delta: &fss_core::MeaningfulDelta| {
        delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition)
    };
    for (label, sealed, unsealed) in [
        (
            "mission_state",
            resealed_copy(&template, predecessor, close)?,
            unsealed_copy(&template, close)?,
        ),
        (
            "claim:mission",
            publication_with_cell("claim:mission:meaningful-delta", None, true, predecessor)?,
            publication_with_cell("claim:mission:meaningful-delta", None, false, None)?,
        ),
    ] {
        let delta = bound_delta(&basis, &sealed)?;
        assert!(terminal(&delta), "{label} sealed: {:?}", delta.classes);
        assert!(delta.is_non_coalescible(), "{label}");
        assert_eq!(delta.priority, DeltaPriority::Critical, "{label}");
        delta.validate()?;
        let store = recorded(&[&basis])?;
        let delta = bound(&store, &basis, &unsealed)?;
        store.cleanup();
        assert!(!terminal(&delta), "{label} unsealed: {:?}", delta.classes);
        assert!(
            delta.classes.contains(&MeaningfulDeltaClass::MaterialState),
            "{label} unsealed: {:?}",
            delta.classes
        );
        delta.validate()?;
    }
    Ok(())
}

/// `variant` published as the successor of `basis`: sealed with the fixture subject and `basis` as
/// its sealed predecessor, as a compile path chains a lineage (fss-mnlz1).
fn successor_of(
    basis: &crate::ReferenceSituationPublication,
    variant: &Variant,
) -> Result<crate::ReferenceSituationPublication, Box<dyn Error>> {
    let mut variant = variant.clone();
    variant.predecessor = Some(basis.publication_digest);
    publication(&variant)
}

/// fss-mnlz1: a proved effect is terminal only when the durable lineage records the result as the
/// basis's successor. The chained, recorded pair is terminal; a result naming no predecessor or
/// another one, which the lineage cannot record after the basis, reports the change without a
/// terminal transition.
#[test]
fn effect_terminalization_needs_the_result_to_continue_the_basis() -> Result<(), Box<dyn Error>> {
    let basis = publication(&Variant::baseline()?)?;
    let mut result_variant = Variant::baseline()?;
    result_variant.sequence = 2;
    result_variant.effect_state = Some(KnowledgeState::Known);
    let terminal = |delta: &fss_core::MeaningfulDelta| {
        delta
            .classes
            .contains(&MeaningfulDeltaClass::TerminalTransition)
    };
    let chained = successor_of(&basis, &result_variant)?;
    let delta = bound_delta(&basis, &chained)?;
    assert!(terminal(&delta), "{:?}", delta.classes);
    let store = recorded(&[&basis])?;
    for predecessor in [None, Some(ContentDigest::sha256(b"another-publication"))] {
        let mut variant = result_variant.clone();
        variant.predecessor = predecessor;
        let delta = bound(&store, &basis, &publication(&variant)?)?;
        assert!(!terminal(&delta), "{predecessor:?}: {:?}", delta.classes);
        assert!(
            delta.classes.contains(&MeaningfulDeltaClass::MaterialState),
            "{predecessor:?}: {:?}",
            delta.classes
        );
        delta.validate()?;
    }
    store.cleanup();
    Ok(())
}

/// Site lineage of the fixture authority.
const FIXTURE_AUTHORITY_SITE: &str = "site:meaningful-delta:authority";

/// The one authority batch every fixture publication stands compiled against: an authority ledger
/// holding it commits the authority anchor the fixtures seal (fss-mnlz1).
fn fixture_authority_batch() -> Result<fss_core::EvidenceDeltaBatch, Box<dyn Error>> {
    let root = ContentDigest::sha256(b"meaningful-delta-authority");
    let delta = fss_core::EvidenceDelta {
        delta_id: "delta:meaningful-delta:authority".to_owned(),
        family: "fixture_authority".to_owned(),
        object_id: fss_core::ObjectId::parse("object:meaningful-delta:authority")?,
        prior_generation: None,
        new_generation: 1,
        validity: fss_core::CaptureInterval::new(TimestampNs(0), TimestampNs(0))?,
        plane: fss_core::Plane::Authority,
        payload_digest: root,
        witness_digest: None,
        operation_id: None,
    };
    Ok(
        fss_core::ReferenceLedger::new(FIXTURE_AUTHORITY_SITE).prepare_batch(
            fss_core::BatchId::parse("batch:meaningful-delta:authority")?,
            vec![delta],
            [root],
        )?,
    )
}

/// The authority anchor fixture publications seal, as a compile path seals the anchor it compiled
/// against.
fn fixture_authority_anchor() -> Result<LedgerAnchor, Box<dyn Error>> {
    Ok(fixture_authority_batch()?.new_anchor)
}

/// A durable fixture authority under a fresh temporary path: the fixture authority batch, then the
/// publication lineage a test records. Removed by [`Self::cleanup`].
struct FixtureLineage {
    authority: fss_ledger::DurableReferenceLedger,
    path: std::path::PathBuf,
}

impl FixtureLineage {
    /// Opens an authority whose path is unique to this process, thread and instant.
    fn new() -> Result<Self, Box<dyn Error>> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let thread = format!("{:?}", std::thread::current().id())
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>();
        let path = std::env::temp_dir().join(format!(
            "fss-reference-authority-{}-{thread}-{nanos}.journal",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut authority = fss_ledger::DurableReferenceLedger::open(
            &path,
            FIXTURE_AUTHORITY_SITE,
            fss_ledger::IncompleteTailPolicy::Reject,
        )?;
        let _ = authority.append(fixture_authority_batch()?)?;
        Ok(Self { authority, path })
    }

    /// Removes the authority file.
    fn cleanup(self) {
        let path = self.path.clone();
        drop(self);
        let _ = std::fs::remove_file(path);
    }
}

/// A fresh fixture authority with `chain` recorded in order.
fn recorded(
    chain: &[&crate::ReferenceSituationPublication],
) -> Result<FixtureLineage, Box<dyn Error>> {
    let mut store = FixtureLineage::new()?;
    for publication in chain {
        crate::record_reference_publication(&mut store.authority, publication)?;
    }
    Ok(store)
}

/// Classifies `basis` to `result` bound to `store` and no journal.
fn bound(
    store: &FixtureLineage,
    basis: &crate::ReferenceSituationPublication,
    result: &crate::ReferenceSituationPublication,
) -> Result<fss_core::MeaningfulDelta, crate::ReferenceError> {
    classify_reference_meaningful_delta_in_lineage(basis, result, &store.authority, None)
}

/// Records `basis` and `result` in a fresh lineage and classifies the pair bound to it.
fn bound_delta(
    basis: &crate::ReferenceSituationPublication,
    result: &crate::ReferenceSituationPublication,
) -> Result<fss_core::MeaningfulDelta, Box<dyn Error>> {
    let store = recorded(&[basis, result])?;
    let delta = bound(&store, basis, result);
    store.cleanup();
    Ok(delta?)
}

/// fss-mnlz1 M4: without the durable stores the plain classifier reports exactly the changes the
/// lineage-bound classifier reports, minus the terminal transition: never an error, never silence.
#[test]
fn plain_classify_reports_terminal_changes_as_non_terminal() -> Result<(), Box<dyn Error>> {
    let obligation = ObligationId::parse("obligation:meaningful-delta")?;
    let mut basis_variant = Variant::baseline()?;
    basis_variant.effect_state = Some(KnowledgeState::Indeterminate);
    basis_variant.obligations = vec![obligation];
    let basis = publication(&basis_variant)?;
    let mut result_variant = basis_variant.clone();
    result_variant.sequence = 2;
    result_variant.effect_state = Some(KnowledgeState::Known);
    result_variant.obligations.clear();
    let result = successor_of(&basis, &result_variant)?;
    let bound_classes = bound_delta(&basis, &result)?.classes;
    assert!(
        bound_classes.contains(&MeaningfulDeltaClass::TerminalTransition),
        "{bound_classes:?}"
    );
    let plain = classify_reference_meaningful_delta(&basis, &result)?;
    let mut expected = bound_classes.clone();
    expected.remove(&MeaningfulDeltaClass::TerminalTransition);
    assert_eq!(plain.classes, expected);
    assert!(plain.silence_certificate.is_none());
    assert!(plain.classes.contains(&MeaningfulDeltaClass::Obligation));
    plain.validate()?;
    Ok(())
}

/// The obligation the fixture journal discharges.
const DISCHARGED: &str = "obligation:meaningful-delta";

/// An effect intent of the fixture journal.
fn fixture_intent(name: &str) -> Result<fss_core::EffectIntent, Box<dyn Error>> {
    Ok(fss_core::EffectIntent {
        operation_id: fss_core::OperationId::parse(format!("operation:meaningful-delta:{name}"))?,
        idempotency_key: fss_core::IdempotencyKey::parse(format!(
            "idempotency:meaningful-delta:{name}"
        ))?,
        effect_class: "alert.dispatch".to_owned(),
        request_digest: ContentDigest::sha256(b"meaningful-delta-request"),
        precondition_digest: ContentDigest::sha256(b"meaningful-delta-preconditions"),
    })
}

/// A durable effect journal under a fresh temporary path holding [`DISCHARGED`]'s history, then an
/// unrelated obligation, with the root after each committed record (fss-mnlz1 N1 and N3).
struct FixtureJournal {
    journal: crate::DurableEffectJournal,
    path: std::path::PathBuf,
    /// Roots after [`DISCHARGED`] is prepared (0, pending), committed (1, pending), marked
    /// indeterminate (2), and reconciled as failed (3, terminal), then after the unrelated
    /// obligation is prepared (4).
    roots: Vec<ContentDigest>,
}

impl FixtureJournal {
    fn new(name: &str) -> Result<Self, Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!(
            "fss-reference-delta-journal-{}-{name}.journal",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut journal =
            crate::DurableEffectJournal::open(&path, fss_ledger::IncompleteTailPolicy::Reject)?;
        let intent = fixture_intent("discharged")?;
        let operation = intent.operation_id.clone();
        let mut roots = Vec::new();
        let _ = journal.prepare(
            intent,
            ObligationId::parse(DISCHARGED)?,
            "the alert reaches a terminal outcome",
            TimestampNs(10),
        )?;
        roots.push(journal.last_root());
        let _ = journal.transition(
            &operation,
            fss_core::EffectState::Committed,
            TimestampNs(11),
            None,
            None,
        )?;
        roots.push(journal.last_root());
        let _ = journal.mark_indeterminate(&operation, TimestampNs(12), "acknowledgement lost")?;
        roots.push(journal.last_root());
        let _ = journal.reconcile_failed(
            &operation,
            ContentDigest::sha256(b"meaningful-delta-failure"),
            TimestampNs(13),
            "provider refused",
        )?;
        roots.push(journal.last_root());
        let _ = journal.prepare(
            fixture_intent("unrelated")?,
            ObligationId::parse("obligation:meaningful-delta:unrelated")?,
            "the unrelated alert reaches a terminal outcome",
            TimestampNs(14),
        )?;
        roots.push(journal.last_root());
        Ok(Self {
            journal,
            path,
            roots,
        })
    }

    /// The root after committed record `index`.
    fn root(&self, index: usize) -> Result<ContentDigest, Box<dyn Error>> {
        Ok(*self
            .roots
            .get(index)
            .ok_or(crate::ReferenceError::InvalidSpec("fixture_journal_root"))?)
    }

    /// Removes the journal file.
    fn cleanup(self) {
        let path = self.path.clone();
        drop(self);
        let _ = std::fs::remove_file(path);
    }
}

/// The basis holds `basis_obligation` and seals `basis_root`; its recorded successor drops it and
/// seals `result_root`. Classifies the pair bound to the fixture authority and `journal`.
fn discharge_delta(
    journal: &crate::DurableEffectJournal,
    basis_obligation: &str,
    basis_root: Option<ContentDigest>,
    result_root: Option<ContentDigest>,
) -> Result<Result<fss_core::MeaningfulDelta, crate::ReferenceError>, Box<dyn Error>> {
    let mut basis_variant = Variant::baseline()?;
    basis_variant.obligations = vec![ObligationId::parse(basis_obligation)?];
    basis_variant.journal_root = basis_root;
    let basis = publication(&basis_variant)?;
    let mut result_variant = Variant::baseline()?;
    result_variant.sequence = 2;
    result_variant.journal_root = result_root;
    let result = successor_of(&basis, &result_variant)?;
    let store = recorded(&[&basis, &result])?;
    let delta = classify_reference_meaningful_delta_in_lineage(
        &basis,
        &result,
        &store.authority,
        Some(journal),
    );
    store.cleanup();
    Ok(delta)
}

fn discharged_terminally(delta: &fss_core::MeaningfulDelta) -> bool {
    delta
        .classes
        .contains(&MeaningfulDeltaClass::TerminalTransition)
}

/// fss-mnlz1 N3: a discharge sealed at roots the journal has since moved past stays terminal, since
/// its committed history still holds them. A result root outside the history, or none, is reported
/// but never refused and never terminal.
#[test]
fn a_discharge_is_checked_against_a_prefix_of_the_journal_history() -> Result<(), Box<dyn Error>> {
    let fixture = FixtureJournal::new("n3-prefix")?;
    assert_ne!(fixture.root(3)?, fixture.journal.last_root());
    let delta = discharge_delta(
        &fixture.journal,
        DISCHARGED,
        Some(fixture.root(0)?),
        Some(fixture.root(3)?),
    )??;
    assert!(discharged_terminally(&delta), "{:?}", delta.classes);
    assert!(delta.classes.contains(&MeaningfulDeltaClass::Obligation));
    delta.validate()?;
    for result_root in [Some(ContentDigest::sha256(b"another-journal-root")), None] {
        let delta = discharge_delta(
            &fixture.journal,
            DISCHARGED,
            Some(fixture.root(0)?),
            result_root,
        )??;
        assert!(
            !discharged_terminally(&delta),
            "{result_root:?}: {:?}",
            delta.classes
        );
        assert!(
            delta.classes.contains(&MeaningfulDeltaClass::Obligation),
            "{result_root:?}: {:?}",
            delta.classes
        );
        delta.validate()?;
    }
    fixture.cleanup();
    Ok(())
}

/// fss-mnlz1 N1: the result's sealed root must not precede the basis's in the journal history. A
/// result sealed at the failed root, after a basis sealed later, is reported but never terminal,
/// although the obligation is terminal at the result's root.
#[test]
fn a_result_sealed_before_its_basis_never_discharges() -> Result<(), Box<dyn Error>> {
    let fixture = FixtureJournal::new("n1-order")?;
    let delta = discharge_delta(
        &fixture.journal,
        DISCHARGED,
        Some(fixture.root(4)?),
        Some(fixture.root(3)?),
    )??;
    assert!(!discharged_terminally(&delta), "{:?}", delta.classes);
    assert!(delta.classes.contains(&MeaningfulDeltaClass::Obligation));
    delta.validate()?;
    fixture.cleanup();
    Ok(())
}

/// fss-mnlz1 N1: a dropped obligation the journal never recorded is refused, never taken as
/// discharged.
#[test]
fn discharging_an_obligation_the_journal_never_recorded_is_refused() -> Result<(), Box<dyn Error>> {
    let fixture = FixtureJournal::new("n1-unknown")?;
    let delta = discharge_delta(
        &fixture.journal,
        "obligation:meaningful-delta:never-recorded",
        Some(fixture.root(0)?),
        Some(fixture.root(3)?),
    )?;
    assert!(
        matches!(
            delta,
            Err(crate::ReferenceError::InvalidSpec(
                "meaningful_delta_obligation_unknown_to_journal"
            ))
        ),
        "{:?}",
        delta.map(|delta| delta.classes)
    );
    fixture.cleanup();
    Ok(())
}

/// fss-mnlz1 N1: a discharge is judged as the journal stood at the result's sealed root, so later
/// history never launders it. The obligation is pending at root 1 and indeterminate at root 2, both
/// refused as still open, although the journal has since reconciled it as failed.
#[test]
fn a_discharge_is_judged_as_the_journal_stood_at_the_results_root() -> Result<(), Box<dyn Error>> {
    let fixture = FixtureJournal::new("n1-as-of")?;
    for index in [1, 2] {
        let delta = discharge_delta(
            &fixture.journal,
            DISCHARGED,
            Some(fixture.root(0)?),
            Some(fixture.root(index)?),
        )?;
        assert!(
            matches!(
                delta,
                Err(crate::ReferenceError::InvalidSpec(
                    "meaningful_delta_obligation_still_open"
                ))
            ),
            "root {index}: {:?}",
            delta.map(|delta| delta.classes)
        );
    }
    fixture.cleanup();
    Ok(())
}

#[test]
fn compute_meaningful_delta_refuses_evidence_laundering_between_basis_and_result()
-> Result<(), Box<dyn Error>> {
    let shared_evidence = ContentDigest::sha256(b"counterfactual_prediction_evidence_001");

    let mut v1 = Variant::baseline()?;
    v1.sequence = 1;
    v1.extra_cells.push(KnowledgeCell {
        claim_id: "claim:fire:predicted_spread".to_owned(),
        statement: "Model predicts fire expansion".to_owned(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Predicted,
        hypothesis: None,
        evidence: vec![shared_evidence],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    });
    let first = publication(&v1)?;

    let mut v2 = Variant::baseline()?;
    v2.sequence = 2;
    v2.predecessor = Some(first.publication_digest);
    v2.extra_cells.push(KnowledgeCell {
        claim_id: "claim:fire:observed_spread".to_owned(),
        statement: "Physical observation of fire expansion".to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![shared_evidence],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    });
    let second = publication(&v2)?;

    let res = classify_reference_meaningful_delta(&first, &second);
    assert!(
        matches!(
            res,
            Err(crate::ReferenceError::Contract(
                fss_core::ContractError::EvidenceLaunderingDetected
            ))
        ),
        "classify_reference_meaningful_delta must refuse laundering predicted evidence into observed across frames: {res:?}"
    );

    Ok(())
}
