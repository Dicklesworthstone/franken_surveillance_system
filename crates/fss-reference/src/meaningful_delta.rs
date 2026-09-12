//! Deterministic decision-impact comparison for complete reference situation publications.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    ActionAffordance, AffordanceClass, CanonicalEncode, CanonicalEncoder, Completeness,
    ContentDigest, ContractError, DeltaPriority, HypothesisDisposition, KnowledgeCell,
    KnowledgeState, MeaningfulDelta, MeaningfulDeltaClass, ResourcePressure, SilenceCertificate,
    TimestampNs, WorldEnvelope,
};

use crate::{ReferenceError, ReferenceSituationPublication};

/// Returns whether a premise that a plan relied on at `prior` is invalidated by its `current`
/// knowledge state (registries/AGENT_CONTRACTS.md, "Knowledge states").
///
/// Only `KSTATE-001` `known` may authorize an irreversible effect, so every transition from `Known`
/// to any other state leaves the premise unable to carry the decision it supported. The match is
/// exhaustive so a new state must be classified here rather than silently passing.
const fn premise_state_invalidated(prior: KnowledgeState, current: KnowledgeState) -> bool {
    match current {
        // KSTATE-001: still established for the anchor; only new contradictions (checked by the
        // caller) can invalidate it.
        KnowledgeState::Known => false,
        // KSTATE-002: may plan but may not authorize an irreversible effect and needs explicit
        // assumptions, so Known->Estimated is a downgrade; Estimated->Estimated is unchanged.
        KnowledgeState::Estimated => matches!(prior, KnowledgeState::Known),
        // KSTATE-003: the evidence no longer establishes the proposition; open branch only.
        KnowledgeState::Unknown
        // KSTATE-004: incompatible admissible evidence; competing branches only.
        | KnowledgeState::Conflicted
        // KSTATE-005: valid only at an older anchor; revalidation candidate only.
        | KnowledgeState::Stale
        // KSTATE-006: the domain could not have established it; protected residual only.
        | KnowledgeState::NotObservable
        // KSTATE-008: a consequential outcome is unproved; reconciliation branches only.
        | KnowledgeState::Indeterminate
        // KSTATE-007: withheld by the current privacy/capability projection; the plan may use it
        // only through non-leaking abstract constraints and it can never authorize an
        // irreversible effect, so a premise that became redacted is invalidated (fss-2kntt).
        | KnowledgeState::Redacted
        // KSTATE-009: the proposition has no meaning for the object, scope, or lifecycle state;
        // it may not even support planning, so the premise is invalidated a fortiori. It is not
        // a coverage gap, which is why the degraded-cell list below excludes it.
        | KnowledgeState::NotApplicable => true,
    }
}

/// What the result frame says about an effect cell that the basis carried as `KSTATE-008`
/// `indeterminate` (registries/AGENT_CONTRACTS.md, "Knowledge states").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IndeterminateEffectSuccessor {
    /// A retained terminal outcome resolved the effect uncertainty.
    Resolved,
    /// The consequential outcome is still unproved. `coverage_gap` additionally reports the cell
    /// as lost coverage because its new state withholds or fails to establish the outcome.
    Unresolved { coverage_gap: bool },
}

/// Classifies the result cell of an effect that was `Indeterminate` in the basis, at the result
/// capsule's time `now`.
///
/// Only a cell that clears the full irreversible-effect premise bar resolves the uncertainty:
/// `KnowledgeCell::is_irreversible_effect_premise` requires `KSTATE-001` `known`, a valid state
/// basis, retained evidence roots, no contradicting roots, and a validity window still open at
/// `now`. Every other state leaves the outcome unproved, so it is never flattened into a resolution
/// or a terminal transition. The match is exhaustive so a new state must be classified here rather
/// than silently resolving.
fn indeterminate_effect_successor(
    current: &KnowledgeCell,
    now: TimestampNs,
) -> IndeterminateEffectSuccessor {
    let unresolved_gap = IndeterminateEffectSuccessor::Unresolved { coverage_gap: true };
    let unresolved = IndeterminateEffectSuccessor::Unresolved {
        coverage_gap: false,
    };
    match current.knowledge_state {
        // KSTATE-001: resolved only by a proved terminal outcome; a `known` claim without evidence
        // roots, with contradicting roots, with an invalid state basis, or whose validity window has
        // already closed does not establish what happened.
        KnowledgeState::Known => {
            if current.is_irreversible_effect_premise(now) {
                IndeterminateEffectSuccessor::Resolved
            } else {
                unresolved_gap
            }
        }
        // KSTATE-002: an estimate of the outcome is not proof; still unresolved, but the estimate
        // is explicit uncertainty rather than a coverage gap.
        KnowledgeState::Estimated => unresolved,
        // KSTATE-003: the evidence does not establish the outcome; unresolved and a gap.
        KnowledgeState::Unknown => unresolved_gap,
        // KSTATE-004: incompatible evidence about the outcome; unresolved and a gap.
        KnowledgeState::Conflicted => unresolved_gap,
        // KSTATE-005: only an older anchor spoke to the outcome; unresolved and a gap.
        KnowledgeState::Stale => unresolved_gap,
        // KSTATE-006: the domain could not have established the outcome; unresolved and a gap.
        KnowledgeState::NotObservable => unresolved_gap,
        // KSTATE-007: the outcome is withheld by the projection, not proved; unresolved and a gap.
        KnowledgeState::Redacted => unresolved_gap,
        // KSTATE-008: still indeterminate (not reached from the set difference, kept exhaustive).
        KnowledgeState::Indeterminate => unresolved_gap,
        // KSTATE-009: says the proposition has no meaning in scope, which neither proves nor
        // negates an outcome that may already have happened; unresolved, but not a coverage gap.
        KnowledgeState::NotApplicable => unresolved,
    }
}

/// Classifies every decision-relevant change between two exact reference publications.
///
/// Terminal transitions, coverage loss, contradictions, plan invalidation, obligation changes,
/// new effect uncertainty, and authority changes are emitted as non-coalescible critical deltas.
/// Optional presentation detail and harmless anchor advancement are never substituted for typed
/// mission-state change.
pub fn classify_reference_meaningful_delta(
    basis: &ReferenceSituationPublication,
    result: &ReferenceSituationPublication,
) -> Result<MeaningfulDelta, ReferenceError> {
    basis.verify()?;
    result.verify()?;
    validate_comparison_basis(basis, result)?;

    let basis_capsule = &basis.situation.capsule;
    let result_capsule = &result.situation.capsule;
    let basis_frame = &basis_capsule.frame;
    let result_frame = &result_capsule.frame;
    let mut classes = BTreeSet::new();
    let changed_cells = changed_cells(&basis_frame.knowledge_cells, &result_frame.knowledge_cells);
    let mut invalidated_assumptions = Vec::new();
    let mut coverage_changes = Vec::new();
    let mut obligation_changes = Vec::new();
    let mut effect_uncertainty_changes = Vec::new();

    if basis_frame.now != result_frame.now
        || basis_frame.at_risk != result_frame.at_risk
        || basis_frame.unknown != result_frame.unknown
        || world_semantic_digest(&basis_frame.world_envelope)
            != world_semantic_digest(&result_frame.world_envelope)
        || affordance_frontier_digest(&basis_capsule.affordances)
            != affordance_frontier_digest(&result_capsule.affordances)
    {
        classes.insert(MeaningfulDeltaClass::MaterialState);
    }

    if changed_cells.iter().any(|cell| {
        let prior = basis_frame
            .knowledge_cells
            .iter()
            .find(|candidate| candidate.claim_id == cell.claim_id);
        prior.is_none_or(|prior| {
            prior.hypothesis != cell.hypothesis || prior.knowledge_state != cell.knowledge_state
        })
    }) {
        classes.insert(MeaningfulDeltaClass::Hypothesis);
    }
    if !changed_cells.is_empty() {
        classes.insert(MeaningfulDeltaClass::MaterialState);
    }
    if contradiction_changed(
        &basis_frame.knowledge_cells,
        &result_frame.knowledge_cells,
        &changed_cells,
    ) {
        classes.insert(MeaningfulDeltaClass::Contradiction);
    }

    let basis_coverage = &basis_frame.world_envelope.coverage_boundary_handles;
    let result_coverage = &result_frame.world_envelope.coverage_boundary_handles;
    for lost in basis_coverage.difference(result_coverage) {
        coverage_changes.push(format!("coverage handle lost: {lost}"));
    }
    for recovered in result_coverage.difference(basis_coverage) {
        coverage_changes.push(format!("coverage handle recovered: {recovered}"));
    }
    let basis_completeness = completeness_rank(basis_capsule.completeness);
    let result_completeness = completeness_rank(result_capsule.completeness);
    if !basis_coverage.is_subset(result_coverage) || result_completeness > basis_completeness {
        classes.insert(MeaningfulDeltaClass::CoverageLoss);
        if result_completeness > basis_completeness {
            coverage_changes.push(format!(
                "situation completeness degraded from {:?} to {:?}",
                basis_capsule.completeness, result_capsule.completeness
            ));
        }
    } else if result_completeness == basis_completeness
        && result_capsule.completeness != Completeness::Complete
    {
        classes.insert(MeaningfulDeltaClass::CoverageLoss);
        coverage_changes.push(format!(
            "situation completeness remains degraded at {:?}",
            result_capsule.completeness
        ));
    }
    if !result_coverage.is_subset(basis_coverage) || result_completeness < basis_completeness {
        classes.insert(MeaningfulDeltaClass::CoverageRecovery);
        if result_completeness < basis_completeness {
            coverage_changes.push(format!(
                "situation completeness improved from {:?} to {:?}",
                basis_capsule.completeness, result_capsule.completeness
            ));
        }
    }
    if result_coverage.is_empty() {
        classes.insert(MeaningfulDeltaClass::CoverageLoss);
        coverage_changes
            .push("result situation has no active coverage boundary handles".to_owned());
    }

    let result_actionable: BTreeSet<_> = result_capsule
        .affordances
        .iter()
        .filter(|affordance| {
            !matches!(
                affordance.class,
                AffordanceClass::Blocked | AffordanceClass::Unavailable
            )
        })
        .map(|affordance| affordance.affordance_id.as_str())
        .collect();
    for prior in &basis_frame.next {
        if !result_actionable.contains(prior.as_str())
            || !result_frame.next.iter().any(|current| current == prior)
        {
            invalidated_assumptions.push(format!(
                "previous next affordance {prior} is no longer actionable"
            ));
        }
    }
    for prior in &basis_frame.knowledge_cells {
        if !matches!(
            prior.knowledge_state,
            KnowledgeState::Known | KnowledgeState::Estimated
        ) {
            continue;
        }
        let state_label = prior.knowledge_state.as_str();
        match result_frame
            .knowledge_cells
            .iter()
            .find(|candidate| candidate.claim_id == prior.claim_id)
        {
            Some(current)
                if premise_state_invalidated(prior.knowledge_state, current.knowledge_state)
                    || (prior.contradictions != current.contradictions
                        && !current.contradictions.is_empty()) =>
            {
                if prior.knowledge_state != current.knowledge_state {
                    invalidated_assumptions.push(format!(
                        "{state_label} premise {} became {}",
                        prior.claim_id,
                        current.knowledge_state.as_str()
                    ));
                } else {
                    invalidated_assumptions.push(format!(
                        "{state_label} premise {} gained contradictory evidence",
                        prior.claim_id
                    ));
                }
            }
            None => invalidated_assumptions.push(format!(
                "{state_label} premise {} disappeared from the result frame",
                prior.claim_id
            )),
            Some(_) => {}
        }
    }
    if !invalidated_assumptions.is_empty() {
        classes.insert(MeaningfulDeltaClass::PlanInvalidation);
    }

    let basis_obligations: BTreeSet<_> = basis_capsule.obligations.iter().collect();
    let result_obligations: BTreeSet<_> = result_capsule.obligations.iter().collect();
    for added in result_obligations.difference(&basis_obligations) {
        obligation_changes.push(format!("obligation added: {added}"));
    }
    for removed in basis_obligations.difference(&result_obligations) {
        obligation_changes.push(format!("obligation removed: {removed}"));
    }
    if !obligation_changes.is_empty() {
        classes.insert(MeaningfulDeltaClass::Obligation);
    }

    let basis_indeterminate = indeterminate_effect_claims(&basis_frame.knowledge_cells);
    let result_indeterminate = indeterminate_effect_claims(&result_frame.knowledge_cells);
    for added in result_indeterminate.difference(&basis_indeterminate) {
        effect_uncertainty_changes.push(format!("effect uncertainty added: {added}"));
    }
    let mut effect_resolved = false;
    for claim_id in basis_indeterminate.difference(&result_indeterminate) {
        match result_frame
            .knowledge_cells
            .iter()
            .find(|candidate| candidate.claim_id == *claim_id)
        {
            Some(current) => {
                match indeterminate_effect_successor(current, result_capsule.created_at) {
                    IndeterminateEffectSuccessor::Resolved => {
                        effect_resolved = true;
                        effect_uncertainty_changes.push(format!(
                        "effect uncertainty resolved: {claim_id} became known with retained outcome evidence"
                    ));
                    }
                    IndeterminateEffectSuccessor::Unresolved { coverage_gap } => {
                        let state = current.knowledge_state.as_str();
                        effect_uncertainty_changes.push(format!(
                        "effect uncertainty remains: indeterminate effect {claim_id} became {state} without a proved outcome"
                    ));
                        if coverage_gap {
                            classes.insert(MeaningfulDeltaClass::CoverageLoss);
                            coverage_changes.push(format!(
                                "unproved effect {claim_id} degraded from indeterminate to {state}"
                            ));
                        }
                    }
                }
            }
            None => {
                effect_uncertainty_changes.push(format!(
                    "effect uncertainty remains: indeterminate effect {claim_id} disappeared from the result frame without a proved outcome"
                ));
                classes.insert(MeaningfulDeltaClass::CoverageLoss);
                coverage_changes.push(format!(
                    "unproved effect {claim_id} disappeared from the result frame while indeterminate"
                ));
            }
        }
    }
    if !effect_uncertainty_changes.is_empty() {
        classes.insert(MeaningfulDeltaClass::EffectUncertainty);
    }

    let obligation_terminalized = basis_obligations
        .difference(&result_obligations)
        .next()
        .is_some()
        || result_frame.knowledge_cells.iter().any(|cell| {
            cell.claim_id.starts_with("claim:obligation:")
                && (cell.knowledge_state == KnowledgeState::Known
                    || matches!(
                        cell.hypothesis,
                        Some(
                            HypothesisDisposition::Refuted
                                | HypothesisDisposition::Resolved
                                | HypothesisDisposition::Superseded
                        )
                    ))
                && basis_frame
                    .knowledge_cells
                    .iter()
                    .find(|b| b.claim_id == cell.claim_id)
                    .is_none_or(|b| {
                        b.knowledge_state != KnowledgeState::Known
                            && !matches!(
                                b.hypothesis,
                                Some(
                                    HypothesisDisposition::Refuted
                                        | HypothesisDisposition::Resolved
                                        | HypothesisDisposition::Superseded
                                )
                            )
                    })
        });
    // A basis-indeterminate effect is terminal only when it resolved above; its other successors
    // are classified there and must not be re-read as terminal here.
    let effect_terminalized = effect_resolved
        || result_frame.knowledge_cells.iter().any(|cell| {
            cell.claim_id.starts_with("claim:effect:")
                && !basis_indeterminate.contains(cell.claim_id.as_str())
                && (cell.knowledge_state == KnowledgeState::Known
                    || matches!(
                        cell.hypothesis,
                        Some(
                            HypothesisDisposition::Refuted
                                | HypothesisDisposition::Resolved
                                | HypothesisDisposition::Superseded
                        )
                    ))
                && basis_frame
                    .knowledge_cells
                    .iter()
                    .find(|b| b.claim_id == cell.claim_id)
                    .is_none_or(|b| {
                        b.knowledge_state != KnowledgeState::Known
                            && !matches!(
                                b.hypothesis,
                                Some(
                                    HypothesisDisposition::Refuted
                                        | HypothesisDisposition::Resolved
                                        | HypothesisDisposition::Superseded
                                )
                            )
                    })
        });
    // A basis-indeterminate effect is terminal only through the resolution classified above, so a
    // terminal hypothesis disposition on its unresolved successor never terminalizes it here.
    let event_terminalized = result_frame.knowledge_cells.iter().any(|cell| {
        if basis_indeterminate.contains(cell.claim_id.as_str()) {
            return false;
        }
        let is_terminal_hypothesis = matches!(
            cell.hypothesis,
            Some(
                HypothesisDisposition::Refuted
                    | HypothesisDisposition::Resolved
                    | HypothesisDisposition::Superseded
            )
        );
        is_terminal_hypothesis
            && basis_frame
                .knowledge_cells
                .iter()
                .find(|b| b.claim_id == cell.claim_id)
                .is_none_or(|b| {
                    !matches!(
                        b.hypothesis,
                        Some(
                            HypothesisDisposition::Refuted
                                | HypothesisDisposition::Resolved
                                | HypothesisDisposition::Superseded
                        )
                    )
                })
    });
    let mission_terminalized = match (basis_capsule.mission_state, result_capsule.mission_state) {
        (Some(basis_state), Some(result_state)) => {
            !basis_state.is_terminal() && result_state.is_terminal()
        }
        (None, Some(result_state)) => result_state.is_terminal(),
        _ => false,
    } || result_frame.knowledge_cells.iter().any(|cell| {
        cell.claim_id.starts_with("claim:mission:")
            && (matches!(
                cell.hypothesis,
                Some(
                    HypothesisDisposition::Refuted
                        | HypothesisDisposition::Resolved
                        | HypothesisDisposition::Superseded
                )
            ) || cell.knowledge_state == KnowledgeState::Known)
            && basis_frame
                .knowledge_cells
                .iter()
                .find(|b| b.claim_id == cell.claim_id)
                .is_none_or(|b| {
                    !matches!(
                        b.hypothesis,
                        Some(
                            HypothesisDisposition::Refuted
                                | HypothesisDisposition::Resolved
                                | HypothesisDisposition::Superseded
                        )
                    ) && b.knowledge_state != KnowledgeState::Known
                })
    });

    if obligation_terminalized || effect_terminalized || event_terminalized || mission_terminalized
    {
        classes.insert(MeaningfulDeltaClass::TerminalTransition);
    }

    if basis_capsule.contract_basis != result_capsule.contract_basis
        || authority_generation_changed(&basis_capsule.anchor, &result_capsule.anchor)
    {
        classes.insert(MeaningfulDeltaClass::PolicyOrAuthority);
    }
    if basis.resource_state != result.resource_state
        || result.resource_state.pressure != ResourcePressure::Nominal
        || !result.resource_state.degraded_dimensions.is_empty()
    {
        classes.insert(MeaningfulDeltaClass::BudgetPressure);
    }

    sort_dedup(&mut invalidated_assumptions);
    sort_dedup(&mut coverage_changes);
    sort_dedup(&mut obligation_changes);
    sort_dedup(&mut effect_uncertainty_changes);

    let missing_coverage: Vec<String> = basis_coverage
        .difference(result_coverage)
        .cloned()
        .collect();
    let degraded_epistemic_cells: Vec<String> = result_frame
        .knowledge_cells
        .iter()
        .filter(|cell| {
            // Every state that leaves the proposition unestablished or withheld for this decision
            // is degraded. `Known` is established, `Estimated` carries explicit uncertainty and
            // its Known->Estimated drop is reported as an invalidated premise above, and
            // `NotApplicable` asserts the proposition has no meaning in scope rather than a gap.
            matches!(
                cell.knowledge_state,
                KnowledgeState::NotObservable
                    | KnowledgeState::Conflicted
                    | KnowledgeState::Stale
                    | KnowledgeState::Indeterminate
                    | KnowledgeState::Unknown
                    | KnowledgeState::Redacted
            )
        })
        .map(|cell| cell.claim_id.clone())
        .collect();
    let generation_mismatch = basis_capsule.contract_basis.ontology_generation_id
        != result_capsule.contract_basis.ontology_generation_id;
    let stale_revision = result_capsule.revision < basis_capsule.revision;
    let has_active_coverage_gap = result_capsule.completeness != Completeness::Complete
        || result_coverage.is_empty()
        || !missing_coverage.is_empty()
        || !degraded_epistemic_cells.is_empty()
        || generation_mismatch
        || stale_revision;
    if has_active_coverage_gap {
        classes.insert(MeaningfulDeltaClass::CoverageLoss);
        if result_capsule.completeness != Completeness::Complete {
            coverage_changes.push(format!(
                "situation coverage is incomplete: completeness={:?}",
                result_capsule.completeness
            ));
        }
        if result_coverage.is_empty() {
            coverage_changes.push("situation coverage domain is empty".to_owned());
        }
        if !missing_coverage.is_empty() {
            coverage_changes.push(format!(
                "missing coverage for authorized domain identities: {:?}",
                missing_coverage
            ));
        }
        if !degraded_epistemic_cells.is_empty() {
            coverage_changes.push(format!(
                "epistemic cell degraded for claim identities: {:?}",
                degraded_epistemic_cells
            ));
        }
        if generation_mismatch {
            coverage_changes.push(format!(
                "generation mismatch: basis ontology generation '{}' != result ontology generation '{}'",
                basis_capsule.contract_basis.ontology_generation_id,
                result_capsule.contract_basis.ontology_generation_id
            ));
        }
        if stale_revision {
            coverage_changes.push(format!(
                "stale capsule revision: result revision {} < basis revision {}",
                result_capsule.revision, basis_capsule.revision
            ));
        }
        sort_dedup(&mut coverage_changes);
    }
    let is_silence = classes.is_empty()
        && !has_active_coverage_gap
        && result.resource_state.pressure == ResourcePressure::Nominal
        && result.resource_state.degraded_dimensions.is_empty();
    if is_silence {
        classes.insert(MeaningfulDeltaClass::NoMeaningfulChange);
    }
    let selection_witness = comparison_witness(ComparisonWitnessInputs {
        basis,
        result,
        classes: &classes,
        changed_cells: &changed_cells,
        invalidated_assumptions: &invalidated_assumptions,
        coverage_changes: &coverage_changes,
        obligation_changes: &obligation_changes,
        effect_uncertainty_changes: &effect_uncertainty_changes,
    });
    let identity = delta_identity(basis, result, selection_witness);
    let silence_certificate = if is_silence {
        Some(SilenceCertificate {
            basis_frame_digest: basis_frame.frame_digest(),
            result_frame_digest: result_frame.frame_digest(),
            selection_witness,
            authorized_domain: result_coverage.clone(),
            authorized_generation: result_capsule.contract_basis.ontology_generation_id.clone(),
            reason: "the complete typed comparison found no decision-relevant change".to_owned(),
        })
    } else {
        None
    };
    let priority = delta_priority(&classes);
    let delta = MeaningfulDelta {
        delta_id: format!("meaningful-delta:{identity}"),
        contract_basis: result_capsule.contract_basis.clone(),
        session_id: result_capsule.session_id.clone(),
        basis_frame_id: basis_frame.frame_id.clone(),
        result_frame_id: result_frame.frame_id.clone(),
        basis_anchor: basis_capsule.anchor.clone(),
        result_anchor: result_capsule.anchor.clone(),
        classes,
        changed_cells,
        invalidated_assumptions,
        coverage_changes,
        obligation_changes,
        effect_uncertainty_changes,
        coalesced_count: 0,
        omitted_count: 0,
        omission_reasons: Vec::new(),
        priority,
        continuation: format!("continuation:meaningful-delta:{identity}"),
        selection_witness,
        silence_certificate,
    };
    delta.validate()?;
    Ok(delta)
}

fn validate_comparison_basis(
    basis: &ReferenceSituationPublication,
    result: &ReferenceSituationPublication,
) -> Result<(), ReferenceError> {
    let basis_capsule = &basis.situation.capsule;
    let result_capsule = &result.situation.capsule;
    if basis_capsule.mission_id != result_capsule.mission_id
        || basis_capsule.session_id != result_capsule.session_id
        || basis_capsule.principal_id != result_capsule.principal_id
        || basis_capsule.anchor.site_lineage != result_capsule.anchor.site_lineage
        || basis_capsule.anchor.ledger_epoch != result_capsule.anchor.ledger_epoch
        || result_capsule.anchor.commit_sequence < basis_capsule.anchor.commit_sequence
        || (result_capsule.anchor.commit_sequence == basis_capsule.anchor.commit_sequence
            && result_capsule.anchor != basis_capsule.anchor)
    {
        return Err(ContractError::InvalidAnchorSuccessor.into());
    }
    Ok(())
}

fn changed_cells(basis: &[KnowledgeCell], result: &[KnowledgeCell]) -> Vec<KnowledgeCell> {
    let prior: BTreeMap<_, _> = basis
        .iter()
        .map(|cell| (cell.claim_id.as_str(), cell.cell_digest()))
        .collect();
    let mut changed: Vec<_> = result
        .iter()
        .filter(|cell| prior.get(cell.claim_id.as_str()) != Some(&cell.cell_digest()))
        .cloned()
        .collect();
    changed.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
    changed
}

fn contradiction_changed(
    basis: &[KnowledgeCell],
    result: &[KnowledgeCell],
    changed: &[KnowledgeCell],
) -> bool {
    if changed.iter().any(|cell| {
        cell.knowledge_state == KnowledgeState::Conflicted || !cell.contradictions.is_empty()
    }) {
        return true;
    }
    basis.iter().any(|prior| {
        result
            .iter()
            .find(|current| current.claim_id == prior.claim_id)
            .is_some_and(|current| prior.contradictions != current.contradictions)
    })
}

fn indeterminate_effect_claims(cells: &[KnowledgeCell]) -> BTreeSet<&str> {
    cells
        .iter()
        .filter(|cell| {
            cell.claim_id.starts_with("claim:effect:")
                && cell.knowledge_state == KnowledgeState::Indeterminate
        })
        .map(|cell| cell.claim_id.as_str())
        .collect()
}

fn authority_generation_changed(
    basis: &fss_core::LedgerAnchor,
    result: &fss_core::LedgerAnchor,
) -> bool {
    basis.ledger_epoch != result.ledger_epoch
        || basis.adapter_registry_epoch != result.adapter_registry_epoch
        || basis.schema_epoch != result.schema_epoch
        || basis.policy_epoch != result.policy_epoch
        || basis.privacy_epoch != result.privacy_epoch
}

fn completeness_rank(value: Completeness) -> u8 {
    match value {
        Completeness::Complete => 0,
        Completeness::Bounded => 1,
        Completeness::Partial => 2,
        Completeness::Unknown => 3,
        Completeness::Stale => 4,
        Completeness::NotObservable => 5,
        Completeness::Unauthorized => 6,
    }
}

fn world_semantic_digest(envelope: &WorldEnvelope) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.reference_world_semantics.v1");
    encoder.text(&envelope.objective_id);
    encode_text_set(&envelope.nominal_claim_ids, &mut encoder);
    encode_text_set(&envelope.certified_core_claim_ids, &mut encoder);
    let mut alternatives = envelope.alternatives.clone();
    alternatives.sort_by(|left, right| left.world_id.cmp(&right.world_id));
    encoder.u64(alternatives.len() as u64);
    for world in &alternatives {
        world.encode_canonical(&mut encoder);
    }
    let mut residuals = envelope.adversarial_residuals.clone();
    residuals.sort_by(|left, right| left.world_id.cmp(&right.world_id));
    encoder.u64(residuals.len() as u64);
    for world in &residuals {
        world.encode_canonical(&mut encoder);
    }
    encode_text_set(&envelope.common_invariants, &mut encoder);
    encode_text_set(&envelope.coverage_boundary_handles, &mut encoder);
    ContentDigest::sha256(&encoder.finish())
}

fn affordance_frontier_digest(affordances: &[ActionAffordance]) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.reference_affordance_frontier.v1");
    let mut affordances = affordances.to_vec();
    affordances.sort_by(|left, right| left.affordance_id.cmp(&right.affordance_id));
    encoder.u64(affordances.len() as u64);
    for affordance in &affordances {
        affordance.encode_canonical(&mut encoder);
    }
    ContentDigest::sha256(&encoder.finish())
}

fn delta_priority(classes: &BTreeSet<MeaningfulDeltaClass>) -> DeltaPriority {
    if classes.contains(&MeaningfulDeltaClass::PolicyOrAuthority) {
        DeltaPriority::Constitutional
    } else if classes.iter().any(|class| class.is_non_coalescible()) {
        DeltaPriority::Critical
    } else if classes.iter().any(|class| {
        matches!(
            class,
            MeaningfulDeltaClass::MaterialState
                | MeaningfulDeltaClass::Hypothesis
                | MeaningfulDeltaClass::CoverageRecovery
                | MeaningfulDeltaClass::SensorHealth
        )
    }) {
        DeltaPriority::High
    } else if classes.contains(&MeaningfulDeltaClass::NoMeaningfulChange) {
        DeltaPriority::Low
    } else {
        DeltaPriority::Normal
    }
}

struct ComparisonWitnessInputs<'a> {
    basis: &'a ReferenceSituationPublication,
    result: &'a ReferenceSituationPublication,
    classes: &'a BTreeSet<MeaningfulDeltaClass>,
    changed_cells: &'a [KnowledgeCell],
    invalidated_assumptions: &'a [String],
    coverage_changes: &'a [String],
    obligation_changes: &'a [String],
    effect_uncertainty_changes: &'a [String],
}

fn comparison_witness(inputs: ComparisonWitnessInputs<'_>) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.reference_meaningful_delta_selection.v1");
    encoder.digest(inputs.basis.publication_digest);
    encoder.digest(inputs.result.publication_digest);
    encoder.u64(inputs.classes.len() as u64);
    for class in inputs.classes {
        class.encode_canonical(&mut encoder);
    }
    encoder.u64(inputs.changed_cells.len() as u64);
    for cell in inputs.changed_cells {
        encoder.digest(cell.cell_digest());
    }
    encode_text(inputs.invalidated_assumptions, &mut encoder);
    encode_text(inputs.coverage_changes, &mut encoder);
    encode_text(inputs.obligation_changes, &mut encoder);
    encode_text(inputs.effect_uncertainty_changes, &mut encoder);
    ContentDigest::sha256(&encoder.finish())
}

fn delta_identity(
    basis: &ReferenceSituationPublication,
    result: &ReferenceSituationPublication,
    selection_witness: ContentDigest,
) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.reference_meaningful_delta_identity.v1");
    encoder.digest(basis.publication_digest);
    encoder.digest(result.publication_digest);
    encoder.digest(selection_witness);
    ContentDigest::sha256(&encoder.finish())
}

fn encode_text_set(values: &BTreeSet<String>, encoder: &mut CanonicalEncoder) {
    encoder.u64(values.len() as u64);
    for value in values {
        encoder.text(value);
    }
}

fn encode_text(values: &[String], encoder: &mut CanonicalEncoder) {
    encoder.u64(values.len() as u64);
    for value in values {
        encoder.text(value);
    }
}

fn sort_dedup(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}
