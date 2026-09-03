//! Deterministic decision-impact comparison for complete reference situation publications.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    ActionAffordance, AffordanceClass, CanonicalEncode, CanonicalEncoder, Completeness,
    ContentDigest, ContractError, DeltaPriority, KnowledgeCell, KnowledgeState, MeaningfulDelta,
    MeaningfulDeltaClass, SilenceCertificate, WorldEnvelope,
};

use crate::{ReferenceError, ReferenceSituationPublication};

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
        if prior.knowledge_state != KnowledgeState::Known {
            continue;
        }
        match result_frame
            .knowledge_cells
            .iter()
            .find(|candidate| candidate.claim_id == prior.claim_id)
        {
            Some(current)
                if matches!(
                    current.knowledge_state,
                    KnowledgeState::Unknown
                        | KnowledgeState::Conflicted
                        | KnowledgeState::Stale
                        | KnowledgeState::NotObservable
                        | KnowledgeState::Indeterminate
                ) =>
            {
                invalidated_assumptions.push(format!(
                    "known premise {} became {}",
                    prior.claim_id,
                    current.knowledge_state.as_str()
                ));
            }
            None => invalidated_assumptions.push(format!(
                "known premise {} disappeared from the result frame",
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
    for resolved in basis_indeterminate.difference(&result_indeterminate) {
        effect_uncertainty_changes.push(format!("effect uncertainty resolved: {resolved}"));
    }
    if !effect_uncertainty_changes.is_empty() {
        classes.insert(MeaningfulDeltaClass::EffectUncertainty);
    }
    if basis_indeterminate.iter().any(|claim| {
        result_frame.knowledge_cells.iter().any(|cell| {
            cell.claim_id.as_str() == *claim && cell.knowledge_state == KnowledgeState::Known
        })
    }) {
        classes.insert(MeaningfulDeltaClass::TerminalTransition);
    }

    if basis_capsule.contract_basis != result_capsule.contract_basis
        || authority_generation_changed(&basis_capsule.anchor, &result_capsule.anchor)
    {
        classes.insert(MeaningfulDeltaClass::PolicyOrAuthority);
    }
    if basis.resource_state != result.resource_state {
        classes.insert(MeaningfulDeltaClass::BudgetPressure);
    }

    sort_dedup(&mut invalidated_assumptions);
    sort_dedup(&mut coverage_changes);
    sort_dedup(&mut obligation_changes);
    sort_dedup(&mut effect_uncertainty_changes);

    let is_silence = classes.is_empty();
    if is_silence {
        classes.insert(MeaningfulDeltaClass::NoMeaningfulChange);
    }
    let selection_witness = comparison_witness(
        basis,
        result,
        &classes,
        &changed_cells,
        &invalidated_assumptions,
        &coverage_changes,
        &obligation_changes,
        &effect_uncertainty_changes,
    );
    let identity = delta_identity(basis, result, selection_witness);
    let silence_certificate = if is_silence {
        Some(SilenceCertificate {
            basis_frame_digest: basis_frame.frame_digest(),
            result_frame_digest: result_frame.frame_digest(),
            selection_witness,
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
    basis.adapter_registry_epoch != result.adapter_registry_epoch
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

#[allow(clippy::too_many_arguments)]
fn comparison_witness(
    basis: &ReferenceSituationPublication,
    result: &ReferenceSituationPublication,
    classes: &BTreeSet<MeaningfulDeltaClass>,
    changed_cells: &[KnowledgeCell],
    invalidated_assumptions: &[String],
    coverage_changes: &[String],
    obligation_changes: &[String],
    effect_uncertainty_changes: &[String],
) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.reference_meaningful_delta_selection.v1");
    encoder.digest(basis.publication_digest);
    encoder.digest(result.publication_digest);
    encoder.u64(classes.len() as u64);
    for class in classes {
        class.encode_canonical(&mut encoder);
    }
    encoder.u64(changed_cells.len() as u64);
    for cell in changed_cells {
        encoder.digest(cell.cell_digest());
    }
    encode_text(invalidated_assumptions, &mut encoder);
    encode_text(coverage_changes, &mut encoder);
    encode_text(obligation_changes, &mut encoder);
    encode_text(effect_uncertainty_changes, &mut encoder);
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
