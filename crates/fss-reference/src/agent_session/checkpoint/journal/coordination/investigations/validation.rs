#![forbid(unsafe_code)]
//! Bounds and existing-contract validation before retained-state allocation.

use super::*;

fn text(value: &str, maximum: usize) -> Result<(), InvestigationError> {
    if value.is_empty() || value.len() > maximum { return Err(InvestigationError::InvalidRecord); }
    Ok(())
}

fn id(value: &str) -> Result<(), InvestigationError> {
    CaseId::parse(value).map(|_| ()).map_err(|_| InvestigationError::InvalidRecord)
}

fn count(length: usize, maximum: usize) -> Result<(), InvestigationError> {
    if length > maximum { return Err(InvestigationError::CapacityExceeded); }
    Ok(())
}

fn unique<T: Ord>(values: &[T]) -> Result<(), InvestigationError> {
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(InvestigationError::InvalidRecord);
    }
    Ok(())
}

pub(super) fn command(command: &InvestigationCommand) -> Result<(), InvestigationError> {
    match command {
        InvestigationCommand::Open { record, privacy_class } => {
            text(privacy_class, 256)?;
            record_fields(record)
        }
        InvestigationCommand::Inspect { case_id, .. } => id(case_id),
        InvestigationCommand::Change { case_id, change, .. } => {
            id(case_id)?;
            match change {
                InvestigationChange::Cite { hypothesis, .. }
                | InvestigationChange::Assess { hypothesis, .. } => id(hypothesis),
                InvestigationChange::Conclude { stop_rule, residual_unknowns, .. } => {
                    text(stop_rule, 1_024)?;
                    count(residual_unknowns.len(), 256)?;
                    for residual in residual_unknowns { id(residual)?; }
                    Ok(())
                }
                InvestigationChange::Activate | InvestigationChange::SetState { .. } => Ok(()),
            }
        }
    }
}

pub(super) fn record_fields(r: &InvestigationState) -> Result<(), InvestigationError> {
    id(&r.investigation_id)?;
    text(&r.question, 8_192)?;
    text(&r.decision_informed, 1_024)?;
    count(r.hypotheses.len(), 64)?;
    count(r.knowns.len(), 256)?;
    count(r.unknowns.len(), 256)?;
    count(r.discriminators.len(), 128)?;
    count(r.probes.len(), 128)?;
    count(r.stop_rules.len(), 64)?;
    let mut text_bytes = r.question.len() + r.decision_informed.len();
    for h in &r.hypotheses {
        id(&h.hypothesis_id)?;
        text(&h.description, 8_192)?;
        count(h.predictions.len(), 128)?;
        count(h.evidence.len(), 256)?;
        count(h.contradictions.len(), 128)?;
        unique(&h.evidence)?;
        unique(&h.contradictions)?;
        text_bytes += h.description.len();
        for p in &h.predictions { text(p, 1_024)?; text_bytes += p.len(); }
    }
    let mut statements = BTreeSet::new();
    for s in r.knowns.iter().chain(&r.unknowns) {
        id(&s.statement_id)?;
        if !statements.insert(&s.statement_id) { return Err(InvestigationError::InvalidRecord); }
        text(&s.text, 8_192)?;
        count(s.basis.len(), 256)?;
        unique(&s.basis)?;
        text_bytes += s.text.len();
        for root in &s.basis { id(root)?; text_bytes += root.len(); }
    }
    let mut discriminators = BTreeSet::new();
    for d in &r.discriminators {
        id(&d.discriminator_id)?;
        if !discriminators.insert(&d.discriminator_id) { return Err(InvestigationError::InvalidRecord); }
        text(&d.description, 1_024)?;
        count(d.separates.len(), 64)?;
        count(d.expected_outcomes.len(), 64)?;
        unique(&d.separates)?;
        if d.separates.len() != d.expected_outcomes.len() { return Err(InvestigationError::InvalidRecord); }
        text_bytes += d.description.len();
        for h in &d.separates { id(h)?; text_bytes += h.len(); }
        for outcome in &d.expected_outcomes { text(outcome, 1_024)?; text_bytes += outcome.len(); }
    }
    unique(&r.probes)?;
    unique(&r.stop_rules)?;
    for probe in &r.probes { id(probe)?; text_bytes += probe.len(); }
    for rule in &r.stop_rules { text(rule, 1_024)?; text_bytes += rule.len(); }
    // Every addition above is bounded by fixed counts and string lengths (< 64 MiB even on
    // 32-bit hosts), before any clone or aggregate canonical allocation.
    count(text_bytes, MAX_INVESTIGATION_BYTES)?;
    if r.decision_deadline_ns < 0 { return Err(InvestigationError::InvalidRecord); }
    InvestigationState::new(InvestigationStateParams {
        investigation_id: r.investigation_id.clone(), contract_basis: r.contract_basis.clone(),
        mission_id: r.mission_id.clone(), revision: r.revision, state: r.state,
        question: r.question.clone(), decision_informed: r.decision_informed.clone(),
        basis_anchor: r.basis_anchor.clone(), hypotheses: r.hypotheses.clone(),
        knowns: r.knowns.clone(), unknowns: r.unknowns.clone(), discriminators: r.discriminators.clone(),
        probes: r.probes.clone(), stop_rules: r.stop_rules.clone(),
        decision_deadline_ns: r.decision_deadline_ns,
    }).map_err(|_| InvestigationError::InvalidRecord)?;
    let bytes = r.try_canonical_bytes().map_err(|_| InvestigationError::InvalidRecord)?;
    count(bytes.len(), MAX_INVESTIGATION_BYTES)
}
