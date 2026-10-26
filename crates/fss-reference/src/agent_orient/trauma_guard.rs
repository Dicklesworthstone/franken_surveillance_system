#![forbid(unsafe_code)]
//! Principal-admitted historical advisories enter canonical context before budget selection.
//!
//! This module performs no I/O and makes no policy or effect decision. Its known propositions
//! concern the existence of retained reports; applicability to the current mission stays unknown.

use super::*;
use crate::deployment_session::trauma_guard::MAX_TRAUMA_WARNINGS;

#[cfg(test)]
mod tests;

#[derive(Default)]
pub(super) struct Projection {
    pub cells: Vec<KnowledgeCell>,
    pub proof_roots: BTreeSet<ContentDigest>,
    pub unknown: Vec<String>,
    pub at_risk: Vec<String>,
    pub warnings: Vec<String>,
}

/// The caller admits the owner and privacy scope before providing historical warnings.
/// None means unavailable, while Some(empty) is a completed scan with no recurring advisory.
pub(super) fn project(
    warnings: Option<&[AntiPatternWarning]>,
) -> Result<Projection, ContractError> {
    let mut result = Projection::default();
    let Some(warnings) = warnings else {
        result.unknown.push(
            "Advisory operational memory is unavailable in this projection; no absence of harmful history is established."
                .to_owned(),
        );
        return Ok(result);
    };
    if warnings.len() > MAX_TRAUMA_WARNINGS {
        return Err(ContractError::BudgetExhausted);
    }
    if warnings.is_empty() {
        return Ok(result);
    }
    let mut ordered: Vec<_> = warnings.iter().collect();
    ordered.sort_by(|left, right| left.warning_id.cmp(&right.warning_id));
    if ordered
        .windows(2)
        .any(|pair| pair[0].warning_id == pair[1].warning_id)
    {
        return Err(ContractError::NonCanonicalOrdering);
    }
    // Workspaces conserve uncertainty. Keep applicability stable instead of accumulating
    // volatile record identities, counts or decay weights in the unknown collection.
    result.unknown.push(
        "Applicability of historical harmful outcomes to the current mission is unverified."
            .to_owned(),
    );
    for warning in ordered {
        warning.validate()?;
        let root = warning.canonical_digest();
        let mut evidence: BTreeSet<_> = warning.cited_evidence_digests.iter().copied().collect();
        evidence.insert(root);
        result.proof_roots.extend(evidence.iter().copied());
        result.cells.push(cell(KnowledgeCellParams {
            claim_id: format!("claim:memory:{}", warning.warning_id),
            statement: format!(
                "Retained historical advisory {} records {} negative reports about {} with cause {} and decay weight {} ppm. These reports do not establish the current target state, current mission applicability, or permission to change policy or execute effects.",
                warning.warning_id, warning.negative_count, warning.target_json,
                warning.cause_class.as_str(), warning.decay_weight_ppm,
            ),
            knowledge_state: KnowledgeState::Known, provenance: ProvenanceClass::Derived,
            hypothesis: None, evidence: evidence.into_iter().collect(),
            contradictions: Vec::new(), valid_until: None, state_basis: None,
        })?);
        let summary = warning.summary();
        // at_risk is a critical context class. Exact warning identity, source citations and
        // decay survive all view budgets, or the existing selector explicitly refuses.
        result
            .at_risk
            .push(format!("Historical advisory only. {summary}"));
        result.warnings.push(summary);
    }
    result.warnings.push(
        "Operational memory is advisory history from the admitted principal. Repeated negative reports are not calibrated predictions, current-world facts, or policy/effect authority."
            .to_owned(),
    );
    Ok(result)
}
