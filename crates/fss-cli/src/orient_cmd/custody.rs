#![forbid(unsafe_code)]
//! Opt-in custody within AOP-011; no new operation, payload schema or media export route.

use std::time::Duration;

use fss_core::{
    AgentCognitiveEnvelope, Completeness, ContentDigest, EnvelopeBudget, ExplainQuestion,
    ExplainReceipt, KnowledgeState, ResponseOutcome, ResponseSafeRetry,
};
use fss_graph_algorithms::GraphError;
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::evidence::EvidenceProjectionError;
use fss_graph_algorithms::evidence_brief::availability::{
    AvailabilityObservation, EvidenceAvailabilityAnalysis, ObjectAvailability,
    analyze_current_availability,
};
use fss_publication::custody_audit::{CustodyAuditLimits, CustodyObjectState};
use fss_reference::agent_orient::{DeploymentOrientation, EventExplanation};

use super::{ResponseParts, agent_json, evidence, read_only_boundary};
use crate::custody_review::{
    CustodyReview, CustodyReviewError, MAX_RECHECK_ACCOUNTED_BYTES, MAX_RECHECK_ACCOUNTED_FILES,
};
use crate::error::CliError;

/// Fixed request-owned deadline for explicitly requested custody work, including the initial
/// orientation. Checkpoints cannot preempt a blocking syscall. Default explains read no clock.
pub(super) const TIMEOUT: Duration = Duration::from_secs(30);
pub(super) const METER_SCOPE: &str = "Custody bytes/calls are metered; separately admitted deployment-read counters exclude doctor preflight. Tokens estimate semantic UTF-8 bytes/4. CPU, latency and allocator peak are unmeasured.";
const DECLINED: &str = "Raw media disclosure and out-of-closure expansion were not requested.";
const VALIDITY: &str = "Custody observations are not an atomic snapshot.";
const INVALIDATOR: &str =
    "Recheck after byte, publication or tombstone changes, even with an unchanged ledger.";

pub(super) fn parse(values: &[(String, String, usize)]) -> Result<bool, CliError> {
    match super::take(values, "--custody") {
        None => Ok(false),
        Some((_, value, _)) if value == "no" => Ok(false),
        Some((_, value, _)) if value == "yes" => Ok(true),
        Some((_, value, index)) => Err(CliError::MalformedValue {
            option: "--custody".to_owned(),
            value: value.clone(),
            reason: "custody must be exactly yes or no".to_owned(),
            command: Some("explain".to_owned()),
            index: *index,
        }),
    }
}

fn add(left: u64, right: u64) -> Result<u64, CustodyReviewError> {
    left.checked_add(right)
        .ok_or(CustodyReviewError::ContextBound)
}

fn proposition_bytes(
    propositions: &[fss_core::EnvelopeProposition],
) -> Result<u64, CustodyReviewError> {
    let mut bytes = 0;
    for p in propositions {
        for text in [&p.id, &p.statement, &p.provenance] {
            bytes = add(bytes, text.len() as u64)?;
        }
        bytes = add(bytes, p.state.as_str().len() as u64)?;
        for text in &p.evidence {
            bytes = add(bytes, text.len() as u64)?;
        }
    }
    Ok(bytes)
}

// An inability to establish bytes is not evidence that those bytes are missing.
fn availability(state: CustodyObjectState) -> ObjectAvailability {
    match state {
        CustodyObjectState::Verified => ObjectAvailability::Verified,
        CustodyObjectState::Unreadable | CustodyObjectState::ObjectOverLimit => {
            ObjectAvailability::Unchecked
        }
        CustodyObjectState::Missing
        | CustodyObjectState::Corrupt
        | CustodyObjectState::InvalidManifest
        | CustodyObjectState::Deleted
        | CustodyObjectState::LocallyTombstoned => ObjectAvailability::Unavailable,
    }
}

fn graph_error(error: EvidenceProjectionError) -> CustodyReviewError {
    match error {
        EvidenceProjectionError::Graph(
            GraphError::BudgetExhausted { .. } | GraphError::TooLarge,
        ) => CustodyReviewError::ContextBound,
        _ => CustodyReviewError::SupportGraph,
    }
}

fn conditioned_support(
    support: &evidence::SupportReview,
    review: &CustodyReview,
) -> Result<EvidenceAvailabilityAnalysis, CustodyReviewError> {
    let (projection, anchor, root) = support
        .availability_basis
        .as_ref()
        .ok_or(CustodyReviewError::InvalidBinding)?;
    if anchor != review.basis_anchor()
        || review.audit().roots() != [*root]
        || support.receipt.subject() != review.receipt().subject()
        || support.graph_remaining.max_operations > evidence::GRAPH_BUDGET.max_operations
        || support.graph_remaining.max_output_entries > evidence::GRAPH_BUDGET.max_output_entries
    {
        return Err(CustodyReviewError::InvalidBinding);
    }
    let target = projection
        .heads()
        .iter()
        .find(|(_, digest)| **digest == support.receipt.subject())
        .map(|(id, _)| id)
        .ok_or(CustodyReviewError::InvalidBinding)?;
    let observations: Vec<_> = review
        .audit()
        .objects()
        .iter()
        .map(|row| AvailabilityObservation {
            digest: row.digest,
            availability: availability(row.state),
        })
        .collect();
    analyze_current_availability(
        projection,
        target,
        &observations,
        anchor.clone(),
        support.graph_remaining,
    )
    .map_err(graph_error)
}

/// Stage all additions, bindings and pricing before modifying the existing support review.
/// Replacements retain their old paid charge and pay any additional length; shorter text does
/// not refill the allowance. This is a semantic-field estimate, not a full-output tokenizer.
pub(super) fn augment(
    support: &mut evidence::SupportReview,
    review: &CustodyReview,
) -> Result<(), CustodyReviewError> {
    if support.receipt.subject() != review.receipt().subject() {
        return Err(CustodyReviewError::InvalidBinding);
    }
    let conditioned = conditioned_support(support, review)?;
    let graph_remaining = Budget::new(
        support
            .graph_remaining
            .max_operations
            .checked_sub(conditioned.graph_operations)
            .ok_or(CustodyReviewError::ContextBound)?,
        support
            .graph_remaining
            .max_output_entries
            .checked_sub(conditioned.graph_output_entries)
            .ok_or(CustodyReviewError::ContextBound)?,
    );
    let receipt = ExplainReceipt::compile(
        ExplainQuestion::Why,
        support.receipt.subject(),
        vec![
            support.receipt.receipt_digest(),
            review.receipt().receipt_digest(),
            conditioned.possible_witness.digest(),
            conditioned.verified_witness.digest(),
        ],
        Vec::new(),
        0,
    )
    .map_err(|_| CustodyReviewError::InvalidBinding)?;
    let pointers = [
        review.receipt().receipt_digest().to_text(),
        receipt.receipt_digest().to_text(),
        conditioned.possible_witness.digest().to_text(),
        conditioned.verified_witness.digest().to_text(),
    ];
    let support_state = fss_core::EnvelopeProposition {
        id: format!("claim:event-support:{}:availability", conditioned.target),
        statement: format!(
            "Declared support availability: {}. Reference paths only, not proof of truth or sufficiency; all custody faults and original uncertainty still apply.",
            conditioned.support.as_str(),
        ),
        state: KnowledgeState::Known,
        provenance: "derived".to_owned(),
        evidence: vec![receipt.receipt_digest().to_text()],
    };
    let audit = review.audit();
    let mut cost = format!(
        " Custody: {} charged bytes, {} peak reserved bytes, {} calls; recheck: {} accounted bytes, {} files. Deadline: 30000 ms at checkpoints.",
        audit.charged_read_bytes(),
        audit.peak_reserved_read_bytes(),
        audit.io_calls(),
        review.recheck_bytes(),
        review.recheck_files(),
    );
    cost.push_str(&format!(
        " Availability: {} operations, {} output entries; shared remaining={}/{}. Whole-graph observations: {} mapped, {} outside (not irrelevant); {} unchecked frontiers. Filter construction is separately bounded.",
        conditioned.graph_operations, conditioned.graph_output_entries,
        graph_remaining.max_operations, graph_remaining.max_output_entries,
        conditioned.mapped_observations, conditioned.outside_graph_observations,
        conditioned.unchecked_frontier_references,
    ));
    let mut replacements = Vec::new();
    for (index, p) in support.propositions.iter().enumerate() {
        let replacement = if p.id.ends_with(":unexpanded-references") {
            Some(
                "This graph stage did not hydrate these references. The custody section reports only the current publication closure; other references remain unexamined.",
            )
        } else if p.id.ends_with(":custody-and-independence") {
            Some(
                "This graph stage certifies neither custody nor independence. The custody section adds current publication-byte observations, not independent corroboration or complete semantic provenance.",
            )
        } else {
            None
        };
        if let Some(text) = replacement {
            replacements.push((index, text.to_owned()));
        }
    }
    let mut warnings = vec![VALIDITY.to_owned()];
    if !audit.all_verified() {
        warnings.push("Custody faults are present. This explanation is not an intact-custody success and does not retract or adjudicate the event.".to_owned());
    }
    let mut extra_bytes = add(
        proposition_bytes(review.propositions())?,
        proposition_bytes(std::slice::from_ref(&support_state))?,
    )?;
    for text in pointers
        .iter()
        .map(String::as_str)
        .chain(warnings.iter().map(String::as_str))
        .chain([cost.as_str(), INVALIDATOR, METER_SCOPE, DECLINED])
    {
        extra_bytes = add(extra_bytes, text.len() as u64)?;
    }
    for (index, text) in &replacements {
        extra_bytes = add(
            extra_bytes,
            text.len()
                .saturating_sub(support.propositions[*index].statement.len()) as u64,
        )?;
    }
    let mut requested = support.requested;
    let mut consumed = support.consumed;
    consumed.tokens = add(consumed.tokens, extra_bytes.div_ceil(4))?;
    if extra_bytes > 8 * 1024 || consumed.tokens > requested.tokens {
        return Err(CustodyReviewError::ContextBound);
    }
    let limits = CustodyAuditLimits::default();
    requested.bytes = add(
        requested.bytes.max(support.consumed.bytes),
        add(limits.max_read_bytes, MAX_RECHECK_ACCOUNTED_BYTES)?,
    )?;
    requested.storage_operations = add(
        requested
            .storage_operations
            .max(support.consumed.storage_operations),
        add(limits.max_io_calls, MAX_RECHECK_ACCOUNTED_FILES)?,
    )?;
    consumed.bytes = add(
        consumed.bytes,
        add(audit.charged_read_bytes(), review.recheck_bytes())?,
    )?;
    consumed.storage_operations = add(
        consumed.storage_operations,
        add(audit.io_calls(), review.recheck_files())?,
    )?;
    // No wall-clock consumption is fabricated from the enforced checkpoint deadline.
    requested.latency_ms = requested.latency_ms.max(TIMEOUT.as_millis() as u64);
    for (index, text) in replacements {
        support.propositions[index].statement = text;
    }
    support
        .propositions
        .extend(review.propositions().iter().cloned());
    support.propositions.push(support_state);
    support.invalidators.push(INVALIDATOR.to_owned());
    support.warnings.extend(warnings);
    support.proof_pointers.extend(pointers);
    support.cost_statement.push_str(&cost);
    support.receipt = receipt;
    support.requested = requested;
    support.consumed = consumed;
    support.graph_remaining = graph_remaining;
    // The same basis cannot be augmented and charged a second time accidentally.
    support.availability_basis = None;
    Ok(())
}

pub(super) fn budget(support: &evidence::SupportReview, checked: bool) -> EnvelopeBudget {
    let mut budget = evidence::budget(support);
    if checked {
        budget.degraded_dimensions.push(METER_SCOPE.to_owned());
        budget.marginal_work_declined = vec![DECLINED.to_owned()];
    }
    budget
}

pub(super) fn refusal(
    orientation: &DeploymentOrientation,
    explanation: &EventExplanation,
    request_digest: ContentDigest,
    support: &evidence::SupportReview,
    error: &CustodyReviewError,
) -> Result<String, Box<dyn std::error::Error>> {
    let refresh = matches!(
        error,
        CustodyReviewError::BasisChanged | CustodyReviewError::RecheckFailed
    );
    let capsule = orientation.capsule();
    let error_id = if matches!(error, CustodyReviewError::ContextBound) {
        super::ERR_AGENT_CONTEXT_INCOMPLETE
    } else {
        crate::ERR_CLI_RUNTIME_FAILURE
    };
    let mut boundary = read_only_boundary(
        "No complete custody-bearing explanation was served; no event or effect was changed."
            .to_owned(),
    );
    if refresh {
        boundary.invalidated.push(
            "The earlier custody authority basis cannot be reused without a fresh read.".to_owned(),
        );
    }
    super::build_response_with_resnapshot(ResponseParts {
        operation: "explain", request_digest, principal: capsule.principal_id.clone(),
        session_id: Some(capsule.session_id.as_str().to_owned()),
        mission_id: Some(capsule.mission_id.as_str().to_owned()), anchor: capsule.anchor.clone(),
        view: support.view, capability: super::CAPABILITY_EXPLAIN,
        outcome: ResponseOutcome::Refused, error_id: Some(error_id),
        payload_schema: AgentCognitiveEnvelope::SCHEMA, payload_json: "null".to_owned(),
        epistemic_state: KnowledgeState::Unknown, completeness: Completeness::Partial,
        warnings: vec![error.reason().to_owned()], contradictions: orientation.contradictions.clone(),
        degradation: vec![
            "No failed check was replaced by an unchecked explanation; no fault or uncertainty was truncated.".to_owned(),
            "Counters retain the completed support review and any admitted custody addition. Unreturned audit/recheck/availability-graph work is not measured here and is not claimed to have consumed zero.".to_owned(),
        ],
        budgets_json: agent_json::budget_summary(&support.requested, &support.consumed),
        proof_pointers: vec![explanation.event.event_root.to_text(), explanation.event.revision_digest.to_text()],
        affordances: Vec::new(), affordance_objects: Vec::new(), decision_fingerprint: request_digest,
        compression_receipt_id: None, continuation: None,
        recovery_class: if refresh { "refresh_and_retry" } else { "operator_action_required" },
        safe_retry: if refresh { ResponseSafeRetry::YesAfterRefresh } else { ResponseSafeRetry::No },
        boundary, created_at_ns: capsule.created_at.0, workspace_revision: None, idempotency_key: None,
    }, refresh)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opt_in_is_exact_and_default_is_unchanged() {
        assert_eq!(parse(&[]).ok(), Some(false));
        for (value, expected) in [("yes", true), ("no", false)] {
            assert_eq!(
                parse(&[("--custody".to_owned(), value.to_owned(), 1)]).ok(),
                Some(expected)
            );
        }
        for value in ["", "true", "YES", "1", "yes "] {
            assert!(parse(&[("--custody".to_owned(), value.to_owned(), 1)]).is_err());
        }
    }

    #[test]
    fn additive_accounting_refuses_overflow() {
        assert_eq!(add(u64::MAX, 1), Err(CustodyReviewError::ContextBound));
        assert_eq!(add(u64::MAX - 1, 1), Ok(u64::MAX));
    }
}

#[cfg(test)]
#[path = "availability_tests.rs"]
mod availability_tests;
