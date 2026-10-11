#![forbid(unsafe_code)]
//! Explicit explanation view and aggregate context admission; never an automatic escalation.

use fss_core::{
    AgentCognitiveEnvelope, AgentView, BudgetVector, Completeness, ContentDigest, KnowledgeState,
    PrincipalId, ResponseOutcome, ResponseSafeRetry,
};
use fss_reference::agent_orient::DeploymentSnapshot;

use super::{
    CAPABILITY_EXPLAIN, ERR_AGENT_CONTEXT_INCOMPLETE, ResponseParts, agent_json, build_response,
    read_only_boundary, take,
};
use crate::error::CliError;

/// The old compact allowance remains unchanged. Forensic work starts at its registered target;
/// only an explicit budget can use more, up to that view's registered maximum.
pub(super) fn limit(view: AgentView, requested: Option<u64>) -> Option<u64> {
    let default = match view {
        AgentView::DecisionDiff => view.maximum_tokens(),
        AgentView::Forensic => view.target_tokens(),
        _ => return None,
    };
    let tokens = requested.unwrap_or(u64::from(default));
    (1..=u64::from(view.maximum_tokens()))
        .contains(&tokens)
        .then_some(tokens)
}

pub(super) fn parse(
    values: &[(String, String, usize)],
) -> Result<(AgentView, Option<u64>), CliError> {
    let view = match take(values, "--view") {
        None => AgentView::DecisionDiff,
        Some((_, value, _)) if value == "decision_diff" => AgentView::DecisionDiff,
        Some((_, value, _)) if value == "forensic" => AgentView::Forensic,
        Some((_, value, index)) => {
            return Err(CliError::MalformedValue {
                option: "--view".to_owned(),
                value: value.clone(),
                reason: "explain view must be decision_diff or forensic".to_owned(),
                command: Some("explain".to_owned()),
                index: *index,
            });
        }
    };
    let tokens = match take(values, "--budget-tokens") {
        None => None,
        Some((_, value, index)) => {
            let parsed = value.parse::<u64>().ok();
            if parsed.is_none() || limit(view, parsed).is_none() {
                return Err(CliError::MalformedValue {
                    option: "--budget-tokens".to_owned(),
                    value: value.clone(),
                    reason: format!(
                        "budget must be an integer in 1..={} (the {} view maximum)",
                        view.maximum_tokens(),
                        view.name()
                    ),
                    command: Some("explain".to_owned()),
                    index: *index,
                });
            }
            parsed
        }
    };
    Ok((view, tokens))
}

/// Failure of the prerequisite orientation still answers AOP-011 under the caller's exact
/// view/allowance. The completed deployment read is charged; no failed context is called free.
pub(super) fn orientation_refusal(
    snapshot: &DeploymentSnapshot,
    request_digest: ContentDigest,
    view: AgentView,
    principal: &PrincipalId,
    token_limit: u64,
    reason: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut consumed = BudgetVector::ZERO;
    consumed.bytes = snapshot.bytes_read;
    consumed.storage_operations = snapshot.files_read;
    let mut requested = consumed;
    requested.tokens = token_limit;
    build_response(ResponseParts {
        operation: "explain", request_digest, principal: principal.clone(),
        session_id: None, mission_id: None, anchor: snapshot.anchor.clone(), view,
        capability: CAPABILITY_EXPLAIN, outcome: ResponseOutcome::Refused,
        error_id: Some(ERR_AGENT_CONTEXT_INCOMPLETE),
        payload_schema: AgentCognitiveEnvelope::SCHEMA, payload_json: "null".to_owned(),
        epistemic_state: KnowledgeState::Unknown, completeness: Completeness::Partial,
        warnings: vec![reason], contradictions: Vec::new(),
        degradation: vec![
            "The prerequisite orientation did not fit. No protected context was truncated and the requested view or allowance was not widened.".to_owned(),
            "Only the completed deployment read is metered here; failed context construction has no completed token receipt and is not claimed to have consumed zero work.".to_owned(),
            "For a larger complete explanation, explicitly request --view forensic --budget-tokens 8000; the forensic maximum is 16000.".to_owned(),
        ],
        budgets_json: agent_json::budget_summary(&requested, &consumed),
        proof_pointers: vec![snapshot.anchor.state_root.to_text()],
        affordances: Vec::new(), affordance_objects: Vec::new(),
        decision_fingerprint: request_digest, compression_receipt_id: None, continuation: None,
        recovery_class: "never_unchanged", safe_retry: ResponseSafeRetry::No,
        boundary: read_only_boundary("No complete explanation was served; no event or effect was changed.".to_owned()),
        created_at_ns: snapshot.latest_evidence_time.0, workspace_revision: None, idempotency_key: None,
    })
}
