#![forbid(unsafe_code)]
//! `fss.agent_cognitive_envelope.v1` payload builder and explanation evidence-handle helpers.

use fss_core::{
    ActionAffordance, AgentCognitiveEnvelope, AgentView, CognitiveAnswerClass, ContentDigest,
    EnvelopeBudget, EnvelopeContinuity, EnvelopeCoverage, EnvelopeEpistemic,
};
use fss_reference::agent_orient::{CAPABILITY_EXPLAIN, DeploymentOrientation, EventExplanation};

use super::capsule_json::contexts;
use super::diagnostics::RenderError;
use crate::agent_json;

/// Privacy class of retained event revisions (the only privacy class fss-core uses).
pub(super) const EVENT_PRIVACY_CLASS: &str = "private:property";

fn explain_budget(orientation: &DeploymentOrientation) -> (String, String, String) {
    (
        agent_json::budget(&orientation.requested),
        agent_json::budget(&orientation.consumed),
        agent_json::remaining(&orientation.requested, &orientation.consumed),
    )
}

/// The answer-specific blocks of one cognitive envelope.
pub(crate) struct CognitiveParts {
    pub(crate) answer_class: CognitiveAnswerClass,
    pub(crate) epistemic: EnvelopeEpistemic,
    pub(crate) coverage: EnvelopeCoverage,
    pub(crate) evidence_handles: Vec<agent_json::EvidenceHandle>,
    pub(crate) next_actions: Vec<ActionAffordance>,
    pub(crate) decision_digest: ContentDigest,
}

/// Rendered cognitive payload, next-action identities, and next-action objects.
pub(crate) type CognitivePayload = (String, Vec<String>, Vec<String>);

/// One `fss.agent_cognitive_envelope.v1` payload for `operation` (its registered name, which is
/// also the semantic verb) over `orientation`, with its next-action identities and objects.
pub(crate) fn cognitive_payload(
    orientation: &DeploymentOrientation,
    request_digest: ContentDigest,
    operation: &str,
    view: AgentView,
    parts: CognitiveParts,
) -> Result<CognitivePayload, Box<dyn std::error::Error>> {
    cognitive_payload_with_budget(orientation, request_digest, operation, view, parts, None)
}

pub(super) fn cognitive_payload_with_budget(
    orientation: &DeploymentOrientation,
    request_digest: ContentDigest,
    operation: &str,
    view: AgentView,
    parts: CognitiveParts,
    budget_override: Option<EnvelopeBudget>,
) -> Result<CognitivePayload, Box<dyn std::error::Error>> {
    let CognitiveParts {
        answer_class,
        epistemic,
        coverage,
        evidence_handles,
        next_actions,
        decision_digest,
    } = parts;
    let text = request_digest.to_text();
    let hex = text.split_once(':').map_or(text.as_str(), |(_, hex)| hex);
    let (requested, consumed, remaining) = explain_budget(orientation);
    let capsule = orientation.capsule();
    let (_, affordance_context) = contexts(orientation);
    let next_ids: Vec<String> = next_actions
        .iter()
        .map(|candidate| candidate.affordance_id.clone())
        .collect();
    let next_objects =
        agent_json::affordance_objects(&next_ids, &next_actions, &affordance_context)
            .ok_or(RenderError("next action objects"))?;
    let envelope = AgentCognitiveEnvelope::new(
        capsule.contract_basis.clone(),
        format!("request:{operation}:{hex}"),
        format!("response:{operation}:{hex}"),
        format!("trace:{operation}:{hex}"),
        operation,
        operation,
        view.id(),
        answer_class,
        capsule.anchor.clone(),
        epistemic,
        coverage,
        budget_override.unwrap_or(EnvelopeBudget {
            requested_json: requested,
            consumed_json: consumed,
            remaining_json: remaining,
            degraded_dimensions: Vec::new(),
            marginal_work_declined: Vec::new(),
        }),
        evidence_handles
            .iter()
            .map(|handle| handle.handle_id.clone())
            .collect(),
        next_ids.clone(),
        EnvelopeContinuity {
            cursor: None,
            reanchor_triggers: vec![format!(
                "The ledger head advances past commit {}.",
                capsule.anchor.commit_sequence
            )],
            session_capsule_digest: None,
            unresolved_obligations: capsule
                .obligations
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect(),
        },
        decision_digest.to_text(),
    )?;
    let json = agent_json::cognitive_envelope(&envelope, &evidence_handles, &next_objects)
        .ok_or(RenderError("cognitive envelope"))?;
    Ok((json, next_ids, next_objects))
}

/// The objects an explanation names, at the level it carries them (both verified read-back).
pub(super) fn explanation_handles(
    explanation: &EventExplanation,
) -> Vec<agent_json::EvidenceHandle> {
    let slot = &explanation.hydration;
    vec![
        agent_json::EvidenceHandle {
            handle_id: slot.handle.clone(),
            object_digest: explanation.event.revision_digest,
            kind: "event_revision".to_owned(),
            hydration: "H1",
            allowed_hydration: vec!["H0", "H1"],
            privacy_class: EVENT_PRIVACY_CLASS.to_owned(),
            availability: "available",
            estimated_cost: slot.synopsis_cost,
            required_capability: Some(CAPABILITY_EXPLAIN.to_owned()),
        },
        agent_json::EvidenceHandle {
            handle_id: format!("fss://proof/{}", explanation.event.event_root),
            object_digest: explanation.event.event_root,
            kind: "event_manifest".to_owned(),
            hydration: "H0",
            allowed_hydration: vec!["H0"],
            privacy_class: EVENT_PRIVACY_CLASS.to_owned(),
            availability: "available",
            estimated_cost: slot.source_cost,
            required_capability: None,
        },
    ]
}
