#![forbid(unsafe_code)]
//! Schema-faithful AOP-013 experience projection and recovery after partial publication.

use fss_core::{
    AgentFeedbackProposal, AgentView, CanonicalEncode, ExperienceCapsule, FeedbackProposalKind,
    ResponseOutcome, ResponseSafeRetry,
};
use fss_reference::deployment_session::DeploymentSessionError;
use fss_reference::deployment_session::feedback::{CAPABILITY_FEEDBACK, PublishedFeedback};
use fss_reference::deployment_session::learning::PublishedLearning;

use crate::agent_json;
use crate::error::ERR_CLI_RUNTIME_FAILURE;
use crate::orient_cmd::{RenderError, ResponseParts, build_response, contexts};
use crate::session_cmd::{Refusal, agent_plane_boundary, classify, idempotency_key};

fn micro(value: u32) -> String {
    format!("{}.{:06}", value / 1_000_000, value % 1_000_000)
}

fn experience_json(published: &PublishedFeedback, learning: &PublishedLearning) -> String {
    let experience = &learning.experience;
    let statements: Vec<String> = experience
        .initial_epistemic_map
        .iter()
        .map(|statement| {
            agent_json::object(&[
                ("statementId", agent_json::string(&statement.statement_id)),
                ("text", agent_json::string(&statement.text)),
                (
                    "epistemicState",
                    agent_json::string(statement.epistemic_state.as_str()),
                ),
                ("basis", agent_json::strings(&statement.basis)),
            ])
        })
        .collect();
    let template_kind = match published.proposal.kind {
        FeedbackProposalKind::RunbookCandidate => "runbook",
        FeedbackProposalKind::HardNegativeCandidate => "hard_negative",
        FeedbackProposalKind::PolicyCandidate => "policy_proposal",
        _ => "investigation",
    };
    agent_json::object(&[
        ("schema", agent_json::string(ExperienceCapsule::SCHEMA)),
        (
            "contractBasis",
            agent_json::contract_basis(&learning.contract_basis),
        ),
        (
            "experienceId",
            agent_json::string(&experience.experience_id),
        ),
        (
            "missionId",
            agent_json::string(experience.mission_id.as_str()),
        ),
        (
            "deploymentScope",
            agent_json::strings(&experience.deployment_scope),
        ),
        (
            "basisAnchor",
            agent_json::evidence_anchor(&experience.basis_anchor),
        ),
        (
            "situationSignature",
            experience.situation_signature_json.clone(),
        ),
        ("objective", agent_json::string(&experience.objective)),
        ("initialEpistemicMap", agent_json::array(&statements)),
        ("operations", agent_json::strings(&experience.operations)),
        ("evidence", agent_json::digests(&learning.evidence)),
        ("outcome", agent_json::string(&experience.outcome)),
        (
            "predictiveSignals",
            agent_json::strings(&experience.predictive_signals),
        ),
        (
            "misleadingSignals",
            agent_json::strings(&experience.misleading_signals),
        ),
        (
            "failedAssumptions",
            agent_json::strings(&experience.failed_assumptions),
        ),
        (
            "missingEvidence",
            agent_json::strings(&learning.missing_evidence),
        ),
        (
            "candidateTemplates",
            agent_json::array(&[agent_json::object(&[
                ("kind", agent_json::string(template_kind)),
                ("content", agent_json::string(&learning.proposal.statement)),
            ])]),
        ),
        ("cost", agent_json::budget(&experience.cost)),
        (
            "applicability",
            agent_json::strings(&experience.applicability),
        ),
        (
            "evidenceStrength",
            agent_json::string(experience.evidence_strength.as_str()),
        ),
        ("confidence", micro(experience.confidence_numerator)),
        (
            "decayHalfLifeDays",
            experience.decay_half_life_days.to_string(),
        ),
        (
            "helpfulCount",
            learning.proposal.helpful_outcomes.to_string(),
        ),
        (
            "harmfulCount",
            learning.proposal.harmful_outcomes.to_string(),
        ),
        (
            "revivalPredicates",
            agent_json::strings(&learning.proposal.revival_conditions),
        ),
        (
            "privacyClass",
            agent_json::string(&experience.privacy_class),
        ),
        ("createdAtNs", experience.created_at_ns.to_string()),
    ])
}

fn proof_pointers(published: &PublishedFeedback) -> Vec<String> {
    if let Some(learning) = &published.learning {
        vec![
            learning.root.to_text(),
            learning.experience_digest.to_text(),
            learning.proposal_digest.to_text(),
            learning.episode_root.to_text(),
            learning.feedback_root.to_text(),
            learning.plan_root.to_text(),
            published.orientation.anchor_token.clone(),
        ]
    } else {
        vec![
            published.root.to_text(),
            published
                .proposal
                .canonical_digest(AgentFeedbackProposal::SCHEMA)
                .to_text(),
            published.orientation.anchor_token.clone(),
        ]
    }
}

pub(super) fn response(
    published: &PublishedFeedback,
    learning: &PublishedLearning,
) -> Result<String, Box<dyn std::error::Error>> {
    let orientation = &published.orientation;
    let capsule = orientation.capsule();
    let (_, affordance_context) = contexts(orientation);
    let affordance_objects = agent_json::affordance_objects(
        &capsule.frame.next,
        &capsule.affordances,
        &affordance_context,
    )
    .ok_or(RenderError("next affordance objects"))?;
    let mut degradation = orientation.degradation.clone();
    degradation.push(format!(
        "Captured advisory learning proposal {} of class {} from retained episode {}. Its promotion state is {}; no policy, model, threshold, identity, retention, privacy or effect authority changed.",
        learning.proposal.proposal_id,
        learning.proposal.class.as_str(),
        learning.proposal.source_episode_id,
        learning.proposal.promotion_state.as_str(),
    ));
    degradation.push(
        "This is one retained execution episode. The feedback statement and its evidence sides remain proposals; they do not establish causal attribution, helpfulness, harmfulness, or completion of the broader mission."
            .to_owned(),
    );
    degradation.push(
        "The experience cost vector contains lower bounds only. missingEvidence and the canonical unknown-cost statement identify unmetered dimensions; the exact original resource measurements remain in the cited episode. Full task and capture costs are not certified."
            .to_owned(),
    );
    degradation.push(format!(
        "Review after evidence time {}; expiry {}. Review, expiry, counterexamples and required validation belong to the captured proposal; this command neither promotes it nor waives those checks.",
        learning.proposal.review_after_ns.map_or_else(|| "unscheduled".to_owned(), |at| format!("{at} ns")),
        learning.proposal.expiry_ns.map_or_else(|| "unscheduled".to_owned(), |at| format!("{at} ns")),
    ));
    if published.head_moved {
        degradation.push(
            "The deployment head has advanced. This experience preserves the original feedback and episode anchors and does not assert fresh mission completion or rebase the session."
                .to_owned(),
        );
    }
    let mut boundary = agent_plane_boundary(
        format!(
            "Retained feedback {} at {}; authenticated its source plan and closed episode; retained experience {} and learning proposal {} under root {}.",
            published.proposal.feedback_id,
            published.root,
            learning.experience.experience_id,
            learning.proposal.proposal_id,
            learning.root,
        ),
        Vec::new(),
    );
    boundary.not_started.push(
        "Learning promotion, causal validation, active policy/model/threshold changes, and external effects."
            .to_owned(),
    );
    build_response(ResponseParts {
        operation: "feedback",
        request_digest: published.request_digest,
        principal: published.session.principal_id.clone(),
        session_id: Some(published.session.session_id.as_str().to_owned()),
        mission_id: Some(published.session.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: AgentView::DecisionDiff,
        capability: CAPABILITY_FEEDBACK,
        outcome: ResponseOutcome::Ok,
        error_id: None,
        payload_schema: ExperienceCapsule::SCHEMA,
        payload_json: experience_json(published, learning),
        epistemic_state: fss_core::KnowledgeState::Unknown,
        completeness: fss_core::Completeness::Partial,
        warnings: orientation.warnings.clone(),
        contradictions: orientation.contradictions.clone(),
        degradation,
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers: proof_pointers(published),
        affordances: capsule.frame.next.clone(),
        affordance_objects,
        decision_fingerprint: learning.experience.experience_digest(),
        compression_receipt_id: Some(
            orientation
                .publication
                .compression_receipt
                .receipt_id
                .clone(),
        ),
        continuation: orientation.publication.context_pack.continuation.clone(),
        recovery_class: "refresh_and_retry",
        safe_retry: ResponseSafeRetry::YesSameRequest,
        boundary,
        created_at_ns: learning.experience.created_at_ns,
        workspace_revision: None,
        idempotency_key: Some(idempotency_key(published.request_digest)),
    })
}

/// Preserve a known feedback publication when downstream capture or response rendering fails.
fn partial(
    published: &PublishedFeedback,
    refusal: Refusal,
) -> Result<String, Box<dyn std::error::Error>> {
    let orientation = &published.orientation;
    let capsule = orientation.capsule();
    let mut boundary = agent_plane_boundary(
        format!(
            "Retained feedback proposal {} root-last at {}; that immutable proposal is preserved.",
            published.proposal.feedback_id, published.root,
        ),
        Vec::new(),
    );
    if let Some(learning) = &published.learning {
        boundary.completed.push(format!(
            "Retained experience {} and learning proposal {} under root {}; their complete public response was not delivered.",
            learning.experience.experience_id, learning.proposal.proposal_id, learning.root,
        ));
    } else {
        boundary.possibly_occurred.push(
            "Learning-publication staging or durability may have occurred before the refusal. Recovery verifies any retained graph instead of replacing it."
                .to_owned(),
        );
    }
    boundary
        .not_started
        .push("Learning promotion, active policy/model changes, and external effects.".to_owned());
    let mut degradation = vec![
        refusal.reason,
        refusal.guidance.to_owned(),
        "Feedback was retained, but the requested learning result was not delivered. Preserve the exact original feedback request and its source plan/episode; repair or refresh the failed precondition before retrying."
            .to_owned(),
    ];
    if published.head_moved {
        degradation.push(
            "The retained feedback remains bound to its original session anchor; the deployment head has advanced."
                .to_owned(),
        );
    }
    build_response(ResponseParts {
        operation: "feedback",
        request_digest: published.request_digest,
        principal: published.session.principal_id.clone(),
        session_id: Some(published.session.session_id.as_str().to_owned()),
        mission_id: Some(published.session.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: AgentView::DecisionDiff,
        capability: CAPABILITY_FEEDBACK,
        outcome: ResponseOutcome::Partial,
        error_id: Some(refusal.error_id),
        payload_schema: super::FEEDBACK_PAYLOAD_SCHEMA,
        payload_json: super::feedback_json(&published.proposal),
        epistemic_state: fss_core::KnowledgeState::Unknown,
        completeness: fss_core::Completeness::Partial,
        warnings: orientation.warnings.clone(),
        contradictions: orientation.contradictions.clone(),
        degradation,
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers: proof_pointers(published),
        affordances: Vec::new(),
        affordance_objects: Vec::new(),
        decision_fingerprint: published
            .proposal
            .canonical_digest(AgentFeedbackProposal::SCHEMA),
        compression_receipt_id: None,
        continuation: None,
        recovery_class: refusal.recovery_class,
        safe_retry: refusal.safe_retry,
        boundary,
        created_at_ns: capsule.created_at.0,
        workspace_revision: None,
        idempotency_key: Some(idempotency_key(published.request_digest)),
    })
}

pub(super) fn capture_refusal(
    published: &PublishedFeedback,
    error: DeploymentSessionError,
) -> Result<String, Box<dyn std::error::Error>> {
    let refusal = classify(error).unwrap_or_else(|_| Refusal {
        error_id: ERR_CLI_RUNTIME_FAILURE,
        reason: "Learning capture did not complete; the original feedback publication remains retained."
            .to_owned(),
        guidance: "Inspect the existing source and publication history before retrying the same request. Do not delete or recreate retained feedback to hide uncertain progress.",
        recovery_class: "operator_action_required",
        safe_retry: ResponseSafeRetry::No,
    });
    partial(published, refusal)
}

pub(super) fn render_failure(
    published: &PublishedFeedback,
) -> Result<String, Box<dyn std::error::Error>> {
    partial(
        published,
        Refusal {
            error_id: ERR_CLI_RUNTIME_FAILURE,
            reason: "The feedback or learning publication was retained, but its complete response could not be rendered."
                .to_owned(),
            guidance: "Preserve the named publication roots and retry the exact feedback request to recover its response; no new binding or external effect is authorized by this failure.",
            recovery_class: "refresh_and_retry",
            safe_retry: ResponseSafeRetry::YesSameRequest,
        },
    )
}
