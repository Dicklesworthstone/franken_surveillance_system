#![forbid(unsafe_code)]
//! AOP-013 feedback projection for an explicitly requested native investigation draft.
//!
//! The registered payload remains the complete feedback proposal. The case identity, original
//! opening digest, current revision and journal receipt are proof pointers; ordinary investigation
//! affordances come from the native refreshed orientation, with no transport-defined case schema.

use fss_core::{
    AgentView, CanonicalEncoder, Completeness, ContentDigest, KnowledgeState, ResponseOutcome,
    ResponseSafeRetry,
};
use fss_reference::deployment_session::DeploymentSessionError;
use fss_reference::deployment_session::feedback::case::{OpenedFeedbackCase, identity};
use fss_reference::deployment_session::feedback::{CAPABILITY_FEEDBACK, PublishedFeedback};

use crate::agent_json;
use crate::error::ERR_CLI_RUNTIME_FAILURE;
use crate::orient_cmd::{RenderError, ResponseParts, build_response, contexts};
use crate::session_cmd::{
    ERR_OP_PRECONDITION_FAILED, ERR_PRECONDITION_STALE, Refusal, agent_plane_boundary, classify,
    idempotency_key,
};

/// Stable review meaning includes the original submission and current case revision. A no-op
/// Open retry can append a new native command receipt without changing this decision identity.
fn decision(published: &PublishedFeedback) -> Result<ContentDigest, fss_core::ContractError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.feedback_case_response.v1");
    encoder.digest(published.root);
    encoder.digest(published.proposal.proposal_digest());
    encoder.bool(published.case.is_some());
    if let Some(case) = &published.case {
        encoder.text(&case.revision.record().investigation_id);
        encoder.digest(case.opening.investigation_digest());
        encoder.digest(case.revision.digest());
    }
    Ok(ContentDigest::sha256(&encoder.finish_checked()?))
}

/// Feedback root and typed proposal digest first; then known case identity, original opening,
/// current revision, native command journal receipt and the original situation anchor.
fn proof_pointers(published: &PublishedFeedback) -> Vec<String> {
    let mut pointers = vec![
        published.root.to_text(),
        published.proposal.proposal_digest().to_text(),
    ];
    if let Some(case) = &published.case {
        pointers.extend([
            case.revision.record().investigation_id.clone(),
            case.opening.investigation_digest().to_text(),
            case.revision.digest().to_text(),
            case.journal_root.to_text(),
        ]);
    }
    pointers.push(published.orientation.anchor_token.clone());
    pointers
}

fn case_completed(case: &OpenedFeedbackCase) -> String {
    format!(
        "The native investigation owner retained or recovered case {} at revision {} ({}) in state {} under session journal root {}. Its original opening digest is {} and original evidence-clock deadline is {} ns.",
        case.revision.record().investigation_id,
        case.revision.record().revision,
        case.revision.digest(),
        case.revision.record().state.as_str(),
        case.journal_root,
        case.opening.investigation_digest(),
        case.opening.decision_deadline_ns,
    )
}

pub(super) fn response(
    published: &PublishedFeedback,
    case: &OpenedFeedbackCase,
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
    degradation.push(
        "The requested open_case disposition materialized an evidence-linked review draft through the native investigation owner. The complete literal feedback is retained in this payload; its truth and causal attribution remain unresolved."
            .to_owned(),
    );
    degradation.push(
        "The original draft preserves supported, contradicted or misattributed, and insufficient-evidence alternatives. Caller-supplied supporting and contradicting handles were not automatically admitted as hypothesis evidence. Full case-publication and review resource costs remain unknown."
            .to_owned(),
    );
    degradation.push(
        "Advisory review only: opening or recovering this case does not execute probes, adjudicate physical truth, or activate a policy, model, threshold, privacy, retention, identity or external effect."
            .to_owned(),
    );
    if published.head_moved {
        degradation.push(
            "The deployment head has advanced. The feedback and original case opening retain their original session anchor; this command does not rebase a case or renew its decision deadline."
                .to_owned(),
        );
    }
    let mut boundary = agent_plane_boundary(
        format!(
            "Retained complete feedback proposal {} root-last at {}.",
            published.proposal.feedback_id, published.root,
        ),
        Vec::new(),
    );
    boundary.completed.push(case_completed(case));
    boundary.completed.push(
        "Pinned the native journal command and projected its admitted current review context."
            .to_owned(),
    );
    boundary.not_started.push(
        "Further case transitions, admission of requested evidence, truth adjudication, corrective activation and external effects."
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
        payload_schema: super::FEEDBACK_PAYLOAD_SCHEMA,
        payload_json: super::feedback_json(&published.proposal),
        epistemic_state: KnowledgeState::Unknown,
        completeness: Completeness::Partial,
        warnings: orientation.warnings.clone(),
        contradictions: orientation.contradictions.clone(),
        degradation,
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers: proof_pointers(published),
        affordances: capsule.frame.next.clone(),
        affordance_objects,
        decision_fingerprint: decision(published)?,
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
        created_at_ns: published.proposal.created_at_ns,
        workspace_revision: None,
        idempotency_key: Some(idempotency_key(published.request_digest)),
    })
}

fn partial(
    published: &PublishedFeedback,
    refusal: Refusal,
    append_uncertain: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let orientation = &published.orientation;
    let capsule = orientation.capsule();
    let mut boundary = agent_plane_boundary(
        format!(
            "Retained complete feedback proposal {} root-last at {}; that immutable proposal is preserved.",
            published.proposal.feedback_id, published.root,
        ),
        Vec::new(),
    );
    if let Some(case) = &published.case {
        boundary.completed.push(case_completed(case));
        boundary.possibly_occurred.push(
            "Journal-root pin replacement or complete context/response delivery may have progressed before the refusal. The known native case revision was already retained; this failure does not roll it back."
                .to_owned(),
        );
    } else if append_uncertain {
        boundary.possibly_occurred.push(format!(
            "Native investigation initialization or a case append may have occurred. Preserve the journal and inspect deterministic case {} before assuming the case was not retained.",
            identity(published.root),
        ));
    } else {
        boundary.not_started.push(
            "No new investigation case revision was admitted by this feedback attempt.".to_owned(),
        );
    }
    boundary.not_started.push(
        "Further case transitions, admission of requested evidence, truth adjudication, corrective activation and external effects."
            .to_owned(),
    );
    let mut degradation = vec![
        refusal.reason,
        refusal.guidance.to_owned(),
        format!(
            "Feedback is retained, but its requested case result was not completely delivered. The deterministic case identity is {}; preserve the original feedback request, root and decision deadline when repairing or retrying.",
            identity(published.root),
        ),
    ];
    if published.head_moved {
        degradation.push(
            "The original feedback remains bound to its session anchor; the deployment head has advanced."
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
        epistemic_state: KnowledgeState::Unknown,
        completeness: Completeness::Partial,
        warnings: orientation.warnings.clone(),
        contradictions: orientation.contradictions.clone(),
        degradation,
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers: proof_pointers(published),
        // The pre-failure orientation may lack the case or may be the failed projection's input.
        // Preserve known proof without advertising potentially stale write affordances.
        affordances: Vec::new(),
        affordance_objects: Vec::new(),
        decision_fingerprint: decision(published)?,
        compression_receipt_id: None,
        continuation: None,
        recovery_class: refusal.recovery_class,
        safe_retry: refusal.safe_retry,
        boundary,
        created_at_ns: published.proposal.created_at_ns,
        workspace_revision: None,
        idempotency_key: Some(idempotency_key(published.request_digest)),
    })
}

pub(super) fn capture_refusal(
    published: &PublishedFeedback,
    error: DeploymentSessionError,
) -> Result<String, Box<dyn std::error::Error>> {
    // Typed admission refusals cannot append a case revision. Persistence failures can be
    // ambiguous, including a failed administrative initialization before the Open command.
    let append_uncertain = !matches!(
        &error,
        DeploymentSessionError::CaseRefused(_)
            | DeploymentSessionError::FeedbackRefused(_)
            | DeploymentSessionError::FeedbackDenied
            | DeploymentSessionError::PlanUnknown
            | DeploymentSessionError::PlanInvalid(_)
            | DeploymentSessionError::SessionUnknown
            | DeploymentSessionError::SessionStale(_)
    );
    let mut refusal = classify(error).unwrap_or_else(|_| Refusal {
        error_id: ERR_CLI_RUNTIME_FAILURE,
        reason: "The native feedback-case request did not completely return; retained feedback and any known case revision are preserved."
            .to_owned(),
        guidance: "Inspect the named feedback root and existing session journal before retrying. Do not delete retained state or mint another case to hide uncertain progress.",
        recovery_class: "operator_action_required",
        safe_retry: ResponseSafeRetry::No,
    });
    // The legacy classifier retains this historical constant, but the new surface must emit
    // the live registry identity rather than resurrecting its tombstone.
    if refusal.error_id == ERR_OP_PRECONDITION_FAILED {
        refusal.error_id = ERR_PRECONDITION_STALE;
    }
    partial(published, refusal, append_uncertain)
}

pub(super) fn render_failure(
    published: &PublishedFeedback,
) -> Result<String, Box<dyn std::error::Error>> {
    partial(
        published,
        Refusal {
            error_id: ERR_CLI_RUNTIME_FAILURE,
            reason: "The feedback and native case request completed, but their complete public response could not be rendered."
                .to_owned(),
            guidance: "Preserve the exact named feedback and case identities. Retry the same feedback request to recover the current case revision, or inspect that case through investigate; never re-open it under a new identity.",
            recovery_class: "refresh_and_retry",
            safe_retry: ResponseSafeRetry::YesSameRequest,
        },
        false,
    )
}
