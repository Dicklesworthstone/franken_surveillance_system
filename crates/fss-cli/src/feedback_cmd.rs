#![forbid(unsafe_code)]
//! `fss feedback` (AOP-013 `feedback`): advisory, evidence-linked proposals over a deployment
//! root, answered as the registered `AgentResponseEnvelope`.
//!
//! [`fss_reference::deployment_session::feedback`] owns the durable effect: the proposal is
//! published root-last under `<root>/agent/publications/`. Recording a proposal never changes
//! evidence, authority, policy, thresholds, models, retention, privacy, or effects
//! (`activePolicyMutation` is the constant `false`).
//!
//! ```text
//! fss feedback --json --root DIR --session ID --target event|case|operation|plan:ID
//!     --kind correction|adjudication|helpful|harmful|missing_evidence|bad_affordance|
//!            bad_summary|adapter_quirk|runbook_candidate|hard_negative_candidate|
//!            policy_candidate|model_candidate
//!     --statement TEXT [--supporting sha256:..[,..]] [--contradicting sha256:..[,..]]
//!     [--disposition record_only|create_learning_proposal|open_case|requalify|deprecate|
//!                    operator_review] [--principal ID]
//! ```

use std::path::PathBuf;

use fss_core::{
    AgentFeedbackProposal, AgentView, CanonicalEncode, ContentDigest, FeedbackProposalKind,
    RequestedDisposition, ResponseOutcome, ResponseSafeRetry, SessionId,
};
use fss_reference::deployment_session::feedback::{
    CAPABILITY_FEEDBACK, FeedbackRequest, FeedbackTarget, PublishedFeedback, publish_feedback,
};

use crate::agent_json;
use crate::error::{CliError, ExitIdentity};
use crate::orient_cmd::{
    RenderError, ResponseParts, build_response, collect_options, contexts, principal, rendered,
    required_root, take,
};
use crate::session_cmd::{Operation, agent_plane_boundary, idempotency_key, refuse};
use crate::token::ArgToken;

/// Response payload schema of `feedback`.
pub const FEEDBACK_PAYLOAD_SCHEMA: &str = "fss.agent_feedback_proposal.v1";
const COMMAND: &str = "feedback";

/// Options for `fss feedback`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedbackArgs {
    /// Existing deployment root.
    pub root: PathBuf,
    /// The decoded request.
    pub request: FeedbackRequest,
}

fn malformed(option: &str, value: &str, reason: &str, index: usize) -> CliError {
    CliError::MalformedValue {
        option: option.to_owned(),
        value: value.to_owned(),
        reason: reason.to_owned(),
        command: Some(COMMAND.to_owned()),
        index,
    }
}

fn required<'a>(
    values: &'a [(String, String, usize)],
    option: &str,
    expected: &str,
) -> Result<&'a (String, String, usize), CliError> {
    take(values, option).ok_or_else(|| CliError::MissingValue {
        option: option.to_owned(),
        command: Some(COMMAND.to_owned()),
        expected: expected.to_owned(),
    })
}

fn digests(
    values: &[(String, String, usize)],
    option: &str,
) -> Result<Vec<ContentDigest>, CliError> {
    match take(values, option) {
        None => Ok(Vec::new()),
        Some((_, raw, index)) => raw
            .split(',')
            .map(|item| {
                ContentDigest::parse(item).map_err(|_| {
                    malformed(
                        option,
                        raw,
                        "expected comma-separated sha256:<64 hex> digests",
                        *index,
                    )
                })
            })
            .collect(),
    }
}

fn kind(raw: &str) -> Option<FeedbackProposalKind> {
    Some(match raw {
        "correction" => FeedbackProposalKind::Correction,
        "adjudication" => FeedbackProposalKind::Adjudication,
        "helpful" => FeedbackProposalKind::Helpful,
        "harmful" => FeedbackProposalKind::Harmful,
        "missing_evidence" => FeedbackProposalKind::MissingEvidence,
        "bad_affordance" => FeedbackProposalKind::BadAffordance,
        "bad_summary" => FeedbackProposalKind::BadSummary,
        "adapter_quirk" => FeedbackProposalKind::AdapterQuirk,
        "runbook_candidate" => FeedbackProposalKind::RunbookCandidate,
        "hard_negative_candidate" => FeedbackProposalKind::HardNegativeCandidate,
        "policy_candidate" => FeedbackProposalKind::PolicyCandidate,
        "model_candidate" => FeedbackProposalKind::ModelCandidate,
        _ => return None,
    })
}

fn disposition(raw: &str) -> Option<RequestedDisposition> {
    Some(match raw {
        "record_only" => RequestedDisposition::RecordOnly,
        "create_learning_proposal" => RequestedDisposition::CreateLearningProposal,
        "open_case" => RequestedDisposition::OpenCase,
        "requalify" => RequestedDisposition::Requalify,
        "deprecate" => RequestedDisposition::Deprecate,
        "operator_review" => RequestedDisposition::OperatorReview,
        _ => return None,
    })
}

/// Parses `feedback --json --root <dir> --session <id> --target <kind>:<id> ...`.
pub fn parse_feedback_args(tokens: &[ArgToken]) -> Result<FeedbackArgs, CliError> {
    let values = collect_options(
        COMMAND,
        tokens,
        &[
            "--root",
            "--session",
            "--principal",
            "--target",
            "--kind",
            "--statement",
            "--supporting",
            "--contradicting",
            "--disposition",
        ],
    )?;
    let root = required_root(COMMAND, &values)?;
    let (_, raw, index) = required(&values, "--session", "the session identity")?;
    let session_id = SessionId::parse(raw.clone()).map_err(|_| {
        malformed(
            "--session",
            raw,
            "session identity must be 1..128 characters of [A-Za-z0-9._:-]",
            *index,
        )
    })?;
    let (_, raw, index) = required(&values, "--target", "event|case|operation|plan:<id>")?;
    let target = match raw.split_once(':') {
        Some(("event", id)) if !id.is_empty() => FeedbackTarget::Event(id.to_owned()),
        Some(("case", id)) if !id.is_empty() => FeedbackTarget::Case(id.to_owned()),
        Some(("operation", id)) if !id.is_empty() => FeedbackTarget::Operation(id.to_owned()),
        Some(("plan", id)) if !id.is_empty() => FeedbackTarget::Plan(id.to_owned()),
        _ => {
            return Err(malformed(
                "--target",
                raw,
                "target must be event:<id>, case:<id>, operation:<id>, or plan:<id>",
                *index,
            ));
        }
    };
    let (_, raw, index) = required(&values, "--kind", "a registered feedback kind")?;
    let kind = kind(raw).ok_or_else(|| {
        malformed(
            "--kind",
            raw,
            "kind must be a registered feedback kind (correction, adjudication, helpful, harmful, \
             missing_evidence, bad_affordance, bad_summary, adapter_quirk, runbook_candidate, \
             hard_negative_candidate, policy_candidate, model_candidate)",
            *index,
        )
    })?;
    let (_, statement, index) = required(&values, "--statement", "the proposal statement")?;
    if statement.len() > 16_384 {
        return Err(malformed(
            "--statement",
            statement,
            "the statement must be at most 16384 bytes",
            *index,
        ));
    }
    let disposition = match take(&values, "--disposition") {
        None => RequestedDisposition::RecordOnly,
        Some((_, raw, index)) => disposition(raw).ok_or_else(|| {
            malformed(
                "--disposition",
                raw,
                "disposition must be record_only, create_learning_proposal, open_case, \
                 requalify, deprecate, or operator_review",
                *index,
            )
        })?,
    };
    Ok(FeedbackArgs {
        root,
        request: FeedbackRequest {
            session_id,
            principal: principal(COMMAND, &values)?,
            target,
            kind,
            statement: statement.clone(),
            supporting: digests(&values, "--supporting")?,
            contradicting: digests(&values, "--contradicting")?,
            disposition,
        },
    })
}

/// One proposal as `fss.agent_feedback_proposal.v1`.
#[must_use]
pub fn feedback_json(proposal: &AgentFeedbackProposal) -> String {
    agent_json::object(&[
        ("schema", agent_json::string(AgentFeedbackProposal::SCHEMA)),
        (
            "contractBasis",
            agent_json::contract_basis(&fss_core::reference_contract_basis()),
        ),
        ("feedbackId", agent_json::string(&proposal.feedback_id)),
        (
            "principalId",
            agent_json::string(proposal.principal_id.as_str()),
        ),
        (
            "sessionId",
            agent_json::string(proposal.session_id.as_str()),
        ),
        (
            "basisAnchor",
            agent_json::evidence_anchor(&proposal.basis_anchor),
        ),
        ("target", proposal.target_json.clone()),
        ("kind", agent_json::string(proposal.kind.as_str())),
        ("statement", agent_json::string(&proposal.statement)),
        (
            "supportingEvidence",
            agent_json::strings(&proposal.supporting_evidence),
        ),
        (
            "contradictingEvidence",
            agent_json::strings(&proposal.contradicting_evidence),
        ),
        (
            "requestedDisposition",
            agent_json::string(proposal.requested_disposition.as_str()),
        ),
        (
            "privacyClass",
            agent_json::string(proposal.privacy_class.as_str()),
        ),
        ("createdAtNs", proposal.created_at_ns.max(0).to_string()),
        ("activePolicyMutation", "false".to_owned()),
    ])
}

fn response(published: &PublishedFeedback) -> Result<String, Box<dyn std::error::Error>> {
    let orientation = &published.orientation;
    let capsule = orientation.capsule();
    let proposal = &published.proposal;
    let (_, affordance_context) = contexts(orientation);
    let affordance_objects = agent_json::affordance_objects(
        &capsule.frame.next,
        &capsule.affordances,
        &affordance_context,
    )
    .ok_or(RenderError("next affordance objects"))?;
    let mut degradation = orientation.degradation.clone();
    if published.head_moved {
        degradation.push(
            "The deployment head has moved past this session's anchor: the proposal is bound to \
             the session's anchor."
                .to_owned(),
        );
    }
    degradation.push(format!(
        "Advisory only: requested disposition {} is recorded, not performed; no policy, model, \
         threshold, retention, privacy, identity, or effect changed.",
        proposal.requested_disposition.as_str()
    ));
    build_response(ResponseParts {
        operation: COMMAND,
        request_digest: published.request_digest,
        principal: published.session.principal_id.clone(),
        session_id: Some(published.session.session_id.as_str().to_owned()),
        mission_id: Some(published.session.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: AgentView::DecisionDiff,
        capability: CAPABILITY_FEEDBACK,
        outcome: ResponseOutcome::Ok,
        error_id: None,
        payload_schema: FEEDBACK_PAYLOAD_SCHEMA,
        payload_json: feedback_json(proposal),
        epistemic_state: orientation.epistemic_state,
        completeness: capsule.completeness,
        warnings: orientation.warnings.clone(),
        contradictions: orientation.contradictions.clone(),
        degradation,
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers: vec![
            published.root.to_text(),
            proposal
                .canonical_digest(AgentFeedbackProposal::SCHEMA)
                .to_text(),
            orientation.anchor_token.clone(),
        ],
        affordances: capsule.frame.next.clone(),
        affordance_objects,
        decision_fingerprint: proposal.canonical_digest(AgentFeedbackProposal::SCHEMA),
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
        boundary: agent_plane_boundary(
            format!(
                "Published feedback proposal {} about {} root-last (root {}).",
                proposal.feedback_id, proposal.target_json, published.root
            ),
            Vec::new(),
        ),
        created_at_ns: capsule.created_at.0,
        workspace_revision: None,
        idempotency_key: Some(idempotency_key(published.request_digest)),
    })
}

/// Executes `fss feedback`, returning the rendered response and its exit identity.
#[must_use]
pub fn execute_feedback(args: &FeedbackArgs) -> (String, ExitIdentity) {
    match publish_feedback(&args.root, &args.request) {
        Ok(published) => rendered(
            response(&published),
            ExitIdentity::SUCCESS,
            COMMAND,
            &args.root,
        ),
        Err(error) => refuse(
            &Operation {
                command: COMMAND,
                name: COMMAND,
                capability: CAPABILITY_FEEDBACK,
                payload_schema: FEEDBACK_PAYLOAD_SCHEMA,
                view: AgentView::DecisionDiff,
                root: args.root.clone(),
                principal: args.request.principal.clone(),
                request: [
                    args.request.session_id.as_str().as_bytes(),
                    b"\0",
                    args.request.target.id().as_bytes(),
                ]
                .concat(),
            },
            error,
        ),
    }
}
