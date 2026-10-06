#![forbid(unsafe_code)]
//! `fss plan --close` (the `close` intent family of AOP-007 `plan`): records the immutable
//! execution episode of a plan whose effect is terminal, answered as the registered
//! `AgentResponseEnvelope`.
//!
//! [`fss_reference::deployment_session::episode`] owns the record: one episode per plan,
//! published root-last under `<root>/agent/publications/` and never rewritten. Closing writes
//! agent-plane state only; evidence, authority, policy, and the effect journal are unchanged.
//!
//! The frozen public registry lets AOP-007 answer only `fss.agent_control_plan.v1`, so the
//! payload is the closed plan exactly as published; the episode is identified by the proof
//! pointers (episode root, the digest of its `fss.agent_execution_episode.v1` rendering, and its
//! canonical digest), its outcome and every residual-uncertainty statement are stated in
//! `degradation`, and the rendering is hydrated from the agent publication store (the drift is
//! recorded in `architecture/agent_contracts.json`).
//!
//! ```text
//! fss plan --json --root DIR --session ID --close PLAN_ID [--principal ID]
//! ```

use std::path::PathBuf;

use fss_core::{
    AgentView, ExecutionEpisode, PrincipalId, ResponseOutcome, ResponseSafeRetry, SessionId,
};
use fss_reference::deployment_session::episode::{CloseRequest, ClosedPlan, close_plan};

use crate::agent_json;
use crate::error::{CliError, ExitIdentity};
use crate::orient_cmd::{
    RenderError, ResponseParts, build_response, collect_options, contexts, principal, rendered,
    required_root, take,
};
use crate::session_cmd::{Operation, agent_plane_boundary, idempotency_key, refuse};
use crate::token::ArgToken;

/// Schema of the episode rendering published beside the record (hydrated, never the payload).
pub const EPISODE_SCHEMA: &str = "fss.agent_execution_episode.v1";
/// Response payload schema of `plan --close`: AOP-007 answers only the control plan
/// (gen:fss1:public-v1), so the payload is the closed plan exactly as published.
pub const CONTROL_PLAN_SCHEMA: &str = "fss.agent_control_plan.v1";
/// Capability registry row of AOP-007 (`plan`).
const CAPABILITY_PLAN_PREPARE: &str = "CAP-AGENT-PLAN-PREPARE-001";
const COMMAND: &str = "plan";

/// Options for `fss plan --close`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloseArgs {
    /// Existing deployment root.
    pub root: PathBuf,
    /// Session whose authority admits the close.
    pub session: SessionId,
    /// The session's principal.
    pub principal: PrincipalId,
    /// Plan to close.
    pub plan: String,
}

/// True when `tokens` select the `close` intent family of `plan`.
#[must_use]
pub fn selects_close(tokens: &[ArgToken]) -> bool {
    tokens.iter().skip(1).any(|token| {
        let text = token.as_str();
        text == "--close" || text.starts_with("--close=")
    })
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

/// Parses `plan --json --root <dir> --session <id> --close <plan-id> [--principal <id>]`.
pub fn parse_close_args(tokens: &[ArgToken]) -> Result<CloseArgs, CliError> {
    let values = collect_options(
        COMMAND,
        tokens,
        &["--root", "--session", "--principal", "--close"],
    )?;
    let root = required_root(COMMAND, &values)?;
    let (_, raw, index) = take(&values, "--session").ok_or_else(|| CliError::MissingValue {
        option: "--session".to_owned(),
        command: Some(COMMAND.to_owned()),
        expected: "the session identity".to_owned(),
    })?;
    let session = SessionId::parse(raw.clone()).map_err(|_| {
        malformed(
            "--session",
            raw,
            "session identity must be 1..128 characters of [A-Za-z0-9._:-]",
            *index,
        )
    })?;
    let (_, plan, index) = take(&values, "--close").ok_or_else(|| CliError::MissingValue {
        option: "--close".to_owned(),
        command: Some(COMMAND.to_owned()),
        expected: "a published plan identity".to_owned(),
    })?;
    if plan.is_empty()
        || plan.len() > 128
        || !plan
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(malformed(
            "--close",
            plan,
            "plan identity must be 1..128 characters of [A-Za-z0-9._:-]",
            *index,
        ));
    }
    Ok(CloseArgs {
        root,
        session,
        principal: principal(COMMAND, &values)?,
        plan: plan.clone(),
    })
}

/// Exact decimal rendering of a micro-denominator numerator (`1_000_000` is `1`).
fn micro(numerator: u32) -> String {
    if numerator >= 1_000_000 {
        return "1".to_owned();
    }
    let fraction = format!("{numerator:06}");
    let trimmed = fraction.trim_end_matches('0');
    if trimmed.is_empty() {
        "0".to_owned()
    } else {
        format!("0.{trimmed}")
    }
}

fn number(value: f64) -> String {
    if value.is_finite() {
        format!("{value}")
    } else {
        "null".to_owned()
    }
}

/// One episode as `fss.agent_execution_episode.v1`.
#[must_use]
pub fn episode_json(episode: &ExecutionEpisode) -> String {
    let predictions: Vec<String> = episode
        .predictions
        .iter()
        .map(|prediction| {
            agent_json::object(&[
                (
                    "predictionId",
                    agent_json::string(&prediction.prediction_id),
                ),
                ("statement", agent_json::string(&prediction.statement)),
                (
                    "expectedState",
                    agent_json::string(&prediction.expected_state),
                ),
                (
                    "observedState",
                    agent_json::optional_string(prediction.observed_state.as_deref()),
                ),
                (
                    "error",
                    prediction.error.map_or_else(|| "null".to_owned(), number),
                ),
            ])
        })
        .collect();
    let attributions: Vec<String> = episode
        .attribution_hypotheses
        .iter()
        .map(|hypothesis| {
            agent_json::object(&[
                (
                    "causeClass",
                    agent_json::string(hypothesis.cause_class.as_str()),
                ),
                ("statement", agent_json::string(&hypothesis.statement)),
                (
                    "supportingEvidence",
                    agent_json::strings(&hypothesis.supporting_evidence),
                ),
                (
                    "contradictingEvidence",
                    agent_json::strings(&hypothesis.contradicting_evidence),
                ),
                ("confidence", micro(hypothesis.confidence_numerator)),
            ])
        })
        .collect();
    agent_json::object(&[
        ("schema", agent_json::string(EPISODE_SCHEMA)),
        (
            "contractBasis",
            agent_json::contract_basis(&fss_core::reference_contract_basis()),
        ),
        ("episodeId", agent_json::string(&episode.episode_id)),
        ("sessionId", agent_json::string(episode.session_id.as_str())),
        ("objectiveId", agent_json::string(&episode.objective_id)),
        (
            "initialAnchor",
            agent_json::evidence_anchor(&episode.initial_anchor),
        ),
        (
            "terminalAnchor",
            agent_json::evidence_anchor(&episode.terminal_anchor),
        ),
        ("planDigest", agent_json::string(&episode.plan_digest)),
        ("predictions", agent_json::array(&predictions)),
        ("stepReceipts", agent_json::strings(&episode.step_receipts)),
        (
            "effectReceipts",
            agent_json::strings(&episode.effect_receipts),
        ),
        ("obligations", agent_json::strings(&episode.obligations)),
        (
            "outcome",
            agent_json::object(&[
                ("state", agent_json::string(episode.outcome.state.as_str())),
                (
                    "successPredicates",
                    agent_json::strings(&episode.outcome.success_predicates),
                ),
                (
                    "failedPredicates",
                    agent_json::strings(&episode.outcome.failed_predicates),
                ),
                (
                    "indeterminatePredicates",
                    agent_json::strings(&episode.outcome.indeterminate_predicates),
                ),
            ]),
        ),
        ("resourceUse", episode.resource_use_json.clone()),
        ("attributionHypotheses", agent_json::array(&attributions)),
        (
            "residualUncertainty",
            agent_json::strings(&episode.residual_uncertainty),
        ),
        (
            "decisionDigest",
            agent_json::string(&episode.decision_digest),
        ),
    ])
}

fn response(closed: &ClosedPlan) -> Result<String, Box<dyn std::error::Error>> {
    let orientation = &closed.orientation;
    let capsule = orientation.capsule();
    let record = &closed.episode.record;
    let episode = &record.episode;
    let (_, affordance_context) = contexts(orientation);
    let affordance_objects = agent_json::affordance_objects(
        &capsule.frame.next,
        &capsule.affordances,
        &affordance_context,
    )
    .ok_or(RenderError("next affordance objects"))?;
    let control_plan = String::from_utf8(closed.control_plan.clone())
        .map_err(|_| RenderError("the published control plan is not UTF-8"))?;
    let digest = episode.episode_digest();
    let mut degradation = orientation.degradation.clone();
    if closed.head_moved {
        degradation.push(
            "The deployment head has moved past this session's anchor: the situation is as of \
             the session's anchor; the episode's terminal anchor is the head."
                .to_owned(),
        );
    }
    if !closed.committed {
        degradation.push(format!(
            "Plan {} was already closed: this is its published episode, unchanged (episodes \
             are immutable).",
            record.plan_id
        ));
    }
    degradation.push(format!(
        "Plan {} is closed by execution episode {}: outcome {} (operation {} is {}); succeeded \
         [{}], failed [{}], indeterminate [{}]. The payload is the closed plan as published; \
         hydrate the fss.agent_execution_episode.v1 rendering {} from the agent publication \
         store.",
        record.plan_id,
        episode.episode_id,
        episode.outcome.state.as_str(),
        record.operation_id,
        record.terminal_state.as_str(),
        episode.outcome.success_predicates.join(", "),
        episode.outcome.failed_predicates.join(", "),
        episode.outcome.indeterminate_predicates.join(", "),
        closed.episode.rendering
    ));
    // Residual uncertainty is never left to hydration alone.
    degradation.extend(
        episode
            .residual_uncertainty
            .iter()
            .map(|statement| format!("Residual uncertainty: {statement}")),
    );
    build_response(ResponseParts {
        operation: COMMAND,
        request_digest: closed.request_digest,
        principal: closed.session.principal_id.clone(),
        session_id: Some(closed.session.session_id.as_str().to_owned()),
        mission_id: Some(closed.session.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: AgentView::DecisionDiff,
        capability: CAPABILITY_PLAN_PREPARE,
        outcome: ResponseOutcome::Ok,
        error_id: None,
        payload_schema: CONTROL_PLAN_SCHEMA,
        payload_json: control_plan,
        epistemic_state: orientation.epistemic_state,
        completeness: capsule.completeness,
        warnings: orientation.warnings.clone(),
        contradictions: orientation.contradictions.clone(),
        degradation,
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers: vec![
            closed.episode.root.to_text(),
            closed.episode.rendering.to_text(),
            digest.to_text(),
            closed.plan_root.to_text(),
            orientation.anchor_token.clone(),
        ],
        affordances: capsule.frame.next.clone(),
        affordance_objects,
        decision_fingerprint: digest,
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
                "{} episode {} of plan {} root-last (root {}).",
                if closed.committed {
                    "Published"
                } else {
                    "Read the already published"
                },
                episode.episode_id,
                record.plan_id,
                closed.episode.root
            ),
            Vec::new(),
        ),
        created_at_ns: capsule.created_at.0,
        workspace_revision: None,
        idempotency_key: Some(idempotency_key(closed.request_digest)),
    })
}

/// Executes `fss plan --close`, returning the rendered response and its exit identity.
#[must_use]
pub fn execute_close(args: &CloseArgs) -> (String, ExitIdentity) {
    let request = CloseRequest {
        session_id: args.session.clone(),
        principal: args.principal.clone(),
        plan_id: args.plan.clone(),
    };
    match close_plan(&args.root, &request, &episode_json) {
        Ok(closed) => rendered(
            response(&closed),
            ExitIdentity::SUCCESS,
            COMMAND,
            &args.root,
        ),
        Err(error) => refuse(
            &Operation {
                command: COMMAND,
                name: COMMAND,
                capability: CAPABILITY_PLAN_PREPARE,
                payload_schema: CONTROL_PLAN_SCHEMA,
                view: AgentView::DecisionDiff,
                root: args.root.clone(),
                principal: args.principal.clone(),
                request: [
                    args.session.as_str().as_bytes(),
                    b"\0close\0",
                    args.plan.as_bytes(),
                ]
                .concat(),
            },
            error,
        ),
    }
}
