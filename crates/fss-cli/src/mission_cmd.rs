#![forbid(unsafe_code)]
//! Explicit plan-outcome mission contracts through the existing AOP-007 plan grammar.
//!
//! Binding and assessment write cognition only. The payload remains the original registered
//! ControlPlan; exact mission revision identities and outcome are carried in the envelope.
//! The native owner verifies custody and derives the state; no command accepts a requested state.

use std::path::PathBuf;

use fss_core::{
    AgentView, ContentDigest, ExecutionBoundary, PrincipalId, ResponseOutcome, ResponseSafeRetry,
    SessionId, TimestampNs,
};
use fss_reference::agent_orient::OrientError;
use fss_reference::deployment_session::DeploymentSessionError;
use fss_reference::deployment_session::mission::{
    MissionAction, MissionAnswer, MissionError, MissionRequest,
};

use crate::agent_json;
use crate::effect_cmd::{CAPABILITY_PLAN_PREPARE, CONTROL_PLAN_SCHEMA, finish, hold_deployment};
use crate::error::{CliError, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use crate::orient_cmd::{
    ERR_AGENT_CONTEXT_INCOMPLETE, RenderError, ResponseParts, build_response, collect_options,
    contexts, principal, rendered, required_root, take,
};
use crate::session_cmd::{
    Operation, Refusal, agent_plane_boundary, idempotency_key, refusal_response,
    refuse_typed_with_boundary,
};
use crate::token::ArgToken;

const COMMAND: &str = "plan";

/// Explicit mission enrollment or assessment under an existing live session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionArgs {
    /// Existing deployment root.
    pub root: PathBuf,
    /// Owning session.
    pub session: SessionId,
    /// Admitted principal.
    pub principal: PrincipalId,
    /// Native typed action; arbitrary lifecycle labels are not inputs.
    pub action: MissionAction,
}

/// Select the mission intent family without interpreting any option value.
#[must_use]
pub fn selects_mission(tokens: &[ArgToken]) -> bool {
    tokens.iter().skip(1).any(|token| {
        let text = token.as_str();
        ["--mission-bind", "--mission-assess"]
            .iter()
            .any(|flag| text == *flag || text.starts_with(&format!("{flag}=")))
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

fn missing(option: &str, expected: &str) -> CliError {
    CliError::MissingValue {
        option: option.to_owned(),
        command: Some(COMMAND.to_owned()),
        expected: expected.to_owned(),
    }
}

/// Parse mutually exclusive mission bind/assess intents using native bounded values.
pub fn parse_mission_args(tokens: &[ArgToken]) -> Result<MissionArgs, CliError> {
    let values = collect_options(
        COMMAND,
        tokens,
        &[
            "--root",
            "--session",
            "--principal",
            "--mission-bind",
            "--mission-assess",
            "--mission-deadline-ns",
            "--expected-mission",
        ],
    )?;
    let root = required_root(COMMAND, &values)?;
    let (_, raw, index) = take(&values, "--session")
        .ok_or_else(|| missing("--session", "the owning live session"))?;
    let session = SessionId::parse(raw.clone())
        .map_err(|_| malformed("--session", raw, "invalid bounded session identity", *index))?;
    let bind = take(&values, "--mission-bind");
    let assess = take(&values, "--mission-assess");
    let (flag, plan, index) = match (bind, assess) {
        (Some(value), None) | (None, Some(value)) => value,
        (Some(value), Some(_)) => {
            return Err(malformed(
                &value.0,
                &value.1,
                "choose exactly one mission action",
                value.2,
            ));
        }
        (None, None) => {
            return Err(missing(
                "--mission-bind",
                "exactly one mission bind or assess action",
            ));
        }
    };
    if !plan.starts_with("plan:")
        || plan.len() > 128
        || !plan
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(malformed(
            flag,
            plan,
            "invalid bounded plan identity",
            *index,
        ));
    }
    let action = if bind.is_some() {
        if let Some((name, value, index)) = take(&values, "--expected-mission") {
            return Err(malformed(
                name,
                value,
                "bind creates an initial contract; use assess for an existing head",
                *index,
            ));
        }
        let (_, raw, index) = take(&values, "--mission-deadline-ns").ok_or_else(|| {
            missing(
                "--mission-deadline-ns",
                "an explicit evidence-clock decision deadline",
            )
        })?;
        let deadline = raw
            .parse::<i128>()
            .ok()
            .filter(|value| *value > 0 && value.to_string() == *raw)
            .ok_or_else(|| {
                malformed(
                    "--mission-deadline-ns",
                    raw,
                    "expected canonical positive signed 128-bit decimal nanoseconds",
                    *index,
                )
            })?;
        MissionAction::Adopt {
            plan_id: plan.clone(),
            decision_deadline: TimestampNs(deadline),
        }
    } else {
        if let Some((name, value, index)) = take(&values, "--mission-deadline-ns") {
            return Err(malformed(
                name,
                value,
                "assessment uses the immutable enrolled deadline",
                *index,
            ));
        }
        let (_, raw, index) = take(&values, "--expected-mission").ok_or_else(|| {
            missing(
                "--expected-mission",
                "the exact retained mission revision digest",
            )
        })?;
        let expected = ContentDigest::parse(raw)
            .ok()
            .filter(|_| raw.starts_with("sha256:"))
            .ok_or_else(|| {
                malformed(
                    "--expected-mission",
                    raw,
                    "expected an exact SHA-256 revision digest",
                    *index,
                )
            })?;
        MissionAction::Assess {
            plan_id: plan.clone(),
            expected,
        }
    };
    Ok(MissionArgs {
        root,
        session,
        principal: principal(COMMAND, &values)?,
        action,
    })
}

fn response(answer: &MissionAnswer) -> Result<String, Box<dyn std::error::Error>> {
    let orientation = &answer.orientation;
    let capsule = orientation.capsule();
    let revision = &answer.revision;
    let criterion = revision.criterion();
    let (_, affordance_context) = contexts(orientation);
    let affordance_objects = agent_json::affordance_objects(
        &capsule.frame.next,
        &capsule.affordances,
        &affordance_context,
    )
    .ok_or(RenderError("mission next affordance objects"))?;
    let control_plan = String::from_utf8(answer.control_plan.clone())
        .map_err(|_| RenderError("the published control plan is not UTF-8"))?;
    let mut degradation = orientation.degradation.clone();
    degradation.push(format!(
        "PlanOutcomeV1 mission revision {} is {} at {}. This explicitly enrolled execution objective concerns plan {}; it does not establish that the underlying surveillance event was real. The payload is the original ControlPlan; the mission revision and its evidence are named by proof pointers.",
        revision.revision(), revision.state().as_str(), revision.digest(), criterion.plan_id,
    ));
    let current = orientation
        .mission_progress
        .as_ref()
        .is_some_and(|progress| {
            progress.current && progress.revision.digest() == revision.digest()
        });
    degradation.push(
        if current {
            "This retained mission revision is current for this projection."
        } else {
            "This is a historical retained mission revision. The current mission lifecycle is unassessed; the state above is an immutable as-of result, not a fresh completion claim."
        }
        .to_owned(),
    );
    if answer.head_moved {
        degradation.push(
            "The deployment has moved beyond the session anchor. This assessment uses compatible current generations; resume explicitly to advance the session workspace."
                .to_owned(),
        );
    }
    if revision.deadline_reached() {
        degradation.push(
            "The decision deadline has elapsed on the evidence clock. Deadline passage does not prove cancellation, failure, or absence of a dispatched effect."
                .to_owned(),
        );
    }
    let mut proof_pointers = vec![
        revision.digest().to_text(),
        answer.journal_root.to_text(),
        answer.plan_root.to_text(),
        orientation.anchor_token.clone(),
    ];
    for root in revision.proof_roots() {
        let text = root.to_text();
        if !proof_pointers.contains(&text) {
            proof_pointers.push(text);
        }
    }
    build_response(ResponseParts {
        operation: COMMAND,
        request_digest: answer.request_digest,
        principal: answer.session.principal_id.clone(),
        session_id: Some(answer.session.session_id.as_str().to_owned()),
        mission_id: Some(answer.session.mission_id.as_str().to_owned()),
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
        proof_pointers,
        affordances: capsule.frame.next.clone(),
        affordance_objects,
        decision_fingerprint: capsule.decision_fingerprint()?,
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
                "Retained mission revision {} ({}) for plan {} in the authenticated session journal.",
                revision.revision(),
                revision.digest(),
                criterion.plan_id,
            ),
            Vec::new(),
        ),
        created_at_ns: capsule.created_at.0,
        workspace_revision: None,
        idempotency_key: Some(idempotency_key(answer.request_digest)),
    })
}

fn mission_refusal(error: &MissionError) -> Refusal {
    let id = error.stable_id();
    let (guidance, recovery_class, safe_retry) = match id {
        ERR_AGENT_CONTEXT_INCOMPLETE => (
            "Critical context exceeds the admitted session view and is never truncated. A mission revision may already be retained; preserve that history and its exact plan binding. Use a sufficiently large registered view before enrolling a new session; retrying this unchanged request cannot enlarge its view.",
            "never_unchanged",
            ResponseSafeRetry::No,
        ),
        "ERR-AGENT-SESSION-STORE-LOCKED-001" => (
            "Retry after the other session command finishes; preserve any existing mission revision.",
            "backoff",
            ResponseSafeRetry::YesSameRequest,
        ),
        "ERR-AGENT-SESSION-STORE-INVALID-001" => (
            "Inspect the existing agent session journal and its pinned root. A mission revision may already be retained; never erase history or recreate the binding to hide an uncertain append.",
            "operator_action_required",
            ResponseSafeRetry::No,
        ),
        _ => (
            "Read the current authorized session and exact mission head; preserve the original enrollment, reconcile unresolved effects, and retry only against the retained revision. No effect is dispatched by this command.",
            "refresh_and_retry",
            ResponseSafeRetry::YesAfterRefresh,
        ),
    };
    let reason = match error {
        MissionError::Session(DeploymentSessionError::Orient(
            orient
            @ (OrientError::ContextBudgetExceeded { .. } | OrientError::TooManyEvents { .. }),
        )) => orient.to_string(),
        _ => error.to_string(),
    };
    Refusal {
        error_id: id,
        reason,
        guidance,
        recovery_class,
        safe_retry,
    }
}

fn mission_failure_boundary(retained: Option<(u64, ContentDigest)>) -> ExecutionBoundary {
    let mut boundary = agent_plane_boundary(
        match retained {
            Some((revision, digest)) => format!(
                "Mission revision {revision} ({digest}) is durably retained; public response rendering failed."
            ),
            None => {
                "The native mission request returned without a complete public answer.".to_owned()
            }
        },
        Vec::new(),
    );
    if retained.is_none() {
        boundary.possibly_occurred.push(
            "Session admission and a mission revision may already be retained in agent/sessions; inspect the existing durable history before recovery."
                .to_owned(),
        );
    }
    boundary
}

/// Execute with the same deployment lock used by plan closure, without effect authority.
#[must_use]
pub fn execute_mission(args: &MissionArgs) -> (String, ExitIdentity) {
    let request = MissionRequest {
        session_id: args.session.clone(),
        principal: args.principal.clone(),
        action: args.action.clone(),
    };
    let mut request_bytes = args.session.as_str().as_bytes().to_vec();
    request_bytes.push(0);
    match &args.action {
        MissionAction::Adopt {
            plan_id,
            decision_deadline,
        } => {
            request_bytes.extend_from_slice(b"mission-bind\0");
            request_bytes.extend_from_slice(plan_id.as_bytes());
            request_bytes.push(0);
            request_bytes.extend_from_slice(&decision_deadline.0.to_be_bytes());
        }
        MissionAction::Assess { plan_id, expected } => {
            request_bytes.extend_from_slice(b"mission-assess\0");
            request_bytes.extend_from_slice(plan_id.as_bytes());
            request_bytes.push(0);
            request_bytes.extend_from_slice(expected.to_text().as_bytes());
        }
    }
    let operation = Operation {
        command: COMMAND,
        name: COMMAND,
        capability: CAPABILITY_PLAN_PREPARE,
        payload_schema: CONTROL_PLAN_SCHEMA,
        view: AgentView::DecisionDiff,
        root: args.root.clone(),
        principal: args.principal.clone(),
        request: request_bytes,
    };
    let deployment = match hold_deployment(&args.root, &args.principal) {
        Ok(deployment) => deployment,
        Err(failure) => return finish(Err(failure), ExitIdentity::SUCCESS, &operation),
    };
    let result = fss_reference::deployment_session::mission::execute(&args.root, &request);
    // Refusal rendering may reread the deployment. Release only this command's lock after the
    // native owner has pinned its result, before that independent read.
    drop(deployment);
    match result {
        Err(error) => refuse_typed_with_boundary(
            &operation,
            mission_refusal(&error),
            ExitIdentity::AGENT_REFUSED,
            Some(mission_failure_boundary(None)),
        ),
        Ok(answer) => match response(&answer) {
            Ok(json) => (json, ExitIdentity::SUCCESS),
            Err(_) => rendered(
                refusal_response(
                    &operation,
                    &answer.orientation.capsule().anchor,
                    answer.orientation.capsule().created_at.0,
                    Refusal {
                        error_id: ERR_CLI_RUNTIME_FAILURE,
                        reason: "The mission revision was retained, but its public response could not be rendered.".to_owned(),
                        guidance: "Preserve the retained revision and recover the same request's response; a rendering failure never permits a new mission binding or an external effect.",
                        recovery_class: "safe_read_retry",
                        safe_retry: ResponseSafeRetry::YesSameRequest,
                    },
                    Some(mission_failure_boundary(Some((
                        answer.revision.revision(),
                        answer.revision.digest(),
                    )))),
                ),
                ExitIdentity::RUNTIME_FAILURE,
                operation.command,
                &operation.root,
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FssCommand, parse_fss_args};

    fn parse(extra: &[&str]) -> Result<MissionArgs, Box<dyn std::error::Error>> {
        let mut args = vec![
            "plan",
            "--json",
            "--root",
            "/fixture",
            "--session",
            "session:one",
        ];
        args.extend_from_slice(extra);
        match parse_fss_args(args) {
            Ok(FssCommand::Effect(command)) => match *command {
                crate::effect_cmd::EffectCommand::Mission(args) => Ok(args),
                _ => Err("wrong native plan intent".into()),
            },
            Ok(_) => Err("wrong command".into()),
            Err(error) => Err(error.into()),
        }
    }

    #[test]
    fn context_refusals_preserve_identity_and_possible_durable_progress()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::json_input::{Value, parse};

        let operation = Operation {
            command: COMMAND,
            name: COMMAND,
            capability: CAPABILITY_PLAN_PREPARE,
            payload_schema: CONTROL_PLAN_SCHEMA,
            view: AgentView::DecisionDiff,
            root: PathBuf::from("/unused-pure-envelope-fixture"),
            principal: PrincipalId::parse("principal:mission-refusal-test")?,
            request: b"synthetic mission refusal contract".to_vec(),
        };
        let anchor = fss_core::LedgerAnchor::genesis("site:mission-refusal-test");
        for orient in [
            OrientError::ContextBudgetExceeded {
                view: AgentView::Pulse,
                budget_tokens: 256,
            },
            OrientError::TooManyEvents {
                published: 65,
                maximum: 64,
            },
        ] {
            let error = MissionError::Session(DeploymentSessionError::Orient(orient));
            assert_eq!(error.stable_id(), ERR_AGENT_CONTEXT_INCOMPLETE);
            let refusal = mission_refusal(&error);
            assert_eq!(refusal.error_id, ERR_AGENT_CONTEXT_INCOMPLETE);
            assert_eq!(refusal.recovery_class, "never_unchanged");
            assert_eq!(refusal.safe_retry, ResponseSafeRetry::No);
            let response = parse(&refusal_response(
                &operation,
                &anchor,
                0,
                refusal,
                Some(mission_failure_boundary(None)),
            )?)?;
            let fields = response.object().ok_or("response object")?;
            assert_eq!(
                fields.get("errorId"),
                Some(&Value::Text(ERR_AGENT_CONTEXT_INCOMPLETE.to_owned()))
            );
            let boundary = fields
                .get("executionBoundary")
                .and_then(Value::object)
                .ok_or("execution boundary")?;
            let possible = boundary
                .get("possiblyOccurred")
                .and_then(Value::array)
                .ok_or("possible progress")?;
            assert!(possible.iter().any(|entry| {
                entry
                    .text()
                    .is_some_and(|text| text.contains("mission revision may already be retained"))
            }));
            let not_started = boundary
                .get("notStarted")
                .and_then(Value::array)
                .ok_or("not-started boundary")?;
            assert!(not_started.iter().all(|entry| {
                entry
                    .text()
                    .is_some_and(|text| !text.contains("requested session command"))
            }));
        }
        let digest = ContentDigest::sha256(b"synthetic confirmed retained mission revision");
        let confirmed = mission_failure_boundary(Some((2, digest)));
        assert!(
            confirmed.completed.iter().any(|line| {
                line.contains(&digest.to_text()) && line.contains("durably retained")
            })
        );
        assert!(confirmed.possibly_occurred.is_empty());
        assert!(
            confirmed
                .not_started
                .iter()
                .all(|line| { !line.contains("requested session command") })
        );
        let corrupt = MissionError::Session(DeploymentSessionError::StoreInvalid(
            "synthetic invalid journal".to_owned(),
        ));
        let refusal = mission_refusal(&corrupt);
        assert_eq!(refusal.error_id, "ERR-AGENT-SESSION-STORE-INVALID-001");
        assert_eq!(refusal.recovery_class, "operator_action_required");
        Ok(())
    }

    #[test]
    fn mission_actions_require_exact_explicit_scope_and_preserve_full_deadline_precision()
    -> Result<(), Box<dyn std::error::Error>> {
        let parsed = parse(&[
            "--mission-bind",
            "plan:one",
            "--mission-deadline-ns",
            "170141183460469231731687303715884105727",
        ])?;
        assert!(matches!(
            parsed.action,
            MissionAction::Adopt {
                decision_deadline: TimestampNs(i128::MAX),
                ..
            }
        ));
        let digest = format!("sha256:{}", "11".repeat(32));
        assert!(matches!(
            parse(&[
                "--mission-assess",
                "plan:one",
                "--expected-mission",
                &digest
            ])?
            .action,
            MissionAction::Assess { .. }
        ));
        for args in [
            vec!["--mission-bind", "plan:one"],
            vec!["--mission-assess", "plan:one"],
            vec!["--mission-bind", "plan:one", "--mission-assess", "plan:one"],
            vec!["--mission-bind", "plan:one", "--mission-deadline-ns", "1e9"],
            vec!["--mission-bind", "plan:one", "--mission-deadline-ns", "+12"],
            vec!["--mission-bind", "plan:one", "--mission-deadline-ns", "01"],
            vec![
                "--mission-bind",
                "plan:one",
                "--mission-deadline-ns",
                "12",
                "--expected-mission",
                &digest,
            ],
            vec![
                "--mission-assess",
                "plan:one",
                "--expected-mission",
                &digest,
                "--mission-deadline-ns",
                "12",
            ],
            vec![
                "--mission-assess",
                "plan:one",
                "--expected-mission",
                &digest,
                "--state",
                "resolved",
            ],
            vec![
                "--mission-bind",
                "plan:one",
                "--mission-deadline-ns",
                "12",
                "--close",
                "plan:one",
            ],
            vec![
                "--mission-bind",
                "plan:one",
                "--mission-deadline-ns",
                "12",
                "--approve",
                &digest,
            ],
        ] {
            assert!(parse(&args).is_err(), "{args:?}");
        }
        Ok(())
    }
}
