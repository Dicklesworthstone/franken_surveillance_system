#![forbid(unsafe_code)]
//! The canonical agent effect grammar over a deployment root, answered as the registered
//! `AgentResponseEnvelope`:
//!
//! ```text
//! fss plan   (AOP-007)  compile and publish a witnessed ControlPlan for one alert intent;
//!                       with --approve PLAN_APPROVAL, durably prepare the effect
//! fss commit (AOP-008)  revalidate the published plan and dispatch exactly once under the
//!                       operator's exact dispatch approval
//! fss wait   (AOP-009)  bounded read until the operation leaves its current state
//! fss cancel (AOP-010)  preview, then cancel a still-prepared operation under approval
//! ```
//!
//! **Authority.** A plan is cognition and grants nothing. Preparation needs the operator's exact
//! plan approval digest, and commitment the exact dispatch approval digest (both computed exactly
//! as `fss-event alert` computes them, through [`crate::alert_effect`], so the two surfaces share
//! one operation identity per event revision and relay route). The principal is an audit label,
//! not authentication. Commitment is durable before any network I/O; a lost acknowledgement is
//! recorded as `indeterminate` and is never resent.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    AgentView, BudgetVector, Completeness, ContentDigest, ControlEdge, ControlPlan, ControlStep,
    ControlStepKind, EffectJournal, EffectState, EventId, ExecutionBoundary, KnowledgeState,
    OperationId, OperationReceipt, PrincipalId, ResponseOutcome, ResponseSafeRetry, SessionId,
    StepReversibility, StepRisk, StepRobustness, TimestampNs,
};
use fss_reference::agent_orient::{DeploymentSnapshot, OrientLimits, read_deployment};
use fss_reference::alert_control::{
    AlertControlError, cancel_prepared_alert, preview_alert_cancellation,
};
use fss_reference::alert_reconcile::{
    AlertAttestation, AlertReconcileError, AlertReconciliationOutcome, CAP_ALERT_RECONCILE,
    MAX_RECONCILE_STATEMENT_BYTES, preview_alert_reconciliation, reconcile_alert_operation,
};
use fss_reference::deployment_session::plan::{
    AlertRoute, PlanRecord, PlanningContext, planning_context, publish_plan, read_plan,
};
use fss_reference::webhook::WebhookEndpoint;
use fss_reference::{
    PrepareAlertParams, REFERENCE_ALERT_TERMINAL_PREDICATE, ReferenceAlertPlan,
    ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx,
    committed_reference_policy_action, prepare_reference_alert, rehydrate_reference_alert_plan,
};

use crate::agent_json;
use crate::alert_effect::{
    AlertEffectError, CAP_ALERT_COMMIT, CAP_ALERT_PREPARE, MAX_DEADLINE_MS, alert_identities,
    dispatch_approval_digest, dispatch_prepared_alert, not_eligible, obligation_state,
    outcome_text, plan_approval_digest, wall_ns,
};
use crate::error::{CliError, ExitIdentity};
use crate::orient_cmd::{
    RenderError, ResponseParts, build_response, collect_options, contexts, principal, rendered,
    required_root, take,
};
use crate::session_cmd::{
    ERR_OP_PRECONDITION_FAILED, ERR_OP_TIMEOUT, Operation, Refusal, refuse, refuse_typed,
};
use crate::token::ArgToken;

/// Capability registry row of AOP-007 (`plan`).
pub const CAPABILITY_PLAN_PREPARE: &str = "CAP-AGENT-PLAN-PREPARE-001";
/// Capability registry row of AOP-008 (`commit`).
pub const CAPABILITY_PLAN_COMMIT: &str = "CAP-AGENT-PLAN-COMMIT-001";
/// Capability registry row of AOP-009 (`wait`).
pub const CAPABILITY_SITUATION_READ: &str = "CAP-AGENT-SITUATION-READ-001";
/// Capability registry row of AOP-010 (`cancel`).
pub const CAPABILITY_CANCEL: &str = "CAP-AGENT-CANCEL-001";
/// Response payload schema of `plan`.
pub const CONTROL_PLAN_SCHEMA: &str = "fss.agent_control_plan.v1";
/// Response payload schema of `commit`, `wait`, and `cancel`.
pub const OPERATION_RECEIPT_SCHEMA: &str = "fss.operation_receipt.v1";
/// Registered error identity: the plan's premises no longer hold; replan.
pub const ERR_AGENT_AFFORDANCE_INVALIDATED: &str = "ERR-AGENT-AFFORDANCE-INVALIDATED-001";
/// Registered error identity: the effect outcome is unknown.
pub const ERR_EFFECT_INDETERMINATE: &str = "ERR-EFFECT-INDETERMINATE-001";
/// Largest admitted `wait` deadline.
pub const MAX_WAIT_MS: u64 = 60_000;

/// Options for `fss plan --intent alert`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanArgs {
    /// Existing deployment root.
    pub root: PathBuf,
    /// Session the plan is compiled in.
    pub session: SessionId,
    /// The session's principal (also the approving principal of the plan digests).
    pub principal: PrincipalId,
    /// Event to alert about.
    pub event_id: EventId,
    /// Exact relay socket address.
    pub relay: SocketAddr,
    /// Absolute request path.
    pub path: String,
    /// Owner approval of the plaintext relay.
    pub plaintext_approval: ContentDigest,
    /// Dispatch deadline.
    pub deadline_ms: u64,
    /// Investigation case the plan rests on.
    pub case: Option<String>,
    /// Exact plan approval: durably prepare the effect.
    pub approve: Option<ContentDigest>,
}

/// Options for `fss commit`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitArgs {
    /// Existing deployment root.
    pub root: PathBuf,
    /// Published plan identity.
    pub plan: String,
    /// Committing principal (must be the plan's).
    pub principal: PrincipalId,
    /// Exact dispatch approval digest.
    pub approve: ContentDigest,
}

/// Options for `fss commit --reconcile`: an owner-attested reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconcileArgs {
    /// Existing deployment root.
    pub root: PathBuf,
    /// Dispatched alert operation to reconcile.
    pub operation: OperationId,
    /// Attesting principal.
    pub principal: PrincipalId,
    /// The owner's attestation.
    pub attestation: AlertAttestation,
    /// Exact reconciliation approval (absent: preview only).
    pub approve: Option<ContentDigest>,
}

/// Options for `fss wait`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WaitArgs {
    /// Existing deployment root.
    pub root: PathBuf,
    /// Operation to watch.
    pub operation: OperationId,
    /// Reading principal.
    pub principal: PrincipalId,
    /// Bounded wait.
    pub deadline_ms: u64,
}

/// Options for `fss cancel`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelArgs {
    /// Existing deployment root.
    pub root: PathBuf,
    /// Operation to cancel.
    pub operation: OperationId,
    /// Cancelling principal.
    pub principal: PrincipalId,
    /// Exact cancellation approval (absent: preview only).
    pub approve: Option<ContentDigest>,
}

/// One effect-grammar command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectCommand {
    /// AOP-007 `plan`.
    Plan(PlanArgs),
    /// AOP-008 `commit` of a published plan.
    Commit(CommitArgs),
    /// AOP-008 `commit`, reconcile intent family: owner-attested reconciliation.
    Reconcile(ReconcileArgs),
    /// AOP-009 `wait`.
    Wait(WaitArgs),
    /// AOP-010 `cancel`.
    Cancel(CancelArgs),
}

// ---------------------------------------------------------------------------------------------
// Parsing.
// ---------------------------------------------------------------------------------------------

fn malformed(command: &str, option: &str, value: &str, reason: &str, index: usize) -> CliError {
    CliError::MalformedValue {
        option: option.to_owned(),
        value: value.to_owned(),
        reason: reason.to_owned(),
        command: Some(command.to_owned()),
        index,
    }
}

fn required<'a>(
    command: &str,
    values: &'a [(String, String, usize)],
    option: &str,
    expected: &str,
) -> Result<&'a (String, String, usize), CliError> {
    take(values, option).ok_or_else(|| CliError::MissingValue {
        option: option.to_owned(),
        command: Some(command.to_owned()),
        expected: expected.to_owned(),
    })
}

fn digest_option(
    command: &str,
    values: &[(String, String, usize)],
    option: &str,
) -> Result<Option<ContentDigest>, CliError> {
    take(values, option)
        .map(|(_, raw, index)| {
            ContentDigest::parse(raw).map_err(|_| {
                malformed(
                    command,
                    option,
                    raw,
                    "expected a sha256:<64 hex> digest",
                    *index,
                )
            })
        })
        .transpose()
}

fn deadline(
    command: &str,
    values: &[(String, String, usize)],
    maximum: u64,
) -> Result<u64, CliError> {
    let (_, raw, index) = required(command, values, "--deadline-ms", "1..60000 milliseconds")?;
    match raw.parse::<u64>() {
        Ok(ms) if (1..=maximum).contains(&ms) => Ok(ms),
        _ => Err(malformed(
            command,
            "--deadline-ms",
            raw,
            &format!("deadline must be an integer in 1..={maximum}"),
            *index,
        )),
    }
}

fn operation_id(
    command: &str,
    values: &[(String, String, usize)],
) -> Result<OperationId, CliError> {
    let (_, raw, index) = required(command, values, "--operation", "an operation identity")?;
    OperationId::parse(raw.clone()).map_err(|_| {
        malformed(
            command,
            "--operation",
            raw,
            "operation identity must be 1..128 characters of [A-Za-z0-9._:-]",
            *index,
        )
    })
}

/// Parses `plan --json --root <dir> --session <id> --intent alert ...`.
pub fn parse_plan_args(tokens: &[ArgToken]) -> Result<PlanArgs, CliError> {
    const COMMAND: &str = "plan";
    let values = collect_options(
        COMMAND,
        tokens,
        &[
            "--root",
            "--session",
            "--principal",
            "--intent",
            "--event-id",
            "--relay",
            "--path",
            "--plaintext-approval",
            "--deadline-ms",
            "--case",
            "--approve",
        ],
    )?;
    let root = required_root(COMMAND, &values)?;
    let (_, raw, index) = required(COMMAND, &values, "--session", "the session identity")?;
    let session = SessionId::parse(raw.clone()).map_err(|_| {
        malformed(
            COMMAND,
            "--session",
            raw,
            "session identity must be 1..128 characters of [A-Za-z0-9._:-]",
            *index,
        )
    })?;
    let (_, intent, index) = required(COMMAND, &values, "--intent", "alert")?;
    if intent != "alert" {
        return Err(malformed(
            COMMAND,
            "--intent",
            intent,
            "the only implemented intent family is alert (one webhook for one corroborated \
             event over an owner-approved relay)",
            *index,
        ));
    }
    let (_, raw, index) = required(COMMAND, &values, "--event-id", "an event identity")?;
    let event_id = EventId::parse(raw.clone())
        .map_err(|_| malformed(COMMAND, "--event-id", raw, "invalid event identity", *index))?;
    let (_, raw, index) = required(COMMAND, &values, "--relay", "an exact IP:PORT")?;
    let relay = raw.parse::<SocketAddr>().map_err(|_| {
        malformed(
            COMMAND,
            "--relay",
            raw,
            "relay must be an exact IP:PORT socket address (no DNS)",
            *index,
        )
    })?;
    let (_, path, _) = required(COMMAND, &values, "--path", "an absolute request path")?;
    let plaintext_approval =
        digest_option(COMMAND, &values, "--plaintext-approval")?.ok_or_else(|| {
            CliError::MissingValue {
                option: "--plaintext-approval".to_owned(),
                command: Some(COMMAND.to_owned()),
                expected: "the owner's sha256 approval of the plaintext relay".to_owned(),
            }
        })?;
    let case = match take(&values, "--case") {
        None => None,
        Some((_, raw, index)) => {
            if raw.is_empty()
                || raw.len() > 128
                || !raw.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
                })
            {
                return Err(malformed(
                    COMMAND,
                    "--case",
                    raw,
                    "case identity must be 1..128 characters of [A-Za-z0-9._:-]",
                    *index,
                ));
            }
            Some(raw.clone())
        }
    };
    Ok(PlanArgs {
        root,
        session,
        principal: principal(COMMAND, &values)?,
        event_id,
        relay,
        path: path.clone(),
        plaintext_approval,
        deadline_ms: deadline(COMMAND, &values, MAX_DEADLINE_MS)?,
        case,
        approve: digest_option(COMMAND, &values, "--approve")?,
    })
}

/// Parses `commit --json --root <dir> --plan <id> --approve <digest>` (dispatch), or
/// `commit --json --root <dir> --reconcile <outcome> --operation <id> --evidence <digest>
/// --statement <text> [--approve <digest>]` (owner-attested reconciliation).
pub fn parse_commit_args(tokens: &[ArgToken]) -> Result<EffectCommand, CliError> {
    const COMMAND: &str = "commit";
    let values = collect_options(
        COMMAND,
        tokens,
        &[
            "--root",
            "--plan",
            "--principal",
            "--approve",
            "--reconcile",
            "--operation",
            "--evidence",
            "--statement",
        ],
    )?;
    let root = required_root(COMMAND, &values)?;
    if let Some((_, raw, index)) = take(&values, "--reconcile") {
        if let Some((name, _, index)) = take(&values, "--plan") {
            return Err(CliError::UnknownOption {
                option: name.clone(),
                command: Some("commit --reconcile".to_owned()),
                index: *index,
            });
        }
        let outcome = match raw.as_str() {
            "delivered" => AlertReconciliationOutcome::Delivered,
            "not_delivered" => AlertReconciliationOutcome::NotDelivered,
            _ => {
                return Err(malformed(
                    COMMAND,
                    "--reconcile",
                    raw,
                    "reconciliation outcome must be delivered or not_delivered",
                    *index,
                ));
            }
        };
        let evidence = digest_option(COMMAND, &values, "--evidence")?.ok_or_else(|| {
            CliError::MissingValue {
                option: "--evidence".to_owned(),
                command: Some(COMMAND.to_owned()),
                expected: "the digest of the owner's delivery evidence".to_owned(),
            }
        })?;
        let (_, statement, index) = required(
            COMMAND,
            &values,
            "--statement",
            "the owner's attestation statement",
        )?;
        if statement.len() > MAX_RECONCILE_STATEMENT_BYTES {
            return Err(malformed(
                COMMAND,
                "--statement",
                statement,
                &format!("the statement must be at most {MAX_RECONCILE_STATEMENT_BYTES} bytes"),
                *index,
            ));
        }
        return Ok(EffectCommand::Reconcile(ReconcileArgs {
            root,
            operation: operation_id(COMMAND, &values)?,
            principal: principal(COMMAND, &values)?,
            attestation: AlertAttestation {
                outcome,
                evidence,
                statement: statement.clone(),
            },
            approve: digest_option(COMMAND, &values, "--approve")?,
        }));
    }
    for option in ["--operation", "--evidence", "--statement"] {
        if let Some((name, _, index)) = take(&values, option) {
            return Err(CliError::UnknownOption {
                option: name.clone(),
                command: Some("commit --plan".to_owned()),
                index: *index,
            });
        }
    }
    let (_, plan, index) = required(COMMAND, &values, "--plan", "a published plan identity")?;
    if !plan.starts_with("plan:") || plan.len() > 128 {
        return Err(malformed(
            COMMAND,
            "--plan",
            plan,
            "plan identity must be the `plan:<hex>` identity `fss plan` returned",
            *index,
        ));
    }
    let approve =
        digest_option(COMMAND, &values, "--approve")?.ok_or_else(|| CliError::MissingValue {
            option: "--approve".to_owned(),
            command: Some(COMMAND.to_owned()),
            expected: "the operator's exact dispatch approval digest".to_owned(),
        })?;
    Ok(EffectCommand::Commit(CommitArgs {
        root,
        plan: plan.clone(),
        principal: principal(COMMAND, &values)?,
        approve,
    }))
}

/// Parses `wait --json --root <dir> --operation <id> --deadline-ms <n>`.
pub fn parse_wait_args(tokens: &[ArgToken]) -> Result<WaitArgs, CliError> {
    const COMMAND: &str = "wait";
    let values = collect_options(
        COMMAND,
        tokens,
        &["--root", "--operation", "--principal", "--deadline-ms"],
    )?;
    Ok(WaitArgs {
        root: required_root(COMMAND, &values)?,
        operation: operation_id(COMMAND, &values)?,
        principal: principal(COMMAND, &values)?,
        deadline_ms: deadline(COMMAND, &values, MAX_WAIT_MS)?,
    })
}

/// Parses `cancel --json --root <dir> --operation <id> [--approve <digest>]`.
pub fn parse_cancel_args(tokens: &[ArgToken]) -> Result<CancelArgs, CliError> {
    const COMMAND: &str = "cancel";
    let values = collect_options(
        COMMAND,
        tokens,
        &["--root", "--operation", "--principal", "--approve"],
    )?;
    Ok(CancelArgs {
        root: required_root(COMMAND, &values)?,
        operation: operation_id(COMMAND, &values)?,
        principal: principal(COMMAND, &values)?,
        approve: digest_option(COMMAND, &values, "--approve")?,
    })
}

// ---------------------------------------------------------------------------------------------
// Shared execution helpers.
// ---------------------------------------------------------------------------------------------

/// A rendered answer (or a render failure) and its exit identity.
type Answered = (Result<String, Box<dyn std::error::Error>>, ExitIdentity);

/// Failures of an effect command before an answer can be rendered.
enum Failure {
    /// A typed refusal (exit 5), or an indeterminate outcome (exit 1).
    Typed(Refusal, ExitIdentity),
    /// An agent-plane refusal classified by the session command.
    Session(fss_reference::deployment_session::DeploymentSessionError),
    /// Anything else: an internal failure, never a partial answer.
    Internal,
}

impl From<fss_reference::deployment_session::DeploymentSessionError> for Failure {
    fn from(error: fss_reference::deployment_session::DeploymentSessionError) -> Self {
        Self::Session(error)
    }
}

fn alert_refusal(error: &AlertEffectError) -> Failure {
    let (guidance, recovery_class, safe_retry, exit) = match error {
        AlertEffectError::Route => (
            "Name an exact literal IP:PORT relay, a plain absolute path, and a nonzero owner \
             plaintext approval.",
            "never_unchanged",
            ResponseSafeRetry::No,
            ExitIdentity::AGENT_REFUSED,
        ),
        AlertEffectError::Authority(_) => (
            "The event is absent or its authority does not verify; orient and replan.",
            "refresh_and_retry",
            ResponseSafeRetry::YesAfterRefresh,
            ExitIdentity::AGENT_REFUSED,
        ),
        AlertEffectError::NotEligible(_) => (
            "Policy, corroboration, or sensor-integrity gates refuse an alert for this event; \
             investigate instead.",
            "never_unchanged",
            ResponseSafeRetry::No,
            ExitIdentity::AGENT_REFUSED,
        ),
        AlertEffectError::StaleApproval(_) => (
            "The approval does not match the current plan or prepared operation: review the \
             current plan and approve its exact digest.",
            "refresh_and_retry",
            ResponseSafeRetry::YesAfterRefresh,
            ExitIdentity::AGENT_REFUSED,
        ),
        AlertEffectError::Clock => (
            "The host clock is unavailable or behind the effect journal.",
            "operator_action_required",
            ResponseSafeRetry::No,
            ExitIdentity::AGENT_REFUSED,
        ),
        AlertEffectError::Dispatch(_) => (
            "The effect journal or webhook owner refused before any network I/O.",
            "operator_action_required",
            ResponseSafeRetry::No,
            ExitIdentity::AGENT_REFUSED,
        ),
        AlertEffectError::Indeterminate => (
            "The outcome is unknown: reconcile before any retry; never resend.",
            "reconciliation_required",
            ResponseSafeRetry::YesAfterReconcile,
            ExitIdentity::RUNTIME_FAILURE,
        ),
    };
    Failure::Typed(
        Refusal {
            error_id: error.stable_id(),
            reason: error.to_string(),
            guidance,
            recovery_class,
            safe_retry,
        },
        exit,
    )
}

fn control_refusal(error: &AlertControlError) -> Failure {
    Failure::Typed(
        Refusal {
            error_id: error.stable_id(),
            reason: error.to_string(),
            guidance: "Only a still-prepared alert operation can be cancelled, under the exact \
                       approval its preview returned; a committed or indeterminate operation \
                       needs reconciliation, never cancellation.",
            recovery_class: "operator_action_required",
            safe_retry: ResponseSafeRetry::No,
        },
        ExitIdentity::AGENT_REFUSED,
    )
}

fn precondition(reason: String, guidance: &'static str) -> Failure {
    Failure::Typed(
        Refusal {
            error_id: ERR_OP_PRECONDITION_FAILED,
            reason,
            guidance,
            recovery_class: "operator_action_required",
            safe_retry: ResponseSafeRetry::No,
        },
        ExitIdentity::AGENT_REFUSED,
    )
}

fn snapshot(root: &Path) -> Result<DeploymentSnapshot, Failure> {
    read_deployment(root, &OrientLimits::default()).map_err(|error| {
        Failure::Session(fss_reference::deployment_session::DeploymentSessionError::Read(error))
    })
}

/// Opens the deployment under a root authority holding exactly `capabilities`.
fn open_deployment(
    root: &Path,
    site: &str,
    principal: &PrincipalId,
    capabilities: &[&str],
) -> Result<(ReferenceDeployment, ContextAuthority, ReplayCx), Failure> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:agent-effect".into(),
        operation_id: OperationId::parse("operation:agent-effect")
            .map_err(|_| Failure::Internal)?,
        principal: principal.as_str().to_owned(),
        capabilities: std::iter::once("ADP-REPLAY-001")
            .chain(capabilities.iter().copied())
            .map(ToOwned::to_owned)
            .collect(),
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(8192)
            .build()
            .map_err(|_| Failure::Internal)?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(site.as_bytes()),
        generation: 1,
    })
    .map_err(|_| Failure::Internal)?;
    let cx = ReplayCx::from_context_authority(&authority, root.to_path_buf())
        .map_err(|_| Failure::Internal)?;
    match ReferenceDeployment::open(root, site, &cx) {
        Ok(deployment) => Ok((deployment, authority, cx)),
        Err(error) if error.is_deployment_locked() => Err(Failure::Typed(
            Refusal {
                error_id: ERR_OP_PRECONDITION_FAILED,
                reason: "another command holds the deployment".to_owned(),
                guidance: "Retry after the other deployment command finishes.",
                recovery_class: "backoff",
                safe_retry: ResponseSafeRetry::YesSameRequest,
            },
            ExitIdentity::AGENT_REFUSED,
        )),
        Err(error) => Err(alert_refusal(&AlertEffectError::Authority(error))),
    }
}

fn delivery_claim(state: EffectState) -> &'static str {
    match state {
        EffectState::AdapterAccepted => "relay_acceptance_only",
        EffectState::Committed | EffectState::Indeterminate => "indeterminate",
        EffectState::Verified => "verified",
        EffectState::Failed => "failed",
        EffectState::Cancelled => "cancelled_not_sent",
        _ => "not_dispatched",
    }
}

fn effect_boundary(
    completed: Vec<String>,
    not_started: Vec<String>,
    possibly_occurred: Vec<String>,
    preserved_truth: Vec<String>,
) -> ExecutionBoundary {
    ExecutionBoundary {
        completed,
        not_started,
        possibly_occurred,
        preserved_truth,
        invalidated: Vec::new(),
    }
}

/// An operation-receipt answer at the deployment's committed anchor (commit, wait, cancel).
struct ReceiptAnswer<'a> {
    operation: &'static str,
    capability: &'static str,
    principal: &'a PrincipalId,
    session: Option<(&'a SessionId, &'a fss_core::MissionId)>,
    snapshot: &'a DeploymentSnapshot,
    receipt: &'a OperationReceipt,
    outcome: ResponseOutcome,
    error_id: Option<&'static str>,
    degradation: Vec<String>,
    proof_pointers: Vec<String>,
    request_digest: ContentDigest,
    recovery_class: &'static str,
    safe_retry: ResponseSafeRetry,
    boundary: ExecutionBoundary,
    idempotency_key: Option<String>,
}

fn receipt_response(answer: ReceiptAnswer<'_>) -> Result<String, Box<dyn std::error::Error>> {
    let mut degradation = answer.degradation;
    degradation.push(format!(
        "Operation {} is {}: delivery claim {}. No affordance is listed by this answer; \
         `fss wait`, `fss cancel` (prepared only), or `fss session orient` give the next moves.",
        answer.receipt.intent.operation_id,
        answer.receipt.state.as_str(),
        delivery_claim(answer.receipt.state)
    ));
    let epistemic_state = match answer.receipt.state {
        EffectState::Verified | EffectState::Failed | EffectState::Cancelled => {
            KnowledgeState::Known
        }
        EffectState::Prepared => KnowledgeState::Unknown,
        _ => KnowledgeState::Indeterminate,
    };
    build_response(ResponseParts {
        operation: answer.operation,
        request_digest: answer.request_digest,
        principal: answer.principal.clone(),
        session_id: answer.session.map(|(id, _)| id.as_str().to_owned()),
        mission_id: answer
            .session
            .map(|(_, mission)| mission.as_str().to_owned()),
        anchor: answer.snapshot.anchor.clone(),
        view: AgentView::Operation,
        capability: answer.capability,
        outcome: answer.outcome,
        error_id: answer.error_id,
        payload_schema: OPERATION_RECEIPT_SCHEMA,
        payload_json: answer.receipt.to_canonical_json(),
        epistemic_state,
        completeness: Completeness::Partial,
        warnings: Vec::new(),
        contradictions: Vec::new(),
        degradation,
        budgets_json: agent_json::budget_summary(&BudgetVector::ZERO, &BudgetVector::ZERO),
        proof_pointers: answer.proof_pointers,
        affordances: Vec::new(),
        affordance_objects: Vec::new(),
        decision_fingerprint: answer.receipt.receipt_digest(),
        compression_receipt_id: None,
        continuation: None,
        recovery_class: answer.recovery_class,
        safe_retry: answer.safe_retry,
        boundary: answer.boundary,
        created_at_ns: answer.snapshot.latest_evidence_time.0,
        workspace_revision: None,
        idempotency_key: answer.idempotency_key,
    })
}

fn finish(
    result: Result<Result<String, Box<dyn std::error::Error>>, Failure>,
    exit: ExitIdentity,
    operation: &Operation,
) -> (String, ExitIdentity) {
    match result {
        Ok(rendered_answer) => rendered(rendered_answer, exit, operation.command, &operation.root),
        Err(Failure::Typed(refusal, exit)) => refuse_typed(operation, refusal, exit),
        Err(Failure::Session(error)) => refuse(operation, error),
        Err(Failure::Internal) => {
            crate::orient_cmd::internal_failure(operation.command, &operation.root)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// plan (AOP-007)
// ---------------------------------------------------------------------------------------------

/// World identities of the session's envelope an alert serves (activity) and those in which it
/// is a false alarm (artifacts).
fn alert_worlds(context: &PlanningContext) -> (Vec<String>, Vec<String>) {
    let envelope = &context.orientation.capsule().frame.world_envelope;
    let mut supported = Vec::new();
    let mut unsafe_worlds = Vec::new();
    for world in envelope
        .alternatives
        .iter()
        .chain(&envelope.adversarial_residuals)
    {
        let id = world.world_id.as_str();
        if id.contains("artifact") {
            unsafe_worlds.push(id.to_owned());
        } else if id.contains("activity") && !id.contains("unobserved") {
            supported.push(id.to_owned());
        }
    }
    (supported, unsafe_worlds)
}

struct PlanFacts<'a> {
    args: &'a PlanArgs,
    context: &'a PlanningContext,
    plan: &'a ReferenceAlertPlan,
    endpoint: &'a WebhookEndpoint,
    event_state: &'a str,
    plan_approval: ContentDigest,
    plan_id: &'a str,
}

fn step(step_id: &str, kind: ControlStepKind, owner: &str, verb: String) -> ControlStep {
    ControlStep {
        step_id: step_id.to_owned(),
        kind,
        owner: owner.to_owned(),
        verb,
        robustness_class: StepRobustness::InformationGathering,
        supported_world_ids: Vec::new(),
        unsafe_world_ids: Vec::new(),
        preconditions: Vec::new(),
        read_witnesses: Vec::new(),
        write_witnesses: Vec::new(),
        negative_witnesses: Vec::new(),
        required_capabilities: Vec::new(),
        budget_json: "{}".to_owned(),
        expected_information_gain: 0.0,
        expected_objective_gain: 0.0,
        risk: StepRisk::None,
        privacy_exposure: 0.0,
        reversibility: StepReversibility::ReadOnly,
        success_transition: Vec::new(),
        failure_transition: Vec::new(),
        cancel_transition: Vec::new(),
        indeterminate_transition: Vec::new(),
        terminal_proof: Vec::new(),
    }
}

/// The witnessed contingent DAG of one alert intent.
fn compile_alert_plan(facts: &PlanFacts<'_>) -> Result<ControlPlan, Box<dyn std::error::Error>> {
    let capsule = facts.context.orientation.capsule();
    let (supported, unsafe_worlds) = alert_worlds(facts.context);
    let operation = facts.plan.intent.operation_id.as_str().to_owned();
    let obligation = facts.plan.obligation_id.as_str().to_owned();
    let event = facts.args.event_id.as_str();
    let mut observe = step(
        "step:observe-event",
        ControlStepKind::Observe,
        "fss-event",
        format!("Read event {event}'s current revision, tamper witnesses, and policy action."),
    );
    observe.read_witnesses = vec![
        facts.plan.event_revision_digest.to_text(),
        facts.plan.event_root.to_text(),
    ];
    observe.preconditions = vec![format!(
        "Event {event} is still at revision {} (any newer revision invalidates this plan).",
        facts.plan.event_revision_digest
    )];
    observe.success_transition = vec!["step:decide-policy".to_owned()];
    observe.failure_transition = vec!["replan".to_owned()];
    let mut decide = step(
        "step:decide-policy",
        ControlStepKind::Decide,
        "fss-policy",
        format!(
            "Admit the alert only while the committed policy action is prepare_alert (event state \
             {}, independently corroborated, no sensor-integrity risk).",
            facts.event_state
        ),
    );
    decide.robustness_class = StepRobustness::NotApplicable;
    decide.success_transition = vec!["step:prepare".to_owned()];
    decide.failure_transition = vec!["abstain".to_owned()];
    let mut prepare = step(
        "step:prepare",
        ControlStepKind::PrepareEffect,
        "fss-effect",
        format!(
            "Durably prepare {operation} (alert.dispatch, one idempotency key, obligation \
             {obligation}) in the effect journal."
        ),
    );
    prepare.robustness_class = StepRobustness::NotApplicable;
    prepare.preconditions = vec![format!(
        "Operator approval of exactly this plan: {}.",
        facts.plan_approval
    )];
    prepare.required_capabilities = vec![CAP_ALERT_PREPARE.to_owned()];
    prepare.write_witnesses = vec![operation.clone(), obligation.clone()];
    prepare.reversibility = StepReversibility::Compensatable;
    prepare.risk = StepRisk::Low;
    prepare.success_transition = vec!["step:commit".to_owned()];
    prepare.cancel_transition = vec!["cancelled_before_dispatch".to_owned()];
    let mut commit = step(
        "step:commit",
        ControlStepKind::CommitEffect,
        "fss-effect",
        format!(
            "Commit {operation} durably, then send exactly one plaintext webhook POST to {}{} \
             (route {}); never retried.",
            facts.args.relay,
            facts.args.path,
            facts.endpoint.digest()
        ),
    );
    commit.robustness_class = if supported.is_empty() {
        StepRobustness::NotApplicable
    } else {
        StepRobustness::ConditionalOnNamedWorlds
    };
    commit.supported_world_ids = supported;
    commit.unsafe_world_ids = unsafe_worlds;
    commit.preconditions = vec![
        "The operation is still prepared (no second commit).".to_owned(),
        "The event revision and policy action are unchanged (revalidated at commit).".to_owned(),
        "Operator approval of the exact dispatch (prepared record, route, deadline, principal)."
            .to_owned(),
    ];
    commit.required_capabilities = vec![
        CAPABILITY_PLAN_COMMIT.to_owned(),
        CAP_ALERT_COMMIT.to_owned(),
    ];
    commit.write_witnesses = vec![operation.clone()];
    commit.budget_json = format!(
        "{{\"latencyMs\":{},\"networkBytes\":4096}}",
        facts.args.deadline_ms
    );
    commit.risk = StepRisk::High;
    commit.reversibility = StepReversibility::Irreversible;
    commit.success_transition = vec!["step:record".to_owned()];
    commit.failure_transition = vec!["step:record".to_owned()];
    commit.indeterminate_transition = vec!["step:reconcile".to_owned()];
    let mut record = step(
        "step:record",
        ControlStepKind::WaitFor,
        "fss-effect",
        "Record the local observation: a complete 2xx head is adapter_accepted (relay \
         acceptance only, never human delivery); anything else is indeterminate."
            .to_owned(),
    );
    record.robustness_class = StepRobustness::WaitAndWatch;
    record.success_transition = vec!["step:reconcile".to_owned()];
    record.indeterminate_transition = vec!["step:reconcile".to_owned()];
    let mut reconcile = step(
        "step:reconcile",
        ControlStepKind::Verify,
        "fss-obligation",
        format!(
            "Discharge obligation {obligation} only by independent reconciliation: \"{}\".",
            REFERENCE_ALERT_TERMINAL_PREDICATE
        ),
    );
    reconcile.robustness_class = StepRobustness::WaitAndWatch;
    reconcile.terminal_proof = vec![REFERENCE_ALERT_TERMINAL_PREDICATE.to_owned()];
    reconcile.negative_witnesses = vec![
        "No provider lookup exists for webhook relays in this build: the obligation stays \
         pending or indeterminate until an operator reconciles it."
            .to_owned(),
    ];
    let edge = |from: &str, to: &str, condition: &str, priority: i64| ControlEdge {
        from: from.to_owned(),
        to: to.to_owned(),
        condition: condition.to_owned(),
        priority,
    };
    let edges = vec![
        edge(
            "step:observe-event",
            "step:decide-policy",
            "revision current",
            0,
        ),
        edge(
            "step:decide-policy",
            "step:prepare",
            "policy action prepare_alert",
            0,
        ),
        edge(
            "step:prepare",
            "step:commit",
            "operator dispatch approval",
            0,
        ),
        edge("step:commit", "step:record", "attempt finished", 0),
        edge("step:commit", "step:reconcile", "outcome indeterminate", 1),
        edge("step:record", "step:reconcile", "observation recorded", 0),
    ];
    let mut plan_budget = BudgetVector::builder()
        .network_bytes(4096)
        .latency_ms(facts.args.deadline_ms)
        .build()
        .map_err(|_| RenderError("plan budget"))?;
    plan_budget.storage_operations = 16;
    Ok(ControlPlan::compile(
        facts.plan_id,
        capsule.frame.objective_id.clone(),
        capsule.anchor.clone(),
        capsule.frame.frame_digest()?.to_text(),
        capsule.frame.world_envelope.envelope_digest()?,
        facts
            .context
            .case
            .as_ref()
            .map(|case| case.digest().to_text()),
        facts.context.session.capabilities.iter().cloned().collect(),
        plan_budget,
        vec![observe, decide, prepare, commit, record, reconcile],
        edges,
        vec!["step:observe-event".to_owned()],
        vec![REFERENCE_ALERT_TERMINAL_PREDICATE.to_owned()],
        facts.plan_approval.to_text(),
    )?)
}

fn strings_json(values: &[String]) -> String {
    agent_json::strings(values)
}

fn number(value: f64) -> String {
    if value.is_finite() && value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{value:.0}")
    } else {
        format!("{value}")
    }
}

/// One control plan as `fss.agent_control_plan.v1`.
#[must_use]
pub fn control_plan_json(plan: &ControlPlan) -> String {
    let steps: Vec<String> = plan
        .steps
        .iter()
        .map(|step| {
            agent_json::object(&[
                ("stepId", agent_json::string(&step.step_id)),
                ("kind", agent_json::string(step.kind.as_str())),
                ("owner", agent_json::string(&step.owner)),
                ("verb", agent_json::string(&step.verb)),
                (
                    "robustnessClass",
                    agent_json::string(step.robustness_class.as_str()),
                ),
                ("supportedWorldIds", strings_json(&step.supported_world_ids)),
                ("unsafeWorldIds", strings_json(&step.unsafe_world_ids)),
                ("preconditions", strings_json(&step.preconditions)),
                ("readWitnesses", strings_json(&step.read_witnesses)),
                ("writeWitnesses", strings_json(&step.write_witnesses)),
                ("negativeWitnesses", strings_json(&step.negative_witnesses)),
                (
                    "requiredCapabilities",
                    strings_json(&step.required_capabilities),
                ),
                ("budget", step.budget_json.clone()),
                (
                    "expectedInformationGain",
                    number(step.expected_information_gain),
                ),
                (
                    "expectedObjectiveGain",
                    number(step.expected_objective_gain),
                ),
                ("risk", agent_json::string(step.risk.as_str())),
                ("privacyExposure", number(step.privacy_exposure)),
                (
                    "reversibility",
                    agent_json::string(step.reversibility.as_str()),
                ),
                ("successTransition", strings_json(&step.success_transition)),
                ("failureTransition", strings_json(&step.failure_transition)),
                ("cancelTransition", strings_json(&step.cancel_transition)),
                (
                    "indeterminateTransition",
                    strings_json(&step.indeterminate_transition),
                ),
                ("terminalProof", strings_json(&step.terminal_proof)),
            ])
        })
        .collect();
    let edges: Vec<String> = plan
        .edges
        .iter()
        .map(|edge| {
            agent_json::object(&[
                ("from", agent_json::string(&edge.from)),
                ("to", agent_json::string(&edge.to)),
                ("condition", agent_json::string(&edge.condition)),
                ("priority", edge.priority.to_string()),
            ])
        })
        .collect();
    agent_json::object(&[
        ("schema", agent_json::string(CONTROL_PLAN_SCHEMA)),
        (
            "contractBasis",
            agent_json::contract_basis(&fss_core::reference_contract_basis()),
        ),
        ("planId", agent_json::string(&plan.plan_id)),
        ("objectiveId", agent_json::string(&plan.objective_id)),
        (
            "basisAnchor",
            agent_json::evidence_anchor(&plan.basis_anchor),
        ),
        (
            "situationFrameDigest",
            agent_json::string(&plan.situation_frame_digest),
        ),
        (
            "worldEnvelopeDigest",
            agent_json::string(&plan.world_envelope_digest.to_text()),
        ),
        (
            "hypothesisWorkspaceDigest",
            agent_json::optional_string(plan.hypothesis_workspace_digest.as_deref()),
        ),
        (
            "capabilityProjection",
            strings_json(&plan.capability_projection),
        ),
        ("budget", agent_json::budget(&plan.budget)),
        ("steps", agent_json::array(&steps)),
        ("edges", agent_json::array(&edges)),
        ("entrySteps", strings_json(&plan.entry_steps)),
        (
            "terminalPredicates",
            strings_json(&plan.terminal_predicates),
        ),
        ("decisionDigest", agent_json::string(&plan.decision_digest)),
    ])
}

fn plan_answer(args: &PlanArgs) -> Result<Result<String, Box<dyn std::error::Error>>, Failure> {
    let context = planning_context(
        &args.root,
        &args.principal,
        &args.session,
        args.case.as_deref(),
    )?;
    if !context
        .session
        .capabilities
        .contains(CAPABILITY_PLAN_PREPARE)
    {
        return Err(Failure::Typed(
            Refusal {
                error_id: crate::session_cmd::ERR_AUTH_DENIED,
                reason: format!("the session lacks {CAPABILITY_PLAN_PREPARE}"),
                guidance: "Open a new session: sessions are negotiated with the plan grant.",
                recovery_class: "operator_action_required",
                safe_retry: ResponseSafeRetry::No,
            },
            ExitIdentity::AGENT_REFUSED,
        ));
    }
    let principal_label = args.principal.as_str();
    let (mut deployment, _authority, cx) = open_deployment(
        &args.root,
        &context.site_lineage,
        &args.principal,
        &[CAP_ALERT_PREPARE],
    )?;
    let result = (|| -> Result<Result<String, Box<dyn std::error::Error>>, Failure> {
        let endpoint = WebhookEndpoint::new(args.relay, &args.path, args.plaintext_approval)
            .map_err(|_| alert_refusal(&AlertEffectError::Route))?;
        let (event, receipt) = deployment
            .current_event_authority(&args.event_id)
            .map_err(|error| alert_refusal(&AlertEffectError::Authority(error)))?;
        let policy_action = committed_reference_policy_action(&event);
        let decision = ReferencePolicyDecision {
            event: event.clone(),
            action: policy_action,
        };
        let ids = alert_identities(receipt.event_revision_digest, endpoint.digest())
            .map_err(|_| Failure::Internal)?;
        let existing = deployment.effects().operation(&ids.operation).cloned();
        let now = TimestampNs(i128::from(
            wall_ns().map_err(|error| alert_refusal(&error))?,
        ));
        let (plan, prepared_now) = match &existing {
            None => {
                let plan = prepare_reference_alert(
                    PrepareAlertParams {
                        decision: &decision,
                        event_receipt: &receipt,
                        authority: deployment.ledger(),
                        operation_id: ids.operation.clone(),
                        idempotency_key: ids.idempotency.clone(),
                        obligation_id: ids.obligation.clone(),
                        channel: endpoint.channel().to_owned(),
                        now,
                    },
                    &mut EffectJournal::new(),
                )
                .map_err(|error| alert_refusal(&not_eligible(error)))?;
                (plan, false)
            }
            Some(operation) => (
                rehydrate_reference_alert_plan(
                    operation,
                    ids.obligation.clone(),
                    &event,
                    &receipt,
                    deployment.ledger(),
                    endpoint.channel(),
                )
                .map_err(|error| alert_refusal(&AlertEffectError::Authority(error)))?,
                false,
            ),
        };
        let approval = plan_approval_digest(&plan, &endpoint, principal_label);
        let mut prepared_now = prepared_now;
        let operation = match (&existing, args.approve) {
            (_, Some(given)) if given != approval => {
                return Err(alert_refusal(&AlertEffectError::StaleApproval(given)));
            }
            (None, Some(_)) => {
                let (journal, ledger) = deployment.effects_and_ledger();
                let prepared = journal
                    .prepare_alert(PrepareAlertParams {
                        decision: &decision,
                        event_receipt: &receipt,
                        authority: ledger,
                        operation_id: ids.operation.clone(),
                        idempotency_key: ids.idempotency.clone(),
                        obligation_id: ids.obligation.clone(),
                        channel: endpoint.channel().to_owned(),
                        now,
                    })
                    .map_err(|error| {
                        alert_refusal(&AlertEffectError::Dispatch(error.to_string()))
                    })?;
                if plan_approval_digest(&prepared, &endpoint, principal_label) != approval {
                    return Err(alert_refusal(&AlertEffectError::StaleApproval(approval)));
                }
                prepared_now = true;
                journal.operation(&ids.operation).cloned()
            }
            (existing, _) => existing.clone(),
        };
        let dispatch = operation
            .as_ref()
            .filter(|operation| operation.state == EffectState::Prepared)
            .map(|operation| {
                dispatch_approval_digest(approval, operation, args.deadline_ms, principal_label)
            });
        let anchor_token = context.orientation.anchor_token.clone();
        let plan_id = PlanRecord::identity(&context.session.session_id, &anchor_token, approval);
        let event_state = event.state.as_str();
        let control = compile_alert_plan(&PlanFacts {
            args,
            context: &context,
            plan: &plan,
            endpoint: &endpoint,
            event_state,
            plan_approval: approval,
            plan_id: &plan_id,
        })
        .map_err(|_| Failure::Internal)?;
        let control_json = control_plan_json(&control);
        let record = PlanRecord {
            plan_id: plan_id.clone(),
            session_id: context.session.session_id.clone(),
            mission_id: context.session.mission_id.clone(),
            principal: args.principal.clone(),
            anchor_token: anchor_token.clone(),
            intent: "alert".to_owned(),
            event_id: args.event_id.as_str().to_owned(),
            event_revision: receipt.event_revision_digest,
            route: AlertRoute {
                relay: args.relay.to_string(),
                path: args.path.clone(),
                plaintext_approval: args.plaintext_approval,
                deadline_ms: args.deadline_ms,
            },
            operation_id: ids.operation.as_str().to_owned(),
            obligation_id: ids.obligation.as_str().to_owned(),
            plan_approval: approval,
            control_plan_digest: ContentDigest::sha256(control_json.as_bytes()),
            case: context
                .case
                .as_ref()
                .map(|case| (case.record().investigation_id.clone(), case.digest())),
            // The situation time of the anchor the plan binds: stable for that anchor, so a
            // replan of the same intent there is an exact retry even after evidence advances.
            created_at: context.orientation.capsule().created_at,
        };
        let plan_root = publish_plan(&args.root, &record, control_json.as_bytes())?;
        let state = operation.as_ref().map(|operation| operation.state);
        let mut completed = vec![format!(
            "Compiled plan {plan_id} for {} and published it root-last (root {plan_root}).",
            ids.operation
        )];
        let mut not_started = Vec::new();
        match (state, dispatch) {
            (None, _) => {
                completed.push(format!(
                    "Nothing was prepared. Operator approval of this exact plan is {approval}; \
                     repeat this command with `--approve {approval}` to durably prepare it."
                ));
                not_started.push("Preparation, commitment, and any network I/O.".to_owned());
            }
            (Some(EffectState::Prepared), Some(dispatch)) => {
                completed.push(format!(
                    "{} {} with obligation {} in the effect journal.",
                    if prepared_now {
                        "Durably prepared"
                    } else {
                        "Found prepared"
                    },
                    ids.operation,
                    ids.obligation
                ));
                completed.push(format!(
                    "Operator approval of the exact dispatch is {dispatch}; commit with \
                     `fss commit --plan {plan_id} --approve {dispatch}`."
                ));
                not_started.push("Commitment and any network I/O.".to_owned());
            }
            (Some(state), _) => {
                completed.push(format!(
                    "{} is already {} (delivery claim {}): this plan will never resend it.",
                    ids.operation,
                    state.as_str(),
                    delivery_claim(state)
                ));
                not_started.push("Any resend.".to_owned());
            }
        }
        let orientation = &context.orientation;
        let capsule = orientation.capsule();
        let (_, affordance_context) = contexts(orientation);
        let affordance_objects = agent_json::affordance_objects(
            &capsule.frame.next,
            &capsule.affordances,
            &affordance_context,
        )
        .ok_or(Failure::Internal)?;
        let mut degradation = orientation.degradation.clone();
        if context.head_moved {
            degradation.push(
                "The deployment head has moved past this session's anchor: the plan binds the \
                 session's situation; hand off and resume to plan at the head."
                    .to_owned(),
            );
        }
        let commit_step = control
            .steps
            .iter()
            .find(|step| step.step_id == "step:commit");
        if let Some(commit_step) = commit_step
            && !commit_step.unsafe_world_ids.is_empty()
        {
            degradation.push(format!(
                "The commit step is conditional: worlds {} remain live, in which the alert is a \
                 false alarm.",
                commit_step.unsafe_world_ids.join(", ")
            ));
        }
        if policy_action != ReferencePolicyAction::PrepareAlert {
            degradation.push(
                "The committed policy action is hold: preparation will be refused.".to_owned(),
            );
        }
        let mut proof_pointers = vec![
            plan_root.to_text(),
            record.control_plan_digest.to_text(),
            approval.to_text(),
            receipt.event_revision_digest.to_text(),
            context.journal_root.to_text(),
            anchor_token,
        ];
        if let Some(dispatch) = dispatch {
            proof_pointers.push(dispatch.to_text());
        }
        let request_digest = crate::orient_cmd::request_identity("fss.cli_agent_plan.v1", |e| {
            e.text(&plan_id);
            e.bool(args.approve.is_some());
        });
        Ok(build_response(ResponseParts {
            operation: "plan",
            request_digest,
            principal: args.principal.clone(),
            session_id: Some(context.session.session_id.as_str().to_owned()),
            mission_id: Some(context.session.mission_id.as_str().to_owned()),
            anchor: capsule.anchor.clone(),
            view: AgentView::DecisionDiff,
            capability: CAPABILITY_PLAN_PREPARE,
            outcome: ResponseOutcome::Ok,
            error_id: None,
            payload_schema: CONTROL_PLAN_SCHEMA,
            payload_json: control_json,
            epistemic_state: orientation.epistemic_state,
            completeness: capsule.completeness,
            warnings: orientation.warnings.clone(),
            contradictions: orientation.contradictions.clone(),
            degradation,
            budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
            proof_pointers,
            affordances: capsule.frame.next.clone(),
            affordance_objects,
            decision_fingerprint: control.plan_digest(),
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
            boundary: effect_boundary(
                completed,
                not_started,
                Vec::new(),
                vec![format!(
                    "{}; the plan grants no effect authority.",
                    if prepared_now {
                        "Only the effect-journal preparation and the agent-plane plan \
                         publication were written"
                    } else {
                        "Only the agent-plane plan publication was written"
                    }
                )],
            ),
            created_at_ns: capsule.created_at.0,
            workspace_revision: None,
            idempotency_key: Some(crate::session_cmd::idempotency_key(request_digest)),
        }))
    })();
    cx.drain_and_finalize();
    result
}

fn execute_plan(args: &PlanArgs) -> (String, ExitIdentity) {
    finish(
        plan_answer(args),
        ExitIdentity::SUCCESS,
        &Operation {
            command: "plan",
            name: "plan",
            capability: CAPABILITY_PLAN_PREPARE,
            payload_schema: CONTROL_PLAN_SCHEMA,
            view: AgentView::DecisionDiff,
            root: args.root.clone(),
            principal: args.principal.clone(),
            request: [
                args.session.as_str().as_bytes(),
                b"\0",
                args.event_id.as_str().as_bytes(),
            ]
            .concat(),
        },
    )
}

// ---------------------------------------------------------------------------------------------
// commit (AOP-008)
// ---------------------------------------------------------------------------------------------

fn commit_answer(args: &CommitArgs) -> Result<Answered, Failure> {
    let (record, plan_root) = read_plan(&args.root, &args.plan)?;
    if record.principal != args.principal {
        return Err(precondition(
            "the committing principal is not the plan's principal".to_owned(),
            "Commit only plans compiled in your own session.",
        ));
    }
    // The plan's session must still be live; its lock is released before any network I/O.
    let context = planning_context(&args.root, &record.principal, &record.session_id, None)?;
    let principal_label = args.principal.as_str();
    let relay: SocketAddr = record.route.relay.parse().map_err(|_| Failure::Internal)?;
    let event_id = EventId::parse(record.event_id.clone()).map_err(|_| Failure::Internal)?;
    let (mut deployment, authority, cx) = open_deployment(
        &args.root,
        &context.site_lineage,
        &args.principal,
        &[CAP_ALERT_PREPARE, CAP_ALERT_COMMIT],
    )?;
    let result = (|| {
        let endpoint =
            WebhookEndpoint::new(relay, &record.route.path, record.route.plaintext_approval)
                .map_err(|_| alert_refusal(&AlertEffectError::Route))?;
        let (event, receipt) = deployment
            .current_event_authority(&event_id)
            .map_err(|error| alert_refusal(&AlertEffectError::Authority(error)))?;
        if receipt.event_revision_digest != record.event_revision {
            return Err(Failure::Typed(
                Refusal {
                    error_id: ERR_AGENT_AFFORDANCE_INVALIDATED,
                    reason: format!(
                        "event {} moved past the revision plan {} was compiled against",
                        record.event_id, record.plan_id
                    ),
                    guidance: "Replan against the current event revision; a plan is never \
                               silently rebased.",
                    recovery_class: "refresh_and_retry",
                    safe_retry: ResponseSafeRetry::YesAfterRefresh,
                },
                ExitIdentity::AGENT_REFUSED,
            ));
        }
        let ids = alert_identities(receipt.event_revision_digest, endpoint.digest())
            .map_err(|_| Failure::Internal)?;
        if ids.operation.as_str() != record.operation_id {
            return Err(Failure::Internal);
        }
        let operation = deployment
            .effects()
            .operation(&ids.operation)
            .cloned()
            .ok_or_else(|| {
                precondition(
                    format!("{} was never prepared", ids.operation),
                    "Prepare first: `fss plan ... --approve <plan approval>`.",
                )
            })?;
        let request_digest = crate::orient_cmd::request_identity("fss.cli_agent_commit.v1", |e| {
            e.text(&record.plan_id);
            e.digest(args.approve);
        });
        let snapshot_now = snapshot(&args.root)?;
        if operation.state != EffectState::Prepared {
            // Report only. Never resend.
            let indeterminate = matches!(
                operation.state,
                EffectState::Committed | EffectState::Indeterminate
            );
            let rendered_answer = receipt_response(ReceiptAnswer {
                operation: "commit",
                capability: CAPABILITY_PLAN_COMMIT,
                principal: &args.principal,
                session: Some((&record.session_id, &record.mission_id)),
                snapshot: &snapshot_now,
                receipt: &operation,
                outcome: if indeterminate {
                    ResponseOutcome::Indeterminate
                } else {
                    ResponseOutcome::Ok
                },
                error_id: indeterminate.then_some(ERR_EFFECT_INDETERMINATE),
                degradation: vec![format!(
                    "{} was already {} before this request: nothing was committed or sent.",
                    ids.operation,
                    operation.state.as_str()
                )],
                proof_pointers: vec![plan_root.to_text(), operation.receipt_digest().to_text()],
                request_digest,
                recovery_class: if indeterminate {
                    "reconciliation_required"
                } else {
                    "never_unchanged"
                },
                safe_retry: ResponseSafeRetry::No,
                boundary: effect_boundary(
                    vec![format!(
                        "Read {} ({}).",
                        ids.operation,
                        operation.state.as_str()
                    )],
                    vec!["Any commit or resend.".to_owned()],
                    Vec::new(),
                    vec!["Nothing was written.".to_owned()],
                ),
                idempotency_key: Some(operation.intent.idempotency_key.as_str().to_owned()),
            });
            return Ok((
                rendered_answer,
                if indeterminate {
                    ExitIdentity::RUNTIME_FAILURE
                } else {
                    ExitIdentity::SUCCESS
                },
            ));
        }
        let plan = rehydrate_reference_alert_plan(
            &operation,
            ids.obligation.clone(),
            &event,
            &receipt,
            deployment.ledger(),
            endpoint.channel(),
        )
        .map_err(|error| alert_refusal(&AlertEffectError::Authority(error)))?;
        let approval = plan_approval_digest(&plan, &endpoint, principal_label);
        if approval != record.plan_approval {
            return Err(alert_refusal(&AlertEffectError::StaleApproval(approval)));
        }
        let dispatch = dispatch_approval_digest(
            approval,
            &operation,
            record.route.deadline_ms,
            principal_label,
        );
        if dispatch != args.approve {
            return Err(alert_refusal(&AlertEffectError::StaleApproval(
                args.approve,
            )));
        }
        let dispatched = dispatch_prepared_alert(
            &mut deployment,
            &plan,
            &endpoint,
            &operation,
            authority.has_capability(CAP_ALERT_COMMIT)
                && authority.principal == args.principal.as_str(),
            record.route.deadline_ms,
            &cx,
        )
        .map_err(|error| alert_refusal(&error))?;
        let obligation = deployment
            .effects()
            .obligation(&ids.obligation)
            .map(|obligation| obligation_state(obligation.state))
            .unwrap_or("absent");
        let accepted = dispatched.accepted();
        let evidence = &dispatched.evidence;
        let observation = format!(
            "Outcome {}: request {} ({} bytes, {} sent, {} I/O calls), commitment root {}.",
            dispatched
                .evidence
                .outcome()
                .map_or_else(|| "unfinished".to_owned(), outcome_text),
            ContentDigest::sha256(evidence.request()),
            evidence.request().len(),
            evidence.sent_bytes(),
            evidence.io_calls(),
            evidence.commitment_root()
        );
        let snapshot_after = snapshot(&args.root)?;
        let rendered_answer = receipt_response(ReceiptAnswer {
            operation: "commit",
            capability: CAPABILITY_PLAN_COMMIT,
            principal: &args.principal,
            session: Some((&record.session_id, &record.mission_id)),
            snapshot: &snapshot_after,
            receipt: &dispatched.recorded,
            outcome: if accepted {
                ResponseOutcome::Ok
            } else {
                ResponseOutcome::Indeterminate
            },
            error_id: (!accepted).then_some(ERR_EFFECT_INDETERMINATE),
            degradation: vec![format!(
                "Obligation {} is {obligation}: a webhook 2xx proves relay acceptance only; the \
                 obligation is discharged only by independent reconciliation.",
                ids.obligation
            )],
            proof_pointers: vec![
                plan_root.to_text(),
                dispatched.recorded.receipt_digest().to_text(),
                evidence.commitment_root().to_text(),
            ],
            request_digest,
            recovery_class: if accepted {
                "never_unchanged"
            } else {
                "reconciliation_required"
            },
            safe_retry: ResponseSafeRetry::No,
            boundary: effect_boundary(
                vec![
                    format!(
                        "Committed {} durably before any network I/O and made one bounded attempt.",
                        ids.operation
                    ),
                    observation,
                ],
                vec!["Any retry or resend.".to_owned()],
                if accepted {
                    Vec::new()
                } else {
                    vec![
                        "The relay may have received and forwarded the alert: the outcome is \
                         recorded as indeterminate and must be reconciled, never resent."
                            .to_owned(),
                    ]
                },
                vec![format!(
                    "Delivery claim {}: no human delivery is inferred.",
                    delivery_claim(dispatched.recorded.state)
                )],
            ),
            idempotency_key: Some(
                dispatched
                    .recorded
                    .intent
                    .idempotency_key
                    .as_str()
                    .to_owned(),
            ),
        });
        Ok((
            rendered_answer,
            if accepted {
                ExitIdentity::SUCCESS
            } else {
                ExitIdentity::RUNTIME_FAILURE
            },
        ))
    })();
    cx.drain_and_finalize();
    result
}

fn execute_commit(args: &CommitArgs) -> (String, ExitIdentity) {
    let operation = Operation {
        command: "commit",
        name: "commit",
        capability: CAPABILITY_PLAN_COMMIT,
        payload_schema: OPERATION_RECEIPT_SCHEMA,
        view: AgentView::Operation,
        root: args.root.clone(),
        principal: args.principal.clone(),
        request: args.plan.as_bytes().to_vec(),
    };
    match commit_answer(args) {
        Ok((answer, exit)) => finish(Ok(answer), exit, &operation),
        Err(failure) => finish(Err(failure), ExitIdentity::SUCCESS, &operation),
    }
}

// ---------------------------------------------------------------------------------------------
// commit --reconcile (AOP-008, reconcile intent family)
// ---------------------------------------------------------------------------------------------

fn reconcile_refusal(error: &AlertReconcileError) -> Failure {
    Failure::Typed(
        Refusal {
            error_id: error.stable_id(),
            reason: error.to_string(),
            guidance: "Reconcile only a dispatched alert (adapter_accepted or indeterminate; \
                       not_delivered also from committed) under the exact approval its preview \
                       returned; a changed operation needs a new preview.",
            recovery_class: "operator_action_required",
            safe_retry: ResponseSafeRetry::No,
        },
        ExitIdentity::AGENT_REFUSED,
    )
}

fn reconcile_answer(
    args: &ReconcileArgs,
) -> Result<Result<String, Box<dyn std::error::Error>>, Failure> {
    let before = snapshot(&args.root)?;
    let site = before.site_lineage.clone();
    let (mut deployment, authority, cx) =
        open_deployment(&args.root, &site, &args.principal, &[CAP_ALERT_RECONCILE])?;
    let result = (|| {
        let (plan, outcome) = match args.approve {
            None => (
                preview_alert_reconciliation(
                    &deployment,
                    &args.operation,
                    &args.attestation,
                    &authority,
                    &cx,
                )
                .map_err(|error| reconcile_refusal(&error))?,
                "proposed",
            ),
            Some(approval) => {
                let now = TimestampNs(i128::from(
                    wall_ns().map_err(|error| alert_refusal(&error))?,
                ));
                let receipt = reconcile_alert_operation(
                    &mut deployment,
                    &args.operation,
                    &args.attestation,
                    approval,
                    now,
                    &authority,
                    &cx,
                )
                .map_err(|error| reconcile_refusal(&error))?;
                (receipt.plan, receipt.outcome.as_str())
            }
        };
        let receipt = deployment
            .effects()
            .operation(&args.operation)
            .cloned()
            .ok_or(Failure::Internal)?;
        let obligation = deployment
            .effects()
            .obligation(&plan.prepared().obligation_id)
            .map(|obligation| obligation_state(obligation.state))
            .unwrap_or("absent");
        let after = snapshot(&args.root)?;
        let request_digest =
            crate::orient_cmd::request_identity("fss.cli_agent_reconcile.v1", |e| {
                e.text(args.operation.as_str());
                e.digest(plan.record_digest());
                e.bool(args.approve.is_some());
            });
        let proposed = outcome == "proposed";
        let attested = args.attestation.outcome.as_str();
        Ok(receipt_response(ReceiptAnswer {
            operation: "commit",
            capability: CAPABILITY_PLAN_COMMIT,
            principal: &args.principal,
            session: None,
            snapshot: &after,
            receipt: &receipt,
            outcome: ResponseOutcome::Ok,
            error_id: None,
            degradation: vec![
                if proposed {
                    format!(
                        "Reconciliation proposed, not performed: approve exactly {} with `fss \
                         commit --reconcile {attested} --operation {} --evidence {} --statement \
                         <same text> --approve {}`.",
                        plan.approval_digest(),
                        args.operation,
                        args.attestation.evidence,
                        plan.approval_digest()
                    )
                } else {
                    format!(
                        "Reconciliation {outcome} as {attested}: obligation {} is {obligation}.",
                        plan.prepared().obligation_id
                    )
                },
                "The reconciliation rests on the owner's attestation (operator_asserted \
                 provenance), not on a provider receipt."
                    .to_owned(),
            ],
            proof_pointers: vec![
                plan.approval_digest().to_text(),
                plan.record_digest().to_text(),
                args.attestation.evidence.to_text(),
                receipt.receipt_digest().to_text(),
            ],
            request_digest,
            recovery_class: "never_unchanged",
            safe_retry: ResponseSafeRetry::YesSameRequest,
            boundary: effect_boundary(
                vec![if proposed {
                    format!(
                        "Previewed an owner-attested {attested} reconciliation of {}.",
                        args.operation
                    )
                } else {
                    format!(
                        "Published the owner attestation {} root-last, then reconciled {} ({}).",
                        plan.record_digest(),
                        args.operation,
                        receipt.state.as_str()
                    )
                }],
                if proposed {
                    vec!["The reconciliation itself.".to_owned()]
                } else {
                    Vec::new()
                },
                Vec::new(),
                vec![
                    "No network I/O and no resend: reconciliation only records the owner's \
                      attestation."
                        .to_owned(),
                ],
            ),
            idempotency_key: Some(receipt.intent.idempotency_key.as_str().to_owned()),
        }))
    })();
    cx.drain_and_finalize();
    result
}

fn execute_reconcile(args: &ReconcileArgs) -> (String, ExitIdentity) {
    finish(
        reconcile_answer(args),
        ExitIdentity::SUCCESS,
        &Operation {
            command: "commit",
            name: "commit",
            capability: CAPABILITY_PLAN_COMMIT,
            payload_schema: OPERATION_RECEIPT_SCHEMA,
            view: AgentView::Operation,
            root: args.root.clone(),
            principal: args.principal.clone(),
            request: args.operation.as_str().as_bytes().to_vec(),
        },
    )
}

// ---------------------------------------------------------------------------------------------
// wait (AOP-009)
// ---------------------------------------------------------------------------------------------

fn wait_answer(args: &WaitArgs) -> Result<Result<String, Box<dyn std::error::Error>>, Failure> {
    let first = snapshot(&args.root)?;
    let initial = first
        .operations
        .iter()
        .find(|operation| operation.intent.operation_id == args.operation)
        .cloned()
        .ok_or_else(|| {
            precondition(
                format!("{} is not in the committed effect journal", args.operation),
                "Wait only on an operation that `fss plan --approve` prepared.",
            )
        })?;
    let started = Instant::now();
    let deadline = Duration::from_millis(args.deadline_ms);
    let mut current = (first, initial.clone());
    // A bounded read-only poll of the committed journal: no lock, no write, no retry of anything.
    while current.1.receipt_digest() == initial.receipt_digest() && started.elapsed() < deadline {
        std::thread::sleep(
            Duration::from_millis(25).min(deadline - started.elapsed().min(deadline)),
        );
        let next = snapshot(&args.root)?;
        if let Some(operation) = next
            .operations
            .iter()
            .find(|operation| operation.intent.operation_id == args.operation)
            .cloned()
        {
            current = (next, operation);
        }
    }
    let (snapshot_now, receipt) = current;
    let changed = receipt.receipt_digest() != initial.receipt_digest();
    let request_digest = crate::orient_cmd::request_identity("fss.cli_agent_wait.v1", |e| {
        e.text(args.operation.as_str());
        e.u64(args.deadline_ms);
        e.digest(initial.receipt_digest());
    });
    Ok(receipt_response(ReceiptAnswer {
        operation: "wait",
        capability: CAPABILITY_SITUATION_READ,
        principal: &args.principal,
        session: None,
        snapshot: &snapshot_now,
        receipt: &receipt,
        outcome: if changed {
            ResponseOutcome::Ok
        } else {
            ResponseOutcome::Partial
        },
        error_id: (!changed).then_some(ERR_OP_TIMEOUT),
        degradation: vec![if changed {
            format!(
                "{} moved from {} to {} while waiting.",
                args.operation,
                initial.state.as_str(),
                receipt.state.as_str()
            )
        } else {
            format!(
                "{} stayed {} for the whole {} ms wait: silence is not completion.",
                args.operation,
                receipt.state.as_str(),
                args.deadline_ms
            )
        }],
        proof_pointers: vec![
            initial.receipt_digest().to_text(),
            receipt.receipt_digest().to_text(),
        ],
        request_digest,
        recovery_class: "safe_read_retry",
        safe_retry: ResponseSafeRetry::YesSameRequest,
        boundary: effect_boundary(
            vec![format!(
                "Read the committed effect journal for up to {} ms.",
                args.deadline_ms
            )],
            vec!["Every effect transition: wait only observes.".to_owned()],
            Vec::new(),
            vec!["Nothing was written or locked.".to_owned()],
        ),
        idempotency_key: None,
    }))
}

fn execute_wait(args: &WaitArgs) -> (String, ExitIdentity) {
    finish(
        wait_answer(args),
        ExitIdentity::SUCCESS,
        &Operation {
            command: "wait",
            name: "wait",
            capability: CAPABILITY_SITUATION_READ,
            payload_schema: OPERATION_RECEIPT_SCHEMA,
            view: AgentView::Operation,
            root: args.root.clone(),
            principal: args.principal.clone(),
            request: args.operation.as_str().as_bytes().to_vec(),
        },
    )
}

// ---------------------------------------------------------------------------------------------
// cancel (AOP-010)
// ---------------------------------------------------------------------------------------------

fn cancel_answer(args: &CancelArgs) -> Result<Result<String, Box<dyn std::error::Error>>, Failure> {
    let before = snapshot(&args.root)?;
    let site = before.site_lineage.clone();
    let (mut deployment, authority, cx) =
        open_deployment(&args.root, &site, &args.principal, &[CAPABILITY_CANCEL])?;
    let result = (|| {
        let (plan, outcome) = match args.approve {
            None => (
                preview_alert_cancellation(&deployment, &args.operation, &authority, &cx)
                    .map_err(|error| control_refusal(&error))?,
                "proposed",
            ),
            Some(approval) => {
                let now = TimestampNs(i128::from(
                    wall_ns().map_err(|error| alert_refusal(&error))?,
                ));
                let receipt = cancel_prepared_alert(
                    &mut deployment,
                    &args.operation,
                    approval,
                    now,
                    &authority,
                    &cx,
                )
                .map_err(|error| control_refusal(&error))?;
                (receipt.plan, receipt.outcome.as_str())
            }
        };
        let receipt = deployment
            .effects()
            .operation(&args.operation)
            .cloned()
            .ok_or(Failure::Internal)?;
        let after = snapshot(&args.root)?;
        let request_digest = crate::orient_cmd::request_identity("fss.cli_agent_cancel.v1", |e| {
            e.text(args.operation.as_str());
            e.bool(args.approve.is_some());
        });
        let proposed = outcome == "proposed";
        Ok(receipt_response(ReceiptAnswer {
            operation: "cancel",
            capability: CAPABILITY_CANCEL,
            principal: &args.principal,
            session: None,
            snapshot: &after,
            receipt: &receipt,
            outcome: ResponseOutcome::Ok,
            error_id: None,
            degradation: vec![if proposed {
                format!(
                    "Cancellation proposed, not performed: approve exactly {} with `fss cancel \
                     --operation {} --approve {}`.",
                    plan.approval_digest(),
                    args.operation,
                    plan.approval_digest()
                )
            } else {
                format!(
                    "Cancellation {outcome}: the prepared operation can never be committed; the \
                     cancellation request is retained with proof {}.",
                    plan.proof_digest()
                )
            }],
            proof_pointers: vec![
                plan.approval_digest().to_text(),
                plan.proof_digest().to_text(),
                plan.evidence_digest().to_text(),
                receipt.receipt_digest().to_text(),
            ],
            request_digest,
            recovery_class: "never_unchanged",
            safe_retry: ResponseSafeRetry::YesSameRequest,
            boundary: effect_boundary(
                vec![if proposed {
                    "Previewed the cancellation of a still-prepared operation.".to_owned()
                } else {
                    format!("Cancellation {outcome} and retained in the effect journal.")
                }],
                if proposed {
                    vec!["The cancellation itself.".to_owned()]
                } else {
                    Vec::new()
                },
                Vec::new(),
                vec!["No network I/O; nothing was ever sent for this operation.".to_owned()],
            ),
            idempotency_key: Some(receipt.intent.idempotency_key.as_str().to_owned()),
        }))
    })();
    cx.drain_and_finalize();
    result
}

fn execute_cancel(args: &CancelArgs) -> (String, ExitIdentity) {
    finish(
        cancel_answer(args),
        ExitIdentity::SUCCESS,
        &Operation {
            command: "cancel",
            name: "cancel",
            capability: CAPABILITY_CANCEL,
            payload_schema: OPERATION_RECEIPT_SCHEMA,
            view: AgentView::Operation,
            root: args.root.clone(),
            principal: args.principal.clone(),
            request: args.operation.as_str().as_bytes().to_vec(),
        },
    )
}

/// Executes one effect-grammar command, returning the rendered response and its exit identity.
#[must_use]
pub fn execute_effect(command: &EffectCommand) -> (String, ExitIdentity) {
    match command {
        EffectCommand::Plan(args) => execute_plan(args),
        EffectCommand::Commit(args) => execute_commit(args),
        EffectCommand::Reconcile(args) => execute_reconcile(args),
        EffectCommand::Wait(args) => execute_wait(args),
        EffectCommand::Cancel(args) => execute_cancel(args),
    }
}
