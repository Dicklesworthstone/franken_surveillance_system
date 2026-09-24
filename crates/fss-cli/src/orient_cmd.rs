#![forbid(unsafe_code)]
//! `fss orient` (AOP-003 `session.orient`) and `fss explain` (AOP-011 `explain`): read-only agent
//! reads of an existing deployment root, answered as the registered `AgentResponseEnvelope`.
//!
//! Both commands open no file for writing. The situation is compiled by
//! [`fss_reference::agent_orient`]; this module only decodes arguments, binds the compiled typed
//! values into [`AgentResponseEnvelope`] (and, for explain, [`AgentCognitiveEnvelope`]) through
//! their validated constructors, and renders them with [`crate::agent_json`]. Affordances are
//! listed, never executed.

use std::path::PathBuf;

use fss_core::{
    AgentCognitiveEnvelope, AgentResponseEnvelope, AgentView, BudgetVector, CanonicalEncode,
    CanonicalEncoder, CognitiveAnswerClass, Completeness, ContentDigest, ContractBasisError,
    EnvelopeBudget, EnvelopeContinuity, EnvelopeCoverage, EnvelopeEpistemic, EnvelopeProposition,
    EventId, EventState, ExecutionBoundary, KnowledgeState, LedgerAnchor, PrincipalId,
    ResponseOutcome, ResponseSafeRetry, ResponseTaskState,
};
use fss_reference::agent_orient::{
    AFFORDANCE_REORIENT, CAPABILITY_EXPLAIN, CAPABILITY_SITUATION_READ, DeploymentOrientation,
    DeploymentReadError, DeploymentSnapshot, EventExplanation, OrientError, OrientLimits,
    OrientRequest, explain_event, orient_deployment, read_deployment,
};

use crate::agent_json;
use crate::diagnostic::escape_json_str;
use crate::error::{CliError, ERR_CLI_RUNTIME_FAILURE, ERR_DOCTOR_NOT_A_DEPLOYMENT, ExitIdentity};
use crate::redact::redact_value_or_digest;
use crate::token::ArgToken;

/// Registered error identity: the critical context does not fit the admitted token budget.
pub const ERR_AGENT_CONTEXT_INCOMPLETE: &str = "ERR-AGENT-CONTEXT-INCOMPLETE-001";
/// Registered error identity: no committed revision publishes the requested event.
pub const ERR_AGENT_EVENT_NOT_FOUND: &str = "ERR-AGENT-EVENT-NOT-FOUND-001";
/// Principal recorded when `--principal` is omitted (an audit label, not authentication).
pub const DEFAULT_PRINCIPAL: &str = "principal:local-operator";
/// Views an orientation may be requested in.
pub const ORIENT_VIEWS: [&str; 3] = ["pulse", "brief", "epistemic_map"];

/// Options for the `orient` command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrientArgs {
    /// Existing deployment root, read-only.
    pub root: PathBuf,
    /// Registered view (default `brief`).
    pub view: AgentView,
    /// Requesting principal label.
    pub principal: PrincipalId,
    /// Explicit context-token budget (1..=view maximum).
    pub budget_tokens: Option<u64>,
}

/// Options for the `explain` command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplainArgs {
    /// Existing deployment root, read-only.
    pub root: PathBuf,
    /// Published event to explain.
    pub event_id: EventId,
    /// Requesting principal label.
    pub principal: PrincipalId,
}

/// Collects `--json` and `--name value` / `--name=value` options with exact exhaustion.
fn collect_options(
    command: &str,
    tokens: &[ArgToken],
    valued: &[&str],
) -> Result<Vec<(String, String, usize)>, CliError> {
    let mut seen_json = false;
    let mut values: Vec<(String, String, usize)> = Vec::new();
    let mut index = 1;
    while index < tokens.len() {
        let token = &tokens[index];
        let text = token.as_str();
        if text == "--json" {
            if seen_json {
                return Err(CliError::DuplicateOption {
                    option: "--json".to_owned(),
                    command: Some(command.to_owned()),
                    index: token.index,
                });
            }
            seen_json = true;
            index += 1;
            continue;
        }
        let (name, inline) = match text.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value)),
            _ => (text, None),
        };
        if !valued.contains(&name) {
            return Err(if name.starts_with('-') {
                CliError::UnknownOption {
                    option: name.to_owned(),
                    command: Some(command.to_owned()),
                    index: token.index,
                }
            } else {
                CliError::TrailingArgument {
                    argument: token.raw.clone(),
                    index: token.index,
                    command: Some(command.to_owned()),
                }
            });
        }
        if values.iter().any(|(seen, _, _)| seen == name) {
            return Err(CliError::DuplicateOption {
                option: name.to_owned(),
                command: Some(command.to_owned()),
                index: token.index,
            });
        }
        let value = match inline {
            Some(value) => value.to_owned(),
            None => {
                index += 1;
                tokens
                    .get(index)
                    .map(|next| next.raw.clone())
                    .ok_or_else(|| CliError::MissingValue {
                        option: name.to_owned(),
                        command: Some(command.to_owned()),
                        expected: format!("a value for `{name}`"),
                    })?
            }
        };
        if value.is_empty() {
            return Err(CliError::MissingValue {
                option: name.to_owned(),
                command: Some(command.to_owned()),
                expected: format!("a non-empty value for `{name}`"),
            });
        }
        values.push((name.to_owned(), value, token.index));
        index += 1;
    }
    if !seen_json {
        return Err(CliError::MissingValue {
            option: "--json".to_owned(),
            command: Some(command.to_owned()),
            expected: "flag `--json` is required for this command".to_owned(),
        });
    }
    Ok(values)
}

fn take<'a>(
    values: &'a [(String, String, usize)],
    name: &str,
) -> Option<&'a (String, String, usize)> {
    values.iter().find(|(seen, _, _)| seen == name)
}

fn required_root(command: &str, values: &[(String, String, usize)]) -> Result<PathBuf, CliError> {
    take(values, "--root")
        .map(|(_, value, _)| PathBuf::from(value))
        .ok_or_else(|| CliError::MissingValue {
            option: "--root".to_owned(),
            command: Some(command.to_owned()),
            expected: "directory path for `--root`".to_owned(),
        })
}

fn principal(command: &str, values: &[(String, String, usize)]) -> Result<PrincipalId, CliError> {
    match take(values, "--principal") {
        None => PrincipalId::parse(DEFAULT_PRINCIPAL).map_err(|_| CliError::MalformedValue {
            option: "--principal".to_owned(),
            value: DEFAULT_PRINCIPAL.to_owned(),
            reason: "default principal is not a valid identifier".to_owned(),
            command: Some(command.to_owned()),
            index: 0,
        }),
        Some((_, value, index)) => {
            PrincipalId::parse(value.clone()).map_err(|_| CliError::MalformedValue {
                option: "--principal".to_owned(),
                value: value.clone(),
                reason: "principal must be 1..128 characters of [A-Za-z0-9._:-]".to_owned(),
                command: Some(command.to_owned()),
                index: *index,
            })
        }
    }
}

/// Parses `orient --json --root <dir> [--view <name>] [--principal <id>] [--budget-tokens <n>]`.
pub fn parse_orient_args(tokens: &[ArgToken]) -> Result<OrientArgs, CliError> {
    let values = collect_options(
        "orient",
        tokens,
        &["--root", "--view", "--principal", "--budget-tokens"],
    )?;
    let root = required_root("orient", &values)?;
    let view = match take(&values, "--view") {
        None => AgentView::Brief,
        Some((_, value, index)) => {
            if !ORIENT_VIEWS.contains(&value.as_str()) {
                return Err(CliError::MalformedValue {
                    option: "--view".to_owned(),
                    value: value.clone(),
                    reason: "view must be one of pulse, brief, epistemic_map".to_owned(),
                    command: Some("orient".to_owned()),
                    index: *index,
                });
            }
            AgentView::from_name(value).map_err(|_| CliError::MalformedValue {
                option: "--view".to_owned(),
                value: value.clone(),
                reason: "view is not registered".to_owned(),
                command: Some("orient".to_owned()),
                index: *index,
            })?
        }
    };
    let budget_tokens = match take(&values, "--budget-tokens") {
        None => None,
        Some((_, value, index)) => {
            let maximum = u64::from(view.maximum_tokens());
            match value.parse::<u64>() {
                Ok(tokens) if (1..=maximum).contains(&tokens) => Some(tokens),
                _ => {
                    return Err(CliError::MalformedValue {
                        option: "--budget-tokens".to_owned(),
                        value: value.clone(),
                        reason: format!(
                            "budget must be an integer in 1..={maximum} (the {} view maximum)",
                            view.name()
                        ),
                        command: Some("orient".to_owned()),
                        index: *index,
                    });
                }
            }
        }
    };
    Ok(OrientArgs {
        root,
        view,
        principal: principal("orient", &values)?,
        budget_tokens,
    })
}

/// Parses `explain --json --root <dir> --event-id <id> [--principal <id>]`.
pub fn parse_explain_args(tokens: &[ArgToken]) -> Result<ExplainArgs, CliError> {
    let values = collect_options("explain", tokens, &["--root", "--event-id", "--principal"])?;
    let root = required_root("explain", &values)?;
    let (_, raw, index) = take(&values, "--event-id").ok_or_else(|| CliError::MissingValue {
        option: "--event-id".to_owned(),
        command: Some("explain".to_owned()),
        expected: "a published event identity for `--event-id`".to_owned(),
    })?;
    let event_id = EventId::parse(raw.clone()).map_err(|_| CliError::MalformedValue {
        option: "--event-id".to_owned(),
        value: raw.clone(),
        reason: "event identity must be 1..128 characters of [A-Za-z0-9._:-]".to_owned(),
        command: Some("explain".to_owned()),
        index: *index,
    })?;
    Ok(ExplainArgs {
        root,
        event_id,
        principal: principal("explain", &values)?,
    })
}

/// Execution-phase refusal rendered as `fss.cli_diagnostic.v1` (no anchor exists to answer at).
fn execution_diagnostic(
    command: &str,
    root: &std::path::Path,
    error_id: &str,
    exit: ExitIdentity,
) -> String {
    let input = redact_value_or_digest(&root.to_string_lossy());
    format!(
        "{{\"schema\":\"fss.cli_diagnostic.v1\",\"phase\":\"execution\",\"binary\":\"fss\",\"command\":\"{command}\",\"argument_index\":null,\"redacted_input\":\"{}\",\"error_id\":\"{error_id}\",\"exit_id\":\"{}\",\"exit_code\":{},\"contract_basis\":\"fss/1\",\"effect_started\":false,\"retryable\":false,\"recovery_class\":\"operator_action_required\",\"correlation_id\":\"corr-fss-{error_id}\",\"proof_handle\":\"fss://proof/cli/{command}-refusal\"}}",
        escape_json_str(&input),
        exit.identifier,
        exit.code
    )
}

fn read_refusal(
    command: &str,
    root: &std::path::Path,
    error: &DeploymentReadError,
) -> (String, ExitIdentity) {
    match error {
        DeploymentReadError::NotADeployment { .. } => (
            execution_diagnostic(
                command,
                root,
                ERR_DOCTOR_NOT_A_DEPLOYMENT,
                ExitIdentity::DOCTOR_NOT_A_DEPLOYMENT,
            ),
            ExitIdentity::DOCTOR_NOT_A_DEPLOYMENT,
        ),
        DeploymentReadError::Unreadable { .. } | DeploymentReadError::Corrupt { .. } => (
            execution_diagnostic(
                command,
                root,
                ERR_CLI_RUNTIME_FAILURE,
                ExitIdentity::RUNTIME_FAILURE,
            ),
            ExitIdentity::RUNTIME_FAILURE,
        ),
    }
}

fn internal_failure(command: &str, root: &std::path::Path) -> (String, ExitIdentity) {
    (
        execution_diagnostic(
            command,
            root,
            ERR_CLI_RUNTIME_FAILURE,
            ExitIdentity::RUNTIME_FAILURE,
        ),
        ExitIdentity::RUNTIME_FAILURE,
    )
}

fn request_identity(domain: &str, parts: impl FnOnce(&mut CanonicalEncoder)) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(domain);
    parts(&mut encoder);
    ContentDigest::sha256(&encoder.finish())
}

fn privacy_projection(purpose: &str) -> String {
    agent_json::object(&[
        ("purpose", agent_json::string(purpose)),
        (
            "policyGenerationId",
            agent_json::string("privacy:local-authorized-files"),
        ),
        (
            "allowedDomains",
            agent_json::strings([
                "authority-ledger",
                "effect-journal",
                "event-revisions",
                "deployment-layout",
            ]),
        ),
        ("redactedDomains", agent_json::strings(["media-payloads"])),
    ])
}

/// Everything that differs between one response and another; the rest is fixed per command.
struct ResponseParts {
    operation: &'static str,
    request_digest: ContentDigest,
    principal: PrincipalId,
    session_id: Option<String>,
    mission_id: Option<String>,
    anchor: LedgerAnchor,
    view: AgentView,
    capability: &'static str,
    outcome: ResponseOutcome,
    error_id: Option<&'static str>,
    payload_schema: &'static str,
    payload_json: String,
    epistemic_state: KnowledgeState,
    completeness: Completeness,
    warnings: Vec<String>,
    contradictions: Vec<String>,
    degradation: Vec<String>,
    budgets_json: String,
    proof_pointers: Vec<String>,
    affordances: Vec<String>,
    decision_fingerprint: ContentDigest,
    compression_receipt_id: Option<String>,
    continuation: Option<String>,
    recovery_class: &'static str,
    safe_retry: ResponseSafeRetry,
    boundary: ExecutionBoundary,
    created_at_ns: i128,
}

fn build_response(parts: ResponseParts) -> Result<AgentResponseEnvelope, ContractBasisError> {
    let payload_digest = ContentDigest::sha256(parts.payload_json.as_bytes());
    let short = parts.request_digest.to_text();
    let hex = short.split_once(':').map_or(short.as_str(), |(_, hex)| hex);
    let envelope = AgentResponseEnvelope::new(
        fss_core::reference_contract_basis(),
        parts.operation,
        format!("request:{}:{hex}", parts.operation),
        1,
        parts.principal.as_str(),
        parts.session_id,
        parts.mission_id,
        format!("trace:{}:{hex}", parts.operation),
        parts.anchor,
        None,
        None,
        parts.view,
        vec![parts.capability.to_owned()],
        privacy_projection("read-only agent read of a local reference deployment"),
        parts.outcome,
        None,
        Some(ResponseTaskState::None),
        parts.error_id.map(ToOwned::to_owned),
        parts.payload_schema,
        parts.payload_json,
        payload_digest,
        parts.epistemic_state,
        parts.completeness,
        parts.warnings,
        parts.contradictions,
        parts.degradation,
        parts.budgets_json,
        parts.proof_pointers,
        parts.affordances,
        parts.decision_fingerprint,
        parts.compression_receipt_id,
        None,
        parts.continuation,
        None,
        parts.recovery_class,
        parts.safe_retry,
        false,
        parts.boundary,
        parts.created_at_ns,
    )?;
    envelope.validate().map_err(ContractBasisError::Contract)?;
    Ok(envelope)
}

fn read_only_boundary(completed: String) -> ExecutionBoundary {
    ExecutionBoundary {
        completed: vec![completed],
        not_started: vec!["Every listed affordance: this read executes none of them.".to_owned()],
        possibly_occurred: Vec::new(),
        preserved_truth: vec![
            "The deployment root was only read: no file was created, written, locked, or \
             repaired."
                .to_owned(),
        ],
        invalidated: Vec::new(),
    }
}

/// The orient payload: the capsule and every verified publication section for the view.
fn orient_payload(orientation: &DeploymentOrientation) -> Result<String, OrientError> {
    let publication = &orientation.publication;
    let capsule = orientation.capsule();
    let affordances: Vec<String> = capsule
        .affordances
        .iter()
        .map(agent_json::affordance)
        .collect();
    Ok(agent_json::object(&[
        ("capsuleId", agent_json::string(&capsule.capsule_id)),
        ("revision", capsule.revision.to_string()),
        (
            "contractBasis",
            agent_json::contract_basis(&capsule.contract_basis),
        ),
        ("missionId", agent_json::string(capsule.mission_id.as_str())),
        ("sessionId", agent_json::string(capsule.session_id.as_str())),
        (
            "principalId",
            agent_json::string(capsule.principal_id.as_str()),
        ),
        ("viewId", agent_json::string(orientation.view.id())),
        ("anchor", agent_json::anchor(&capsule.anchor)),
        ("previousAnchor", "null".to_owned()),
        (
            "situationFrame",
            agent_json::situation_frame(&capsule.frame),
        ),
        (
            "obligations",
            agent_json::strings(capsule.obligations.iter().map(|id| id.as_str())),
        ),
        (
            "indeterminateEffects",
            agent_json::strings(
                orientation
                    .indeterminate_effects
                    .iter()
                    .map(|id| id.as_str()),
            ),
        ),
        ("affordances", agent_json::array(&affordances)),
        (
            "controlEnvelope",
            agent_json::control_envelope(&publication.control_envelope),
        ),
        (
            "resourceState",
            agent_json::resource_state(&publication.resource_state),
        ),
        (
            "contextPack",
            agent_json::context_pack(&publication.context_pack),
        ),
        (
            "compressionReceipt",
            agent_json::compression_receipt(&publication.compression_receipt),
        ),
        (
            "orientProjection",
            agent_json::orient_projection(&orientation.projection),
        ),
        (
            "completeness",
            agent_json::string(capsule.completeness.as_str()),
        ),
        ("missionState", "null".to_owned()),
        (
            "decisionFingerprint",
            agent_json::string(&capsule.decision_fingerprint()?.to_text()),
        ),
        (
            "publicationDigest",
            agent_json::string(&publication.publication_digest.to_text()),
        ),
        ("createdAtNs", capsule.created_at.0.to_string()),
    ]))
}

fn orient_response(
    orientation: &DeploymentOrientation,
    request_digest: ContentDigest,
) -> Result<AgentResponseEnvelope, Box<dyn std::error::Error>> {
    let capsule = orientation.capsule();
    let publication = &orientation.publication;
    let mut proof_pointers: Vec<String> = orientation
        .proof_roots()
        .iter()
        .map(|root| root.to_text())
        .collect();
    proof_pointers.push(publication.publication_digest.to_text());
    proof_pointers.push(orientation.projection.projection_digest().to_text());
    build_response(ResponseParts {
        operation: "session.orient",
        request_digest,
        principal: capsule.principal_id.clone(),
        session_id: Some(capsule.session_id.as_str().to_owned()),
        mission_id: Some(capsule.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: orientation.view,
        capability: CAPABILITY_SITUATION_READ,
        outcome: ResponseOutcome::Ok,
        error_id: None,
        payload_schema: "fss.situation_capsule.v1",
        payload_json: orient_payload(orientation)?,
        epistemic_state: orientation.epistemic_state,
        completeness: capsule.completeness,
        warnings: orientation.warnings.clone(),
        contradictions: orientation.contradictions.clone(),
        degradation: orientation.degradation.clone(),
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers,
        affordances: capsule.frame.next.clone(),
        decision_fingerprint: capsule.decision_fingerprint()?,
        compression_receipt_id: Some(publication.compression_receipt.receipt_id.clone()),
        continuation: publication.context_pack.continuation.clone(),
        recovery_class: "safe_read_retry",
        safe_retry: ResponseSafeRetry::YesSameRequest,
        boundary: read_only_boundary(format!(
            "Compiled the {} situation at commit {}.",
            orientation.view.name(),
            capsule.anchor.commit_sequence
        )),
        created_at_ns: capsule.created_at.0,
    })
    .map_err(Into::into)
}

fn budget_refusal(
    snapshot: &DeploymentSnapshot,
    request_digest: ContentDigest,
    view: AgentView,
    principal: &PrincipalId,
    budget_tokens: u64,
    reason: String,
) -> Result<AgentResponseEnvelope, ContractBasisError> {
    let requested = BudgetVector::builder()
        .tokens(budget_tokens)
        .build()
        .map_err(|_| ContractBasisError::Contract(fss_core::ContractError::BudgetExhausted))?;
    build_response(ResponseParts {
        operation: "session.orient",
        request_digest,
        principal: principal.clone(),
        session_id: None,
        mission_id: None,
        anchor: snapshot.anchor.clone(),
        view,
        capability: CAPABILITY_SITUATION_READ,
        outcome: ResponseOutcome::Refused,
        error_id: Some(ERR_AGENT_CONTEXT_INCOMPLETE),
        payload_schema: "fss.situation_capsule.v1",
        payload_json: "null".to_owned(),
        epistemic_state: KnowledgeState::Unknown,
        completeness: Completeness::Partial,
        warnings: Vec::new(),
        contradictions: Vec::new(),
        degradation: vec![
            reason,
            "Critical context is never truncated; request --view brief or --view epistemic_map, \
             or a larger --budget-tokens up to the view maximum."
                .to_owned(),
        ],
        budgets_json: agent_json::budget_summary(&requested, &BudgetVector::ZERO),
        proof_pointers: vec![snapshot.anchor.state_root.to_text()],
        affordances: Vec::new(),
        decision_fingerprint: request_digest,
        compression_receipt_id: None,
        continuation: None,
        recovery_class: "never_unchanged",
        safe_retry: ResponseSafeRetry::No,
        boundary: read_only_boundary(format!(
            "Read the deployment at commit {}; no situation was published.",
            snapshot.anchor.commit_sequence
        )),
        created_at_ns: snapshot.latest_evidence_time.0,
    })
}

fn rendered(
    result: Result<AgentResponseEnvelope, impl Sized>,
    exit: ExitIdentity,
    command: &str,
    root: &std::path::Path,
) -> (String, ExitIdentity) {
    match result {
        Ok(envelope) => (agent_json::response_envelope(&envelope), exit),
        Err(_) => internal_failure(command, root),
    }
}

fn orient_request_digest(args: &OrientArgs, snapshot: &DeploymentSnapshot) -> ContentDigest {
    request_identity("fss.cli.orient.request.v1", |encoder| {
        encoder.text(args.view.id());
        args.principal.encode_canonical(encoder);
        encoder.u64(args.budget_tokens.unwrap_or(0));
        snapshot.anchor.encode_canonical(encoder);
    })
}

/// Executes `orient`, returning the rendered response and its exit identity.
#[must_use]
pub fn execute_orient(args: &OrientArgs) -> (String, ExitIdentity) {
    let limits = OrientLimits::default();
    let snapshot = match read_deployment(&args.root, &limits) {
        Ok(snapshot) => snapshot,
        Err(error) => return read_refusal("orient", &args.root, &error),
    };
    let request_digest = orient_request_digest(args, &snapshot);
    let request = OrientRequest {
        view: args.view,
        principal: args.principal.clone(),
        budget_tokens: args.budget_tokens,
    };
    match orient_deployment(&snapshot, &request, &limits) {
        Ok(orientation) => rendered(
            orient_response(&orientation, request_digest),
            ExitIdentity::SUCCESS,
            "orient",
            &args.root,
        ),
        Err(error @ OrientError::ContextBudgetExceeded { budget_tokens, .. }) => rendered(
            budget_refusal(
                &snapshot,
                request_digest,
                args.view,
                &args.principal,
                budget_tokens,
                error.to_string(),
            ),
            ExitIdentity::AGENT_REFUSED,
            "orient",
            &args.root,
        ),
        Err(error @ OrientError::TooManyEvents { .. }) => rendered(
            budget_refusal(
                &snapshot,
                request_digest,
                args.view,
                &args.principal,
                args.budget_tokens
                    .unwrap_or_else(|| u64::from(args.view.maximum_tokens())),
                error.to_string(),
            ),
            ExitIdentity::AGENT_REFUSED,
            "orient",
            &args.root,
        ),
        Err(OrientError::UnsupportedView(_) | OrientError::Contract(_)) => {
            internal_failure("orient", &args.root)
        }
    }
}

fn explain_budget(orientation: &DeploymentOrientation) -> (String, String, String) {
    (
        agent_json::budget(&orientation.requested),
        agent_json::budget(&orientation.consumed),
        agent_json::remaining(&orientation.requested, &orientation.consumed),
    )
}

/// The answer-specific blocks of one explain cognitive envelope.
struct CognitiveParts {
    answer_class: CognitiveAnswerClass,
    epistemic: EnvelopeEpistemic,
    coverage: EnvelopeCoverage,
    evidence_handles: Vec<String>,
    next_actions: Vec<String>,
    decision_digest: ContentDigest,
}

fn cognitive(
    orientation: &DeploymentOrientation,
    request_digest: ContentDigest,
    parts: CognitiveParts,
) -> Result<AgentCognitiveEnvelope, ContractBasisError> {
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
    AgentCognitiveEnvelope::new(
        capsule.contract_basis.clone(),
        format!("request:explain:{hex}"),
        format!("response:explain:{hex}"),
        format!("trace:explain:{hex}"),
        "explain",
        "explain",
        AgentView::DecisionDiff.id(),
        answer_class,
        capsule.anchor.clone(),
        epistemic,
        coverage,
        EnvelopeBudget {
            requested_json: requested,
            consumed_json: consumed,
            remaining_json: remaining,
            degraded_dimensions: Vec::new(),
            marginal_work_declined: Vec::new(),
        },
        evidence_handles,
        next_actions,
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
    )
}

fn explanation_response(
    orientation: &DeploymentOrientation,
    explanation: &EventExplanation,
    request_digest: ContentDigest,
) -> Result<AgentResponseEnvelope, ContractBasisError> {
    let event = &explanation.event.event;
    let propositions = explanation
        .cells
        .iter()
        .map(|cell| EnvelopeProposition {
            id: cell.claim_id().to_owned(),
            statement: cell.disclosable_statement().to_owned(),
            state: cell.knowledge_state(),
            provenance: cell.provenance().as_str().to_owned(),
            evidence: cell
                .evidence_digests()
                .iter()
                .map(|digest| digest.to_text())
                .collect(),
        })
        .collect();
    let mut invalidators = explanation.would_change.clone();
    invalidators.extend(
        explanation
            .cells
            .iter()
            .filter(|cell| !cell.contradictions().is_empty())
            .map(|cell| {
                format!(
                    "{} is contradicted by {} retained root(s).",
                    cell.claim_id(),
                    cell.contradictions().len()
                )
            }),
    );
    let physical = explanation
        .cells
        .iter()
        .find(|cell| cell.claim_id().ends_with(":unknown-presence"))
        .map_or(KnowledgeState::Unknown, |cell| cell.knowledge_state());
    let answer_class = if event.state == EventState::Indeterminate {
        CognitiveAnswerClass::Indeterminate
    } else {
        CognitiveAnswerClass::HypothesisSet
    };
    let evidence_handles: Vec<String> = explanation
        .receipt
        .evidence_subgraph()
        .iter()
        .map(|digest| format!("fss://proof/{digest}"))
        .chain(explanation.receipt.expansion_handles().iter().cloned())
        .collect();
    let payload = cognitive(
        orientation,
        request_digest,
        CognitiveParts {
            answer_class,
            epistemic: EnvelopeEpistemic {
                propositions,
                assumptions: explanation.assumptions.clone(),
                invalidators,
            },
            coverage: EnvelopeCoverage {
                authorized_domain: event.zone_ids.clone(),
                observed_domain: explanation.event.failure_domains().into_iter().collect(),
                not_observable_domain: vec![
                    "site activity outside the retained recording".to_owned(),
                ],
                omitted_count: 0,
                omission_reasons: Vec::new(),
                stop_reason: "complete".to_owned(),
            },
            evidence_handles,
            next_actions: explanation.next_actions.clone(),
            decision_digest: explanation.receipt.receipt_digest(),
        },
    )?;
    let contradictions = explanation
        .cells
        .iter()
        .filter(|cell| {
            !cell.contradictions().is_empty()
                || cell.knowledge_state() == KnowledgeState::Conflicted
        })
        .map(|cell| cell.claim_id().to_owned())
        .collect();
    let mut warnings: Vec<String> = orientation
        .warnings
        .iter()
        .filter(|warning| warning.starts_with(event.event_id.as_str()))
        .cloned()
        .collect();
    warnings.push(
        "An explanation grants no effect authority; it binds the committed revision only."
            .to_owned(),
    );
    let mut proof_pointers = vec![
        explanation.receipt.receipt_digest().to_text(),
        explanation.event.revision_digest.to_text(),
        explanation.event.event_root.to_text(),
    ];
    proof_pointers.extend(
        explanation
            .receipt
            .evidence_subgraph()
            .iter()
            .map(|digest| digest.to_text()),
    );
    proof_pointers.sort();
    proof_pointers.dedup();
    let capsule = orientation.capsule();
    build_response(ResponseParts {
        operation: "explain",
        request_digest,
        principal: capsule.principal_id.clone(),
        session_id: Some(capsule.session_id.as_str().to_owned()),
        mission_id: Some(capsule.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: AgentView::DecisionDiff,
        capability: CAPABILITY_EXPLAIN,
        outcome: ResponseOutcome::Ok,
        error_id: None,
        payload_schema: AgentCognitiveEnvelope::SCHEMA,
        payload_json: agent_json::cognitive_envelope(&payload),
        epistemic_state: physical,
        completeness: Completeness::Partial,
        warnings,
        contradictions,
        degradation: orientation
            .degradation
            .iter()
            .filter(|line| !line.contains("pulse view"))
            .cloned()
            .collect(),
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers,
        affordances: explanation.next_actions.clone(),
        decision_fingerprint: explanation.receipt.receipt_digest(),
        compression_receipt_id: None,
        continuation: None,
        recovery_class: "safe_read_retry",
        safe_retry: ResponseSafeRetry::YesSameRequest,
        boundary: read_only_boundary(format!(
            "Explained {} revision {} at commit {}.",
            event.event_id.as_str(),
            event.revision,
            capsule.anchor.commit_sequence
        )),
        created_at_ns: capsule.created_at.0,
    })
}

fn unknown_event_response(
    snapshot: &DeploymentSnapshot,
    orientation: &DeploymentOrientation,
    event_id: &EventId,
    request_digest: ContentDigest,
) -> Result<AgentResponseEnvelope, ContractBasisError> {
    let capsule = orientation.capsule();
    let evidence = if snapshot.batch_count == 0 {
        snapshot.anchor.state_root
    } else {
        snapshot.ledger_root
    };
    let statement = format!(
        "No committed event_revision delta names {} at commit {}; {} event(s) are published.",
        event_id.as_str(),
        capsule.anchor.commit_sequence,
        snapshot.events.len()
    );
    let decision = request_identity("fss.cli.explain.not_found.v1", |encoder| {
        encoder.text(event_id.as_str());
        capsule.anchor.encode_canonical(encoder);
        encoder.digest(evidence);
    });
    let payload = cognitive(
        orientation,
        request_digest,
        CognitiveParts {
            answer_class: CognitiveAnswerClass::Refusal,
            epistemic: EnvelopeEpistemic {
                propositions: vec![EnvelopeProposition {
                    id: "claim:event-index:requested".to_owned(),
                    statement,
                    state: KnowledgeState::Known,
                    provenance: "derived".to_owned(),
                    evidence: vec![evidence.to_text()],
                }],
                assumptions: Vec::new(),
                invalidators: vec![
                    "A later commit that publishes the event would answer the question.".to_owned(),
                ],
            },
            coverage: EnvelopeCoverage {
                authorized_domain: vec!["committed event_revision deltas".to_owned()],
                observed_domain: vec!["committed event_revision deltas".to_owned()],
                not_observable_domain: Vec::new(),
                omitted_count: 0,
                omission_reasons: Vec::new(),
                stop_reason: "complete".to_owned(),
            },
            evidence_handles: vec![format!("fss://proof/{evidence}")],
            next_actions: vec![AFFORDANCE_REORIENT.to_owned()],
            decision_digest: decision,
        },
    )?;
    build_response(ResponseParts {
        operation: "explain",
        request_digest,
        principal: capsule.principal_id.clone(),
        session_id: Some(capsule.session_id.as_str().to_owned()),
        mission_id: Some(capsule.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: AgentView::DecisionDiff,
        capability: CAPABILITY_EXPLAIN,
        outcome: ResponseOutcome::Refused,
        error_id: Some(ERR_AGENT_EVENT_NOT_FOUND),
        payload_schema: AgentCognitiveEnvelope::SCHEMA,
        payload_json: agent_json::cognitive_envelope(&payload),
        epistemic_state: KnowledgeState::Known,
        completeness: Completeness::Complete,
        warnings: Vec::new(),
        contradictions: Vec::new(),
        degradation: Vec::new(),
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers: vec![evidence.to_text()],
        affordances: vec![AFFORDANCE_REORIENT.to_owned()],
        decision_fingerprint: decision,
        compression_receipt_id: None,
        continuation: None,
        recovery_class: "refresh_and_retry",
        safe_retry: ResponseSafeRetry::YesAfterRefresh,
        boundary: read_only_boundary(format!(
            "Searched every committed event revision at commit {}.",
            capsule.anchor.commit_sequence
        )),
        created_at_ns: capsule.created_at.0,
    })
}

/// Executes `explain`, returning the rendered response and its exit identity.
#[must_use]
pub fn execute_explain(args: &ExplainArgs) -> (String, ExitIdentity) {
    let limits = OrientLimits::default();
    let snapshot = match read_deployment(&args.root, &limits) {
        Ok(snapshot) => snapshot,
        Err(error) => return read_refusal("explain", &args.root, &error),
    };
    let request_digest = request_identity("fss.cli.explain.request.v1", |encoder| {
        encoder.text(args.event_id.as_str());
        args.principal.encode_canonical(encoder);
        snapshot.anchor.encode_canonical(encoder);
    });
    let request = OrientRequest {
        view: AgentView::Brief,
        principal: args.principal.clone(),
        budget_tokens: Some(u64::from(AgentView::Brief.maximum_tokens())),
    };
    let orientation = match orient_deployment(&snapshot, &request, &limits) {
        Ok(orientation) => orientation,
        Err(
            error @ (OrientError::ContextBudgetExceeded { .. } | OrientError::TooManyEvents { .. }),
        ) => {
            return rendered(
                budget_refusal(
                    &snapshot,
                    request_digest,
                    AgentView::Brief,
                    &args.principal,
                    u64::from(AgentView::Brief.maximum_tokens()),
                    error.to_string(),
                ),
                ExitIdentity::AGENT_REFUSED,
                "explain",
                &args.root,
            );
        }
        Err(OrientError::UnsupportedView(_) | OrientError::Contract(_)) => {
            return internal_failure("explain", &args.root);
        }
    };
    match explain_event(&snapshot, &orientation, &args.event_id) {
        Ok(Some(explanation)) => rendered(
            explanation_response(&orientation, &explanation, request_digest),
            ExitIdentity::SUCCESS,
            "explain",
            &args.root,
        ),
        Ok(None) => rendered(
            unknown_event_response(&snapshot, &orientation, &args.event_id, request_digest),
            ExitIdentity::AGENT_REFUSED,
            "explain",
            &args.root,
        ),
        Err(_) => internal_failure("explain", &args.root),
    }
}
