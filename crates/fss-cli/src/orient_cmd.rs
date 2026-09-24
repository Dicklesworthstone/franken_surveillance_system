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
    ActionAffordance, AgentCognitiveEnvelope, AgentResponseEnvelope, AgentView, BudgetVector,
    CanonicalEncode, CanonicalEncoder, CognitiveAnswerClass, Completeness, ContentDigest,
    ContractBasisError, EnvelopeBudget, EnvelopeContinuity, EnvelopeCoverage, EnvelopeEpistemic,
    EnvelopeProposition, EventId, EventState, ExecutionBoundary, KnowledgeState, LedgerAnchor,
    PrincipalId, ResponseOutcome, ResponseSafeRetry, ResponseTaskState,
};
use fss_reference::agent_orient::{
    AFFORDANCE_REORIENT, CAPABILITY_EXPLAIN, CAPABILITY_SITUATION_READ, DeploymentOrientation,
    DeploymentReadError, DeploymentSnapshot, EventExplanation, ORIENT_DATA_CLASSES, OrientError,
    OrientLimits, OrientRequest, explain_event, orient_deployment, read_deployment,
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

/// The privacy projection every orient/explain answer is served under, at the anchor's privacy
/// epoch.
fn privacy_projection(anchor: &LedgerAnchor) -> agent_json::PrivacyProjection {
    agent_json::PrivacyProjection {
        purpose: "read-only agent read of a local reference deployment".to_owned(),
        policy_generation_id: format!("privacy-epoch:{}", anchor.privacy_epoch),
        visible_domains: ORIENT_DATA_CLASSES
            .iter()
            .map(|class| (*class).to_owned())
            .collect(),
        redacted_domains: vec!["media-payloads".to_owned()],
    }
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
    /// Affordance identities, in order.
    affordances: Vec<String>,
    /// Their registered `agent_affordance.v1` objects, in the same order.
    affordance_objects: Vec<String>,
    decision_fingerprint: ContentDigest,
    compression_receipt_id: Option<String>,
    continuation: Option<String>,
    recovery_class: &'static str,
    safe_retry: ResponseSafeRetry,
    boundary: ExecutionBoundary,
    created_at_ns: i128,
}

/// Why a typed answer could not be rendered (an internal failure, never a partial answer).
#[derive(Debug)]
struct RenderError(&'static str);

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for RenderError {}

fn build_response(parts: ResponseParts) -> Result<String, Box<dyn std::error::Error>> {
    let payload_digest = ContentDigest::sha256(parts.payload_json.as_bytes());
    let short = parts.request_digest.to_text();
    let hex = short.split_once(':').map_or(short.as_str(), |(_, hex)| hex);
    let privacy = privacy_projection(&parts.anchor).envelope_json();
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
        privacy,
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
    agent_json::response_envelope(&envelope, &parts.affordance_objects)
        .ok_or_else(|| RenderError("affordance objects do not match the envelope").into())
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

/// Rendering context of one orientation's cells and affordances.
fn contexts(
    orientation: &DeploymentOrientation,
) -> (
    agent_json::CellContext<'_>,
    agent_json::AffordanceContext<'_>,
) {
    let capsule = orientation.capsule();
    (
        agent_json::CellContext {
            anchor: &capsule.anchor,
            mission_id: capsule.mission_id.as_str(),
            invalidators: &orientation.validity.invalidators,
        },
        agent_json::AffordanceContext {
            anchor: &capsule.anchor,
            world_envelope_id: &capsule.frame.world_envelope.envelope_id,
            expires_at_ns: orientation.validity.valid_until.0,
            invalidators: &orientation.validity.invalidators,
        },
    )
}

/// The capsule's `situationFrame` as `fss.agent_situation_frame.v1`.
fn situation_frame(orientation: &DeploymentOrientation) -> Result<String, RenderError> {
    let capsule = orientation.capsule();
    let frame = &capsule.frame;
    let (cell_context, _) = contexts(orientation);
    let cells: Vec<String> = frame
        .knowledge_cells
        .iter()
        .map(|cell| agent_json::knowledge_cell(cell, &cell_context))
        .collect();
    let receipt = &orientation.publication.compression_receipt;
    let entities: Vec<String> = orientation
        .hydration
        .iter()
        .filter(|slot| {
            slot.cells_inline || orientation.headline_event.as_ref() == Some(&slot.event_id)
        })
        .map(|slot| {
            agent_json::object(&[
                ("entityId", agent_json::string(slot.event_id.as_str())),
                ("kind", agent_json::string("event")),
                ("relevance", slot.consequence_severity.to_string()),
                ("state", agent_json::string(slot.physical_state.as_str())),
                ("provenance", agent_json::string("derived")),
                ("summary", agent_json::string(&slot.summary)),
                (
                    "evidenceHandles",
                    agent_json::strings([slot.handle.as_str()]),
                ),
            ])
        })
        .collect();
    let summarized_cells: usize = orientation
        .hydration
        .iter()
        .filter(|slot| !slot.cells_inline)
        .map(|slot| slot.cell_count)
        .sum();
    let selected = frame.knowledge_cells.len();
    let hard: Vec<&str> = frame
        .knowledge_cells
        .iter()
        .filter(|cell| agent_json::can_change_action(cell))
        .map(|cell| cell.claim_id())
        .collect();
    let mut decision_changing: Vec<String> = orientation.contradictions.clone();
    if let Some(top) = &orientation.headline_event {
        decision_changing.push(top.as_str().to_owned());
    }
    let world_stop = if orientation.aggregated_world_count > 0 {
        "per-event worlds aggregated per kind; members hydrate through event handles"
    } else {
        "complete"
    };
    let frame_digest = frame
        .frame_digest()
        .map_err(|_| RenderError("frame digest"))?;
    Ok(agent_json::object(&[
        ("schema", agent_json::string("fss.agent_situation_frame.v1")),
        ("frameId", agent_json::string(&frame.frame_id)),
        ("objectiveId", agent_json::string(&frame.objective_id)),
        ("anchor", agent_json::evidence_anchor(&frame.anchor)),
        ("priorFrameId", "null".to_owned()),
        (
            "worldEnvelope",
            agent_json::world_envelope(
                &frame.world_envelope,
                &capsule.affordances,
                &frame.knowledge_cells,
                &agent_json::WorldSelection {
                    candidate_world_count: orientation.candidate_world_count,
                    stop_reason: world_stop,
                },
            ),
        ),
        ("knowledgeCells", agent_json::array(&cells)),
        ("salientEntities", agent_json::array(&entities)),
        ("changes", agent_json::strings(&frame.changed)),
        (
            "contradictions",
            agent_json::strings(&orientation.contradictions),
        ),
        ("unknowns", agent_json::strings(&frame.unknown)),
        (
            "notObservableDomains",
            agent_json::strings(["site activity outside retained evidence"]),
        ),
        (
            "coverage",
            agent_json::object(&[
                ("status", agent_json::string("uncertified")),
                (
                    "domains",
                    agent_json::strings([capsule.anchor.site_lineage.as_str()]),
                ),
                ("witnessIds", "[]".to_owned()),
                (
                    "gaps",
                    agent_json::strings(["No CoverageWitness is retained for the site."]),
                ),
                ("absenceClaimsCertified", "false".to_owned()),
            ]),
        ),
        (
            "obligations",
            agent_json::strings(capsule.obligations.iter().map(|id| id.as_str())),
        ),
        (
            "evidenceHandles",
            agent_json::strings(&frame.evidence_handles),
        ),
        ("selectedHypothesisWorkspaceId", "null".to_owned()),
        ("activePlanId", "null".to_owned()),
        (
            "selectionWitness",
            agent_json::object(&[
                ("candidateCount", (selected + summarized_cells).to_string()),
                ("selectedCount", selected.to_string()),
                ("omittedCount", summarized_cells.to_string()),
                ("hardInclusions", agent_json::strings(hard)),
                (
                    "decisionChangingItems",
                    agent_json::strings(&decision_changing),
                ),
                (
                    "stopReason",
                    agent_json::string(receipt.stop_reason.as_str()),
                ),
                ("outputDigest", agent_json::string(&frame_digest.to_text())),
            ]),
        ),
    ]))
}

/// The orient payload: the capsule as `fss.situation_capsule.v1` with every verified
/// publication section for the view.
fn orient_payload(
    orientation: &DeploymentOrientation,
) -> Result<String, Box<dyn std::error::Error>> {
    let publication = &orientation.publication;
    let capsule = orientation.capsule();
    let (_, affordance_context) = contexts(orientation);
    let affordances = capsule
        .affordances
        .iter()
        .map(|candidate| agent_json::affordance(candidate, &affordance_context))
        .collect::<Option<Vec<_>>>()
        .ok_or(RenderError("unregistered affordance operation"))?;
    let objective = agent_json::objective_contract(&orientation.objective)
        .ok_or(RenderError("objective contract"))?;
    let attention: Vec<String> = orientation
        .attention
        .iter()
        .map(|item| {
            agent_json::object(&[
                ("itemId", agent_json::string(&item.item_id)),
                ("kind", agent_json::string(item.kind)),
                ("priorityClass", agent_json::string(item.priority_class)),
                ("missionRelevance", format!("{}", item.mission_relevance)),
                ("decisionImpact", format!("{}", item.decision_impact)),
                ("reason", agent_json::string(&item.reason)),
                ("handle", agent_json::string(&item.handle)),
            ])
        })
        .collect();
    let debt: Vec<String> = orientation
        .epistemic_debt
        .iter()
        .map(|item| {
            agent_json::object(&[
                ("debtId", agent_json::string(&item.debt_id)),
                ("assumption", agent_json::string(&item.assumption)),
                ("deferredReason", agent_json::string(&item.deferred_reason)),
                (
                    "dependentDecisions",
                    agent_json::strings(&item.dependent_decisions),
                ),
                (
                    "consequenceIfWrong",
                    agent_json::string(&item.consequence_if_wrong),
                ),
                ("cheapestTest", agent_json::string(&item.cheapest_test)),
                ("reviewTrigger", agent_json::string(&item.review_trigger)),
            ])
        })
        .collect();
    let validity = &orientation.validity;
    Ok(agent_json::object(&[
        ("schema", agent_json::string("fss.situation_capsule.v1")),
        (
            "contractBasis",
            agent_json::contract_basis(&capsule.contract_basis),
        ),
        ("capsuleId", agent_json::string(&capsule.capsule_id)),
        ("revision", capsule.revision.to_string()),
        ("missionId", agent_json::string(capsule.mission_id.as_str())),
        // No durable mission exists (session.open is not exposed): the orientation mission is
        // never revised.
        ("missionRevision", "0".to_owned()),
        ("sessionId", agent_json::string(capsule.session_id.as_str())),
        (
            "principalId",
            agent_json::string(capsule.principal_id.as_str()),
        ),
        ("anchor", agent_json::evidence_anchor(&capsule.anchor)),
        ("previousAnchor", "null".to_owned()),
        ("objectiveContract", objective),
        (
            "effectiveCapabilities",
            agent_json::strings([CAPABILITY_SITUATION_READ]),
        ),
        (
            "privacyProjection",
            privacy_projection(&capsule.anchor).capsule_json(),
        ),
        ("decisionDeadlineNs", "null".to_owned()),
        ("situationFrame", situation_frame(orientation)?),
        // No previous anchor was supplied, so no change is claimed.
        ("meaningfulDelta", "null".to_owned()),
        ("attentionFrontier", agent_json::array(&attention)),
        ("activeInvestigations", "[]".to_owned()),
        ("activeHypotheses", "[]".to_owned()),
        ("activePlans", "[]".to_owned()),
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
        ("epistemicDebt", agent_json::array(&debt)),
        (
            "resourceState",
            agent_json::resource_state(&publication.resource_state),
        ),
        ("affordances", agent_json::array(&affordances)),
        (
            "controlEnvelope",
            agent_json::control_envelope(&publication.control_envelope),
        ),
        (
            "contextPack",
            agent_json::context_pack(&publication.context_pack),
        ),
        (
            "compressionReceipt",
            agent_json::compression_receipt(&publication.compression_receipt),
        ),
        // Context items carry no aliases, so no symbol table generation exists.
        ("symbolTableGeneration", "0".to_owned()),
        (
            "validity",
            agent_json::object(&[
                ("validUntilNs", validity.valid_until.0.max(0).to_string()),
                ("invalidators", agent_json::strings(&validity.invalidators)),
                (
                    "reanchorRequiredOn",
                    agent_json::strings(&validity.reanchor_required_on),
                ),
            ]),
        ),
        (
            "continuation",
            agent_json::optional_string(publication.context_pack.continuation.as_deref()),
        ),
        (
            "decisionFingerprint",
            agent_json::string(&capsule.decision_fingerprint()?.to_text()),
        ),
        ("createdAtNs", capsule.created_at.0.max(0).to_string()),
    ]))
}

fn orient_response(
    orientation: &DeploymentOrientation,
) -> Result<String, Box<dyn std::error::Error>> {
    let capsule = orientation.capsule();
    let publication = &orientation.publication;
    let mut proof_pointers: Vec<String> = orientation
        .proof_roots()
        .iter()
        .map(|root| root.to_text())
        .collect();
    proof_pointers.push(publication.publication_digest.to_text());
    proof_pointers.push(orientation.projection.projection_digest().to_text());
    let (_, affordance_context) = contexts(orientation);
    let affordance_objects = agent_json::affordance_objects(
        &capsule.frame.next,
        &capsule.affordances,
        &affordance_context,
    )
    .ok_or(RenderError("next affordance objects"))?;
    let mut degradation = orientation.degradation.clone();
    degradation.push(
        "No previous anchor was supplied: meaningfulDelta is null and no change is claimed."
            .to_owned(),
    );
    build_response(ResponseParts {
        operation: "session.orient",
        request_digest: orientation.request_digest,
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
        degradation,
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers,
        affordances: capsule.frame.next.clone(),
        affordance_objects,
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
}

fn budget_refusal(
    snapshot: &DeploymentSnapshot,
    request_digest: ContentDigest,
    view: AgentView,
    principal: &PrincipalId,
    budget_tokens: u64,
    reason: String,
) -> Result<String, Box<dyn std::error::Error>> {
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
        affordance_objects: Vec::new(),
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
    result: Result<String, Box<dyn std::error::Error>>,
    exit: ExitIdentity,
    command: &str,
    root: &std::path::Path,
) -> (String, ExitIdentity) {
    match result {
        Ok(json) => (json, exit),
        Err(_) => internal_failure(command, root),
    }
}

/// Executes `orient`, returning the rendered response and its exit identity.
#[must_use]
pub fn execute_orient(args: &OrientArgs) -> (String, ExitIdentity) {
    let limits = OrientLimits::default();
    let snapshot = match read_deployment(&args.root, &limits) {
        Ok(snapshot) => snapshot,
        Err(error) => return read_refusal("orient", &args.root, &error),
    };
    let request = OrientRequest {
        view: args.view,
        principal: args.principal.clone(),
        budget_tokens: args.budget_tokens,
    };
    let request_digest = request.digest_at(&snapshot.anchor);
    match orient_deployment(&snapshot, &request, &limits) {
        Ok(orientation) => rendered(
            orient_response(&orientation),
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
    evidence_handles: Vec<agent_json::EvidenceHandle>,
    next_actions: Vec<ActionAffordance>,
    decision_digest: ContentDigest,
}

/// Rendered explain payload, next-action identities, and next-action objects.
type CognitivePayload = (String, Vec<String>, Vec<String>);

/// The explain payload (`fss.agent_cognitive_envelope.v1`) and its next-action identities and
/// objects.
fn cognitive(
    orientation: &DeploymentOrientation,
    request_digest: ContentDigest,
    parts: CognitiveParts,
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
fn explanation_handles(explanation: &EventExplanation) -> Vec<agent_json::EvidenceHandle> {
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

/// Privacy class of retained event revisions (the only privacy class fss-core uses).
const EVENT_PRIVACY_CLASS: &str = "private:property";

fn explanation_response(
    orientation: &DeploymentOrientation,
    explanation: &EventExplanation,
    request_digest: ContentDigest,
) -> Result<String, Box<dyn std::error::Error>> {
    let event = &explanation.event.event;
    let physical = explanation
        .cells
        .iter()
        .find(|cell| cell.claim_id().ends_with(":unknown-presence"))
        .map_or(KnowledgeState::Unknown, |cell| cell.knowledge_state());
    let mut propositions: Vec<EnvelopeProposition> = explanation
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
    // The event's per-event worlds (the members its orientation aggregates): each remains
    // exactly as possible as the event's physical-presence claim is uncertain.
    propositions.extend(explanation.worlds.iter().map(|world| {
        EnvelopeProposition {
            id: world.world_id.clone(),
            statement: format!(
                "{}{} world, consequence severity {}: {}",
                if explanation.residual_ids.contains(&world.world_id) {
                    "Adversarial residual"
                } else {
                    "Material alternative"
                },
                if world.protected { " (protected)" } else { "" },
                world.consequence_severity,
                world.description
            ),
            state: physical,
            provenance: "derived".to_owned(),
            evidence: world
                .evidence
                .iter()
                .map(|digest| digest.to_text())
                .collect(),
        }
    }));
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
    let answer_class = if event.state == EventState::Indeterminate {
        CognitiveAnswerClass::Indeterminate
    } else {
        CognitiveAnswerClass::HypothesisSet
    };
    let (payload, next_ids, next_objects) = cognitive(
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
            evidence_handles: explanation_handles(explanation),
            next_actions: explanation.affordances.clone(),
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
    let mut warnings = explanation.warnings.clone();
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
        payload_json: payload,
        epistemic_state: physical,
        completeness: Completeness::Partial,
        warnings,
        contradictions,
        degradation: vec![
            "Latency and CPU time are not metered by this reference path; consumed reports \
             reads and context tokens only."
                .to_owned(),
        ],
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers,
        affordances: next_ids,
        affordance_objects: next_objects,
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
) -> Result<String, Box<dyn std::error::Error>> {
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
    let reorient: Vec<ActionAffordance> = capsule
        .affordances
        .iter()
        .filter(|candidate| candidate.affordance_id == AFFORDANCE_REORIENT)
        .cloned()
        .collect();
    let (payload, next_ids, next_objects) = cognitive(
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
            evidence_handles: Vec::new(),
            next_actions: reorient,
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
        payload_json: payload,
        epistemic_state: KnowledgeState::Known,
        completeness: Completeness::Complete,
        warnings: Vec::new(),
        contradictions: Vec::new(),
        degradation: Vec::new(),
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers: vec![evidence.to_text()],
        affordances: next_ids,
        affordance_objects: next_objects,
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
        budget_tokens: None,
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
