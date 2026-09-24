#![forbid(unsafe_code)]
//! `fss session open` (AOP-001 `session.open`), `fss session handoff` (AOP-012 `handoff`), and
//! `fss session resume` (AOP-002 `session.resume`): durable, mission-scoped agent sessions over a
//! deployment root, answered as the registered `AgentResponseEnvelope`.
//!
//! [`fss_reference::deployment_session`] owns every durable effect of these commands, and every
//! one of them is agent-plane state under `<root>/agent/`: the session journal (sessions and
//! immutable workspace revisions) and root-last mission and handoff publications. The authority
//! ledger, the effect journal, and the deployment spool are only read. This module decodes
//! arguments and renders the typed values under their registered schemas: `session open` and
//! `session resume` answer `fss.situation_capsule.v1` (the registered response payload of AOP-001
//! and AOP-002), and `session handoff` answers `fss.agent_handoff_capsule.v1` (AOP-012). The
//! handoff publication also carries the handed-off session as `fss.agent_session.v1` and its
//! workspace revision as `fss.agent_session_capsule.v1`, so another agent can hydrate them from
//! the handoff alone. Affordances are listed, never executed.

use std::path::{Path, PathBuf};

use fss_core::{
    AgentView, BudgetVector, CanonicalEncode, Completeness, ContentDigest, HandoffId,
    KnowledgeState, LedgerAnchor, PrincipalId, ResponseOutcome, ResponseSafeRetry, SessionId,
};
use fss_reference::agent_orient::{
    DeploymentReadError, OrientError, OrientLimits, read_deployment,
};
use fss_reference::deployment_session::{
    DeploymentSessionError, HandoffRecord, HandoffRequest, MAX_MISSION_BYTES, MAX_NOTE_BYTES,
    MAX_OBJECTIVE_BYTES, MAX_SESSION_TOKEN_BUDGET, OpenSessionRequest, OpenedSession,
    PreparedHandoff, PublishedHandoff, ResumeRequest, ResumedSession, open_session,
    prepare_handoff, resume_session, split_assumption,
};

use crate::agent_json;
use crate::error::{CliError, ExitIdentity};
use crate::follow_cmd::meaningful_delta_json;
use crate::orient_cmd::{
    CapsuleOverrides, ERR_AGENT_CONTEXT_INCOMPLETE, ORIENT_VIEWS, RenderError, ResponseParts,
    build_response, collect_options, contexts, internal_failure, principal, read_refusal, rendered,
    required_root, situation_capsule_payload, take,
};
use crate::token::ArgToken;

/// Registered error identity: the session is unknown, closed, expired, or another principal's.
pub const ERR_AGENT_SESSION_NOT_FOUND: &str = "ERR-AGENT-SESSION-NOT-FOUND-001";
/// Registered error identity: the session or workspace basis no longer admits the request.
pub const ERR_AGENT_SESSION_STALE: &str = "ERR-AGENT-SESSION-STALE-001";
/// Registered error identity: no handoff with that identity is published in the deployment.
pub const ERR_AGENT_HANDOFF_NOT_FOUND: &str = "ERR-AGENT-HANDOFF-NOT-FOUND-001";
/// Registered error identity: the handoff is tampered, incomplete, expired, unauthorized, or
/// foreign.
pub const ERR_AGENT_HANDOFF_INVALID: &str = "ERR-AGENT-HANDOFF-INVALID-001";
/// Registered error identity: another command holds the deployment's agent-session store.
pub const ERR_AGENT_SESSION_STORE_LOCKED: &str = "ERR-AGENT-SESSION-STORE-LOCKED-001";
/// Registered error identity: the agent-session store failed verification.
pub const ERR_AGENT_SESSION_STORE_INVALID: &str = "ERR-AGENT-SESSION-STORE-INVALID-001";
/// Capability registry row admitting `session.open` (AOP-001).
pub const CAPABILITY_SESSION_OPEN: &str = "CAP-AGENT-SESSION-OPEN-001";
/// Capability registry row admitting `session.resume` (AOP-002).
pub const CAPABILITY_SESSION_READ: &str = "CAP-AGENT-SESSION-READ-001";
/// Capability registry row admitting `handoff` (AOP-012).
pub const CAPABILITY_HANDOFF_WRITE: &str = "CAP-AGENT-HANDOFF-WRITE-001";
/// Response payload schema of `session open` and `session resume`.
pub const SITUATION_PAYLOAD_SCHEMA: &str = "fss.situation_capsule.v1";
/// Response payload schema of `session handoff`.
pub const HANDOFF_PAYLOAD_SCHEMA: &str = "fss.agent_handoff_capsule.v1";

/// Options for `session open`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionOpenArgs {
    /// Existing deployment root.
    pub root: PathBuf,
    /// Mission statement (the `--mission` text, or the contents of the file it names).
    pub mission: String,
    /// Objective text.
    pub objective: String,
    /// Opening principal label.
    pub principal: PrincipalId,
    /// Orientation view the session compiles situations in (default `brief`).
    pub view: AgentView,
    /// Cumulative session token budget (default: the view's registered maximum).
    pub budget_tokens: u64,
}

/// Options for `session handoff`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionHandoffArgs {
    /// Existing deployment root.
    pub root: PathBuf,
    /// Session to hand off.
    pub session: SessionId,
    /// The session's principal.
    pub principal: PrincipalId,
    /// Operator note carried verbatim in the handoff.
    pub note: Option<String>,
}

/// Options for `session resume`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionResumeArgs {
    /// Existing deployment root.
    pub root: PathBuf,
    /// Published handoff to accept.
    pub handoff: HandoffId,
    /// Resuming principal.
    pub principal: PrincipalId,
}

/// One `fss session` subcommand.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionCommand {
    /// AOP-001 `session.open`.
    Open(SessionOpenArgs),
    /// AOP-012 `handoff`.
    Handoff(SessionHandoffArgs),
    /// AOP-002 `session.resume`.
    Resume(SessionResumeArgs),
}

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

/// Reads `--mission`: the contents of the regular file it names, or else the text itself.
fn mission_text(value: &str, index: usize) -> Result<String, CliError> {
    let path = Path::new(value);
    let text = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            if metadata.len() > MAX_MISSION_BYTES as u64 {
                return Err(malformed(
                    "session open",
                    "--mission",
                    value,
                    &format!("the mission file exceeds {MAX_MISSION_BYTES} bytes"),
                    index,
                ));
            }
            let bytes = std::fs::read(path).map_err(|error| {
                malformed(
                    "session open",
                    "--mission",
                    value,
                    &format!("the mission file cannot be read: {error}"),
                    index,
                )
            })?;
            String::from_utf8(bytes).map_err(|_| {
                malformed(
                    "session open",
                    "--mission",
                    value,
                    "the mission file is not UTF-8",
                    index,
                )
            })?
        }
        _ => value.to_owned(),
    };
    if text.is_empty() || text.len() > MAX_MISSION_BYTES {
        return Err(malformed(
            "session open",
            "--mission",
            value,
            &format!("the mission statement must be 1..={MAX_MISSION_BYTES} bytes"),
            index,
        ));
    }
    Ok(text)
}

fn parse_open(tokens: &[ArgToken]) -> Result<SessionOpenArgs, CliError> {
    const COMMAND: &str = "session open";
    let values = collect_options(
        COMMAND,
        tokens,
        &[
            "--root",
            "--mission",
            "--objective",
            "--principal",
            "--view",
            "--budget-tokens",
        ],
    )?;
    let root = required_root(COMMAND, &values)?;
    let (_, raw, index) = required(COMMAND, &values, "--mission", "a mission statement or file")?;
    let mission = mission_text(raw, *index)?;
    let (_, objective, index) = required(COMMAND, &values, "--objective", "an objective")?;
    if objective.len() > MAX_OBJECTIVE_BYTES {
        return Err(malformed(
            COMMAND,
            "--objective",
            objective,
            &format!("the objective must be at most {MAX_OBJECTIVE_BYTES} bytes"),
            *index,
        ));
    }
    let view = match take(&values, "--view") {
        None => AgentView::Brief,
        Some((_, value, index)) => {
            if !ORIENT_VIEWS.contains(&value.as_str()) {
                return Err(malformed(
                    COMMAND,
                    "--view",
                    value,
                    "view must be one of pulse, brief, epistemic_map",
                    *index,
                ));
            }
            AgentView::from_name(value).map_err(|_| {
                malformed(COMMAND, "--view", value, "view is not registered", *index)
            })?
        }
    };
    let budget_tokens = match take(&values, "--budget-tokens") {
        None => u64::from(view.maximum_tokens()),
        Some((_, value, index)) => match value.parse::<u64>() {
            Ok(tokens) if (1..=MAX_SESSION_TOKEN_BUDGET).contains(&tokens) => tokens,
            _ => {
                return Err(malformed(
                    COMMAND,
                    "--budget-tokens",
                    value,
                    &format!(
                        "the session budget must be an integer in 1..={MAX_SESSION_TOKEN_BUDGET}"
                    ),
                    *index,
                ));
            }
        },
    };
    Ok(SessionOpenArgs {
        root,
        mission,
        objective: objective.clone(),
        principal: principal(COMMAND, &values)?,
        view,
        budget_tokens,
    })
}

fn parse_handoff(tokens: &[ArgToken]) -> Result<SessionHandoffArgs, CliError> {
    const COMMAND: &str = "session handoff";
    let values = collect_options(
        COMMAND,
        tokens,
        &["--root", "--session", "--principal", "--note"],
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
    let note = match take(&values, "--note") {
        None => None,
        Some((_, value, index)) => {
            if value.len() > MAX_NOTE_BYTES {
                return Err(malformed(
                    COMMAND,
                    "--note",
                    value,
                    &format!("the note must be at most {MAX_NOTE_BYTES} bytes"),
                    *index,
                ));
            }
            Some(value.clone())
        }
    };
    Ok(SessionHandoffArgs {
        root,
        session,
        principal: principal(COMMAND, &values)?,
        note,
    })
}

fn parse_resume(tokens: &[ArgToken]) -> Result<SessionResumeArgs, CliError> {
    const COMMAND: &str = "session resume";
    let values = collect_options(COMMAND, tokens, &["--root", "--handoff", "--principal"])?;
    let root = required_root(COMMAND, &values)?;
    let (_, raw, index) = required(COMMAND, &values, "--handoff", "the handoff identity")?;
    let handoff = HandoffId::parse(raw.clone()).map_err(|_| {
        malformed(
            COMMAND,
            "--handoff",
            raw,
            "handoff identity must be 1..128 characters of [A-Za-z0-9._:-]",
            *index,
        )
    })?;
    Ok(SessionResumeArgs {
        root,
        handoff,
        principal: principal(COMMAND, &values)?,
    })
}

/// Parses `session <open|handoff|resume> --json --root <dir> ...`.
pub fn parse_session_args(tokens: &[ArgToken]) -> Result<SessionCommand, CliError> {
    let Some(sub) = tokens.get(1) else {
        return Err(CliError::MissingValue {
            option: "<open|handoff|resume>".to_owned(),
            command: Some("session".to_owned()),
            expected: "a session subcommand: open, handoff, or resume".to_owned(),
        });
    };
    let rest = &tokens[1..];
    match sub.as_str() {
        "open" => Ok(SessionCommand::Open(parse_open(rest)?)),
        "handoff" => Ok(SessionCommand::Handoff(parse_handoff(rest)?)),
        "resume" => Ok(SessionCommand::Resume(parse_resume(rest)?)),
        other if other.starts_with('-') => Err(CliError::UnknownOption {
            option: other.to_owned(),
            command: Some("session".to_owned()),
            index: sub.index,
        }),
        other => Err(CliError::UnknownCommand {
            command: other.to_owned(),
            context: Some("session".to_owned()),
            index: sub.index,
        }),
    }
}

fn idempotency_key(request_digest: ContentDigest) -> String {
    let text = request_digest.to_text();
    let hex = text.split_once(':').map_or(text.as_str(), |(_, hex)| hex);
    format!("idempotency:{hex}")
}

fn agent_plane_boundary(
    completed: String,
    invalidated: Vec<String>,
) -> fss_core::ExecutionBoundary {
    fss_core::ExecutionBoundary {
        completed: vec![completed],
        not_started: vec![
            "Every listed affordance: this command executes none of them.".to_owned(),
        ],
        possibly_occurred: Vec::new(),
        preserved_truth: vec![
            "Only agent-plane state under agent/ was written: no authority-ledger batch, \
             effect-journal record, or deployment spool object was created."
                .to_owned(),
        ],
        invalidated,
    }
}

// ---------------------------------------------------------------------------------------------
// session open
// ---------------------------------------------------------------------------------------------

fn open_response(opened: &OpenedSession) -> Result<String, Box<dyn std::error::Error>> {
    let orientation = &opened.orientation;
    let capsule = orientation.capsule();
    let publication = &orientation.publication;
    let mut proof_pointers: Vec<String> = orientation
        .proof_roots()
        .iter()
        .map(|root| root.to_text())
        .collect();
    proof_pointers.push(publication.publication_digest.to_text());
    proof_pointers.push(orientation.projection.projection_digest().to_text());
    proof_pointers.push(orientation.anchor_token.clone());
    proof_pointers.push(opened.mission.digest().to_text());
    proof_pointers.push(opened.mission_root.to_text());
    proof_pointers.push(opened.revision.digest().to_text());
    proof_pointers.push(opened.journal_root.to_text());
    let (_, affordance_context) = contexts(orientation);
    let affordance_objects = agent_json::affordance_objects(
        &capsule.frame.next,
        &capsule.affordances,
        &affordance_context,
    )
    .ok_or(RenderError("next affordance objects"))?;
    let mut degradation = orientation.degradation.clone();
    degradation.push(
        "The session was opened at this anchor: meaningfulDelta is null and no change is claimed."
            .to_owned(),
    );
    degradation.push(format!(
        "Session lease and handoff lifetimes run on the deployment evidence clock; this session \
         expires at evidence time {} ns.",
        opened.session.expires_at_ns
    ));
    build_response(ResponseParts {
        operation: "session.open",
        request_digest: opened.request_digest,
        principal: opened.session.principal_id.clone(),
        session_id: Some(opened.session.session_id.as_str().to_owned()),
        mission_id: Some(opened.session.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: orientation.view,
        capability: CAPABILITY_SESSION_OPEN,
        outcome: ResponseOutcome::Ok,
        error_id: None,
        payload_schema: SITUATION_PAYLOAD_SCHEMA,
        payload_json: situation_capsule_payload(
            orientation,
            &CapsuleOverrides {
                symbol_table_generation: opened.session.symbol_table_generation,
                ..CapsuleOverrides::default()
            },
        )?,
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
        boundary: agent_plane_boundary(
            format!(
                "Published mission record {} root-last and committed session {} with workspace \
                 revision 0 at commit {} (session journal root {}).",
                opened.mission.digest(),
                opened.session.session_id.as_str(),
                capsule.anchor.commit_sequence,
                opened.journal_root
            ),
            Vec::new(),
        ),
        created_at_ns: capsule.created_at.0,
        workspace_revision: Some(opened.revision.capsule().revision),
        idempotency_key: Some(idempotency_key(opened.request_digest)),
    })
}

// ---------------------------------------------------------------------------------------------
// session handoff
// ---------------------------------------------------------------------------------------------

/// Reasons the handoff's not-applicable sentinels give.
const NO_RETENTION_POLICY: &str = "no_retention_policy_retained";
const NO_DELETION_CLOSURE: &str = "deletion_closure_not_implemented";

fn assumption_objects(record: &HandoffRecord) -> Vec<String> {
    record
        .assumptions
        .iter()
        .map(|entry| {
            let (statement, text) = split_assumption(entry);
            let anchored = statement == fss_reference::deployment_session::ANCHOR_ASSUMPTION_ID;
            agent_json::object(&[
                ("statementId", agent_json::string(statement)),
                ("text", agent_json::string(text)),
                (
                    "epistemicState",
                    agent_json::string(if anchored { "known" } else { "unknown" }),
                ),
                (
                    "basis",
                    agent_json::strings([if anchored {
                        record.anchor_token.as_str()
                    } else {
                        statement
                    }]),
                ),
            ])
        })
        .collect()
}

fn handoff_payload(
    record: &HandoffRecord,
    objective: &str,
    publication_receipt: ContentDigest,
    workspace_digest: ContentDigest,
) -> String {
    let capsule = &record.capsule;
    let schema = HANDOFF_PAYLOAD_SCHEMA;
    let mut invalidated: Vec<&str> = record
        .invalidated_assumptions
        .iter()
        .map(|entry| split_assumption(entry).0)
        .collect();
    invalidated.sort_unstable();
    invalidated.dedup();
    let budgets = BudgetVector::builder()
        .tokens(record.token_budget)
        .build()
        .unwrap_or(BudgetVector::ZERO);
    agent_json::object(&[
        ("schema", agent_json::string(schema)),
        ("handoffId", agent_json::string(capsule.handoff_id.as_str())),
        ("missionId", agent_json::string(capsule.mission_id.as_str())),
        (
            "sourceSessionId",
            agent_json::string(capsule.source_session_id.as_str()),
        ),
        (
            "sourcePrincipalId",
            agent_json::string(capsule.source_principal_id.as_str()),
        ),
        ("anchor", agent_json::evidence_anchor(&capsule.anchor)),
        (
            "situationFingerprint",
            agent_json::string(&record.situation_fingerprint.to_text()),
        ),
        ("objective", agent_json::string(objective)),
        (
            "criteria",
            agent_json::object(&[
                ("success", "[]".to_owned()),
                ("failure", "[]".to_owned()),
                ("stop", "[]".to_owned()),
            ]),
        ),
        ("budgets", agent_json::budget(&budgets)),
        (
            "symbolTableGeneration",
            record.symbol_table_generation.to_string(),
        ),
        ("activeInvestigations", "[]".to_owned()),
        ("findings", "[]".to_owned()),
        ("unresolvedQuestions", agent_json::strings(&record.unknowns)),
        (
            "assumptions",
            agent_json::array(&assumption_objects(record)),
        ),
        ("invalidatedAssumptions", agent_json::strings(invalidated)),
        ("activePlans", "[]".to_owned()),
        (
            "preparedOperations",
            agent_json::strings(&record.prepared_operations),
        ),
        ("tasks", "[]".to_owned()),
        ("leases", "[]".to_owned()),
        ("obligations", agent_json::strings(&record.obligations)),
        (
            "indeterminateEffects",
            agent_json::strings(&record.indeterminate_effects),
        ),
        (
            "recommendedAffordances",
            agent_json::strings(&record.recommended_affordances),
        ),
        (
            "proofPointers",
            agent_json::strings([
                record.publication_digest.to_text(),
                record.mission_digest.to_text(),
                workspace_digest.to_text(),
                record.session_digest.to_text(),
                record.anchor_token.clone(),
            ]),
        ),
        (
            "requiredCapabilityProjection",
            agent_json::strings([CAPABILITY_SESSION_READ]),
        ),
        (
            "compressionReceiptId",
            agent_json::string(&record.compression_receipt_id),
        ),
        (
            "continuation",
            agent_json::optional_string(record.continuation.as_deref()),
        ),
        ("createdAtNs", capsule.created_at.0.max(0).to_string()),
        ("expiresAtNs", capsule.expires_at.0.max(0).to_string()),
        (
            "contractBasis",
            agent_json::contract_basis(&capsule.contract_basis),
        ),
        (
            "handoffRoot",
            agent_json::string(&capsule.handoff_root.to_text()),
        ),
        ("childRoots", agent_json::digests(&capsule.child_roots)),
        (
            "situationCapsuleRoot",
            agent_json::string(&capsule.situation_capsule_root.to_text()),
        ),
        (
            "recipientScope",
            agent_json::object(&[
                (
                    "allowedPrincipals",
                    agent_json::strings([capsule.source_principal_id.as_str()]),
                ),
                (
                    "requiredCapabilities",
                    agent_json::strings([CAPABILITY_SESSION_READ]),
                ),
                (
                    "purpose",
                    agent_json::string(&format!(
                        "Resume session {} of mission {} on this deployment.",
                        capsule.source_session_id.as_str(),
                        capsule.mission_id.as_str()
                    )),
                ),
            ]),
        ),
        (
            "privacyGenerationId",
            agent_json::string(&record.privacy_generation_id),
        ),
        (
            "retentionClass",
            agent_json::string(&agent_json::not_applicable_sentinel(
                schema,
                "retentionClass",
                NO_RETENTION_POLICY,
            )),
        ),
        (
            "deletionClosureId",
            agent_json::string(&agent_json::not_applicable_sentinel(
                schema,
                "deletionClosureId",
                NO_DELETION_CLOSURE,
            )),
        ),
        (
            "resumePolicy",
            agent_json::object(&[
                ("rebaseRequired", "true".to_owned()),
                ("invalidators", agent_json::strings(&record.invalidators)),
                ("minimumSemanticProtocol", agent_json::string("fss/1")),
                (
                    "expiredAction",
                    agent_json::string("orient_from_live_state"),
                ),
            ]),
        ),
        (
            "publicationReceiptId",
            agent_json::string(&publication_receipt.to_text()),
        ),
    ])
}

/// The public projections published beside the handoff record: the session and the workspace
/// revision handed off.
fn handoff_children(prepared: &PreparedHandoff) -> Vec<Vec<u8>> {
    let basis = &prepared.record.capsule.contract_basis;
    vec![
        agent_json::agent_session(&prepared.session, basis).into_bytes(),
        agent_json::session_capsule(
            prepared.workspace.capsule(),
            basis,
            prepared.workspace.invalidated_actions(),
        )
        .into_bytes(),
    ]
}

fn handoff_response(
    prepared_orientation: &fss_reference::agent_orient::DeploymentOrientation,
    published: &PublishedHandoff,
    objective: &str,
    children: &[Vec<u8>],
    journal_root: ContentDigest,
    request_digest: ContentDigest,
) -> Result<String, Box<dyn std::error::Error>> {
    let record = &published.record;
    let capsule = &record.capsule;
    let orientation = prepared_orientation;
    let mut proof_pointers = vec![
        capsule.handoff_root.to_text(),
        published.receipt.root.to_text(),
        published.receipt.record_digest.to_text(),
        record.workspace_digest.to_text(),
        record.mission_digest.to_text(),
        journal_root.to_text(),
        record.anchor_token.clone(),
    ];
    proof_pointers.extend(
        children
            .iter()
            .map(|child| ContentDigest::sha256(child).to_text()),
    );
    let (_, affordance_context) = contexts(orientation);
    let affordance_objects = agent_json::affordance_objects(
        &record.recommended_affordances,
        &orientation.capsule().affordances,
        &affordance_context,
    )
    .ok_or(RenderError("recommended affordance objects"))?;
    let mut degradation = orientation.degradation.clone();
    degradation.push(
        "The handoff carries no success, failure, or stop criteria: none were supplied at \
         session open."
            .to_owned(),
    );
    build_response(ResponseParts {
        operation: "handoff",
        request_digest,
        principal: capsule.source_principal_id.clone(),
        session_id: Some(capsule.source_session_id.as_str().to_owned()),
        mission_id: Some(capsule.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: AgentView::Handoff,
        capability: CAPABILITY_HANDOFF_WRITE,
        outcome: ResponseOutcome::Ok,
        error_id: None,
        payload_schema: HANDOFF_PAYLOAD_SCHEMA,
        payload_json: handoff_payload(
            record,
            objective,
            published.receipt.record_digest,
            record.workspace_digest,
        ),
        epistemic_state: orientation.epistemic_state,
        completeness: orientation.capsule().completeness,
        warnings: orientation.warnings.clone(),
        contradictions: orientation.contradictions.clone(),
        degradation,
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers,
        affordances: record.recommended_affordances.clone(),
        affordance_objects,
        decision_fingerprint: capsule.handoff_root,
        compression_receipt_id: Some(record.compression_receipt_id.clone()),
        continuation: record.continuation.clone(),
        recovery_class: "safe_read_retry",
        safe_retry: ResponseSafeRetry::YesSameRequest,
        boundary: agent_plane_boundary(
            format!(
                "Published handoff {} of session {} root-last (root {}) as of commit {}.",
                capsule.handoff_id.as_str(),
                capsule.source_session_id.as_str(),
                published.receipt.root,
                capsule.anchor.commit_sequence
            ),
            Vec::new(),
        ),
        created_at_ns: capsule.created_at.0,
        workspace_revision: Some(record.workspace_revision),
        idempotency_key: Some(idempotency_key(request_digest)),
    })
}

// ---------------------------------------------------------------------------------------------
// session resume
// ---------------------------------------------------------------------------------------------

fn resume_response(resumed: &ResumedSession) -> Result<String, Box<dyn std::error::Error>> {
    let result = &resumed.result;
    let capsule = result.capsule();
    let publication = &result.publication;
    let handoff = &resumed.handoff;
    let delta_json = meaningful_delta_json(
        &resumed.delta,
        &resumed.items,
        &resumed.delta.continuation,
        result,
    );
    let extra_debt: Vec<String> = if resumed.anchor_moved {
        resumed
            .handed_off
            .capsule()
            .assumptions
            .iter()
            .map(|entry| {
                agent_json::workspace_debt_item(
                    entry,
                    &format!(
                        "Invalidated since the handoff anchor {}: the head is now {}.",
                        handoff.anchor_token, result.anchor_token
                    ),
                )
            })
            .collect()
    } else {
        Vec::new()
    };
    let mut proof_pointers: Vec<String> = result
        .proof_roots()
        .iter()
        .map(|root| root.to_text())
        .collect();
    proof_pointers.push(publication.publication_digest.to_text());
    proof_pointers.push(result.projection.projection_digest().to_text());
    proof_pointers.push(resumed.delta.selection_witness.to_text());
    proof_pointers.push(handoff.capsule.handoff_root.to_text());
    proof_pointers.push(resumed.handoff_publication_root.to_text());
    proof_pointers.push(resumed.revision.digest().to_text());
    proof_pointers.push(resumed.journal_root.to_text());
    proof_pointers.push(handoff.anchor_token.clone());
    proof_pointers.push(result.anchor_token.clone());
    proof_pointers.dedup();
    let (_, affordance_context) = contexts(result);
    let affordance_objects = agent_json::affordance_objects(
        &capsule.frame.next,
        &capsule.affordances,
        &affordance_context,
    )
    .ok_or(RenderError("next affordance objects"))?;
    let mut warnings = result.warnings.clone();
    if resumed.anchor_moved {
        warnings.push(format!(
            "The committed position moved since the handoff ({} -> {}): {} assumption(s), \
             action(s), and anchor-bound fact(s) are invalidated; re-derive every next action \
             at the head before acting.",
            handoff.anchor_token,
            result.anchor_token,
            resumed.invalidated.len()
        ));
    }
    let mut degradation = result.degradation.clone();
    if !resumed.anchor_moved {
        degradation.push(
            "Nothing was committed since the handoff anchor: no assumption is invalidated; the \
             engine still reports every persisting protected class."
                .to_owned(),
        );
    }
    // Described from the resulting state, never from whether this call committed, so an exact
    // retry after a lost answer renders the identical answer.
    let (id, session, revision, commit) = (
        handoff.capsule.handoff_id.as_str(),
        resumed.session.session_id.as_str(),
        resumed.revision.capsule().revision,
        capsule.anchor.commit_sequence,
    );
    let completed = if resumed.revision.digest() == handoff.workspace_digest {
        format!(
            "Accepted handoff {id}; session {session} holds the handed-off workspace revision \
             {revision} at commit {commit}, so nothing needed a rebase."
        )
    } else if resumed.revision.parent_digest() == Some(handoff.workspace_digest) {
        format!(
            "Accepted handoff {id}; session {session} is rebased from the handed-off revision \
             onto commit {commit} as workspace revision {revision}."
        )
    } else {
        degradation.push(
            "The session's workspace had already moved past the handed-off revision; the current \
             head revision is returned."
                .to_owned(),
        );
        format!(
            "Accepted handoff {id}; session {session} already holds the later workspace revision \
             {revision} at commit {commit}."
        )
    };
    build_response(ResponseParts {
        operation: "session.resume",
        request_digest: resumed.request_digest,
        principal: resumed.session.principal_id.clone(),
        session_id: Some(resumed.session.session_id.as_str().to_owned()),
        mission_id: Some(resumed.session.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: result.view,
        capability: CAPABILITY_SESSION_READ,
        outcome: ResponseOutcome::Ok,
        error_id: None,
        payload_schema: SITUATION_PAYLOAD_SCHEMA,
        payload_json: situation_capsule_payload(
            result,
            &CapsuleOverrides {
                previous_anchor: Some(&handoff.capsule.anchor),
                meaningful_delta: Some(delta_json),
                extra_debt,
                symbol_table_generation: resumed.session.symbol_table_generation,
            },
        )?,
        epistemic_state: result.epistemic_state,
        completeness: capsule.completeness,
        warnings,
        contradictions: result.contradictions.clone(),
        degradation,
        budgets_json: agent_json::budget_summary(
            &result.requested,
            &resumed
                .basis
                .consumed
                .checked_add(&result.consumed)
                .map_err(|_| RenderError("consumed budget overflows"))?,
        ),
        proof_pointers,
        affordances: capsule.frame.next.clone(),
        affordance_objects,
        decision_fingerprint: capsule.decision_fingerprint()?,
        compression_receipt_id: Some(publication.compression_receipt.receipt_id.clone()),
        continuation: publication.context_pack.continuation.clone(),
        recovery_class: "safe_read_retry",
        safe_retry: ResponseSafeRetry::YesSameRequest,
        boundary: agent_plane_boundary(completed, resumed.invalidated.clone()),
        created_at_ns: capsule.created_at.0,
        workspace_revision: Some(resumed.revision.capsule().revision),
        idempotency_key: Some(idempotency_key(resumed.request_digest)),
    })
}

// ---------------------------------------------------------------------------------------------
// Refusals and dispatch.
// ---------------------------------------------------------------------------------------------

/// What differs between the three commands' refusals.
struct Operation {
    command: &'static str,
    name: &'static str,
    capability: &'static str,
    payload_schema: &'static str,
    view: AgentView,
    root: PathBuf,
    principal: PrincipalId,
    request: Vec<u8>,
}

/// One typed refusal: what was refused and how to recover.
struct Refusal {
    error_id: &'static str,
    reason: String,
    guidance: &'static str,
    recovery_class: &'static str,
    safe_retry: ResponseSafeRetry,
}

fn classify(error: DeploymentSessionError) -> Result<Refusal, DeploymentSessionError> {
    Ok(match error {
        DeploymentSessionError::SessionUnknown => Refusal {
            error_id: ERR_AGENT_SESSION_NOT_FOUND,
            reason: error.to_string(),
            guidance: "Open a session with `fss session open`, or resume a published handoff \
                       with `fss session resume`.",
            recovery_class: "operator_action_required",
            safe_retry: ResponseSafeRetry::No,
        },
        DeploymentSessionError::SessionStale(_) => Refusal {
            error_id: ERR_AGENT_SESSION_STALE,
            reason: error.to_string(),
            guidance: "Hand off and resume the session, or open a new one at the head.",
            recovery_class: "rebase_required",
            safe_retry: ResponseSafeRetry::YesAfterRefresh,
        },
        DeploymentSessionError::HandoffUnknown => Refusal {
            error_id: ERR_AGENT_HANDOFF_NOT_FOUND,
            reason: error.to_string(),
            guidance: "Resume only a handoff identity that `fss session handoff` returned for \
                       this deployment.",
            recovery_class: "never_unchanged",
            safe_retry: ResponseSafeRetry::No,
        },
        DeploymentSessionError::HandoffInvalid(_) => Refusal {
            error_id: ERR_AGENT_HANDOFF_INVALID,
            reason: error.to_string(),
            guidance: "Never resume silently: orient the live deployment and open a new session, \
                       or have the source principal publish a fresh handoff.",
            recovery_class: "never_unchanged",
            safe_retry: ResponseSafeRetry::No,
        },
        DeploymentSessionError::StoreLocked => Refusal {
            error_id: ERR_AGENT_SESSION_STORE_LOCKED,
            reason: error.to_string(),
            guidance: "Retry after the other session command finishes.",
            recovery_class: "backoff",
            safe_retry: ResponseSafeRetry::YesSameRequest,
        },
        DeploymentSessionError::StoreInvalid(_) => Refusal {
            error_id: ERR_AGENT_SESSION_STORE_INVALID,
            reason: error.to_string(),
            guidance: "Inspect agent/ under the deployment root; the session store is never \
                       repaired implicitly.",
            recovery_class: "operator_action_required",
            safe_retry: ResponseSafeRetry::No,
        },
        DeploymentSessionError::Orient(
            orient
            @ (OrientError::ContextBudgetExceeded { .. } | OrientError::TooManyEvents { .. }),
        ) => Refusal {
            error_id: ERR_AGENT_CONTEXT_INCOMPLETE,
            reason: orient.to_string(),
            guidance: "Critical context is never truncated; open the session with --view brief \
                       or --view epistemic_map.",
            recovery_class: "never_unchanged",
            safe_retry: ResponseSafeRetry::No,
        },
        other => return Err(other),
    })
}

fn refusal_response(
    operation: &Operation,
    anchor: &LedgerAnchor,
    created_at_ns: i128,
    refusal: Refusal,
) -> Result<String, Box<dyn std::error::Error>> {
    let request_digest = crate::orient_cmd::request_identity(operation.name, |encoder| {
        encoder.bytes(&operation.request);
        operation.principal.encode_canonical(encoder);
        anchor.encode_canonical(encoder);
    });
    build_response(ResponseParts {
        operation: operation.name,
        request_digest,
        principal: operation.principal.clone(),
        session_id: None,
        mission_id: None,
        anchor: anchor.clone(),
        view: operation.view,
        capability: operation.capability,
        outcome: ResponseOutcome::Refused,
        error_id: Some(refusal.error_id),
        payload_schema: operation.payload_schema,
        payload_json: "null".to_owned(),
        epistemic_state: KnowledgeState::Unknown,
        completeness: Completeness::Partial,
        warnings: Vec::new(),
        contradictions: Vec::new(),
        degradation: vec![refusal.reason, refusal.guidance.to_owned()],
        budgets_json: agent_json::budget_summary(&BudgetVector::ZERO, &BudgetVector::ZERO),
        proof_pointers: vec![anchor.state_root.to_text()],
        affordances: Vec::new(),
        affordance_objects: Vec::new(),
        decision_fingerprint: request_digest,
        compression_receipt_id: None,
        continuation: None,
        recovery_class: refusal.recovery_class,
        safe_retry: refusal.safe_retry,
        boundary: fss_core::ExecutionBoundary {
            completed: vec![format!(
                "Read the deployment at commit {}; the request was refused.",
                anchor.commit_sequence
            )],
            not_started: vec!["The requested session command.".to_owned()],
            possibly_occurred: Vec::new(),
            preserved_truth: vec![
                "No authority-ledger batch, effect-journal record, or deployment spool object \
                 was written."
                    .to_owned(),
            ],
            invalidated: Vec::new(),
        },
        created_at_ns,
        workspace_revision: None,
        idempotency_key: None,
    })
}

fn refuse(operation: &Operation, error: DeploymentSessionError) -> (String, ExitIdentity) {
    let refusal = match error {
        DeploymentSessionError::Read(read) => {
            return read_refusal(operation.command, &operation.root, &read);
        }
        other => match classify(other) {
            Ok(refusal) => refusal,
            Err(_) => return internal_failure(operation.command, &operation.root),
        },
    };
    let snapshot = match read_deployment(&operation.root, &OrientLimits::default()) {
        Ok(snapshot) => snapshot,
        Err(error @ DeploymentReadError::NotADeployment { .. }) => {
            return read_refusal(operation.command, &operation.root, &error);
        }
        Err(_) => return internal_failure(operation.command, &operation.root),
    };
    rendered(
        refusal_response(
            operation,
            &snapshot.anchor,
            snapshot.latest_evidence_time.0,
            refusal,
        ),
        ExitIdentity::AGENT_REFUSED,
        operation.command,
        &operation.root,
    )
}

fn execute_open(args: &SessionOpenArgs) -> (String, ExitIdentity) {
    let request = OpenSessionRequest {
        mission: args.mission.clone(),
        objective: args.objective.clone(),
        principal: args.principal.clone(),
        view: args.view,
        token_budget: args.budget_tokens,
    };
    match open_session(&args.root, &request) {
        Ok(opened) => rendered(
            open_response(&opened),
            ExitIdentity::SUCCESS,
            "session",
            &args.root,
        ),
        Err(error) => refuse(
            &Operation {
                command: "session",
                name: "session.open",
                capability: CAPABILITY_SESSION_OPEN,
                payload_schema: SITUATION_PAYLOAD_SCHEMA,
                view: args.view,
                root: args.root.clone(),
                principal: args.principal.clone(),
                request: [args.mission.as_bytes(), b"\0", args.objective.as_bytes()].concat(),
            },
            error,
        ),
    }
}

fn execute_handoff(args: &SessionHandoffArgs) -> (String, ExitIdentity) {
    let operation = Operation {
        command: "session",
        name: "handoff",
        capability: CAPABILITY_HANDOFF_WRITE,
        payload_schema: HANDOFF_PAYLOAD_SCHEMA,
        view: AgentView::Handoff,
        root: args.root.clone(),
        principal: args.principal.clone(),
        request: args.session.as_str().as_bytes().to_vec(),
    };
    let request = HandoffRequest {
        session_id: args.session.clone(),
        principal: args.principal.clone(),
        note: args.note.clone(),
    };
    let prepared = match prepare_handoff(&args.root, &request) {
        Ok(prepared) => prepared,
        Err(error) => return refuse(&operation, error),
    };
    let children = handoff_children(&prepared);
    let orientation = prepared.orientation.clone();
    let objective = prepared.mission.objective.clone();
    let journal_root = prepared.journal_root;
    let request_digest = prepared.request_digest;
    match prepared.publish(&children) {
        Ok(published) => rendered(
            handoff_response(
                &orientation,
                &published,
                &objective,
                &children,
                journal_root,
                request_digest,
            ),
            ExitIdentity::SUCCESS,
            "session",
            &args.root,
        ),
        Err(error) => refuse(&operation, error),
    }
}

fn execute_resume(args: &SessionResumeArgs) -> (String, ExitIdentity) {
    let request = ResumeRequest {
        handoff_id: args.handoff.clone(),
        principal: args.principal.clone(),
    };
    match resume_session(&args.root, &request) {
        Ok(resumed) => rendered(
            resume_response(&resumed),
            ExitIdentity::SUCCESS,
            "session",
            &args.root,
        ),
        Err(error) => refuse(
            &Operation {
                command: "session",
                name: "session.resume",
                capability: CAPABILITY_SESSION_READ,
                payload_schema: SITUATION_PAYLOAD_SCHEMA,
                view: AgentView::Handoff,
                root: args.root.clone(),
                principal: args.principal.clone(),
                request: args.handoff.as_str().as_bytes().to_vec(),
            },
            error,
        ),
    }
}

/// Executes one `fss session` subcommand, returning the rendered response and its exit identity.
#[must_use]
pub fn execute_session(command: &SessionCommand) -> (String, ExitIdentity) {
    match command {
        SessionCommand::Open(args) => execute_open(args),
        SessionCommand::Handoff(args) => execute_handoff(args),
        SessionCommand::Resume(args) => execute_resume(args),
    }
}
