#![forbid(unsafe_code)]
//! Shared findings (FSS-227): the case-board intent family of `fss investigate` (AOP-006),
//! answered as the registered `AgentResponseEnvelope` carrying `fss.agent_cognitive_envelope.v1`.
//!
//! [`fss_reference::deployment_session::findings`] owns the records: immutable, root-last
//! publications whose `fss.agent_finding.v1` rendering is hydrated from the agent publication
//! store. Findings never mutate evidence, a case, policy, or an effect; disagreements are
//! reported, never ranked away.
//!
//! ```text
//! finding          --case ID --claim TEXT --state STATE --supporting sha256:..[,..]
//!                  [--contradicting sha256:..[,..]] [--hypothesis H] [--follow-up ID[,ID..]]
//!                  [--disagrees-with FINDING[,FINDING..]] [--supersedes FINDING]
//! finding-withdraw --finding ID --claim TEXT --supporting sha256:..[,..]
//! finding-list     [--case ID]
//! ```

use std::path::PathBuf;

use fss_core::{
    AgentView, BudgetVector, CognitiveAnswerClass, ContentDigest, ContractError, EnvelopeCoverage,
    EnvelopeEpistemic, EnvelopeProposition, KnowledgeState, ResponseOutcome, ResponseSafeRetry,
    SessionId,
};
use fss_reference::deployment_session::findings::{
    CAPABILITY_FINDING, FindingAction, FindingAnswer, FindingDraft, FindingRecord, FindingRequest,
    FindingView, MAX_FINDING_LINKS, finding,
};

use crate::agent_json;
use crate::error::{CliError, ExitIdentity};
use crate::orient_cmd::{
    CognitiveParts, ResponseParts, build_response, cognitive_payload, collect_options, principal,
    rendered, required_root, take,
};
use crate::session_cmd::{Operation, agent_plane_boundary, idempotency_key, refuse};
use crate::token::ArgToken;

/// Response payload schema of every finding answer.
pub const COGNITIVE_PAYLOAD_SCHEMA: &str = "fss.agent_cognitive_envelope.v1";
/// Schema of the rendering published beside each finding record.
pub const FINDING_SCHEMA: &str = "fss.agent_finding.v1";
const COMMAND: &str = "investigate";
const OPTIONS: &[&str] = &[
    "--root",
    "--session",
    "--principal",
    "--transition",
    "--case",
    "--claim",
    "--state",
    "--supporting",
    "--contradicting",
    "--hypothesis",
    "--follow-up",
    "--disagrees-with",
    "--supersedes",
    "--finding",
];
const COMMON: &[&str] = &["--root", "--session", "--principal", "--transition"];

/// Options for one finding transition of `fss investigate`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingArgs {
    /// Existing deployment root.
    pub root: PathBuf,
    /// The decoded request.
    pub request: FindingRequest,
}

/// True when `tokens` select a finding transition (`--transition finding...`).
#[must_use]
pub fn selects_finding(tokens: &[ArgToken]) -> bool {
    let texts: Vec<&str> = tokens.iter().map(ArgToken::as_str).collect();
    texts.iter().enumerate().any(|(index, text)| {
        text.strip_prefix("--transition=")
            .or_else(|| {
                (*text == "--transition")
                    .then(|| texts.get(index + 1).copied())
                    .flatten()
            })
            .is_some_and(|value| value == "finding" || value.starts_with("finding-"))
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

fn only(
    transition: &str,
    values: &[(String, String, usize)],
    allowed: &[&str],
) -> Result<(), CliError> {
    for (option, value, index) in values {
        if !COMMON.contains(&option.as_str()) && !allowed.contains(&option.as_str()) {
            return Err(malformed(
                option,
                value,
                &format!("not an option of --transition {transition}"),
                *index,
            ));
        }
    }
    Ok(())
}

fn portable(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn identity(values: &[(String, String, usize)], option: &str) -> Result<String, CliError> {
    let (_, raw, index) = required(values, option, "an identity of [A-Za-z0-9._:-]")?;
    if !portable(raw) {
        return Err(malformed(
            option,
            raw,
            "identity must be 1..128 characters of [A-Za-z0-9._:-]",
            *index,
        ));
    }
    Ok(raw.clone())
}

fn optional_identity(
    values: &[(String, String, usize)],
    option: &str,
) -> Result<Option<String>, CliError> {
    take(values, option)
        .map(|_| identity(values, option))
        .transpose()
}

fn identities(values: &[(String, String, usize)], option: &str) -> Result<Vec<String>, CliError> {
    let Some((_, raw, index)) = take(values, option) else {
        return Ok(Vec::new());
    };
    let items: Vec<String> = raw.split(',').map(ToOwned::to_owned).collect();
    if items.len() > MAX_FINDING_LINKS || !items.iter().all(|item| portable(item)) {
        return Err(malformed(
            option,
            raw,
            "expected 1..64 comma-separated identities of [A-Za-z0-9._:-]",
            *index,
        ));
    }
    Ok(items)
}

fn digests(values: &[(String, String, usize)], option: &str) -> Result<Vec<String>, CliError> {
    let Some((_, raw, index)) = take(values, option) else {
        return Ok(Vec::new());
    };
    raw.split(',')
        .map(|item| {
            ContentDigest::parse(item)
                .map(|digest| digest.to_text())
                .map_err(|_| {
                    malformed(
                        option,
                        raw,
                        "expected comma-separated sha256:<64 hex> digests",
                        *index,
                    )
                })
        })
        .collect()
}

fn claim(values: &[(String, String, usize)]) -> Result<String, CliError> {
    let (_, raw, index) = required(values, "--claim", "the finding's claim")?;
    if raw.is_empty() || raw.len() > 8192 {
        return Err(malformed(
            "--claim",
            raw,
            "the claim must be 1..=8192 bytes",
            *index,
        ));
    }
    Ok(raw.clone())
}

/// Parses one `investigate --transition finding...` invocation.
pub fn parse_finding_args(tokens: &[ArgToken]) -> Result<FindingArgs, CliError> {
    let values = collect_options(COMMAND, tokens, OPTIONS)?;
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
    let principal = principal(COMMAND, &values)?;
    let (_, transition, index) = required(&values, "--transition", "a finding transition")?;
    let transition = transition.as_str();
    let action = match transition {
        "finding" => {
            only(
                transition,
                &values,
                &[
                    "--case",
                    "--claim",
                    "--state",
                    "--supporting",
                    "--contradicting",
                    "--hypothesis",
                    "--follow-up",
                    "--disagrees-with",
                    "--supersedes",
                ],
            )?;
            let (_, raw, state_index) =
                required(&values, "--state", "a registered knowledge state")?;
            let epistemic_state = raw.parse::<KnowledgeState>().map_err(|_| {
                malformed(
                    "--state",
                    raw,
                    "state must be a registered knowledge state (known, estimated, unknown, \
                     conflicted, stale, not_observable, redacted, indeterminate, not_applicable)",
                    *state_index,
                )
            })?;
            FindingAction::Publish(FindingDraft {
                case_id: identity(&values, "--case")?,
                hypothesis_id: optional_identity(&values, "--hypothesis")?,
                claim: claim(&values)?,
                epistemic_state,
                supporting: digests(&values, "--supporting")?,
                contradicting: digests(&values, "--contradicting")?,
                follow_up: identities(&values, "--follow-up")?,
                disagrees_with: identities(&values, "--disagrees-with")?,
                supersedes: optional_identity(&values, "--supersedes")?,
            })
        }
        "finding-withdraw" => {
            only(
                transition,
                &values,
                &["--finding", "--claim", "--supporting"],
            )?;
            FindingAction::Withdraw {
                finding_id: identity(&values, "--finding")?,
                claim: claim(&values)?,
                supporting: digests(&values, "--supporting")?,
            }
        }
        "finding-list" => {
            only(transition, &values, &["--case"])?;
            FindingAction::List {
                case_id: optional_identity(&values, "--case")?,
            }
        }
        other => {
            return Err(malformed(
                "--transition",
                other,
                "finding transitions are finding, finding-withdraw, or finding-list",
                *index,
            ));
        }
    };
    Ok(FindingArgs {
        root,
        request: FindingRequest {
            session_id,
            principal,
            action,
        },
    })
}

/// One finding as `fss.agent_finding.v1` (the rendering published beside its record).
pub fn finding_json(record: &FindingRecord) -> Result<String, ContractError> {
    let finding = record.finding()?;
    Ok(agent_json::object(&[
        ("schema", agent_json::string(FINDING_SCHEMA)),
        (
            "contractBasis",
            agent_json::contract_basis(&fss_core::reference_contract_basis()),
        ),
        ("findingId", agent_json::string(&finding.finding_id)),
        ("missionId", agent_json::string(finding.mission_id.as_str())),
        ("branchId", "null".to_owned()),
        (
            "authorPrincipalId",
            agent_json::string(&finding.author_principal_id),
        ),
        ("anchor", agent_json::evidence_anchor(&finding.anchor)),
        (
            "questionOrClaim",
            agent_json::string(&finding.question_or_claim),
        ),
        (
            "epistemicState",
            agent_json::string(finding.epistemic_state.as_str()),
        ),
        (
            "supportingEvidence",
            agent_json::strings(&finding.supporting_evidence),
        ),
        (
            "contradictoryEvidence",
            agent_json::strings(&finding.contradictory_evidence),
        ),
        ("assumptions", "[]".to_owned()),
        ("coverage", agent_json::strings(&finding.coverage)),
        (
            "methodReceipts",
            agent_json::strings(&finding.method_receipts),
        ),
        (
            "affectedObjects",
            agent_json::strings(&finding.affected_objects),
        ),
        (
            "suggestedFollowUp",
            agent_json::strings(&finding.suggested_follow_up),
        ),
        (
            "supersedes",
            agent_json::optional_string(record.supersedes.as_deref()),
        ),
        (
            "withdrawn",
            if record.withdrawn { "true" } else { "false" }.to_owned(),
        ),
        ("createdAtNs", finding.created_at_ns.max(0).to_string()),
    ]))
}

/// One finding as an envelope proposition, in the standing a reader must see.
fn finding_proposition(view: &FindingView) -> EnvelopeProposition {
    let record = &view.record;
    let standing = match (&view.superseded_by, record.withdrawn) {
        (_, true) => format!(
            "withdraws {}",
            record.supersedes.as_deref().unwrap_or("nothing")
        ),
        (Some(successor), false) => format!("superseded by {successor}"),
        (None, false) if !view.disputed_by.is_empty() => {
            format!("disputed by {}", view.disputed_by.join(", "))
        }
        (None, false) => "undisputed".to_owned(),
    };
    EnvelopeProposition {
        id: record.finding_id.clone(),
        statement: format!(
            "Finding {} by session {} on case {}{} ({} as recorded; {}): {}",
            record.finding_id,
            record.session_id.as_str(),
            record.case_id,
            record
                .hypothesis_id
                .as_deref()
                .map(|hypothesis| format!(", hypothesis {hypothesis}"))
                .unwrap_or_default(),
            record.epistemic_state.as_str(),
            standing,
            record.claim
        ),
        state: view.standing(),
        provenance: "derived".to_owned(),
        evidence: record.supporting.clone(),
    }
}

fn finding_handle(view: &FindingView) -> agent_json::EvidenceHandle {
    agent_json::EvidenceHandle {
        handle_id: format!("fss://finding/{}/{}", view.record.finding_id, view.root),
        object_digest: view.rendering,
        kind: "agent_finding".to_owned(),
        hydration: "H0",
        allowed_hydration: vec!["H0", "H1"],
        privacy_class: "private:property".to_owned(),
        availability: "available",
        estimated_cost: BudgetVector::ZERO,
        required_capability: Some(CAPABILITY_FINDING.to_owned()),
    }
}

fn response(answer: &FindingAnswer) -> Result<String, Box<dyn std::error::Error>> {
    let orientation = &answer.orientation;
    let capsule = orientation.capsule();
    let shown: Vec<&FindingView> = match &answer.finding {
        Some(view) => vec![view],
        None => answer.findings.iter().collect(),
    };
    let conflicts: Vec<String> = answer
        .findings
        .iter()
        .filter(|view| view.is_active() && !view.disputed_by.is_empty())
        .map(|view| {
            format!(
                "Finding {} is disputed by {}.",
                view.record.finding_id,
                view.disputed_by.join(", ")
            )
        })
        .collect();
    let domain = format!(
        "fss://mission/{}/findings",
        answer.session.mission_id.as_str()
    );
    let decision_digest = match &answer.finding {
        Some(view) => view.rendering,
        None => capsule.decision_fingerprint()?,
    };
    let (payload, next_ids, next_objects) = cognitive_payload(
        orientation,
        answer.request_digest,
        COMMAND,
        AgentView::Case,
        CognitiveParts {
            answer_class: if answer.finding.is_some() {
                CognitiveAnswerClass::DirectFact
            } else {
                CognitiveAnswerClass::BoundedSummary
            },
            epistemic: EnvelopeEpistemic {
                propositions: shown.iter().map(|view| finding_proposition(view)).collect(),
                assumptions: vec![
                    "Findings are immutable: a correction is a superseding finding or a \
                     withdrawal, never an edit."
                        .to_owned(),
                ],
                invalidators: conflicts.clone(),
            },
            coverage: EnvelopeCoverage {
                authorized_domain: vec![domain.clone()],
                observed_domain: vec![domain],
                not_observable_domain: Vec::new(),
                omitted_count: 0,
                omission_reasons: Vec::new(),
                stop_reason: "complete".to_owned(),
            },
            evidence_handles: shown.iter().map(|view| finding_handle(view)).collect(),
            next_actions: capsule
                .affordances
                .iter()
                .filter(|affordance| capsule.frame.next.contains(&affordance.affordance_id))
                .cloned()
                .collect(),
            decision_digest,
        },
    )?;
    let mut degradation = orientation.degradation.clone();
    if answer.head_moved {
        degradation.push(
            "The deployment head has moved past this session's anchor: findings are bound to \
             the session's anchor."
                .to_owned(),
        );
    }
    if let Some(view) = &answer.finding
        && !answer.committed
    {
        degradation.push(format!(
            "Finding {} was already published: this is the published record, unchanged.",
            view.record.finding_id
        ));
    }
    degradation.extend(
        conflicts
            .iter()
            .map(|line| format!("Unresolved conflict: {line}")),
    );
    let mut proof_pointers = Vec::new();
    if let Some(view) = &answer.finding {
        proof_pointers.push(view.root.to_text());
        proof_pointers.push(view.rendering.to_text());
    }
    proof_pointers.push(orientation.anchor_token.clone());
    let completed = match &answer.finding {
        Some(view) => format!(
            "{} finding {} root-last (root {}).",
            if answer.committed {
                "Published"
            } else {
                "Read the already published"
            },
            view.record.finding_id,
            view.root
        ),
        None => format!(
            "Listed {} finding(s) of mission {} ({} in unresolved disagreement).",
            answer.findings.len(),
            answer.session.mission_id.as_str(),
            conflicts.len()
        ),
    };
    build_response(ResponseParts {
        operation: COMMAND,
        request_digest: answer.request_digest,
        principal: answer.session.principal_id.clone(),
        session_id: Some(answer.session.session_id.as_str().to_owned()),
        mission_id: Some(answer.session.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: AgentView::Case,
        capability: CAPABILITY_FINDING,
        outcome: ResponseOutcome::Ok,
        error_id: None,
        payload_schema: COGNITIVE_PAYLOAD_SCHEMA,
        payload_json: payload,
        epistemic_state: orientation.epistemic_state,
        completeness: capsule.completeness,
        warnings: orientation.warnings.clone(),
        contradictions: orientation.contradictions.clone(),
        degradation,
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers,
        affordances: next_ids,
        affordance_objects: next_objects,
        decision_fingerprint: decision_digest,
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
        boundary: agent_plane_boundary(completed, Vec::new()),
        created_at_ns: capsule.created_at.0,
        workspace_revision: None,
        idempotency_key: Some(idempotency_key(answer.request_digest)),
    })
}

/// Executes one finding transition, returning the rendered response and its exit identity.
#[must_use]
pub fn execute_finding(args: &FindingArgs) -> (String, ExitIdentity) {
    match finding(&args.root, &args.request, &finding_json) {
        Ok(answer) => rendered(
            response(&answer),
            ExitIdentity::SUCCESS,
            COMMAND,
            &args.root,
        ),
        Err(error) => refuse(
            &Operation {
                command: COMMAND,
                name: COMMAND,
                capability: CAPABILITY_FINDING,
                payload_schema: COGNITIVE_PAYLOAD_SCHEMA,
                view: AgentView::Case,
                root: args.root.clone(),
                principal: args.request.principal.clone(),
                request: [
                    args.request.session_id.as_str().as_bytes(),
                    b"\0finding\0",
                    format!("{:?}", args.request.action).as_bytes(),
                ]
                .concat(),
            },
            error,
        ),
    }
}
