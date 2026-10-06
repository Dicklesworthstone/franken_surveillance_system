#![forbid(unsafe_code)]
//! `fss investigate` (AOP-006 `investigate`): durable, mission-scoped investigation cases over a
//! deployment root, answered as the registered `AgentResponseEnvelope`.
//!
//! [`fss_reference::deployment_session::investigation`] owns every durable effect: case
//! revisions are committed to the deployment's agent-session journal under `<root>/agent/`. The
//! authority ledger, effect journal, and spool are only read. A case is cognition: no transition
//! executes a probe, certifies physical truth, or grants effect authority.
//!
//! Transitions (`--transition`, one registered operation):
//!
//! ```text
//! open       --case-file FILE|-                       new case in draft (exact retry is harmless)
//! inspect    --case ID [--revision sha256:..]         current head or an exact retained revision
//! list                                                the session-bound situation with every case
//! activate   --case ID --expected sha256:..
//! cite       --case ID --expected .. --hypothesis H --evidence sha256:.. --side support|contradiction
//! assess     --case ID --expected .. --hypothesis H --disposition supported|disfavored|refuted
//!            --evidence sha256:..
//! set-state  --case ID --expected .. --state S --reason sha256:..
//! conclude   --case ID --expected .. --conclusion resolved|refuted --stop-rule TEXT
//!            --assessment sha256:.. --residual-unknowns ID[,ID..]|none
//! rebase     --case ID --expected ..                  carry the case onto the session's anchor
//! readmit    --case ID --expected .. --hypothesis H --evidence sha256:.. --side ..
//!            --witness sha256:..
//! expand     --case ID --expected .. --expansion-file FILE|-
//! ```
//!
//! Every case answer carries the case revision digest as its `decisionFingerprint`; that digest
//! is the exact `--expected` precondition of the next change.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use fss_core::{
    AgentView, CaseDiscriminator, CaseHypothesis, ContentDigest, HypothesisDisposition,
    InvestigationLifecycle, KnowledgeState, KnownStatement, PrincipalId, ResponseOutcome,
    ResponseSafeRetry, SessionId,
};
use fss_reference::agent_session::checkpoint::journal::coordination::investigations::InvestigationChange;
use fss_reference::agent_session::checkpoint::journal::coordination::investigations::InvestigationRevision;
use fss_reference::agent_session::checkpoint::journal::coordination::investigations::evolution::InvestigationCitation;
use fss_reference::deployment_session::investigation::{
    CaseAction, CaseAnswer, CaseDeadline, CaseDraft, InvestigateRequest, investigate,
    stale_case_ids,
};

use crate::agent_json;
use crate::error::{CliError, ExitIdentity};
use crate::json_input::{Value, read_document};
use crate::orient_cmd::{
    CapsuleOverrides, RenderError, ResponseParts, build_response, collect_options, contexts,
    principal, rendered, required_root, situation_capsule_payload, take,
};
use crate::session_cmd::{
    Operation, SITUATION_PAYLOAD_SCHEMA, agent_plane_boundary, idempotency_key, refuse,
};
use crate::token::ArgToken;

/// Capability registry row of AOP-006 (`investigate`).
pub const CAPABILITY_CASE_WRITE: &str = "CAP-AGENT-CASE-WRITE-001";
/// Response payload schema of a case answer.
pub const INVESTIGATION_PAYLOAD_SCHEMA: &str = "fss.investigation_state.v1";

const COMMAND: &str = "investigate";
const OPTIONS: &[&str] = &[
    "--root",
    "--session",
    "--principal",
    "--transition",
    "--case",
    "--case-file",
    "--revision",
    "--expected",
    "--hypothesis",
    "--evidence",
    "--side",
    "--disposition",
    "--state",
    "--reason",
    "--conclusion",
    "--stop-rule",
    "--assessment",
    "--residual-unknowns",
    "--witness",
    "--expansion-file",
];
const COMMON: &[&str] = &["--root", "--session", "--principal", "--transition"];

/// Options for `fss investigate`.
#[derive(Clone, Debug, PartialEq)]
pub struct InvestigateArgs {
    /// Existing deployment root.
    pub root: PathBuf,
    /// Session whose authority admits the command.
    pub session: SessionId,
    /// The session's principal.
    pub principal: PrincipalId,
    /// The decoded intent.
    pub action: CaseAction,
}

// Every field compares exactly (no floating-point values), so equality is reflexive.
impl Eq for InvestigateArgs {}

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

fn digest(values: &[(String, String, usize)], option: &str) -> Result<ContentDigest, CliError> {
    let (_, raw, index) = required(values, option, "a sha256:<64 hex> digest")?;
    ContentDigest::parse(raw)
        .map_err(|_| malformed(option, raw, "expected a sha256:<64 hex> digest", *index))
}

fn case_id(values: &[(String, String, usize)]) -> Result<String, CliError> {
    let (_, raw, index) = required(values, "--case", "the case identity")?;
    if raw.is_empty()
        || raw.len() > 128
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(malformed(
            "--case",
            raw,
            "case identity must be 1..128 characters of [A-Za-z0-9._:-]",
            *index,
        ));
    }
    Ok(raw.clone())
}

fn text(values: &[(String, String, usize)], option: &str, max: usize) -> Result<String, CliError> {
    let (_, raw, index) = required(values, option, "a non-empty value")?;
    if raw.len() > max {
        return Err(malformed(
            option,
            raw,
            &format!("must be at most {max} bytes"),
            *index,
        ));
    }
    Ok(raw.clone())
}

fn side(values: &[(String, String, usize)]) -> Result<bool, CliError> {
    let (_, raw, index) = required(values, "--side", "support or contradiction")?;
    match raw.as_str() {
        "support" => Ok(false),
        "contradiction" => Ok(true),
        _ => Err(malformed(
            "--side",
            raw,
            "side must be support or contradiction",
            *index,
        )),
    }
}

fn lifecycle(raw: &str) -> Option<InvestigationLifecycle> {
    Some(match raw {
        "awaiting_evidence" | "awaiting-evidence" => InvestigationLifecycle::AwaitingEvidence,
        "awaiting_approval" | "awaiting-approval" => InvestigationLifecycle::AwaitingApproval,
        "blocked" => InvestigationLifecycle::Blocked,
        "indeterminate" => InvestigationLifecycle::Indeterminate,
        "cancelled" => InvestigationLifecycle::Cancelled,
        "closed" => InvestigationLifecycle::Closed,
        _ => return None,
    })
}

/// Refuses options that the chosen transition does not take (exact grammar exhaustion).
fn only(
    transition: &str,
    values: &[(String, String, usize)],
    allowed: &[&str],
) -> Result<(), CliError> {
    for (name, _, index) in values {
        if !COMMON.contains(&name.as_str()) && !allowed.contains(&name.as_str()) {
            return Err(CliError::UnknownOption {
                option: name.clone(),
                command: Some(format!("{COMMAND} --transition {transition}")),
                index: *index,
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Intent documents.
// ---------------------------------------------------------------------------------------------

type Fields = BTreeMap<String, Value>;

fn object<'a>(value: &'a Value, what: &str) -> Result<&'a Fields, String> {
    value
        .object()
        .ok_or_else(|| format!("{what} must be a JSON object"))
}

fn exact_keys(fields: &Fields, what: &str, allowed: &[&str]) -> Result<(), String> {
    for key in fields.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("{what} has an unknown field `{key}`"));
        }
    }
    Ok(())
}

fn field_text(fields: &Fields, key: &str, what: &str) -> Result<String, String> {
    fields
        .get(key)
        .and_then(Value::text)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("{what} needs a string `{key}`"))
}

fn field_texts(fields: &Fields, key: &str, what: &str) -> Result<Vec<String>, String> {
    match fields.get(key) {
        None => Ok(Vec::new()),
        Some(value) => value
            .array()
            .ok_or_else(|| format!("{what}: `{key}` must be an array of strings"))?
            .iter()
            .map(|item| {
                item.text()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| format!("{what}: `{key}` must be an array of strings"))
            })
            .collect(),
    }
}

fn field_state(
    fields: &Fields,
    what: &str,
    default: KnowledgeState,
) -> Result<KnowledgeState, String> {
    match fields.get("epistemicState") {
        None => Ok(default),
        Some(value) => {
            let name = value
                .text()
                .ok_or_else(|| format!("{what}: `epistemicState` must be a string"))?;
            KnowledgeState::from_name(name)
                .map_err(|_| format!("{what}: `{name}` is not a registered knowledge state"))
        }
    }
}

fn hypothesis(value: &Value, what: &str) -> Result<CaseHypothesis, String> {
    let fields = object(value, what)?;
    exact_keys(
        fields,
        what,
        &[
            "hypothesisId",
            "description",
            "epistemicState",
            "predictions",
        ],
    )?;
    Ok(CaseHypothesis {
        hypothesis_id: field_text(fields, "hypothesisId", what)?,
        description: field_text(fields, "description", what)?,
        epistemic_state: field_state(fields, what, KnowledgeState::Unknown)?,
        predictions: field_texts(fields, "predictions", what)?,
        evidence: Vec::new(),
        contradictions: Vec::new(),
    })
}

fn statement(value: &Value, what: &str, default: KnowledgeState) -> Result<KnownStatement, String> {
    let fields = object(value, what)?;
    exact_keys(
        fields,
        what,
        &["statementId", "text", "epistemicState", "basis"],
    )?;
    Ok(KnownStatement {
        statement_id: field_text(fields, "statementId", what)?,
        text: field_text(fields, "text", what)?,
        epistemic_state: field_state(fields, what, default)?,
        basis: field_texts(fields, "basis", what)?,
    })
}

fn discriminator(value: &Value, what: &str) -> Result<CaseDiscriminator, String> {
    let fields = object(value, what)?;
    exact_keys(
        fields,
        what,
        &[
            "discriminatorId",
            "description",
            "separates",
            "expectedOutcomes",
        ],
    )?;
    Ok(CaseDiscriminator {
        discriminator_id: field_text(fields, "discriminatorId", what)?,
        description: field_text(fields, "description", what)?,
        separates: field_texts(fields, "separates", what)?,
        expected_outcomes: field_texts(fields, "expectedOutcomes", what)?,
    })
}

fn items<'a>(fields: &'a Fields, key: &str) -> Result<&'a [Value], String> {
    match fields.get(key) {
        None => Ok(&[]),
        Some(value) => value
            .array()
            .ok_or_else(|| format!("`{key}` must be an array")),
    }
}

/// Decodes an `open` case document (camelCase fields of `fss.investigation_state.v1`).
///
/// Identity, mission, revision, lifecycle state, basis anchor, and contract basis are never read
/// from the document; citations are attached only through `cite`.
pub fn decode_case_draft(document: &Value) -> Result<CaseDraft, String> {
    let fields = object(document, "the case document")?;
    exact_keys(
        fields,
        "the case document",
        &[
            "caseId",
            "question",
            "decisionInformed",
            "hypotheses",
            "knowns",
            "unknowns",
            "discriminators",
            "probes",
            "stopRules",
            "decisionDeadlineNs",
            "decisionWindowNs",
        ],
    )?;
    let deadline = match (
        fields.get("decisionDeadlineNs"),
        fields.get("decisionWindowNs"),
    ) {
        (Some(at), None) => CaseDeadline::At(
            at.integer()
                .ok_or("`decisionDeadlineNs` must be an integer (or its decimal string)")?,
        ),
        (None, Some(after)) => CaseDeadline::After(
            after
                .integer()
                .ok_or("`decisionWindowNs` must be an integer (or its decimal string)")?,
        ),
        _ => {
            return Err(
                "give exactly one of `decisionDeadlineNs` (absolute evidence time) or \
                 `decisionWindowNs` (after the current evidence time)"
                    .to_owned(),
            );
        }
    };
    Ok(CaseDraft {
        case_id: field_text(fields, "caseId", "the case document")?,
        question: field_text(fields, "question", "the case document")?,
        decision_informed: field_text(fields, "decisionInformed", "the case document")?,
        hypotheses: items(fields, "hypotheses")?
            .iter()
            .map(|value| hypothesis(value, "a hypothesis"))
            .collect::<Result<_, _>>()?,
        knowns: items(fields, "knowns")?
            .iter()
            .map(|value| statement(value, "a known", KnowledgeState::Known))
            .collect::<Result<_, _>>()?,
        unknowns: items(fields, "unknowns")?
            .iter()
            .map(|value| statement(value, "an unknown", KnowledgeState::Unknown))
            .collect::<Result<_, _>>()?,
        discriminators: items(fields, "discriminators")?
            .iter()
            .map(|value| discriminator(value, "a discriminator"))
            .collect::<Result<_, _>>()?,
        probes: field_texts(fields, "probes", "the case document")?,
        stop_rules: field_texts(fields, "stopRules", "the case document")?,
        deadline,
    })
}

/// Decodes an `expand` document: `{"hypothesis": {..}, "discriminator": {..}, "probe": ".."}`.
pub fn decode_expansion(
    document: &Value,
) -> Result<(CaseHypothesis, CaseDiscriminator, String), String> {
    let fields = object(document, "the expansion document")?;
    exact_keys(
        fields,
        "the expansion document",
        &["hypothesis", "discriminator", "probe"],
    )?;
    let hypothesis = hypothesis(
        fields.get("hypothesis").ok_or("missing `hypothesis`")?,
        "the hypothesis",
    )?;
    let discriminator = discriminator(
        fields
            .get("discriminator")
            .ok_or("missing `discriminator`")?,
        "the discriminator",
    )?;
    Ok((
        hypothesis,
        discriminator,
        field_text(fields, "probe", "the expansion document")?,
    ))
}

fn document(values: &[(String, String, usize)], option: &str) -> Result<Value, CliError> {
    let (_, raw, index) = required(values, option, "a JSON file path, or - for stdin")?;
    read_document(raw).map_err(|reason| malformed(option, raw, &reason, *index))
}

/// Parses `investigate --json --root <dir> --session <id> --transition <t> ...`.
pub fn parse_investigate_args(tokens: &[ArgToken]) -> Result<InvestigateArgs, CliError> {
    let values = collect_options(COMMAND, tokens, OPTIONS)?;
    let root = required_root(COMMAND, &values)?;
    let (_, raw, index) = required(&values, "--session", "the session identity")?;
    let session = SessionId::parse(raw.clone()).map_err(|_| {
        malformed(
            "--session",
            raw,
            "session identity must be 1..128 characters of [A-Za-z0-9._:-]",
            *index,
        )
    })?;
    let principal = principal(COMMAND, &values)?;
    let (_, transition, index) = required(
        &values,
        "--transition",
        "open, inspect, list, activate, cite, assess, set-state, conclude, rebase, readmit, or \
         expand",
    )?;
    let transition = transition.as_str();
    let action = match transition {
        "open" => {
            only(transition, &values, &["--case-file"])?;
            let document = document(&values, "--case-file")?;
            let draft = decode_case_draft(&document).map_err(|reason| {
                let (_, raw, index) = take(&values, "--case-file").cloned().unwrap_or_default();
                malformed("--case-file", &raw, &reason, index)
            })?;
            CaseAction::Open(Box::new(draft))
        }
        "inspect" => {
            only(transition, &values, &["--case", "--revision"])?;
            let revision = match take(&values, "--revision") {
                None => None,
                Some(_) => Some(digest(&values, "--revision")?),
            };
            CaseAction::Inspect {
                case_id: case_id(&values)?,
                revision,
            }
        }
        "list" => {
            only(transition, &values, &[])?;
            CaseAction::List
        }
        "rebase" => {
            only(transition, &values, &["--case", "--expected"])?;
            CaseAction::Rebase {
                case_id: case_id(&values)?,
                expected: digest(&values, "--expected")?,
            }
        }
        "readmit" => {
            only(
                transition,
                &values,
                &[
                    "--case",
                    "--expected",
                    "--hypothesis",
                    "--evidence",
                    "--side",
                    "--witness",
                ],
            )?;
            CaseAction::Readmit {
                case_id: case_id(&values)?,
                expected: digest(&values, "--expected")?,
                citation: InvestigationCitation {
                    hypothesis: text(&values, "--hypothesis", 128)?,
                    evidence: digest(&values, "--evidence")?,
                    contradicts: side(&values)?,
                },
                witness: digest(&values, "--witness")?,
            }
        }
        "expand" => {
            only(
                transition,
                &values,
                &["--case", "--expected", "--expansion-file"],
            )?;
            let document = document(&values, "--expansion-file")?;
            let (hypothesis, discriminator, probe) =
                decode_expansion(&document).map_err(|reason| {
                    let (_, raw, index) = take(&values, "--expansion-file")
                        .cloned()
                        .unwrap_or_default();
                    malformed("--expansion-file", &raw, &reason, index)
                })?;
            CaseAction::Expand {
                case_id: case_id(&values)?,
                expected: digest(&values, "--expected")?,
                hypothesis: Box::new(hypothesis),
                discriminator: Box::new(discriminator),
                probe,
            }
        }
        "activate" | "cite" | "assess" | "set-state" | "conclude" => {
            let change = match transition {
                "activate" => {
                    only(transition, &values, &["--case", "--expected"])?;
                    InvestigationChange::Activate
                }
                "cite" => {
                    only(
                        transition,
                        &values,
                        &[
                            "--case",
                            "--expected",
                            "--hypothesis",
                            "--evidence",
                            "--side",
                        ],
                    )?;
                    InvestigationChange::Cite {
                        hypothesis: text(&values, "--hypothesis", 128)?,
                        evidence: digest(&values, "--evidence")?,
                        contradicts: side(&values)?,
                    }
                }
                "assess" => {
                    only(
                        transition,
                        &values,
                        &[
                            "--case",
                            "--expected",
                            "--hypothesis",
                            "--disposition",
                            "--evidence",
                        ],
                    )?;
                    let (_, raw, index) = required(
                        &values,
                        "--disposition",
                        "supported, disfavored, or refuted",
                    )?;
                    let disposition = match raw.as_str() {
                        "supported" => HypothesisDisposition::Supported,
                        "disfavored" => HypothesisDisposition::Disfavored,
                        "refuted" => HypothesisDisposition::Refuted,
                        _ => {
                            return Err(malformed(
                                "--disposition",
                                raw,
                                "disposition must be supported, disfavored, or refuted",
                                *index,
                            ));
                        }
                    };
                    InvestigationChange::Assess {
                        hypothesis: text(&values, "--hypothesis", 128)?,
                        disposition,
                        evidence: digest(&values, "--evidence")?,
                    }
                }
                "set-state" => {
                    only(
                        transition,
                        &values,
                        &["--case", "--expected", "--state", "--reason"],
                    )?;
                    let (_, raw, index) = required(&values, "--state", "a lifecycle state")?;
                    let state = lifecycle(raw).ok_or_else(|| {
                        malformed(
                            "--state",
                            raw,
                            "state must be awaiting_evidence, awaiting_approval, blocked, \
                             indeterminate, cancelled, or closed",
                            *index,
                        )
                    })?;
                    InvestigationChange::SetState {
                        state,
                        reason: digest(&values, "--reason")?,
                    }
                }
                _ => {
                    only(
                        transition,
                        &values,
                        &[
                            "--case",
                            "--expected",
                            "--conclusion",
                            "--stop-rule",
                            "--assessment",
                            "--residual-unknowns",
                        ],
                    )?;
                    let (_, raw, index) = required(&values, "--conclusion", "resolved or refuted")?;
                    let refuted = match raw.as_str() {
                        "resolved" => false,
                        "refuted" => true,
                        _ => {
                            return Err(malformed(
                                "--conclusion",
                                raw,
                                "conclusion must be resolved or refuted",
                                *index,
                            ));
                        }
                    };
                    let (_, residuals, _) = required(
                        &values,
                        "--residual-unknowns",
                        "the comma-separated identities of every unknown, or none",
                    )?;
                    let residual_unknowns: BTreeSet<String> = if residuals == "none" {
                        BTreeSet::new()
                    } else {
                        residuals.split(',').map(ToOwned::to_owned).collect()
                    };
                    InvestigationChange::Conclude {
                        refuted,
                        stop_rule: text(&values, "--stop-rule", 1024)?,
                        assessment: digest(&values, "--assessment")?,
                        residual_unknowns,
                    }
                }
            };
            CaseAction::Change {
                case_id: case_id(&values)?,
                expected: digest(&values, "--expected")?,
                change,
            }
        }
        other => {
            return Err(malformed(
                "--transition",
                other,
                "transition must be open, inspect, list, activate, cite, assess, set-state, \
                 conclude, rebase, readmit, or expand",
                *index,
            ));
        }
    };
    Ok(InvestigateArgs {
        root,
        session,
        principal,
        action,
    })
}

// ---------------------------------------------------------------------------------------------
// Rendering.
// ---------------------------------------------------------------------------------------------

fn statement_json(statement: &KnownStatement) -> String {
    agent_json::object(&[
        ("statementId", agent_json::string(&statement.statement_id)),
        ("text", agent_json::string(&statement.text)),
        (
            "epistemicState",
            agent_json::string(statement.epistemic_state.as_str()),
        ),
        ("basis", agent_json::strings(&statement.basis)),
    ])
}

/// One case revision as `fss.investigation_state.v1`, with each hypothesis's disposition (an
/// orthogonal coordinate, never folded into its knowledge state) and the exact revision digests.
#[must_use]
pub fn investigation_json(revision: &InvestigationRevision) -> String {
    let record = revision.record();
    let dispositions = revision.control().hypotheses();
    let hypotheses: Vec<String> = record
        .hypotheses
        .iter()
        .map(|hypothesis| {
            let disposition = dispositions
                .get(&hypothesis.hypothesis_id)
                .map_or("live", |disposition| disposition.as_str());
            agent_json::object(&[
                (
                    "hypothesisId",
                    agent_json::string(&hypothesis.hypothesis_id),
                ),
                ("description", agent_json::string(&hypothesis.description)),
                (
                    "epistemicState",
                    agent_json::string(hypothesis.epistemic_state.as_str()),
                ),
                ("disposition", agent_json::string(disposition)),
                ("predictions", agent_json::strings(&hypothesis.predictions)),
                ("evidence", agent_json::digests(&hypothesis.evidence)),
                (
                    "contradictions",
                    agent_json::digests(&hypothesis.contradictions),
                ),
            ])
        })
        .collect();
    let discriminators: Vec<String> = record
        .discriminators
        .iter()
        .map(|discriminator| {
            agent_json::object(&[
                (
                    "discriminatorId",
                    agent_json::string(&discriminator.discriminator_id),
                ),
                (
                    "description",
                    agent_json::string(&discriminator.description),
                ),
                ("separates", agent_json::strings(&discriminator.separates)),
                (
                    "expectedOutcomes",
                    agent_json::strings(&discriminator.expected_outcomes),
                ),
            ])
        })
        .collect();
    agent_json::object(&[
        ("schema", agent_json::string(INVESTIGATION_PAYLOAD_SCHEMA)),
        (
            "contractBasis",
            agent_json::contract_basis(&record.contract_basis),
        ),
        (
            "investigationId",
            agent_json::string(&record.investigation_id),
        ),
        ("missionId", agent_json::string(record.mission_id.as_str())),
        ("revision", record.revision.to_string()),
        ("state", agent_json::string(record.state.as_str())),
        ("question", agent_json::string(&record.question)),
        (
            "decisionInformed",
            agent_json::string(&record.decision_informed),
        ),
        (
            "basisAnchor",
            agent_json::evidence_anchor(&record.basis_anchor),
        ),
        ("hypotheses", agent_json::array(&hypotheses)),
        (
            "knowns",
            agent_json::array(&record.knowns.iter().map(statement_json).collect::<Vec<_>>()),
        ),
        (
            "unknowns",
            agent_json::array(
                &record
                    .unknowns
                    .iter()
                    .map(statement_json)
                    .collect::<Vec<_>>(),
            ),
        ),
        ("discriminators", agent_json::array(&discriminators)),
        ("probes", agent_json::strings(&record.probes)),
        (
            "decisionDeadlineNs",
            record.decision_deadline_ns.max(0).to_string(),
        ),
        ("stopRules", agent_json::strings(&record.stop_rules)),
        (
            "revisionDigest",
            agent_json::string(&revision.digest().to_text()),
        ),
        (
            "predecessorRevision",
            agent_json::optional_string(
                revision
                    .predecessor()
                    .map(|digest| digest.to_text())
                    .as_deref(),
            ),
        ),
    ])
}

/// Valid next transitions of a case revision, for the human-readable boundary.
fn next_transitions(revision: &InvestigationRevision, rebase_required: bool) -> String {
    use InvestigationLifecycle as L;
    let record = revision.record();
    if rebase_required {
        return "rebase (the case basis is not the session's anchor)".to_owned();
    }
    let live = revision
        .control()
        .hypotheses()
        .values()
        .filter(|disposition| **disposition == HypothesisDisposition::Live)
        .count();
    match record.state {
        L::Closed => "none (closed)".to_owned(),
        L::Resolved | L::Refuted | L::Cancelled => "set-state closed".to_owned(),
        L::Active => format!("cite, assess ({live} live), conclude, set-state, expand"),
        L::Draft | L::AwaitingEvidence | L::AwaitingApproval | L::Blocked | L::Indeterminate => {
            "activate, cite, set-state, expand".to_owned()
        }
    }
}

fn case_index(answer: &CaseAnswer) -> Vec<String> {
    answer
        .cases
        .iter()
        .map(|case| {
            format!(
                "Case {}: {}, revision {}, head {}.",
                case.record().investigation_id,
                case.record().state.as_str(),
                case.record().revision,
                case.digest()
            )
        })
        .collect()
}

fn case_response(
    args: &InvestigateArgs,
    answer: &CaseAnswer,
) -> Result<String, Box<dyn std::error::Error>> {
    let orientation = &answer.orientation;
    let capsule = orientation.capsule();
    let publication = &orientation.publication;
    let stale = stale_case_ids(&answer.cases, &answer.session);
    let mut degradation = orientation.degradation.clone();
    if answer.head_moved {
        degradation.push(
            "The deployment head has moved past this session's anchor: hand off and resume the \
             session to rebase it, then rebase each open case."
                .to_owned(),
        );
    }
    if !stale.is_empty() {
        degradation.push(format!(
            "Open cases opened at an earlier anchor must be rebased before any change: {}.",
            stale.join(", ")
        ));
    }
    degradation.push(
        "Case revisions are cognition: no probe was executed and no effect authority was granted."
            .to_owned(),
    );
    let (_, affordance_context) = contexts(orientation);
    let affordance_objects = agent_json::affordance_objects(
        &capsule.frame.next,
        &capsule.affordances,
        &affordance_context,
    )
    .ok_or(RenderError("next affordance objects"))?;
    let mut proof_pointers = vec![
        answer.journal_root.to_text(),
        orientation.anchor_token.clone(),
        publication.publication_digest.to_text(),
    ];
    let (payload_schema, payload_json, decision_fingerprint, mut completed) = match &answer.revision
    {
        Some(revision) => {
            proof_pointers.insert(0, revision.digest().to_text());
            if let Some(predecessor) = revision.predecessor() {
                proof_pointers.insert(1, predecessor.to_text());
            }
            let rebase_required = revision.record().basis_anchor != answer.session.current_anchor;
            let verb = if answer.committed {
                "Committed"
            } else {
                "Read"
            };
            (
                INVESTIGATION_PAYLOAD_SCHEMA,
                investigation_json(revision),
                revision.digest(),
                vec![
                    format!(
                        "{verb} case {} revision {} ({}) in session journal root {} at evidence \
                         time {} ns.",
                        revision.record().investigation_id,
                        revision.record().revision,
                        revision.digest(),
                        answer.journal_root,
                        answer.now.0
                    ),
                    format!(
                        "Valid next transitions: {}. Pass decisionFingerprint as --expected.",
                        next_transitions(revision, rebase_required)
                    ),
                ],
            )
        }
        None => {
            proof_pointers.extend(answer.cases.iter().map(|case| case.digest().to_text()));
            let mut completed = vec![format!(
                "Listed {} case(s) of mission {} visible to session {}.",
                answer.cases.len(),
                answer.session.mission_id.as_str(),
                answer.session.session_id.as_str()
            )];
            completed.extend(case_index(answer));
            (
                SITUATION_PAYLOAD_SCHEMA,
                situation_capsule_payload(
                    orientation,
                    &CapsuleOverrides {
                        symbol_table_generation: answer.session.symbol_table_generation,
                        ..CapsuleOverrides::default()
                    },
                )?,
                capsule.decision_fingerprint()?,
                completed,
            )
        }
    };
    let mut boundary = agent_plane_boundary(
        completed.remove(0),
        stale
            .iter()
            .map(|case| {
                format!(
                    "case {case}: basis anchor superseded by the session's anchor; rebase required"
                )
            })
            .collect(),
    );
    boundary.completed.extend(completed);
    build_response(ResponseParts {
        operation: COMMAND,
        request_digest: answer.request_digest,
        principal: answer.session.principal_id.clone(),
        session_id: Some(answer.session.session_id.as_str().to_owned()),
        mission_id: Some(answer.session.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: AgentView::Case,
        capability: CAPABILITY_CASE_WRITE,
        outcome: ResponseOutcome::Ok,
        error_id: None,
        payload_schema,
        payload_json,
        epistemic_state: orientation.epistemic_state,
        completeness: capsule.completeness,
        warnings: orientation.warnings.clone(),
        contradictions: orientation.contradictions.clone(),
        degradation,
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers,
        affordances: capsule.frame.next.clone(),
        affordance_objects,
        decision_fingerprint,
        compression_receipt_id: Some(publication.compression_receipt.receipt_id.clone()),
        continuation: publication.context_pack.continuation.clone(),
        recovery_class: "refresh_and_retry",
        safe_retry: if args.action.writes_case() && answer.committed {
            ResponseSafeRetry::YesAfterRefresh
        } else {
            ResponseSafeRetry::YesSameRequest
        },
        boundary,
        created_at_ns: capsule.created_at.0,
        workspace_revision: None,
        idempotency_key: args
            .action
            .writes_case()
            .then(|| idempotency_key(answer.request_digest)),
    })
}

/// Executes `fss investigate`, returning the rendered response and its exit identity.
#[must_use]
pub fn execute_investigate(args: &InvestigateArgs) -> (String, ExitIdentity) {
    let request = InvestigateRequest {
        session_id: args.session.clone(),
        principal: args.principal.clone(),
        action: args.action.clone(),
    };
    match investigate(&args.root, &request) {
        Ok(answer) => rendered(
            case_response(args, &answer),
            ExitIdentity::SUCCESS,
            COMMAND,
            &args.root,
        ),
        Err(error) => refuse(
            &Operation {
                command: COMMAND,
                name: COMMAND,
                capability: CAPABILITY_CASE_WRITE,
                payload_schema: INVESTIGATION_PAYLOAD_SCHEMA,
                view: AgentView::Case,
                root: args.root.clone(),
                principal: args.principal.clone(),
                request: [
                    args.session.as_str().as_bytes(),
                    b"\0",
                    args.action.name().as_bytes(),
                ]
                .concat(),
            },
            error,
        ),
    }
}
