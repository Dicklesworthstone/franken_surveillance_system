#![forbid(unsafe_code)]
//! CLI argument structs, option collectors, and parsers for `fss orient` and `fss explain`.

use std::path::PathBuf;

use fss_core::{AgentView, ContentDigest, EventId, PrincipalId, SessionId};
use fss_reference::agent_follow::AnchorToken;

use super::{custody, explain_options, fusion, history};
use crate::error::CliError;
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
    /// Optional existing durable session, admitted under the requesting principal.
    pub session: Option<SessionId>,
    /// Registered view (default `brief`).
    pub view: AgentView,
    /// Requesting principal label.
    pub principal: PrincipalId,
    /// Explicit context-token budget (1..=view maximum).
    pub budget_tokens: Option<u64>,
}

/// One exact target for the existing explanation operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExplainTarget {
    /// A committed event, optionally at an explicitly selected historical anchor (`why`).
    Event(EventId),
    /// A committed event explaining why corroboration, alert escalation, or absence certification
    /// did not occur (`why_not`).
    EventWhyNot(EventId),
    /// One exact current event revision and its immediately preceding committed revision.
    EventComparison {
        /// Event whose adjacent revision pair is selected.
        event_id: EventId,
        /// Exact digest of the immediately preceding committed revision.
        from_revision_digest: ContentDigest,
        /// Exact digest of the current committed revision.
        to_revision_digest: ContentDigest,
    },
    /// One exact current event under explicit numerical source-loss assumptions.
    EventCounterfactual {
        /// Selected retained event lineage.
        event_id: EventId,
        /// Complete canonical inline request, never a path or source-read grant.
        scenario: String,
    },
    /// One immutable captured-learning graph under current session authority.
    Learning {
        /// Session whose retained capture is being inspected.
        session: SessionId,
        /// Exact visible learning publication, never a replacement or latest alias.
        publication_root: ContentDigest,
    },
}

/// Options for the existing explanation operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplainArgs {
    /// Existing deployment root, read-only.
    pub root: PathBuf,
    /// Explicit historical metadata prefix; current deletion restrictions still apply.
    pub at: Option<AnchorToken>,
    /// Exact event or session-owned learning publication to explain.
    pub target: ExplainTarget,
    /// Requesting principal label.
    pub principal: PrincipalId,
    /// Registered explanation view: `decision_diff` by default, or explicit `forensic`.
    pub view: AgentView,
    /// Explicit combined context allowance, never above the selected view's maximum.
    pub budget_tokens: Option<u64>,
    /// Explicitly rehash the current publication closure and revalidate its authority.
    /// Defaults to false; this never grants source-media disclosure or effect authority.
    pub custody: bool,
    /// Optional `fss.score_calibration.v1` JSON artifact for calibrated posterior LLR and
    /// minimal-flip counterfactual projection.
    pub score_calibration: Option<PathBuf>,
    /// Optional fusion policy thresholds (`alert_mban,corroborate_mban,conflict_floor_mban`).
    pub fusion_policy: Option<String>,
}

/// Collects `--json` and `--name value` / `--name=value` options with exact exhaustion.
pub(crate) fn collect_options(
    command: &str,
    tokens: &[ArgToken],
    valued: &[&str],
) -> Result<Vec<(String, String, usize)>, CliError> {
    collect_options_with_repeatable(command, tokens, valued, &[])
}

/// Collect explicitly repeatable valued options while preserving ordinary duplicate refusal.
pub(crate) fn collect_options_with_repeatable(
    command: &str,
    tokens: &[ArgToken],
    valued: &[&str],
    repeatable: &[(&str, usize)],
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
        let count = values.iter().filter(|(seen, _, _)| seen == name).count();
        let repeat_limit = repeatable
            .iter()
            .find_map(|(option, maximum)| (*option == name).then_some(*maximum));
        if repeat_limit.is_some_and(|maximum| count >= maximum) {
            return Err(CliError::MalformedValue {
                option: name.to_owned(),
                value: "[too many selections]".to_owned(),
                reason: "repeated option exceeds its declared bound".to_owned(),
                command: Some(command.to_owned()),
                index: token.index,
            });
        }
        if repeat_limit.is_none() && count != 0 {
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

pub(crate) fn take<'a>(
    values: &'a [(String, String, usize)],
    name: &str,
) -> Option<&'a (String, String, usize)> {
    values.iter().find(|(seen, _, _)| seen == name)
}

pub(crate) fn required_root(
    command: &str,
    values: &[(String, String, usize)],
) -> Result<PathBuf, CliError> {
    take(values, "--root")
        .map(|(_, value, _)| PathBuf::from(value))
        .ok_or_else(|| CliError::MissingValue {
            option: "--root".to_owned(),
            command: Some(command.to_owned()),
            expected: "directory path for `--root`".to_owned(),
        })
}

pub(crate) fn principal(
    command: &str,
    values: &[(String, String, usize)],
) -> Result<PrincipalId, CliError> {
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

/// Parses a read-only deployment orientation, optionally bound to an existing `--session`.
pub fn parse_orient_args(tokens: &[ArgToken]) -> Result<OrientArgs, CliError> {
    let values = collect_options(
        "orient",
        tokens,
        &[
            "--root",
            "--session",
            "--view",
            "--principal",
            "--budget-tokens",
        ],
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
    let session = take(&values, "--session")
        .map(|(_, value, index)| {
            SessionId::parse(value.clone()).map_err(|_| CliError::MalformedValue {
                option: "--session".to_owned(),
                value: value.clone(),
                reason: "session must be a registered identifier of 1..128 characters".to_owned(),
                command: Some("orient".to_owned()),
                index: *index,
            })
        })
        .transpose()?;
    Ok(OrientArgs {
        root,
        session,
        view,
        principal: principal("orient", &values)?,
        budget_tokens,
    })
}

/// Parses an explanation with optional registered view, context budget and custody audit.
pub fn parse_explain_args(tokens: &[ArgToken]) -> Result<ExplainArgs, CliError> {
    let values = collect_options(
        "explain",
        tokens,
        &[
            "--root",
            "--event-id",
            "--session",
            "--learning-root",
            "--at",
            "--principal",
            "--custody",
            "--view",
            "--budget-tokens",
            "--score-calibration",
            "--fusion-policy",
            "--question",
            "--from-revision-digest",
            "--to-revision-digest",
            "--counterfactual",
        ],
    )?;
    let (view, budget_tokens) = explain_options::parse(&values)?;
    let root = required_root("explain", &values)?;
    let malformed =
        |option: &str, raw: &str, index: usize, reason: &str| CliError::MalformedValue {
            option: option.to_owned(),
            value: raw.to_owned(),
            reason: reason.to_owned(),
            command: Some("explain".to_owned()),
            index,
        };
    let question = match take(&values, "--question") {
        None => "why",
        Some((_, value, _))
            if matches!(
                value.as_str(),
                "why" | "why_not" | "what_changed" | "what_if"
            ) =>
        {
            value.as_str()
        }
        Some((_, value, index)) => {
            return Err(malformed(
                "--question",
                value,
                *index,
                "explain admits why, why_not, exact adjacent-revision what_changed, or explicit source-loss what_if",
            ));
        }
    };
    if question != "what_if" && take(&values, "--counterfactual").is_some() {
        return Err(malformed(
            "--counterfactual",
            "[redacted]",
            0,
            "counterfactual input requires --question what_if",
        ));
    }
    let target = if question == "what_if" {
        for option in [
            "--at",
            "--session",
            "--learning-root",
            "--custody",
            "--score-calibration",
            "--fusion-policy",
            "--from-revision-digest",
            "--to-revision-digest",
        ] {
            if let Some((_, _, index)) = take(&values, option) {
                return Err(malformed(
                    option,
                    "[redacted]",
                    *index,
                    "what_if requires current pinned metadata and one complete inline counterfactual request",
                ));
            }
        }
        let (_, raw, index) =
            take(&values, "--event-id").ok_or_else(|| CliError::MissingValue {
                option: "--event-id".to_owned(),
                command: Some("explain".to_owned()),
                expected: "the exact retained event for hypothetical source loss".to_owned(),
            })?;
        let event_id = EventId::parse(raw.clone()).map_err(|_| {
            malformed(
                "--event-id",
                "[redacted]",
                *index,
                "expected an exact event identity",
            )
        })?;
        let (_, raw, index) =
            take(&values, "--counterfactual").ok_or_else(|| CliError::MissingValue {
                option: "--counterfactual".to_owned(),
                command: Some("explain".to_owned()),
                expected: "a complete inline fss.event_counterfactual_request.v1 JSON object"
                    .to_owned(),
            })?;
        let scenario = crate::event_counterfactual::EventCounterfactualRequest::parse(raw)
            .map_err(|_| malformed(
                "--counterfactual",
                "[redacted]",
                *index,
                "counterfactual requires an exact revision, unique declared domains, explicit scores and a verified calibration",
            ))?
            .canonical_request_json();
        ExplainTarget::EventCounterfactual { event_id, scenario }
    } else if question == "what_changed" {
        for option in [
            "--at",
            "--session",
            "--learning-root",
            "--custody",
            "--score-calibration",
            "--fusion-policy",
        ] {
            if let Some((_, value, index)) = take(&values, option) {
                return Err(malformed(
                    option,
                    value,
                    *index,
                    "what_changed verifies exact current adjacent metadata and cannot combine with historical, learning, custody or fusion options",
                ));
            }
        }
        let (_, raw, index) =
            take(&values, "--event-id").ok_or_else(|| CliError::MissingValue {
                option: "--event-id".to_owned(),
                command: Some("explain".to_owned()),
                expected: "the event whose adjacent revisions are being compared".to_owned(),
            })?;
        let event_id = EventId::parse(raw.clone()).map_err(|_| {
            malformed(
                "--event-id",
                raw,
                *index,
                "expected an exact event identity",
            )
        })?;
        let exact_digest = |option: &str| -> Result<ContentDigest, CliError> {
            let (_, raw, index) = take(&values, option).ok_or_else(|| CliError::MissingValue {
                option: option.to_owned(),
                command: Some("explain".to_owned()),
                expected: "an exact nonzero canonical SHA-256 event revision digest".to_owned(),
            })?;
            ContentDigest::parse(raw).ok().filter(|digest| digest.algorithm() == fss_core::DigestAlgorithm::Sha256 && digest.to_text() == *raw && digest.bytes().iter().any(|byte| *byte != 0))
                .ok_or_else(|| malformed(option, "[redacted]", *index, "expected an exact nonzero canonical sha256:<64 lowercase hex> revision digest"))
        };
        ExplainTarget::EventComparison {
            event_id,
            from_revision_digest: exact_digest("--from-revision-digest")?,
            to_revision_digest: exact_digest("--to-revision-digest")?,
        }
    } else if let Some((_, raw, index)) = take(&values, "--learning-root") {
        if question == "why_not" {
            return Err(malformed(
                "--question",
                question,
                *index,
                "why_not applies to a committed event, not learning inspection",
            ));
        }
        for option in [
            "--event-id",
            "--at",
            "--custody",
            "--score-calibration",
            "--fusion-policy",
            "--from-revision-digest",
            "--to-revision-digest",
        ] {
            if let Some((_, value, at)) = take(&values, option) {
                return Err(malformed(
                    option,
                    value,
                    *at,
                    "learning inspection requires its complete retained custody and cannot use event-only options",
                ));
            }
        }
        let publication_root = ContentDigest::parse(raw).map_err(|_| {
            malformed(
                "--learning-root",
                raw,
                *index,
                "expected the exact sha256:<64 hex> learning publication root",
            )
        })?;
        let (_, raw, index) = take(&values, "--session").ok_or_else(|| CliError::MissingValue {
            option: "--session".to_owned(),
            command: Some("explain".to_owned()),
            expected: "the existing session that owns this learning publication".to_owned(),
        })?;
        let session = SessionId::parse(raw.clone()).map_err(|_| {
            malformed(
                "--session",
                raw,
                *index,
                "session identity must be 1..128 characters of [A-Za-z0-9._:-]",
            )
        })?;
        ExplainTarget::Learning {
            session,
            publication_root,
        }
    } else {
        for option in ["--from-revision-digest", "--to-revision-digest"] {
            if let Some((_, raw, index)) = take(&values, option) {
                return Err(malformed(
                    option,
                    raw,
                    *index,
                    "revision comparison pins require --question what_changed",
                ));
            }
        }
        if let Some((_, raw, index)) = take(&values, "--session") {
            return Err(malformed(
                "--session",
                raw,
                *index,
                "--session requires --learning-root",
            ));
        }
        let (_, raw, index) =
            take(&values, "--event-id").ok_or_else(|| CliError::MissingValue {
                option: "--event-id".to_owned(),
                command: Some("explain".to_owned()),
                expected: "a published event, or --learning-root with --session".to_owned(),
            })?;
        let event = EventId::parse(raw.clone()).map_err(|_| {
            malformed(
                "--event-id",
                raw,
                *index,
                "event identity must be 1..128 characters of [A-Za-z0-9._:-]",
            )
        })?;
        if question == "why_not" {
            ExplainTarget::EventWhyNot(event)
        } else {
            ExplainTarget::Event(event)
        }
    };
    let (score_calibration, fusion_policy) = fusion::parse(&values)?;
    Ok(ExplainArgs {
        root,
        at: history::parse("explain", &values)?,
        target,
        principal: principal("explain", &values)?,
        view,
        budget_tokens,
        custody: custody::parse(&values)?,
        score_calibration,
        fusion_policy,
    })
}
