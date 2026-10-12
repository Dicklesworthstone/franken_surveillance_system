#![forbid(unsafe_code)]
//! Typed AOP-006 input over the already bounded MCP JSON tree.
//!
//! Drafts and expansions are values, never host paths or stdin requests. Their native pure
//! decoders remain the owner of document grammar; the deployment investigation owner validates
//! authority, evidence, revision preconditions, deadlines and every state transition.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::PathBuf;

use fss_cli::FssCommand;
use fss_cli::investigate_cmd::{InvestigateArgs, decode_case_draft, decode_expansion};
use fss_cli::json_input::Value as NativeValue;
use fss_core::{
    ContentDigest, HypothesisDisposition, InvestigationLifecycle, PrincipalId, SessionId,
};
use fss_reference::agent_session::checkpoint::journal::coordination::investigations::InvestigationChange;
use fss_reference::agent_session::checkpoint::journal::coordination::investigations::evolution::InvestigationCitation;
use fss_reference::deployment_session::investigation::CaseAction;

use super::json::Value;

pub(super) type Refusal = (i32, &'static str);
const INVALID: Refusal = (-32602, "Invalid or unsupported investigation arguments");
const MAX_RESIDUALS: usize = 256;

/// Copies one already admitted, depth/node/byte-bounded wire tree into the native input type.
/// Number spelling and every array element are preserved; this function performs no I/O.
pub(super) fn document(value: &Value) -> NativeValue {
    match value {
        Value::Null => NativeValue::Null,
        Value::Boolean(value) => NativeValue::Bool(*value),
        Value::Number(value) => NativeValue::Number(value.clone()),
        Value::Text(value) => NativeValue::Text(value.clone()),
        Value::Array(values) => NativeValue::Array(values.iter().map(document).collect()),
        Value::Object(values) => NativeValue::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), document(value)))
                .collect(),
        ),
    }
}

pub(super) fn text<'a>(
    args: &'a BTreeMap<String, Value>,
    key: &str,
    maximum: usize,
) -> Result<&'a str, Refusal> {
    args.get(key)
        .and_then(Value::text)
        .filter(|value| !value.is_empty() && value.len() <= maximum)
        .ok_or(INVALID)
}

pub(super) fn identity(args: &BTreeMap<String, Value>, key: &str) -> Result<String, Refusal> {
    let value = text(args, key, 128)?;
    fss_core::validate_id(value).map_err(|_| INVALID)?;
    Ok(value.to_owned())
}

pub(super) fn digest(args: &BTreeMap<String, Value>, key: &str) -> Result<ContentDigest, Refusal> {
    ContentDigest::parse(text(args, key, 71)?).map_err(|_| INVALID)
}

pub(super) fn only(args: &BTreeMap<String, Value>, fields: &[&str]) -> Result<(), Refusal> {
    if args.keys().all(|key| {
        matches!(key.as_str(), "session" | "transition") || fields.contains(&key.as_str())
    }) {
        Ok(())
    } else {
        Err(INVALID)
    }
}

fn contradicts(args: &BTreeMap<String, Value>) -> Result<bool, Refusal> {
    match text(args, "side", 32)? {
        "support" => Ok(false),
        "contradiction" => Ok(true),
        _ => Err(INVALID),
    }
}

fn residuals(args: &BTreeMap<String, Value>) -> Result<BTreeSet<String>, Refusal> {
    let Some(Value::Array(values)) = args.get("residual_unknowns") else {
        return Err(INVALID);
    };
    if values.len() > MAX_RESIDUALS {
        return Err(INVALID);
    }
    let mut result = BTreeSet::new();
    for value in values {
        let value = value.text().ok_or(INVALID)?;
        fss_core::validate_id(value).map_err(|_| INVALID)?;
        if !result.insert(value.to_owned()) {
            return Err(INVALID);
        }
    }
    Ok(result)
}

/// Constructs exactly one native command; root and principal are supplied only by the launcher.
pub(super) fn command(
    root: &OsStr,
    principal: &str,
    args: &BTreeMap<String, Value>,
) -> Result<FssCommand, Refusal> {
    let session = SessionId::parse(text(args, "session", 128)?).map_err(|_| INVALID)?;
    let principal = PrincipalId::parse(principal).map_err(|_| INVALID)?;
    let action = match text(args, "transition", 32)? {
        "open" => {
            only(args, &["draft"])?;
            let draft = decode_case_draft(&document(args.get("draft").ok_or(INVALID)?))
                .map_err(|_| INVALID)?;
            CaseAction::Open(Box::new(draft))
        }
        "expand" => {
            only(args, &["case", "expected", "expansion"])?;
            let (hypothesis, discriminator, probe) =
                decode_expansion(&document(args.get("expansion").ok_or(INVALID)?))
                    .map_err(|_| INVALID)?;
            CaseAction::Expand {
                case_id: identity(args, "case")?,
                expected: digest(args, "expected")?,
                hypothesis: Box::new(hypothesis),
                discriminator: Box::new(discriminator),
                probe,
            }
        }
        "inspect" => {
            only(args, &["case", "revision"])?;
            CaseAction::Inspect {
                case_id: identity(args, "case")?,
                revision: args
                    .contains_key("revision")
                    .then(|| digest(args, "revision"))
                    .transpose()?,
            }
        }
        "list" => {
            only(args, &[])?;
            CaseAction::List
        }
        "rebase" => {
            only(args, &["case", "expected"])?;
            CaseAction::Rebase {
                case_id: identity(args, "case")?,
                expected: digest(args, "expected")?,
            }
        }
        "readmit" => {
            only(
                args,
                &[
                    "case",
                    "expected",
                    "hypothesis",
                    "evidence",
                    "side",
                    "witness",
                ],
            )?;
            CaseAction::Readmit {
                case_id: identity(args, "case")?,
                expected: digest(args, "expected")?,
                citation: InvestigationCitation {
                    hypothesis: identity(args, "hypothesis")?,
                    evidence: digest(args, "evidence")?,
                    contradicts: contradicts(args)?,
                },
                witness: digest(args, "witness")?,
            }
        }
        transition @ ("activate" | "cite" | "assess" | "set-state" | "conclude") => {
            let change = match transition {
                "activate" => {
                    only(args, &["case", "expected"])?;
                    InvestigationChange::Activate
                }
                "cite" => {
                    only(
                        args,
                        &["case", "expected", "hypothesis", "evidence", "side"],
                    )?;
                    InvestigationChange::Cite {
                        hypothesis: identity(args, "hypothesis")?,
                        evidence: digest(args, "evidence")?,
                        contradicts: contradicts(args)?,
                    }
                }
                "assess" => {
                    only(
                        args,
                        &["case", "expected", "hypothesis", "disposition", "evidence"],
                    )?;
                    let disposition = match text(args, "disposition", 32)? {
                        "supported" => HypothesisDisposition::Supported,
                        "disfavored" => HypothesisDisposition::Disfavored,
                        "refuted" => HypothesisDisposition::Refuted,
                        _ => return Err(INVALID),
                    };
                    InvestigationChange::Assess {
                        hypothesis: identity(args, "hypothesis")?,
                        disposition,
                        evidence: digest(args, "evidence")?,
                    }
                }
                "set-state" => {
                    only(args, &["case", "expected", "state", "reason"])?;
                    let state = match text(args, "state", 32)? {
                        "awaiting_evidence" => InvestigationLifecycle::AwaitingEvidence,
                        "awaiting_approval" => InvestigationLifecycle::AwaitingApproval,
                        "blocked" => InvestigationLifecycle::Blocked,
                        "indeterminate" => InvestigationLifecycle::Indeterminate,
                        "cancelled" => InvestigationLifecycle::Cancelled,
                        "closed" => InvestigationLifecycle::Closed,
                        _ => return Err(INVALID),
                    };
                    InvestigationChange::SetState {
                        state,
                        reason: digest(args, "reason")?,
                    }
                }
                _ => {
                    only(
                        args,
                        &[
                            "case",
                            "expected",
                            "conclusion",
                            "stop_rule",
                            "assessment",
                            "residual_unknowns",
                        ],
                    )?;
                    let refuted = match text(args, "conclusion", 32)? {
                        "resolved" => false,
                        "refuted" => true,
                        _ => return Err(INVALID),
                    };
                    InvestigationChange::Conclude {
                        refuted,
                        stop_rule: text(args, "stop_rule", 1024)?.to_owned(),
                        assessment: digest(args, "assessment")?,
                        residual_unknowns: residuals(args)?,
                    }
                }
            };
            CaseAction::Change {
                case_id: identity(args, "case")?,
                expected: digest(args, "expected")?,
                change,
            }
        }
        _ => return Err(INVALID),
    };
    Ok(FssCommand::Investigate(Box::new(InvestigateArgs {
        root: PathBuf::from(root),
        session,
        principal,
        action,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_reference::deployment_session::investigation::CaseDeadline;

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const DRAFT: &str = r#"{
        "caseId":"case:front-door",
        "question":"/private/operator-note\n--root=/other",
        "decisionInformed":"Retain competing explanations",
        "hypotheses":[
            {"hypothesisId":"h:person","description":"Person","predictions":["Door opens"]},
            {"hypothesisId":"h:animal","description":"Animal","epistemicState":"unknown"}
        ],
        "knowns":[{"statementId":"k:retained","text":"Source retained","basis":["source:one"]}],
        "unknowns":[{"statementId":"u:identity","text":"Identity unresolved"}],
        "discriminators":[{"discriminatorId":"d:door","description":"Door state",
            "separates":["h:person","h:animal"],"expectedOutcomes":["Open","Closed"]}],
        "probes":["probe:door"],
        "stopRules":["Evidence distinguishes the explanations"],
        "decisionWindowNs":"170141183460469231731687303715884105727"
    }"#;
    const EXPANSION: &str = r#"{
        "hypothesis":{"hypothesisId":"h:reflection","description":"Reflection",
            "predictions":["No independent motion"]},
        "discriminator":{"discriminatorId":"d:side","description":"Side view",
            "separates":["h:reflection","h:person"],"expectedOutcomes":["Present","Absent"]},
        "probe":"probe:side"
    }"#;

    fn decode(args: &str) -> Result<InvestigateArgs, Box<dyn std::error::Error>> {
        let value = super::super::json::parse(args).map_err(|_| "invalid fixture JSON")?;
        let fields = value.object().ok_or("fixture is not an object")?;
        let parsed = command(OsStr::new("/owner/deployment"), "principal:owner", fields)
            .map_err(|_| "investigation arguments refused")?;
        let FssCommand::Investigate(args) = parsed else {
            return Err("non-investigation command".into());
        };
        assert_eq!(args.root, PathBuf::from("/owner/deployment"));
        assert_eq!(args.principal.as_str(), "principal:owner");
        assert_eq!(args.session.as_str(), "session:owner");
        Ok(*args)
    }

    #[test]
    fn investigation_documents_preserve_literals_arrays_and_i128_deadlines()
    -> Result<(), Box<dyn std::error::Error>> {
        let open = decode(&format!(
            r#"{{"session":"session:owner","transition":"open","draft":{DRAFT}}}"#
        ))?;
        let CaseAction::Open(draft) = open.action else {
            return Err("expected open".into());
        };
        assert_eq!(draft.case_id, "case:front-door");
        assert_eq!(draft.question, "/private/operator-note\n--root=/other");
        assert_eq!(draft.hypotheses.len(), 2);
        assert_eq!(draft.hypotheses[0].predictions, ["Door opens"]);
        assert_eq!(draft.knowns[0].basis, ["source:one"]);
        assert_eq!(draft.unknowns[0].statement_id, "u:identity");
        assert_eq!(draft.discriminators[0].separates, ["h:person", "h:animal"]);
        assert_eq!(draft.deadline, CaseDeadline::After(i128::MAX));
        let expand = decode(&format!(
            r#"{{"session":"session:owner","transition":"expand","case":"case:front-door","expected":"{DIGEST}","expansion":{EXPANSION}}}"#
        ))?;
        let CaseAction::Expand {
            expected,
            hypothesis,
            discriminator,
            probe,
            ..
        } = expand.action
        else {
            return Err("expected expand".into());
        };
        assert_eq!(expected.to_text(), DIGEST);
        assert_eq!(hypothesis.predictions, ["No independent motion"]);
        assert_eq!(discriminator.separates, ["h:reflection", "h:person"]);
        assert_eq!(probe, "probe:side");
        Ok(())
    }

    #[test]
    fn investigation_maps_every_non_document_transition_exactly()
    -> Result<(), Box<dyn std::error::Error>> {
        let expected = ContentDigest::parse(DIGEST)?;
        let case = "case:front-door".to_owned();
        let scoped = format!(r#""case":"{case}","expected":"{DIGEST}""#);
        for (transition, fields, action) in [
            (
                "inspect",
                format!(r#""case":"{case}","revision":"{DIGEST}""#),
                CaseAction::Inspect {
                    case_id: case.clone(),
                    revision: Some(expected),
                },
            ),
            ("list", String::new(), CaseAction::List),
            (
                "rebase",
                scoped.clone(),
                CaseAction::Rebase {
                    case_id: case.clone(),
                    expected,
                },
            ),
            (
                "readmit",
                format!(
                    r#"{scoped},"hypothesis":"h:person","evidence":"{DIGEST}","side":"contradiction","witness":"{DIGEST}""#
                ),
                CaseAction::Readmit {
                    case_id: case.clone(),
                    expected,
                    citation: InvestigationCitation {
                        hypothesis: "h:person".to_owned(),
                        evidence: expected,
                        contradicts: true,
                    },
                    witness: expected,
                },
            ),
            (
                "activate",
                scoped.clone(),
                CaseAction::Change {
                    case_id: case.clone(),
                    expected,
                    change: InvestigationChange::Activate,
                },
            ),
            (
                "cite",
                format!(
                    r#"{scoped},"hypothesis":"h:person","evidence":"{DIGEST}","side":"support""#
                ),
                CaseAction::Change {
                    case_id: case.clone(),
                    expected,
                    change: InvestigationChange::Cite {
                        hypothesis: "h:person".to_owned(),
                        evidence: expected,
                        contradicts: false,
                    },
                },
            ),
            (
                "assess",
                format!(
                    r#"{scoped},"hypothesis":"h:person","evidence":"{DIGEST}","disposition":"supported""#
                ),
                CaseAction::Change {
                    case_id: case.clone(),
                    expected,
                    change: InvestigationChange::Assess {
                        hypothesis: "h:person".to_owned(),
                        disposition: HypothesisDisposition::Supported,
                        evidence: expected,
                    },
                },
            ),
            (
                "set-state",
                format!(r#"{scoped},"state":"indeterminate","reason":"{DIGEST}""#),
                CaseAction::Change {
                    case_id: case.clone(),
                    expected,
                    change: InvestigationChange::SetState {
                        state: InvestigationLifecycle::Indeterminate,
                        reason: expected,
                    },
                },
            ),
            (
                "conclude",
                format!(
                    r#"{scoped},"conclusion":"resolved","stop_rule":"Stop","assessment":"{DIGEST}","residual_unknowns":["u:identity","none"]"#
                ),
                CaseAction::Change {
                    case_id: case.clone(),
                    expected,
                    change: InvestigationChange::Conclude {
                        refuted: false,
                        stop_rule: "Stop".to_owned(),
                        assessment: expected,
                        residual_unknowns: ["none".to_owned(), "u:identity".to_owned()]
                            .into_iter()
                            .collect(),
                    },
                },
            ),
        ] {
            let suffix = if fields.is_empty() {
                String::new()
            } else {
                format!(",{fields}")
            };
            let parsed = decode(&format!(
                r#"{{"session":"session:owner","transition":"{transition}"{suffix}}}"#
            ))?;
            assert_eq!(parsed.action, action, "{transition}");
        }
        assert!(matches!(
            decode(
                r#"{"session":"session:owner","transition":"inspect","case":"case:front-door"}"#
            )?
            .action,
            CaseAction::Inspect { revision: None, .. }
        ));
        Ok(())
    }

    #[test]
    fn investigation_refuses_scope_overrides_files_and_cross_transition_fields() {
        for arguments in [
            r#"{"session":"session:owner","transition":"list","root":"/other"}"#.to_owned(),
            r#"{"session":"session:owner","transition":"list","principal":"principal:other"}"#.to_owned(),
            r#"{"session":"session:owner","transition":"list","case":"case:one"}"#.to_owned(),
            r#"{"session":"session:owner","transition":"open","case_file":"/private/case"}"#.to_owned(),
            r#"{"session":"session:owner","transition":"open","draft":"/private/case"}"#.to_owned(),
            r#"{"session":"session:owner","transition":"open","draft":{"caseId":"case:one","decisionWindowNs":1,"authority":"grant"}}"#.to_owned(),
            r#"{"session":"session:owner","transition":"expand","expansion_file":"-"}"#.to_owned(),
            r#"{"session":"session:owner","transition":"activate","case":"case:one","expected":"wrong"}"#.to_owned(),
            r#"{"session":"session:owner","transition":"inspect","case":"../private"}"#.to_owned(),
            r#"{"session":"session:owner","transition":"list","draft":{}}"#.to_owned(),
            r#"{"session":"session:owner","transition":"commit"}"#.to_owned(),
            format!(r#"{{"session":"session:owner","transition":"set-state","case":"case:one","expected":"{DIGEST}","state":"resolved","reason":"{DIGEST}"}}"#),
            format!(r#"{{"session":"session:owner","transition":"assess","case":"case:one","expected":"{DIGEST}","hypothesis":"h:one","disposition":"certain","evidence":"{DIGEST}"}}"#),
            format!(r#"{{"session":"session:owner","transition":"conclude","case":"case:one","expected":"{DIGEST}","conclusion":"refuted","stop_rule":"Stop","assessment":"{DIGEST}","residual_unknowns":"none"}}"#),
            format!(r#"{{"session":"session:owner","transition":"conclude","case":"case:one","expected":"{DIGEST}","conclusion":"refuted","stop_rule":"Stop","assessment":"{DIGEST}","residual_unknowns":["u:one","u:one"]}}"#),
            format!(r#"{{"session":"session:owner","transition":"open","draft":{}}}"#, DRAFT.replace(r#""basis":["source:one"]"#, r#""basis":true"#)),
        ] {
            assert!(decode(&arguments).is_err(), "accepted {arguments}");
        }
    }
}
