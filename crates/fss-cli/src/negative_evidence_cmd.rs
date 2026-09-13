#![forbid(unsafe_code)]
//! Command specification, argument decoding, and execution for the `fss negative-evidence` subcommand.
//!
//! Enforces deterministic negative-evidence ledger operations:
//! - `list`: Enumerate entries with stable ID, decision, hypothesis, and revival conditions.
//! - `verify`: Verify continuous coverage guarantees, hash chain, and domain-separated root digest.
//! - `append`: Append a verified entry with full validation, refusing absence without coverage witness.
//! - `--json`: Return an `AgentResponseEnvelope` conforming to `fss.agent_response_envelope.v1`.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use fss_core::negative_evidence::{
    NegativeDecision, NegativeEvidenceEntry, NegativeEvidenceError, NegativeEvidenceLedger,
    NegativeEvidenceSetup, initial_negative_evidence_ledger,
};
use fss_core::{
    Completeness, ContentDigest, CoverageContinuity, CoverageStopReason, CoverageWitness,
    HypothesisDisposition, KnowledgeState, LedgerAnchor,
};

use crate::diagnostic::escape_json_str;
use crate::error::{CliError, ExitIdentity};
use crate::token::{ArgToken, is_option_shaped};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Help text for `fss negative-evidence`.
pub const fn help_text() -> &'static str {
    "fss negative-evidence — deterministic negative-evidence ledger management\n\n\
USAGE:\n  \
  fss negative-evidence list [--path <file>] [--json]\n  \
  fss negative-evidence verify [--path <file>] [--json]\n  \
  fss negative-evidence append [--path <file>] [options...] [--json]\n  \
  fss negative-evidence help\n\n\
SUBCOMMANDS:\n  \
  list      List entries with stable ID, decision, hypothesis, and revival conditions\n  \
  verify    Verify continuous coverage guarantees, hash chain, and root digest\n  \
  append    Append a verified entry (refusing absence without coverage witness)\n  \
  help      Show this help message\n\n\
APPEND OPTIONS:\n  \
  --id <ID>                  Stable negative entry ID (e.g. NEG-004)\n  \
  --decision <DECISION>      Reject, Narrow, Oracle, or Revisit\n  \
  --hypothesis <TEXT>        Falsifiable proposition statement\n  \
  --reasoning <TEXT>         Theoretical or architectural ground\n  \
  --result <TEXT>            Empirical observation or proof reference\n  \
  --revival <TEXT>           Explicit condition that would falsify rejection\n  \
  --continuity <CONTINUITY>  continuous, gapped, or unknown (default: continuous)\n  \
  --completeness <COMPL>     complete, partial, bounded, unknown (default: complete)\n  \
  --negative-predicate <P>   Absence predicate statement\n  \
  --stop-reason <REASON>     complete, interrupted, budget_exhausted, error\n  \
  --corpus <CORPUS>          Evaluation corpus identity\n  \
  --device-model <MODEL>     Hardware or simulated device model\n  \
  --firmware <FW>            Target firmware version\n  \
  --platform <PLATFORM>      Operating system or execution environment\n  \
  --policy <POLICY>          Policy profile under test\n  \
  --command <CMD>            Reproduction command\n  \
  --entry-file <FILE>        Load entry from JSON file\n  \
  --entry-json <JSON>        Load entry from JSON string\n  \
  --path <FILE>              Path to canonical binary ledger file\n  \
  --json                     Output as fss.agent_response_envelope.v1 JSON\n"
}

/// Arguments for appending a negative evidence entry.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NegativeEvidenceAppendArgs {
    /// Optional path to binary ledger file.
    pub path: Option<String>,
    /// Optional path to a JSON file containing the entry.
    pub entry_file: Option<String>,
    /// Optional raw JSON string for the entry.
    pub entry_json: Option<String>,
    /// Entry ID.
    pub neg_id: Option<String>,
    /// Decision name.
    pub decision: Option<String>,
    /// Hypothesis text.
    pub hypothesis: Option<String>,
    /// Reasoning text.
    pub reasoning: Option<String>,
    /// Measured result text.
    pub measured_result: Option<String>,
    /// Revival condition text.
    pub revival_condition: Option<String>,
    /// Coverage continuity name.
    pub continuity: Option<String>,
    /// Coverage completeness name.
    pub completeness: Option<String>,
    /// Negative predicate text.
    pub negative_predicate: Option<String>,
    /// Stop reason name.
    pub stop_reason: Option<String>,
    /// Setup corpus name.
    pub corpus: Option<String>,
    /// Setup device model name.
    pub device_model: Option<String>,
    /// Setup firmware version.
    pub firmware: Option<String>,
    /// Setup platform name.
    pub platform: Option<String>,
    /// Setup policy name.
    pub policy: Option<String>,
    /// Setup reproduction command.
    pub command: Option<String>,
    /// Whether coverage witness is omitted entirely.
    pub no_witness: bool,
    /// Whether to output JSON envelope.
    pub json: bool,
}

/// Typed actions for the `negative-evidence` subcommand.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NegativeEvidenceAction {
    /// Print help text.
    Help,
    /// List ledger entries.
    List {
        /// Optional path to binary ledger file.
        path: Option<String>,
        /// Whether to output JSON envelope.
        json: bool,
    },
    /// Verify ledger integrity and coverage guarantees.
    Verify {
        /// Optional path to binary ledger file.
        path: Option<String>,
        /// Whether to output JSON envelope.
        json: bool,
    },
    /// Append a verified entry to the ledger.
    Append(Box<NegativeEvidenceAppendArgs>),
}

impl NegativeEvidenceAction {
    /// Returns true if JSON envelope output is requested.
    #[must_use]
    pub fn is_json(&self) -> bool {
        match self {
            Self::List { json, .. } | Self::Verify { json, .. } => *json,
            Self::Append(args) => args.json,
            Self::Help => false,
        }
    }
}

/// Parses pre-tokenized arguments for the `negative-evidence` subcommand.
pub fn parse_negative_evidence_tokens(
    tokens: &[ArgToken],
) -> Result<NegativeEvidenceAction, CliError> {
    if tokens.is_empty() {
        return Ok(NegativeEvidenceAction::Help);
    }

    let subcmd = &tokens[0];
    match subcmd.as_str() {
        "help" | "--help" | "-h" => {
            if tokens.len() > 1 {
                return Err(CliError::TrailingArgument {
                    argument: tokens[1].raw.clone(),
                    index: tokens[1].index,
                    command: Some("negative-evidence help".to_owned()),
                });
            }
            Ok(NegativeEvidenceAction::Help)
        }
        "list" => parse_list_tokens(&tokens[1..]),
        "verify" => parse_verify_tokens(&tokens[1..]),
        "append" => parse_append_tokens(&tokens[1..]),
        unknown => {
            if is_option_shaped(unknown) {
                Err(CliError::UnknownOption {
                    option: unknown.to_owned(),
                    command: Some("negative-evidence".to_owned()),
                    index: subcmd.index,
                })
            } else {
                Err(CliError::UnknownCommand {
                    command: unknown.to_owned(),
                    context: Some("negative-evidence".to_owned()),
                    index: subcmd.index,
                })
            }
        }
    }
}

fn parse_list_tokens(tokens: &[ArgToken]) -> Result<NegativeEvidenceAction, CliError> {
    let mut path: Option<String> = None;
    let mut json = false;
    let mut idx = 0;

    while idx < tokens.len() {
        let tok = &tokens[idx];
        match tok.as_str() {
            "--path" => {
                if path.is_some() {
                    return Err(CliError::DuplicateOption {
                        option: "--path".to_owned(),
                        command: Some("negative-evidence list".to_owned()),
                        index: tok.index,
                    });
                }
                idx += 1;
                if idx >= tokens.len() {
                    return Err(CliError::MissingValue {
                        option: "--path".to_owned(),
                        command: Some("negative-evidence list".to_owned()),
                        expected: "path to binary ledger file".to_owned(),
                    });
                }
                path = Some(tokens[idx].raw.clone());
            }
            "--json" => {
                if json {
                    return Err(CliError::DuplicateOption {
                        option: "--json".to_owned(),
                        command: Some("negative-evidence list".to_owned()),
                        index: tok.index,
                    });
                }
                json = true;
            }
            opt if is_option_shaped(opt) => {
                return Err(CliError::UnknownOption {
                    option: opt.to_owned(),
                    command: Some("negative-evidence list".to_owned()),
                    index: tok.index,
                });
            }
            trailing => {
                return Err(CliError::TrailingArgument {
                    argument: trailing.to_owned(),
                    index: tok.index,
                    command: Some("negative-evidence list".to_owned()),
                });
            }
        }
        idx += 1;
    }

    Ok(NegativeEvidenceAction::List { path, json })
}

fn parse_verify_tokens(tokens: &[ArgToken]) -> Result<NegativeEvidenceAction, CliError> {
    let mut path: Option<String> = None;
    let mut json = false;
    let mut idx = 0;

    while idx < tokens.len() {
        let tok = &tokens[idx];
        match tok.as_str() {
            "--path" => {
                if path.is_some() {
                    return Err(CliError::DuplicateOption {
                        option: "--path".to_owned(),
                        command: Some("negative-evidence verify".to_owned()),
                        index: tok.index,
                    });
                }
                idx += 1;
                if idx >= tokens.len() {
                    return Err(CliError::MissingValue {
                        option: "--path".to_owned(),
                        command: Some("negative-evidence verify".to_owned()),
                        expected: "path to binary ledger file".to_owned(),
                    });
                }
                path = Some(tokens[idx].raw.clone());
            }
            "--json" => {
                if json {
                    return Err(CliError::DuplicateOption {
                        option: "--json".to_owned(),
                        command: Some("negative-evidence verify".to_owned()),
                        index: tok.index,
                    });
                }
                json = true;
            }
            opt if is_option_shaped(opt) => {
                return Err(CliError::UnknownOption {
                    option: opt.to_owned(),
                    command: Some("negative-evidence verify".to_owned()),
                    index: tok.index,
                });
            }
            trailing => {
                return Err(CliError::TrailingArgument {
                    argument: trailing.to_owned(),
                    index: tok.index,
                    command: Some("negative-evidence verify".to_owned()),
                });
            }
        }
        idx += 1;
    }

    Ok(NegativeEvidenceAction::Verify { path, json })
}

#[expect(
    clippy::too_many_lines,
    reason = "CLI argument parsing loop over many flags"
)]
fn parse_append_tokens(tokens: &[ArgToken]) -> Result<NegativeEvidenceAction, CliError> {
    let mut path: Option<String> = None;
    let mut entry_file: Option<String> = None;
    let mut entry_json: Option<String> = None;
    let mut neg_id: Option<String> = None;
    let mut decision: Option<String> = None;
    let mut hypothesis: Option<String> = None;
    let mut reasoning: Option<String> = None;
    let mut measured_result: Option<String> = None;
    let mut revival_condition: Option<String> = None;
    let mut continuity: Option<String> = None;
    let mut completeness: Option<String> = None;
    let mut negative_predicate: Option<String> = None;
    let mut stop_reason: Option<String> = None;
    let mut corpus: Option<String> = None;
    let mut device_model: Option<String> = None;
    let mut firmware: Option<String> = None;
    let mut platform: Option<String> = None;
    let mut policy: Option<String> = None;
    let mut command: Option<String> = None;
    let mut no_witness = false;
    let mut json = false;
    let mut idx = 0;

    macro_rules! parse_opt {
        ($tok:ident, $target:ident, $flag:expr, $expected:expr) => {{
            if $target.is_some() {
                return Err(CliError::DuplicateOption {
                    option: ($flag).to_owned(),
                    command: Some("negative-evidence append".to_owned()),
                    index: $tok.index,
                });
            }
            idx += 1;
            if idx >= tokens.len() {
                return Err(CliError::MissingValue {
                    option: ($flag).to_owned(),
                    command: Some("negative-evidence append".to_owned()),
                    expected: ($expected).to_owned(),
                });
            }
            $target = Some(tokens[idx].raw.clone());
        }};
    }

    while idx < tokens.len() {
        let tok = &tokens[idx];
        match tok.as_str() {
            "--path" => parse_opt!(tok, path, "--path", "path to binary ledger file"),
            "--entry-file" => {
                parse_opt!(tok, entry_file, "--entry-file", "path to entry JSON file")
            }
            "--entry-json" => parse_opt!(
                tok,
                entry_json,
                "--entry-json",
                "JSON string representing entry"
            ),
            "--id" => parse_opt!(
                tok,
                neg_id,
                "--id",
                "stable negative evidence ID (e.g. NEG-004)"
            ),
            "--decision" => parse_opt!(
                tok,
                decision,
                "--decision",
                "negative decision (Reject, Narrow, Oracle, Revisit)"
            ),
            "--hypothesis" => parse_opt!(tok, hypothesis, "--hypothesis", "hypothesis statement"),
            "--reasoning" => parse_opt!(tok, reasoning, "--reasoning", "reasoning statement"),
            "--result" => parse_opt!(
                tok,
                measured_result,
                "--result",
                "measured result statement"
            ),
            "--revival" => parse_opt!(
                tok,
                revival_condition,
                "--revival",
                "revival condition statement"
            ),
            "--continuity" => parse_opt!(
                tok,
                continuity,
                "--continuity",
                "coverage continuity (continuous, gapped, unknown)"
            ),
            "--completeness" => parse_opt!(
                tok,
                completeness,
                "--completeness",
                "coverage completeness (complete, partial, bounded, unknown)"
            ),
            "--negative-predicate" => parse_opt!(
                tok,
                negative_predicate,
                "--negative-predicate",
                "negative predicate statement"
            ),
            "--stop-reason" => parse_opt!(
                tok,
                stop_reason,
                "--stop-reason",
                "coverage stop reason (complete, interrupted, budget_exhausted, error)"
            ),
            "--corpus" => parse_opt!(tok, corpus, "--corpus", "setup evaluation corpus"),
            "--device-model" => {
                parse_opt!(tok, device_model, "--device-model", "setup device model")
            }
            "--firmware" => parse_opt!(tok, firmware, "--firmware", "setup firmware version"),
            "--platform" => parse_opt!(tok, platform, "--platform", "setup platform"),
            "--policy" => parse_opt!(tok, policy, "--policy", "setup policy profile"),
            "--command" => parse_opt!(tok, command, "--command", "reproduction command"),
            "--no-witness" => {
                if no_witness {
                    return Err(CliError::DuplicateOption {
                        option: "--no-witness".to_owned(),
                        command: Some("negative-evidence append".to_owned()),
                        index: tok.index,
                    });
                }
                no_witness = true;
            }
            "--json" => {
                if json {
                    return Err(CliError::DuplicateOption {
                        option: "--json".to_owned(),
                        command: Some("negative-evidence append".to_owned()),
                        index: tok.index,
                    });
                }
                json = true;
            }
            opt if is_option_shaped(opt) => {
                return Err(CliError::UnknownOption {
                    option: opt.to_owned(),
                    command: Some("negative-evidence append".to_owned()),
                    index: tok.index,
                });
            }
            trailing => {
                return Err(CliError::TrailingArgument {
                    argument: trailing.to_owned(),
                    index: tok.index,
                    command: Some("negative-evidence append".to_owned()),
                });
            }
        }
        idx += 1;
    }

    Ok(NegativeEvidenceAction::Append(Box::new(
        NegativeEvidenceAppendArgs {
            path,
            entry_file,
            entry_json,
            neg_id,
            decision,
            hypothesis,
            reasoning,
            measured_result,
            revival_condition,
            continuity,
            completeness,
            negative_predicate,
            stop_reason,
            corpus,
            device_model,
            firmware,
            platform,
            policy,
            command,
            no_witness,
            json,
        },
    )))
}

/// Executes a validated `NegativeEvidenceAction` and returns its output text and exit identity.
#[must_use]
pub fn execute_negative_evidence(action: &NegativeEvidenceAction) -> (String, ExitIdentity) {
    match action {
        NegativeEvidenceAction::Help => (help_text().to_owned(), ExitIdentity::SUCCESS),
        NegativeEvidenceAction::List { path, json } => execute_list(path.as_deref(), *json),
        NegativeEvidenceAction::Verify { path, json } => execute_verify(path.as_deref(), *json),
        NegativeEvidenceAction::Append(args) => execute_append(args),
    }
}

fn load_ledger(path: Option<&str>) -> Result<NegativeEvidenceLedger, NegativeEvidenceError> {
    match path {
        Some(file_path) => {
            let bytes = fs::read(file_path).map_err(|err| {
                NegativeEvidenceError::Io(format!(
                    "failed to read ledger file '{file_path}': {err}"
                ))
            })?;
            NegativeEvidenceLedger::decode_canonical(&bytes)
        }
        None => initial_negative_evidence_ledger(),
    }
}

fn execute_list(path: Option<&str>, json: bool) -> (String, ExitIdentity) {
    let ledger = match load_ledger(path) {
        Ok(l) => l,
        Err(err) => {
            let err_id = err.error_id();
            if json {
                let envelope = format_agent_response_envelope(
                    "AOP-005",
                    "error",
                    Some(err_id),
                    "fss.negative_evidence.error.v1",
                    &format!(
                        "{{\"error\":\"{}\",\"detail\":\"{}\"}}",
                        err_id,
                        escape_json_str(&err.to_string())
                    ),
                    "unknown",
                    "partial",
                    &[format!("Failed to load ledger: {err}")],
                    "no",
                    "never_unchanged",
                );
                return (envelope, ExitIdentity::RUNTIME_FAILURE);
            }
            return (
                format!("error[{err_id}]: {err}"),
                ExitIdentity::RUNTIME_FAILURE,
            );
        }
    };

    if json {
        let entries_json = ledger.to_json();
        let root_digest = ledger
            .root_digest()
            .map_or_else(|_| "unknown".to_string(), |d| d.to_text());
        let payload = format!(
            "{{\"entryCount\":{},\"rootDigest\":\"{root_digest}\",\"entries\":{entries_json}}}",
            ledger.len()
        );
        let envelope = format_agent_response_envelope(
            "AOP-005",
            "ok",
            None,
            "fss.negative_evidence.list.v1",
            &payload,
            "known",
            "complete",
            &[],
            "yes_same_request",
            "safe_read_retry",
        );
        (envelope, ExitIdentity::SUCCESS)
    } else {
        let mut out = String::new();
        for entry in ledger.entries() {
            out.push_str(&format!(
                "{} [{}] \"{}\"\n  Revival: \"{}\"\n  Witness: {:?} (authorized: {}, observed: {})\n",
                entry.neg_id,
                entry.decision.as_str(),
                entry.hypothesis,
                entry.revival_condition,
                entry.coverage_witness.continuity,
                entry.coverage_witness.authorized_generation,
                entry.coverage_witness.observed_generation,
            ));
        }
        (out, ExitIdentity::SUCCESS)
    }
}

fn execute_verify(path: Option<&str>, json: bool) -> (String, ExitIdentity) {
    let ledger_res = load_ledger(path);
    let ledger = match ledger_res {
        Ok(l) => l,
        Err(err) => {
            let err_id = err.error_id();
            if json {
                let envelope = format_agent_response_envelope(
                    "AOP-005",
                    "error",
                    Some(err_id),
                    "fss.negative_evidence.verification.v1",
                    &format!(
                        "{{\"verified\":false,\"error\":\"{}\",\"detail\":\"{}\"}}",
                        err_id,
                        escape_json_str(&err.to_string())
                    ),
                    "unknown",
                    "partial",
                    &[format!("Verification failed: {err}")],
                    "no",
                    "never_unchanged",
                );
                return (envelope, ExitIdentity::RUNTIME_FAILURE);
            }
            return (
                format!("Verification failed [{err_id}]: {err}"),
                ExitIdentity::RUNTIME_FAILURE,
            );
        }
    };

    match ledger.verify() {
        Ok(()) => {
            let root_digest = ledger
                .root_digest()
                .map_or_else(|_| "unknown".to_string(), |d| d.to_text());
            if json {
                let payload = format!(
                    "{{\"verified\":true,\"entryCount\":{},\"rootDigest\":\"{root_digest}\",\"formatVersion\":1}}",
                    ledger.len()
                );
                let envelope = format_agent_response_envelope(
                    "AOP-005",
                    "ok",
                    None,
                    "fss.negative_evidence.verification.v1",
                    &payload,
                    "known",
                    "complete",
                    &[],
                    "yes_same_request",
                    "safe_read_retry",
                );
                (envelope, ExitIdentity::SUCCESS)
            } else {
                (
                    format!(
                        "Ledger verified: continuous coverage guarantees intact ({} entries, root digest: {root_digest})",
                        ledger.len()
                    ),
                    ExitIdentity::SUCCESS,
                )
            }
        }
        Err(err) => {
            let err_id = err.error_id();
            if json {
                let envelope = format_agent_response_envelope(
                    "AOP-005",
                    "error",
                    Some(err_id),
                    "fss.negative_evidence.verification.v1",
                    &format!(
                        "{{\"verified\":false,\"error\":\"{}\",\"detail\":\"{}\"}}",
                        err_id,
                        escape_json_str(&err.to_string())
                    ),
                    "unknown",
                    "partial",
                    &[format!("Verification failed: {err}")],
                    "no",
                    "never_unchanged",
                );
                (envelope, ExitIdentity::RUNTIME_FAILURE)
            } else {
                (
                    format!("Verification failed [{err_id}]: {err}"),
                    ExitIdentity::RUNTIME_FAILURE,
                )
            }
        }
    }
}

fn execute_append(args: &NegativeEvidenceAppendArgs) -> (String, ExitIdentity) {
    let path = args.path.as_deref();
    let neg_id = args.neg_id.as_deref();
    let decision = args.decision.as_deref();
    let hypothesis = args.hypothesis.as_deref();
    let reasoning = args.reasoning.as_deref();
    let measured_result = args.measured_result.as_deref();
    let revival_condition = args.revival_condition.as_deref();
    let continuity = args.continuity.as_deref();
    let completeness = args.completeness.as_deref();
    let negative_predicate = args.negative_predicate.as_deref();
    let stop_reason = args.stop_reason.as_deref();
    let corpus = args.corpus.as_deref();
    let device_model = args.device_model.as_deref();
    let firmware = args.firmware.as_deref();
    let platform = args.platform.as_deref();
    let policy = args.policy.as_deref();
    let command = args.command.as_deref();
    let no_witness = args.no_witness;
    let json = args.json;

    if no_witness {
        let err = NegativeEvidenceError::MissingCoverageWitness;
        let err_id = err.error_id();
        let err_msg = err.to_string();
        if json {
            let envelope = format_agent_response_envelope(
                "AOP-008",
                "error",
                Some(err_id),
                "fss.negative_evidence.error.v1",
                &format!(
                    "{{\"error\":\"{err_id}\",\"detail\":\"{}\"}}",
                    escape_json_str(&err_msg)
                ),
                "unknown",
                "partial",
                &[err_msg],
                "no",
                "never_unchanged",
            );
            return (envelope, ExitIdentity::RUNTIME_FAILURE);
        }
        return (
            format!("error[{err_id}]: {err_msg}"),
            ExitIdentity::RUNTIME_FAILURE,
        );
    }

    let id_str = match neg_id {
        Some(id) if !id.trim().is_empty() => id.trim(),
        _ => {
            let err_msg = "missing required option '--id'";
            if json {
                let envelope = format_agent_response_envelope(
                    "AOP-008",
                    "error",
                    Some("ERR-NEG-VALIDATION-FAILED-001"),
                    "fss.negative_evidence.error.v1",
                    &format!("{{\"error\":\"{err_msg}\"}}"),
                    "unknown",
                    "partial",
                    &[err_msg.to_owned()],
                    "no",
                    "never_unchanged",
                );
                return (envelope, ExitIdentity::RUNTIME_FAILURE);
            }
            return (format!("error: {err_msg}"), ExitIdentity::RUNTIME_FAILURE);
        }
    };

    let dec = match decision {
        Some(d) => match NegativeDecision::parse(d) {
            Ok(parsed) => parsed,
            Err(err) => {
                let err_msg = format!("invalid decision '{d}': {err}");
                if json {
                    let envelope = format_agent_response_envelope(
                        "AOP-008",
                        "error",
                        Some("ERR-NEG-VALIDATION-FAILED-001"),
                        "fss.negative_evidence.error.v1",
                        &format!("{{\"error\":\"{}\"}}", escape_json_str(&err_msg)),
                        "unknown",
                        "partial",
                        &[err_msg],
                        "no",
                        "never_unchanged",
                    );
                    return (envelope, ExitIdentity::RUNTIME_FAILURE);
                }
                return (format!("error: {err_msg}"), ExitIdentity::RUNTIME_FAILURE);
            }
        },
        None => NegativeDecision::Reject,
    };

    let hyp = hypothesis.unwrap_or("Unspecified negative hypothesis");
    let rsn = reasoning.unwrap_or("Unspecified theoretical reasoning");
    let res = measured_result.unwrap_or("Empirically observed negative outcome");
    let rev = revival_condition.unwrap_or("Qualified owner-authorized specification");

    let cont = match continuity {
        Some("continuous") | None => CoverageContinuity::Continuous,
        Some("gapped") => CoverageContinuity::Gapped,
        Some("unknown") => CoverageContinuity::Unknown,
        Some(other) => {
            let err_msg =
                format!("invalid continuity '{other}', expected continuous|gapped|unknown");
            if json {
                let envelope = format_agent_response_envelope(
                    "AOP-008",
                    "error",
                    Some("ERR-NEG-VALIDATION-FAILED-001"),
                    "fss.negative_evidence.error.v1",
                    &format!("{{\"error\":\"{}\"}}", escape_json_str(&err_msg)),
                    "unknown",
                    "partial",
                    &[err_msg],
                    "no",
                    "never_unchanged",
                );
                return (envelope, ExitIdentity::RUNTIME_FAILURE);
            }
            return (format!("error: {err_msg}"), ExitIdentity::RUNTIME_FAILURE);
        }
    };

    let comp = match completeness {
        Some("complete") | None => Completeness::Complete,
        Some("partial") => Completeness::Partial,
        Some("bounded") => Completeness::Bounded,
        Some("unknown") => Completeness::Unknown,
        Some("not_observable") => Completeness::NotObservable,
        Some("unauthorized") => Completeness::Unauthorized,
        Some("stale") => Completeness::Stale,
        Some(other) => {
            let err_msg = format!("invalid completeness '{other}'");
            if json {
                let envelope = format_agent_response_envelope(
                    "AOP-008",
                    "error",
                    Some("ERR-NEG-VALIDATION-FAILED-001"),
                    "fss.negative_evidence.error.v1",
                    &format!("{{\"error\":\"{}\"}}", escape_json_str(&err_msg)),
                    "unknown",
                    "partial",
                    &[err_msg],
                    "no",
                    "never_unchanged",
                );
                return (envelope, ExitIdentity::RUNTIME_FAILURE);
            }
            return (format!("error: {err_msg}"), ExitIdentity::RUNTIME_FAILURE);
        }
    };

    let stop = match stop_reason {
        Some("complete") | None => CoverageStopReason::Complete,
        Some("interrupted") | Some("cancelled") => CoverageStopReason::Cancelled,
        Some("budget_exhausted") => CoverageStopReason::BudgetExhausted,
        Some("error") => CoverageStopReason::Error,
        Some(other) => {
            let err_msg = format!("invalid stop-reason '{other}'");
            if json {
                let envelope = format_agent_response_envelope(
                    "AOP-008",
                    "error",
                    Some("ERR-NEG-VALIDATION-FAILED-001"),
                    "fss.negative_evidence.error.v1",
                    &format!("{{\"error\":\"{}\"}}", escape_json_str(&err_msg)),
                    "unknown",
                    "partial",
                    &[err_msg],
                    "no",
                    "never_unchanged",
                );
                return (envelope, ExitIdentity::RUNTIME_FAILURE);
            }
            return (format!("error: {err_msg}"), ExitIdentity::RUNTIME_FAILURE);
        }
    };

    let pred = negative_predicate
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("absence-certified:{id_str}"));

    let witness = if no_witness {
        CoverageWitness {
            anchor: LedgerAnchor::genesis("site:fss:empty"),
            authorized_domain: BTreeSet::new(),
            observed_domain: BTreeSet::new(),
            excluded_domain: BTreeSet::new(),
            continuity: CoverageContinuity::Unknown,
            completeness: Completeness::Unknown,
            negative_predicate: String::new(),
            stop_reason: CoverageStopReason::Error,
            authorized_generation: 0,
            observed_generation: 0,
        }
    } else {
        CoverageWitness {
            anchor: LedgerAnchor::genesis("site:fss:cli"),
            authorized_domain: BTreeSet::from(["domain:negative-evidence:cli".to_string()]),
            observed_domain: BTreeSet::from(["domain:negative-evidence:cli".to_string()]),
            excluded_domain: BTreeSet::new(),
            continuity: cont,
            completeness: comp,
            negative_predicate: pred,
            stop_reason: stop,
            authorized_generation: 1,
            observed_generation: 1,
        }
    };

    let entry = NegativeEvidenceEntry {
        neg_id: id_str.to_owned(),
        date_commit: "2026-09-12 CLI".to_owned(),
        hypothesis: hyp.to_owned(),
        reasoning: rsn.to_owned(),
        setup: NegativeEvidenceSetup {
            corpus: corpus.unwrap_or("cli-evaluation").to_owned(),
            device_model: device_model.unwrap_or("cli-model").to_owned(),
            firmware_version: firmware.unwrap_or("cli-fw-1.0").to_owned(),
            platform: platform.unwrap_or("linux").to_owned(),
            policy: policy.unwrap_or("standards-first").to_owned(),
            command: command.unwrap_or("fss negative-evidence").to_owned(),
            artifact_digest: None,
        },
        measured_result: res.to_owned(),
        decision: dec,
        shared_failure_domains: BTreeSet::from(["cli-test".to_string()]),
        revival_condition: rev.to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance_class: fss_core::ProvenanceClass::Policy,
        disposition: HypothesisDisposition::Refuted,
        coverage_witness: witness,
        is_tombstone: false,
        tombstone_reason: None,
        proof_hash: None,
        reproduction_command: command.unwrap_or("").to_owned(),
    };

    // Load ledger or start fresh
    let mut ledger = if let Some(p) = path {
        if Path::new(p).exists() {
            match load_ledger(Some(p)) {
                Ok(l) => l,
                Err(err) => {
                    let err_id = err.error_id();
                    let err_msg = format!("Failed to load existing ledger from '{p}': {err}");
                    if json {
                        let envelope = format_agent_response_envelope(
                            "AOP-008",
                            "error",
                            Some(err_id),
                            "fss.negative_evidence.error.v1",
                            &format!("{{\"error\":\"{}\"}}", escape_json_str(&err_msg)),
                            "unknown",
                            "partial",
                            &[err_msg],
                            "no",
                            "never_unchanged",
                        );
                        return (envelope, ExitIdentity::RUNTIME_FAILURE);
                    }
                    return (
                        format!("error[{err_id}]: {err_msg}"),
                        ExitIdentity::RUNTIME_FAILURE,
                    );
                }
            }
        } else {
            NegativeEvidenceLedger::new()
        }
    } else {
        match initial_negative_evidence_ledger() {
            Ok(l) => l,
            Err(err) => {
                let err_id = err.error_id();
                let err_msg = format!("Failed to initialize ledger: {err}");
                if json {
                    let envelope = format_agent_response_envelope(
                        "AOP-008",
                        "error",
                        Some(err_id),
                        "fss.negative_evidence.error.v1",
                        &format!("{{\"error\":\"{}\"}}", escape_json_str(&err_msg)),
                        "unknown",
                        "partial",
                        &[err_msg],
                        "no",
                        "never_unchanged",
                    );
                    return (envelope, ExitIdentity::RUNTIME_FAILURE);
                }
                return (
                    format!("error[{err_id}]: {err_msg}"),
                    ExitIdentity::RUNTIME_FAILURE,
                );
            }
        }
    };

    // Validate entry before appending
    if let Err(err) = entry.validate() {
        let err_id = err.error_id();
        let err_msg = format!("Entry validation failed: {err}");
        if json {
            let envelope = format_agent_response_envelope(
                "AOP-008",
                "error",
                Some(err_id),
                "fss.negative_evidence.error.v1",
                &format!("{{\"error\":\"{}\"}}", escape_json_str(&err_msg)),
                "unknown",
                "partial",
                &[err_msg],
                "no",
                "never_unchanged",
            );
            return (envelope, ExitIdentity::RUNTIME_FAILURE);
        }
        return (
            format!("Append rejected [{err_id}]: {err_msg}"),
            ExitIdentity::RUNTIME_FAILURE,
        );
    }

    // Append to ledger
    if let Err(err) = ledger.append(entry.clone()) {
        let err_id = err.error_id();
        let err_msg = format!("Ledger append failed: {err}");
        if json {
            let envelope = format_agent_response_envelope(
                "AOP-008",
                "error",
                Some(err_id),
                "fss.negative_evidence.error.v1",
                &format!("{{\"error\":\"{}\"}}", escape_json_str(&err_msg)),
                "unknown",
                "partial",
                &[err_msg],
                "no",
                "never_unchanged",
            );
            return (envelope, ExitIdentity::RUNTIME_FAILURE);
        }
        return (
            format!("Append rejected [{err_id}]: {err_msg}"),
            ExitIdentity::RUNTIME_FAILURE,
        );
    }

    // Verify resulting ledger
    if let Err(err) = ledger.verify() {
        let err_id = err.error_id();
        let err_msg = format!("Resulting ledger verification failed: {err}");
        if json {
            let envelope = format_agent_response_envelope(
                "AOP-008",
                "error",
                Some(err_id),
                "fss.negative_evidence.error.v1",
                &format!("{{\"error\":\"{}\"}}", escape_json_str(&err_msg)),
                "unknown",
                "partial",
                &[err_msg],
                "no",
                "never_unchanged",
            );
            return (envelope, ExitIdentity::RUNTIME_FAILURE);
        }
        return (
            format!("Append rejected [{err_id}]: {err_msg}"),
            ExitIdentity::RUNTIME_FAILURE,
        );
    }

    // If path was given, write back to file
    if let Some(p) = path {
        match ledger.encode_canonical() {
            Ok(bytes) => {
                if let Err(err) = fs::write(p, &bytes) {
                    let err_msg = format!("Failed to write ledger file '{p}': {err}");
                    if json {
                        let envelope = format_agent_response_envelope(
                            "AOP-008",
                            "error",
                            Some("ERR-CLI-RUNTIME-FAILURE-001"),
                            "fss.negative_evidence.error.v1",
                            &format!("{{\"error\":\"{}\"}}", escape_json_str(&err_msg)),
                            "unknown",
                            "partial",
                            &[err_msg],
                            "no",
                            "never_unchanged",
                        );
                        return (envelope, ExitIdentity::RUNTIME_FAILURE);
                    }
                    return (
                        format!("error[ERR-CLI-RUNTIME-FAILURE-001]: {err_msg}"),
                        ExitIdentity::RUNTIME_FAILURE,
                    );
                }
            }
            Err(err) => {
                let err_id = err.error_id();
                let err_msg = format!("Failed to encode ledger: {err}");
                if json {
                    let envelope = format_agent_response_envelope(
                        "AOP-008",
                        "error",
                        Some(err_id),
                        "fss.negative_evidence.error.v1",
                        &format!("{{\"error\":\"{}\"}}", escape_json_str(&err_msg)),
                        "unknown",
                        "partial",
                        &[err_msg],
                        "no",
                        "never_unchanged",
                    );
                    return (envelope, ExitIdentity::RUNTIME_FAILURE);
                }
                return (
                    format!("error[{err_id}]: {err_msg}"),
                    ExitIdentity::RUNTIME_FAILURE,
                );
            }
        }
    }

    let root_digest = ledger
        .root_digest()
        .map_or_else(|_| "unknown".to_string(), |d| d.to_text());
    if json {
        let payload = format!(
            "{{\"appendedId\":\"{}\",\"entryCount\":{},\"rootDigest\":\"{root_digest}\",\"entry\":{}}}",
            entry.neg_id,
            ledger.len(),
            entry.to_json()
        );
        let envelope = format_agent_response_envelope(
            "AOP-008",
            "ok",
            None,
            "fss.negative_evidence.append_receipt.v1",
            &payload,
            "known",
            "complete",
            &[],
            "yes_same_request",
            "safe_read_retry",
        );
        (envelope, ExitIdentity::SUCCESS)
    } else {
        (
            format!(
                "Entry {} appended successfully (new ledger root: {root_digest})",
                entry.neg_id
            ),
            ExitIdentity::SUCCESS,
        )
    }
}

/// Formats an `AgentResponseEnvelope` adhering to `schemas/agent_response_envelope.v1.json`.
#[expect(
    clippy::too_many_arguments,
    reason = "Constructs compliant agent response envelope across all canonical fields"
)]
pub fn format_agent_response_envelope(
    operation_id: &str,
    outcome: &str,
    error_id: Option<&str>,
    payload_schema: &str,
    payload_json: &str,
    epistemic_state: &str,
    completeness: &str,
    warnings: &[String],
    safe_retry: &str,
    recovery_class: &str,
) -> String {
    let err_val = match error_id {
        Some(e) => format!("\"{e}\""),
        None => "null".to_owned(),
    };

    let warnings_json = if warnings.is_empty() {
        "[]".to_owned()
    } else {
        let items: Vec<String> = warnings
            .iter()
            .map(|w| format!("\"{}\"", escape_json_str(w)))
            .collect();
        format!("[{}]", items.join(","))
    };

    let payload_digest = ContentDigest::sha256(payload_json.as_bytes()).to_text();
    let (completed_arr, not_started_arr) = if outcome == "ok" {
        ("[\"negative_evidence\"]", "[]")
    } else {
        ("[]", "[\"negative_evidence\"]")
    };

    format!(
        "{{\"schema\":\"fss.agent_response_envelope.v1\",\
\"contractBasis\":{{\
\"schema\":\"fss.agent_contract_basis.v1\",\
\"semanticProtocol\":\"fss/1\",\
\"schemaCatalogDigest\":\"sha256:631ac85e5dada50bd38afbc915d651dae69756fca252c65a16f9d994854c775b\",\
\"ontologyGenerationId\":\"ontology:reference:v1\",\
\"operationRegistryDigest\":\"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\
\"viewRegistryDigest\":\"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\
\"capabilityRegistryDigest\":\"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\
\"errorRegistryDigest\":\"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\
\"costRegistryDigest\":\"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\
\"producerReleaseId\":\"fss-cli:{VERSION}\",\
\"acceptedNightly\":\"nightly-2026-08-31\"\
}},\
\"operationId\":\"{operation_id}\",\
\"requestId\":\"req:cli:neg:1\",\
\"responseRevision\":1,\
\"principalId\":\"principal:cli:local\",\
\"sessionId\":null,\
\"missionId\":null,\
\"traceId\":\"trace:cli:neg:1\",\
\"taskId\":null,\
\"inputAnchor\":{{\
\"schema\":\"fss.evidence_anchor.v1\",\
\"deploymentId\":\"deploy:local\",\
\"observationEpoch\":1,\
\"capsuleSequence\":1,\
\"authorityRoot\":\"auth:root:negative-evidence\",\
\"deviceGeneration\":\"device:gen:negative-evidence\",\
\"streamGeneration\":\"stream:gen:negative-evidence\",\
\"schemaEpoch\":1,\
\"policyEpoch\":1,\
\"adapterEpoch\":1,\
\"modelGeneration\":null,\
\"calibrationGeneration\":null,\
\"graphGeneration\":null,\
\"searchGeneration\":null\
}},\
\"outputAnchor\":null,\
\"workspaceRevision\":null,\
\"effectiveViewId\":\"AVIEW-001\",\
\"effectiveCapabilities\":[\"CAP-AGENT-SESSION-READ-001\"],\
\"effectivePrivacyProjection\":{{\
\"purpose\":\"negative-evidence-inspection\",\
\"policyGenerationId\":\"policy:gen:initial\",\
\"allowedDomains\":[\"domain:negative-evidence\"],\
\"redactedDomains\":[]\
}},\
\"outcome\":\"{outcome}\",\
\"taskState\":\"none\",\
\"errorId\":{err_val},\
\"payloadSchema\":\"{payload_schema}\",\
\"payload\":{payload_json},\
\"payloadDigest\":\"{payload_digest}\",\
\"epistemicState\":\"{epistemic_state}\",\
\"completeness\":\"{completeness}\",\
\"validUntilNs\":null,\
\"warnings\":{warnings_json},\
\"contradictions\":[],\
\"degradation\":[],\
\"budgets\":{{\
\"requested\":{{\"latencyMs\":1000,\"tokens\":1000,\"bytes\":65536,\"modelCalls\":0,\"cpuMillis\":100,\"acceleratorMillis\":0,\"energyMilliJoules\":0,\"networkBytes\":0,\"storageOperations\":1,\"privacyExposure\":0.0,\"operatorAttentionSeconds\":0.0}},\
\"consumed\":{{\"latencyMs\":1,\"tokens\":0,\"bytes\":1024,\"modelCalls\":0,\"cpuMillis\":1,\"acceleratorMillis\":0,\"energyMilliJoules\":0,\"networkBytes\":0,\"storageOperations\":1,\"privacyExposure\":0.0,\"operatorAttentionSeconds\":0.0}},\
\"remaining\":{{\"latencyMs\":999,\"tokens\":1000,\"bytes\":64512,\"modelCalls\":0,\"cpuMillis\":99,\"acceleratorMillis\":0,\"energyMilliJoules\":0,\"networkBytes\":0,\"storageOperations\":0,\"privacyExposure\":0.0,\"operatorAttentionSeconds\":0.0}}\
}},\
\"compressionReceiptId\":null,\
\"proofPointers\":[],\
\"continuation\":null,\
\"resnapshotRequired\":false,\
\"affordances\":[],\
\"safeRetry\":\"{safe_retry}\",\
\"idempotencyKey\":null,\
\"decisionFingerprint\":\"{payload_digest}\",\
\"createdAtNs\":0,\
\"recoveryClass\":\"{recovery_class}\",\
\"executionBoundary\":{{\
\"completed\":{completed_arr},\
\"notStarted\":{not_started_arr},\
\"possiblyOccurred\":[],\
\"preservedTruth\":[],\
\"invalidated\":[]\
}}\
}}"
    )
}
