#![forbid(unsafe_code)]
//! Command specification, argument decoding, and execution for the `fss negative-evidence` subcommand.
//!
//! Enforces deterministic negative-evidence ledger operations:
//! - `init`: Create a ledger file holding the NEG-001..NEG-003 seeds; never overwrites.
//! - `list`: Enumerate entries with stable ID, decision, hypothesis, certification, and revival.
//! - `verify`: Verify integrity, canonical order, coverage certification, and root digest.
//! - `append`: Append a locally certified entry to an existing ledger file. Absence without a
//!   complete coverage witness is refused (`ERR-NEG-MISSING-COVERAGE-001`); the file is replaced
//!   atomically (temp file in the same directory, then rename).
//! - `--json`: Emit output shaped as `fss.agent_response_envelope.v1`. `fss negative-evidence` is
//!   not a registered operation (no AOP row in `registries/OPERATION_CROSSWALK.md`) and fss-cli
//!   derives no registry digests, anchors, or budget meters, so `operationId`, the contract-basis
//!   digests, `inputAnchor`, and the budget figures are `null` and named in `degradation`; they
//!   are never invented.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use fss_core::negative_evidence::{
    EvidenceCertification, NOT_EVALUATED, NOT_LOCALLY_REPRODUCIBLE, NegativeDecision,
    NegativeEvidenceEntry, NegativeEvidenceError, NegativeEvidenceLedger, NegativeEvidenceSetup,
    initial_negative_evidence_ledger,
};
use fss_core::{
    Completeness, ContentDigest, CoverageContinuity, CoverageStopReason, CoverageWitness,
    HypothesisDisposition, KnowledgeState, LedgerAnchor, ProvenanceClass,
};

use crate::diagnostic::escape_json_str;
use crate::error::{CliError, ExitIdentity};
use crate::token::{ArgToken, is_option_shaped};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const APPEND_COMMAND: &str = "negative-evidence append";

const ERROR_PAYLOAD_SCHEMA: &str = "fss.negative_evidence.error.v1";

/// Degradations every negative-evidence envelope reports instead of inventing values.
const ENVELOPE_DEGRADATION: [&str; 4] = [
    "operation_unregistered: `fss negative-evidence` has no AOP row in registries/OPERATION_CROSSWALK.md; operationId is null",
    "contract_basis_unavailable: fss-cli derives no schema-catalog, ontology, or registry digests; those contractBasis fields are null",
    "input_anchor_unavailable: no EvidenceAnchor is bound to this local ledger file; inputAnchor is null",
    "budget_unmetered: fss-cli does not meter this command; requested, consumed, and remaining budgets are null",
];

/// Help text for `fss negative-evidence`.
pub const fn help_text() -> &'static str {
    "fss negative-evidence — deterministic negative-evidence ledger management\n\n\
USAGE:\n  \
  fss negative-evidence init --path <file> [--json]\n  \
  fss negative-evidence list [--path <file>] [--json]\n  \
  fss negative-evidence verify [--path <file>] [--json]\n  \
  fss negative-evidence append --path <file> <required options> <coverage witness> [options...] [--json]\n  \
  fss negative-evidence help\n\n\
SUBCOMMANDS:\n  \
  init      Create a ledger file holding the NEG-001..NEG-003 seeds (never overwrites)\n  \
  list      List entries with stable ID, decision, hypothesis, certification, and revival conditions\n  \
  verify    Verify integrity, canonical order, coverage certification, and root digest\n  \
  append    Append a locally certified entry (refusing absence without a coverage witness)\n  \
  help      Show this help message\n\n\
Without --path, list and verify read the built-in seed ledger.\n\n\
APPEND REQUIRED OPTIONS:\n  \
  --path <FILE>              Existing canonical binary ledger file (create one with `init`)\n  \
  --id <ID>                  Stable negative entry ID (e.g. NEG-004)\n  \
  --date-commit <TEXT>       Exact date and commit of the experiment\n  \
  --decision <DECISION>      reject, oracle, narrow, or revisit\n  \
  --disposition <DISP>       live, supported, disfavored, refuted, resolved, or superseded\n  \
  --hypothesis <TEXT>        What was expected and why\n  \
  --reasoning <TEXT>         Architectural or theoretical reasoning\n  \
  --result <TEXT>            Measured result, divergences, and failures\n  \
  --revival <TEXT>           Explicit condition that would justify repeating the work\n  \
  --failure-domain <LABEL>   Shared failure domain (repeatable; at least one)\n\n\
COVERAGE WITNESS (all required; absence without a coverage witness is never evidence):\n  \
  --coverage-domain <LABEL>  Domain the entry claims and the witness observed\n  \
  --coverage-generation <N>  Authorized and observed generation (N >= 1)\n  \
  --negative-predicate <P>   Absence predicate; its last ':' segment must be the entry ID\n  \
  --continuity <C>           continuous, gapped, or unknown\n  \
  --completeness <C>         complete, bounded, partial, unknown, not_observable, unauthorized, or stale\n  \
  --stop-reason <R>          complete, budget_exhausted, cancelled, source_gap, authorization_filtered, unsupported, or error\n\n\
APPEND OPTIONAL:\n  \
  --decision-text <TEXT>     Verbatim decision text\n  \
  --supersedes <ID>          Earlier entry this entry supersedes (append-only link)\n  \
  --corpus <CORPUS>          Evaluation corpus identity (default: not-evaluated)\n  \
  --device-model <MODEL>     Hardware or simulated device model (default: not-evaluated)\n  \
  --firmware <FW>            Target firmware version (default: not-evaluated)\n  \
  --platform <PLATFORM>      Operating system or execution environment (default: not-evaluated)\n  \
  --policy <POLICY>          Policy profile under test (default: not-evaluated)\n  \
  --command <CMD>            Reproduction command (default: not-locally-reproducible)\n  \
  --json                     Output as fss.agent_response_envelope.v1-shaped JSON\n"
}

/// Coverage witness options for `append`; all six are required to certify absence.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoverageWitnessArgs {
    /// Domain claimed by the entry and observed by the witness.
    pub domain: Option<String>,
    /// Authorized and observed generation.
    pub generation: Option<u64>,
    /// Absence predicate naming the entry.
    pub negative_predicate: Option<String>,
    /// Coverage continuity.
    pub continuity: Option<CoverageContinuity>,
    /// Coverage completeness.
    pub completeness: Option<Completeness>,
    /// Coverage stop reason.
    pub stop_reason: Option<CoverageStopReason>,
}

impl CoverageWitnessArgs {
    fn missing_options(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.domain.is_none() {
            missing.push("--coverage-domain");
        }
        if self.generation.is_none() {
            missing.push("--coverage-generation");
        }
        if self.negative_predicate.is_none() {
            missing.push("--negative-predicate");
        }
        if self.continuity.is_none() {
            missing.push("--continuity");
        }
        if self.completeness.is_none() {
            missing.push("--completeness");
        }
        if self.stop_reason.is_none() {
            missing.push("--stop-reason");
        }
        missing
    }
}

/// Validated arguments for appending a negative evidence entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeEvidenceAppendArgs {
    /// Path to an existing binary ledger file.
    pub path: String,
    /// Entry ID.
    pub neg_id: String,
    /// Exact date and commit of the experiment.
    pub date_commit: String,
    /// Normative decision.
    pub decision: NegativeDecision,
    /// Verbatim decision text (may be empty).
    pub decision_text: String,
    /// Hypothesis disposition.
    pub disposition: HypothesisDisposition,
    /// Hypothesis text.
    pub hypothesis: String,
    /// Reasoning text.
    pub reasoning: String,
    /// Measured result text.
    pub measured_result: String,
    /// Revival condition text.
    pub revival_condition: String,
    /// Shared failure domains.
    pub failure_domains: BTreeSet<String>,
    /// Earlier entry superseded by this entry.
    pub supersedes: Option<String>,
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
    /// Coverage witness options.
    pub witness: CoverageWitnessArgs,
    /// Whether to output JSON envelope.
    pub json: bool,
}

/// Typed actions for the `negative-evidence` subcommand.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NegativeEvidenceAction {
    /// Print help text.
    Help,
    /// Create a new ledger file holding the seed entries.
    Init {
        /// Path of the ledger file to create.
        path: String,
        /// Whether to output JSON envelope.
        json: bool,
    },
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
            Self::Init { json, .. } | Self::List { json, .. } | Self::Verify { json, .. } => *json,
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
        "init" => {
            let (path, json) = parse_path_and_json(&tokens[1..], "negative-evidence init")?;
            let path = path.ok_or_else(|| CliError::MissingValue {
                option: "--path".to_owned(),
                command: Some("negative-evidence init".to_owned()),
                expected: "path of the ledger file to create".to_owned(),
            })?;
            Ok(NegativeEvidenceAction::Init { path, json })
        }
        "list" => {
            let (path, json) = parse_path_and_json(&tokens[1..], "negative-evidence list")?;
            Ok(NegativeEvidenceAction::List { path, json })
        }
        "verify" => {
            let (path, json) = parse_path_and_json(&tokens[1..], "negative-evidence verify")?;
            Ok(NegativeEvidenceAction::Verify { path, json })
        }
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

fn parse_path_and_json(
    tokens: &[ArgToken],
    command: &str,
) -> Result<(Option<String>, bool), CliError> {
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
                        command: Some(command.to_owned()),
                        index: tok.index,
                    });
                }
                idx += 1;
                if idx >= tokens.len() {
                    return Err(CliError::MissingValue {
                        option: "--path".to_owned(),
                        command: Some(command.to_owned()),
                        expected: "path to binary ledger file".to_owned(),
                    });
                }
                path = Some(tokens[idx].raw.clone());
            }
            "--json" => {
                if json {
                    return Err(CliError::DuplicateOption {
                        option: "--json".to_owned(),
                        command: Some(command.to_owned()),
                        index: tok.index,
                    });
                }
                json = true;
            }
            opt if is_option_shaped(opt) => {
                return Err(CliError::UnknownOption {
                    option: opt.to_owned(),
                    command: Some(command.to_owned()),
                    index: tok.index,
                });
            }
            trailing => {
                return Err(CliError::TrailingArgument {
                    argument: trailing.to_owned(),
                    index: tok.index,
                    command: Some(command.to_owned()),
                });
            }
        }
        idx += 1;
    }

    Ok((path, json))
}

/// A raw option value together with the argv index of the value token.
type RawValue = Option<(String, usize)>;

fn malformed(option: &str, value: &str, reason: &str, index: usize) -> CliError {
    CliError::MalformedValue {
        option: option.to_owned(),
        value: value.to_owned(),
        reason: reason.to_owned(),
        command: Some(APPEND_COMMAND.to_owned()),
        index,
    }
}

fn required(value: RawValue, option: &str, expected: &str) -> Result<(String, usize), CliError> {
    value.ok_or_else(|| CliError::MissingValue {
        option: option.to_owned(),
        command: Some(APPEND_COMMAND.to_owned()),
        expected: expected.to_owned(),
    })
}

fn parse_typed<T>(
    value: RawValue,
    option: &str,
    reason: &str,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<Option<T>, CliError> {
    match value {
        None => Ok(None),
        Some((raw, index)) => parse(&raw)
            .map(Some)
            .ok_or_else(|| malformed(option, &raw, reason, index)),
    }
}

fn parse_continuity(raw: &str) -> Option<CoverageContinuity> {
    match raw {
        "continuous" => Some(CoverageContinuity::Continuous),
        "gapped" => Some(CoverageContinuity::Gapped),
        "unknown" => Some(CoverageContinuity::Unknown),
        _ => None,
    }
}

fn parse_completeness(raw: &str) -> Option<Completeness> {
    match raw {
        "complete" => Some(Completeness::Complete),
        "bounded" => Some(Completeness::Bounded),
        "partial" => Some(Completeness::Partial),
        "unknown" => Some(Completeness::Unknown),
        "not_observable" => Some(Completeness::NotObservable),
        "unauthorized" => Some(Completeness::Unauthorized),
        "stale" => Some(Completeness::Stale),
        _ => None,
    }
}

fn parse_stop_reason(raw: &str) -> Option<CoverageStopReason> {
    match raw {
        "complete" => Some(CoverageStopReason::Complete),
        "budget_exhausted" => Some(CoverageStopReason::BudgetExhausted),
        "cancelled" => Some(CoverageStopReason::Cancelled),
        "source_gap" => Some(CoverageStopReason::SourceGap),
        "authorization_filtered" => Some(CoverageStopReason::AuthorizationFiltered),
        "unsupported" => Some(CoverageStopReason::Unsupported),
        "error" => Some(CoverageStopReason::Error),
        _ => None,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "CLI argument parsing loop over many flags"
)]
fn parse_append_tokens(tokens: &[ArgToken]) -> Result<NegativeEvidenceAction, CliError> {
    let mut path: RawValue = None;
    let mut neg_id: RawValue = None;
    let mut date_commit: RawValue = None;
    let mut decision: RawValue = None;
    let mut decision_text: RawValue = None;
    let mut disposition: RawValue = None;
    let mut hypothesis: RawValue = None;
    let mut reasoning: RawValue = None;
    let mut measured_result: RawValue = None;
    let mut revival_condition: RawValue = None;
    let mut supersedes: RawValue = None;
    let mut coverage_domain: RawValue = None;
    let mut coverage_generation: RawValue = None;
    let mut negative_predicate: RawValue = None;
    let mut continuity: RawValue = None;
    let mut completeness: RawValue = None;
    let mut stop_reason: RawValue = None;
    let mut corpus: RawValue = None;
    let mut device_model: RawValue = None;
    let mut firmware: RawValue = None;
    let mut platform: RawValue = None;
    let mut policy: RawValue = None;
    let mut command: RawValue = None;
    let mut failure_domains: BTreeSet<String> = BTreeSet::new();
    let mut json = false;
    let mut idx = 0;

    macro_rules! parse_opt {
        ($tok:ident, $target:ident, $flag:expr, $expected:expr) => {{
            if $target.is_some() {
                return Err(CliError::DuplicateOption {
                    option: ($flag).to_owned(),
                    command: Some(APPEND_COMMAND.to_owned()),
                    index: $tok.index,
                });
            }
            idx += 1;
            if idx >= tokens.len() {
                return Err(CliError::MissingValue {
                    option: ($flag).to_owned(),
                    command: Some(APPEND_COMMAND.to_owned()),
                    expected: ($expected).to_owned(),
                });
            }
            $target = Some((tokens[idx].raw.clone(), tokens[idx].index));
        }};
    }

    while idx < tokens.len() {
        let tok = &tokens[idx];
        match tok.as_str() {
            "--path" => parse_opt!(tok, path, "--path", "path to binary ledger file"),
            "--id" => parse_opt!(
                tok,
                neg_id,
                "--id",
                "stable negative evidence ID (e.g. NEG-004)"
            ),
            "--date-commit" => parse_opt!(
                tok,
                date_commit,
                "--date-commit",
                "exact date and commit of the experiment"
            ),
            "--decision" => parse_opt!(
                tok,
                decision,
                "--decision",
                "negative decision (reject, oracle, narrow, revisit)"
            ),
            "--decision-text" => {
                parse_opt!(tok, decision_text, "--decision-text", "decision text")
            }
            "--disposition" => parse_opt!(
                tok,
                disposition,
                "--disposition",
                "hypothesis disposition (live, supported, disfavored, refuted, resolved, superseded)"
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
            "--supersedes" => parse_opt!(
                tok,
                supersedes,
                "--supersedes",
                "earlier entry ID superseded by this entry"
            ),
            "--failure-domain" => {
                idx += 1;
                if idx >= tokens.len() {
                    return Err(CliError::MissingValue {
                        option: "--failure-domain".to_owned(),
                        command: Some(APPEND_COMMAND.to_owned()),
                        expected: "shared failure domain label".to_owned(),
                    });
                }
                let value = &tokens[idx];
                if !failure_domains.insert(value.raw.clone()) {
                    return Err(malformed(
                        "--failure-domain",
                        &value.raw,
                        "failure domain listed more than once",
                        value.index,
                    ));
                }
            }
            "--coverage-domain" => parse_opt!(
                tok,
                coverage_domain,
                "--coverage-domain",
                "coverage domain label"
            ),
            "--coverage-generation" => parse_opt!(
                tok,
                coverage_generation,
                "--coverage-generation",
                "coverage generation (integer >= 1)"
            ),
            "--negative-predicate" => parse_opt!(
                tok,
                negative_predicate,
                "--negative-predicate",
                "negative predicate naming the entry"
            ),
            "--continuity" => parse_opt!(
                tok,
                continuity,
                "--continuity",
                "coverage continuity (continuous, gapped, unknown)"
            ),
            "--completeness" => {
                parse_opt!(tok, completeness, "--completeness", "coverage completeness")
            }
            "--stop-reason" => {
                parse_opt!(tok, stop_reason, "--stop-reason", "coverage stop reason")
            }
            "--corpus" => parse_opt!(tok, corpus, "--corpus", "setup evaluation corpus"),
            "--device-model" => {
                parse_opt!(tok, device_model, "--device-model", "setup device model")
            }
            "--firmware" => parse_opt!(tok, firmware, "--firmware", "setup firmware version"),
            "--platform" => parse_opt!(tok, platform, "--platform", "setup platform"),
            "--policy" => parse_opt!(tok, policy, "--policy", "setup policy profile"),
            "--command" => parse_opt!(tok, command, "--command", "reproduction command"),
            "--json" => {
                if json {
                    return Err(CliError::DuplicateOption {
                        option: "--json".to_owned(),
                        command: Some(APPEND_COMMAND.to_owned()),
                        index: tok.index,
                    });
                }
                json = true;
            }
            opt if is_option_shaped(opt) => {
                return Err(CliError::UnknownOption {
                    option: opt.to_owned(),
                    command: Some(APPEND_COMMAND.to_owned()),
                    index: tok.index,
                });
            }
            trailing => {
                return Err(CliError::TrailingArgument {
                    argument: trailing.to_owned(),
                    index: tok.index,
                    command: Some(APPEND_COMMAND.to_owned()),
                });
            }
        }
        idx += 1;
    }

    let (path, _) = required(
        path,
        "--path",
        "existing ledger file (create one with `init`)",
    )?;
    let (neg_id, _) = required(neg_id, "--id", "stable negative evidence ID (e.g. NEG-004)")?;
    let (date_commit, _) = required(
        date_commit,
        "--date-commit",
        "exact date and commit of the experiment",
    )?;
    let (decision_raw, decision_index) = required(
        decision,
        "--decision",
        "negative decision (reject, oracle, narrow, revisit)",
    )?;
    let decision = NegativeDecision::parse(&decision_raw).map_err(|_| {
        malformed(
            "--decision",
            &decision_raw,
            "expected reject, oracle, narrow, or revisit",
            decision_index,
        )
    })?;
    let (disposition_raw, disposition_index) = required(
        disposition,
        "--disposition",
        "hypothesis disposition (live, supported, disfavored, refuted, resolved, superseded)",
    )?;
    let disposition = HypothesisDisposition::from_name(&disposition_raw).map_err(|_| {
        malformed(
            "--disposition",
            &disposition_raw,
            "expected live, supported, disfavored, refuted, resolved, or superseded",
            disposition_index,
        )
    })?;
    let (hypothesis, _) = required(hypothesis, "--hypothesis", "hypothesis statement")?;
    let (reasoning, _) = required(reasoning, "--reasoning", "reasoning statement")?;
    let (measured_result, _) = required(measured_result, "--result", "measured result statement")?;
    let (revival_condition, _) = required(
        revival_condition,
        "--revival",
        "revival condition statement",
    )?;
    if failure_domains.is_empty() {
        return Err(CliError::MissingValue {
            option: "--failure-domain".to_owned(),
            command: Some(APPEND_COMMAND.to_owned()),
            expected: "at least one shared failure domain label".to_owned(),
        });
    }

    let witness = CoverageWitnessArgs {
        domain: coverage_domain.map(|(raw, _)| raw),
        generation: parse_typed(
            coverage_generation,
            "--coverage-generation",
            "expected an integer >= 1",
            |raw| raw.parse::<u64>().ok().filter(|generation| *generation > 0),
        )?,
        negative_predicate: negative_predicate.map(|(raw, _)| raw),
        continuity: parse_typed(
            continuity,
            "--continuity",
            "expected continuous, gapped, or unknown",
            parse_continuity,
        )?,
        completeness: parse_typed(
            completeness,
            "--completeness",
            "expected complete, bounded, partial, unknown, not_observable, unauthorized, or stale",
            parse_completeness,
        )?,
        stop_reason: parse_typed(
            stop_reason,
            "--stop-reason",
            "expected complete, budget_exhausted, cancelled, source_gap, authorization_filtered, unsupported, or error",
            parse_stop_reason,
        )?,
    };

    Ok(NegativeEvidenceAction::Append(Box::new(
        NegativeEvidenceAppendArgs {
            path,
            neg_id,
            date_commit,
            decision,
            decision_text: decision_text.map(|(raw, _)| raw).unwrap_or_default(),
            disposition,
            hypothesis,
            reasoning,
            measured_result,
            revival_condition,
            failure_domains,
            supersedes: supersedes.map(|(raw, _)| raw),
            corpus: corpus.map(|(raw, _)| raw),
            device_model: device_model.map(|(raw, _)| raw),
            firmware: firmware.map(|(raw, _)| raw),
            platform: platform.map(|(raw, _)| raw),
            policy: policy.map(|(raw, _)| raw),
            command: command.map(|(raw, _)| raw),
            witness,
            json,
        },
    )))
}

/// Executes a validated `NegativeEvidenceAction` and returns its output text and exit identity.
#[must_use]
pub fn execute_negative_evidence(action: &NegativeEvidenceAction) -> (String, ExitIdentity) {
    match action {
        NegativeEvidenceAction::Help => (help_text().to_owned(), ExitIdentity::SUCCESS),
        NegativeEvidenceAction::Init { path, json } => execute_init(path, *json),
        NegativeEvidenceAction::List { path, json } => execute_list(path.as_deref(), *json),
        NegativeEvidenceAction::Verify { path, json } => execute_verify(path.as_deref(), *json),
        NegativeEvidenceAction::Append(args) => execute_append(args),
    }
}

fn load_ledger(path: Option<&str>) -> Result<NegativeEvidenceLedger, NegativeEvidenceError> {
    match path {
        Some(file_path) => {
            let bytes = fs::read(file_path).map_err(|err| {
                if err.kind() == ErrorKind::NotFound {
                    NegativeEvidenceError::Io(format!(
                        "ledger file '{file_path}' does not exist; create it with `fss negative-evidence init --path {file_path}`"
                    ))
                } else {
                    NegativeEvidenceError::Io(format!(
                        "failed to read ledger file '{file_path}': {err}"
                    ))
                }
            })?;
            NegativeEvidenceLedger::decode_canonical(&bytes)
        }
        None => initial_negative_evidence_ledger(),
    }
}

/// How [`write_ledger_atomically`] publishes the temporary file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteMode {
    /// Fail if the target already exists (no clobber), via hard link.
    CreateNew,
    /// Atomically replace the target via rename.
    Replace,
}

/// Writes `bytes` to a temp file in the target's directory, syncs it, then publishes it by
/// rename (replace) or hard link (create-new). A crash never leaves a partially written ledger
/// at `path`. There is no retry loop.
fn write_ledger_atomically(
    path: &str,
    bytes: &[u8],
    mode: WriteMode,
) -> Result<(), NegativeEvidenceError> {
    let target = Path::new(path);
    let file_name = target.file_name().ok_or_else(|| {
        NegativeEvidenceError::Io(format!("ledger path '{path}' does not name a file"))
    })?;
    let dir = match target.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut temp_name = OsString::from(".");
    temp_name.push(file_name);
    temp_name.push(format!(".tmp-{}", std::process::id()));
    let temp = dir.join(temp_name);

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|err| {
            NegativeEvidenceError::Io(format!(
                "failed to create temporary ledger file '{}': {err}",
                temp.display()
            ))
        })?;
    if let Err(err) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(NegativeEvidenceError::Io(format!(
            "failed to write temporary ledger file '{}': {err}",
            temp.display()
        )));
    }
    drop(file);

    let published = match mode {
        WriteMode::Replace => fs::rename(&temp, target),
        WriteMode::CreateNew => fs::hard_link(&temp, target),
    };
    if let Err(err) = published {
        let _ = fs::remove_file(&temp);
        return Err(NegativeEvidenceError::Io(format!(
            "failed to publish ledger file '{path}': {err}"
        )));
    }
    if mode == WriteMode::CreateNew {
        fs::remove_file(&temp).map_err(|err| {
            NegativeEvidenceError::Io(format!(
                "ledger '{path}' was created but temporary file '{}' could not be removed: {err}",
                temp.display()
            ))
        })?;
    }
    // Persist the directory entry; a failure here does not undo the published ledger.
    if let Ok(dir_handle) = fs::File::open(&dir) {
        let _ = dir_handle.sync_all();
    }
    Ok(())
}

/// Renders a refusal as plain text or as a JSON error envelope; always a runtime failure.
fn failure(
    json: bool,
    payload_schema: &str,
    payload_prefix: &str,
    err_id: &str,
    message: &str,
) -> (String, ExitIdentity) {
    if json {
        let payload = format!(
            "{{{payload_prefix}\"error\":\"{err_id}\",\"detail\":\"{}\"}}",
            escape_json_str(message)
        );
        let envelope = format_agent_response_envelope(
            "error",
            Some(err_id),
            payload_schema,
            &payload,
            "unknown",
            "partial",
            &[message.to_owned()],
            "no",
            "never_unchanged",
        );
        (envelope, ExitIdentity::RUNTIME_FAILURE)
    } else {
        (message.to_owned(), ExitIdentity::RUNTIME_FAILURE)
    }
}

fn init_ledger(path: &str) -> Result<(usize, String), NegativeEvidenceError> {
    if Path::new(path).symlink_metadata().is_ok() {
        return Err(NegativeEvidenceError::Io(format!(
            "ledger file '{path}' already exists; init never overwrites a ledger"
        )));
    }
    let ledger = initial_negative_evidence_ledger()?;
    let bytes = ledger.encode_canonical()?;
    write_ledger_atomically(path, &bytes, WriteMode::CreateNew)?;
    Ok((ledger.len(), ContentDigest::sha256(&bytes).to_text()))
}

fn execute_init(path: &str, json: bool) -> (String, ExitIdentity) {
    match init_ledger(path) {
        Ok((count, root_digest)) => {
            if json {
                let payload = format!(
                    "{{\"path\":\"{}\",\"entryCount\":{count},\"rootDigest\":\"{root_digest}\"}}",
                    escape_json_str(path)
                );
                let envelope = format_agent_response_envelope(
                    "ok",
                    None,
                    "fss.negative_evidence.init_receipt.v1",
                    &payload,
                    "known",
                    "complete",
                    &[],
                    "no",
                    "never_unchanged",
                );
                (envelope, ExitIdentity::SUCCESS)
            } else {
                (
                    format!(
                        "Ledger '{path}' initialized with {count} seed entries (root digest: {root_digest})"
                    ),
                    ExitIdentity::SUCCESS,
                )
            }
        }
        Err(err) => {
            let err_id = err.error_id();
            failure(
                json,
                ERROR_PAYLOAD_SCHEMA,
                "",
                err_id,
                &format!("Init refused [{err_id}]: {err}"),
            )
        }
    }
}

fn certification_label(entry: &NegativeEvidenceEntry) -> String {
    match &entry.certification {
        EvidenceCertification::LocallyCertified => "locally-certified".to_owned(),
        EvidenceCertification::NotLocallyCertified { source } => {
            format!("not-locally-certified (source: {source})")
        }
    }
}

fn execute_list(path: Option<&str>, json: bool) -> (String, ExitIdentity) {
    let ledger = match load_ledger(path) {
        Ok(l) => l,
        Err(err) => {
            let err_id = err.error_id();
            return failure(
                json,
                ERROR_PAYLOAD_SCHEMA,
                "",
                err_id,
                &format!("error[{err_id}]: failed to load ledger: {err}"),
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
                "{} [{}] \"{}\"\n  Revival: \"{}\"\n  Certification: {}\n  Witness: {:?} (authorized: {}, observed: {})\n",
                entry.neg_id,
                entry.decision.as_str(),
                entry.hypothesis,
                entry.revival_condition,
                certification_label(entry),
                entry.coverage_witness.continuity,
                entry.coverage_witness.authorized_generation,
                entry.coverage_witness.observed_generation,
            ));
        }
        (out, ExitIdentity::SUCCESS)
    }
}

fn execute_verify(path: Option<&str>, json: bool) -> (String, ExitIdentity) {
    let verified = load_ledger(path).and_then(|ledger| {
        ledger.verify()?;
        let root_digest = ledger.root_digest()?.to_text();
        Ok((ledger, root_digest))
    });
    let (ledger, root_digest) = match verified {
        Ok(result) => result,
        Err(err) => {
            let err_id = err.error_id();
            return failure(
                json,
                "fss.negative_evidence.verification.v1",
                "\"verified\":false,",
                err_id,
                &format!("Verification failed [{err_id}]: {err}"),
            );
        }
    };

    let certified = ledger
        .entries()
        .iter()
        .filter(|e| e.certification == EvidenceCertification::LocallyCertified)
        .count();
    let uncertified = ledger.len() - certified;
    if json {
        let payload = format!(
            "{{\"verified\":true,\"entryCount\":{},\"locallyCertified\":{certified},\"notLocallyCertified\":{uncertified},\"rootDigest\":\"{root_digest}\",\"formatVersion\":1}}",
            ledger.len()
        );
        let envelope = format_agent_response_envelope(
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
                "Ledger verified: continuous coverage guarantees intact for all {certified} locally certified entries; {uncertified} entries are not locally certified ({} entries, root digest: {root_digest})",
                ledger.len()
            ),
            ExitIdentity::SUCCESS,
        )
    }
}

/// Builds the caller-supplied witness; refuses when any of the six witness options is absent.
fn build_witness(
    args: &CoverageWitnessArgs,
) -> Result<(String, CoverageWitness), NegativeEvidenceError> {
    let (
        Some(domain),
        Some(generation),
        Some(predicate),
        Some(continuity),
        Some(completeness),
        Some(stop_reason),
    ) = (
        &args.domain,
        args.generation,
        &args.negative_predicate,
        args.continuity,
        args.completeness,
        args.stop_reason,
    )
    else {
        let missing = args.missing_options();
        let detail = if missing.len() == 6 {
            "no coverage witness supplied".to_owned()
        } else {
            format!(
                "incomplete coverage witness; missing {}",
                missing.join(", ")
            )
        };
        return Err(NegativeEvidenceError::MissingCoverageWitness { detail });
    };
    let domain_set = BTreeSet::from([domain.clone()]);
    Ok((
        domain.clone(),
        CoverageWitness {
            anchor: LedgerAnchor::genesis("site:fss:cli"),
            authorized_domain: domain_set.clone(),
            observed_domain: domain_set,
            excluded_domain: BTreeSet::new(),
            continuity,
            completeness,
            negative_predicate: predicate.clone(),
            stop_reason,
            authorized_generation: generation,
            observed_generation: generation,
        },
    ))
}

fn append_entry(
    args: &NegativeEvidenceAppendArgs,
) -> Result<(NegativeEvidenceEntry, usize, String), NegativeEvidenceError> {
    let (domain, witness) = build_witness(&args.witness)?;
    let or_not_evaluated =
        |value: &Option<String>| value.clone().unwrap_or_else(|| NOT_EVALUATED.to_owned());
    let command = args
        .command
        .clone()
        .unwrap_or_else(|| NOT_LOCALLY_REPRODUCIBLE.to_owned());
    let entry = NegativeEvidenceEntry {
        neg_id: args.neg_id.clone(),
        date_commit: args.date_commit.clone(),
        hypothesis: args.hypothesis.clone(),
        reasoning: args.reasoning.clone(),
        setup: NegativeEvidenceSetup {
            corpus: or_not_evaluated(&args.corpus),
            device_model: or_not_evaluated(&args.device_model),
            firmware_version: or_not_evaluated(&args.firmware),
            platform: or_not_evaluated(&args.platform),
            policy: or_not_evaluated(&args.policy),
            command: command.clone(),
            artifact_digest: None,
        },
        measured_result: args.measured_result.clone(),
        decision: args.decision,
        decision_text: args.decision_text.clone(),
        shared_failure_domains: args.failure_domains.clone(),
        revival_condition: args.revival_condition.clone(),
        knowledge_state: KnowledgeState::Known,
        provenance_class: ProvenanceClass::OperatorAsserted,
        disposition: args.disposition,
        coverage_witness: witness,
        claimed_domain: BTreeSet::from([domain]),
        certification: EvidenceCertification::LocallyCertified,
        supersedes: args.supersedes.clone(),
        is_tombstone: false,
        tombstone_reason: None,
        proof_hash: None,
        reproduction_command: command,
    };

    let mut ledger = load_ledger(Some(&args.path))?;
    ledger.append(entry.clone())?;
    ledger.verify()?;
    let bytes = ledger.encode_canonical()?;
    write_ledger_atomically(&args.path, &bytes, WriteMode::Replace)?;
    Ok((entry, ledger.len(), ContentDigest::sha256(&bytes).to_text()))
}

fn execute_append(args: &NegativeEvidenceAppendArgs) -> (String, ExitIdentity) {
    match append_entry(args) {
        Ok((entry, count, root_digest)) => {
            if args.json {
                let payload = format!(
                    "{{\"appendedId\":\"{}\",\"entryCount\":{count},\"rootDigest\":\"{root_digest}\",\"entry\":{}}}",
                    escape_json_str(&entry.neg_id),
                    entry.to_json()
                );
                let envelope = format_agent_response_envelope(
                    "ok",
                    None,
                    "fss.negative_evidence.append_receipt.v1",
                    &payload,
                    "known",
                    "complete",
                    &[],
                    "no",
                    "never_unchanged",
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
        Err(err) => {
            let err_id = err.error_id();
            failure(
                args.json,
                ERROR_PAYLOAD_SCHEMA,
                "",
                err_id,
                &format!("Append rejected [{err_id}]: {err}"),
            )
        }
    }
}

/// Formats output shaped as `schemas/agent_response_envelope.v1.json`.
///
/// Fields this command cannot derive honestly (operation ID, registry digests, input anchor,
/// budgets) are emitted as `null` and listed in `degradation`; they are never fabricated.
#[expect(
    clippy::too_many_arguments,
    reason = "Constructs agent response envelope across all canonical fields"
)]
pub fn format_agent_response_envelope(
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
    let degradation_json = {
        let items: Vec<String> = ENVELOPE_DEGRADATION
            .iter()
            .map(|d| format!("\"{}\"", escape_json_str(d)))
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
\"schemaCatalogDigest\":null,\
\"ontologyGenerationId\":null,\
\"operationRegistryDigest\":null,\
\"viewRegistryDigest\":null,\
\"capabilityRegistryDigest\":null,\
\"errorRegistryDigest\":null,\
\"costRegistryDigest\":null,\
\"producerReleaseId\":\"fss-cli:{VERSION}\",\
\"acceptedNightly\":\"nightly-2026-08-31\"\
}},\
\"operationId\":null,\
\"requestId\":\"req:cli:neg:1\",\
\"responseRevision\":1,\
\"principalId\":\"principal:cli:local\",\
\"sessionId\":null,\
\"missionId\":null,\
\"traceId\":\"trace:cli:neg:1\",\
\"taskId\":null,\
\"inputAnchor\":null,\
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
\"degradation\":{degradation_json},\
\"budgets\":{{\"requested\":null,\"consumed\":null,\"remaining\":null}},\
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
