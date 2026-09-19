#![forbid(unsafe_code)]
//! Command specification, argument decoding, and execution for the `fss negative-evidence` subcommand.
//!
//! - `init`: create a ledger file holding the NEG-001..NEG-003 seeds; never overwrites (the
//!   file is published with a hard link, which fails if the target exists).
//! - `list` / `verify`: read a ledger (the built-in seed ledger when `--path` is absent).
//! - `append`: append a locally certified entry. The caller supplies the claimed and the observed
//!   coverage separately, an explicit witness anchor, a proof hash, and a retained evidence
//!   reference; without them the append is refused and `known` is never stamped. An append holds
//!   an exclusive lock file for its whole read-modify-write, re-checks the ledger digest just
//!   before publishing (compare-and-swap, at most [`MAX_APPEND_ATTEMPTS`] attempts), and publishes
//!   atomically (temp file in the same directory, then rename).
//! - `--json`: emits `fss.negative_evidence_report.v1` (`schemas/negative_evidence_report.v1.json`).
//!   The command has no AOP registry row, so it does not claim the agent response envelope, and
//!   every reported field is derived from the ledger or the refusal.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use fss_core::negative_evidence::{
    EvidenceCertification, NEGATIVE_EVIDENCE_FORMAT_VERSION, NOT_EVALUATED,
    NOT_LOCALLY_REPRODUCIBLE, NegativeDecision, NegativeEvidenceEntry, NegativeEvidenceError,
    NegativeEvidenceLedger, NegativeEvidenceSetup, initial_negative_evidence_ledger,
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

/// Schema of the JSON report every `fss negative-evidence ... --json` invocation emits.
pub const NEGATIVE_EVIDENCE_REPORT_SCHEMA: &str = "fss.negative_evidence_report.v1";

/// Maximum compare-and-swap attempts for one append before it is refused.
pub const MAX_APPEND_ATTEMPTS: u32 = 3;

const UNREGISTERED_OPERATION_NOTE: &str = "not_an_agent_response_envelope: `fss negative-evidence` has no AOP row in registries/OPERATION_CROSSWALK.md, so no operation, anchor, contract-basis, or budget fields are reported";

const MIXED_STATES_NOTE: &str = "mixed_knowledge_states: entries carry different knowledge states, so epistemicState is null; see knowledgeStateCounts";

/// Help text for `fss negative-evidence`.
pub const fn help_text() -> &'static str {
    "fss negative-evidence — deterministic negative-evidence ledger management\n\n\
USAGE:\n  \
  fss negative-evidence init --path <file> [--json]\n  \
  fss negative-evidence list [--path <file>] [--json]\n  \
  fss negative-evidence verify [--path <file>] [--json]\n  \
  fss negative-evidence append --path <file> <required options> <coverage witness> <proof> [options...] [--json]\n  \
  fss negative-evidence help\n\n\
SUBCOMMANDS:\n  \
  init      Create a ledger file holding the NEG-001..NEG-003 seeds (never overwrites)\n  \
  list      List entries with stable ID, decision, hypothesis, certification, and revival conditions\n  \
  verify    Verify integrity, canonical order, coverage certification, and root digest\n  \
  append    Append a locally certified entry (refusing absence without a coverage witness and proof)\n  \
  help      Show this help message\n\n\
Without --path, list and verify read the built-in seed ledger. --json emits\n\
fss.negative_evidence_report.v1.\n\n\
APPEND REQUIRED OPTIONS:\n  \
  --path <FILE>                Existing canonical binary ledger file (create one with `init`)\n  \
  --id <ID>                    Stable ID: NEG- plus at least three digits (e.g. NEG-004, NEG-1000)\n  \
  --date-commit <TEXT>         Exact date and commit of the experiment\n  \
  --decision <DECISION>        reject, oracle, narrow, or revisit\n  \
  --disposition <DISP>         live, supported, disfavored, refuted, resolved, or superseded\n  \
  --hypothesis <TEXT>          What was expected and why\n  \
  --reasoning <TEXT>           Architectural or theoretical reasoning\n  \
  --result <TEXT>              Measured result, divergences, and failures\n  \
  --revival <TEXT>             Explicit condition that would justify repeating the work\n  \
  --failure-domain <LABEL>     Shared failure domain (repeatable; at least one)\n\n\
COVERAGE WITNESS (all required; absence without a coverage witness is never evidence):\n  \
  --coverage-domain <LABEL>    Domain the entry claims (the witness's authorized domain)\n  \
  --coverage-generation <N>    Authorized generation (N >= 1)\n  \
  --observed-domain <LABEL>    Domain the experiment actually observed\n  \
  --observed-generation <N>    Generation the experiment actually observed (N >= 1)\n  \
  --coverage-anchor <ANCHOR>   <site>@<epoch>.<sequence>.<adapter>.<schema>.<policy>.<privacy>@<state-root digest>\n  \
  --negative-predicate <P>     Exactly absence-certified:<coverage-domain>:<ID>\n  \
  --continuity <C>             continuous, gapped, or unknown\n  \
  --completeness <C>           complete, bounded, partial, unknown, not_observable, unauthorized, or stale\n  \
  --stop-reason <R>            complete, budget_exhausted, cancelled, source_gap, authorization_filtered, unsupported, or error\n\n\
PROOF (both required; known is never recorded without them):\n  \
  --proof-hash <DIGEST>        Digest of the retained proof artifact (e.g. sha256:<64 hex>)\n  \
  --evidence-ref <HANDLE>      Secret-free handle of the retained evidence the proof hash binds\n\n\
APPEND OPTIONAL:\n  \
  --decision-text <TEXT>       Verbatim decision text\n  \
  --supersedes <ID>            Earlier entry this entry supersedes (append-only link)\n  \
  --corpus <CORPUS>            Evaluation corpus identity (default: not-evaluated)\n  \
  --device-model <MODEL>       Hardware or simulated device model (default: not-evaluated)\n  \
  --firmware <FW>              Target firmware version (default: not-evaluated)\n  \
  --platform <PLATFORM>        Operating system or execution environment (default: not-evaluated)\n  \
  --policy <POLICY>            Policy profile under test (default: not-evaluated)\n  \
  --command <CMD>              Reproduction command (default: not-locally-reproducible)\n  \
  --json                       Output a fss.negative_evidence_report.v1 JSON report\n"
}

/// Coverage witness options for `append`; all nine are required to certify absence.
///
/// The claimed (authorized) coverage and the observed coverage are separate inputs: the witness
/// certifies absence only when what was observed equals what is claimed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoverageWitnessArgs {
    /// Domain the entry claims (the witness's authorized domain).
    pub claimed_domain: Option<String>,
    /// Authorized generation.
    pub authorized_generation: Option<u64>,
    /// Domain actually observed.
    pub observed_domain: Option<String>,
    /// Generation actually observed.
    pub observed_generation: Option<u64>,
    /// Exact ledger anchor the witness was evaluated against.
    pub anchor: Option<LedgerAnchor>,
    /// Absence predicate naming the claimed domain and the entry.
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
        [
            (self.claimed_domain.is_none(), "--coverage-domain"),
            (
                self.authorized_generation.is_none(),
                "--coverage-generation",
            ),
            (self.observed_domain.is_none(), "--observed-domain"),
            (self.observed_generation.is_none(), "--observed-generation"),
            (self.anchor.is_none(), "--coverage-anchor"),
            (self.negative_predicate.is_none(), "--negative-predicate"),
            (self.continuity.is_none(), "--continuity"),
            (self.completeness.is_none(), "--completeness"),
            (self.stop_reason.is_none(), "--stop-reason"),
        ]
        .into_iter()
        .filter_map(|(missing, option)| missing.then_some(option))
        .collect()
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
    /// Digest of the retained proof artifact.
    pub proof_hash: Option<ContentDigest>,
    /// Handle of the retained evidence the proof hash binds.
    pub evidence_reference: Option<String>,
    /// Whether to output the JSON report.
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
        /// Whether to output the JSON report.
        json: bool,
    },
    /// List ledger entries.
    List {
        /// Optional path to binary ledger file.
        path: Option<String>,
        /// Whether to output the JSON report.
        json: bool,
    },
    /// Verify ledger integrity and coverage guarantees.
    Verify {
        /// Optional path to binary ledger file.
        path: Option<String>,
        /// Whether to output the JSON report.
        json: bool,
    },
    /// Append a verified entry to the ledger.
    Append(Box<NegativeEvidenceAppendArgs>),
}

impl NegativeEvidenceAction {
    /// Returns true if JSON output is requested.
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

fn parse_generation(raw: &str) -> Option<u64> {
    raw.parse::<u64>().ok().filter(|generation| *generation > 0)
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

/// Parses `<site>@<epoch>.<sequence>.<adapter>.<schema>.<policy>.<privacy>@<state-root digest>`.
fn parse_anchor(raw: &str) -> Option<LedgerAnchor> {
    let mut parts = raw.split('@');
    let (Some(site), Some(counters), Some(root), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if site.trim().is_empty() {
        return None;
    }
    let numbers = counters
        .split('.')
        .map(|number| number.parse::<u64>().ok())
        .collect::<Option<Vec<u64>>>()?;
    let [
        ledger_epoch,
        commit_sequence,
        adapter_registry_epoch,
        schema_epoch,
        policy_epoch,
        privacy_epoch,
    ] = numbers.as_slice()
    else {
        return None;
    };
    Some(LedgerAnchor {
        site_lineage: site.to_owned(),
        ledger_epoch: *ledger_epoch,
        commit_sequence: *commit_sequence,
        adapter_registry_epoch: *adapter_registry_epoch,
        schema_epoch: *schema_epoch,
        policy_epoch: *policy_epoch,
        privacy_epoch: *privacy_epoch,
        state_root: ContentDigest::parse(root).ok()?,
    })
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
    let mut observed_domain: RawValue = None;
    let mut observed_generation: RawValue = None;
    let mut coverage_anchor: RawValue = None;
    let mut negative_predicate: RawValue = None;
    let mut continuity: RawValue = None;
    let mut completeness: RawValue = None;
    let mut stop_reason: RawValue = None;
    let mut proof_hash: RawValue = None;
    let mut evidence_reference: RawValue = None;
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
                "claimed coverage domain label"
            ),
            "--coverage-generation" => parse_opt!(
                tok,
                coverage_generation,
                "--coverage-generation",
                "authorized coverage generation (integer >= 1)"
            ),
            "--observed-domain" => parse_opt!(
                tok,
                observed_domain,
                "--observed-domain",
                "observed coverage domain label"
            ),
            "--observed-generation" => parse_opt!(
                tok,
                observed_generation,
                "--observed-generation",
                "observed coverage generation (integer >= 1)"
            ),
            "--coverage-anchor" => parse_opt!(
                tok,
                coverage_anchor,
                "--coverage-anchor",
                "ledger anchor <site>@<epoch>.<sequence>.<adapter>.<schema>.<policy>.<privacy>@<state-root digest>"
            ),
            "--negative-predicate" => parse_opt!(
                tok,
                negative_predicate,
                "--negative-predicate",
                "negative predicate absence-certified:<coverage-domain>:<ID>"
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
            "--proof-hash" => parse_opt!(
                tok,
                proof_hash,
                "--proof-hash",
                "digest of the retained proof artifact"
            ),
            "--evidence-ref" => parse_opt!(
                tok,
                evidence_reference,
                "--evidence-ref",
                "handle of the retained evidence"
            ),
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
        claimed_domain: coverage_domain.map(|(raw, _)| raw),
        authorized_generation: parse_typed(
            coverage_generation,
            "--coverage-generation",
            "expected an integer >= 1",
            parse_generation,
        )?,
        observed_domain: observed_domain.map(|(raw, _)| raw),
        observed_generation: parse_typed(
            observed_generation,
            "--observed-generation",
            "expected an integer >= 1",
            parse_generation,
        )?,
        anchor: parse_typed(
            coverage_anchor,
            "--coverage-anchor",
            "expected <site>@<epoch>.<sequence>.<adapter>.<schema>.<policy>.<privacy>@<state-root digest>",
            parse_anchor,
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
    let proof_hash = parse_typed(
        proof_hash,
        "--proof-hash",
        "expected a content digest such as sha256:<64 hex digits>",
        |raw| ContentDigest::parse(raw).ok(),
    )?;

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
            proof_hash,
            evidence_reference: evidence_reference.map(|(raw, _)| raw),
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

fn read_ledger_bytes(path: &str) -> Result<Vec<u8>, NegativeEvidenceError> {
    fs::read(path).map_err(|err| {
        if err.kind() == ErrorKind::NotFound {
            NegativeEvidenceError::LedgerNotFound {
                path: path.to_owned(),
            }
        } else {
            NegativeEvidenceError::Io(format!("failed to read ledger file '{path}': {err}"))
        }
    })
}

/// Resolves every symlink in a ledger path to the real ledger file it names.
fn resolve_ledger_path(path: &str) -> Result<PathBuf, NegativeEvidenceError> {
    fs::canonicalize(path).map_err(|err| {
        if err.kind() == ErrorKind::NotFound {
            NegativeEvidenceError::LedgerNotFound {
                path: path.to_owned(),
            }
        } else {
            NegativeEvidenceError::Io(format!("failed to resolve ledger path '{path}': {err}"))
        }
    })
}

/// Returns the hard-link count of an open file, or `None` where the platform does not expose it.
#[cfg(unix)]
fn link_count(metadata: &fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.nlink())
}

/// Returns the hard-link count of an open file, or `None` where the platform does not expose it.
#[cfg(not(unix))]
fn link_count(_metadata: &fs::Metadata) -> Option<u64> {
    None
}

/// Reads the resolved ledger through one open handle and refuses it unless the file has exactly
/// one hard link. Renaming the new ledger into place updates a single name, so any other hard
/// link would keep the old ledger (a fork); symlinks were already resolved. The count comes from
/// the same open handle the bytes are read from. Where no link count is available the append
/// fails closed.
fn read_single_link_ledger(
    real: &Path,
    given: &str,
) -> Result<(Vec<u8>, fs::File), NegativeEvidenceError> {
    let io_error = |err: std::io::Error| {
        if err.kind() == ErrorKind::NotFound {
            NegativeEvidenceError::LedgerNotFound {
                path: given.to_owned(),
            }
        } else {
            NegativeEvidenceError::Io(format!("failed to read ledger file '{given}': {err}"))
        }
    };
    let mut file = fs::File::open(real).map_err(io_error)?;
    let metadata = file.metadata().map_err(io_error)?;
    let Some(links) = link_count(&metadata) else {
        return Err(NegativeEvidenceError::Io(format!(
            "cannot determine the hard-link count of ledger '{given}' on this platform; refusing to append"
        )));
    };
    if links != 1 {
        return Err(NegativeEvidenceError::LedgerHardLinked {
            path: given.to_owned(),
            links,
        });
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(io_error)?;
    Ok((bytes, file))
}

fn load_ledger(path: Option<&str>) -> Result<NegativeEvidenceLedger, NegativeEvidenceError> {
    match path {
        Some(file_path) => NegativeEvidenceLedger::decode_canonical(&read_ledger_bytes(file_path)?),
        None => initial_negative_evidence_ledger(),
    }
}

/// Path of a hidden sibling of the ledger: `.<ledger file name><suffix>` in the same directory.
fn sibling_path(ledger: &Path, suffix: &str) -> Result<PathBuf, NegativeEvidenceError> {
    let file_name = ledger.file_name().ok_or_else(|| {
        NegativeEvidenceError::Io(format!(
            "ledger path '{}' does not name a file",
            ledger.display()
        ))
    })?;
    let dir = match ledger.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut name = OsString::from(".");
    name.push(file_name);
    name.push(suffix);
    Ok(dir.join(name))
}

/// Exclusive per-ledger writer lock: `.<ledger file name>.lock`, created with `create_new` and
/// removed when dropped, which covers every exit path. A lock left behind by a crashed writer is
/// refused with a clear error and never broken automatically.
struct LedgerLock {
    path: PathBuf,
}

impl LedgerLock {
    fn acquire(ledger: &Path) -> Result<Self, NegativeEvidenceError> {
        let path = sibling_path(ledger, ".lock")?;
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                let lock = Self { path };
                // Diagnostic only: names the holder for an operator inspecting a stale lock.
                file.write_all(format!("pid {}\n", std::process::id()).as_bytes())
                    .map_err(|err| {
                        NegativeEvidenceError::Io(format!(
                            "failed to write lock file '{}': {err}",
                            lock.path.display()
                        ))
                    })?;
                Ok(lock)
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                Err(NegativeEvidenceError::LedgerLocked {
                    detail: format!(
                        "lock file '{}' exists: another append holds it, or a crashed writer left it stale; it is never removed automatically, so delete it only after confirming no `fss negative-evidence append` is running",
                        path.display()
                    ),
                })
            }
            Err(err) => Err(NegativeEvidenceError::Io(format!(
                "failed to create lock file '{}': {err}",
                path.display()
            ))),
        }
    }
}

impl Drop for LedgerLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// How [`write_ledger_atomically`] publishes the temporary file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteMode {
    /// Publish with a hard link, which fails if the target already exists (no clobber).
    CreateNew,
    /// Compare-and-swap: rename over the target only if it still has this digest.
    Replace {
        /// Digest of the ledger bytes the caller read.
        expected: ContentDigest,
    },
}

/// Why a publication did not happen.
#[derive(Debug)]
enum PublishError {
    /// The target no longer has the expected digest; nothing was written. Retryable.
    Changed,
    /// A hard failure; nothing was published.
    Failed(NegativeEvidenceError),
}

/// Called with the synced temporary file just before publication (a fault-injection seam).
type PublishHook<'a> = &'a dyn Fn(&Path) -> std::io::Result<()>;

fn publish_now(_temp: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Writes `bytes` to a temp file in the target's directory, syncs it, then publishes it. A crash
/// or failure before publication never changes the ledger at `path`. There is no retry here.
fn write_ledger_atomically(
    path: &str,
    bytes: &[u8],
    mode: WriteMode,
    before_publish: PublishHook<'_>,
    checked: Option<(&fs::File, &str)>,
) -> Result<(), PublishError> {
    let target = Path::new(path);
    let temp = sibling_path(target, &format!(".tmp-{}", std::process::id()))
        .map_err(PublishError::Failed)?;
    let fail = |detail: String| PublishError::Failed(NegativeEvidenceError::Io(detail));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|err| {
            if err.kind() == ErrorKind::AlreadyExists {
                return PublishError::Failed(NegativeEvidenceError::LedgerTempExists {
                    path: temp.display().to_string(),
                });
            }
            fail(format!(
                "failed to create temporary ledger file '{}': {err}",
                temp.display()
            ))
        })?;
    if let Err(err) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(fail(format!(
            "failed to write temporary ledger file '{}': {err}",
            temp.display()
        )));
    }
    drop(file);

    // fss-pl8u9: re-check the held handle immediately before publication. An external
    // `ln ledger other` between the read and this point would fork the append.
    if let Some((file, given)) = checked {
        let links = file
            .metadata()
            .ok()
            .and_then(|metadata| link_count(&metadata))
            .ok_or_else(|| {
                fail(format!(
                    "cannot re-check the hard-link count of ledger '{given}' before publish"
                ))
            })?;
        if links != 1 {
            let _ = fs::remove_file(&temp);
            return Err(PublishError::Failed(
                NegativeEvidenceError::LedgerHardLinked {
                    path: given.to_owned(),
                    links,
                },
            ));
        }
    }

    if let Err(err) = before_publish(&temp) {
        let _ = fs::remove_file(&temp);
        return Err(fail(format!(
            "publication of ledger '{path}' aborted before publish: {err}"
        )));
    }

    let published = match mode {
        WriteMode::Replace { expected } => {
            // Compare-and-swap: publish only if the ledger is still the one that was read.
            let mut old_len: Option<u64> = None;
            let mut old_digest: Option<ContentDigest> = None;
            let cas = match fs::read(target) {
                Ok(current) => {
                    let digest = ContentDigest::sha256(&current);
                    if digest == expected {
                        old_len = Some(current.len() as u64);
                        old_digest = Some(digest);
                        fs::rename(&temp, target)
                    } else {
                        let _ = fs::remove_file(&temp);
                        return Err(PublishError::Changed);
                    }
                }
                Err(err) => Err(err),
            };
            if let Err(err) = cas {
                return Err(fail(format!(
                    "failed to publish ledger file '{path}': {err}"
                )));
            }
            // fss-pl8u9: after the rename the old inode lost its `target` name, so a healthy
            // append leaves it unlinked. A surviving file holding the exact pre-append ledger
            // means another name still shows the old ledger: the append forked and must be
            // reported as a typed failure, never success. The scan matches content digests, not
            // inode ids or nlink: layered filesystems report those unstably after a rename.
            if let (Some(old_digest), Some(old_len_bytes), Some(parent)) = (
                old_digest,
                old_len,
                target.parent().filter(|parent| parent.exists()),
            ) {
                let mut forked_names = Vec::new();
                if let Ok(entries) = fs::read_dir(parent) {
                    for entry in entries.flatten() {
                        let candidate = entry.path();
                        if candidate == target {
                            continue;
                        }
                        // Size gate first: only files the size of the old ledger can hold it.
                        if fs::metadata(&candidate)
                            .map(|metadata| metadata.len() == old_len_bytes)
                            .unwrap_or(false)
                            && fs::read(&candidate).map_or(false, |current| {
                                ContentDigest::sha256(&current) == old_digest
                            })
                        {
                            forked_names.push(candidate.display().to_string());
                        }
                    }
                }
                if !forked_names.is_empty() {
                    return Err(PublishError::Failed(NegativeEvidenceError::LedgerForked {
                        path: forked_names.join(", "),
                        links: forked_names.len() as u64,
                    }));
                }
            }
            Ok(())
        }
        WriteMode::CreateNew => fs::hard_link(&temp, target),
    };
    if let Err(err) = published {
        let _ = fs::remove_file(&temp);
        if mode == WriteMode::CreateNew && err.kind() == ErrorKind::AlreadyExists {
            return Err(PublishError::Failed(NegativeEvidenceError::LedgerExists {
                path: path.to_owned(),
            }));
        }
        return Err(fail(format!(
            "failed to publish ledger file '{path}': {err}"
        )));
    }
    if mode == WriteMode::CreateNew {
        fs::remove_file(&temp).map_err(|err| {
            fail(format!(
                "ledger '{path}' was created but temporary file '{}' could not be removed: {err}",
                temp.display()
            ))
        })?;
    }
    // Persist the directory entry; a failure here does not undo the published ledger.
    let dir = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if let Ok(dir_handle) = fs::File::open(dir) {
        let _ = dir_handle.sync_all();
    }
    Ok(())
}

fn init_ledger(path: &str) -> Result<(NegativeEvidenceLedger, String), NegativeEvidenceError> {
    if Path::new(path).symlink_metadata().is_ok() {
        return Err(NegativeEvidenceError::LedgerExists {
            path: path.to_owned(),
        });
    }
    let ledger = initial_negative_evidence_ledger()?;
    let bytes = ledger.encode_canonical()?;
    write_ledger_atomically(path, &bytes, WriteMode::CreateNew, &publish_now, None).map_err(
        |err| match err {
            PublishError::Failed(err) => err,
            PublishError::Changed => NegativeEvidenceError::LedgerExists {
                path: path.to_owned(),
            },
        },
    )?;
    Ok((ledger, ContentDigest::sha256(&bytes).to_text()))
}

/// Builds the caller-supplied witness; refuses when any of the nine witness options is absent.
/// Claimed and observed coverage stay separate, so a mismatch fails certification.
fn build_witness(
    args: &CoverageWitnessArgs,
) -> Result<(String, CoverageWitness), NegativeEvidenceError> {
    let (
        Some(claimed_domain),
        Some(authorized_generation),
        Some(observed_domain),
        Some(observed_generation),
        Some(anchor),
        Some(predicate),
        Some(continuity),
        Some(completeness),
        Some(stop_reason),
    ) = (
        &args.claimed_domain,
        args.authorized_generation,
        &args.observed_domain,
        args.observed_generation,
        &args.anchor,
        &args.negative_predicate,
        args.continuity,
        args.completeness,
        args.stop_reason,
    )
    else {
        let missing = args.missing_options();
        let detail = if missing.len() == 9 {
            "no coverage witness supplied".to_owned()
        } else {
            format!(
                "incomplete coverage witness; missing {}",
                missing.join(", ")
            )
        };
        return Err(NegativeEvidenceError::MissingCoverageWitness { detail });
    };
    Ok((
        claimed_domain.clone(),
        CoverageWitness {
            anchor: anchor.clone(),
            authorized_domain: BTreeSet::from([claimed_domain.clone()]),
            observed_domain: BTreeSet::from([observed_domain.clone()]),
            excluded_domain: BTreeSet::new(),
            continuity,
            completeness,
            negative_predicate: predicate.clone(),
            stop_reason,
            authorized_generation,
            observed_generation,
        },
    ))
}

/// Builds the entry an append would record. `known` is recorded only with a complete witness, a
/// proof hash, and a retained evidence reference; the finding and decision are operator-asserted.
fn build_entry(
    args: &NegativeEvidenceAppendArgs,
) -> Result<NegativeEvidenceEntry, NegativeEvidenceError> {
    let (claimed_domain, witness) = build_witness(&args.witness)?;
    let (Some(proof_hash), Some(evidence_reference)) = (args.proof_hash, &args.evidence_reference)
    else {
        let missing: Vec<&str> = [
            (args.proof_hash.is_none(), "--proof-hash"),
            (args.evidence_reference.is_none(), "--evidence-ref"),
        ]
        .into_iter()
        .filter_map(|(missing, option)| missing.then_some(option))
        .collect();
        return Err(NegativeEvidenceError::MissingProof {
            detail: format!(
                "a locally certified entry needs a proof hash and a retained evidence reference; missing {}",
                missing.join(", ")
            ),
        });
    };
    let or_not_evaluated =
        |value: &Option<String>| value.clone().unwrap_or_else(|| NOT_EVALUATED.to_owned());
    let command = args
        .command
        .clone()
        .unwrap_or_else(|| NOT_LOCALLY_REPRODUCIBLE.to_owned());
    Ok(NegativeEvidenceEntry {
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
        decision_provenance: ProvenanceClass::OperatorAsserted,
        disposition: args.disposition,
        coverage_witness: witness,
        claimed_domain,
        certification: EvidenceCertification::LocallyCertified,
        supersedes: args.supersedes.clone(),
        is_tombstone: false,
        tombstone_reason: None,
        proof_hash: Some(proof_hash),
        evidence_reference: Some(evidence_reference.clone()),
        reproduction_command: command,
    })
}

/// Appends under the exclusive ledger lock with a bounded compare-and-swap loop.
fn append_entry(
    args: &NegativeEvidenceAppendArgs,
    before_publish: PublishHook<'_>,
) -> Result<(NegativeEvidenceLedger, NegativeEvidenceEntry, String), NegativeEvidenceError> {
    let entry = build_entry(args)?;
    // Resolve symlinks first: the lock, the temp file, the compare-and-swap read, and the rename
    // all act on the real ledger file, so every alias of a ledger shares one lock and a symlinked
    // path is never replaced by a regular file.
    let real_path = resolve_ledger_path(&args.path)?;
    let real = real_path.to_str().ok_or_else(|| {
        NegativeEvidenceError::Io(format!(
            "resolved ledger path '{}' is not valid UTF-8",
            real_path.display()
        ))
    })?;
    let _lock = LedgerLock::acquire(&real_path)?;
    for _ in 0..MAX_APPEND_ATTEMPTS {
        let (original, checked_ledger) = read_single_link_ledger(&real_path, &args.path)?;
        let mut ledger = NegativeEvidenceLedger::decode_canonical(&original)?;
        ledger.append(entry.clone())?;
        ledger.verify()?;
        let bytes = ledger.encode_canonical()?;
        let mode = WriteMode::Replace {
            expected: ContentDigest::sha256(&original),
        };
        match write_ledger_atomically(
            real,
            &bytes,
            mode,
            before_publish,
            Some((&checked_ledger, &args.path)),
        ) {
            Ok(()) => {
                let root_digest = ContentDigest::sha256(&bytes).to_text();
                return Ok((ledger, entry, root_digest));
            }
            Err(PublishError::Changed) => {}
            Err(PublishError::Failed(err)) => return Err(err),
        }
    }
    Err(NegativeEvidenceError::ConcurrentModification {
        detail: format!(
            "ledger '{}' changed between read and publish on all {MAX_APPEND_ATTEMPTS} attempts; this append wrote nothing",
            args.path
        ),
    })
}

/// Everything one report states; every field is derived from a ledger or a refusal.
struct Report<'a> {
    command: &'static str,
    ledger_path: Option<&'a str>,
    ledger: Option<&'a NegativeEvidenceLedger>,
    root_digest: Option<String>,
    verified: Option<bool>,
    entries: Vec<&'a NegativeEvidenceEntry>,
    appended_id: Option<&'a str>,
    refusal: Option<(&'static str, String)>,
}

fn json_str(value: &str) -> String {
    format!("\"{}\"", escape_json_str(value))
}

fn json_opt(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), json_str)
}

fn render_report(report: &Report<'_>) -> String {
    let (outcome, error_id, detail) = match &report.refusal {
        Some((id, detail)) => ("error", json_str(id), json_str(detail)),
        None => ("ok", "null".to_owned(), "null".to_owned()),
    };
    let mut degradation = vec![UNREGISTERED_OPERATION_NOTE.to_owned()];
    let (entry_count, certified, uncertified, state_counts, epistemic_state) = match report.ledger {
        Some(ledger) => {
            let certified = ledger
                .entries()
                .iter()
                .filter(|e| e.certification == EvidenceCertification::LocallyCertified)
                .count();
            let uncertified = ledger.len() - certified;
            let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
            for entry in ledger.entries() {
                *counts.entry(entry.knowledge_state.as_str()).or_insert(0) += 1;
            }
            if uncertified > 0 {
                degradation.push(format!(
                    "not_locally_certified: {uncertified} of {} entries are not locally certified, so their absence claims carry no coverage guarantee",
                    ledger.len()
                ));
            }
            let epistemic_state = match counts.keys().next() {
                Some(state) if counts.len() == 1 => json_str(state),
                Some(_) => {
                    degradation.push(MIXED_STATES_NOTE.to_owned());
                    "null".to_owned()
                }
                None => "null".to_owned(),
            };
            let counts_json = counts
                .iter()
                .map(|(state, count)| format!("\"{state}\":{count}"))
                .collect::<Vec<_>>()
                .join(",");
            (
                ledger.len().to_string(),
                certified.to_string(),
                uncertified.to_string(),
                format!("{{{counts_json}}}"),
                epistemic_state,
            )
        }
        None => (
            "null".to_owned(),
            "null".to_owned(),
            "null".to_owned(),
            "{}".to_owned(),
            "null".to_owned(),
        ),
    };
    let verified = report
        .verified
        .map_or_else(|| "null".to_owned(), |v| v.to_string());
    let entries = report
        .entries
        .iter()
        .map(|entry| entry.to_json())
        .collect::<Vec<_>>()
        .join(",");
    let degradation = degradation
        .iter()
        .map(|note| json_str(note))
        .collect::<Vec<_>>()
        .join(",");
    let ledger_source = if report.ledger_path.is_some() {
        "file"
    } else {
        "built_in_seed_ledger"
    };
    format!(
        "{{\"schema\":\"{NEGATIVE_EVIDENCE_REPORT_SCHEMA}\",\"producer\":\"fss-cli:{VERSION}\",\"command\":\"{}\",\"outcome\":\"{outcome}\",\"errorId\":{error_id},\"detail\":{detail},\"ledgerSource\":\"{ledger_source}\",\"ledgerPath\":{},\"formatVersion\":{NEGATIVE_EVIDENCE_FORMAT_VERSION},\"entryCount\":{entry_count},\"rootDigest\":{},\"verified\":{verified},\"locallyCertified\":{certified},\"notLocallyCertified\":{uncertified},\"knowledgeStateCounts\":{state_counts},\"epistemicState\":{epistemic_state},\"appendedId\":{},\"entries\":[{entries}],\"degradation\":[{degradation}]}}",
        report.command,
        json_opt(report.ledger_path),
        json_opt(report.root_digest.as_deref()),
        json_opt(report.appended_id),
    )
}

/// Renders a refusal as plain text or as a JSON report; always a runtime failure.
fn refusal_output(
    json: bool,
    command: &'static str,
    ledger_path: Option<&str>,
    verified: Option<bool>,
    err: &NegativeEvidenceError,
    human: String,
) -> (String, ExitIdentity) {
    if json {
        let report = Report {
            command,
            ledger_path,
            ledger: None,
            root_digest: None,
            verified,
            entries: Vec::new(),
            appended_id: None,
            refusal: Some((err.error_id(), err.to_string())),
        };
        (render_report(&report), ExitIdentity::RUNTIME_FAILURE)
    } else {
        (human, ExitIdentity::RUNTIME_FAILURE)
    }
}

fn execute_init(path: &str, json: bool) -> (String, ExitIdentity) {
    match init_ledger(path) {
        Ok((ledger, root_digest)) => {
            if json {
                let report = Report {
                    command: "init",
                    ledger_path: Some(path),
                    ledger: Some(&ledger),
                    root_digest: Some(root_digest),
                    verified: None,
                    entries: Vec::new(),
                    appended_id: None,
                    refusal: None,
                };
                (render_report(&report), ExitIdentity::SUCCESS)
            } else {
                (
                    format!(
                        "Ledger '{path}' initialized with {} seed entries (root digest: {root_digest})",
                        ledger.len()
                    ),
                    ExitIdentity::SUCCESS,
                )
            }
        }
        Err(err) => {
            let human = format!("Init refused [{}]: {err}", err.error_id());
            refusal_output(json, "init", Some(path), None, &err, human)
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
    let loaded = load_ledger(path).and_then(|ledger| {
        let root_digest = ledger.root_digest()?.to_text();
        Ok((ledger, root_digest))
    });
    let (ledger, root_digest) = match loaded {
        Ok(result) => result,
        Err(err) => {
            let human = format!("error[{}]: failed to load ledger: {err}", err.error_id());
            return refusal_output(json, "list", path, None, &err, human);
        }
    };

    if json {
        let report = Report {
            command: "list",
            ledger_path: path,
            ledger: Some(&ledger),
            root_digest: Some(root_digest),
            verified: None,
            entries: ledger.entries().iter().collect(),
            appended_id: None,
            refusal: None,
        };
        (render_report(&report), ExitIdentity::SUCCESS)
    } else {
        let mut out = String::new();
        for entry in ledger.entries() {
            out.push_str(&format!(
                "{} [{}] \"{}\"\n  Revival: \"{}\"\n  Certification: {}\n  Knowledge: {} (finding: {}, decision: {})\n  Witness: {:?} (authorized: {}, observed: {})\n",
                entry.neg_id,
                entry.decision.as_str(),
                entry.hypothesis,
                entry.revival_condition,
                certification_label(entry),
                entry.knowledge_state.as_str(),
                fss_core::negative_evidence::provenance_class_as_str(entry.provenance_class),
                fss_core::negative_evidence::provenance_class_as_str(entry.decision_provenance),
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
            let human = format!("Verification failed [{}]: {err}", err.error_id());
            return refusal_output(json, "verify", path, Some(false), &err, human);
        }
    };

    if json {
        let report = Report {
            command: "verify",
            ledger_path: path,
            ledger: Some(&ledger),
            root_digest: Some(root_digest),
            verified: Some(true),
            entries: Vec::new(),
            appended_id: None,
            refusal: None,
        };
        return (render_report(&report), ExitIdentity::SUCCESS);
    }
    let certified = ledger
        .entries()
        .iter()
        .filter(|e| e.certification == EvidenceCertification::LocallyCertified)
        .count();
    let uncertified = ledger.len() - certified;
    let message = if certified == 0 {
        format!(
            "Ledger verified: {} entries, none locally certified, so no continuous-coverage guarantee is claimed (root digest: {root_digest})",
            ledger.len()
        )
    } else {
        format!(
            "Ledger verified: continuous coverage guarantees intact for all {certified} locally certified entries; {uncertified} entries are not locally certified ({} entries, root digest: {root_digest})",
            ledger.len()
        )
    };
    (message, ExitIdentity::SUCCESS)
}

fn execute_append(args: &NegativeEvidenceAppendArgs) -> (String, ExitIdentity) {
    match append_entry(args, &publish_now) {
        Ok((ledger, entry, root_digest)) => {
            if args.json {
                let report = Report {
                    command: "append",
                    ledger_path: Some(&args.path),
                    ledger: Some(&ledger),
                    root_digest: Some(root_digest),
                    verified: None,
                    entries: vec![&entry],
                    appended_id: Some(&entry.neg_id),
                    refusal: None,
                };
                (render_report(&report), ExitIdentity::SUCCESS)
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
            let human = format!("Append rejected [{}]: {err}", err.error_id());
            refusal_output(args.json, "append", Some(&args.path), None, &err, human)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::error::Error;
    use std::time::{SystemTime, UNIX_EPOCH};

    use fss_core::negative_evidence::negative_predicate_for;

    const DOMAIN: &str = "domain:negative-evidence:cli-unit-test";

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Result<Self, Box<dyn Error>> {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let dir = std::env::temp_dir()
                .join(format!("fss-neg-unit-{tag}-{}-{nanos}", std::process::id()));
            fs::create_dir_all(&dir)?;
            Ok(Self(dir))
        }

        fn ledger(&self) -> Result<String, Box<dyn Error>> {
            Ok(self
                .0
                .join("ledger.bin")
                .to_str()
                .ok_or("non-unicode temp path")?
                .to_owned())
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn args_for(path: &str, id: &str) -> NegativeEvidenceAppendArgs {
        NegativeEvidenceAppendArgs {
            path: path.to_owned(),
            neg_id: id.to_owned(),
            date_commit: "2026-09-13 unit-test".to_owned(),
            decision: NegativeDecision::Reject,
            decision_text: String::new(),
            disposition: HypothesisDisposition::Refuted,
            hypothesis: format!("hypothesis {id}"),
            reasoning: "reasoning".to_owned(),
            measured_result: "measured".to_owned(),
            revival_condition: "revival".to_owned(),
            failure_domains: BTreeSet::from(["vendor-cloud".to_owned()]),
            supersedes: None,
            corpus: None,
            device_model: None,
            firmware: None,
            platform: None,
            policy: None,
            command: None,
            witness: CoverageWitnessArgs {
                claimed_domain: Some(DOMAIN.to_owned()),
                authorized_generation: Some(1),
                observed_domain: Some(DOMAIN.to_owned()),
                observed_generation: Some(1),
                anchor: Some(LedgerAnchor::genesis("site:fss:unit-test")),
                negative_predicate: Some(negative_predicate_for(DOMAIN, id)),
                continuity: Some(CoverageContinuity::Continuous),
                completeness: Some(Completeness::Complete),
                stop_reason: Some(CoverageStopReason::Complete),
            },
            proof_hash: Some(ContentDigest::sha256(b"unit-test-proof")),
            evidence_reference: Some("proof-bundle:unit-test".to_owned()),
            json: false,
        }
    }

    /// Seed ledger plus the listed externally written entries.
    fn ledger_bytes_with(path: &str, ids: &[&str]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut ledger = initial_negative_evidence_ledger()?;
        for id in ids {
            ledger.append(build_entry(&args_for(path, id))?)?;
        }
        Ok(ledger.encode_canonical()?)
    }

    fn sidecars(dir: &Path) -> Result<Vec<String>, Box<dyn Error>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(dir)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                names.push(name);
            }
        }
        Ok(names)
    }

    #[test]
    fn failure_before_publish_leaves_ledger_byte_identical() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new("atomic")?;
        let path = dir.ledger()?;
        let original = ledger_bytes_with(&path, &[])?;
        fs::write(&path, &original)?;
        let replacement = ledger_bytes_with(&path, &["NEG-004"])?;
        let inject = |_: &Path| Err(std::io::Error::other("injected failure before publish"));
        let mode = WriteMode::Replace {
            expected: ContentDigest::sha256(&original),
        };
        let result = write_ledger_atomically(&path, &replacement, mode, &inject, None);
        assert!(matches!(result, Err(PublishError::Failed(_))), "{result:?}");
        assert_eq!(fs::read(&path)?, original, "ledger must be byte-identical");
        assert_eq!(
            sidecars(&dir.0)?,
            Vec::<String>::new(),
            "temp file must be removed"
        );
        Ok(())
    }

    #[test]
    fn create_new_publish_never_clobbers_a_racing_ledger() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new("hardlink")?;
        let path = dir.ledger()?;
        let racer_path = PathBuf::from(&path);
        // A racer creates the target after init's fast-path existence check.
        let race = move |_: &Path| fs::write(&racer_path, b"racing ledger");
        let bytes = ledger_bytes_with(&path, &[])?;
        let result = write_ledger_atomically(&path, &bytes, WriteMode::CreateNew, &race, None);
        match result {
            Err(PublishError::Failed(NegativeEvidenceError::LedgerExists { path: refused })) => {
                assert_eq!(refused, path);
            }
            other => return Err(format!("expected LedgerExists, got {other:?}").into()),
        }
        assert_eq!(fs::read(&path)?, b"racing ledger");
        assert_eq!(sidecars(&dir.0)?, Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn compare_and_swap_retries_and_keeps_concurrent_entries() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new("cas-retry")?;
        let path = dir.ledger()?;
        fs::write(&path, ledger_bytes_with(&path, &[])?)?;
        // A writer bypassing the lock lands NEG-100 between this append's read and publish.
        let foreign = ledger_bytes_with(&path, &["NEG-100"])?;
        let calls = Cell::new(0u32);
        let target = PathBuf::from(&path);
        let intrude = |_: &Path| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                fs::write(&target, &foreign)?;
            }
            Ok(())
        };
        let (ledger, entry, _) = append_entry(&args_for(&path, "NEG-200"), &intrude)?;
        assert_eq!(entry.neg_id, "NEG-200");
        assert_eq!(calls.get(), 2, "one retry after the detected change");
        let on_disk = NegativeEvidenceLedger::decode_canonical(&fs::read(&path)?)?;
        assert_eq!(on_disk, ledger);
        assert!(
            on_disk.contains("NEG-100"),
            "the concurrent entry must survive"
        );
        assert!(on_disk.contains("NEG-200"));
        assert_eq!(sidecars(&dir.0)?, Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn compare_and_swap_gives_up_after_bounded_attempts() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new("cas-bounded")?;
        let path = dir.ledger()?;
        fs::write(&path, ledger_bytes_with(&path, &[])?)?;
        let ids = ["NEG-100", "NEG-101", "NEG-102", "NEG-103"];
        let calls = Cell::new(0usize);
        let target = PathBuf::from(&path);
        let path_for_hook = path.clone();
        let always_intrude = |_: &Path| {
            let n = calls.get() + 1;
            calls.set(n);
            let bytes = ledger_bytes_with(&path_for_hook, &ids[..n.min(ids.len())])
                .map_err(|err| std::io::Error::other(err.to_string()))?;
            fs::write(&target, bytes)
        };
        let result = append_entry(&args_for(&path, "NEG-200"), &always_intrude);
        match result {
            Err(err @ NegativeEvidenceError::ConcurrentModification { .. }) => {
                assert_eq!(err.error_id(), "ERR-NEG-CONCURRENT-MODIFICATION-001");
            }
            other => return Err(format!("expected ConcurrentModification, got {other:?}").into()),
        }
        assert_eq!(calls.get(), MAX_APPEND_ATTEMPTS as usize);
        let on_disk = NegativeEvidenceLedger::decode_canonical(&fs::read(&path)?)?;
        for id in &ids[..MAX_APPEND_ATTEMPTS as usize] {
            assert!(on_disk.contains(id), "concurrent entry {id} must survive");
        }
        assert!(
            !on_disk.contains("NEG-200"),
            "the refused append wrote nothing"
        );
        assert_eq!(sidecars(&dir.0)?, Vec::<String>::new());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn publish_replaces_the_ledger_by_rename_never_in_place() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::MetadataExt;

        let dir = TempDir::new("crash-atomic")?;
        let path = dir.ledger()?;
        let original = ledger_bytes_with(&path, &[])?;
        fs::write(&path, &original)?;
        let original_inode = fs::metadata(&path)?.ino();
        let replacement = ledger_bytes_with(&path, &["NEG-004"])?;
        let temp_inode = Cell::new(0u64);
        let target = PathBuf::from(&path);
        // Crash point: the temp file is written and synced, nothing is published yet. A crash
        // here must leave the original ledger, byte-identical and whole, at the ledger path.
        let at_crash_point = |temp: &Path| {
            if fs::read(&target)? != original {
                return Err(std::io::Error::other(
                    "ledger path modified before publication",
                ));
            }
            if fs::read(temp)? != replacement {
                return Err(std::io::Error::other(
                    "temp file not fully written before publication",
                ));
            }
            temp_inode.set(fs::metadata(temp)?.ino());
            Ok(())
        };
        let mode = WriteMode::Replace {
            expected: ContentDigest::sha256(&original),
        };
        write_ledger_atomically(&path, &replacement, mode, &at_crash_point, None)
            .map_err(|err| format!("{err:?}"))?;
        let published = fs::metadata(&path)?;
        assert_eq!(
            published.ino(),
            temp_inode.get(),
            "the ledger is published by renaming the synced temp file"
        );
        assert_ne!(
            published.ino(),
            original_inode,
            "the ledger file is never rewritten in place"
        );
        assert_eq!(fs::read(&path)?, replacement);
        assert_eq!(sidecars(&dir.0)?, Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn stale_lock_is_refused_and_never_broken() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new("stale-lock")?;
        let path = dir.ledger()?;
        let original = ledger_bytes_with(&path, &[])?;
        fs::write(&path, &original)?;
        let lock = sibling_path(Path::new(&path), ".lock")?;
        fs::write(&lock, b"pid 1\n")?;
        let err = append_entry(&args_for(&path, "NEG-004"), &publish_now)
            .err()
            .ok_or("append must be refused while the lock exists")?;
        assert_eq!(err.error_id(), "ERR-NEG-LEDGER-LOCKED-001");
        assert!(lock.exists(), "a stale lock is never removed automatically");
        assert_eq!(fs::read(&path)?, original);
        Ok(())
    }

    #[test]
    fn lock_is_released_on_success_and_on_refusal() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new("lock-release")?;
        let path = dir.ledger()?;
        fs::write(&path, ledger_bytes_with(&path, &[])?)?;
        let lock = sibling_path(Path::new(&path), ".lock")?;
        // Refused after the lock is taken (duplicate identifier).
        let err = append_entry(&args_for(&path, "NEG-001"), &publish_now)
            .err()
            .ok_or("duplicate must be refused")?;
        assert_eq!(err.error_id(), "ERR-NEG-DUPLICATE-ID-001");
        assert!(!lock.exists(), "lock must be released on refusal");
        append_entry(&args_for(&path, "NEG-004"), &publish_now)?;
        assert!(!lock.exists(), "lock must be released on success");
        Ok(())
    }

    /// fss-pl8u9: a hard link created between the read-side check and the pre-rename re-check
    /// refuses the append with the typed hard-linked error and writes nothing.
    #[test]
    fn hard_link_before_publish_refuses_append_fss_pl8u9() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new("fork-pre")?;
        let path = dir.ledger()?;
        let original = ledger_bytes_with(&path, &[])?;
        fs::write(&path, &original)?;
        let checked = fs::File::open(&path)?;
        let replacement = ledger_bytes_with(&path, &["NEG-004"])?;
        let fork = format!("{path}.fork");
        // The fork exists before publication: the pre-rename re-check refuses it.
        fs::hard_link(Path::new(&path), Path::new(&fork))?;
        let mode = WriteMode::Replace {
            expected: ContentDigest::sha256(&original),
        };
        let result = write_ledger_atomically(
            &path,
            &replacement,
            mode,
            &publish_now,
            Some((&checked, &path)),
        );
        match result {
            Err(PublishError::Failed(NegativeEvidenceError::LedgerHardLinked {
                links, ..
            })) => {
                assert_eq!(links, 2, "the pre-rename re-check must see both names");
            }
            other => return Err(format!("expected LedgerHardLinked, got {other:?}").into()),
        }
        assert_eq!(fs::read(&path)?, original, "the ledger must be untouched");
        Ok(())
    }

    /// fss-pl8u9: a hard link that lands between the pre-rename check and the rename forks the
    /// append; the post-rename re-check reports the typed forked error, never success.
    #[test]
    fn fork_after_rename_is_reported_not_success_fss_pl8u9() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new("fork-post")?;
        let path = dir.ledger()?;
        let original = ledger_bytes_with(&path, &[])?;
        fs::write(&path, &original)?;
        let checked = fs::File::open(&path)?;
        let replacement = ledger_bytes_with(&path, &["NEG-004"])?;
        let fork = format!("{path}.fork");
        let target_for_hook = path.clone();
        let fork_for_hook = fork.clone();
        let inject = move |_: &Path| {
            // Lands after the pre-rename re-check: the rename forks the two names.
            fs::hard_link(&target_for_hook, &fork_for_hook)
        };
        let mode = WriteMode::Replace {
            expected: ContentDigest::sha256(&original),
        };
        let result =
            write_ledger_atomically(&path, &replacement, mode, &inject, Some((&checked, &path)));
        match result {
            Err(PublishError::Failed(NegativeEvidenceError::LedgerForked { path, .. })) => {
                assert!(
                    path.split(", ").all(|name| Path::new(name).exists()),
                    "every reported fork name must exist: {path}"
                );
            }
            other => return Err(format!("expected LedgerForked, got {other:?}").into()),
        }
        // The fork is real: the other name holds the pre-append ledger while the published
        // name holds the new entry. The typed error refuses to paper over it with success.
        assert_eq!(fs::read(&fork)?, original);
        // The published name holds the appended entry (initial seed + NEG-004) while the fork
        // name keeps the pre-append ledger: exactly the silent fork the typed error reports.
        let published = NegativeEvidenceLedger::decode_canonical(&fs::read(&path)?)?;
        assert_eq!(published.len(), 4);
        Ok(())
    }

    /// fss-pl8u9: a temporary path that already exists is refused with its specific typed
    /// error instead of the generic execution failure.
    #[test]
    fn preexisting_temp_name_is_refused_specifically_fss_pl8u9() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new("temp-exists")?;
        let path = dir.ledger()?;
        let temp = sibling_path(Path::new(&path), &format!(".tmp-{}", std::process::id()))?;
        fs::write(&temp, b"pre-existing")?;
        let bytes = ledger_bytes_with(&path, &[])?;
        let result =
            write_ledger_atomically(&path, &bytes, WriteMode::CreateNew, &publish_now, None);
        match result {
            Err(PublishError::Failed(NegativeEvidenceError::LedgerTempExists {
                path: refused,
            })) => {
                assert_eq!(refused, temp.display().to_string());
            }
            other => return Err(format!("expected LedgerTempExists, got {other:?}").into()),
        }
        fs::remove_file(&temp)?;
        Ok(())
    }
}
