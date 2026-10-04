#![forbid(unsafe_code)]
//! Command specification and argument decoding for the `fss-lab` binary.

use std::ffi::OsString;
use std::path::PathBuf;

use fss_core::ContentDigest;

use crate::diagnostic::escape_json_str;
use crate::error::{CliError, ExitIdentity};
use crate::redact::redact_value_or_digest;
use crate::token::{ArgToken, is_option_shaped, tokenize_os_args};

/// Closed registry of recognized laboratory scenario identifiers. `file-activity` (fss-2h5zq.51)
/// is accepted by `run` and `replay`; `matrix`, `list` and `self-test` keep the six mock scenarios.
pub const VALID_SCENARIOS: [&str; 7] = [
    "quiet",
    "raccoon",
    "intrusion",
    "sneaky",
    "lost-ack",
    "corrupt-source",
    "file-activity",
];

/// Typed action requested of the `fss-lab` binary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LabAction {
    /// Print help text.
    Help,
    /// List available scenarios in JSON format.
    List,
    /// Run the scenario matrix and report in JSON format.
    Matrix {
        /// Target root directory.
        root: PathBuf,
    },
    /// Run deterministic self-test and report in JSON format.
    SelfTest {
        /// Target root directory.
        root: PathBuf,
    },
    /// Run a single scenario.
    Run {
        /// Selected scenario identifier.
        scenario: String,
        /// Target root directory.
        root: PathBuf,
    },
    /// Inject one in-process fault per registered fault point and report recovery
    /// (`fss.lab.crash_matrix.v1`).
    CrashMatrix {
        /// Target root directory; every fault point gets a sub-root under it.
        root: PathBuf,
        /// Scenario the matrix runs (only `intrusion` has an expected-class table).
        scenario: String,
        /// Emit the JSON document instead of the human table.
        json: bool,
    },
    /// Apply explicit operator recovery actions to a deployment root
    /// (`fss.lab.recover_report.v1`, fss-2h5zq.15).
    Recover {
        /// Deployment root to recover.
        root: PathBuf,
        /// The explicit actions requested; never empty.
        request: RecoverRequest,
        /// Emit the JSON report instead of the human summary.
        json: bool,
    },
    /// Replay a scenario N times to prove determinism.
    Replay {
        /// Selected scenario identifier.
        scenario: String,
        /// Repeat count (bounds: 2 <= repeat <= 10_000).
        repeat: usize,
        /// Target root directory.
        root: PathBuf,
    },
}

/// Returns the static help text for `fss-lab`.
#[must_use]
pub const fn help_text() -> &'static str {
    "fss-lab — deterministic reference surveillance laboratory\n\n\
USAGE\n  fss-lab list\n  fss-lab run <scenario> --root <dir>\n  fss-lab matrix --root <dir>\n  fss-lab replay <scenario> --root <dir> [--repeat N]\n  fss-lab self-test --root <dir>\n  fss-lab crash-matrix --root <dir> [--scenario intrusion] [--json]\n  fss-lab recover --root <dir> <action>... [--json]\n\n\
SCENARIOS\n  quiet           complete coverage and a certified absence\n  raccoon         benign wildlife with no alert effect\n  intrusion       independently corroborated person and verified alert\n  sneaky          material person residual plus an observability gap\n  lost-ack        indeterminate alert dispatch resolved by reconciliation\n  corrupt-source  source corruption detected before evidence publication\n  file-activity   recorded JPEG frames scored by the real scalar executor (run/replay only)\n\n\
CRASH MATRIX\n  Injects one in-process fault per publish cut point, ledger cut point, journal append phase,\n  lost alert acknowledgement and cancellation stage, reopens each sub-root, and compares the\n  recovery class with the documented one. Exit 0 when the verdict is pass, 1 otherwise.\n  In-process injection is not process death or power loss.\n\n\
RECOVER\n  Explicit operator recovery of a deployment root; every action is named, nothing is implicit:\n    --truncate-incomplete-tail ledger|effects   drop an incomplete journal tail\n    --plan-ledger-repair | --plan-effects-repair  print the sealed foreign-byte repair plan and\n                                                its digest; read-only, changes nothing\n    --apply-ledger-repair <digest>              apply only the plan with exactly this digest\n    --apply-effects-repair <digest>\n    --discard-orphaned-temps                    remove root temps an interrupted publish left\n    --discard-orphaned-staging                  refused: no supporting publication API yet\n    --reconcile-effects                         resolve indeterminate alerts only from the lab's\n                                                durable simulated provider record; never retries\n  Mutating actions hold <root>/objects/LOCK and run in a fixed order: ledger bytes, effect\n  bytes, a reopen check, orphan discards, effect reconciliation. Refusals exit 6 with\n  ERR-LAB-RECOVER-* identities (root locked, nothing to do, plan mismatch, corrupt history,\n  action unsupported). The simulated provider is not a real vendor.\n"
}

/// Scenarios the crash matrix has an expected-class table for.
pub const CRASH_MATRIX_SCENARIOS: [&str; 1] = ["intrusion"];

/// Parses OS-native arguments for `fss-lab` with total validation and exact grammar exhaustion.
pub fn parse_lab_args<I>(args: I) -> Result<LabAction, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let tokens = tokenize_os_args(args)?;
    parse_lab_tokens(&tokens)
}

/// Validates and parses a slice of pre-tokenized arguments for `fss-lab`.
pub fn parse_lab_tokens(tokens: &[ArgToken]) -> Result<LabAction, CliError> {
    if tokens.is_empty() {
        return Ok(LabAction::Help);
    }

    let first = &tokens[0];
    match first.as_str() {
        "help" | "--help" | "-h" => {
            if tokens.len() > 1 {
                return Err(CliError::TrailingArgument {
                    argument: tokens[1].raw.clone(),
                    index: tokens[1].index,
                    command: Some(first.raw.clone()),
                });
            }
            Ok(LabAction::Help)
        }
        "list" => {
            if tokens.len() > 1 {
                return Err(CliError::TrailingArgument {
                    argument: tokens[1].raw.clone(),
                    index: tokens[1].index,
                    command: Some("list".to_owned()),
                });
            }
            Ok(LabAction::List)
        }
        "matrix" => parse_matrix_command(tokens),
        "self-test" => parse_self_test_command(tokens),
        "run" => parse_run_command(tokens),
        "replay" => parse_replay_command(tokens),
        "crash-matrix" => parse_crash_matrix_command(tokens),
        "recover" => parse_recover_command(tokens),
        unknown => {
            if unknown.starts_with('-') {
                Err(CliError::UnknownOption {
                    option: unknown.to_owned(),
                    command: None,
                    index: first.index,
                })
            } else {
                Err(CliError::UnknownCommand {
                    command: unknown.to_owned(),
                    context: None,
                    index: first.index,
                })
            }
        }
    }
}

fn parse_matrix_command(tokens: &[ArgToken]) -> Result<LabAction, CliError> {
    let mut root: Option<PathBuf> = None;
    let mut idx = 1;

    while idx < tokens.len() {
        let tok = &tokens[idx];
        let s = tok.as_str();

        if s == "--root" {
            if root.is_some() {
                return Err(CliError::DuplicateOption {
                    option: "--root".to_owned(),
                    command: Some("matrix".to_owned()),
                    index: tok.index,
                });
            }
            if idx + 1 >= tokens.len() {
                return Err(CliError::MissingValue {
                    option: "--root".to_owned(),
                    command: Some("matrix".to_owned()),
                    expected: "directory path".to_owned(),
                });
            }
            let val_tok = &tokens[idx + 1];
            if is_option_shaped(val_tok.as_str()) {
                return Err(CliError::MissingValue {
                    option: "--root".to_owned(),
                    command: Some("matrix".to_owned()),
                    expected: "directory path".to_owned(),
                });
            }
            root = Some(parse_root_value(
                &val_tok.raw,
                val_tok.index,
                Some("matrix"),
            )?);
            idx += 2;
        } else if let Some(val_str) = s.strip_prefix("--root=") {
            if root.is_some() {
                return Err(CliError::DuplicateOption {
                    option: "--root".to_owned(),
                    command: Some("matrix".to_owned()),
                    index: tok.index,
                });
            }
            root = Some(parse_root_value(val_str, tok.index, Some("matrix"))?);
            idx += 1;
        } else if s.starts_with('-') {
            return Err(CliError::UnknownOption {
                option: s.to_owned(),
                command: Some("matrix".to_owned()),
                index: tok.index,
            });
        } else {
            return Err(CliError::TrailingArgument {
                argument: s.to_owned(),
                index: tok.index,
                command: Some("matrix".to_owned()),
            });
        }
    }

    match root {
        Some(r) => Ok(LabAction::Matrix { root: r }),
        None => Err(CliError::MissingValue {
            option: "--root".to_owned(),
            command: Some("matrix".to_owned()),
            expected: "directory path".to_owned(),
        }),
    }
}

fn parse_self_test_command(tokens: &[ArgToken]) -> Result<LabAction, CliError> {
    let mut root: Option<PathBuf> = None;
    let mut idx = 1;

    while idx < tokens.len() {
        let tok = &tokens[idx];
        let s = tok.as_str();

        if s == "--root" {
            if root.is_some() {
                return Err(CliError::DuplicateOption {
                    option: "--root".to_owned(),
                    command: Some("self-test".to_owned()),
                    index: tok.index,
                });
            }
            if idx + 1 >= tokens.len() {
                return Err(CliError::MissingValue {
                    option: "--root".to_owned(),
                    command: Some("self-test".to_owned()),
                    expected: "directory path".to_owned(),
                });
            }
            let val_tok = &tokens[idx + 1];
            if is_option_shaped(val_tok.as_str()) {
                return Err(CliError::MissingValue {
                    option: "--root".to_owned(),
                    command: Some("self-test".to_owned()),
                    expected: "directory path".to_owned(),
                });
            }
            root = Some(parse_root_value(
                &val_tok.raw,
                val_tok.index,
                Some("self-test"),
            )?);
            idx += 2;
        } else if let Some(val_str) = s.strip_prefix("--root=") {
            if root.is_some() {
                return Err(CliError::DuplicateOption {
                    option: "--root".to_owned(),
                    command: Some("self-test".to_owned()),
                    index: tok.index,
                });
            }
            root = Some(parse_root_value(val_str, tok.index, Some("self-test"))?);
            idx += 1;
        } else if s.starts_with('-') {
            return Err(CliError::UnknownOption {
                option: s.to_owned(),
                command: Some("self-test".to_owned()),
                index: tok.index,
            });
        } else {
            return Err(CliError::TrailingArgument {
                argument: s.to_owned(),
                index: tok.index,
                command: Some("self-test".to_owned()),
            });
        }
    }

    match root {
        Some(r) => Ok(LabAction::SelfTest { root: r }),
        None => Err(CliError::MissingValue {
            option: "--root".to_owned(),
            command: Some("self-test".to_owned()),
            expected: "directory path".to_owned(),
        }),
    }
}

fn parse_run_command(tokens: &[ArgToken]) -> Result<LabAction, CliError> {
    if tokens.len() == 1 {
        return Err(CliError::MissingValue {
            option: "<scenario>".to_owned(),
            command: Some("run".to_owned()),
            expected:
                "one of: quiet, raccoon, intrusion, sneaky, lost-ack, corrupt-source, file-activity"
                    .to_owned(),
        });
    }

    let mut scenario: Option<String> = None;
    let mut root: Option<PathBuf> = None;
    let mut idx = 1;

    while idx < tokens.len() {
        let tok = &tokens[idx];
        let s = tok.as_str();

        if s == "--root" {
            if root.is_some() {
                return Err(CliError::DuplicateOption {
                    option: "--root".to_owned(),
                    command: Some("run".to_owned()),
                    index: tok.index,
                });
            }
            if idx + 1 >= tokens.len() {
                return Err(CliError::MissingValue {
                    option: "--root".to_owned(),
                    command: Some("run".to_owned()),
                    expected: "directory path".to_owned(),
                });
            }
            let val_tok = &tokens[idx + 1];
            if is_option_shaped(val_tok.as_str()) {
                return Err(CliError::MissingValue {
                    option: "--root".to_owned(),
                    command: Some("run".to_owned()),
                    expected: "directory path".to_owned(),
                });
            }
            root = Some(parse_root_value(&val_tok.raw, val_tok.index, Some("run"))?);
            idx += 2;
        } else if let Some(val_str) = s.strip_prefix("--root=") {
            if root.is_some() {
                return Err(CliError::DuplicateOption {
                    option: "--root".to_owned(),
                    command: Some("run".to_owned()),
                    index: tok.index,
                });
            }
            root = Some(parse_root_value(val_str, tok.index, Some("run"))?);
            idx += 1;
        } else if s.starts_with('-') {
            return Err(CliError::UnknownOption {
                option: s.to_owned(),
                command: Some("run".to_owned()),
                index: tok.index,
            });
        } else {
            if scenario.is_some() {
                return Err(CliError::TrailingArgument {
                    argument: s.to_owned(),
                    index: tok.index,
                    command: Some("run".to_owned()),
                });
            }
            validate_scenario(&tok.raw, tok.index, "run")?;
            scenario = Some(tok.raw.clone());
            idx += 1;
        }
    }

    let scenario = match scenario {
        Some(sc) => sc,
        None => {
            return Err(CliError::MissingValue {
                option: "<scenario>".to_owned(),
                command: Some("run".to_owned()),
                expected: "one of: quiet, raccoon, intrusion, sneaky, lost-ack, corrupt-source, file-activity"
                    .to_owned(),
            });
        }
    };

    let root = match root {
        Some(r) => r,
        None => {
            return Err(CliError::MissingValue {
                option: "--root".to_owned(),
                command: Some("run".to_owned()),
                expected: "directory path".to_owned(),
            });
        }
    };

    Ok(LabAction::Run { scenario, root })
}

fn parse_replay_command(tokens: &[ArgToken]) -> Result<LabAction, CliError> {
    if tokens.len() == 1 {
        return Err(CliError::MissingValue {
            option: "<scenario>".to_owned(),
            command: Some("replay".to_owned()),
            expected:
                "one of: quiet, raccoon, intrusion, sneaky, lost-ack, corrupt-source, file-activity"
                    .to_owned(),
        });
    }

    let mut scenario: Option<String> = None;
    let mut root: Option<PathBuf> = None;
    let mut repeat: usize = 2;
    let mut seen_repeat = false;
    let mut idx = 1;

    while idx < tokens.len() {
        let tok = &tokens[idx];
        let s = tok.as_str();

        if s == "--repeat" {
            if seen_repeat {
                return Err(CliError::DuplicateOption {
                    option: "--repeat".to_owned(),
                    command: Some("replay".to_owned()),
                    index: tok.index,
                });
            }
            seen_repeat = true;
            if idx + 1 >= tokens.len() {
                return Err(CliError::MissingValue {
                    option: "--repeat".to_owned(),
                    command: Some("replay".to_owned()),
                    expected: "positive integer between 2 and 10000".to_owned(),
                });
            }
            let val_tok = &tokens[idx + 1];
            if is_option_shaped(val_tok.as_str()) {
                return Err(CliError::MissingValue {
                    option: "--repeat".to_owned(),
                    command: Some("replay".to_owned()),
                    expected: "positive integer between 2 and 10000".to_owned(),
                });
            }
            repeat = parse_repeat_value(&val_tok.raw, val_tok.index, Some("replay"))?;
            idx += 2;
        } else if let Some(val_str) = s.strip_prefix("--repeat=") {
            if seen_repeat {
                return Err(CliError::DuplicateOption {
                    option: "--repeat".to_owned(),
                    command: Some("replay".to_owned()),
                    index: tok.index,
                });
            }
            seen_repeat = true;
            repeat = parse_repeat_value(val_str, tok.index, Some("replay"))?;
            idx += 1;
        } else if s == "--root" {
            if root.is_some() {
                return Err(CliError::DuplicateOption {
                    option: "--root".to_owned(),
                    command: Some("replay".to_owned()),
                    index: tok.index,
                });
            }
            if idx + 1 >= tokens.len() {
                return Err(CliError::MissingValue {
                    option: "--root".to_owned(),
                    command: Some("replay".to_owned()),
                    expected: "directory path".to_owned(),
                });
            }
            let val_tok = &tokens[idx + 1];
            if is_option_shaped(val_tok.as_str()) {
                return Err(CliError::MissingValue {
                    option: "--root".to_owned(),
                    command: Some("replay".to_owned()),
                    expected: "directory path".to_owned(),
                });
            }
            root = Some(parse_root_value(
                &val_tok.raw,
                val_tok.index,
                Some("replay"),
            )?);
            idx += 2;
        } else if let Some(val_str) = s.strip_prefix("--root=") {
            if root.is_some() {
                return Err(CliError::DuplicateOption {
                    option: "--root".to_owned(),
                    command: Some("replay".to_owned()),
                    index: tok.index,
                });
            }
            root = Some(parse_root_value(val_str, tok.index, Some("replay"))?);
            idx += 1;
        } else if s.starts_with('-') {
            return Err(CliError::UnknownOption {
                option: s.to_owned(),
                command: Some("replay".to_owned()),
                index: tok.index,
            });
        } else {
            if scenario.is_some() {
                return Err(CliError::TrailingArgument {
                    argument: s.to_owned(),
                    index: tok.index,
                    command: Some("replay".to_owned()),
                });
            }
            validate_scenario(&tok.raw, tok.index, "replay")?;
            scenario = Some(tok.raw.clone());
            idx += 1;
        }
    }

    let scenario = match scenario {
        Some(sc) => sc,
        None => {
            return Err(CliError::MissingValue {
                option: "<scenario>".to_owned(),
                command: Some("replay".to_owned()),
                expected: "one of: quiet, raccoon, intrusion, sneaky, lost-ack, corrupt-source, file-activity"
                    .to_owned(),
            });
        }
    };

    let root = match root {
        Some(r) => r,
        None => {
            return Err(CliError::MissingValue {
                option: "--root".to_owned(),
                command: Some("replay".to_owned()),
                expected: "directory path".to_owned(),
            });
        }
    };

    Ok(LabAction::Replay {
        scenario,
        repeat,
        root,
    })
}

fn parse_crash_matrix_command(tokens: &[ArgToken]) -> Result<LabAction, CliError> {
    const COMMAND: &str = "crash-matrix";
    let mut root: Option<PathBuf> = None;
    let mut scenario: Option<String> = None;
    let mut json = false;
    let mut idx = 1;

    while idx < tokens.len() {
        let tok = &tokens[idx];
        let s = tok.as_str();
        let duplicate = |option: &str| CliError::DuplicateOption {
            option: option.to_owned(),
            command: Some(COMMAND.to_owned()),
            index: tok.index,
        };
        if s == "--json" {
            if json {
                return Err(duplicate("--json"));
            }
            json = true;
            idx += 1;
        } else if s == "--root" || s == "--scenario" {
            if (s == "--root" && root.is_some()) || (s == "--scenario" && scenario.is_some()) {
                return Err(duplicate(s));
            }
            let missing = || CliError::MissingValue {
                option: s.to_owned(),
                command: Some(COMMAND.to_owned()),
                expected: if s == "--root" {
                    "directory path".to_owned()
                } else {
                    format!("one of: {}", CRASH_MATRIX_SCENARIOS.join(", "))
                },
            };
            let val_tok = tokens.get(idx + 1).ok_or_else(missing)?;
            if is_option_shaped(val_tok.as_str()) {
                return Err(missing());
            }
            if s == "--root" {
                root = Some(parse_root_value(
                    &val_tok.raw,
                    val_tok.index,
                    Some(COMMAND),
                )?);
            } else {
                validate_crash_matrix_scenario(&val_tok.raw, val_tok.index)?;
                scenario = Some(val_tok.raw.clone());
            }
            idx += 2;
        } else if let Some(val_str) = s.strip_prefix("--root=") {
            if root.is_some() {
                return Err(duplicate("--root"));
            }
            root = Some(parse_root_value(val_str, tok.index, Some(COMMAND))?);
            idx += 1;
        } else if let Some(val_str) = s.strip_prefix("--scenario=") {
            if scenario.is_some() {
                return Err(duplicate("--scenario"));
            }
            validate_crash_matrix_scenario(val_str, tok.index)?;
            scenario = Some(val_str.to_owned());
            idx += 1;
        } else if s.starts_with('-') {
            return Err(CliError::UnknownOption {
                option: s.to_owned(),
                command: Some(COMMAND.to_owned()),
                index: tok.index,
            });
        } else {
            return Err(CliError::TrailingArgument {
                argument: s.to_owned(),
                index: tok.index,
                command: Some(COMMAND.to_owned()),
            });
        }
    }

    let root = root.ok_or_else(|| CliError::MissingValue {
        option: "--root".to_owned(),
        command: Some(COMMAND.to_owned()),
        expected: "directory path".to_owned(),
    })?;
    Ok(LabAction::CrashMatrix {
        root,
        scenario: scenario.unwrap_or_else(|| "intrusion".to_owned()),
        json,
    })
}

/// Journal an explicit `fss-lab recover` byte action targets.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RecoverJournal {
    /// The authority ledger journal (`ledger/journal.fssj`).
    Ledger,
    /// The durable effect journal (`effects/journal.fssj`).
    Effects,
}

impl RecoverJournal {
    /// Stable spelling, as the doctor's affordance targets name it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ledger => "ledger",
            Self::Effects => "effects",
        }
    }
}

/// The explicit actions one `fss-lab recover` invocation requests (fss-2h5zq.15).
///
/// Nothing is implied: an action runs only when it is named here. The binary runs the mutating
/// actions in one fixed order (ledger bytes, effect bytes, a reopen check, orphan discards,
/// effect reconciliation), whatever order the flags were given in.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecoverRequest {
    /// `--truncate-incomplete-tail <journal>`.
    pub truncate_incomplete_tail: Option<RecoverJournal>,
    /// `--plan-ledger-repair` or `--plan-effects-repair`: read-only, exclusive with every other
    /// action.
    pub plan_repair: Option<RecoverJournal>,
    /// `--apply-ledger-repair <digest>`.
    pub apply_ledger_repair: Option<ContentDigest>,
    /// `--apply-effects-repair <digest>`.
    pub apply_effects_repair: Option<ContentDigest>,
    /// `--discard-orphaned-temps`.
    pub discard_orphaned_temps: bool,
    /// `--discard-orphaned-staging`.
    pub discard_orphaned_staging: bool,
    /// `--reconcile-effects`.
    pub reconcile_effects: bool,
}

impl RecoverRequest {
    /// Whether no action is requested.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// Whether any action other than a read-only plan is requested.
    #[must_use]
    pub const fn mutates(&self) -> bool {
        self.truncate_incomplete_tail.is_some()
            || self.apply_ledger_repair.is_some()
            || self.apply_effects_repair.is_some()
            || self.discard_orphaned_temps
            || self.discard_orphaned_staging
            || self.reconcile_effects
    }

    /// The requested actions spelled as `fss-lab recover` flags, in the fixed execution order.
    #[must_use]
    pub fn flags(&self) -> Vec<String> {
        let mut flags = Vec::new();
        if let Some(journal) = self.plan_repair {
            flags.push(format!("--plan-{}-repair", journal.as_str()));
        }
        if self.truncate_incomplete_tail == Some(RecoverJournal::Ledger) {
            flags.push("--truncate-incomplete-tail ledger".to_owned());
        }
        if let Some(digest) = self.apply_ledger_repair {
            flags.push(format!("--apply-ledger-repair {digest}"));
        }
        if self.truncate_incomplete_tail == Some(RecoverJournal::Effects) {
            flags.push("--truncate-incomplete-tail effects".to_owned());
        }
        if let Some(digest) = self.apply_effects_repair {
            flags.push(format!("--apply-effects-repair {digest}"));
        }
        if self.discard_orphaned_temps {
            flags.push("--discard-orphaned-temps".to_owned());
        }
        if self.discard_orphaned_staging {
            flags.push("--discard-orphaned-staging".to_owned());
        }
        if self.reconcile_effects {
            flags.push("--reconcile-effects".to_owned());
        }
        flags
    }
}

/// Execution-phase `fss.cli_diagnostic.v1` line for a refused `fss-lab recover` action.
///
/// The exit identity is always [`ExitIdentity::LAB_RECOVER_REFUSED`]; `error_id` (one of the
/// `ERR-LAB-RECOVER-*` identities) says why. Only `recover_root_locked` is retryable unchanged,
/// after the lock holder exits.
#[must_use]
pub fn lab_recover_diagnostic(error_id: &str, root: &std::path::Path) -> String {
    let exit = ExitIdentity::LAB_RECOVER_REFUSED;
    let retryable = error_id == crate::error::ERR_LAB_RECOVER_ROOT_LOCKED;
    let recovery_class = if retryable {
        "backoff"
    } else {
        "operator_action_required"
    };
    let input = redact_value_or_digest(&root.to_string_lossy());
    format!(
        "{{\"schema\":\"fss.cli_diagnostic.v1\",\"phase\":\"execution\",\"binary\":\"fss-lab\",\"command\":\"recover\",\"argument_index\":null,\"redacted_input\":\"{}\",\"error_id\":\"{}\",\"exit_id\":\"{}\",\"exit_code\":{},\"contract_basis\":\"fss/1\",\"effect_started\":false,\"retryable\":{retryable},\"recovery_class\":\"{recovery_class}\",\"correlation_id\":\"corr-fss-lab-{}\",\"proof_handle\":\"fss://proof/cli/recover-refusal\"}}",
        escape_json_str(&input),
        escape_json_str(error_id),
        exit.identifier,
        exit.code,
        escape_json_str(error_id),
    )
}

const RECOVER_ACTIONS: &str = "--truncate-incomplete-tail, --plan-ledger-repair, --plan-effects-repair, --apply-ledger-repair, --apply-effects-repair, --discard-orphaned-temps, --discard-orphaned-staging or --reconcile-effects";

/// One recover flag after `--name=value` splitting; `value` is `(text, argument index)`.
fn recover_value<'a>(
    tokens: &'a [ArgToken],
    idx: &mut usize,
    name: &str,
    inline: Option<&'a str>,
) -> Result<(&'a str, usize), CliError> {
    let expected = match name {
        "--root" => "directory path",
        "--truncate-incomplete-tail" => "one of: ledger, effects",
        _ => "repair plan digest (sha256:<64 lowercase hex>)",
    };
    let missing = || CliError::MissingValue {
        option: name.to_owned(),
        command: Some("recover".to_owned()),
        expected: expected.to_owned(),
    };
    let tok = &tokens[*idx];
    if let Some(value) = inline {
        return Ok((value, tok.index));
    }
    let val_tok = tokens.get(*idx + 1).ok_or_else(missing)?;
    if is_option_shaped(val_tok.as_str()) {
        return Err(missing());
    }
    *idx += 1;
    Ok((val_tok.raw.as_str(), val_tok.index))
}

fn parse_recover_command(tokens: &[ArgToken]) -> Result<LabAction, CliError> {
    const COMMAND: &str = "recover";
    let mut root: Option<PathBuf> = None;
    let mut json = false;
    let mut request = RecoverRequest::default();
    let mut idx = 1;

    while idx < tokens.len() {
        let tok = &tokens[idx];
        let raw = tok.as_str();
        let duplicate = |option: &str| CliError::DuplicateOption {
            option: option.to_owned(),
            command: Some(COMMAND.to_owned()),
            index: tok.index,
        };
        let (name, inline) = match raw.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value)),
            _ => (raw, None),
        };
        match name {
            "--root" => {
                let (value, index) = recover_value(tokens, &mut idx, name, inline)?;
                if root.is_some() {
                    return Err(duplicate(name));
                }
                root = Some(parse_root_value(value, index, Some(COMMAND))?);
            }
            "--truncate-incomplete-tail" => {
                let (value, index) = recover_value(tokens, &mut idx, name, inline)?;
                if request.truncate_incomplete_tail.is_some() {
                    return Err(duplicate(name));
                }
                request.truncate_incomplete_tail = Some(match value {
                    "ledger" => RecoverJournal::Ledger,
                    "effects" => RecoverJournal::Effects,
                    _ => {
                        return Err(CliError::MalformedValue {
                            option: name.to_owned(),
                            value: value.to_owned(),
                            reason: "expected one of: ledger, effects".to_owned(),
                            command: Some(COMMAND.to_owned()),
                            index,
                        });
                    }
                });
            }
            "--apply-ledger-repair" | "--apply-effects-repair" => {
                let (value, index) = recover_value(tokens, &mut idx, name, inline)?;
                let digest =
                    value
                        .parse::<ContentDigest>()
                        .map_err(|_| CliError::MalformedValue {
                            option: name.to_owned(),
                            value: value.to_owned(),
                            reason: "expected a repair plan digest sha256:<64 lowercase hex>"
                                .to_owned(),
                            command: Some(COMMAND.to_owned()),
                            index,
                        })?;
                let slot = if name == "--apply-ledger-repair" {
                    &mut request.apply_ledger_repair
                } else {
                    &mut request.apply_effects_repair
                };
                if slot.is_some() {
                    return Err(duplicate(name));
                }
                *slot = Some(digest);
            }
            "--plan-ledger-repair"
            | "--plan-effects-repair"
            | "--discard-orphaned-temps"
            | "--discard-orphaned-staging"
            | "--reconcile-effects"
            | "--json" => {
                if inline.is_some() {
                    return Err(CliError::MalformedValue {
                        option: name.to_owned(),
                        value: raw.to_owned(),
                        reason: format!("{name} takes no value"),
                        command: Some(COMMAND.to_owned()),
                        index: tok.index,
                    });
                }
                let already = match name {
                    "--plan-ledger-repair" | "--plan-effects-repair" => {
                        let seen = request.plan_repair.is_some();
                        request.plan_repair = Some(if name == "--plan-ledger-repair" {
                            RecoverJournal::Ledger
                        } else {
                            RecoverJournal::Effects
                        });
                        seen
                    }
                    "--discard-orphaned-temps" => {
                        std::mem::replace(&mut request.discard_orphaned_temps, true)
                    }
                    "--discard-orphaned-staging" => {
                        std::mem::replace(&mut request.discard_orphaned_staging, true)
                    }
                    "--reconcile-effects" => {
                        std::mem::replace(&mut request.reconcile_effects, true)
                    }
                    _ => std::mem::replace(&mut json, true),
                };
                if already {
                    return Err(duplicate(name));
                }
            }
            _ if raw.starts_with('-') => {
                return Err(CliError::UnknownOption {
                    option: raw.to_owned(),
                    command: Some(COMMAND.to_owned()),
                    index: tok.index,
                });
            }
            _ => {
                return Err(CliError::TrailingArgument {
                    argument: raw.to_owned(),
                    index: tok.index,
                    command: Some(COMMAND.to_owned()),
                });
            }
        }
        idx += 1;
    }

    let root = root.ok_or_else(|| CliError::MissingValue {
        option: "--root".to_owned(),
        command: Some(COMMAND.to_owned()),
        expected: "directory path".to_owned(),
    })?;
    if request.is_empty() {
        return Err(CliError::MissingValue {
            option: "<action>".to_owned(),
            command: Some(COMMAND.to_owned()),
            expected: format!("at least one explicit action: {RECOVER_ACTIONS}"),
        });
    }
    if request.plan_repair.is_some() && request.mutates() {
        // A plan is read-only and is reviewed before its digest is applied: planning and any
        // mutating action never run in one invocation.
        return Err(CliError::DuplicateOption {
            option: "--plan-*-repair with a mutating action".to_owned(),
            command: Some(COMMAND.to_owned()),
            index: tokens.last().map_or(0, |tok| tok.index),
        });
    }
    Ok(LabAction::Recover {
        root,
        request,
        json,
    })
}

fn validate_crash_matrix_scenario(name: &str, index: usize) -> Result<(), CliError> {
    if CRASH_MATRIX_SCENARIOS.contains(&name) {
        Ok(())
    } else {
        Err(CliError::MalformedValue {
            option: "--scenario".to_owned(),
            value: name.to_owned(),
            reason: format!(
                "the crash matrix has an expected-class table only for: {}",
                CRASH_MATRIX_SCENARIOS.join(", ")
            ),
            command: Some("crash-matrix".to_owned()),
            index,
        })
    }
}

fn parse_root_value(val: &str, index: usize, command: Option<&str>) -> Result<PathBuf, CliError> {
    if val.is_empty() {
        return Err(CliError::MalformedValue {
            option: "--root".to_owned(),
            value: val.to_owned(),
            reason: "--root requires a non-empty directory path".to_owned(),
            command: command.map(ToOwned::to_owned),
            index,
        });
    }
    Ok(PathBuf::from(val))
}

fn parse_repeat_value(val: &str, index: usize, command: Option<&str>) -> Result<usize, CliError> {
    let parsed = val.parse::<usize>().map_err(|_| CliError::MalformedValue {
        option: "--repeat".to_owned(),
        value: val.to_owned(),
        reason: "--repeat requires a positive integer".to_owned(),
        command: command.map(ToOwned::to_owned),
        index,
    })?;

    if parsed < 2 {
        return Err(CliError::MalformedValue {
            option: "--repeat".to_owned(),
            value: val.to_owned(),
            reason: "replay requires --repeat >= 2".to_owned(),
            command: command.map(ToOwned::to_owned),
            index,
        });
    }
    if parsed > 10_000 {
        return Err(CliError::MalformedValue {
            option: "--repeat".to_owned(),
            value: val.to_owned(),
            reason: "replay repeat count exceeds the 10000-run bound".to_owned(),
            command: command.map(ToOwned::to_owned),
            index,
        });
    }

    Ok(parsed)
}

fn validate_scenario(name: &str, index: usize, command: &str) -> Result<(), CliError> {
    if VALID_SCENARIOS.contains(&name) {
        Ok(())
    } else {
        Err(CliError::MalformedValue {
            option: "<scenario>".to_owned(),
            value: name.to_owned(),
            reason: format!(
                "unknown scenario; expected one of: {}",
                VALID_SCENARIOS.join(", ")
            ),
            command: Some(command.to_owned()),
            index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_lab_commands_parse_successfully() {
        assert_eq!(parse_lab_args([]).ok(), Some(LabAction::Help));
        assert_eq!(
            parse_lab_args([OsString::from("list")]).ok(),
            Some(LabAction::List)
        );
        assert_eq!(
            parse_lab_args([
                OsString::from("matrix"),
                OsString::from("--root"),
                OsString::from("/tmp/matrix-root")
            ])
            .ok(),
            Some(LabAction::Matrix {
                root: PathBuf::from("/tmp/matrix-root")
            })
        );
        assert_eq!(
            parse_lab_args([
                OsString::from("self-test"),
                OsString::from("--root"),
                OsString::from("/tmp/st-root")
            ])
            .ok(),
            Some(LabAction::SelfTest {
                root: PathBuf::from("/tmp/st-root")
            })
        );
        assert_eq!(
            parse_lab_args([
                OsString::from("run"),
                OsString::from("quiet"),
                OsString::from("--root"),
                OsString::from("/tmp/run-root")
            ])
            .ok(),
            Some(LabAction::Run {
                scenario: "quiet".to_owned(),
                root: PathBuf::from("/tmp/run-root")
            })
        );
        assert_eq!(
            parse_lab_args([
                OsString::from("replay"),
                OsString::from("intrusion"),
                OsString::from("--root"),
                OsString::from("/tmp/replay-root")
            ])
            .ok(),
            Some(LabAction::Replay {
                scenario: "intrusion".to_owned(),
                repeat: 2,
                root: PathBuf::from("/tmp/replay-root")
            })
        );
        assert_eq!(
            parse_lab_args([
                OsString::from("replay"),
                OsString::from("intrusion"),
                OsString::from("--repeat"),
                OsString::from("5"),
                OsString::from("--root"),
                OsString::from("/tmp/replay-root")
            ])
            .ok(),
            Some(LabAction::Replay {
                scenario: "intrusion".to_owned(),
                repeat: 5,
                root: PathBuf::from("/tmp/replay-root")
            })
        );
    }

    #[test]
    fn trailing_arguments_are_rejected() {
        let cases = [
            vec!["list", "extra"],
            vec!["matrix", "--root", "/tmp/r", "extra"],
            vec!["self-test", "--root", "/tmp/r", "extra"],
            vec!["run", "quiet", "--root", "/tmp/r", "extra"],
            vec![
                "replay", "quiet", "--repeat", "2", "--root", "/tmp/r", "extra",
            ],
        ];
        for case in cases {
            let args: Vec<OsString> = case.into_iter().map(OsString::from).collect();
            let result = parse_lab_args(args);
            assert!(result.is_err());
            if let Err(err) = result {
                assert_eq!(err.error_id(), crate::error::ERR_CLI_TRAILING_ARGUMENT);
            }
        }
    }

    #[test]
    fn missing_root_is_rejected() {
        for cmd in ["matrix", "self-test"] {
            let result = parse_lab_args([OsString::from(cmd)]);
            assert!(result.is_err());
            if let Err(err) = result {
                assert_eq!(err.error_id(), crate::error::ERR_CLI_MISSING_VALUE);
            }
        }
        let res_run = parse_lab_args([OsString::from("run"), OsString::from("quiet")]);
        assert!(res_run.is_err());
        if let Err(err) = res_run {
            assert_eq!(err.error_id(), crate::error::ERR_CLI_MISSING_VALUE);
        }
        let res_replay = parse_lab_args([OsString::from("replay"), OsString::from("quiet")]);
        assert!(res_replay.is_err());
        if let Err(err) = res_replay {
            assert_eq!(err.error_id(), crate::error::ERR_CLI_MISSING_VALUE);
        }
    }

    #[test]
    fn malformed_scenarios_are_rejected() {
        let result = parse_lab_args([
            OsString::from("run"),
            OsString::from("unknown"),
            OsString::from("--root"),
            OsString::from("/tmp/r"),
        ]);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err.error_id(), crate::error::ERR_CLI_MALFORMED_VALUE);
        }
    }

    #[test]
    fn invalid_repeat_values_are_rejected() {
        let cases = ["1", "10001", "xyz", "0", "-5"];
        for rep in cases {
            let result = parse_lab_args([
                OsString::from("replay"),
                OsString::from("quiet"),
                OsString::from("--repeat"),
                OsString::from(rep),
                OsString::from("--root"),
                OsString::from("/tmp/r"),
            ]);
            assert!(result.is_err());
            if let Err(err) = result {
                assert_eq!(err.error_id(), crate::error::ERR_CLI_MALFORMED_VALUE);
            }
        }
    }

    #[test]
    fn repeat_missing_value_when_followed_by_option() {
        for opt in ["--token=x", "-p"] {
            let result = parse_lab_args([
                OsString::from("replay"),
                OsString::from("quiet"),
                OsString::from("--repeat"),
                OsString::from(opt),
                OsString::from("--root"),
                OsString::from("/tmp/r"),
            ]);
            assert!(result.is_err());
            if let Err(err) = result {
                assert_eq!(
                    err.error_id(),
                    crate::error::ERR_CLI_MISSING_VALUE,
                    "expected MissingValue for --repeat followed by {opt}, got {err:?}"
                );
            }
        }
    }

    #[test]
    fn repeat_malformed_value_for_negative_and_bare_dash() {
        for val in ["-5", "-"] {
            let result = parse_lab_args([
                OsString::from("replay"),
                OsString::from("quiet"),
                OsString::from("--repeat"),
                OsString::from(val),
                OsString::from("--root"),
                OsString::from("/tmp/r"),
            ]);
            assert!(result.is_err());
            if let Err(err) = result {
                assert_eq!(
                    err.error_id(),
                    crate::error::ERR_CLI_MALFORMED_VALUE,
                    "expected MalformedValue for --repeat followed by {val}, got {err:?}"
                );
            }
        }
    }
}
