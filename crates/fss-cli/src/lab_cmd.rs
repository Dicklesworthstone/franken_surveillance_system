#![forbid(unsafe_code)]
//! Command specification and argument decoding for the `fss-lab` binary.

use std::ffi::OsString;

use crate::error::CliError;
use crate::token::{ArgToken, is_option_shaped, tokenize_os_args};

/// Closed registry of recognized laboratory scenario identifiers.
pub const VALID_SCENARIOS: [&str; 6] = [
    "quiet",
    "raccoon",
    "intrusion",
    "sneaky",
    "lost-ack",
    "corrupt-source",
];

/// Typed action requested of the `fss-lab` binary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LabAction {
    /// Print help text.
    Help,
    /// List available scenarios in JSON format.
    List,
    /// Run the scenario matrix and report in JSON format.
    Matrix,
    /// Run deterministic self-test and report in JSON format.
    SelfTest,
    /// Run a single scenario.
    Run {
        /// Selected scenario identifier.
        scenario: String,
    },
    /// Replay a scenario N times to prove determinism.
    Replay {
        /// Selected scenario identifier.
        scenario: String,
        /// Repeat count (bounds: 2 <= repeat <= 10_000).
        repeat: usize,
    },
}

/// Returns the static help text for `fss-lab`.
#[must_use]
pub const fn help_text() -> &'static str {
    "fss-lab — deterministic reference surveillance laboratory\n\n\
USAGE\n  fss-lab list\n  fss-lab run <scenario>\n  fss-lab matrix\n  fss-lab replay <scenario> [--repeat N]\n  fss-lab self-test\n\n\
SCENARIOS\n  quiet           complete coverage and a certified absence\n  raccoon         benign wildlife with no alert effect\n  intrusion       independently corroborated person and verified alert\n  sneaky          material person residual plus an observability gap\n  lost-ack        indeterminate alert dispatch resolved by reconciliation\n  corrupt-source  source corruption detected before evidence publication\n"
}

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
        "matrix" => {
            if tokens.len() > 1 {
                return Err(CliError::TrailingArgument {
                    argument: tokens[1].raw.clone(),
                    index: tokens[1].index,
                    command: Some("matrix".to_owned()),
                });
            }
            Ok(LabAction::Matrix)
        }
        "self-test" => {
            if tokens.len() > 1 {
                return Err(CliError::TrailingArgument {
                    argument: tokens[1].raw.clone(),
                    index: tokens[1].index,
                    command: Some("self-test".to_owned()),
                });
            }
            Ok(LabAction::SelfTest)
        }
        "run" => parse_run_command(tokens),
        "replay" => parse_replay_command(tokens),
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

fn parse_run_command(tokens: &[ArgToken]) -> Result<LabAction, CliError> {
    if tokens.len() == 1 {
        return Err(CliError::MissingValue {
            option: "<scenario>".to_owned(),
            command: Some("run".to_owned()),
            expected: "one of: quiet, raccoon, intrusion, sneaky, lost-ack, corrupt-source"
                .to_owned(),
        });
    }

    let scenario_tok = &tokens[1];
    validate_scenario(&scenario_tok.raw, scenario_tok.index, "run")?;

    if tokens.len() > 2 {
        return Err(CliError::TrailingArgument {
            argument: tokens[2].raw.clone(),
            index: tokens[2].index,
            command: Some("run".to_owned()),
        });
    }

    Ok(LabAction::Run {
        scenario: scenario_tok.raw.clone(),
    })
}

fn parse_replay_command(tokens: &[ArgToken]) -> Result<LabAction, CliError> {
    if tokens.len() == 1 {
        return Err(CliError::MissingValue {
            option: "<scenario>".to_owned(),
            command: Some("replay".to_owned()),
            expected: "one of: quiet, raccoon, intrusion, sneaky, lost-ack, corrupt-source"
                .to_owned(),
        });
    }

    let mut scenario: Option<String> = None;
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

    match scenario {
        Some(sc) => Ok(LabAction::Replay {
            scenario: sc,
            repeat,
        }),
        None => Err(CliError::MissingValue {
            option: "<scenario>".to_owned(),
            command: Some("replay".to_owned()),
            expected: "one of: quiet, raccoon, intrusion, sneaky, lost-ack, corrupt-source"
                .to_owned(),
        }),
    }
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
            parse_lab_args([OsString::from("matrix")]).ok(),
            Some(LabAction::Matrix)
        );
        assert_eq!(
            parse_lab_args([OsString::from("self-test")]).ok(),
            Some(LabAction::SelfTest)
        );
        assert_eq!(
            parse_lab_args([OsString::from("run"), OsString::from("quiet")]).ok(),
            Some(LabAction::Run {
                scenario: "quiet".to_owned()
            })
        );
        assert_eq!(
            parse_lab_args([OsString::from("replay"), OsString::from("intrusion")]).ok(),
            Some(LabAction::Replay {
                scenario: "intrusion".to_owned(),
                repeat: 2
            })
        );
        assert_eq!(
            parse_lab_args([
                OsString::from("replay"),
                OsString::from("intrusion"),
                OsString::from("--repeat"),
                OsString::from("5")
            ])
            .ok(),
            Some(LabAction::Replay {
                scenario: "intrusion".to_owned(),
                repeat: 5
            })
        );
    }

    #[test]
    fn trailing_arguments_are_rejected() {
        let cases = [
            vec!["list", "extra"],
            vec!["matrix", "extra"],
            vec!["self-test", "extra"],
            vec!["run", "quiet", "extra"],
            vec!["replay", "quiet", "--repeat", "2", "extra"],
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
    fn malformed_scenarios_are_rejected() {
        let result = parse_lab_args([OsString::from("run"), OsString::from("unknown")]);
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
