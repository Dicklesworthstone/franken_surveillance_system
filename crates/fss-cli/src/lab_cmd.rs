#![forbid(unsafe_code)]
//! Command specification and argument decoding for the `fss-lab` binary.

use std::ffi::OsString;

use crate::error::CliError;
use crate::token::{ArgToken, tokenize_os_args};

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

    let scenario_tok = &tokens[1];
    validate_scenario(&scenario_tok.raw, scenario_tok.index, "replay")?;

    let mut repeat: usize = 2;
    let mut seen_repeat = false;
    let mut idx = 2;

    while idx < tokens.len() {
        let tok = &tokens[idx];
        match tok.as_str() {
            "--repeat" => {
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
                let parsed =
                    val_tok
                        .raw
                        .parse::<usize>()
                        .map_err(|_| CliError::MalformedValue {
                            option: "--repeat".to_owned(),
                            value: val_tok.raw.clone(),
                            reason: "--repeat requires a positive integer".to_owned(),
                            index: val_tok.index,
                        })?;

                if parsed < 2 {
                    return Err(CliError::MalformedValue {
                        option: "--repeat".to_owned(),
                        value: val_tok.raw.clone(),
                        reason: "replay requires --repeat >= 2".to_owned(),
                        index: val_tok.index,
                    });
                }
                if parsed > 10_000 {
                    return Err(CliError::MalformedValue {
                        option: "--repeat".to_owned(),
                        value: val_tok.raw.clone(),
                        reason: "replay repeat count exceeds the 10000-run bound".to_owned(),
                        index: val_tok.index,
                    });
                }

                repeat = parsed;
                idx += 2;
            }
            opt if opt.starts_with('-') => {
                return Err(CliError::UnknownOption {
                    option: opt.to_owned(),
                    command: Some("replay".to_owned()),
                    index: tok.index,
                });
            }
            trailing => {
                return Err(CliError::TrailingArgument {
                    argument: trailing.to_owned(),
                    index: tok.index,
                    command: Some("replay".to_owned()),
                });
            }
        }
    }

    Ok(LabAction::Replay {
        scenario: scenario_tok.raw.clone(),
        repeat,
    })
}

fn validate_scenario(name: &str, index: usize, _command: &str) -> Result<(), CliError> {
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
}
