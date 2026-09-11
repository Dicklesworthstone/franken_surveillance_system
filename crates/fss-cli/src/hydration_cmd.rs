#![forbid(unsafe_code)]
//! Command specification and argument decoding for the `fss-hydration-rehearsal` binary.

use std::ffi::OsString;

use crate::error::CliError;
use crate::token::{ArgToken, tokenize_os_args};

/// Closed registry of recognized hydration rehearsal scenarios.
pub const VALID_HYDRATION_SCENARIOS: [&str; 7] = [
    "all",
    "success",
    "budget-fallback",
    "privacy-denied",
    "expired",
    "h4-denied",
    "h4-qualified",
];

/// Typed action requested of the `fss-hydration-rehearsal` binary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HydrationAction {
    /// Print help text.
    Help,
    /// Run rehearsal for one scenario (or "all").
    Run {
        /// Selected scenario name.
        scenario: String,
    },
}

/// Returns the static help text for `fss-hydration-rehearsal`.
#[must_use]
pub const fn help_text() -> &'static str {
    "fss-hydration-rehearsal — deterministic process-level rehearsal of reference hydration catalog\n\n\
USAGE:\n  fss-hydration-rehearsal [--scenario <name>]\n  fss-hydration-rehearsal <name>\n  fss-hydration-rehearsal help\n\n\
SCENARIOS:\n  all              run all scenarios in canonical order (default)\n  success          routine H2 retrieval\n  budget-fallback  downgrades to H1 under budget constraint\n  privacy-denied   unauthorized privacy class refusal\n  expired          stale catalog entry unavailable\n  h4-denied        laboratory grant required\n  h4-qualified     qualification-purpose H4 admission\n"
}

/// Parses OS-native arguments for `fss-hydration-rehearsal` with total validation.
pub fn parse_hydration_args<I>(args: I) -> Result<HydrationAction, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let tokens = tokenize_os_args(args)?;
    parse_hydration_tokens(&tokens)
}

/// Validates and parses a slice of pre-tokenized arguments.
pub fn parse_hydration_tokens(tokens: &[ArgToken]) -> Result<HydrationAction, CliError> {
    if tokens.is_empty() {
        return Ok(HydrationAction::Run {
            scenario: "all".to_owned(),
        });
    }

    let first = &tokens[0];
    if first.as_str() == "help" || first.as_str() == "--help" || first.as_str() == "-h" {
        if tokens.len() > 1 {
            return Err(CliError::TrailingArgument {
                argument: tokens[1].raw.clone(),
                index: tokens[1].index,
                command: Some("help".to_owned()),
            });
        }
        return Ok(HydrationAction::Help);
    }

    let mut scenario: Option<String> = None;
    let mut idx = 0;

    while idx < tokens.len() {
        let tok = &tokens[idx];
        match tok.as_str() {
            "--scenario" => {
                if scenario.is_some() {
                    return Err(CliError::DuplicateOption {
                        option: "--scenario".to_owned(),
                        command: None,
                        index: tok.index,
                    });
                }
                if idx + 1 >= tokens.len() {
                    return Err(CliError::MissingValue {
                        option: "--scenario".to_owned(),
                        command: None,
                        expected: "scenario name (success, budget-fallback, privacy-denied, expired, h4-denied, h4-qualified, or all)".to_owned(),
                    });
                }
                let val_tok = &tokens[idx + 1];
                validate_hydration_scenario(&val_tok.raw, val_tok.index)?;
                scenario = Some(val_tok.raw.clone());
                idx += 2;
            }
            opt if opt.starts_with('-') => {
                return Err(CliError::UnknownOption {
                    option: opt.to_owned(),
                    command: None,
                    index: tok.index,
                });
            }
            positional => {
                if scenario.is_some() {
                    return Err(CliError::TrailingArgument {
                        argument: positional.to_owned(),
                        index: tok.index,
                        command: None,
                    });
                }
                validate_hydration_scenario(positional, tok.index)?;
                scenario = Some(positional.to_owned());
                idx += 1;
            }
        }
    }

    match scenario {
        Some(sc) => Ok(HydrationAction::Run { scenario: sc }),
        None => Ok(HydrationAction::Run {
            scenario: "all".to_owned(),
        }),
    }
}

fn validate_hydration_scenario(name: &str, index: usize) -> Result<(), CliError> {
    if VALID_HYDRATION_SCENARIOS.contains(&name) {
        Ok(())
    } else {
        Err(CliError::MalformedValue {
            option: "--scenario".to_owned(),
            value: name.to_owned(),
            reason: format!(
                "unknown scenario; expected {}",
                VALID_HYDRATION_SCENARIOS.join(", ")
            ),
            index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_hydration_scenarios_parse_successfully() {
        assert_eq!(
            parse_hydration_args([]).ok(),
            Some(HydrationAction::Run {
                scenario: "all".to_owned()
            })
        );
        assert_eq!(
            parse_hydration_args([OsString::from("--scenario"), OsString::from("success")]).ok(),
            Some(HydrationAction::Run {
                scenario: "success".to_owned()
            })
        );
        assert_eq!(
            parse_hydration_args([OsString::from("success")]).ok(),
            Some(HydrationAction::Run {
                scenario: "success".to_owned()
            })
        );
        assert_eq!(
            parse_hydration_args([OsString::from("all")]).ok(),
            Some(HydrationAction::Run {
                scenario: "all".to_owned()
            })
        );
        assert_eq!(
            parse_hydration_args([OsString::from("--help")]).ok(),
            Some(HydrationAction::Help)
        );
    }

    #[test]
    fn trailing_arguments_are_rejected() {
        let cases = [
            vec!["--scenario", "success", "extra"],
            vec!["success", "extra"],
            vec!["all", "extra"],
            vec!["help", "extra"],
        ];
        for case in cases {
            let args: Vec<OsString> = case.into_iter().map(OsString::from).collect();
            let result = parse_hydration_args(args);
            assert!(result.is_err());
            if let Err(err) = result {
                assert_eq!(err.error_id(), crate::error::ERR_CLI_TRAILING_ARGUMENT);
            }
        }
    }

    #[test]
    fn missing_scenario_value_is_rejected() {
        let result = parse_hydration_args([OsString::from("--scenario")]);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err.error_id(), crate::error::ERR_CLI_MISSING_VALUE);
        }
    }

    #[test]
    fn malformed_scenario_is_rejected() {
        let result = parse_hydration_args([OsString::from("not-a-scenario")]);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err.error_id(), crate::error::ERR_CLI_MALFORMED_VALUE);
        }
    }
}
