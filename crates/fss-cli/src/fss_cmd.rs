#![forbid(unsafe_code)]
//! Command specification, argument decoding, and grammar validation for the `fss` binary.

use std::ffi::OsString;

use crate::error::CliError;
use crate::token::{ArgToken, tokenize_os_args};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Canonical commands supported by the `fss` CLI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FssCommand {
    /// Print help and usage information.
    Help,
    /// Print the binary version.
    Version,
    /// Report capabilities in JSON format.
    Capabilities,
    /// Report system diagnostic doctor results in JSON format.
    Doctor,
    /// Report system status in JSON format.
    Status,
}

/// Returns the static help text for `fss`.
#[must_use]
pub const fn help_text() -> &'static str {
    "Franken Surveillance System design skeleton\n\nUSAGE:\n  fss help\n  fss version\n  fss capabilities --json\n  fss doctor --json\n  fss status --json\n\nNo camera, drone, model, archive, or alert operation is implemented yet."
}

/// Parses OS-native arguments for `fss` with total validation and exact grammar exhaustion.
pub fn parse_fss_args<I>(args: I) -> Result<FssCommand, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let tokens = tokenize_os_args(args)?;
    parse_fss_tokens(&tokens)
}

/// Validates and parses a slice of pre-tokenized arguments.
pub fn parse_fss_tokens(tokens: &[ArgToken]) -> Result<FssCommand, CliError> {
    if tokens.is_empty() {
        return Ok(FssCommand::Help);
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
            Ok(FssCommand::Help)
        }
        "version" | "--version" | "-V" => {
            if tokens.len() > 1 {
                return Err(CliError::TrailingArgument {
                    argument: tokens[1].raw.clone(),
                    index: tokens[1].index,
                    command: Some(first.raw.clone()),
                });
            }
            Ok(FssCommand::Version)
        }
        "capabilities" => {
            parse_json_only_subcommand("capabilities", tokens, FssCommand::Capabilities)
        }
        "doctor" => parse_json_only_subcommand("doctor", tokens, FssCommand::Doctor),
        "status" => parse_json_only_subcommand("status", tokens, FssCommand::Status),
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

/// Parses subcommands whose only permitted option is `--json` with exact exhaustion.
fn parse_json_only_subcommand(
    cmd_name: &str,
    tokens: &[ArgToken],
    command: FssCommand,
) -> Result<FssCommand, CliError> {
    if tokens.len() == 1 {
        return Err(CliError::MissingValue {
            option: "--json".to_owned(),
            command: Some(cmd_name.to_owned()),
            expected: "flag `--json` is required for this command".to_owned(),
        });
    }

    let mut seen_json = false;
    for token in &tokens[1..] {
        match token.as_str() {
            "--json" => {
                if seen_json {
                    return Err(CliError::DuplicateOption {
                        option: "--json".to_owned(),
                        command: Some(cmd_name.to_owned()),
                        index: token.index,
                    });
                }
                seen_json = true;
            }
            opt if opt.starts_with('-') => {
                return Err(CliError::UnknownOption {
                    option: opt.to_owned(),
                    command: Some(cmd_name.to_owned()),
                    index: token.index,
                });
            }
            trailing => {
                return Err(CliError::TrailingArgument {
                    argument: trailing.to_owned(),
                    index: token.index,
                    command: Some(cmd_name.to_owned()),
                });
            }
        }
    }

    if !seen_json {
        return Err(CliError::MissingValue {
            option: "--json".to_owned(),
            command: Some(cmd_name.to_owned()),
            expected: "flag `--json` is required for this command".to_owned(),
        });
    }

    Ok(command)
}

/// Executes a validated `FssCommand` and returns its standard output text.
#[must_use]
pub fn execute_fss(command: FssCommand) -> String {
    match command {
        FssCommand::Help => help_text().to_owned(),
        FssCommand::Version => format!("fss {VERSION}"),
        FssCommand::Capabilities => format!(
            "{{\"schema\":\"fss.capabilities.v1\",\"version\":\"{VERSION}\",\"status\":\"design_skeleton\",\"implemented\":[\"semantic_contracts\",\"machine_readable_registries\"],\"not_implemented\":[\"device_acquisition\",\"media_decode\",\"inference\",\"archive_upload\",\"alerts\"]}}"
        ),
        FssCommand::Doctor => format!(
            "{{\"schema\":\"fss.doctor.v1\",\"version\":\"{VERSION}\",\"verdict\":\"design_only\",\"checks\":[{{\"id\":\"core.contracts\",\"status\":\"present\"}},{{\"id\":\"runtime.acquisition\",\"status\":\"not_implemented\"}},{{\"id\":\"release.qualification\",\"status\":\"not_qualified\"}}]}}"
        ),
        FssCommand::Status => format!(
            "{{\"schema\":\"fss.status.v1\",\"version\":\"{VERSION}\",\"phase\":\"architecture_constitution\",\"sensors\":[],\"events\":[],\"degraded\":[\"no_runtime_implementation\"]}}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_commands_parse_successfully() {
        assert_eq!(parse_fss_args([]).ok(), Some(FssCommand::Help));
        assert_eq!(
            parse_fss_args([OsString::from("help")]).ok(),
            Some(FssCommand::Help)
        );
        assert_eq!(
            parse_fss_args([OsString::from("--help")]).ok(),
            Some(FssCommand::Help)
        );
        assert_eq!(
            parse_fss_args([OsString::from("version")]).ok(),
            Some(FssCommand::Version)
        );
        assert_eq!(
            parse_fss_args([OsString::from("capabilities"), OsString::from("--json")]).ok(),
            Some(FssCommand::Capabilities)
        );
        assert_eq!(
            parse_fss_args([OsString::from("doctor"), OsString::from("--json")]).ok(),
            Some(FssCommand::Doctor)
        );
        assert_eq!(
            parse_fss_args([OsString::from("status"), OsString::from("--json")]).ok(),
            Some(FssCommand::Status)
        );
    }

    #[test]
    fn trailing_arguments_are_rejected() {
        let cases = [
            vec!["help", "extra"],
            vec!["version", "extra"],
            vec!["capabilities", "--json", "extra"],
            vec!["doctor", "--json", "extra"],
            vec!["status", "--json", "extra"],
        ];
        for case in cases {
            let args: Vec<OsString> = case.into_iter().map(OsString::from).collect();
            let result = parse_fss_args(args);
            assert!(result.is_err());
            if let Err(err) = result {
                assert_eq!(
                    err.error_id(),
                    crate::error::ERR_CLI_TRAILING_ARGUMENT,
                    "case failed: {err:?}"
                );
            }
        }
    }

    #[test]
    fn missing_json_flag_is_rejected() {
        for cmd in ["capabilities", "doctor", "status"] {
            let result = parse_fss_args([OsString::from(cmd)]);
            assert!(result.is_err());
            if let Err(err) = result {
                assert_eq!(err.error_id(), crate::error::ERR_CLI_MISSING_VALUE);
            }
        }
    }

    #[test]
    fn duplicate_json_flag_is_rejected() {
        let result = parse_fss_args([
            OsString::from("capabilities"),
            OsString::from("--json"),
            OsString::from("--json"),
        ]);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err.error_id(), crate::error::ERR_CLI_DUPLICATE_OPTION);
        }
    }

    #[test]
    fn unknown_option_is_rejected() {
        let result = parse_fss_args([OsString::from("capabilities"), OsString::from("--xml")]);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err.error_id(), crate::error::ERR_CLI_UNKNOWN_OPTION);
        }
    }

    #[test]
    fn global_option_placement_is_rejected() {
        let result = parse_fss_args([OsString::from("--json"), OsString::from("capabilities")]);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err.error_id(), crate::error::ERR_CLI_UNKNOWN_OPTION);
        }
    }
}
