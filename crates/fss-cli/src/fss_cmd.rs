#![forbid(unsafe_code)]
//! Command specification, argument decoding, and grammar validation for the `fss` binary.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::error::{CliError, ExitIdentity};
use crate::negative_evidence_cmd::{
    NegativeEvidenceAction, execute_negative_evidence, parse_negative_evidence_tokens,
};
use crate::token::{ArgToken, tokenize_os_args};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Options for the `doctor` command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DoctorArgs {
    /// Optional deployment root directory to inspect.
    pub root: Option<PathBuf>,
}

/// Canonical commands supported by the `fss` CLI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FssCommand {
    /// Print help and usage information.
    Help,
    /// Print the binary version.
    Version,
    /// Report capabilities in JSON format.
    Capabilities,
    /// Report system diagnostic doctor results in JSON format.
    Doctor(DoctorArgs),
    /// Report system status in JSON format.
    Status,
    /// Negative evidence ledger management.
    NegativeEvidence(Box<NegativeEvidenceAction>),
}

impl FssCommand {
    /// Returns true if JSON envelope output is requested.
    #[must_use]
    pub fn is_json(&self) -> bool {
        match self {
            Self::Capabilities | Self::Doctor(_) | Self::Status => true,
            Self::NegativeEvidence(action) => action.is_json(),
            Self::Help | Self::Version => false,
        }
    }
}

/// Returns the static help text for `fss`.
#[must_use]
pub const fn help_text() -> &'static str {
    "Franken Surveillance System design skeleton\n\nUSAGE:\n  fss help\n  fss version\n  fss capabilities --json\n  fss doctor --json\n      [--root <dir>]  inspect a deployment root read-only (never writes, locks, or repairs)\n  fss status --json\n  fss negative-evidence <init|list|verify|append> [--path <file>] [--json]\n\nNo camera, drone, model, archive, or alert operation is implemented yet."
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
        "doctor" => parse_doctor_tokens(tokens).map(FssCommand::Doctor),
        "status" => parse_json_only_subcommand("status", tokens, FssCommand::Status),
        "negative-evidence" | "neg" | "negative" => {
            let action = parse_negative_evidence_tokens(&tokens[1..])?;
            Ok(FssCommand::NegativeEvidence(Box::new(action)))
        }
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

/// Parses the `doctor` subcommand supporting `--json` and optional `--root <dir>`.
fn parse_doctor_tokens(tokens: &[ArgToken]) -> Result<DoctorArgs, CliError> {
    if tokens.len() == 1 {
        return Err(CliError::MissingValue {
            option: "--json".to_owned(),
            command: Some("doctor".to_owned()),
            expected: "flag `--json` is required for this command".to_owned(),
        });
    }

    let mut seen_json = false;
    let mut root: Option<PathBuf> = None;
    let mut idx = 1;

    while idx < tokens.len() {
        let arg = &tokens[idx];
        match arg.as_str() {
            "--json" => {
                if seen_json {
                    return Err(CliError::DuplicateOption {
                        option: "--json".to_owned(),
                        command: Some("doctor".to_owned()),
                        index: arg.index,
                    });
                }
                seen_json = true;
                idx += 1;
            }
            "--root" => {
                if root.is_some() {
                    return Err(CliError::DuplicateOption {
                        option: "--root".to_owned(),
                        command: Some("doctor".to_owned()),
                        index: arg.index,
                    });
                }
                idx += 1;
                if idx >= tokens.len() {
                    return Err(CliError::MissingValue {
                        option: "--root".to_owned(),
                        command: Some("doctor".to_owned()),
                        expected: "directory path for `--root`".to_owned(),
                    });
                }
                root = Some(PathBuf::from(tokens[idx].raw.clone()));
                idx += 1;
            }
            s if s.starts_with("--root=") => {
                if root.is_some() {
                    return Err(CliError::DuplicateOption {
                        option: "--root".to_owned(),
                        command: Some("doctor".to_owned()),
                        index: arg.index,
                    });
                }
                let val = &s["--root=".len()..];
                if val.is_empty() {
                    return Err(CliError::MissingValue {
                        option: "--root".to_owned(),
                        command: Some("doctor".to_owned()),
                        expected: "directory path for `--root`".to_owned(),
                    });
                }
                root = Some(PathBuf::from(val));
                idx += 1;
            }
            opt if opt.starts_with('-') => {
                return Err(CliError::UnknownOption {
                    option: opt.to_owned(),
                    command: Some("doctor".to_owned()),
                    index: arg.index,
                });
            }
            trailing => {
                return Err(CliError::TrailingArgument {
                    argument: trailing.to_owned(),
                    index: arg.index,
                    command: Some("doctor".to_owned()),
                });
            }
        }
    }

    if !seen_json {
        return Err(CliError::MissingValue {
            option: "--json".to_owned(),
            command: Some("doctor".to_owned()),
            expected: "flag `--json` is required for this command".to_owned(),
        });
    }

    Ok(DoctorArgs { root })
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
    execute_fss_with_exit(command).0
}

/// Executes a validated `FssCommand` and returns output text along with exit identity.
#[must_use]
pub fn execute_fss_with_exit(command: FssCommand) -> (String, ExitIdentity) {
    match command {
        FssCommand::Help => (help_text().to_owned(), ExitIdentity::SUCCESS),
        FssCommand::Version => (format!("fss {VERSION}"), ExitIdentity::SUCCESS),
        FssCommand::Capabilities => (
            format!(
                "{{\"schema\":\"fss.capabilities.v1\",\"version\":\"{VERSION}\",\"status\":\"design_skeleton\",\"implemented\":[\"semantic_contracts\",\"machine_readable_registries\"],\"not_implemented\":[\"device_acquisition\",\"media_decode\",\"inference\",\"archive_upload\",\"alerts\"]}}"
            ),
            ExitIdentity::SUCCESS,
        ),
        FssCommand::Doctor(DoctorArgs { root: None }) => (
            format!(
                "{{\"schema\":\"fss.doctor.v1\",\"version\":\"{VERSION}\",\"verdict\":\"design_only\",\"checks\":[{{\"id\":\"core.contracts\",\"status\":\"present\"}},{{\"id\":\"runtime.acquisition\",\"status\":\"not_implemented\"}},{{\"id\":\"release.qualification\",\"status\":\"not_qualified\"}}]}}"
            ),
            ExitIdentity::SUCCESS,
        ),
        FssCommand::Doctor(DoctorArgs {
            root: Some(ref root),
        }) => {
            let report = fss_reference::doctor::inspect_deployment(root);
            let exit_id = match report.verdict {
                fss_reference::doctor::DoctorVerdict::Healthy => ExitIdentity::SUCCESS,
                fss_reference::doctor::DoctorVerdict::AttentionRequired => {
                    ExitIdentity::DOCTOR_ATTENTION_REQUIRED
                }
                fss_reference::doctor::DoctorVerdict::NotADeployment => {
                    ExitIdentity::DOCTOR_NOT_A_DEPLOYMENT
                }
                fss_reference::doctor::DoctorVerdict::Unreadable => ExitIdentity::RUNTIME_FAILURE,
            };
            (report.to_json(), exit_id)
        }
        FssCommand::Status => (
            format!(
                "{{\"schema\":\"fss.status.v1\",\"version\":\"{VERSION}\",\"phase\":\"architecture_constitution\",\"sensors\":[],\"events\":[],\"degraded\":[\"no_runtime_implementation\"]}}"
            ),
            ExitIdentity::SUCCESS,
        ),
        FssCommand::NegativeEvidence(ref action) => execute_negative_evidence(action),
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
            Some(FssCommand::Doctor(DoctorArgs { root: None }))
        );
        assert_eq!(
            parse_fss_args([
                OsString::from("doctor"),
                OsString::from("--json"),
                OsString::from("--root"),
                OsString::from("/deploy/root"),
            ])
            .ok(),
            Some(FssCommand::Doctor(DoctorArgs {
                root: Some(PathBuf::from("/deploy/root")),
            }))
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
