#![forbid(unsafe_code)]
//! Command specification, argument decoding, and grammar validation for the `fss` binary.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::error::{CliError, ExitIdentity};
use crate::negative_evidence_cmd::{
    NegativeEvidenceAction, execute_negative_evidence, parse_negative_evidence_tokens,
};
use crate::orient_cmd::{
    ExplainArgs, OrientArgs, execute_explain, execute_orient, parse_explain_args, parse_orient_args,
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
    /// Read-only AOP-003 session.orient over a deployment root: an AgentResponseEnvelope carrying the anchor-pinned SituationCapsule, listing (never executing) its affordances.
    Orient(OrientArgs),
    /// Read-only AOP-011 explain of one published event: evidence handles, knowledge states, contradictions, and what would change them.
    Explain(ExplainArgs),
}

impl FssCommand {
    /// Returns true if JSON envelope output is requested.
    #[must_use]
    pub fn is_json(&self) -> bool {
        match self {
            Self::Capabilities
            | Self::Doctor(_)
            | Self::Status
            | Self::Orient(_)
            | Self::Explain(_) => true,
            Self::NegativeEvidence(action) => action.is_json(),
            Self::Help | Self::Version => false,
        }
    }
}

/// Returns the static help text for `fss`.
#[must_use]
pub const fn help_text() -> &'static str {
    "Franken Surveillance System: unqualified reference implementation\n\nUSAGE:\n  fss help\n  fss version\n  fss capabilities --json\n  fss doctor --json [--root <dir>]\n      --root inspects a deployment root read-only (never writes, locks, or repairs)\n  fss status --json\n  fss orient --json --root <dir> [--view pulse|brief|epistemic_map] [--principal <id>] [--budget-tokens <n>]\n      read-only AOP-003 session.orient: AgentResponseEnvelope with the SituationCapsule; lists affordances, never executes them\n  fss explain --json --root <dir> --event-id <id> [--principal <id>]\n      read-only AOP-011 explain of one published event\n  fss negative-evidence <init|list|verify|append> [--path <file>] [--json]\n\nCompanion binaries: fss-file (import and decode recorded media), fss-infer (scalar model\nexecution, detection, tracking), fss-event (recorded event reports and publication),\nfss-archive (RTSP/HTTP capture archives), fss-lab (deterministic scenarios).\nNothing is release-qualified; the capabilities command lists what is implemented."
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
        "doctor" => parse_doctor_tokens(tokens),
        "status" => parse_json_only_subcommand("status", tokens, FssCommand::Status),
        "orient" => parse_orient_tokens(tokens),
        "explain" => parse_explain_tokens(tokens),
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
fn parse_doctor_tokens(tokens: &[ArgToken]) -> Result<FssCommand, CliError> {
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

    Ok(FssCommand::Doctor(DoctorArgs { root }))
}

/// Parses the `orient` subcommand: `--json`, `--root <dir>`, optional `--view`, `--principal`,
/// and `--budget-tokens`, each at most once, in either `--name value` or `--name=value` form.
fn parse_orient_tokens(tokens: &[ArgToken]) -> Result<FssCommand, CliError> {
    Ok(FssCommand::Orient(parse_orient_args(tokens)?))
}

/// Parses the `explain` subcommand: `--json`, `--root <dir>`, `--event-id <id>`, and an optional
/// `--principal`, each at most once.
fn parse_explain_tokens(tokens: &[ArgToken]) -> Result<FssCommand, CliError> {
    Ok(FssCommand::Explain(parse_explain_args(tokens)?))
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
                "{{\"schema\":\"fss.capabilities.v1\",\"version\":\"{VERSION}\",\"status\":\"reference_implementation_unqualified\",\"qualified\":[],\"implemented\":[\"file_import_custody:annexb,mjpeg,rtpplay\",\"jpeg_baseline_decode\",\"h264_baseline_main_high_decode\",\"model_free_watch_pipeline\",\"event_evaluation_harness\",\"rtp_h264_h265_depacketize\",\"rtsp_interleaved_tcp_capture\",\"http_mjpeg_capture\",\"fmp4_remux_avc_hevc\",\"local_capture_archive_verify_export\",\"scalar_model_execution_safetensors\",\"foreground_and_learned_detection_reference\",\"kalman_iou_tracking_reference\",\"recorded_event_publication\",\"durable_ledger_root_last_publication\",\"deployment_doctor\",\"negative_evidence_ledger\",\"agent_orient_explain_cli\"],\"partial\":[\"alert_delivery:webhook_library_unwired\",\"cross_camera_association:caller_supplied_ground_plane\",\"camera_pose_and_localization\",\"agent_operations_cli:orient_explain_only\"],\"not_implemented\":[\"h265_pixel_decode\",\"h264_interlaced_or_non_420\",\"progressive_jpeg_decode\",\"rtp_over_udp\",\"uvc_acquisition\",\"onvif\",\"trained_detector_package\",\"real_footage_quality_evaluation\",\"agent_protocol_transport\",\"mcp\",\"cloud_archive\",\"property_reconstruction\",\"privacy_masking\",\"deletion_closure\",\"asupersync_runtime\",\"live_operator_view\"]}}"
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
                "{{\"schema\":\"fss.status.v1\",\"version\":\"{VERSION}\",\"phase\":\"reference_implementation_unqualified\",\"deployment\":\"not_specified\",\"sensors\":[],\"events\":[],\"degraded\":[\"no_deployment_root_inspected\",\"not_release_qualified\"]}}"
            ),
            ExitIdentity::SUCCESS,
        ),
        FssCommand::NegativeEvidence(ref action) => execute_negative_evidence(action),
        FssCommand::Orient(ref args) => execute_orient(args),
        FssCommand::Explain(ref args) => execute_explain(args),
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
            vec!["orient", "--json", "--root", "/deploy", "extra"],
            vec![
                "explain",
                "--json",
                "--root",
                "/deploy",
                "--event-id",
                "event:x",
                "extra",
            ],
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
        for cmd in ["capabilities", "doctor", "status", "orient", "explain"] {
            let result = parse_fss_args([OsString::from(cmd)]);
            assert!(result.is_err());
            if let Err(err) = result {
                assert_eq!(err.error_id(), crate::error::ERR_CLI_MISSING_VALUE);
            }
        }
    }

    #[test]
    fn orient_and_explain_parse_with_defaults_and_both_value_forms() {
        let parse = |args: &[&str]| parse_fss_args(args.iter().map(OsString::from));
        let Ok(FssCommand::Orient(orient)) = parse(&["orient", "--json", "--root", "/deploy"])
        else {
            unreachable!("orient with --json and --root parses");
        };
        assert_eq!(orient.root, PathBuf::from("/deploy"));
        assert_eq!(orient.view, fss_core::AgentView::Brief);
        assert_eq!(orient.principal.as_str(), "principal:local-operator");
        assert_eq!(orient.budget_tokens, None);
        let Ok(FssCommand::Orient(pulse)) = parse(&[
            "orient",
            "--root=/deploy",
            "--view=pulse",
            "--budget-tokens",
            "300",
            "--principal",
            "principal:agent-7",
            "--json",
        ]) else {
            unreachable!("orient with every option parses");
        };
        assert_eq!(pulse.view, fss_core::AgentView::Pulse);
        assert_eq!(pulse.budget_tokens, Some(300));
        assert_eq!(pulse.principal.as_str(), "principal:agent-7");
        assert!(
            parse(&[
                "orient",
                "--json",
                "--root",
                "/d",
                "--view",
                "pulse",
                "--budget-tokens",
                "301"
            ])
            .is_err()
        );
        let Ok(FssCommand::Explain(explain)) = parse(&[
            "explain",
            "--json",
            "--root",
            "/deploy",
            "--event-id",
            "event:watch:1",
        ]) else {
            unreachable!("explain with --event-id parses");
        };
        assert_eq!(explain.event_id.as_str(), "event:watch:1");
        assert!(FssCommand::Explain(explain).is_json());
        assert!(parse(&["explain", "--json", "--root", "/deploy"]).is_err());
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

    /// Extracts the quoted items of one JSON string array named `key` from flat output.
    fn json_string_array(output: &str, key: &str) -> Vec<String> {
        let marker = format!("\"{key}\":[");
        let Some(start) = output.find(&marker) else {
            return Vec::new();
        };
        let rest = &output[start + marker.len()..];
        let body = &rest[..rest.find(']').unwrap_or(0)];
        body.split(',')
            .map(|item| item.trim_matches('"').to_owned())
            .filter(|item| !item.is_empty())
            .collect()
    }

    #[test]
    fn capabilities_are_disjoint_unqualified_and_name_real_binaries() {
        let output = execute_fss(FssCommand::Capabilities);
        assert!(output.contains("\"status\":\"reference_implementation_unqualified\""));
        assert!(!output.contains("design_skeleton"));
        assert!(
            output.contains("\"qualified\":[]"),
            "nothing is release-qualified"
        );
        let implemented = json_string_array(&output, "implemented");
        let partial = json_string_array(&output, "partial");
        let missing = json_string_array(&output, "not_implemented");
        assert!(!implemented.is_empty() && !partial.is_empty() && !missing.is_empty());
        let mut all: Vec<&String> = implemented.iter().chain(&partial).chain(&missing).collect();
        let total = all.len();
        all.sort();
        all.dedup();
        assert_eq!(
            all.len(),
            total,
            "a capability may appear in exactly one list"
        );

        let manifest = include_str!("../Cargo.toml");
        for binary in [
            "fss-file",
            "fss-infer",
            "fss-event",
            "fss-archive",
            "fss-lab",
        ] {
            assert!(help_text().contains(binary), "help names {binary}");
            let declared = manifest.contains(&format!("name = \"{binary}\""))
                || std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join(format!("src/bin/{binary}"))
                    .is_dir();
            assert!(
                declared,
                "{binary} named in help must be a real binary target"
            );
        }
    }
}
