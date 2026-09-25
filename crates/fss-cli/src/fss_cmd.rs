#![forbid(unsafe_code)]
//! Command specification, argument decoding, and grammar validation for the `fss` binary.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::error::{CliError, ExitIdentity};
use crate::follow_cmd::{FollowArgs, execute_follow, parse_follow_args};
use crate::negative_evidence_cmd::{
    NegativeEvidenceAction, execute_negative_evidence, parse_negative_evidence_tokens,
};
use crate::orient_cmd::{
    ExplainArgs, OrientArgs, execute_explain, execute_orient, parse_explain_args, parse_orient_args,
};
use crate::query_cmd::{QueryArgs, execute_query, parse_query_args};
use crate::session_cmd::{SessionCommand, execute_session, parse_handoff, parse_session_args};
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
    /// Read-only AOP-004 session.follow since an earlier anchor token: an AgentResponseEnvelope carrying one exact page of the MeaningfulDelta between the situation as of that anchor and the head (protected classes never coalesced; the rest through an exact continuation).
    Follow(FollowArgs),
    /// Read-only AOP-005 exact, bounded committed event-record query.
    Query(QueryArgs),
    /// Durable mission-scoped agent sessions (agent-plane writes only; authority and effect state are never written): AOP-001 session.open opens a session and its first workspace revision at the current orient anchor, AOP-012 handoff publishes a root-last HandoffCapsule, and AOP-002 session.resume accepts a handoff and rebases it onto the head, listing every invalidated assumption.
    Session(SessionCommand),
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
            | Self::Explain(_)
            | Self::Follow(_)
            | Self::Query(_)
            | Self::Session(_) => true,
            Self::NegativeEvidence(action) => action.is_json(),
            Self::Help | Self::Version => false,
        }
    }
}

/// Returns the static help text for `fss`.
#[must_use]
pub const fn help_text() -> &'static str {
    "Franken Surveillance System: unqualified reference implementation\n\nUSAGE:\n  fss help\n  fss version\n  fss capabilities --json\n  fss doctor --json [--root <dir>]\n      --root inspects a deployment root read-only (never writes, locks, or repairs)\n  fss status --json\n  fss query --json --root <dir> [--event-id <id>] [--kind <kind>] [--state <state>] [--zone <zone>] [--from-ns <i128>] [--through-ns <i128>] [--max-entries <1..32>] [--anchor <token>] [--continuation <token>] [--principal <id>]\n      read-only AOP-005 exact committed record query; an empty result never certifies physical absence\n  fss session orient --json --root <dir> [--view pulse|brief|epistemic_map] [--principal <id>] [--budget-tokens <n>]\n      (alias: fss orient) read-only AOP-003 session.orient: AgentResponseEnvelope with the SituationCapsule; lists affordances, never executes them\n  fss explain --json --root <dir> --event-id <id> [--principal <id>]\n      read-only AOP-011 explain of one published event\n  fss session follow --json --root <dir> --since <anchor> [--view pulse|brief] [--principal <id>] [--max-entries <n>] [--continuation <token>]\n      (alias: fss follow) read-only AOP-004 session.follow: the MeaningfulDelta since an orient anchor token, paged through exact continuations\n  fss session open --json --root <dir> --mission <text-or-file> --objective <text> [--principal <id>] [--view pulse|brief|epistemic_map] [--budget-tokens <n>]\n      AOP-001 session.open: a durable mission-scoped session and its first workspace revision at the current orient anchor (writes agent/ only)\n  fss handoff --json --root <dir> --session <id> [--principal <id>] [--note <text>]\n      (alias: fss session handoff) AOP-012 handoff: publishes a root-last HandoffCapsule sealed as of the session's anchor\n  fss session resume --json --root <dir> --handoff <id> [--principal <id>]\n      AOP-002 session.resume: accepts the handoff, lists every invalidated assumption, and rebases the session onto the head\n  fss negative-evidence <init|list|verify|append> [--path <file>] [--json]\n\nCompanion binaries: fss-file (import and decode recorded media), fss-infer (scalar model\nexecution, detection, tracking), fss-event (recorded event reports and publication),\nfss-archive (RTSP/HTTP capture archives), fss-lab (deterministic scenarios).\nNothing is release-qualified; the capabilities command lists what is implemented."
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
        // The registered spellings (AGENT_OPERATING_MODEL.md section 24.1, the frozen public
        // registry `gen:fss1:public-v1`, and architecture/operation_crosswalk.json) are
        // `fss session orient` (AOP-003), `fss session follow` (AOP-004), and `fss handoff`
        // (AOP-012); `fss orient`, `fss follow`, and `fss session handoff` are their recorded
        // aliases and parse to the same command.
        "orient" => parse_orient_tokens(tokens),
        "explain" => parse_explain_tokens(tokens),
        "follow" => parse_follow_tokens(tokens),
        "query" => parse_query_args(tokens).map(FssCommand::Query),
        "handoff" => Ok(FssCommand::Session(SessionCommand::Handoff(parse_handoff(
            tokens,
        )?))),
        "session" => match tokens.get(1).map(ArgToken::as_str) {
            Some("orient") => parse_orient_tokens(&tokens[1..]),
            Some("follow") => parse_follow_tokens(&tokens[1..]),
            _ => parse_session_tokens(tokens),
        },
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

/// Parses the `follow` subcommand: `--json`, `--root <dir>`, `--since <anchor>`, and optional
/// `--view`, `--principal`, `--max-entries`, and `--continuation`, each at most once.
fn parse_follow_tokens(tokens: &[ArgToken]) -> Result<FssCommand, CliError> {
    Ok(FssCommand::Follow(parse_follow_args(tokens)?))
}

/// Parses the `session` subcommands: `open`, `handoff`, and `resume`, each with `--json`,
/// `--root <dir>`, and its own options, each at most once.
fn parse_session_tokens(tokens: &[ArgToken]) -> Result<FssCommand, CliError> {
    Ok(FssCommand::Session(parse_session_args(tokens)?))
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
                "{{\"schema\":\"fss.capabilities.v1\",\"version\":\"{VERSION}\",\"status\":\"reference_implementation_unqualified\",\"qualified\":[],\"implemented\":[\"file_import_custody:annexb,hevc,mjpeg,rtpplay\",\"jpeg_baseline_decode\",\"h264_baseline_main_high_decode\",\"h265_main_profile_decode_library\",\"h265_ingest_wiring\",\"model_free_watch_pipeline\",\"trained_detector_package:yolox_nano_verified_fmpk_uncalibrated\",\"detector_cascade:watch_corroborate_gate_selected_frames\",\"package_detection_event_publication\",\"h264_h265_chroma_rgb:bt601_limited\",\"event_evaluation_harness\",\"two_sensor_corroborated_webhook_alert\",\"rtp_h264_h265_depacketize\",\"rtsp_interleaved_tcp_capture\",\"http_mjpeg_capture\",\"fmp4_remux_avc_hevc\",\"local_capture_archive_verify_export\",\"scalar_model_execution_safetensors\",\"foreground_and_learned_detection_reference\",\"kalman_iou_tracking_reference\",\"recorded_event_publication\",\"durable_ledger_root_last_publication\",\"deployment_doctor\",\"negative_evidence_ledger\",\"agent_orient_explain_follow_cli\",\"agent_query_cli_mcp:bounded_committed_event_records\",\"agent_session_cli:open_handoff_resume\",\"privacy_masking:retained_live_and_replay_decode_owner_rectangles\",\"coverage_single_points:alg_bridge_001_witnessed_oracle_certified\"],\"partial\":[\"cross_camera_association:caller_supplied_ground_plane\",\"camera_pose_and_localization\",\"agent_operations_cli:orient_explain_follow\",\"certified_graph_intelligence:1_of_27_registered_algorithms\"],\"not_implemented\":[\"h265_main10_rext_tiles\",\"h264_interlaced_or_non_420\",\"progressive_jpeg_decode\",\"rtp_over_udp\",\"uvc_acquisition\",\"onvif\",\"real_footage_quality_evaluation\",\"agent_protocol_transport\",\"mcp\",\"cloud_archive\",\"property_reconstruction\",\"deletion_closure\",\"asupersync_runtime\",\"live_operator_view\"]}}"
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
        FssCommand::Follow(ref args) => execute_follow(args),
        FssCommand::Query(ref args) => execute_query(args),
        FssCommand::Session(ref command) => execute_session(command),
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
            vec![
                "follow",
                "--json",
                "--root",
                "/deploy",
                "--since",
                FOLLOW_ANCHOR,
                "extra",
            ],
            vec![
                "session",
                "resume",
                "--json",
                "--root",
                "/deploy",
                "--handoff",
                "handoff:x",
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
        for cmd in [
            "capabilities",
            "doctor",
            "status",
            "orient",
            "explain",
            "follow",
        ] {
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

    /// A syntactically canonical anchor token (it resolves against no deployment).
    const FOLLOW_ANCHOR: &str = "anchor:0123456789abcdef:3:e2:\
        abababababababababababababababababababababababababababababababab";

    #[test]
    fn follow_parses_with_defaults_and_refuses_malformed_tokens() {
        let parse = |args: &[&str]| parse_fss_args(args.iter().map(OsString::from));
        let Ok(FssCommand::Follow(follow)) = parse(&[
            "follow",
            "--json",
            "--root",
            "/deploy",
            "--since",
            FOLLOW_ANCHOR,
        ]) else {
            unreachable!("follow with --json, --root, and --since parses");
        };
        assert_eq!(follow.root, PathBuf::from("/deploy"));
        assert_eq!(follow.since.as_str(), FOLLOW_ANCHOR);
        assert_eq!(follow.view, fss_core::AgentView::Pulse);
        assert_eq!(follow.principal.as_str(), "principal:local-operator");
        assert_eq!(follow.max_entries, 64);
        assert_eq!(follow.continuation, None);
        assert!(FssCommand::Follow(follow).is_json());
        let since = format!("--since={FOLLOW_ANCHOR}");
        let Ok(FssCommand::Follow(paged)) = parse(&[
            "follow",
            "--root=/deploy",
            &since,
            "--view=brief",
            "--max-entries",
            "2",
            "--continuation",
            "continuation:sha256:00ff",
            "--principal",
            "principal:agent-7",
            "--json",
        ]) else {
            unreachable!("follow with every option parses");
        };
        assert_eq!(paged.view, fss_core::AgentView::Brief);
        assert_eq!(paged.max_entries, 2);
        assert_eq!(
            paged.continuation.as_deref(),
            Some("continuation:sha256:00ff")
        );
        let refused = |extra: &[&str]| {
            let mut args = vec!["follow", "--json", "--root", "/deploy"];
            args.extend_from_slice(extra);
            parse(&args).err().map(|error| error.error_id())
        };
        let malformed = Some(crate::error::ERR_CLI_MALFORMED_VALUE);
        assert_eq!(refused(&[]), Some(crate::error::ERR_CLI_MISSING_VALUE));
        for bad in [
            "anchor:0123456789abcdef:03:e2:abab",
            "anchor:0123456789ABCDEF:3:e2:\
             abababababababababababababababababababababababababababababababab",
            "commit:3",
        ] {
            assert_eq!(refused(&["--since", bad]), malformed, "{bad}");
        }
        for extra in [
            ["--view", "epistemic_map"],
            ["--max-entries", "0"],
            ["--max-entries", "4097"],
            ["--continuation", "cursor:1"],
            ["--continuation", "continuation:UPPER"],
        ] {
            let mut args = vec!["--since", FOLLOW_ANCHOR];
            args.extend_from_slice(&extra);
            assert_eq!(refused(&args), malformed, "{extra:?}");
        }
    }

    #[test]
    fn registered_crosswalk_spellings_parse_to_their_operations() {
        // Every implemented continuity and read operation parses under the exact cli_command of
        // its crosswalk row (the frozen public registry spelling), and each recorded alias
        // parses to the identical command.
        let parse = |args: &[&str]| parse_fss_args(args.iter().map(OsString::from)).ok();
        let registered = |operation: &str| {
            crate::crosswalk::lookup_by_operation_id(operation)
                .map(|entry| entry.cli_command.split_whitespace().skip(1).collect())
                .unwrap_or_default()
        };
        let orient_tail = ["--json", "--root", "/deploy", "--view", "pulse"];
        let follow_tail = ["--json", "--root", "/deploy", "--since", FOLLOW_ANCHOR];
        let handoff_tail = ["--json", "--root", "/deploy", "--session", "session:abc"];
        let resume_tail = ["--json", "--root", "/deploy", "--handoff", "handoff:abc"];
        let open_tail = [
            "--json",
            "--root",
            "/deploy",
            "--mission",
            "m",
            "--objective",
            "o",
        ];
        let cases: [(&str, &[&str], Vec<&str>); 5] = [
            ("AOP-003", &orient_tail, vec!["orient"]),
            ("AOP-004", &follow_tail, vec!["follow"]),
            ("AOP-012", &handoff_tail, vec!["session", "handoff"]),
            ("AOP-001", &open_tail, vec!["session", "open"]),
            ("AOP-002", &resume_tail, vec!["session", "resume"]),
        ];
        for (operation, tail, alias) in cases {
            let mut spelled: Vec<&str> = registered(operation);
            assert!(!spelled.is_empty(), "{operation} has a crosswalk row");
            spelled.extend_from_slice(tail);
            let parsed = parse(&spelled);
            assert!(parsed.is_some(), "{operation}: {spelled:?} parses");
            let mut aliased = alias;
            aliased.extend_from_slice(tail);
            assert_eq!(parse(&aliased), parsed, "{operation}: {aliased:?}");
        }
        assert!(matches!(
            parse(&["session", "orient", "--json", "--root", "/deploy"]),
            Some(FssCommand::Orient(_))
        ));
        assert!(matches!(
            parse(&[
                "session",
                "follow",
                "--json",
                "--root",
                "/deploy",
                "--since",
                FOLLOW_ANCHOR
            ]),
            Some(FssCommand::Follow(_))
        ));
        assert!(matches!(
            parse(&[
                "handoff",
                "--json",
                "--root",
                "/deploy",
                "--session",
                "session:abc"
            ]),
            Some(FssCommand::Session(SessionCommand::Handoff(_)))
        ));
        // The help lists the registered spellings.
        for spelling in [
            "fss session orient",
            "fss session follow",
            "fss handoff --json",
        ] {
            assert!(help_text().contains(spelling), "{spelling}");
        }
    }

    #[test]
    fn session_subcommands_parse_and_refuse_malformed_input() {
        let parse = |args: &[&str]| parse_fss_args(args.iter().map(OsString::from));
        let Ok(FssCommand::Session(SessionCommand::Open(open))) = parse(&[
            "session",
            "open",
            "--json",
            "--root",
            "/deploy",
            "--mission",
            "watch the east door",
            "--objective",
            "know who entered",
        ]) else {
            unreachable!("session open with its required options parses");
        };
        assert_eq!(open.root, PathBuf::from("/deploy"));
        assert_eq!(open.mission, "watch the east door");
        assert_eq!(open.objective, "know who entered");
        assert_eq!(open.view, fss_core::AgentView::Brief);
        assert_eq!(open.budget_tokens, 1_600);
        assert_eq!(open.principal.as_str(), "principal:local-operator");
        let Ok(FssCommand::Session(SessionCommand::Handoff(handoff))) = parse(&[
            "session",
            "handoff",
            "--root=/deploy",
            "--session",
            "session:abc",
            "--note",
            "shift change",
            "--json",
        ]) else {
            unreachable!("session handoff parses");
        };
        assert_eq!(handoff.session.as_str(), "session:abc");
        assert_eq!(handoff.note.as_deref(), Some("shift change"));
        let Ok(command @ FssCommand::Session(SessionCommand::Resume(_))) = parse(&[
            "session",
            "resume",
            "--json",
            "--root",
            "/deploy",
            "--handoff",
            "handoff:abc",
            "--principal",
            "principal:agent-7",
        ]) else {
            unreachable!("session resume parses");
        };
        assert!(command.is_json());
        let refused = |args: &[&str]| parse(args).err().map(|error| error.error_id());
        assert_eq!(
            refused(&["session"]),
            Some(crate::error::ERR_CLI_MISSING_VALUE)
        );
        assert_eq!(
            refused(&["session", "close", "--json"]),
            Some(crate::error::ERR_CLI_UNKNOWN_COMMAND)
        );
        assert_eq!(
            refused(&[
                "session",
                "open",
                "--json",
                "--root",
                "/d",
                "--objective",
                "o"
            ]),
            Some(crate::error::ERR_CLI_MISSING_VALUE)
        );
        assert_eq!(
            refused(&[
                "session",
                "open",
                "--json",
                "--root",
                "/d",
                "--mission",
                "m",
                "--objective",
                "o",
                "--budget-tokens",
                "0",
            ]),
            Some(crate::error::ERR_CLI_MALFORMED_VALUE)
        );
        assert_eq!(
            refused(&[
                "session",
                "handoff",
                "--json",
                "--root",
                "/d",
                "--session",
                "bad id"
            ]),
            Some(crate::error::ERR_CLI_MALFORMED_VALUE)
        );
        assert_eq!(
            refused(&[
                "session",
                "resume",
                "--root",
                "/d",
                "--handoff",
                "handoff:x"
            ]),
            Some(crate::error::ERR_CLI_MISSING_VALUE)
        );
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
                || std::env::var_os("CARGO_MANIFEST_DIR")
                    .map_or_else(
                        || std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")),
                        std::path::PathBuf::from,
                    )
                    .join(format!("src/bin/{binary}"))
                    .is_dir();
            assert!(
                declared,
                "{binary} named in help must be a real binary target"
            );
        }
    }
}
