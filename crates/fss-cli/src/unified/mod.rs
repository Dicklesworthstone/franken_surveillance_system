#![forbid(unsafe_code)]
//! Cohesive unified `fss <domain> <verb>` command router, flag normalizer, in-process operational
//! executor, sibling companion delegator, and automated ergonomics linter.
//!
//! Semantic plane: `"support"` (transport/presentation routing over existing in-process cognition
//! projections and approval-gated companion binaries; never invents authority).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use fss_core::{EventId, PrincipalId, SensorId, SessionId};

use crate::error::{CliError, ExitIdentity};
use crate::query_cmd::ops_targets::{
    self, CAP_AGENT_QUERY, CAP_OBSERVE_STATUS, CAP_RETENTION_PREPARE, OpsDispatch,
};
use crate::token::ArgToken;

/// Static catalog of unified domains, verbs, flags, and backends.
pub mod domains;
/// Deterministic structured `--help` / `-h` rendering for all `fss` commands.
pub mod help;
/// Automated deterministic CLI ergonomics linter (`lint_unified_cli_surface`).
pub mod linter;
/// Uniform flag translation, canonical ID validation, and preview JSON normalization.
pub mod normalize;

#[cfg(test)]
mod tests;

pub use domains::{
    DomainSpec, FlagSpec, FlagTranslationMode, UNIFIED_DOMAINS, UnifiedBackend, VerbSpec,
    find_domain, find_verb, is_routed_unified_domain,
};
pub use help::{
    TOP_LEVEL_HELP_SPECS, TopLevelHelpSpec, detect_subcommand_help, render_domain_help,
    render_top_level_help, render_verb_help,
};
pub use linter::{LintFinding, LintReport, lint_unified_cli_surface};
pub use normalize::{
    CanonicalIdKind, TranslatedCompanionCall, decode_hold_id_from_storage,
    encode_hold_id_for_storage, normalize_preview_json, translate_companion_args,
    validate_canonical_id,
};

/// Parsed unified `fss <domain> <verb>` invocation ready for execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnifiedCommand {
    /// Canonical domain name (for example `"graph"` or `"hold"`).
    pub domain: &'static str,
    /// Canonical verb name (for example `"coverage"` or `"list"`).
    pub verb: &'static str,
    /// Remaining argument tokens after `<domain> <verb>`.
    pub args: Vec<ArgToken>,
    /// True when machine-readable JSON output was requested or is native to this verb.
    pub json: bool,
}

impl UnifiedCommand {
    /// Returns `true` when stdout output is structured JSON.
    #[must_use]
    pub const fn is_json(&self) -> bool {
        self.json
    }
}

/// Outcome of parsing a routed unified domain invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnifiedParseOutcome {
    /// Structured help text to print on stdout with exit code 0.
    Help(String),
    /// Validated unified command ready for execution.
    Command(UnifiedCommand),
}

/// Parses `tokens` whose leading token is a routed unified domain (`camera`, `media`, `infer`,
/// `event`, `fuse`, `graph`, `hold`, `privacy`, `backup`).
pub fn parse_unified_tokens(tokens: &[ArgToken]) -> Result<UnifiedParseOutcome, CliError> {
    let domain_tok = tokens.first().ok_or_else(|| CliError::MissingValue {
        option: "domain".to_owned(),
        command: None,
        expected: "unified domain name".to_owned(),
    })?;
    let domain = find_domain(domain_tok.as_str()).ok_or_else(|| CliError::UnknownCommand {
        command: domain_tok.raw.clone(),
        context: None,
        index: domain_tok.index,
    })?;

    let Some(second) = tokens.get(1) else {
        let verb_list: Vec<&str> = domain.verbs.iter().map(|v| v.verb).collect();
        return Err(CliError::MissingValue {
            option: domain.name.to_owned(),
            command: Some(domain.name.to_owned()),
            expected: format!(
                "verb for `{}` (one of: {}; or `--help`)",
                domain.name,
                verb_list.join(", ")
            ),
        });
    };

    if matches!(second.as_str(), "--help" | "-h" | "help") {
        if tokens.len() > 2 && second.as_str() == "help" {
            if let Some(target_verb) = find_verb(domain.name, tokens[2].as_str()) {
                return Ok(UnifiedParseOutcome::Help(render_verb_help(target_verb)));
            }
            return Err(CliError::UnknownCommand {
                command: tokens[2].raw.clone(),
                context: Some(domain.name.to_owned()),
                index: tokens[2].index,
            });
        }
        return Ok(UnifiedParseOutcome::Help(render_domain_help(domain)));
    }

    let Some(verb) = find_verb(domain.name, second.as_str()) else {
        if second.as_str().starts_with('-') {
            return Err(CliError::UnknownOption {
                option: second.raw.clone(),
                command: Some(domain.name.to_owned()),
                index: second.index,
            });
        }
        return Err(CliError::UnknownCommand {
            command: second.raw.clone(),
            context: Some(domain.name.to_owned()),
            index: second.index,
        });
    };

    let tail = &tokens[2..];
    if help::has_standalone_help_flag(tail) {
        return Ok(UnifiedParseOutcome::Help(render_verb_help(verb)));
    }

    // Fail fast at parse time on semantic flag mismatches (for example `--root` on an archive-only
    // capture command or malformed canonical IDs).
    if matches!(verb.backend, UnifiedBackend::Companion { .. }) {
        let translated = translate_companion_args(verb, tail)?;
        return Ok(UnifiedParseOutcome::Command(UnifiedCommand {
            domain: domain.name,
            verb: verb.verb,
            args: tail.to_vec(),
            json: translated.json_requested,
        }));
    }

    let json = matches!(
        verb.backend,
        UnifiedBackend::InProcessCameras
            | UnifiedBackend::InProcessGraph { .. }
            | UnifiedBackend::InProcessHolds
            | UnifiedBackend::InProcessPrivacyMasks
            | UnifiedBackend::InProcessVault
            | UnifiedBackend::InProcessNotify
            | UnifiedBackend::InProcessPackArchive
            | UnifiedBackend::InProcessFusionOrCompanion { .. }
    ) || tail.iter().any(|t| t.as_str() == "--json");

    Ok(UnifiedParseOutcome::Command(UnifiedCommand {
        domain: domain.name,
        verb: verb.verb,
        args: tail.to_vec(),
        json,
    }))
}

/// Executes a parsed [`UnifiedCommand`] under cooperative cancellation, using in-process
/// `ops_targets` handlers where available and sibling companion binaries otherwise.
#[must_use]
pub fn execute_unified_with_control(
    cmd: &UnifiedCommand,
    control: &crate::RequestControl<'_>,
) -> (String, ExitIdentity) {
    if control.is_cancelled() {
        return (
            "{\"error\":\"ERR-CLI-READ-CANCELLED-001\",\"message\":\"cancelled before dispatch\"}"
                .to_owned(),
            ExitIdentity::RUNTIME_FAILURE,
        );
    }
    let Some(verb) = find_verb(cmd.domain, cmd.verb) else {
        return (
            format!("unknown unified command `fss {} {}`", cmd.domain, cmd.verb),
            ExitIdentity::UNKNOWN_COMMAND,
        );
    };

    match verb.backend {
        UnifiedBackend::InProcessCameras => execute_camera_list(&cmd.args, control),
        UnifiedBackend::InProcessGraph {
            default_projection,
            default_algorithm,
        } => execute_graph_in_process(
            cmd.verb,
            default_projection,
            default_algorithm,
            &cmd.args,
            control,
        ),
        UnifiedBackend::InProcessHolds => execute_holds_in_process(&cmd.args, control),
        UnifiedBackend::InProcessPrivacyMasks => {
            execute_privacy_list_in_process(&cmd.args, control)
        }
        UnifiedBackend::InProcessVault => {
            crate::vault_cmd::execute_vault_command(cmd.verb, &cmd.args, control)
        }
        UnifiedBackend::InProcessNotify => {
            crate::notify_cmd::execute_notify_command(cmd.verb, &cmd.args, control)
        }
        UnifiedBackend::InProcessPackArchive => {
            crate::pack_archive_cmd::execute_pack_archive_command(cmd.verb, &cmd.args, control)
        }
        UnifiedBackend::InProcessFusionOrCompanion {
            binary,
            ablation_mode,
        } => execute_fusion_or_companion(verb, binary, ablation_mode, &cmd.args, control),
        UnifiedBackend::Companion { .. } => execute_companion(verb, &cmd.args, control),
        UnifiedBackend::InProcessSite | UnifiedBackend::InProcessMigrate => (
            format!(
                "`fss {} {}` must be dispatched through its native FssCommand variant",
                cmd.domain, cmd.verb
            ),
            ExitIdentity::RUNTIME_FAILURE,
        ),
    }
}

/// Shared key-value option extractor for in-process read-only unified commands.
struct ParsedOpsOpts {
    root: PathBuf,
    principal: PrincipalId,
    session_id: Option<SessionId>,
    site_id: Option<String>,
    camera_id: Option<String>,
    sensor: Option<SensorId>,
    projection: Option<String>,
    algorithm: Option<String>,
    root_node: Option<String>,
    event_id: Option<EventId>,
    without_sensors: Vec<String>,
    without_domains: Vec<String>,
    coverage: String,
    attested_now_ns: Option<(i128, i128)>,
    capabilities: BTreeSet<String>,
}

fn parse_in_process_opts(
    label: &str,
    tokens: &[ArgToken],
    default_caps: &[&str],
) -> Result<ParsedOpsOpts, String> {
    let mut root: Option<PathBuf> = None;
    let mut principal_raw: Option<String> = None;
    let mut session_raw: Option<String> = None;
    let mut site_id: Option<String> = None;
    let mut camera_id: Option<String> = None;
    let mut sensor_raw: Option<String> = None;
    let mut projection: Option<String> = None;
    let mut algorithm: Option<String> = None;
    let mut root_node: Option<String> = None;
    let mut event_id_raw: Option<String> = None;
    let mut without_sensors = Vec::new();
    let mut without_domains = Vec::new();
    let mut coverage = "complete".to_owned();
    let mut attested_earliest: Option<i128> = None;
    let mut attested_latest: Option<i128> = None;
    let mut capabilities: BTreeSet<String> = default_caps.iter().map(|s| (*s).to_owned()).collect();

    let mut idx = 0_usize;
    while idx < tokens.len() {
        let raw = tokens[idx].as_str();
        if raw == "--json" {
            idx += 1;
            continue;
        }
        let (flag, val) = if let Some((k, v)) = raw.split_once('=') {
            if v.is_empty() {
                return Err(format!("{label}: missing value for `{k}`"));
            }
            (k, v.to_owned())
        } else {
            let next = tokens
                .get(idx + 1)
                .ok_or_else(|| format!("{label}: missing value for `{raw}`"))?;
            idx += 1;
            (raw, next.raw.clone())
        };
        idx += 1;
        match flag {
            "--root" => root = Some(PathBuf::from(val)),
            "--principal" => principal_raw = Some(val),
            "--session" => session_raw = Some(val),
            "--site" | "--site-id" => site_id = Some(val),
            "--camera-id" => camera_id = Some(val),
            "--sensor" => sensor_raw = Some(val),
            "--projection" => projection = Some(val),
            "--algorithm" => algorithm = Some(val),
            "--root-node" => root_node = Some(val),
            "--event-id" => event_id_raw = Some(val),
            "--without-sensor" => without_sensors.push(val),
            "--without-domain" => without_domains.push(val),
            "--coverage" => coverage = val,
            "--attested-now-ns" => {
                let (lo, hi) = val
                    .split_once(':')
                    .ok_or_else(|| format!("{label}: --attested-now-ns expects EARLIEST:LATEST"))?;
                attested_earliest =
                    Some(lo.parse::<i128>().map_err(|_| {
                        format!("{label}: invalid earliest_ns in --attested-now-ns")
                    })?);
                attested_latest = Some(
                    hi.parse::<i128>()
                        .map_err(|_| format!("{label}: invalid latest_ns in --attested-now-ns"))?,
                );
            }
            "--attested-earliest-ns" => {
                attested_earliest = Some(
                    val.parse::<i128>()
                        .map_err(|_| format!("{label}: invalid --attested-earliest-ns"))?,
                );
            }
            "--attested-latest-ns" => {
                attested_latest = Some(
                    val.parse::<i128>()
                        .map_err(|_| format!("{label}: invalid --attested-latest-ns"))?,
                );
            }
            "--capability" => {
                capabilities.insert(val);
            }
            other => return Err(format!("{label}: unknown option `{other}`; use `--help`")),
        }
    }

    let root = root.ok_or_else(|| format!("{label}: required option `--root <deployment-dir>`"))?;
    let principal =
        PrincipalId::parse(principal_raw.unwrap_or_else(|| "principal:local-operator".to_owned()))
            .map_err(|_| format!("{label}: invalid `--principal` identity"))?;
    let session_id = session_raw
        .map(|s| SessionId::parse(s).map_err(|_| format!("{label}: invalid `--session` identity")))
        .transpose()?;
    let sensor = sensor_raw
        .map(|s| SensorId::parse(s).map_err(|_| format!("{label}: invalid `--sensor` identity")))
        .transpose()?;
    let event_id = event_id_raw
        .map(|s| EventId::parse(s).map_err(|_| format!("{label}: invalid `--event-id` identity")))
        .transpose()?;
    let attested_now_ns = match (attested_earliest, attested_latest) {
        (Some(a), Some(b)) => Some((a, b)),
        (None, None) => None,
        _ => {
            return Err(format!(
                "{label}: supply both --attested-earliest-ns and --attested-latest-ns"
            ));
        }
    };

    Ok(ParsedOpsOpts {
        root,
        principal,
        session_id,
        site_id,
        camera_id,
        sensor,
        projection,
        algorithm,
        root_node,
        event_id,
        without_sensors,
        without_domains,
        coverage,
        attested_now_ns,
        capabilities,
    })
}

fn malformed_json(detail: &str) -> (String, ExitIdentity) {
    let out = crate::json_output::object(&[
        ("schema", crate::json_output::string("fss.cli_error.v1")),
        (
            "error_id",
            crate::json_output::string(crate::error::ERR_CLI_MALFORMED_VALUE),
        ),
        ("message", crate::json_output::string(detail)),
    ]);
    (out, ExitIdentity::MALFORMED_VALUE)
}

fn execute_camera_list(
    tokens: &[ArgToken],
    control: &crate::RequestControl<'_>,
) -> (String, ExitIdentity) {
    let opts = match parse_in_process_opts(
        "fss camera list",
        tokens,
        &[CAP_AGENT_QUERY, CAP_OBSERVE_STATUS],
    ) {
        Ok(o) => o,
        Err(err) => return malformed_json(&err),
    };
    let req = ops_targets::cameras::CamerasQueryRequest {
        root: opts.root,
        principal: opts.principal,
        session_id: opts.session_id,
        camera_id: opts.camera_id,
        site_id: opts.site_id,
        granted_capabilities: opts.capabilities,
    };
    ops_targets::execute_with_control(&OpsDispatch::Cameras(req), control)
}

fn execute_graph_in_process(
    verb_name: &str,
    default_projection: &str,
    default_algorithm: &str,
    tokens: &[ArgToken],
    control: &crate::RequestControl<'_>,
) -> (String, ExitIdentity) {
    let label = format!("fss graph {verb_name}");
    let opts = match parse_in_process_opts(&label, tokens, &[CAP_AGENT_QUERY]) {
        Ok(o) => o,
        Err(err) => return malformed_json(&err),
    };
    let projection = match ops_targets::graph::GraphProjectionKind::parse(
        opts.projection.as_deref().unwrap_or(default_projection),
    ) {
        Ok(p) => p,
        Err(err) => return malformed_json(&err.to_string()),
    };
    let algorithm = match ops_targets::graph::GraphAlgorithmKind::parse(
        opts.algorithm.as_deref().unwrap_or(default_algorithm),
    ) {
        Ok(a) => a,
        Err(err) => return malformed_json(&err.to_string()),
    };
    let req = ops_targets::graph::GraphQueryRequest {
        root: opts.root,
        principal: opts.principal,
        session_id: opts.session_id,
        projection,
        algorithm,
        root_node: opts.root_node,
        granted_capabilities: opts.capabilities,
    };
    ops_targets::execute_with_control(&OpsDispatch::Graph(req), control)
}

fn execute_holds_in_process(
    tokens: &[ArgToken],
    control: &crate::RequestControl<'_>,
) -> (String, ExitIdentity) {
    let opts = match parse_in_process_opts(
        "fss hold list",
        tokens,
        &[CAP_AGENT_QUERY, CAP_RETENTION_PREPARE],
    ) {
        Ok(o) => o,
        Err(err) => return malformed_json(&err),
    };
    let req = ops_targets::holds_masks::HoldsQueryRequest {
        root: opts.root,
        principal: opts.principal,
        session_id: opts.session_id,
        sensor: opts.sensor,
        attested_now_ns: opts.attested_now_ns,
        granted_capabilities: opts.capabilities,
    };
    ops_targets::execute_with_control(&OpsDispatch::Holds(req), control)
}

fn execute_privacy_list_in_process(
    tokens: &[ArgToken],
    control: &crate::RequestControl<'_>,
) -> (String, ExitIdentity) {
    let opts = match parse_in_process_opts("fss privacy list", tokens, &[CAP_AGENT_QUERY]) {
        Ok(o) => o,
        Err(err) => return malformed_json(&err),
    };
    let req = ops_targets::holds_masks::PrivacyMasksQueryRequest {
        root: opts.root,
        principal: opts.principal,
        session_id: opts.session_id,
        sensor: opts.sensor,
        granted_capabilities: opts.capabilities,
    };
    ops_targets::execute_with_control(&OpsDispatch::PrivacyMasks(req), control)
}

fn execute_fusion_or_companion(
    verb: &VerbSpec,
    binary: &'static str,
    ablation_mode: bool,
    tokens: &[ArgToken],
    control: &crate::RequestControl<'_>,
) -> (String, ExitIdentity) {
    let uses_companion_file = tokens.iter().any(|t| {
        let s = t.as_str();
        s == "--query"
            || s.starts_with("--query=")
            || s == "--sequence"
            || s.starts_with("--sequence=")
    });
    if uses_companion_file {
        let companion_verb = VerbSpec {
            backend: UnifiedBackend::Companion {
                binary,
                prefix_args: &[],
                flag_mode: domains::FlagTranslationMode::Standard,
                companion_accepts_json: false,
            },
            ..*verb
        };
        return execute_companion(&companion_verb, tokens, control);
    }

    let label = format!("fss fuse {}", verb.verb);
    let opts = match parse_in_process_opts(&label, tokens, &[CAP_AGENT_QUERY]) {
        Ok(o) => o,
        Err(err) => return malformed_json(&err),
    };
    if ablation_mode && opts.without_sensors.is_empty() && opts.without_domains.is_empty() {
        return malformed_json(
            "fss fuse ablate requires at least one `--without-sensor <id>` or `--without-domain <domain>`",
        );
    }
    let req = ops_targets::fusion::FusionQueryRequest {
        root: opts.root,
        principal: opts.principal,
        session_id: opts.session_id,
        event_id: opts.event_id,
        evidence: Vec::new(),
        prior: (-500, -400),
        coverage_state: opts.coverage,
        alert_threshold: 1000,
        retain_threshold: 0,
        reject_threshold: -1000,
        min_independent_support: 2,
        without_sensors: opts.without_sensors,
        without_domains: opts.without_domains,
        granted_capabilities: opts.capabilities,
    };
    ops_targets::execute_with_control(&OpsDispatch::Fusion(req), control)
}

/// Resolves a sibling companion binary strictly beside the current executable (or one directory
/// above when invoked inside Cargo's `target/*/deps/` test harness), never consulting ambient PATH.
#[must_use]
pub fn resolve_sibling_binary(binary: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let file_name = format!("{binary}{}", std::env::consts::EXE_SUFFIX);
    let direct = dir.join(&file_name);
    if direct.is_file() {
        return Some(direct);
    }
    if dir.file_name().is_some_and(|name| name == "deps")
        && let Some(parent) = dir.parent()
    {
        let sibling = parent.join(&file_name);
        if sibling.is_file() {
            return Some(sibling);
        }
    }
    None
}

fn execute_companion(
    verb: &VerbSpec,
    tokens: &[ArgToken],
    control: &crate::RequestControl<'_>,
) -> (String, ExitIdentity) {
    if control.is_cancelled() {
        return (
            "{\"error\":\"ERR-CLI-READ-CANCELLED-001\",\"message\":\"cancelled before companion dispatch\"}"
                .to_owned(),
            ExitIdentity::RUNTIME_FAILURE,
        );
    }
    let translated = match translate_companion_args(verb, tokens) {
        Ok(call) => call,
        Err(err) => return malformed_json(&err.to_string()),
    };
    let Some(bin_path) = resolve_sibling_binary(translated.binary) else {
        return (
            crate::json_output::object(&[
                ("schema", crate::json_output::string("fss.cli_error.v1")),
                (
                    "error_id",
                    crate::json_output::string(crate::error::ERR_CLI_RUNTIME_FAILURE),
                ),
                (
                    "message",
                    crate::json_output::string(&format!(
                        "companion binary `{}` not found beside `fss` executable",
                        translated.binary
                    )),
                ),
            ]),
            ExitIdentity::RUNTIME_FAILURE,
        );
    };

    match run_companion_process(&bin_path, &translated, verb.normalizes_preview) {
        Ok(result) => result,
        Err(err) => (
            crate::json_output::object(&[
                ("schema", crate::json_output::string("fss.cli_error.v1")),
                (
                    "error_id",
                    crate::json_output::string(crate::error::ERR_CLI_RUNTIME_FAILURE),
                ),
                ("message", crate::json_output::string(&err)),
            ]),
            ExitIdentity::RUNTIME_FAILURE,
        ),
    }
}

fn run_companion_process(
    bin_path: &Path,
    translated: &TranslatedCompanionCall,
    normalize_preview: bool,
) -> Result<(String, ExitIdentity), String> {
    let output = Command::new(bin_path)
        .args(&translated.args)
        .output()
        .map_err(|err| format!("failed to launch `{}`: {err}", translated.binary))?;
    let stdout = String::from_utf8_lossy(&output.stdout)
        .trim_end_matches('\n')
        .to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr)
        .trim_end_matches('\n')
        .to_owned();
    if output.status.success() {
        let rendered = if normalize_preview {
            normalize_preview_json(&stdout, Some(&translated.unified_rerun_prefix))
        } else {
            stdout
        };
        Ok((rendered, ExitIdentity::SUCCESS))
    } else {
        let code = output.status.code().unwrap_or(1);
        let exit_id = if code == 2 {
            ExitIdentity::MALFORMED_VALUE
        } else {
            ExitIdentity::RUNTIME_FAILURE
        };
        let body = if !stderr.is_empty() { stderr } else { stdout };
        Ok((body, exit_id))
    }
}
