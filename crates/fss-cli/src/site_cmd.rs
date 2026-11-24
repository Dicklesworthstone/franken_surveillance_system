#![forbid(unsafe_code)]
//! Site onboarding: inventory, recorded observations, capture plans and approved native probes.
//!
//! Host inputs are explicitly named manifests, receipts and recorded protocol evidence.
//! UniFi planning reads exact protected exports and checks existing output parents.
//! Planning never reads credential files, contacts cameras, or inspects rights stores.
//! The pure compiler owns plan semantics; this module owns bounded CLI/file presentation.
//! An exactly approved probe delegates network/credential ownership to `site_probe`.

use std::collections::BTreeMap;
use std::fs::{self, Metadata, OpenOptions};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fss_core::PrincipalId;
use fss_core::json_input::MAX_INPUT_BYTES;
use fss_daemon::{
    DaemonError, DaemonStartConfig, DaemonSupervisor, SiteManifest as DaemonSiteManifest,
    query_live_daemon_status, render_live_status_json, render_stop_accepted_json,
    request_live_daemon_stop,
};
use fss_reference::site::{MAX_SITE_SOURCES, SiteManifest, parse_manifest, parse_probe_receipts};

use crate::agent_json::{array, object, string};
use crate::error::{CliError, ExitIdentity};
use crate::orient_cmd::{collect_options_with_repeatable, take};
use crate::site_plan::{SitePlanOptions, compile, compile_selected};
use crate::site_probe::{SiteProbeOptions, execute_probe, parse_probe_args};
use crate::token::ArgToken;

/// Schema of the bounded, non-disclosing manifest validation summary.
pub const SITE_VALIDATION_SCHEMA: &str = "fss.site_validation.v1";
/// Complete site command output ceiling; results are refused rather than truncated.
pub const MAX_SITE_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_INPUT_OPERATIONS: usize = 1024;
const INPUT_ERROR: &str = "ERR-SITE-INPUT-001";
const OUTPUT_ERROR: &str = "ERR-SITE-OUTPUT-BOUND-001";

/// Parsed options for `fss site run`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteRunArgs {
    /// Path to the secret-free daemon site manifest (`site.json`).
    pub manifest: PathBuf,
    /// Optional deployment root directory overriding `manifest.deployment_root`.
    pub root: Option<PathBuf>,
    /// Optional `fss-vault` directory for scoped camera credential resolution at startup.
    pub vault_dir: Option<PathBuf>,
    /// Optional owner-only (`0600`) passphrase file unlocking `vault_dir` once during startup.
    pub passphrase_file: Option<PathBuf>,
    /// Optional bounded supervision tick count for finite / CI runs.
    pub once_ticks: Option<u64>,
    /// Inter-tick poll interval in milliseconds (default `50`).
    pub tick_ms: u64,
    /// Emit structured JSON output instead of human-readable text.
    pub json: bool,
}

/// Parsed options for `fss site status`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteStatusArgs {
    /// Deployment root directory containing `<root>/run/daemon.sock`.
    pub root: PathBuf,
    /// Optional explicit site identifier override.
    pub site_id: Option<String>,
    /// Emit structured JSON output instead of human-readable text.
    pub json: bool,
}

/// Parsed options for `fss site stop`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteStopArgs {
    /// Deployment root directory containing `<root>/run/daemon.sock`.
    pub root: PathBuf,
    /// Optional explicit site identifier override.
    pub site_id: Option<String>,
    /// Emit structured JSON output instead of human-readable text.
    pub json: bool,
}

/// Operator-only site commands. Onboarding variants never grant capture authority; `run`/`status`/`stop`
/// operate the local always-on `fss-daemon` supervisor over owner-owned roots and `fss-ipc` UDS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SiteCommand {
    /// Measure a supplied native DESCRIBE response and RTPdump into a probe receipt.
    ProbeFile(Box<crate::site_probe_cmd::ProbeFileArgs>),
    /// Inspect or approve one bounded native RTSP observation, without recording.
    Probe {
        /// Exact site inventory to read before approval revalidation.
        manifest: PathBuf,
        /// Exact selected source, protocol, observation budget and approval.
        options: SiteProbeOptions,
    },
    /// Parse one manifest and return its canonical identity and bounded source inventory.
    Validate {
        /// The only file the validation request may read.
        manifest: PathBuf,
    },
    /// Compile one complete set of native capture plans, atomically.
    Plan {
        /// Exact manifest file to read.
        manifest: PathBuf,
        /// Exact file containing the complete array of supplied probe receipts.
        probes: PathBuf,
        /// Optional exact bindings for protected UniFi exports and rendition selection.
        unifi_bindings: Option<PathBuf>,
        /// Optional exact historical ONVIF handoffs and independently pinned RTSP scope.
        onvif_bindings: Option<PathBuf>,
        /// Explicit source subset, or the complete manifest inventory when omitted.
        source_ids: Option<Vec<String>>,
        /// Explicit identity epoch, output destinations, principal and picture budget.
        options: SitePlanOptions,
    },
    /// Run the always-on Asupersync-owned `fss-daemon` supervising all cameras in `site.json`.
    Run(Box<SiteRunArgs>),
    /// Query live daemon status over the local `fss-ipc` Unix domain socket.
    Status(SiteStatusArgs),
    /// Request graceful `request -> drain -> finalize` shutdown over `fss-ipc`.
    Stop(SiteStopArgs),
}

impl SiteCommand {
    /// Returns true if JSON output is requested for this site subcommand.
    #[must_use]
    pub const fn is_json(&self) -> bool {
        match self {
            Self::ProbeFile(_) | Self::Probe { .. } | Self::Validate { .. } | Self::Plan { .. } => {
                true
            }
            Self::Run(args) => args.json,
            Self::Status(args) => args.json,
            Self::Stop(args) => args.json,
        }
    }
}

/// Parse site validation, recorded/native probing, planning, or daemon control with exact exhaustion.
pub fn parse_site_args(tokens: &[ArgToken]) -> Result<SiteCommand, CliError> {
    let action = tokens.get(1).ok_or_else(|| CliError::MissingValue {
        option: "site".to_owned(),
        command: Some("site".to_owned()),
        expected: "validate, plan, probe, probe-file, run, status or stop".to_owned(),
    })?;
    if action.as_str() == "run" {
        return parse_site_run_args(tokens).map(|a| SiteCommand::Run(Box::new(a)));
    }
    if action.as_str() == "status" {
        return parse_site_root_args("site status", tokens).map(|(root, site_id, json)| {
            SiteCommand::Status(SiteStatusArgs {
                root,
                site_id,
                json,
            })
        });
    }
    if action.as_str() == "stop" {
        return parse_site_root_args("site stop", tokens).map(|(root, site_id, json)| {
            SiteCommand::Stop(SiteStopArgs {
                root,
                site_id,
                json,
            })
        });
    }
    if action.as_str() == "probe" {
        let (manifest, options) = parse_probe_args(tokens)?;
        return Ok(SiteCommand::Probe { manifest, options });
    }
    if action.as_str() == "probe-file" {
        return crate::site_probe_cmd::parse(tokens)
            .map(|args| SiteCommand::ProbeFile(Box::new(args)));
    }
    let command = match action.as_str() {
        "validate" => "site validate",
        "plan" => "site plan",
        _ => {
            return Err(CliError::UnknownCommand {
                command: "site: unsupported subcommand".to_owned(),
                context: Some("site".to_owned()),
                index: action.index,
            });
        }
    };
    let allowed: &[&str] = if action.as_str() == "validate" {
        &["--manifest"]
    } else {
        &[
            "--manifest",
            "--probes",
            "--unifi-bindings",
            "--onvif-bindings",
            "--source",
            "--archive-root",
            "--pins-root",
            "--epoch",
            "--stop-after-pictures",
            "--principal",
        ]
    };
    // collect_options skips its command token; original argument indices remain intact.
    let values = collect_options_with_repeatable(
        command,
        &tokens[1..],
        allowed,
        &[("--source", MAX_SITE_SOURCES)],
    )?;
    let required = |name: &str| -> Result<String, CliError> {
        take(&values, name)
            .map(|(_, value, _)| value.clone())
            .ok_or_else(|| CliError::MissingValue {
                option: name.to_owned(),
                command: Some(command.to_owned()),
                expected: format!("a value for {name}"),
            })
    };
    let number = |name: &str| -> Result<u64, CliError> {
        let text = required(name)?;
        let parsed = text.parse::<u64>().ok();
        match parsed {
            Some(value) if value != 0 && value.to_string() == text => Ok(value),
            _ => Err(CliError::MalformedValue {
                option: name.to_owned(),
                value: "[invalid integer]".to_owned(),
                reason: "expected a positive canonical decimal integer".to_owned(),
                command: Some(command.to_owned()),
                index: take(&values, name).map_or(0, |(_, _, index)| *index),
            }),
        }
    };
    let manifest = PathBuf::from(required("--manifest")?);
    if action.as_str() == "validate" {
        return Ok(SiteCommand::Validate { manifest });
    }
    let source_ids: Vec<_> = values
        .iter()
        .filter(|(name, _, _)| name == "--source")
        .map(|(_, value, _)| value.clone())
        .collect();
    Ok(SiteCommand::Plan {
        manifest,
        probes: PathBuf::from(required("--probes")?),
        unifi_bindings: take(&values, "--unifi-bindings").map(|(_, value, _)| PathBuf::from(value)),
        onvif_bindings: take(&values, "--onvif-bindings").map(|(_, value, _)| PathBuf::from(value)),
        source_ids: (!source_ids.is_empty()).then_some(source_ids),
        options: SitePlanOptions {
            epoch: number("--epoch")?,
            archive_root: PathBuf::from(required("--archive-root")?),
            pins_root: PathBuf::from(required("--pins-root")?),
            principal: take(&values, "--principal").map_or_else(
                || "principal:local-operator".to_owned(),
                |(_, value, _)| value.clone(),
            ),
            stop_after_pictures: number("--stop-after-pictures")?,
        },
    })
}

/// A read capability restricted to the input documents named in one operator command.
/// Every native file boundary spends this request's finite operation budget.
pub(crate) struct InputAuthority {
    paths: BTreeMap<PathBuf, usize>,
    operations: usize,
    bytes: usize,
}

impl InputAuthority {
    fn new(command: &SiteCommand) -> Self {
        match command {
            SiteCommand::Validate { manifest } | SiteCommand::Probe { manifest, .. } => {
                Self::for_inputs(&[(manifest, MAX_INPUT_BYTES)])
            }
            SiteCommand::Plan {
                manifest,
                probes,
                unifi_bindings,
                onvif_bindings,
                ..
            } => {
                let mut inputs = vec![
                    (manifest.as_path(), MAX_INPUT_BYTES),
                    (probes.as_path(), MAX_INPUT_BYTES),
                ];
                if let Some(bindings) = unifi_bindings {
                    inputs.push((
                        bindings.as_path(),
                        crate::site_unifi::MAX_SITE_UNIFI_BINDINGS_BYTES,
                    ));
                }
                if let Some(bindings) = onvif_bindings {
                    inputs.push((
                        bindings.as_path(),
                        crate::site_onvif::MAX_SITE_ONVIF_BINDINGS_BYTES,
                    ));
                }
                Self::for_inputs(&inputs)
            }
            SiteCommand::ProbeFile(args) => Self::for_inputs(&args.input_scopes()),
            SiteCommand::Run(args) => Self::for_inputs(&[(&args.manifest, MAX_INPUT_BYTES)]),
            SiteCommand::Status(_) | SiteCommand::Stop(_) => Self::for_inputs(&[]),
        }
    }

    pub(crate) fn for_inputs(inputs: &[(&Path, usize)]) -> Self {
        let mut paths = BTreeMap::new();
        let mut bytes = 0usize;
        for (path, bound) in inputs {
            // Aliased names retain the stricter admission ceiling; one role cannot
            // widen the authority of another input role.
            paths
                .entry((*path).to_path_buf())
                .and_modify(|old: &mut usize| *old = (*old).min(*bound))
                .or_insert(*bound);
            bytes = bytes.saturating_add(bound.saturating_add(1));
        }
        Self {
            paths,
            operations: MAX_INPUT_OPERATIONS,
            bytes,
        }
    }

    fn boundary(&mut self, path: &Path) -> Result<(), &'static str> {
        if !self.paths.contains_key(path) || self.operations == 0 {
            return Err(INPUT_ERROR);
        }
        self.operations -= 1;
        Ok(())
    }

    pub(crate) fn read(&mut self, path: &Path) -> Result<Vec<u8>, &'static str> {
        if !cfg!(any(target_os = "linux", target_os = "macos")) {
            // The admitted open must refuse raced symlinks and nonblocking special
            // files. Other targets have no declared native open contract here.
            return Err(INPUT_ERROR);
        }
        let maximum = *self.paths.get(path).ok_or(INPUT_ERROR)?;
        self.boundary(path)?;
        let before = fs::symlink_metadata(path).map_err(|_| INPUT_ERROR)?;
        if !before.is_file() || before.len() == 0 || before.len() > maximum as u64 {
            return Err(INPUT_ERROR);
        }
        let mut options = OpenOptions::new();
        options.read(true);
        // Nonblocking open plus no-follow prevents a raced symlink/FIFO replacement from
        // turning a bounded control-document read into an unintended or unbounded read.
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(0o4000 | 0o400000); // O_NONBLOCK | O_NOFOLLOW.
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(0x0004 | 0x0100); // O_NONBLOCK | O_NOFOLLOW.
        }
        self.boundary(path)?;
        let mut file = options.open(path).map_err(|_| INPUT_ERROR)?;
        self.boundary(path)?;
        let opened = file.metadata().map_err(|_| INPUT_ERROR)?;
        if !same_file(&before, &opened) {
            return Err(INPUT_ERROR);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(before.len() as usize)
            .map_err(|_| INPUT_ERROR)?;
        let mut chunk = [0_u8; 16 * 1024];
        loop {
            self.boundary(path)?;
            let count = match file.read(&mut chunk) {
                Ok(count) => count,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return Err(INPUT_ERROR),
            };
            if count == 0 {
                break;
            }
            self.bytes = self.bytes.checked_sub(count).ok_or(INPUT_ERROR)?;
            if bytes.len().checked_add(count).ok_or(INPUT_ERROR)? > maximum {
                return Err(INPUT_ERROR);
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
        self.boundary(path)?;
        let after = file.metadata().map_err(|_| INPUT_ERROR)?;
        self.boundary(path)?;
        let named = fs::symlink_metadata(path).map_err(|_| INPUT_ERROR)?;
        if !same_file(&before, &after)
            || !same_file(&before, &named)
            || bytes.len() != before.len() as usize
        {
            return Err(INPUT_ERROR);
        }
        Ok(bytes)
    }
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    if !right.is_file()
        || left.len() != right.len()
        || left.modified().ok() != right.modified().ok()
    {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.mode() == right.mode()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        left.created().ok() == right.created().ok()
    }
}

/// Read exactly the named control inputs and return a complete plan, daemon result, or safe diagnostic.
#[must_use]
pub fn execute_site(command: &SiteCommand) -> (String, ExitIdentity) {
    match command {
        SiteCommand::ProbeFile(args) => return crate::site_probe_cmd::execute(args),
        SiteCommand::Run(args) => return execute_site_run(args),
        SiteCommand::Status(args) => return execute_site_status(args),
        SiteCommand::Stop(args) => return execute_site_stop(args),
        SiteCommand::Validate { .. } | SiteCommand::Plan { .. } | SiteCommand::Probe { .. } => {}
    }
    let mut authority = InputAuthority::new(command);
    let manifest_path = match command {
        SiteCommand::Validate { manifest }
        | SiteCommand::Plan { manifest, .. }
        | SiteCommand::Probe { manifest, .. } => manifest,
        SiteCommand::ProbeFile(args) => &args.manifest,
        SiteCommand::Run(args) => &args.manifest,
        SiteCommand::Status(args) => &args.root,
        SiteCommand::Stop(args) => &args.root,
    };
    let bytes = match authority.read(manifest_path) {
        Ok(bytes) => bytes,
        Err(code) => {
            return refusal(
                code,
                "manifest input could not be read within its bounds",
                None,
            );
        }
    };
    let manifest = match parse_manifest(&bytes) {
        Ok(manifest) => manifest,
        Err(error) => return refusal(error.code(), &error.to_string(), None),
    };
    let output = match command {
        SiteCommand::Probe { options, .. } => return execute_probe(&manifest, options),
        SiteCommand::ProbeFile(args) => return crate::site_probe_cmd::execute(args),
        SiteCommand::Run(args) => return execute_site_run(args),
        SiteCommand::Status(args) => return execute_site_status(args),
        SiteCommand::Stop(args) => return execute_site_stop(args),
        SiteCommand::Validate { .. } => match render_validation(&manifest) {
            Ok(output) => output,
            Err(error) => return refusal(error.code(), &error.to_string(), None),
        },
        SiteCommand::Plan {
            probes,
            unifi_bindings,
            onvif_bindings,
            source_ids,
            options,
            ..
        } => {
            let bytes = match authority.read(probes) {
                Ok(bytes) => bytes,
                Err(code) => {
                    return refusal(
                        code,
                        "probe input could not be read within its bounds",
                        None,
                    );
                }
            };
            let receipts = match parse_probe_receipts(&bytes) {
                Ok(receipts) => receipts,
                Err(error) => return refusal(error.code(), &error.to_string(), None),
            };
            let unifi_bytes = if let Some(path) = unifi_bindings {
                let bytes = match authority.read(path) {
                    Ok(bytes) => bytes,
                    Err(code) => {
                        return refusal(
                            code,
                            "UniFi binding input could not be read within its bounds",
                            None,
                        );
                    }
                };
                Some(bytes)
            } else {
                None
            };
            let result = if let Some(path) = onvif_bindings {
                let bytes = match authority.read(path) {
                    Ok(bytes) => bytes,
                    Err(code) => {
                        return refusal(
                            code,
                            "ONVIF binding input could not be read within its bounds",
                            None,
                        );
                    }
                };
                if let Some(source_ids) = source_ids {
                    crate::site_unifi::compile_selected_with_onvif_bindings(
                        &manifest,
                        &receipts,
                        options,
                        source_ids,
                        &bytes,
                        unifi_bytes.as_deref(),
                    )
                } else {
                    crate::site_unifi::compile_with_onvif_bindings(
                        &manifest,
                        &receipts,
                        options,
                        &bytes,
                        unifi_bytes.as_deref(),
                    )
                }
            } else if let Some(bytes) = unifi_bytes {
                if let Some(source_ids) = source_ids {
                    crate::site_unifi::compile_selected_from_bindings(
                        &manifest, &receipts, options, source_ids, &bytes,
                    )
                } else {
                    crate::site_unifi::compile_from_bindings(&manifest, &receipts, options, &bytes)
                }
            } else if let Some(source_ids) = source_ids {
                compile_selected(&manifest, &receipts, options, source_ids)
            } else {
                compile(&manifest, &receipts, options)
            };
            match result {
                Ok(plan) => plan.render_json(),
                Err(error) => return refusal(error.code, error.reason, error.source_index),
            }
        }
    };
    if output.len() > MAX_SITE_OUTPUT_BYTES {
        return refusal(
            OUTPUT_ERROR,
            "complete site result exceeds its output bound",
            None,
        );
    }
    (output, ExitIdentity::SUCCESS)
}

fn render_validation(manifest: &SiteManifest) -> Result<String, fss_reference::site::SiteError> {
    let sources: Vec<_> = manifest
        .sources
        .iter()
        .map(|source| {
            object(&[
                ("source_id", string(&source.source_id)),
                ("kind", string(source.kind.as_str())),
                ("stream_role", string(source.stream_role.as_str())),
            ])
        })
        .collect();
    Ok(object(&[
        ("schema", string(SITE_VALIDATION_SCHEMA)),
        ("status", string("validated")),
        ("site_id", string(&manifest.site_id)),
        ("generation", manifest.generation.to_string()),
        ("manifest_digest", string(&manifest.digest()?.to_text())),
        ("source_count", manifest.sources.len().to_string()),
        ("sources", array(&sources)),
        ("device_contacted", "false".to_owned()),
        ("credentials_read", "false".to_owned()),
        ("rights_verdict_verified", "false".to_owned()),
        ("capture_authorized", "false".to_owned()),
    ]))
}

pub(crate) fn refusal(
    code: &str,
    reason: &str,
    source_index: Option<usize>,
) -> (String, ExitIdentity) {
    let exit = ExitIdentity::MALFORMED_VALUE;
    (
        object(&[
            ("schema", string("fss.site_diagnostic.v1")),
            ("phase", string("execution")),
            ("binary", string("fss")),
            ("command", string("site")),
            ("error_id", string(code)),
            ("exit_id", string(exit.identifier)),
            ("exit_code", exit.code.to_string()),
            ("reason", string(reason)),
            (
                "source_index",
                source_index.map_or_else(|| "null".to_owned(), |i| i.to_string()),
            ),
            ("device_contacted", "false".to_owned()),
            ("credentials_read", "false".to_owned()),
            ("effect_started", "false".to_owned()),
            ("partial_plan", "false".to_owned()),
        ]),
        exit,
    )
}

type ParsedDaemonFlags = (BTreeMap<String, (String, usize)>, bool);

fn parse_daemon_flags(
    command: &str,
    tokens: &[ArgToken],
    allowed: &[&str],
) -> Result<ParsedDaemonFlags, CliError> {
    let (cmd, mut opts, mut json, mut idx) =
        (Some(command.to_owned()), BTreeMap::new(), false, 2_usize);
    while idx < tokens.len() {
        let (arg, s) = (&tokens[idx], tokens[idx].as_str());
        if s == "--json" {
            if json {
                return Err(CliError::DuplicateOption {
                    option: "--json".to_owned(),
                    command: cmd,
                    index: arg.index,
                });
            }
            json = true;
            idx += 1;
            continue;
        }
        if !s.starts_with("--") {
            return Err(CliError::UnexpectedPositional {
                argument: arg.raw.clone(),
                command: cmd,
                index: arg.index,
            });
        }
        let (opt, val, val_idx, step) = if let Some((k, v)) = s.split_once('=') {
            (k, v, arg.index, 1)
        } else {
            let next = tokens.get(idx + 1).ok_or_else(|| CliError::MissingValue {
                option: s.to_owned(),
                command: cmd.clone(),
                expected: format!("a value for `{s}`"),
            })?;
            (s, next.as_str(), next.index, 2)
        };
        if !allowed.contains(&opt) {
            return Err(CliError::UnknownOption {
                option: opt.to_owned(),
                command: cmd,
                index: arg.index,
            });
        }
        if val.is_empty() {
            return Err(CliError::MissingValue {
                option: opt.to_owned(),
                command: cmd,
                expected: format!("non-empty value for `{opt}`"),
            });
        }
        if opts
            .insert(opt.to_owned(), (val.to_owned(), val_idx))
            .is_some()
        {
            return Err(CliError::DuplicateOption {
                option: opt.to_owned(),
                command: cmd,
                index: arg.index,
            });
        }
        idx += step;
    }
    Ok((opts, json))
}

const FORBIDDEN_DAEMON_SECRET_FLAGS: &[&str] = &[
    "--passphrase",
    "--password",
    "--secret",
    "--token",
    "--api-key",
];

fn parse_site_run_args(tokens: &[ArgToken]) -> Result<SiteRunArgs, CliError> {
    for tok in &tokens[2..] {
        let s = tok.as_str();
        let flag = s.split_once('=').map_or(s, |(k, _)| k);
        if FORBIDDEN_DAEMON_SECRET_FLAGS.contains(&flag) {
            return Err(CliError::MalformedValue {
                option: flag.to_owned(),
                value: "[redacted]".to_owned(),
                reason: "plaintext secrets and passphrases are forbidden on CLI argv; use --vault-dir and --passphrase-file (0600)".to_owned(),
                command: Some("site run".to_owned()),
                index: tok.index,
            });
        }
    }
    let (mut opts, json) = parse_daemon_flags(
        "site run",
        tokens,
        &[
            "--manifest",
            "--root",
            "--vault-dir",
            "--passphrase-file",
            "--once-ticks",
            "--tick-ms",
        ],
    )?;
    let cmd = Some("site run".to_owned());
    let manifest = opts
        .remove("--manifest")
        .map(|(v, _)| PathBuf::from(v))
        .ok_or_else(|| CliError::MissingValue {
            option: "--manifest".to_owned(),
            command: cmd.clone(),
            expected: "path to site.json".to_owned(),
        })?;
    let once_ticks = opts
        .remove("--once-ticks")
        .map(|(raw, i)| parse_u64_flag(&raw, "--once-ticks", i, &cmd, true))
        .transpose()?;
    let tick_ms = opts
        .remove("--tick-ms")
        .map(|(raw, i)| parse_u64_flag(&raw, "--tick-ms", i, &cmd, false))
        .transpose()?
        .unwrap_or(50);
    Ok(SiteRunArgs {
        manifest,
        root: opts.remove("--root").map(|(v, _)| PathBuf::from(v)),
        vault_dir: opts.remove("--vault-dir").map(|(v, _)| PathBuf::from(v)),
        passphrase_file: opts
            .remove("--passphrase-file")
            .map(|(v, _)| PathBuf::from(v)),
        once_ticks,
        tick_ms,
        json,
    })
}

fn parse_site_root_args(
    command: &str,
    tokens: &[ArgToken],
) -> Result<(PathBuf, Option<String>, bool), CliError> {
    let (mut opts, json) = parse_daemon_flags(command, tokens, &["--root", "--site-id"])?;
    let root = opts
        .remove("--root")
        .map(|(v, _)| PathBuf::from(v))
        .ok_or_else(|| CliError::MissingValue {
            option: "--root".to_owned(),
            command: Some(command.to_owned()),
            expected: "deployment root".to_owned(),
        })?;
    Ok((root, opts.remove("--site-id").map(|(v, _)| v), json))
}

fn parse_u64_flag(
    raw: &str,
    opt: &str,
    index: usize,
    cmd: &Option<String>,
    positive: bool,
) -> Result<u64, CliError> {
    match raw.parse::<u64>().ok() {
        Some(v) if (!positive || v > 0) && v.to_string() == raw => Ok(v),
        _ => Err(CliError::MalformedValue {
            option: opt.to_owned(),
            value: "[invalid integer]".to_owned(),
            reason: if positive {
                "expected positive integer"
            } else {
                "expected non-negative integer"
            }
            .to_owned(),
            command: cmd.clone(),
            index,
        }),
    }
}

fn execute_site_run(args: &SiteRunArgs) -> (String, ExitIdentity) {
    let manifest = match DaemonSiteManifest::from_file(&args.manifest) {
        Ok(m) => m,
        Err(e) => return daemon_error_response(&e, "site run", args.json),
    };
    let mut cfg = DaemonStartConfig::new(manifest);
    cfg.manifest_path = Some(args.manifest.clone());
    cfg.root_override = args.root.clone();
    cfg.vault_dir = args.vault_dir.clone();
    cfg.vault_passphrase_file = args.passphrase_file.clone();
    let sup = match DaemonSupervisor::start(cfg) {
        Ok(s) => s,
        Err(e) => return daemon_error_response(&e, "site run", args.json),
    };
    let r = match sup.run_until_stopped(args.once_ticks, Duration::from_millis(args.tick_ms)) {
        Ok(r) => r,
        Err(e) => return daemon_error_response(&e, "site run", args.json),
    };
    let out = if args.json {
        r.to_json()
    } else {
        format!(
            "fss site run stopped site={} ticks={} head_seq={} active_tasks={} leaked_obligations={}",
            r.site_id,
            r.ticks_executed,
            r.head_commit_sequence,
            r.active_tasks,
            r.leaked_obligations
        )
    };
    (out, ExitIdentity::SUCCESS)
}

fn execute_site_status(args: &SiteStatusArgs) -> (String, ExitIdentity) {
    let Ok(p) = PrincipalId::parse("principal:local-operator") else {
        return refusal("ERR-DAEMON-IPC-001", "invalid operator principal", None);
    };
    let (d, s) = match query_live_daemon_status(&args.root, args.site_id.as_deref(), p) {
        Ok(v) => v,
        Err(e) => return daemon_error_response(&e, "site status", args.json),
    };
    let out = if args.json {
        render_live_status_json(&d, &s)
    } else {
        format!(
            "fss site status site={} pid={} uptime_ms={} head_seq={} cameras={}",
            d.site_id,
            d.pid,
            s.daemon_uptime_ms,
            s.head_commit_sequence,
            s.cameras.len()
        )
    };
    (out, ExitIdentity::SUCCESS)
}

fn execute_site_stop(args: &SiteStopArgs) -> (String, ExitIdentity) {
    let Ok(p) = PrincipalId::parse("principal:local-operator") else {
        return refusal("ERR-DAEMON-IPC-001", "invalid operator principal", None);
    };
    let (d, op, st) = match request_live_daemon_stop(&args.root, args.site_id.as_deref(), p) {
        Ok(v) => v,
        Err(e) => return daemon_error_response(&e, "site stop", args.json),
    };
    let out = if args.json {
        render_stop_accepted_json(&d, &op, st)
    } else {
        format!(
            "fss site stop accepted site={} operation_id={} state={st:?}",
            d.site_id,
            op.as_str()
        )
    };
    (out, ExitIdentity::SUCCESS)
}

fn daemon_error_response(err: &DaemonError, command: &str, json: bool) -> (String, ExitIdentity) {
    let exit = match err {
        DaemonError::SecretInManifest { .. }
        | DaemonError::InvalidManifest { .. }
        | DaemonError::InvalidConfig { .. } => ExitIdentity::MALFORMED_VALUE,
        _ => ExitIdentity::RUNTIME_FAILURE,
    };
    if !json {
        return (format!("{}: {err}", err.error_id()), exit);
    }
    (
        object(&[
            ("schema", string("fss.site_diagnostic.v1")),
            ("phase", string("execution")),
            ("binary", string("fss")),
            ("command", string(command)),
            ("error_id", string(err.error_id())),
            ("exit_id", string(exit.identifier)),
            ("exit_code", exit.code.to_string()),
            ("reason", string(&err.to_string())),
        ]),
        exit,
    )
}
