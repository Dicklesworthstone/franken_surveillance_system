#![forbid(unsafe_code)]
//! Read-only operator onboarding: validate a site or compile exact native capture plans.
//!
//! The only host inputs are the explicitly named manifest and receipt documents. Planning
//! never inspects destination directories, credential files, cameras, or rights-lease stores.
//! The pure compiler owns plan semantics; this module owns bounded CLI/file presentation.

use std::collections::BTreeSet;
use std::fs::{self, Metadata, OpenOptions};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use fss_core::json_input::MAX_INPUT_BYTES;
use fss_reference::site::{SiteManifest, parse_manifest, parse_probe_receipts};

use crate::agent_json::{array, object, string};
use crate::error::{CliError, ExitIdentity};
use crate::orient_cmd::{collect_options, take};
use crate::site_plan::{SitePlanOptions, compile};
use crate::token::ArgToken;

/// Schema of the bounded, non-disclosing manifest validation summary.
pub const SITE_VALIDATION_SCHEMA: &str = "fss.site_validation.v1";
/// Complete site command output ceiling; results are refused rather than truncated.
pub const MAX_SITE_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_INPUT_OPERATIONS: usize = 1024;
const INPUT_ERROR: &str = "ERR-SITE-INPUT-001";
const OUTPUT_ERROR: &str = "ERR-SITE-OUTPUT-BOUND-001";

/// Operator-only site commands. Neither variant grants or executes capture authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SiteCommand {
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
        /// Explicit identity epoch, output destinations, principal and picture budget.
        options: SitePlanOptions,
    },
}

/// Parse the operator's `site validate` or `site plan` command with exact exhaustion.
pub fn parse_site_args(tokens: &[ArgToken]) -> Result<SiteCommand, CliError> {
    let action = tokens.get(1).ok_or_else(|| CliError::MissingValue {
        option: "site".to_owned(),
        command: Some("site".to_owned()),
        expected: "validate or plan".to_owned(),
    })?;
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
            "--archive-root",
            "--pins-root",
            "--epoch",
            "--stop-after-pictures",
            "--principal",
        ]
    };
    // collect_options skips its command token; original argument indices remain intact.
    let values = collect_options(command, &tokens[1..], allowed)?;
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
    Ok(SiteCommand::Plan {
        manifest,
        probes: PathBuf::from(required("--probes")?),
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
struct InputAuthority {
    paths: BTreeSet<PathBuf>,
    operations: usize,
    bytes: usize,
}

impl InputAuthority {
    fn new(command: &SiteCommand) -> Self {
        let paths = match command {
            SiteCommand::Validate { manifest } => BTreeSet::from([manifest.clone()]),
            SiteCommand::Plan {
                manifest, probes, ..
            } => BTreeSet::from([manifest.clone(), probes.clone()]),
        };
        Self {
            paths,
            operations: MAX_INPUT_OPERATIONS,
            bytes: 2 * (MAX_INPUT_BYTES + 1),
        }
    }

    fn boundary(&mut self, path: &Path) -> Result<(), &'static str> {
        if !self.paths.contains(path) || self.operations == 0 {
            return Err(INPUT_ERROR);
        }
        self.operations -= 1;
        Ok(())
    }

    fn read(&mut self, path: &Path) -> Result<Vec<u8>, &'static str> {
        self.boundary(path)?;
        let before = fs::symlink_metadata(path).map_err(|_| INPUT_ERROR)?;
        if !before.is_file() || before.len() == 0 || before.len() > MAX_INPUT_BYTES as u64 {
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
        let mut bytes = Vec::with_capacity(before.len() as usize);
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
            if bytes.len().checked_add(count).ok_or(INPUT_ERROR)? > MAX_INPUT_BYTES {
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

/// Read exactly the named control inputs and return a complete plan or a safe diagnostic.
#[must_use]
pub fn execute_site(command: &SiteCommand) -> (String, ExitIdentity) {
    let mut authority = InputAuthority::new(command);
    let manifest_path = match command {
        SiteCommand::Validate { manifest } | SiteCommand::Plan { manifest, .. } => manifest,
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
        SiteCommand::Validate { .. } => match render_validation(&manifest) {
            Ok(output) => output,
            Err(error) => return refusal(error.code(), &error.to_string(), None),
        },
        SiteCommand::Plan {
            probes, options, ..
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
            match compile(&manifest, &receipts, options) {
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

fn refusal(code: &str, reason: &str, source_index: Option<usize>) -> (String, ExitIdentity) {
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
