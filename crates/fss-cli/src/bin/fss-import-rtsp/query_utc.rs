#![forbid(unsafe_code)]
//! Exact approved acquisition of conditional UTC candidates across retained capture sessions.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use fss_cli::recording_query_cmd::utc_discover::parse_recording_utc_discovery_query_args;
use fss_cli::recording_query_cmd::utc_sessions::{
    MAX_SESSIONS_JSON_BYTES, parse_recording_utc_sessions_query_args,
};
use fss_cli::{ArgToken, ExitIdentity};
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, PrincipalId};
use fss_reference::agent_recording_context::utc_discover::RecordingUtcDiscoveryContextLimits;
use fss_reference::agent_recording_context::utc_sessions::RecordingUtcSessionsContextLimits;
use fss_reference::ingest::rtsp_import::catalog;
use fss_reference::ingest::rtsp_import::query::RtspQueryImportSettings;
use fss_reference::ingest::rtsp_import::query::utc::RtspUtcQueryImportInput;

use super::plan::{digest, path, timestamp};

#[path = "query_utc_driver.rs"]
mod driver;

pub(super) const MAX_ARGUMENTS: usize = 80;
pub(super) const FORMAT: &str = "fss.rtsp_utc_query_import_operator.v1";
pub(super) const MAX_OUTPUT_BYTES: usize = 256 * 1024;
pub(super) const RESULT_HEADROOM: usize = 64 * 1024;

const HELP: &str = "fss-import-rtsp query-utc --archive EXISTING_ABSOLUTE_ARCHIVE --root EXISTING_ABSOLUTE_DEPLOYMENT --site SITE\n\
  Select exact sessions: --sessions JSON_ARRAY\n\
  Or discover one historical source namespace: --discover-catalogs yes --codec avc|hevc\n\
    --sensor-id ID --stream-id ID --generation N --anchor sha256:HEX --receive-clock sha256:HEX\n\
    --decode-clock sha256:HEX --time-scale N --clock-slot SLOT --clock-root sha256:HEX\n\
  --start-utc-ns N --end-utc-ns N --receive-time-ns N\n\
  --owner-authorized yes --read-originals yes --retain-originals yes\n\
  [--principal ID] [--deployment-anchor ANCHOR] [--approve sha256:PLAN]\n\
  Bounds: --max-windows 32 --max-hydration-bytes 134217728\n\
          --max-frames 16384 --max-original-bytes 134217728 --max-media-bytes 67108864\n\
          --max-work 1000000000000 --timeout-ms 30000.\n\
  Sessions use the same strict literal JSON array as fss query --target recordings --sessions:\n\
  1..8 sessions of one sensor/stream with independent codec, generation, source/decode clocks,\n\
  catalogs and retained clock pins. No input files are read and no latest root is inferred.\n\
  Without --approve, protected metadata preview binds current deployment, exact sources,\n\
  conditional node-clock envelopes, every unknown-clock candidate, gaps and aggregate bounds.\n\
  Approve that exact digest to retain selected WHOLE windows using verified read-only native\n\
  source reads. The archive is never opened as a writer or recovered. No network is accessed.\n\
  UTC describes retained conditional node observations, not camera exposure time. Unknown-time\n\
  windows stay selected. Originals are not trimmed; native imports keep capture time unknown.\n\
  Source generations and clocks remain independent. No continuity, physical coverage or absence\n\
  follows from a query. Current masks apply to later decode/review. This does not grant disclosure.\n\
  A batch is not atomic. On failure, keep completed receipts and the possible-durability flag;\n\
  preview and approve current state again to reconcile unchanged native import identities.\n";

pub(super) struct UtcOptions {
    pub archive: PathBuf,
    pub root: PathBuf,
    pub principal: String,
    pub input: RtspUtcQueryImportInput,
    pub settings: RtspQueryImportSettings,
    pub timeout_ms: u64,
    pub approve: Option<ContentDigest>,
}

impl UtcOptions {
    pub fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.is_empty() || args.len() > MAX_ARGUMENTS || !args.len().is_multiple_of(2) {
            return Err("argument count or byte bound exceeded");
        }
        let query_options = [
            "--sessions",
            "--discover-catalogs",
            "--codec",
            "--sensor-id",
            "--stream-id",
            "--generation",
            "--anchor",
            "--receive-clock",
            "--decode-clock",
            "--time-scale",
            "--clock-slot",
            "--clock-root",
            "--start-utc-ns",
            "--end-utc-ns",
            "--deployment-anchor",
            "--max-windows",
            "--max-hydration-bytes",
        ];
        let operator_options = [
            "--archive",
            "--root",
            "--site",
            "--principal",
            "--receive-time-ns",
            "--owner-authorized",
            "--read-originals",
            "--retain-originals",
            "--max-frames",
            "--max-original-bytes",
            "--max-media-bytes",
            "--max-work",
            "--timeout-ms",
            "--approve",
        ];
        let mut values = BTreeMap::new();
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or("UTF-8 option required")?;
            let value = pair[1].to_str().ok_or("UTF-8 value required")?;
            let maximum = if key == "--sessions" {
                MAX_SESSIONS_JSON_BYTES
            } else {
                4096
            };
            if key.len() > 4096
                || value.is_empty()
                || value.len() > maximum
                || value.starts_with("--")
                || (!query_options.contains(&key) && !operator_options.contains(&key))
            {
                return Err("unknown option, missing value or argument byte bound exceeded");
            }
            if values.insert(key, value).is_some() {
                return Err("duplicate option");
            }
        }
        let required = |key: &str| values.get(key).copied().ok_or("required option missing");
        for key in [
            "--owner-authorized",
            "--read-originals",
            "--retain-originals",
        ] {
            if required(key)? != "yes" {
                return Err(
                    "explicit owner, original-read and retention acknowledgements required",
                );
            }
        }
        let number = |key: &str, default: u64, maximum: u64| -> Result<u64, &'static str> {
            let value = match values.get(key) {
                Some(text) => {
                    let value: u64 = text
                        .parse()
                        .map_err(|_| "canonical unsigned integer required")?;
                    if value.to_string() != *text {
                        return Err("canonical unsigned integer required");
                    }
                    value
                }
                None => default,
            };
            if value == 0 || value > maximum {
                return Err("numeric bound exceeded");
            }
            Ok(value)
        };
        let archive = path(required("--archive")?)?;
        let root = path(required("--root")?)?;
        if archive.starts_with(&root) || root.starts_with(&archive) {
            return Err("distinct non-nested stores required");
        }
        let site = required("--site")?.to_owned();
        if site.len() > 256 || site.chars().any(char::is_control) {
            return Err("invalid site");
        }
        fss_reference::reference_deployment::validate_site_lineage(&site)
            .map_err(|_| "invalid site lineage")?;
        let principal = values
            .get("--principal")
            .copied()
            .unwrap_or("principal:local-operator")
            .to_owned();
        PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
        if principal.len() > 256 {
            return Err("principal byte bound exceeded");
        }
        let settings = RtspQueryImportSettings {
            site,
            receive_time: timestamp(required("--receive-time-ns")?)?,
            max_frames: number(
                "--max-frames",
                catalog::MAX_FRAMES as u64,
                catalog::MAX_FRAMES as u64,
            )? as usize,
            max_original_bytes: number(
                "--max-original-bytes",
                catalog::MAX_ORIGINAL_BYTES,
                catalog::MAX_ORIGINAL_BYTES,
            )?,
            max_media_bytes: number(
                "--max-media-bytes",
                catalog::MAX_MEDIA_BYTES,
                catalog::MAX_MEDIA_BYTES,
            )?,
            max_work: number("--max-work", 1_000_000_000_000, 1_000_000_000_000_000)?,
        };
        let hydration = number(
            "--max-hydration-bytes",
            settings.max_original_bytes,
            settings.max_original_bytes,
        )?;
        let max_windows = number("--max-windows", 32, 32)?;
        // The public metadata parsers own the exact source/clock grammar. Translating option
        // names here adds retention authority without maintaining a second session decoder.
        let mut query = vec![
            ("--target".to_owned(), "recordings".to_owned()),
            ("--root".to_owned(), required("--root")?.to_owned()),
            (
                "--archive-root".to_owned(),
                required("--archive")?.to_owned(),
            ),
            ("--principal".to_owned(), principal.clone()),
            ("--max-windows".to_owned(), max_windows.to_string()),
            ("--max-hydration-bytes".to_owned(), hydration.to_string()),
        ];
        for (key, value) in &values {
            if query_options.contains(key)
                && !matches!(*key, "--max-windows" | "--max-hydration-bytes")
            {
                let translated = match *key {
                    "--sensor-id" => "--sensor",
                    "--stream-id" => "--stream",
                    "--anchor" => "--source-anchor",
                    "--deployment-anchor" => "--anchor",
                    value => value,
                };
                query.push((translated.to_owned(), (*value).to_owned()));
            }
        }
        let tokens = ["query".to_owned(), "--json".to_owned()]
            .into_iter()
            .chain(query.into_iter().flat_map(|(key, value)| [key, value]))
            .enumerate()
            .map(|(index, raw)| ArgToken::new(index, raw))
            .collect::<Vec<_>>();
        let input = if values.contains_key("--sessions") {
            let args = parse_recording_utc_sessions_query_args(&tokens)
                .map_err(|_| "invalid exact UTC sessions query")?;
            RtspUtcQueryImportInput::Sessions {
                request: args.request,
                limits: RecordingUtcSessionsContextLimits::default(),
            }
        } else {
            let args = parse_recording_utc_discovery_query_args(&tokens)
                .map_err(|_| "invalid exact UTC discovery query")?;
            RtspUtcQueryImportInput::Discovery {
                request: args.request,
                limits: RecordingUtcDiscoveryContextLimits::default(),
            }
        };
        Ok(Self {
            archive,
            root,
            principal,
            input,
            settings,
            timeout_ms: number("--timeout-ms", 30_000, 600_000)?,
            approve: values
                .get("--approve")
                .map(|text| digest(text))
                .transpose()?,
        })
    }

    pub fn approval(&self, plan: ContentDigest) -> Result<ContentDigest, &'static str> {
        if plan.algorithm() != DigestAlgorithm::Sha256 || plan.bytes() == [0; 32] {
            return Err("invalid acquisition plan digest");
        }
        let mut e = CanonicalEncoder::new();
        e.text("fss.rtsp_utc_query_import_cli_plan.v1");
        e.text("conditional-node-utc:unknown-candidates-retained:whole-windows:unknown-capture:read-only-pinned-source:v1");
        // The core plan already binds exact owner paths, principal, query, metadata decision,
        // source provenance, settings, ceilings and current deployment anchor.
        e.digest(plan);
        e.u64(self.timeout_ms);
        Ok(ContentDigest::sha256(&e.finish()))
    }
}

pub(super) fn main(args: &[OsString]) -> ExitCode {
    if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help")) {
        return ExitCode::from(if super::emit_bounded(HELP, MAX_OUTPUT_BYTES).is_ok() {
            ExitIdentity::SUCCESS.code
        } else {
            ExitIdentity::RUNTIME_FAILURE.code
        });
    }
    let options = match UtcOptions::parse(args) {
        Ok(options) => options,
        Err(reason) => {
            eprintln!(
                "ERR-CLI-MALFORMED-VALUE-001: {reason}. Use fss-import-rtsp query-utc --help."
            );
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    match driver::run(&options) {
        Ok((report, complete)) if super::emit_bounded(&report, MAX_OUTPUT_BYTES).is_ok() => {
            ExitCode::from(if complete {
                ExitIdentity::SUCCESS.code
            } else {
                ExitIdentity::RUNTIME_FAILURE.code
            })
        }
        Ok(_) => {
            eprintln!(
                "ERR-CLI-RUNTIME-FAILURE-001: output failed; approved imports may already be durable. Preview current state before reconciliation."
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
        Err(code) => {
            eprintln!(
                "{code}: UTC query acquisition not confirmed. Completed imports remain durable; preview and approve current state to reconcile."
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
#[path = "query_utc_tests.rs"]
mod tests;
