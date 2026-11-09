#![forbid(unsafe_code)]
//! Explicit query-selected acquisition of independently source-closed recording windows.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::process::ExitCode;

use fss_cli::ExitIdentity;
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, PrincipalId};
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_recording_context::{RecordingContextLimits, RecordingContextRequest};
use fss_reference::agent_recordings::RecordingQueryRequest;

use super::plan::Options;

#[path = "query_driver.rs"]
mod driver;

pub(super) const MAX_ARGUMENTS: usize = super::plan::MAX_ARGUMENTS + 8;
pub(super) const FORMAT: &str = "fss.rtsp_query_import_operator.v1";

const HELP: &str = "fss-import-rtsp query --archive EXISTING_ABSOLUTE_ARCHIVE --root EXISTING_ABSOLUTE_DEPLOYMENT --site SITE\n\
  --catalog-slot SLOT --catalog-root sha256:HEX --codec avc|hevc\n\
  --sensor-id ID --stream-id ID --generation N --anchor sha256:HEX --receive-clock sha256:HEX\n\
  --decode-clock sha256:HEX --time-scale N --decode-start N --decode-end N\n\
  --receive-time-ns N --owner-authorized yes --read-originals yes --retain-originals yes\n\
  [--principal ID] [--deployment-anchor ANCHOR] [--approve sha256:PLAN]\n\
  Bounds: --max-windows 32 --max-hydration-bytes 134217728\n\
          --max-frames 16384 --max-original-bytes 134217728 --max-media-bytes 67108864\n\
          --max-work 1000000000000 --timeout-ms 30000.\n\
  Without --approve: bounded read-only catalog and current deployment metadata preview.\n\
  No original media, publisher recovery, destination creation or network access during preview.\n\
  Approval binds the exact metadata decision, current deployment, interval, selected whole\n\
  windows, gaps, paths, principal and budgets. Execution revalidates before staging.\n\
  Only selected whole windows are imported, each under its existing native custody proof.\n\
  Approved archive opening still rehashes existing spool objects (up to 1 GiB) and can\n\
  recover publications; the selected-byte quote is not a total disk-I/O estimate.\n\
  The query overlap does not trim originals. Native movie selection uses the returned import IDs.\n\
  Capture time stays unknown; decode ticks never imply UTC, continuity or physical absence.\n\
  A batch is not atomic. On failure, completed imports remain durable; a failed import may\n\
  also be durable. Preview and approve again to reconcile against current deployment state.\n\
  Source and destination must be distinct, non-nested stores. Current privacy masks still\n\
  apply to later decode/review. The timeout is cooperative at bounded custody boundaries.\n";

pub(super) struct QueryOptions {
    pub common: Options,
    pub context: RecordingContextRequest,
    pub limits: RecordingContextLimits,
}

fn unsigned(value: &str) -> Result<u64, &'static str> {
    let parsed: u64 = value
        .parse()
        .map_err(|_| "canonical unsigned integer required")?;
    if parsed.to_string() != value {
        return Err("canonical unsigned integer required");
    }
    Ok(parsed)
}

impl QueryOptions {
    pub fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.is_empty() || args.len() > MAX_ARGUMENTS || !args.len().is_multiple_of(2) {
            return Err("argument count or byte bound exceeded");
        }
        let mut extra = BTreeMap::new();
        let mut common = Vec::new();
        let mut has_windows = false;
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or("UTF-8 option required")?;
            let value = pair[1].to_str().ok_or("UTF-8 value required")?;
            if key.len() > 4096 || value.is_empty() || value.len() > 4096 {
                return Err("argument byte bound exceeded");
            }
            match key {
                "--decode-start"
                | "--decode-end"
                | "--max-hydration-bytes"
                | "--deployment-anchor" => {
                    if extra.insert(key, value).is_some() {
                        return Err("duplicate query option");
                    }
                }
                "--capture-start-ns"
                | "--capture-uncertainty-ns"
                | "--decode-gaps"
                | "--catalog-pages"
                | "--max-pages"
                | "--window-slot"
                | "--window-root" => {
                    return Err(
                        "query acquisition requires one exact catalog and unknown capture time",
                    );
                }
                _ => {
                    has_windows |= key == "--max-windows";
                    common.extend_from_slice(pair);
                }
            }
        }
        if !has_windows {
            common.extend([OsString::from("--max-windows"), OsString::from("32")]);
        }
        let common = Options::parse(&common)?;
        let catalog = common
            .catalog
            .as_ref()
            .ok_or("one exact catalog required")?;
        if catalog.max_windows > 32 {
            return Err("query acquisition admits at most 32 complete windows");
        }
        let required = |key: &str| extra.get(key).copied().ok_or("query interval required");
        let start = unsigned(required("--decode-start")?)?;
        let end = unsigned(required("--decode-end")?)?;
        if start >= end {
            return Err("nonempty half-open decode interval required");
        }
        let hydration = extra
            .get("--max-hydration-bytes")
            .map(|value| unsigned(value))
            .transpose()?
            .unwrap_or(catalog.max_original_bytes);
        if hydration == 0 || hydration > catalog.max_original_bytes {
            return Err("hydration ceiling must fit aggregate original retention allowance");
        }
        let expected_anchor = extra
            .get("--deployment-anchor")
            .map(|value| AnchorToken::parse(value).ok_or("invalid deployment anchor"))
            .transpose()?;
        let limits = RecordingContextLimits::default();
        let context = RecordingContextRequest {
            recording: RecordingQueryRequest {
                codec: match common.request.codec {
                    fss_reference::ingest::rtsp_import::RtspImportCodec::Avc => {
                        fss_reference::agent_recordings::RecordingQueryCodec::Avc
                    }
                    fss_reference::ingest::rtsp_import::RtspImportCodec::Hevc => {
                        fss_reference::agent_recordings::RecordingQueryCodec::Hevc
                    }
                },
                scope: catalog.scope.clone(),
                catalog_slot: catalog.slot.clone(),
                catalog_root: catalog.root,
                interval: start..end,
                max_windows: catalog.max_windows,
                max_hydration_bytes: hydration,
            },
            principal: PrincipalId::parse(&common.principal).map_err(|_| "invalid principal")?,
            expected_anchor,
        };
        context
            .recording
            .request_digest(limits.recording)
            .map_err(|_| "invalid recording query")?;
        Ok(Self {
            common,
            context,
            limits,
        })
    }

    pub fn approval(&self, plan: ContentDigest) -> Result<ContentDigest, &'static str> {
        if plan.algorithm() != DigestAlgorithm::Sha256 || plan.bytes() == [0; 32] {
            return Err("invalid acquisition plan digest");
        }
        let mut e = CanonicalEncoder::new();
        e.text("fss.rtsp_query_import_cli_plan.v1");
        e.text("selected-whole-windows:unknown-capture:no-cross-window-continuity:v1");
        e.digest(self.common.approval()?);
        e.digest(
            self.context
                .recording
                .request_digest(self.limits.recording)
                .map_err(|_| "invalid recording query")?,
        );
        e.bool(self.context.expected_anchor.is_some());
        if let Some(anchor) = &self.context.expected_anchor {
            e.text(anchor.as_str());
        }
        e.digest(plan);
        Ok(ContentDigest::sha256(&e.finish()))
    }
}

pub(super) fn main(args: &[OsString]) -> ExitCode {
    if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help")) {
        return ExitCode::from(if super::emit(HELP).is_ok() {
            ExitIdentity::SUCCESS.code
        } else {
            ExitIdentity::RUNTIME_FAILURE.code
        });
    }
    let options = match QueryOptions::parse(args) {
        Ok(options) => options,
        Err(reason) => {
            eprintln!("ERR-CLI-MALFORMED-VALUE-001: {reason}. Use fss-import-rtsp query --help.");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    match driver::run(&options) {
        Ok((report, complete)) if super::emit(&report).is_ok() => ExitCode::from(if complete {
            ExitIdentity::SUCCESS.code
        } else {
            ExitIdentity::RUNTIME_FAILURE.code
        }),
        Ok(_) => {
            eprintln!(
                "ERR-CLI-RUNTIME-FAILURE-001: output failed; approved imports may already be durable. Preview current state before reconciliation."
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
        Err(code) => {
            eprintln!(
                "{code}: query acquisition not confirmed. Completed imports remain durable; preview and approve current state to reconcile."
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
#[path = "query_tests.rs"]
mod tests;
