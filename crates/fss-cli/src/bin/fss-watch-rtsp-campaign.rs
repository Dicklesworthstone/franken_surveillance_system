#![forbid(unsafe_code)]
//! Exact saved RTSP campaign history → independent native retained recordings → native watch.

#[path = "fss-watch-rtsp-campaign/archive_open.rs"]
mod archive_open;
#[path = "fss-watch-rtsp-campaign/driver.rs"]
mod driver;
#[path = "fss-import-rtsp/plan.rs"]
mod import_plan;
#[path = "fss-watch-rtsp-campaign/plan.rs"]
mod plan;
#[path = "fss-watch-rtsp-campaign/rerun.rs"]
mod rerun;
#[cfg(test)]
#[path = "fss-watch-rtsp-campaign/tests.rs"]
mod tests;
#[path = "fss-watch-rtsp-selected/watch.rs"]
mod watch;

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use fss_cli::ExitIdentity;

const HELP: &str = "fss-watch-rtsp-campaign\n\
  --history-root EXISTING_ABSOLUTE_HISTORY --history-approval sha256:HEX\n\
  --history-plan sha256:HEX --history-root-digest sha256:HEX --history-records N\n\
  --root ABSOLUTE_DEPLOYMENT --site SITE [--principal principal:local-operator]\n\
  --requests JSON --interpretation ycbcr --zone ID:X,Y,W,H (repeat)\n\
  --owner-authorized yes --read-originals yes --retain-originals yes\n\
  [--approve-import sha256:PLAN]\n\
\n\
Use all four independently saved CampaignPin coordinates from history_durable capture receipts.\n\
--requests is an ordered JSON array of 1..16 objects {\"ordinal\":1,\"request\":[...]}\n\
or {\"ordinal\":1,\"request\":null}, one for EVERY started attempt in the selected prefix.\n\
Each non-null request contains ordinary fss-import-rtsp option/value strings selecting the\n\
complete catalog or ordered complete page list recorded for that attempt, its exact archive,\n\
scope, clocks and explicit capture-start-ns/capture-uncertainty-ns. Single windows are refused.\n\
Child root/site/principal must match the outer destination. Child approval/max-work/timeout-ms\n\
are forbidden: one shared work account and deadline govern history and all selected imports.\n\
Null is required when the selected attempt has no catalog: start-only, unavailable native\n\
observation, zero durable pictures, and pictures without a catalog remain distinct report rows.\n\
A null row never opens an archive and never proves absence. Retained catalogs from a failed\n\
attempt can still be analyzed; the original failure remains visible.\n\
\n\
Without approval: pure plan only, no files, locks, clocks, camera or network. Exact approval\n\
verifies the saved history, every scope/page mapping and source/destination separation first;\n\
then uses native custody imports and independent native whole-recording watch. All imports\n\
finish before analysis. Background/tracking state never crosses attempts. Current destination\n\
privacy masks apply before perception. Capture times are operator assumptions, not receive times.\n\
The selected prefix never selects a latest root or proves no later records/attempts exist.\n\
\n\
Whole invocation: --max-work 1000000000000 --timeout-ms 30000\n\
  --archive-read-bytes 1073741824 (shared across native source open/recovery and imports)\n\
  --max-report-bytes 16842752 (complete output; no truncation)\n\
History bounds: --history-max-records 33 --history-object-bytes 262144\n\
  --history-max-scan-entries 4096 --history-metadata-bytes 16777216\n\
  --history-storage-bytes 33554432\n\
Per-recording native limits (aggregate reserved before I/O):\n\
  --work-units 100000000 --stream-read-bytes 536870912\n\
  --stream-pixel-budget 1073741824 --stream-assignment-work 1073741824\n\
  --stream-trace-bytes 8388608 --max-dimension 4096 --max-pixels 4194304\n\
  --max-segment-bytes N --screened yes|no --tolerate-decode-refusals yes|no\n\
Native watch thresholds: --pixel-threshold 25 --threshold-sigma 3\n\
  --learning-rate-num 1 --learning-rate-den 32 --min-region-pixels 16\n\
  --confirmation-hits 3 --maximum-missed-frames 2 --minimum-iou-ppm 100000\n\
\n\
History inspection is read-only. Opening recording archives takes their existing publisher\n\
locks and can finish publication recovery. Destination imports retain originals unencrypted.\n\
Imports are incremental: a later refusal can leave earlier imports durable. Retry the same\n\
exact plan to reconcile imports and recompute analysis. Deadline checks are cooperative.\n\
Reports and fss-event watch rerun hints grant no event, alert or capture-resume authority.\n\
No cross-attempt continuity or absence is certified. No camera or credentials are opened.\n";

fn emit(text: &str, maximum: usize) -> io::Result<()> {
    if text.len() > maximum {
        return Err(io::Error::other("complete campaign output bound exceeded"));
    }
    let mut output = io::stdout().lock();
    let mut bytes = text.as_bytes();
    let mut interrupted = 0;
    while !bytes.is_empty() {
        match output.write(&bytes[..bytes.len().min(4096)]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => {
                bytes = &bytes[count..];
                interrupted = 0;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted && interrupted < 7 => {
                interrupted += 1;
            }
            Err(error) => return Err(error),
        }
    }
    output.flush()
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os()
        .skip(1)
        .take(plan::MAX_ARGUMENTS + 1)
        .collect();
    if args.len() == 1 && args[0] == "--help" {
        return if emit(HELP, plan::MAX_PREVIEW_BYTES).is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        };
    }
    let options = match plan::Options::parse(&args) {
        Ok(options) => options,
        Err(reason) => {
            eprintln!("ERR-CLI-MALFORMED-VALUE-001: {reason}. Use fss-watch-rtsp-campaign --help.");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    let approved = options.approve.is_some();
    let result = if approved {
        driver::execute(&options)
    } else {
        options.preview()
    };
    match result {
        Ok(mut text) => {
            text.push('\n');
            let limit = if approved {
                options.limits.maximum_report_bytes
            } else {
                plan::MAX_PREVIEW_BYTES
            };
            if emit(&text, limit).is_err() {
                eprintln!(
                    "{}: complete campaign report output failed",
                    fss_cli::ERR_CLI_RUNTIME_FAILURE
                );
                return ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code);
            }
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!(
                "{}: {reason}; earlier exact imports may remain durable; retry the same approved plan",
                fss_cli::ERR_CLI_RUNTIME_FAILURE
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}
