#![forbid(unsafe_code)]
//! Exact approved native RTSP selections → retained imports → independent watch reports.

use std::io::{self, Write};
use std::process::ExitCode;

use fss_cli::ExitIdentity;

#[path = "fss-watch-rtsp-selected/driver.rs"]
mod driver;
#[path = "fss-import-rtsp/plan.rs"]
mod import_plan;
#[path = "fss-watch-rtsp-selected/plan.rs"]
mod plan;
#[path = "fss-watch-rtsp-selected/watch.rs"]
mod watch;

const HELP: &str = "fss-watch-rtsp-selected --requests JSON --interpretation ycbcr\n\
  --zone ID:X,Y,W,H (repeat) [--approve-import sha256:PLAN]\n\
JSON is an ordered array of 1..16 arrays of ordinary fss-import-rtsp option/value strings.\n\
Each selection names one exact window, complete catalog, or ordered complete page list.\n\
All selections must name the same archive, destination root, site and principal, explicitly\n\
authorize original reading/retention, and provide capture-start-ns and capture-uncertainty-ns.\n\
Do not include --approve, --max-work or --timeout-ms in a child request. The outer command\n\
owns one shared import work allowance and deadline, which never refill between selections.\n\
Without --approve-import: a pure exact plan; no files, locks, clocks or network are opened.\n\
Approved execution imports every selected recording through the native custody owners,\n\
then performs whole-recording watch independently for each selection. Originals remain\n\
retained locally and unencrypted. Current destination privacy masks apply at native decode.\n\
Input is bounded to 49152 UTF-8 bytes; preview is at most 131072 bytes.\n\
Whole-operation limits: --max-work 1000000000000 --timeout-ms 30000\n\
  --max-report-bytes 16842752. Timeout is cooperative at custody and analysis boundaries;\n\
one native analysis is work-bounded and ReplayCx-cancellable, not preempted by this timer.\n\
Per-selection watch budgets, reserved in aggregate before I/O:\n\
  --work-units 100000000 --stream-read-bytes 536870912\n\
  --stream-pixel-budget 1073741824 --stream-assignment-work 1073741824\n\
  --stream-trace-bytes 8388608 --max-dimension 4096 --max-pixels 4194304\n\
  --max-pixels accepts 256..4194304; AVC rounds down to complete 256-pixel macroblocks.\n\
  --max-segment-bytes N\n\
Watch thresholds: --pixel-threshold 25 --threshold-sigma 3 --learning-rate-num 1\n\
  --learning-rate-den 32 --min-region-pixels 16 --confirmation-hits 3\n\
  --maximum-missed-frames 2 --minimum-iou-ppm 100000\n\
Optional: --screened yes --tolerate-decode-refusals yes (defaults: no).\n\
The ordered selection is finite. It does not establish complete reconnect history, continuity\n\
between selections, or absence. Camera receive time is never promoted to capture time.\n\
Candidate reports grant no event, alert or other effect publication authority.\n\
Source and destination must be distinct non-nested stores. No network is opened. Opening\n\
the archive takes its existing publisher lock and can finish publication recovery.\n\
Imports are incremental: a later failure may leave earlier imports durable. Retain all stores\n\
and repeat the exact approved plan to reconcile imports and recompute analysis.\n";

fn emit(out: &mut impl Write, text: &str, maximum: usize) -> io::Result<()> {
    if text.len() > maximum {
        return Err(io::ErrorKind::InvalidData.into());
    }
    for mut bytes in [text.as_bytes(), b"\n".as_slice()] {
        let mut interrupted = 0;
        while !bytes.is_empty() {
            let chunk = &bytes[..bytes.len().min(4096)];
            match out.write(chunk) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) if n <= chunk.len() => {
                    bytes = &bytes[n..];
                    interrupted = 0;
                }
                Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted && interrupted < 7 => {
                    interrupted += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }
    out.flush()
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os()
        .skip(1)
        .take(plan::MAX_ARGUMENTS + 1)
        .collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help")) {
        return ExitCode::from(
            if emit(&mut io::stdout().lock(), HELP, plan::MAX_PREVIEW_BYTES).is_ok() {
                ExitIdentity::SUCCESS.code
            } else {
                ExitIdentity::RUNTIME_FAILURE.code
            },
        );
    }
    let options = match plan::Options::parse(&args) {
        Ok(options) => options,
        Err(reason) => {
            eprintln!("ERR-CLI-MALFORMED-VALUE-001: {reason}. Use fss-watch-rtsp-selected --help.");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    let (result, maximum) = if options.approve.is_some() {
        (
            driver::execute(&options),
            options.limits.maximum_report_bytes,
        )
    } else {
        (options.preview(), plan::MAX_PREVIEW_BYTES)
    };
    match result {
        Ok(report) if emit(&mut io::stdout().lock(), &report, maximum).is_ok() => {
            ExitCode::from(ExitIdentity::SUCCESS.code)
        }
        Ok(_) => {
            eprintln!(
                "ERR-CLI-RUNTIME-FAILURE-001: report output failed. Imports may be durable; retain all stores and repeat the exact approved plan to reconcile."
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
        Err(code) => {
            eprintln!(
                "{code}: selected RTSP watch not confirmed. Earlier imports may be durable; retain all stores and repeat the exact approved plan to reconcile."
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
#[path = "fss-watch-rtsp-selected/tests.rs"]
mod tests;
