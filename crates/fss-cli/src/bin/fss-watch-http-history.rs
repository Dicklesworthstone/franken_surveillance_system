#![forbid(unsafe_code)]
//! Exact, owner-approved retained HTTP history → native whole-recording watch reports.

use std::io::{self, Write};
use std::process::ExitCode;

use fss_cli::ExitIdentity;

#[path = "fss-watch-http-history/driver.rs"]
mod driver;
#[path = "fss-watch-http-history/plan.rs"]
mod plan;
#[path = "fss-watch-http-history/rerun.rs"]
mod rerun;

use plan::{MAX_ARGUMENTS, Options};

const HELP: &str = "fss-watch-http-history --archive EXISTING_ABSOLUTE_ARCHIVE --root ABSOLUTE_DEPLOYMENT --site SITE\n\
  --history-session sha256:HEX --history-root sha256:HEX --history-connections N\n\
  --binding GENERATION,SENSOR,STREAM,RECEIVE_NS,CAPTURE_START_NS,UNCERTAINTY_NS,FPS (repeat in connection order)\n\
  --interpretation gray|ycbcr --zone ID:X,Y,W,H (repeat) [--principal ID]\n\
  --owner-authorized yes --read-originals yes --retain-originals yes [--approve-import sha256:PLAN]\n\
  Without --approve-import: exact plan preview, with no filesystem, clock or network I/O.\n\
  Approved execution verifies the selected immutable history and imports every complete JPEG\n\
  in each generation, then runs native whole-recording watch with fresh tracking per reconnect.\n\
  Supply explicit capture timing for EVERY generation; receive time never becomes capture time.\n\
  --max-frames-per-generation 128 --max-bytes-per-generation 67108864\n\
  --max-history-reads 8192 --max-history-bytes 536870912 --max-report-bytes 33619968\n\
  Whole-operation source work: --max-work 1000000000000 --max-framing-work 10000000000\n\
  Cooperative deadline: --timeout-ms 30000. These allowances never refill at a reconnect.\n\
  Timer checks bracket each generation's analysis; one native analysis is work-bounded and\n\
  ReplayCx-cancellable but cannot be preempted by this CLI wall-clock timer.\n\
  Per-generation watch budgets: --work-units 100000000 --stream-read-bytes 536870912\n\
    --stream-pixel-budget 1073741824 --stream-assignment-work 1073741824 --stream-trace-bytes 8388608\n\
    --max-dimension 4096 --max-pixels 4194304 --max-segment-bytes N\n\
  Watch thresholds: --pixel-threshold 25 --threshold-sigma 3 --learning-rate-num 1\n\
    --learning-rate-den 32 --min-region-pixels 16 --confirmation-hits 3\n\
    --maximum-missed-frames 2 --minimum-iou-ppm 100000\n\
  Optional: --screened yes --tolerate-decode-refusals yes (defaults: no).\n\
  The preview reserves the sum of all per-generation watch allowances before any I/O.\n\
  Exact retries reconcile completed/partially published imports and recompute analysis.\n\
  A later failure may leave earlier imports durable; retry the same approved plan to reconcile.\n\
  Reports keep empty attempts and prefixes without a complete JPEG explicit; they prove no absence.\n\
  Current sensor privacy masks apply at native decode. Originals remain local, unencrypted.\n\
  Archive opening takes the existing publisher lock and can finish publication recovery.\n\
  Source and destination must be distinct non-nested stores; no network connection is opened.\n\
  This command retains originals and produces candidate reports. Event publication is a separate\n\
  exact fss-event watch --stream-watch command supplied for each eligible candidate.\n";

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
                Err(e) if e.kind() == io::ErrorKind::Interrupted && interrupted < 7 => {
                    interrupted += 1
                }
                Err(e) => return Err(e),
            }
        }
    }
    out.flush()
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os()
        .skip(1)
        .take(MAX_ARGUMENTS + 1)
        .collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "help")) {
        return ExitCode::from(if emit(&mut io::stdout().lock(), HELP, 65536).is_ok() {
            ExitIdentity::SUCCESS.code
        } else {
            ExitIdentity::RUNTIME_FAILURE.code
        });
    }
    let options = match Options::parse(&args) {
        Ok(options) => options,
        Err(reason) => {
            eprintln!("ERR-CLI-MALFORMED-VALUE-001: {reason}. Use fss-watch-http-history --help.");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    let (result, maximum) = if options.approve.is_some() {
        (
            driver::execute(&options),
            options.limits.maximum_report_bytes,
        )
    } else {
        (options.preview(), 65536)
    };
    match result {
        Ok(report) if emit(&mut io::stdout().lock(), &report, maximum).is_ok() => {
            ExitCode::from(ExitIdentity::SUCCESS.code)
        }
        Ok(_) => {
            eprintln!(
                "ERR-CLI-RUNTIME-FAILURE-001: output failed. Approved runs may have retained imports; retry the exact plan to reconcile."
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
        Err(id) => {
            eprintln!(
                "{id}: history watch refused. Approved runs may have retained earlier imports; retry the exact plan to reconcile."
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
#[path = "fss-watch-http-history/tests.rs"]
mod tests;
