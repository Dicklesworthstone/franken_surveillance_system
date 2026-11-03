#![forbid(unsafe_code)]
//! Exact retained HTTP history → native motion-independent trained detector bursts.

#[path = "fss-watch-rtsp-campaign/archive_open.rs"]
mod archive_open;
#[path = "fss-sentinel-http-history/driver.rs"]
mod driver;
#[path = "fss-sentinel-rtsp-campaign/model.rs"]
mod model;
#[path = "fss-sentinel-http-history/plan.rs"]
mod plan;
#[cfg(test)]
#[path = "fss-sentinel-http-history/tests.rs"]
mod tests;

use fss_cli::ExitIdentity;
use std::io::{self, Write};
use std::process::ExitCode;

const HELP: &str = "fss-sentinel-http-history --archive EXISTING_ABSOLUTE_ARCHIVE --root ABSOLUTE_DEPLOYMENT --site SITE\n\
  --history-session sha256:HEX --history-root sha256:HEX --history-connections N\n\
  --binding GENERATION,SENSOR,STREAM,RECEIVE_NS,CAPTURE_START_NS,UNCERTAINTY_NS,FPS (in connection order)\n\
  --interpretation gray|ycbcr --package ABSOLUTE_FMPK --package-digest sha256:HEX\n\
  --sentinel-every-frames N --sentinel-burst-frames K --sentinel-max-inferences M\n\
  --retain-analysis yes|no --owner-authorized yes --read-originals yes --retain-originals yes\n\
  --read-model yes [--principal principal:local-operator] [--approve-import sha256:PLAN]\n\
\n\
Without approval: exact plan preview with no filesystem, clock, model or network I/O.\n\
Approved execution verifies the exact ended HTTP history, imports every complete original JPEG,\n\
then runs the pinned native detector independently of motion. Explicit camera and capture-time\n\
bindings are required for every connection. Receive time never becomes capture time.\n\
\n\
Whole bursts are allocated round-robin across recordings under ONE inference allowance.\n\
Period 1..65536; burst 1..8 and <=period; M 1..2048, at most 64 inferences per generation.\n\
Empty, failed, too-short and budget-skipped generations remain explicit. Tracking never crosses\n\
reconnects or separate bursts. Current destination privacy masks apply before native inference.\n\
\n\
Import bounds: --max-frames-per-generation 128 --max-bytes-per-generation 67108864\n\
  --max-history-reads 8192 --max-history-bytes 536870912\n\
Shared analysis pools: --stream-read-bytes 536870912 --stream-pixel-budget 1073741824\n\
Per-inference ceilings: --max-macs 8000000000 --max-tensor-bytes 268435456\n\
  --max-output-bytes 16777216 [--max-frame-pixels N] [--minimum-score-ppm N]\n\
  --max-frame-pixels accepts 256..9437184 and narrows the exact retained native recipe.\n\
  --kernels optimized-cpu|scalar-reference --threads N (1..64; default 1)\n\
Whole operation: --max-work 1000000000000 --max-framing-work 10000000000\n\
  --archive-read-bytes 1073741824 --timeout-ms 30000 --max-report-bytes 33619968\n\
  --sentinel-report-bytes 16777216. Option names and values are separate arguments.\n\
Archive opening/recovery and subsequent reads share one byte/operation account. Timers are\n\
cooperative at I/O and native operation boundaries; they do not preempt a native operation.\n\
\n\
Retained analyses include exact package and recipes and provide fss-infer sentinel-replay\n\
commands usable after the source archive and loose model go offline. A later refusal may leave\n\
earlier imports or analyses durable; retry the exact approved plan to verify and reuse them.\n\
Source and destination must be distinct non-nested stores. No camera or network is opened.\n\
No model activation, event/alert authority, continuous coverage, absence or quality is claimed.\n";

fn emit(text: &str, maximum: usize) -> io::Result<()> {
    if text.len() > maximum {
        return Err(io::Error::other("complete history output bound"));
    }
    let mut output = io::stdout().lock();
    let mut bytes = text.as_bytes();
    let mut interrupted = 0;
    while !bytes.is_empty() {
        match output.write(&bytes[..bytes.len().min(4096)]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) if count <= bytes.len().min(4096) => {
                bytes = &bytes[count..];
                interrupted = 0;
            }
            Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted && interrupted < 7 => {
                interrupted += 1;
            }
            Err(error) => return Err(error),
        }
    }
    output.flush()
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os()
        .skip(1)
        .take(plan::MAX_ARGUMENTS + 1)
        .collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "help")) {
        return ExitCode::from(if emit(HELP, plan::MAX_PREVIEW_BYTES).is_ok() {
            ExitIdentity::SUCCESS.code
        } else {
            ExitIdentity::RUNTIME_FAILURE.code
        });
    }
    let options = match plan::Options::parse(&args) {
        Ok(options) => options,
        Err(reason) => {
            eprintln!(
                "ERR-CLI-MALFORMED-VALUE-001: {reason}. Use fss-sentinel-http-history --help."
            );
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
        Ok(mut report) => {
            report.push('\n');
            let maximum = if approved {
                options.limits.maximum_report_bytes
            } else {
                plan::MAX_PREVIEW_BYTES
            };
            if emit(&report, maximum).is_ok() {
                ExitCode::SUCCESS
            } else {
                eprintln!(
                    "ERR-CLI-RUNTIME-FAILURE-001: output failed; imports/analysis may be durable; retain stores and retry the exact plan"
                );
                ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
            }
        }
        Err(reason) => {
            eprintln!(
                "{reason}: history sentinel not confirmed; earlier imports/analysis may remain durable; retry the same approved plan"
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}
