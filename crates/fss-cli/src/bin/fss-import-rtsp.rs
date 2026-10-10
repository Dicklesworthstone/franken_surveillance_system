#![forbid(unsafe_code)]
//! Owner-approved, source-preserving import of an exact native RTSP recording window.

use std::io::{self, Write};
use std::process::ExitCode;

use fss_cli::ExitIdentity;

#[path = "fss-import-rtsp/driver.rs"]
mod driver;
#[path = "fss-import-rtsp/plan.rs"]
mod plan;

use plan::{MAX_ARGUMENTS, Options};

const HELP: &str = "fss-import-rtsp --archive EXISTING_ABSOLUTE_ARCHIVE --root ABSOLUTE_DEPLOYMENT --site SITE\n\
  --window-slot SLOT --window-root sha256:HEX --codec avc|hevc\n\
  --sensor-id ID --stream-id ID --generation N --anchor sha256:HEX --receive-clock sha256:HEX\n\
  --receive-time-ns N --owner-authorized yes --read-originals yes --retain-originals yes\n\
  [--approve sha256:PLAN] [--principal ID]\n\
  Optional timing: --capture-start-ns N --capture-uncertainty-ns N (both required).\n\
  MP4 presentation timestamps determine frame offsets. Capture origin is an operator assumption;\n\
  RTP ticks and receive clocks do not establish a capture origin.\n\
  Bounds: --max-frames 256 --max-original-bytes 33554432 --max-media-bytes 33554432\n\
          --max-work 1000000000000 --timeout-ms 30000.\n\
  Without --approve: exact plan preview without filesystem, clock or network I/O.\n\
  Approved execution verifies the original RTP-to-NAL-to-MP4 mapping and retains the\n\
  original recording root, RTP source pack, index, initialization and media fragment.\n\
  Native decode, motion, watch and corroboration consume the returned retained import identity.\n\
  Exact retries reconcile completed or partial imports; they still require the selected archive.\n\
  Destination analysis needs only retained destination custody after the import completes.\n\
  Current destination sensor privacy masks apply when decoding. Originals remain local unencrypted.\n\
  Source and destination must be distinct, non-nested stores. No network connection is opened.\n\
  Opening the archive uses its exclusive publisher lock and can complete publication recovery.\n\
  The timeout is cooperative at custody boundaries; one bounded native verifier is not preempted.\n";

fn emit(text: &str) -> io::Result<()> {
    if text.len() > 16 * 1024 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut out = io::stdout().lock();
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
        .take(MAX_ARGUMENTS + 1)
        .collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help")) {
        return ExitCode::from(if emit(HELP).is_ok() {
            ExitIdentity::SUCCESS.code
        } else {
            ExitIdentity::RUNTIME_FAILURE.code
        });
    }
    let options = match Options::parse(&args) {
        Ok(value) => value,
        Err(reason) => {
            eprintln!("ERR-CLI-MALFORMED-VALUE-001: {reason}. Use fss-import-rtsp --help.");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    let result = if options.approve.is_none() {
        options.preview()
    } else {
        driver::execute(&options)
    };
    match result {
        Ok(report) if emit(&report).is_ok() => ExitCode::from(ExitIdentity::SUCCESS.code),
        Ok(_) => {
            eprintln!(
                "ERR-CLI-RUNTIME-FAILURE-001: output failed; the approved import may already be durable. Retry the exact plan to reconcile."
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
        Err(code) => {
            eprintln!(
                "{code}: this attempt did not confirm the import; retain the exact approved plan for reconciliation."
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
#[path = "fss-import-rtsp/tests.rs"]
mod tests;
