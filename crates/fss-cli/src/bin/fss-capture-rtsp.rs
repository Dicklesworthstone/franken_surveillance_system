#![forbid(unsafe_code)]
//! Bounded, explicitly approved native RTSP/AVC recording with durable recovery pins.

use std::io::{self, Write};
use std::process::ExitCode;

use fss_cli::ExitIdentity;

#[path = "fss-capture-rtsp/authentication.rs"]
mod authentication;
#[path = "fss-capture-rtsp/driver.rs"]
mod driver;
#[path = "fss-capture-rtsp/plan.rs"]
mod plan;
#[path = "fss-capture-rtsp/timing.rs"]
mod timing;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os()
        .skip(1)
        .take(plan::MAX_ARGUMENTS + 1)
        .collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
        return match write_bounded(plan::HELP.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        };
    }
    let options = match plan::Options::parse(&args) {
        Ok(options) => options,
        Err(reason) => {
            eprintln!("ERR-CAPTURE-RTSP-ARGUMENT-001: {reason}; use --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    let result = if let Some(approval) = options.approve {
        match options.digest() {
            Ok(expected) if approval == expected => driver::execute(&options),
            _ => Err("ERR-CAPTURE-RTSP-APPROVAL-001"),
        }
    } else {
        options
            .preview()
            .and_then(|preview| write_bounded((preview + "\n").as_bytes()))
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => {
            eprintln!(
                "{code}: capture not complete; preserve archive, pin journal and complete JSONL rows"
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

// Each call consumes bytes or one of eight permitted interruptions at that offset.
// Preview/help are bounded before reaching this writer; no write_all retry loop is hidden here.
fn write_bounded(bytes: &[u8]) -> Result<(), &'static str> {
    let mut out = io::stdout().lock();
    let mut offset = 0;
    let mut interrupted = 0_u8;
    while offset < bytes.len() {
        let end = (offset + 4096).min(bytes.len());
        match out.write(&bytes[offset..end]) {
            Ok(0) => return Err("ERR-CAPTURE-RTSP-OUTPUT-001"),
            Ok(count) => {
                offset += count;
                interrupted = 0;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted && interrupted < 7 => {
                interrupted += 1;
            }
            Err(_) => return Err("ERR-CAPTURE-RTSP-OUTPUT-001"),
        }
    }
    out.flush().map_err(|_| "ERR-CAPTURE-RTSP-OUTPUT-001")
}
