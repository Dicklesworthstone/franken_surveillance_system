#![forbid(unsafe_code)]
//! Explicitly approved HTTP reacquisition with durable-before-parse source custody.
//!
//! Each connection has an owner-selected generation and a non-replenishing allowance.
//! The existing reconnect and archive owners decide retry, source boundaries and durability.
//! This domain CLI neither publishes events nor certifies scene absence.

use std::io::{self, Write};
use std::process::ExitCode;

use fss_cli::ExitIdentity;

#[path = "fss-capture-reconnect/plan.rs"]
mod plan;
#[path = "fss-capture-reconnect/driver.rs"]
mod driver;
#[path = "fss-capture/privacy.rs"]
mod privacy;
#[path = "fss-capture-reconnect/decode.rs"]
mod decode;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).take(plan::MAX_ARGUMENTS + 1).collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
        return match driver::write_bounded(&mut io::stdout().lock(), plan::HELP.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        };
    }
    let options = match plan::Options::parse(&args) {
        Ok(options) => options,
        Err(reason) => {
            eprintln!("ERR-CAPTURE-RECONNECT-ARGUMENT-001: {reason}; use --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    let mut out = io::stdout().lock();
    let result = if options.approve.is_none() {
        driver::write_bounded(&mut out, (options.preview() + "\n").as_bytes())
            .and_then(|()| out.flush())
            .map(|()| true)
            .map_err(|_| "ERR-CAPTURE-RECONNECT-OUTPUT-001")
    } else {
        driver::capture(&options, &mut out)
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        Err(code) => {
            eprintln!("{code}: preserve all complete prefix pins; inspect storage, not automatic reacquisition");
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

// Shared privacy renderer uses the same exact digest/number presentation as fss-capture.
fn byte_digest(bytes: [u8; 32]) -> String {
    format!("sha256:{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}
fn optional_number(value: Option<u64>) -> String {
    value.map_or_else(|| "null".into(), |n| n.to_string())
}
