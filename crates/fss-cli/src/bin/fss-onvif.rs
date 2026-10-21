#![forbid(unsafe_code)]
//! Bounded owner-authorized ONVIF Media1/Media2 onboarding and private RTSP handoff.

use std::io::{self, Write};
use std::process::ExitCode;

#[path = "fss-capture-rtsp/authentication.rs"]
mod authentication;
#[path = "fss-onvif/driver.rs"]
mod driver;
#[path = "fss-onvif/handoff.rs"]
mod handoff;
#[path = "fss-onvif/plan.rs"]
mod plan;
#[path = "fss-onvif/private_file.rs"]
mod private_file;
#[path = "fss-onvif/runtime.rs"]
mod runtime;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os()
        .skip(1)
        .take(plan::MAX_ARGUMENTS + 1)
        .collect();
    let result = if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
        Ok(plan::HELP.to_owned())
    } else {
        plan::Plan::parse(&args).and_then(|plan| {
            if plan.approval.is_some() {
                driver::execute(&plan)
            } else {
                plan.preview()
            }
        })
    };
    match result.and_then(|text| write_bounded(text.as_bytes())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => {
            eprintln!(
                "{code}: ONVIF onboarding did not complete; use --help; preserve any private output"
            );
            ExitCode::from(1)
        }
    }
}

fn write_bounded(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.len() > 16384 {
        return Err("ERR-ONVIF-OUTPUT-001");
    }
    let mut output = io::stdout().lock();
    let mut offset = 0;
    let mut interruptions = 0;
    while offset < bytes.len() {
        match output.write(&bytes[offset..(offset + 4096).min(bytes.len())]) {
            Ok(0) => return Err("ERR-ONVIF-OUTPUT-001"),
            Ok(count) => {
                offset += count;
                interruptions = 0;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted && interruptions < 7 => {
                interruptions += 1
            }
            Err(_) => return Err("ERR-ONVIF-OUTPUT-001"),
        }
    }
    output.flush().map_err(|_| "ERR-ONVIF-OUTPUT-001")
}
