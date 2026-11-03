#![forbid(unsafe_code)]
//! Exact offline RTP/JPEG source import through the native custody owner.

use std::ffi::OsString;
use std::process::ExitCode;

use fss_cli::ExitIdentity;

#[path = "jpeg/driver.rs"]
mod driver;
#[path = "jpeg/plan.rs"]
mod plan;

pub(super) const MAX_ARGUMENTS: usize = plan::MAX_ARGUMENTS;

pub(super) fn main(args: &[OsString]) -> ExitCode {
    if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help")) {
        return ExitCode::from(if super::emit(plan::HELP).is_ok() {
            ExitIdentity::SUCCESS.code
        } else {
            ExitIdentity::RUNTIME_FAILURE.code
        });
    }
    let options = match plan::Options::parse(args) {
        Ok(options) => options,
        Err(reason) => {
            eprintln!("ERR-CLI-MALFORMED-VALUE-001: {reason}. Use fss-import-rtsp jpeg --help.");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    let result = if options.approve.is_none() {
        options.preview()
    } else {
        driver::execute(&options)
    };
    match result {
        Ok(report) if super::emit(&report).is_ok() => ExitCode::from(ExitIdentity::SUCCESS.code),
        Ok(_) => {
            eprintln!(
                "ERR-CLI-RUNTIME-FAILURE-001: output failed; the approved JPEG import may already be durable. Retry the exact plan to reconcile."
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
        Err(code) => {
            eprintln!(
                "{code}: this attempt did not confirm the JPEG import; preserve the exact approved plan and original source for reconciliation."
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
#[path = "jpeg/tests.rs"]
mod tests;
