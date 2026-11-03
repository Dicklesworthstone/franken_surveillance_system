#![forbid(unsafe_code)]
//! One approved native acquisition feeds source-closed trained detection.

#[path = "../fss-sentinel-http-history/plan.rs"]
mod analysis_plan;
#[path = "../fss-watch-rtsp-campaign/archive_open.rs"]
mod archive_open;
#[path = "sentinel/continuation.rs"]
mod continuation;
#[path = "sentinel/driver.rs"]
mod driver;
#[path = "../fss-sentinel-rtsp-campaign/model.rs"]
mod model;
#[path = "sentinel/plan.rs"]
mod plan;
#[path = "sentinel/preflight.rs"]
mod preflight;
#[cfg(test)]
#[path = "sentinel/tests.rs"]
mod tests;

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use fss_cli::ExitIdentity;
use fss_cli::agent_json::{object, string};

pub(super) use plan::MAX_ARGUMENTS;
use plan::Options;

const AUTHORITY: &str = "ERR-HTTP-CAPTURE-SENTINEL-AUTHORITY-001";
const DEADLINE: &str = "ERR-HTTP-CAPTURE-SENTINEL-DEADLINE-001";
const LIMIT: &str = "ERR-HTTP-CAPTURE-SENTINEL-LIMIT-001";
const PATH: &str = "ERR-HTTP-CAPTURE-SENTINEL-PATH-001";
const SOURCE: &str = "ERR-HTTP-CAPTURE-SENTINEL-SOURCE-001";
const OUTPUT: &str = "ERR-CAPTURE-RECONNECT-OUTPUT-001";

fn emit(
    options: &Options,
    out: &mut impl Write,
    kind: &str,
    detail: String,
) -> Result<(), &'static str> {
    let row = object(&[
        ("format", string(plan::FORMAT)),
        ("kind", string(kind)),
        ("approval_digest", string(&options.approval()?.to_text())),
        ("detail", detail),
    ]) + "\n";
    if row.len() > options.analysis.limits.maximum_report_bytes {
        return Err(LIMIT);
    }
    super::driver::write_bounded(out, row.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|_| OUTPUT)
}

pub(super) fn main(args: &[OsString]) -> ExitCode {
    let mut out = io::stdout().lock();
    if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
        return ExitCode::from(
            if super::driver::write_bounded(&mut out, plan::HELP.as_bytes())
                .and_then(|()| out.flush())
                .is_ok()
            {
                ExitIdentity::SUCCESS.code
            } else {
                ExitIdentity::RUNTIME_FAILURE.code
            },
        );
    }
    let mut options = match Options::parse(args) {
        Ok(options) => options,
        Err(reason) => {
            eprintln!(
                "ERR-CAPTURE-RECONNECT-ARGUMENT-001: {reason}; use fss-capture-reconnect sentinel --help"
            );
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    let result = if options.approve.is_some() {
        driver::execute(&mut options, &mut out)
    } else {
        options.preview().and_then(|preview| {
            super::driver::write_bounded(&mut out, (preview + "\n").as_bytes())
                .and_then(|()| out.flush())
                .map_err(|_| OUTPUT)
        })
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => {
            eprintln!(
                "{code}: preserve the capture transcript and stores; use the exact offline continuation after analysis failure, never automatic camera reacquisition"
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}
