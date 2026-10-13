#![forbid(unsafe_code)]
//! Explicit native frame publication, cold reads and full-range replay verification.

use std::io::{self, Write};
use std::process::ExitCode;

#[path = "fss-video/plan.rs"]
mod plan;
#[path = "fss-video/operation.rs"]
mod operation;

pub(crate) type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).take(plan::MAX_ARGUMENTS + 1).collect();
    let mut out = io::stdout().lock();
    let result = if args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "help" | "-h")) {
        write_bounded(&mut out, plan::HELP.as_bytes())
    } else {
        match plan::Plan::parse(&args) {
            Ok(plan) if plan.approval.is_none() => plan.preview().and_then(|text| {
                write_bounded(&mut out, (text + "\n").as_bytes())
            }),
            Ok(plan) => operation::run(&plan, &mut out),
            Err(reason) => {
                eprintln!("{}: {reason}; use fss-video --help", fss_cli::ERR_CLI_MALFORMED_VALUE);
                return ExitCode::from(fss_cli::ExitIdentity::MALFORMED_VALUE.code);
            }
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Native diagnostics contain categories, never source payloads or credentials.
            eprintln!("{}: {error}", fss_cli::ERR_CLI_RUNTIME_FAILURE);
            if let Some(error) = error.downcast_ref::<fss_reference::ingest::recorded_decode::RecordedDecodeError>() {
                eprintln!("refusal_id={}", error.stable_id());
            }
            eprintln!("Operation incomplete. Preserve emitted frame roots and deployment custody. Completed frames survive later failure; retry the exact publication. No rollback or automatic repair occurred.");
            ExitCode::from(fss_cli::ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

pub(crate) fn fail(message: &'static str) -> Box<dyn std::error::Error> {
    io::Error::other(message).into()
}

// A positive write advances or at most eight interruptions are admitted at the same offset.
pub(crate) fn write_bounded(out: &mut impl Write, bytes: &[u8]) -> Result<()> {
    let mut offset = 0;
    let mut interruptions = 0;
    while offset < bytes.len() {
        let end = (offset + 4096).min(bytes.len());
        match out.write(&bytes[offset..end]) {
            Ok(0) => return Err(fail("output did not advance")),
            Ok(count) => { offset += count; interruptions = 0; }
            Err(error) if error.kind() == io::ErrorKind::Interrupted && interruptions < 7 => {
                interruptions += 1;
            }
            Err(error) => return Err(error.into()),
        }
    }
    out.flush()?;
    Ok(())
}
