#![forbid(unsafe_code)]
//! Explicit local archive operator utility, not a second agent protocol.
use std::io::{self, Write};
use std::process::ExitCode;
use fss_cli::archive_cmd::{ArchiveCommandError, HELP, execute_archive, parse_archive_args};
use fss_cli::{ERR_CLI_RUNTIME_FAILURE, ExitIdentity};

#[path = "fss-archive/work.rs"]
mod work;
#[path = "fss-archive/pins.rs"]
mod pins;
#[path = "fss-archive/recipes.rs"]
mod recipes;
#[path = "fss-archive/http.rs"]
mod http;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).take(66).collect();
    if http::handles(&args) { return http::dispatch(&args); }
    if recipes::handles(&args) { return recipes::dispatch(&args); }
    if pins::handles(&args) { return pins::dispatch(&args); }
    let result = if work::handles(&args) { work::execute(&args) } else { match parse_archive_args(&args) {
        Ok(None) => Ok(format!("{HELP}\n{}\n{}\n{}\n{}", work::HELP, pins::HELP, recipes::HELP, http::HELP)),
        Ok(Some(options)) => execute_archive(&options),
        Err(error) => Err(error),
    }};
    match result {
        Ok(report) => match emit(&mut io::stdout().lock(), report.as_bytes()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Err(error) => {
            let usage = matches!(&error, ArchiveCommandError::Argument { .. });
            let code = match &error { ArchiveCommandError::Argument { code, .. } => *code, _ => ERR_CLI_RUNTIME_FAILURE };
            eprintln!("{code}: {error}");
            if work::handles(&args) {
                eprintln!("No complete report was emitted. Only exact checkpointed roots may have committed. Retain the original work pin, inspect storage and reconcile before retrying; no automatic cleanup occurred. Use fss-archive help.");
            } else {
                eprintln!("No complete report was emitted. Existing roots are not repaired, deleted or replaced. An incomplete export may remain; reconcile COMPLETE.json before reuse. Use fss-archive help.");
            }
            ExitCode::from(if usage { ExitIdentity::MALFORMED_VALUE.code } else { ExitIdentity::RUNTIME_FAILURE.code })
        }
    }
}

// Do not let repeated EINTR turn the final report into an unbounded retry loop.
fn emit(writer: &mut impl Write, mut bytes: &[u8]) -> io::Result<()> {
    let mut interrupted = 0;
    while !bytes.is_empty() {
        let chunk = &bytes[..bytes.len().min(64 * 1024)];
        match writer.write(chunk) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) if n <= chunk.len() => { bytes = &bytes[n..]; interrupted = 0; }
            Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted && interrupted < 7 => interrupted += 1,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
