#![forbid(unsafe_code)]
//! Explicit local archive operator utility, not a second agent protocol.
use std::io::{self, Write};
use std::process::ExitCode;
use fss_cli::archive_cmd::{ArchiveCommandError, HELP, execute_archive, parse_archive_args};
use fss_cli::{ERR_CLI_RUNTIME_FAILURE, ExitIdentity};

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).take(66).collect();
    let result = match parse_archive_args(&args) {
        Ok(None) => Ok(HELP.to_owned()),
        Ok(Some(options)) => execute_archive(&options),
        Err(error) => Err(error),
    };
    match result {
        Ok(report) => match emit(&mut io::stdout().lock(), report.as_bytes()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Err(error) => {
            let usage = matches!(&error, ArchiveCommandError::Argument { .. });
            let code = match &error { ArchiveCommandError::Argument { code, .. } => *code, _ => ERR_CLI_RUNTIME_FAILURE };
            eprintln!("{code}: {error}");
            eprintln!("No complete report was emitted. Existing roots are not repaired, deleted or replaced. An incomplete export may remain; reconcile COMPLETE.json before reuse. Use fss-archive help.");
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
