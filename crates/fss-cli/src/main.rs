#![forbid(unsafe_code)]
//! Agent-friendly design-skeleton CLI for Franken Surveillance System.

use std::env;
use std::process::ExitCode;

use fss_cli::{emit_diagnostic, execute_fss, parse_fss_args};

fn main() -> ExitCode {
    match parse_fss_args(env::args_os().skip(1)) {
        Ok(command) => {
            let output = execute_fss(command);
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            emit_diagnostic(&error, "fss", None);
            ExitCode::from(error.exit_identity().code)
        }
    }
}
