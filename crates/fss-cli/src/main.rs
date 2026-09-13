#![forbid(unsafe_code)]
//! Agent-friendly design-skeleton CLI for Franken Surveillance System.

use std::env;
use std::process::ExitCode;

use fss_cli::{emit_diagnostic, execute_fss_with_exit, parse_fss_args};

fn main() -> ExitCode {
    match parse_fss_args(env::args_os().skip(1)) {
        Ok(command) => {
            let is_json = command.is_json();
            let (output, exit_id) = execute_fss_with_exit(command);
            if is_json || exit_id.code == 0 {
                println!("{output}");
            } else {
                eprintln!("{output}");
            }
            ExitCode::from(exit_id.code)
        }
        Err(error) => {
            emit_diagnostic(&error, "fss", None);
            ExitCode::from(error.exit_identity().code)
        }
    }
}
