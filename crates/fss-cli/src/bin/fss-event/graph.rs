#![forbid(unsafe_code)]
//! Read-only graph command dispatch. Historical commands retain their exact implementation.

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

#[path = "graph_cuts.rs"]
mod cuts;
#[path = "graph_legacy.rs"]
mod legacy;
#[path = "graph_reliability.rs"]
mod reliability;

pub(super) fn main(args: &[OsString]) -> ExitCode {
    if args.first().and_then(|arg| arg.to_str()) == Some("failure-cuts") {
        return cuts::main(args);
    }
    if args.first().and_then(|arg| arg.to_str()) == Some("reliability") {
        return reliability::main(args);
    }
    if matches!(args, [flag] if matches!(flag.to_str(), Some("help" | "--help" | "-h")))
        && writeln!(
            io::stdout().lock(),
            "Joint dependency failures: fss-event graph failure-cuts --help\n\
             Blindness probability bounds: fss-event graph reliability --help"
        )
        .is_err()
    {
        return ExitCode::from(fss_cli::ExitIdentity::RUNTIME_FAILURE.code);
    }
    legacy::main(args)
}
