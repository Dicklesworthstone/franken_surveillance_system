#![forbid(unsafe_code)]
//! Agent-friendly design-skeleton CLI for Franken Surveillance System.

use std::env;
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        None | Some("help" | "--help" | "-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("version" | "--version" | "-V") => {
            println!("fss {VERSION}");
            ExitCode::SUCCESS
        }
        Some("capabilities") if args.next().as_deref() == Some("--json") => {
            println!(
                "{{\"schema\":\"fss.capabilities.v1\",\"version\":\"{VERSION}\",\"status\":\"design_skeleton\",\"implemented\":[\"semantic_contracts\",\"machine_readable_registries\"],\"not_implemented\":[\"device_acquisition\",\"media_decode\",\"inference\",\"archive_upload\",\"alerts\"]}}"
            );
            ExitCode::SUCCESS
        }
        Some("doctor") if args.next().as_deref() == Some("--json") => {
            println!(
                "{{\"schema\":\"fss.doctor.v1\",\"version\":\"{VERSION}\",\"verdict\":\"design_only\",\"checks\":[{{\"id\":\"core.contracts\",\"status\":\"present\"}},{{\"id\":\"runtime.acquisition\",\"status\":\"not_implemented\"}},{{\"id\":\"release.qualification\",\"status\":\"not_qualified\"}}]}}"
            );
            ExitCode::SUCCESS
        }
        Some("status") if args.next().as_deref() == Some("--json") => {
            println!(
                "{{\"schema\":\"fss.status.v1\",\"version\":\"{VERSION}\",\"phase\":\"architecture_constitution\",\"sensors\":[],\"events\":[],\"degraded\":[\"no_runtime_implementation\"]}}"
            );
            ExitCode::SUCCESS
        }
        Some(command) => {
            eprintln!("unknown or incomplete command: {command}");
            eprintln!("run `fss help` for the current design-skeleton surface");
            ExitCode::from(2)
        }
    }
}

fn print_help() {
    println!(
        "Franken Surveillance System design skeleton\n\nUSAGE:\n  fss help\n  fss version\n  fss capabilities --json\n  fss doctor --json\n  fss status --json\n\nNo camera, drone, model, archive, or alert operation is implemented yet."
    );
}
