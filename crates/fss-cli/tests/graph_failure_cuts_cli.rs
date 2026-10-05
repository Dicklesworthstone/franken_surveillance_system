#![forbid(unsafe_code)]
//! Exercise the real binary dispatcher and pre-I/O refusal/output contract.

use std::process::{Command, Output};

fn invoke(args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(args)
        .output()
}

#[test]
fn command_help_is_reachable_without_a_deployment() -> Result<(), Box<dyn std::error::Error>> {
    let output = invoke(&["graph", "failure-cuts", "--help"])?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("--max-failed-domains"));
    assert!(help.contains("--timeline"));
    assert!(help.contains("NOT an independence certificate"));
    let graph_help = invoke(&["graph", "--help"])?;
    assert!(graph_help.status.success());
    assert!(String::from_utf8(graph_help.stdout)?.contains("failure-cuts --help"));
    Ok(())
}

#[test]
fn invalid_requests_produce_no_json_or_partial_prefix() -> Result<(), Box<dyn std::error::Error>> {
    let base = [
        "graph", "failure-cuts", "--root", "must-not-be-opened", "--site", "site:test",
        "--max-failed-domains", "2", "--failure-domain", "power:left=a",
        "--failure-domain", "network:right=b",
    ];
    for window in ["2:1", "NaN:0", "0:1:2", "170141183460469231731687303715884105728:0"] {
        for timeline in [false, true] {
            let mut args = base.to_vec();
            args.extend(["--during", window]);
            if timeline {
                args.push("--timeline");
            }
            let output = invoke(&args)?;
            assert_eq!(output.status.code(), Some(i32::from(fss_cli::ExitIdentity::MALFORMED_VALUE.code)));
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8(output.stderr)?.contains(fss_cli::ERR_CLI_MALFORMED_VALUE));
        }
    }
    Ok(())
}

#[test]
fn oversized_combination_family_is_refused_before_snapshot_io() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = [
        "graph", "failure-cuts", "--root", "must-not-be-opened", "--site", "site:test",
        "--during", "0:1", "--timeline", "--max-failed-domains", "3",
    ].into_iter().map(str::to_owned).collect();
    for index in 0..16 {
        args.push("--failure-domain".into());
        args.push(format!("power:circuit-{index}=camera-{index}"));
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = invoke(&args)?;
    assert_eq!(output.status.code(), Some(i32::from(fss_cli::ExitIdentity::MALFORMED_VALUE.code)));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr)?;
    assert!(error.contains("256 combinations"));
    assert!(!error.contains("deployment read failed"));
    Ok(())
}
