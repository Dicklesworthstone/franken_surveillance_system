#![forbid(unsafe_code)]
//! Tests for total argument decoding of the `fss-hydration-rehearsal` binary.

use std::ffi::OsString;
use std::process::Command;

use fss_cli::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_MALFORMED_VALUE, ERR_CLI_MISSING_VALUE,
    ERR_CLI_TRAILING_ARGUMENT, ERR_CLI_UNKNOWN_OPTION, HydrationAction, parse_hydration_args,
};

#[test]
fn valid_hydration_invocations_decode_successfully() {
    let cases: &[(&[&str], HydrationAction)] = &[
        (
            &[],
            HydrationAction::Run {
                scenario: "all".to_owned(),
            },
        ),
        (
            &["--scenario", "success"],
            HydrationAction::Run {
                scenario: "success".to_owned(),
            },
        ),
        (
            &["budget-fallback"],
            HydrationAction::Run {
                scenario: "budget-fallback".to_owned(),
            },
        ),
        (
            &["all"],
            HydrationAction::Run {
                scenario: "all".to_owned(),
            },
        ),
        (&["help"], HydrationAction::Help),
        (&["--help"], HydrationAction::Help),
    ];

    for (argv, expected) in cases {
        let os_args: Vec<OsString> = argv.iter().map(|&s| OsString::from(s)).collect();
        let result = parse_hydration_args(os_args);
        assert!(result.is_ok(), "failed to parse valid argv: {argv:?}");
        if let Ok(action) = result {
            assert_eq!(action, *expected, "mismatched action for: {argv:?}");
        }
    }
}

#[test]
fn trailing_arguments_on_hydration_rehearsal_are_rejected() {
    let cases: &[&[&str]] = &[
        &["--scenario", "success", "extra"],
        &["success", "extra"],
        &["all", "extra"],
        &["help", "extra"],
    ];

    for argv in cases {
        let os_args: Vec<OsString> = argv.iter().map(|&s| OsString::from(s)).collect();
        let result = parse_hydration_args(os_args);
        assert!(result.is_err(), "must reject trailing tokens: {argv:?}");
        if let Err(err) = result {
            assert_eq!(err.error_id(), ERR_CLI_TRAILING_ARGUMENT);
            assert_eq!(err.exit_identity().code, 2);
        }
    }
}

#[test]
fn hydration_failure_classes_distinguished() {
    // Missing value for --scenario
    let res = parse_hydration_args([OsString::from("--scenario")]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_MISSING_VALUE);
    }

    // Malformed scenario
    let res = parse_hydration_args([OsString::from("not-a-scenario")]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_MALFORMED_VALUE);
    }

    // Duplicate --scenario
    let res = parse_hydration_args([
        OsString::from("--scenario"),
        OsString::from("success"),
        OsString::from("--scenario"),
        OsString::from("expired"),
    ]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_DUPLICATE_OPTION);
    }

    // Unknown option
    let res = parse_hydration_args([OsString::from("--invalid-option")]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_UNKNOWN_OPTION);
    }
}

#[test]
fn real_process_hydration_execution() -> Result<(), Box<dyn std::error::Error>> {
    let bin_path = env!("CARGO_BIN_EXE_fss-hydration-rehearsal");

    // Valid run
    let output = Command::new(bin_path)
        .args(["--scenario", "success"])
        .output()?;
    assert!(output.status.success());
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("\"schema\":\"fss.hydration_rehearsal.v1\""));

    // Trailing argument
    let output = Command::new(bin_path).args(["success", "extra"]).output()?;
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("ERR-CLI-TRAILING-ARGUMENT-001"));
    assert!(stderr.contains("\"schema\":\"fss.cli_diagnostic.v1\""));

    // Missing value
    let output = Command::new(bin_path).arg("--scenario").output()?;
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("ERR-CLI-MISSING-VALUE-001"));

    Ok(())
}
