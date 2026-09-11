#![forbid(unsafe_code)]
//! Tests for total argument decoding of the `fss-lab` binary.

use std::ffi::OsString;
use std::process::Command;

use fss_cli::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_MALFORMED_VALUE, ERR_CLI_MISSING_VALUE,
    ERR_CLI_TRAILING_ARGUMENT, ERR_CLI_UNKNOWN_COMMAND, ERR_CLI_UNKNOWN_OPTION, LabAction,
    parse_lab_args,
};

#[test]
fn valid_lab_commands_decode_successfully() {
    let cases: &[(&[&str], LabAction)] = &[
        (&[], LabAction::Help),
        (&["help"], LabAction::Help),
        (&["--help"], LabAction::Help),
        (&["-h"], LabAction::Help),
        (&["list"], LabAction::List),
        (&["matrix"], LabAction::Matrix),
        (&["self-test"], LabAction::SelfTest),
        (
            &["run", "quiet"],
            LabAction::Run {
                scenario: "quiet".to_owned(),
            },
        ),
        (
            &["run", "intrusion"],
            LabAction::Run {
                scenario: "intrusion".to_owned(),
            },
        ),
        (
            &["replay", "raccoon"],
            LabAction::Replay {
                scenario: "raccoon".to_owned(),
                repeat: 2,
            },
        ),
        (
            &["replay", "sneaky", "--repeat", "10"],
            LabAction::Replay {
                scenario: "sneaky".to_owned(),
                repeat: 10,
            },
        ),
    ];

    for (argv, expected) in cases {
        let os_args: Vec<OsString> = argv.iter().map(|&s| OsString::from(s)).collect();
        let result = parse_lab_args(os_args);
        assert!(result.is_ok(), "failed to parse valid lab argv: {argv:?}");
        if let Ok(action) = result {
            assert_eq!(action, *expected, "mismatched action for argv: {argv:?}");
        }
    }
}

#[test]
fn test_lab_replay_allows_options_before_positional() {
    let args = [
        OsString::from("replay"),
        OsString::from("--repeat"),
        OsString::from("5"),
        OsString::from("intrusion"),
    ];
    let res = parse_lab_args(args);
    assert_eq!(
        res.ok(),
        Some(LabAction::Replay {
            scenario: "intrusion".to_owned(),
            repeat: 5,
        })
    );
}

#[test]
fn trailing_arguments_on_all_lab_commands_are_rejected() {
    let cases: &[&[&str]] = &[
        &["list", "extra"],
        &["matrix", "extra"],
        &["self-test", "extra"],
        &["run", "quiet", "extra"],
        &["replay", "quiet", "extra"],
        &["replay", "quiet", "--repeat", "2", "extra"],
        &["help", "extra"],
    ];

    for argv in cases {
        let os_args: Vec<OsString> = argv.iter().map(|&s| OsString::from(s)).collect();
        let result = parse_lab_args(os_args);
        assert!(result.is_err(), "must reject trailing tokens: {argv:?}");
        if let Err(err) = result {
            assert_eq!(
                err.error_id(),
                ERR_CLI_TRAILING_ARGUMENT,
                "expected trailing argument error for {argv:?}, got: {err:?}"
            );
            assert_eq!(err.exit_identity().code, 2);
        }
    }
}

#[test]
fn lab_failure_classes_distinguished() {
    // Unknown command
    let res = parse_lab_args([OsString::from("unknown_command")]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_UNKNOWN_COMMAND);
    }

    // Missing scenario
    let res = parse_lab_args([OsString::from("run")]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_MISSING_VALUE);
    }

    // Malformed scenario
    let res = parse_lab_args([OsString::from("run"), OsString::from("not_a_scenario")]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_MALFORMED_VALUE);
    }

    // Missing repeat value
    let res = parse_lab_args([
        OsString::from("replay"),
        OsString::from("quiet"),
        OsString::from("--repeat"),
    ]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_MISSING_VALUE);
    }

    // Duplicate repeat flag
    let res = parse_lab_args([
        OsString::from("replay"),
        OsString::from("quiet"),
        OsString::from("--repeat"),
        OsString::from("2"),
        OsString::from("--repeat"),
        OsString::from("3"),
    ]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_DUPLICATE_OPTION);
    }

    // Unknown option
    let res = parse_lab_args([
        OsString::from("replay"),
        OsString::from("quiet"),
        OsString::from("--invalid-flag"),
    ]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_UNKNOWN_OPTION);
    }
}

#[test]
fn public_commands_are_deterministic_integration() -> Result<(), Box<dyn std::error::Error>> {
    let bin_path = env!("CARGO_BIN_EXE_fss-lab");

    // matrix output is deterministic across two runs
    let first = Command::new(bin_path).arg("matrix").output()?;
    assert!(first.status.success());
    let second = Command::new(bin_path).arg("matrix").output()?;
    assert!(second.status.success());
    assert_eq!(
        first.stdout, second.stdout,
        "matrix output must be deterministic"
    );

    // self-test returns status: pass
    let st = Command::new(bin_path).arg("self-test").output()?;
    assert!(st.status.success());
    let st_out = String::from_utf8(st.stdout)?;
    assert!(
        st_out.contains("\"status\":\"pass\""),
        "self-test must report status pass"
    );

    // replay returns deterministic: true
    let rep = Command::new(bin_path)
        .args(["replay", "intrusion", "--repeat", "10"])
        .output()?;
    assert!(rep.status.success());
    let rep_out = String::from_utf8(rep.stdout)?;
    assert!(
        rep_out.contains("\"deterministic\":true"),
        "replay must report deterministic:true"
    );

    Ok(())
}

#[test]
fn real_process_lab_execution() -> Result<(), Box<dyn std::error::Error>> {
    let bin_path = env!("CARGO_BIN_EXE_fss-lab");

    // Valid list command
    let output = Command::new(bin_path).arg("list").output()?;
    assert!(output.status.success());
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("\"schema\":\"fss.lab.scenarios.v1\""));

    // Trailing argument on list
    let output = Command::new(bin_path).args(["list", "extra"]).output()?;
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("ERR-CLI-TRAILING-ARGUMENT-001"));
    assert!(stderr.contains("\"schema\":\"fss.cli_diagnostic.v1\""));

    // Malformed scenario
    let output = Command::new(bin_path).args(["run", "unknown"]).output()?;
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("ERR-CLI-MALFORMED-VALUE-001"));
    assert!(stderr.contains("\"schema\":\"fss.cli_diagnostic.v1\""));

    for line in stderr.lines() {
        if line.contains("\"schema\":\"fss.cli_diagnostic.v1\"") {
            assert_valid_json_payload(line);
        }
    }

    Ok(())
}

fn assert_valid_json_payload(json_str: &str) {
    if let Ok(mut child) = Command::new("python3")
        .args(["-c", "import json, sys; json.loads(sys.stdin.read())"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(json_str.as_bytes());
        }
        if let Ok(output) = child.wait_with_output() {
            assert!(
                output.status.success(),
                "rendered diagnostic is not valid JSON:\n{json_str}\nstderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
