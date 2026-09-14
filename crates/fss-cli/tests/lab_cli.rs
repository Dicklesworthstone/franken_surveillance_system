#![forbid(unsafe_code)]
//! Tests for total argument decoding of the `fss-lab` binary.

use std::ffi::OsString;
use std::path::PathBuf;
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
        (
            &["matrix", "--root", "/tmp/lab-m"],
            LabAction::Matrix {
                root: PathBuf::from("/tmp/lab-m"),
            },
        ),
        (
            &["self-test", "--root", "/tmp/lab-st"],
            LabAction::SelfTest {
                root: PathBuf::from("/tmp/lab-st"),
            },
        ),
        (
            &["run", "quiet", "--root", "/tmp/lab-q"],
            LabAction::Run {
                scenario: "quiet".to_owned(),
                root: PathBuf::from("/tmp/lab-q"),
            },
        ),
        (
            &["run", "intrusion", "--root", "/tmp/lab-i"],
            LabAction::Run {
                scenario: "intrusion".to_owned(),
                root: PathBuf::from("/tmp/lab-i"),
            },
        ),
        (
            &["replay", "raccoon", "--root", "/tmp/lab-r"],
            LabAction::Replay {
                scenario: "raccoon".to_owned(),
                repeat: 2,
                root: PathBuf::from("/tmp/lab-r"),
            },
        ),
        (
            &["replay", "sneaky", "--repeat", "10", "--root", "/tmp/lab-s"],
            LabAction::Replay {
                scenario: "sneaky".to_owned(),
                repeat: 10,
                root: PathBuf::from("/tmp/lab-s"),
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
        OsString::from("--root"),
        OsString::from("/tmp/lab-rep"),
        OsString::from("intrusion"),
    ];
    let res = parse_lab_args(args);
    assert_eq!(
        res.ok(),
        Some(LabAction::Replay {
            scenario: "intrusion".to_owned(),
            repeat: 5,
            root: PathBuf::from("/tmp/lab-rep"),
        })
    );
}

#[test]
fn trailing_arguments_on_all_lab_commands_are_rejected() {
    let cases: &[&[&str]] = &[
        &["list", "extra"],
        &["matrix", "--root", "/tmp/lab", "extra"],
        &["self-test", "--root", "/tmp/lab", "extra"],
        &["run", "quiet", "--root", "/tmp/lab", "extra"],
        &["replay", "quiet", "--root", "/tmp/lab", "extra"],
        &[
            "replay", "quiet", "--root", "/tmp/lab", "--repeat", "2", "extra",
        ],
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
    let res = parse_lab_args([
        OsString::from("run"),
        OsString::from("--root"),
        OsString::from("/tmp/lab"),
    ]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_MISSING_VALUE);
    }

    // Missing root
    let res = parse_lab_args([OsString::from("run"), OsString::from("quiet")]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_MISSING_VALUE);
    }

    // Malformed scenario
    let res = parse_lab_args([
        OsString::from("run"),
        OsString::from("not_a_scenario"),
        OsString::from("--root"),
        OsString::from("/tmp/lab"),
    ]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_MALFORMED_VALUE);
    }

    // Missing repeat value
    let res = parse_lab_args([
        OsString::from("replay"),
        OsString::from("quiet"),
        OsString::from("--root"),
        OsString::from("/tmp/lab"),
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
        OsString::from("--root"),
        OsString::from("/tmp/lab"),
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
        OsString::from("--root"),
        OsString::from("/tmp/lab"),
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
    let base_temp = std::env::temp_dir().join(format!(
        "fss-lab-integ-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&base_temp);
    std::fs::create_dir_all(&base_temp)?;

    let mat_1 = base_temp.join("mat-1");
    let mat_2 = base_temp.join("mat-2");
    let mat_1_str = mat_1.to_str().ok_or("invalid mat_1 path")?;
    let mat_2_str = mat_2.to_str().ok_or("invalid mat_2 path")?;

    // matrix output is deterministic across two runs
    let first = Command::new(bin_path)
        .args(["matrix", "--root", mat_1_str])
        .output()?;
    assert!(
        first.status.success(),
        "matrix 1 failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let second = Command::new(bin_path)
        .args(["matrix", "--root", mat_2_str])
        .output()?;
    assert!(
        second.status.success(),
        "matrix 2 failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        first.stdout, second.stdout,
        "matrix output must be deterministic across roots"
    );

    // self-test returns status: pass
    let st_root = base_temp.join("self-test");
    let st_root_str = st_root.to_str().ok_or("invalid st_root path")?;
    let st = Command::new(bin_path)
        .args(["self-test", "--root", st_root_str])
        .output()?;
    assert!(
        st.status.success(),
        "self-test failed: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let st_out = String::from_utf8(st.stdout)?;
    assert!(
        st_out.contains("\"status\":\"pass\""),
        "self-test must report status pass"
    );

    // replay returns deterministic: true
    let rep_root = base_temp.join("replay");
    let rep_root_str = rep_root.to_str().ok_or("invalid rep_root path")?;
    let rep = Command::new(bin_path)
        .args([
            "replay",
            "intrusion",
            "--repeat",
            "3",
            "--root",
            rep_root_str,
        ])
        .output()?;
    assert!(
        rep.status.success(),
        "replay failed: {}",
        String::from_utf8_lossy(&rep.stderr)
    );
    let rep_out = String::from_utf8(rep.stdout)?;
    assert!(
        rep_out.contains("\"deterministic\":true"),
        "replay must report deterministic:true"
    );

    // run quiet returns schema v2, absence_certified: true, non-empty digests
    let quiet_root = base_temp.join("quiet");
    let quiet_root_str = quiet_root.to_str().ok_or("invalid quiet_root path")?;
    let run_q = Command::new(bin_path)
        .args(["run", "quiet", "--root", quiet_root_str])
        .output()?;
    assert!(
        run_q.status.success(),
        "run quiet failed: {}",
        String::from_utf8_lossy(&run_q.stderr)
    );
    let q_out = String::from_utf8(run_q.stdout)?;
    assert!(q_out.contains("\"schema\":\"fss.lab.scenario.v2\""));
    assert!(q_out.contains("\"absence_certified\":true"));
    assert!(q_out.contains("\"ledger_anchor_root\":\""));
    assert!(q_out.contains("\"publication_root\":\""));
    assert!(q_out.contains("\"handoff_digest\":\""));

    let _ = std::fs::remove_dir_all(&base_temp);
    Ok(())
}

#[test]
fn test_lab_replay_repeat_option_shaped_vs_value() {
    for opt in ["--token=x", "-p"] {
        let res = parse_lab_args([
            OsString::from("replay"),
            OsString::from("quiet"),
            OsString::from("--repeat"),
            OsString::from(opt),
        ]);
        assert!(res.is_err());
        if let Err(err) = res {
            assert_eq!(
                err.error_id(),
                ERR_CLI_MISSING_VALUE,
                "expected MissingValue for --repeat followed by {opt}, got {err:?}"
            );
        }
    }

    for val in ["-5", "-"] {
        let res = parse_lab_args([
            OsString::from("replay"),
            OsString::from("quiet"),
            OsString::from("--repeat"),
            OsString::from(val),
        ]);
        assert!(res.is_err());
        if let Err(err) = res {
            assert_eq!(
                err.error_id(),
                ERR_CLI_MALFORMED_VALUE,
                "expected MalformedValue for --repeat followed by {val}, got {err:?}"
            );
        }
    }
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
