#![forbid(unsafe_code)]
//! Exhaustive table-driven, property, and real-process tests for total CLI argument decoding.

use std::ffi::OsString;
use std::process::Command;

use fss_cli::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_INVALID_UNICODE, ERR_CLI_MALFORMED_VALUE,
    ERR_CLI_MISSING_VALUE, ERR_CLI_TRAILING_ARGUMENT, ERR_CLI_UNKNOWN_COMMAND,
    ERR_CLI_UNKNOWN_OPTION, FssCommand, MAX_ARG_TOKEN_BYTES, parse_fss_args, render_diagnostic,
};

#[test]
fn registered_commands_decode_successfully() {
    let cases: &[(&[&str], FssCommand)] = &[
        (&[], FssCommand::Help),
        (&["help"], FssCommand::Help),
        (&["--help"], FssCommand::Help),
        (&["-h"], FssCommand::Help),
        (&["version"], FssCommand::Version),
        (&["--version"], FssCommand::Version),
        (&["-V"], FssCommand::Version),
        (&["capabilities", "--json"], FssCommand::Capabilities),
        (&["doctor", "--json"], FssCommand::Doctor),
        (&["status", "--json"], FssCommand::Status),
    ];

    for (argv, expected) in cases {
        let os_args: Vec<OsString> = argv.iter().map(|&s| OsString::from(s)).collect();
        let result = parse_fss_args(os_args);
        assert!(result.is_ok(), "failed to parse valid argv: {argv:?}");
        if let Ok(cmd) = result {
            assert_eq!(cmd, *expected, "mismatched command for argv: {argv:?}");
        }
    }
}

#[test]
fn planted_negatives_silently_accepted_before_are_now_rejected() {
    let permissive_historicals: &[&[&str]] = &[
        &["capabilities", "--json", "extra"],
        &["doctor", "--json", "extra"],
        &["status", "--json", "extra"],
        &["help", "extra"],
        &["version", "extra"],
    ];

    for argv in permissive_historicals {
        let os_args: Vec<OsString> = argv.iter().map(|&s| OsString::from(s)).collect();
        let result = parse_fss_args(os_args);
        assert!(
            result.is_err(),
            "historically permissive argv must now be rejected: {argv:?}"
        );
        if let Err(err) = result {
            assert_eq!(
                err.error_id(),
                ERR_CLI_TRAILING_ARGUMENT,
                "expected trailing argument error for {argv:?}, got: {err:?}"
            );
            assert_eq!(err.exit_identity().code, 2);
            assert_eq!(
                err.exit_identity().identifier,
                "EXIT-CLI-TRAILING-ARGUMENT-002"
            );
            assert!(!err.effect_started());
            assert!(!err.safe_retry());
        }
    }
}

#[test]
fn all_failure_classes_distinguished_with_stable_identities() {
    // 1. Unknown command
    let res = parse_fss_args([OsString::from("unrecognized_subcommand")]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_UNKNOWN_COMMAND);
        assert_eq!(err.exit_identity().code, 2);
        assert_eq!(
            err.exit_identity().identifier,
            "EXIT-CLI-UNKNOWN-COMMAND-002"
        );
    }

    // 2. Unknown option
    let res = parse_fss_args([
        OsString::from("capabilities"),
        OsString::from("--unrecognized-flag"),
    ]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_UNKNOWN_OPTION);
        assert_eq!(err.exit_identity().code, 2);
        assert_eq!(
            err.exit_identity().identifier,
            "EXIT-CLI-UNKNOWN-OPTION-002"
        );
    }

    // 3. Missing value
    let res = parse_fss_args([OsString::from("capabilities")]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_MISSING_VALUE);
        assert_eq!(err.exit_identity().code, 2);
        assert_eq!(err.exit_identity().identifier, "EXIT-CLI-MISSING-VALUE-002");
    }

    // 4. Duplicate option
    let res = parse_fss_args([
        OsString::from("capabilities"),
        OsString::from("--json"),
        OsString::from("--json"),
    ]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_DUPLICATE_OPTION);
        assert_eq!(err.exit_identity().code, 2);
        assert_eq!(
            err.exit_identity().identifier,
            "EXIT-CLI-DUPLICATE-OPTION-002"
        );
    }

    // 5. Malformed value (oversized token)
    let huge = "a".repeat(MAX_ARG_TOKEN_BYTES + 1);
    let res = parse_fss_args([OsString::from(huge)]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_MALFORMED_VALUE);
        assert_eq!(err.exit_identity().code, 2);
        assert_eq!(
            err.exit_identity().identifier,
            "EXIT-CLI-MALFORMED-VALUE-002"
        );
    }

    // 6. Trailing argument
    let res = parse_fss_args([
        OsString::from("status"),
        OsString::from("--json"),
        OsString::from("trailing_token"),
    ]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_TRAILING_ARGUMENT);
        assert_eq!(err.exit_identity().code, 2);
        assert_eq!(
            err.exit_identity().identifier,
            "EXIT-CLI-TRAILING-ARGUMENT-002"
        );
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_unix_arguments_produce_typed_invalid_unicode_error() {
    use std::os::unix::ffi::OsStringExt;
    let non_utf8 = OsString::from_vec(vec![0x63, 0x61, 0x70, 0x80, 0x81]);
    let res = parse_fss_args([non_utf8]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_INVALID_UNICODE);
        assert_eq!(err.exit_identity().code, 2);
        assert_eq!(
            err.exit_identity().identifier,
            "EXIT-CLI-INVALID-UNICODE-002"
        );
        assert_eq!(err.argument_index(), Some(0));
    }
}

#[test]
fn global_versus_subcommand_option_placement_is_strictly_enforced() {
    // Registered format: `fss capabilities --json`
    // Unsupported global format: `fss --json capabilities`
    let res = parse_fss_args([OsString::from("--json"), OsString::from("capabilities")]);
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err.error_id(), ERR_CLI_UNKNOWN_OPTION);
    }
}

#[test]
fn diagnostic_structure_and_redaction_are_verified() {
    let err = fss_cli::CliError::UnknownOption {
        option: "--password=supersecretpassword123".to_owned(),
        command: Some("status".to_owned()),
        index: 1,
    };
    let (human, json) = render_diagnostic(&err, "fss", None);

    // Assert sensitive payload is NOT present
    assert!(!human.contains("supersecretpassword123"));
    assert!(!json.contains("supersecretpassword123"));
    assert!(human.contains("[REDACTED]"));
    assert!(json.contains("[REDACTED]"));

    // Assert structured log contains all required fields
    assert!(json.contains("\"schema\":\"fss.cli_diagnostic.v1\""));
    assert!(json.contains("\"phase\":\"argument_parsing\""));
    assert!(json.contains("\"binary\":\"fss\""));
    assert!(json.contains("\"command\":\"status\""));
    assert!(json.contains("\"argument_index\":1"));
    assert!(json.contains("\"error_id\":\"ERR-CLI-UNKNOWN-OPTION-001\""));
    assert!(json.contains("\"exit_id\":\"EXIT-CLI-UNKNOWN-OPTION-002\""));
    assert!(json.contains("\"exit_code\":2"));
    assert!(json.contains("\"contract_basis\":\"fss/1\""));
    assert!(json.contains("\"effect_started\":false"));
    assert!(json.contains("\"retryable\":false"));
    assert!(json.contains("\"recovery_class\":\"never_unchanged\""));
    assert!(json.contains("\"correlation_id\":\"corr-fss-ERR-CLI-UNKNOWN-OPTION-001-1\""));
    assert!(json.contains("\"proof_handle\":\"fss://proof/cli/parse-failure\""));
}

#[test]
fn parser_totality_and_determinism_property() {
    let sample_tokens = [
        "",
        "help",
        "-h",
        "--help",
        "version",
        "-V",
        "--version",
        "capabilities",
        "doctor",
        "status",
        "--json",
        "extra",
        "--unknown",
        "positional",
    ];

    // Test 1-token and 2-token permutations
    for &t1 in &sample_tokens {
        let args1 = [OsString::from(t1)];
        let r1a = parse_fss_args(args1.clone());
        let r1b = parse_fss_args(args1);
        assert_eq!(r1a, r1b, "parse must be deterministic for [{t1}]");

        for &t2 in &sample_tokens {
            let args2 = [OsString::from(t1), OsString::from(t2)];
            let r2a = parse_fss_args(args2.clone());
            let r2b = parse_fss_args(args2);
            assert_eq!(r2a, r2b, "parse must be deterministic for [{t1}, {t2}]");
        }
    }
}

#[test]
fn adding_trailing_tokens_never_preserves_success() {
    let valid_invocations: &[&[&str]] = &[
        &[],
        &["help"],
        &["--help"],
        &["version"],
        &["--version"],
        &["capabilities", "--json"],
        &["doctor", "--json"],
        &["status", "--json"],
    ];

    let extra_tokens = ["extra", "--extra", "123", "trailing"];

    for valid in valid_invocations {
        for extra in extra_tokens {
            let mut extended: Vec<OsString> = valid.iter().map(|&s| OsString::from(s)).collect();
            extended.push(OsString::from(extra));
            let result = parse_fss_args(extended);
            assert!(
                result.is_err(),
                "adding extra token `{extra}` to valid argv {valid:?} must result in an error"
            );
        }
    }
}

#[test]
fn real_process_execution_tests() -> Result<(), Box<dyn std::error::Error>> {
    let bin_path = env!("CARGO_BIN_EXE_fss");

    // Success cases: exit code 0, machine-clean stdout, empty stderr
    let success_cases = [
        vec!["capabilities", "--json"],
        vec!["doctor", "--json"],
        vec!["status", "--json"],
    ];

    for args in success_cases {
        let output = Command::new(bin_path).args(&args).output()?;
        assert!(output.status.success(), "args {args:?} should succeed");
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty(), "stderr must be empty on success");
        let stdout = String::from_utf8(output.stdout)?;
        assert!(
            stdout.contains("\"schema\":"),
            "stdout must contain JSON schema"
        );
    }

    // Failure cases: exit code 2, empty stdout, structured diagnostic on stderr
    let failure_cases = [
        vec!["capabilities", "--json", "extra"],
        vec!["doctor", "--json", "extra"],
        vec!["status", "--json", "extra"],
        vec!["capabilities"],
        vec!["capabilities", "--xml"],
        vec!["unknown_cmd"],
        vec!["--json", "capabilities"],
    ];

    for args in failure_cases {
        let output = Command::new(bin_path).args(&args).output()?;
        assert!(!output.status.success(), "args {args:?} must fail");
        assert_eq!(output.status.code(), Some(2));
        assert!(
            output.stdout.is_empty(),
            "stdout must be machine-clean (empty) on error for {args:?}"
        );
        let stderr = String::from_utf8(output.stderr)?;
        assert!(
            stderr.contains("fss: error[ERR-CLI-"),
            "stderr must contain stable error ID"
        );
        assert!(
            stderr.contains("\"schema\":\"fss.cli_diagnostic.v1\""),
            "stderr must contain structured diagnostic JSON"
        );
        assert!(
            stderr.contains("\"effect_started\":false"),
            "stderr must certify effect_started false"
        );
    }
    Ok(())
}
