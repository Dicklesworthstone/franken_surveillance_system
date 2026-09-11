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

    // Assert Display implementation does not leak secrets
    let err_display = err.to_string();
    assert!(!err_display.contains("supersecretpassword123"));
    assert!(err_display.contains("[REDACTED]"));

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
fn diagnostic_json_is_valid_for_hostile_characters() {
    let tricky_cases = [
        fss_cli::CliError::UnknownOption {
            option: "--opt=\"quoted\"".to_owned(),
            command: Some("status".to_owned()),
            index: 1,
        },
        fss_cli::CliError::TrailingArgument {
            argument: "path\\with\\backslashes".to_owned(),
            index: 2,
            command: Some("doctor".to_owned()),
        },
        fss_cli::CliError::UnexpectedPositional {
            argument: "line1\nline2\ttab".to_owned(),
            index: 1,
            command: None,
        },
        fss_cli::CliError::InvalidUnicode {
            index: 0,
            byte_length: 5,
            redacted_repr: "\\x80\\x81\\x82".to_owned(),
        },
        fss_cli::CliError::UnknownCommand {
            command: "--token=secret12345".to_owned(),
            context: None,
            index: 0,
        },
    ];

    for err in tricky_cases {
        let (human, json) = render_diagnostic(&err, "fss", None);
        assert!(!human.is_empty());
        assert!(!json.is_empty());
        assert_valid_json_payload(&json);
    }
}

#[test]
fn test_safe_os_repr_leaks_sensitive_prefix_on_invalid_utf8() {
    let sensitive_bytes = b"--password=supersecretpassword123\x80";
    let repr = fss_cli::safe_os_repr(sensitive_bytes, 64);
    assert!(
        !repr.contains("supersecretpassword123"),
        "safe_os_repr leaked sensitive password: {repr}"
    );
}

#[test]
fn test_redaction_bypassed_for_short_option_flag() {
    let input = "-p=supersecretpassword123";
    let redacted = fss_cli::redact_argument(input);
    assert!(
        !redacted.contains("supersecretpassword123"),
        "redact_argument leaked short option password: {redacted}"
    );
    assert_eq!(redacted, "-p=[REDACTED]");
}

#[test]
fn test_malformed_value_leaks_token_in_diagnostic() {
    let err = fss_cli::CliError::MalformedValue {
        option: "--repeat".to_owned(),
        value: "my_secret_token_12345".to_owned(),
        reason: "--repeat requires a positive integer".to_owned(),
        command: Some("replay".to_owned()),
        index: 3,
    };
    let (human, json) = fss_cli::render_diagnostic(&err, "fss-lab", Some("replay"));
    assert!(
        !human.contains("my_secret_token_12345"),
        "human output leaked value"
    );
    assert!(
        !json.contains("my_secret_token_12345"),
        "json output leaked value"
    );
}

#[test]
fn test_escape_json_str_unicode_line_separators_and_del() {
    let input = "line1\u{2028}line2\u{2029}\x7fcontrol";
    let escaped = fss_cli::escape_json_str(input);
    assert!(
        !escaped.contains('\u{2028}'),
        "unescaped U+2028 Line Separator in JSON string: {escaped}"
    );
    assert!(
        !escaped.contains('\u{2029}'),
        "unescaped U+2029 Paragraph Separator in JSON string: {escaped}"
    );
    assert!(
        !escaped.contains('\x7f'),
        "unescaped 0x7F DEL control character in JSON string: {escaped}"
    );
    assert!(escaped.contains("\\u2028"));
    assert!(escaped.contains("\\u2029"));
    assert!(escaped.contains("\\u007f"));
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
        vec!["status", "--json", "extra\"with\"quotes"],
        vec!["doctor", "--password=supersecret"],
        vec!["capabilities", "--dir=C:\\Windows\\System32"],
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
        assert!(
            !stderr.contains("supersecret"),
            "stderr must not leak sensitive passwords"
        );
        for line in stderr.lines() {
            if line.contains("\"schema\":\"fss.cli_diagnostic.v1\"") {
                assert_valid_json_payload(line);
            }
        }
    }
    Ok(())
}

fn assert_valid_json_payload(json_str: &str) {
    let validation_script = r#"
import json, os, subprocess, sys, re

candidates = [
    'schemas/cli_diagnostic.v1.json',
    '../../schemas/cli_diagnostic.v1.json',
    '../schemas/cli_diagnostic.v1.json',
    os.path.join(os.environ.get('CARGO_MANIFEST_DIR', '.'), '../../schemas/cli_diagnostic.v1.json'),
]
schema_file = next((c for c in candidates if os.path.isfile(c)), None)
assert schema_file, f'could not find schemas/cli_diagnostic.v1.json in {candidates}'

# Locate scripts/schema_validate.py
validator_candidates = [
    'scripts/schema_validate.py',
    '../../scripts/schema_validate.py',
    '../scripts/schema_validate.py',
    os.path.join(os.environ.get('CARGO_MANIFEST_DIR', '.'), '../../scripts/schema_validate.py'),
]
validator_script = next((c for c in validator_candidates if os.path.isfile(c)), None)
assert validator_script, f'could not find scripts/schema_validate.py in {validator_candidates}'

# Validate schema using repository stdlib schema_validate.py
schema_res = subprocess.run(
    [sys.executable, validator_script, '--schema', schema_file],
    capture_output=True,
    text=True,
)
assert schema_res.returncode == 0, f'schema_validate.py failed: {schema_res.stderr}'

with open(schema_file) as f:
    schema = json.load(f)

raw = sys.stdin.read()
instance = json.loads(raw)

# Strictly validate instance against schema stdlib-only
assert isinstance(instance, dict), "instance must be an object"
required = schema.get("required", [])
for req in required:
    assert req in instance, f"missing required field: {req}"

if schema.get("additionalProperties") is False:
    for k in instance:
        assert k in schema.get("properties", {}), f"unexpected field: {k}"

for k, v in instance.items():
    prop = schema.get("properties", {}).get(k, {})
    if "const" in prop:
        assert v == prop["const"], f"expected const {prop['const']}, got {v}"
    if "pattern" in prop and isinstance(v, str):
        assert re.search(prop["pattern"], v), f"field {k}={v!r} does not match pattern {prop['pattern']}"
    if "maxLength" in prop and isinstance(v, str):
        assert len(v) <= prop["maxLength"], f"field {k}={v!r} exceeds maxLength {prop['maxLength']}"
    if "type" in prop:
        expected_types = prop["type"] if isinstance(prop["type"], list) else [prop["type"]]
        match = False
        for t in expected_types:
            if t == "string" and isinstance(v, str): match = True
            elif t == "integer" and isinstance(v, int) and not isinstance(v, bool): match = True
            elif t == "boolean" and isinstance(v, bool): match = True
            elif t == "null" and v is None: match = True
        assert match, f"field {k}={v!r} does not match type {expected_types}"
"#;

    let child = Command::new("python3")
        .args(["-c", validation_script])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();
    assert!(child.is_ok(), "failed to spawn python validator");
    let Ok(mut child) = child else {
        return;
    };

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let write_res = stdin.write_all(json_str.as_bytes());
        assert!(write_res.is_ok(), "failed to write to python stdin");
    }

    let output = child.wait_with_output();
    assert!(output.is_ok(), "failed to wait for python validator");
    let Ok(output) = output else {
        return;
    };
    assert!(
        output.status.success(),
        "rendered diagnostic failed schema validation against schemas/cli_diagnostic.v1.json:\n{json_str}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_safe_os_repr_leaks_sensitive_in_second_half_of_non_utf8() {
    let sensitive_bytes = b"\x80--password=supersecretpassword123";
    let repr = fss_cli::safe_os_repr(sensitive_bytes, 64);
    assert!(
        !repr.contains("supersecretpassword123"),
        "safe_os_repr leaked sensitive password preceded by non-UTF8 byte: {repr}"
    );
}

#[test]
fn test_unsalted_digest_allows_preimage_brute_force_of_short_secret() {
    let secret = "849201";
    let redacted = fss_cli::redact_value_or_digest(secret);
    assert!(
        !redacted.contains("sha256:"),
        "Unsalted SHA-256 digest allowed preimage search of short secret: {redacted}"
    );
    assert_eq!(redacted, "[redacted]");
}

#[test]
fn test_numeric_secret_leaked_in_plaintext_by_is_safe_to_echo() {
    let pin = "849201";
    assert!(
        !fss_cli::is_safe_to_echo(pin),
        "is_safe_to_echo must not treat arbitrary numeric secrets/PINs as safe identifiers"
    );
    let redacted = fss_cli::redact_value_or_digest(pin);
    assert!(
        !redacted.contains(pin),
        "redact_value_or_digest echoed numeric secret in plaintext: {redacted}"
    );
}

#[test]
fn test_unknown_option_with_unregistered_sensitive_flag_leaks_secret() {
    let err = fss_cli::CliError::UnknownOption {
        option: "--custom-api-token=supersecret123".to_owned(),
        command: Some("status".to_owned()),
        index: 1,
    };
    let (human, json) = fss_cli::render_diagnostic(&err, "fss", None);
    assert!(
        !human.contains("supersecret123"),
        "UnknownOption leaked secret value in human diagnostic: {human}"
    );
    assert!(
        !json.contains("supersecret123"),
        "UnknownOption leaked secret value in JSON diagnostic: {json}"
    );
}

#[test]
fn test_sensitive_standalone_flags_redact_next_token() -> Result<(), Box<dyn std::error::Error>> {
    let args = [
        std::ffi::OsString::from("status"),
        std::ffi::OsString::from("--password"),
        std::ffi::OsString::from("supersecret123"),
    ];
    let tokens = fss_cli::tokenize_os_args(args)?;
    assert_eq!(tokens.len(), 3);
    assert_eq!(tokens[1].raw, "--password");
    assert_eq!(tokens[2].raw, "[redacted]");
    Ok(())
}

#[test]
fn test_diagnostic_json_validates_against_schema_file() {
    let err = fss_cli::CliError::UnknownOption {
        option: "--unknown".to_owned(),
        command: Some("status".to_owned()),
        index: 1,
    };
    let (_, json_str) = fss_cli::render_diagnostic(&err, "fss", None);
    assert_valid_json_payload(&json_str);
}

#[test]
fn test_diagnostic_command_field_leaks_secret_in_context_command() {
    let err = fss_cli::CliError::UnknownOption {
        option: "--verbose".to_owned(),
        command: Some("my_secret_token_12345".to_owned()),
        index: 1,
    };
    let (human, json) = fss_cli::render_diagnostic(&err, "fss", None);
    assert!(
        !human.contains("my_secret_token_12345"),
        "human diagnostic leaked secret command token: {human}"
    );
    assert!(
        !json.contains("my_secret_token_12345"),
        "JSON diagnostic leaked secret command token in 'command' field: {json}"
    );
}

#[test]
fn test_redaction_does_not_leak_exact_secret_byte_length() {
    let secret_pin = "849201";
    let redacted = fss_cli::redact_value_or_digest(secret_pin);
    assert_ne!(
        redacted, "[redacted:6bytes]",
        "redaction leaks exact byte length of secret token"
    );
    assert_eq!(redacted, "[redacted]");
}

#[test]
fn test_option_value_that_is_option_flag_reports_missing_value() {
    let args = [
        std::ffi::OsString::from("replay"),
        std::ffi::OsString::from("quiet"),
        std::ffi::OsString::from("--repeat"),
        std::ffi::OsString::from("--token=secret123"),
    ];
    let res = fss_cli::parse_lab_args(args);
    assert!(
        res.is_err(),
        "expected error for flag passed as option value"
    );
    let Err(err) = res else {
        return;
    };
    assert_eq!(
        err.error_id(),
        fss_cli::ERR_CLI_MISSING_VALUE,
        "expected MissingValue for --repeat when followed by another option flag, got: {err:?}"
    );
}

#[test]
fn test_bearer_and_authorization_standalone_flags_redact_next_token()
-> Result<(), Box<dyn std::error::Error>> {
    let args = [
        std::ffi::OsString::from("status"),
        std::ffi::OsString::from("--bearer"),
        std::ffi::OsString::from("supersecret_jwt_token"),
    ];
    let tokens = fss_cli::tokenize_os_args(args)?;
    assert_eq!(
        tokens[2].raw, "[redacted]",
        "--bearer standalone flag failed to redact following secret token"
    );
    let auth_args = [
        std::ffi::OsString::from("status"),
        std::ffi::OsString::from("--authorization"),
        std::ffi::OsString::from("secret_auth_header"),
    ];
    let auth_tokens = fss_cli::tokenize_os_args(auth_args)?;
    assert_eq!(
        auth_tokens[2].raw, "[redacted]",
        "--authorization standalone flag failed to redact following secret token"
    );
    Ok(())
}

#[test]
fn test_hydration_scenarios_are_safe_to_echo() {
    for scenario in &fss_cli::VALID_HYDRATION_SCENARIOS {
        assert!(
            fss_cli::is_safe_to_echo(scenario),
            "Registered hydration scenario `{scenario}` is missing from SAFE_IDENTIFIERS"
        );
    }
}

#[test]
fn test_malformed_value_under_known_subcommand_preserves_command_identity() {
    let args = [
        std::ffi::OsString::from("replay"),
        std::ffi::OsString::from("quiet"),
        std::ffi::OsString::from("--repeat"),
        std::ffi::OsString::from("not_a_number"),
    ];
    let res = fss_cli::parse_lab_args(args);
    assert!(res.is_err(), "expected error for not_a_number repeat value");
    let Err(err) = res else {
        return;
    };
    assert_eq!(
        err.command_name(),
        Some("replay"),
        "MalformedValue under `replay` must preserve the command name"
    );
}
