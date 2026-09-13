#![forbid(unsafe_code)]
//! Deterministic contract tests for `fss negative-evidence` CLI (FSS-012).
//!
//! Enforces:
//! 1. Help, version, init, list, verify, and append command execution.
//! 2. Bounded agent response envelopes shaped as `fss.agent_response_envelope.v1`, with
//!    underivable contract values reported as null/degraded rather than invented.
//! 3. Deterministic refusal of absence without a (complete) coverage witness.
//! 4. Refusal of corrupt checksum, magic, duplicate entry ID, and missing ledger files.
//! 5. Exact exit identities: value errors are usage errors (exit 2), refusals exit 1.

use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use fss_cli::{
    CliError, ERR_CLI_MALFORMED_VALUE, ERR_CLI_MISSING_VALUE, ERR_CLI_UNKNOWN_OPTION, FssCommand,
    NegativeEvidenceAction, execute_fss_with_exit, execute_negative_evidence, parse_fss_args,
};
use fss_core::ContentDigest;
use fss_core::negative_evidence::{
    INITIAL_NEGATIVE_EVIDENCE_LEDGER_DIGEST, NEGATIVE_EVIDENCE_LEDGER_MAGIC,
    initial_negative_evidence_ledger,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

fn temp_file_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("{prefix}_{nanos}_{counter}.bin"))
}

struct TempFileGuard(PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn argv(parts: &[&str]) -> Vec<OsString> {
    parts.iter().map(OsString::from).collect()
}

/// Every required non-witness `append` option for `id`.
fn required_append_options(id: &str) -> Vec<String> {
    [
        "--id",
        id,
        "--date-commit",
        "2026-09-12 test-fixture",
        "--decision",
        "reject",
        "--disposition",
        "refuted",
        "--hypothesis",
        "Proprietary cloud notification endpoint is reliable",
        "--reasoning",
        "Endpoint is uncertified and subject to vendor rate limiting",
        "--result",
        "Observed 40% packet drops during peak load",
        "--revival",
        "Official SLA offering 99.99% availability guarantee",
        "--failure-domain",
        "vendor-cloud",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

/// A complete certifying coverage witness bound to `id`.
fn witness_options(id: &str) -> Vec<String> {
    vec![
        "--coverage-domain".to_owned(),
        "domain:negative-evidence:cli-test".to_owned(),
        "--coverage-generation".to_owned(),
        "1".to_owned(),
        "--negative-predicate".to_owned(),
        format!("architectural-violation-absence:{id}"),
        "--continuity".to_owned(),
        "continuous".to_owned(),
        "--completeness".to_owned(),
        "complete".to_owned(),
        "--stop-reason".to_owned(),
        "complete".to_owned(),
    ]
}

fn append_argv(path: &str, extra: &[Vec<String>]) -> Vec<OsString> {
    let mut args = argv(&["negative-evidence", "append", "--path", path]);
    for group in extra {
        args.extend(group.iter().map(OsString::from));
    }
    args
}

fn seeded_ledger_file(prefix: &str) -> Result<(TempFileGuard, String), Box<dyn Error>> {
    let path = temp_file_path(prefix);
    fs::write(
        &path,
        initial_negative_evidence_ledger()?.encode_canonical()?,
    )?;
    let path_str = path
        .to_str()
        .ok_or_else(|| "non-unicode path".to_string())?
        .to_owned();
    Ok((TempFileGuard(path), path_str))
}

fn parse_error(args: Vec<OsString>) -> Result<CliError, Box<dyn Error>> {
    match parse_fss_args(args) {
        Err(err) => Ok(err),
        Ok(cmd) => Err(format!("expected a usage error, parsed {cmd:?}").into()),
    }
}

#[test]
fn test_cli_help_action() -> Result<(), Box<dyn Error>> {
    let cmd = parse_fss_args([OsString::from("negative-evidence"), OsString::from("help")])
        .map_err(|e| format!("parse failed: {e:?}"))?;

    let (output, exit_id) = execute_fss_with_exit(cmd);
    assert_eq!(exit_id.code, 0);
    assert!(output.contains("negative-evidence"));
    assert!(output.contains("list"));
    assert!(output.contains("verify"));
    assert!(output.contains("append"));
    // The help advertises exactly the spellings the parser accepts.
    assert!(output.contains("reject, oracle, narrow, or revisit"));
    assert!(!output.contains("Reject"));
    assert!(!output.contains("--no-witness"));
    assert!(!output.contains("--entry-json"));
    Ok(())
}

#[test]
fn test_cli_list_default_and_json() -> Result<(), Box<dyn Error>> {
    // Plaintext table list
    let cmd = parse_fss_args([OsString::from("negative-evidence"), OsString::from("list")])
        .map_err(|e| format!("parse failed: {e:?}"))?;
    let (output, exit_id) = execute_fss_with_exit(cmd);
    assert_eq!(exit_id.code, 0);
    assert!(output.contains("NEG-001"));
    assert!(output.contains("NEG-002"));
    assert!(output.contains("NEG-003"));
    assert!(output.contains("not-locally-certified"));

    // JSON envelope list
    let cmd_json = parse_fss_args([
        OsString::from("negative-evidence"),
        OsString::from("list"),
        OsString::from("--json"),
    ])
    .map_err(|e| format!("parse failed: {e:?}"))?;
    let (json_output, exit_id_json) = execute_fss_with_exit(cmd_json);
    assert_eq!(exit_id_json.code, 0);
    assert!(json_output.contains("\"schema\":\"fss.agent_response_envelope.v1\""));
    assert!(json_output.contains("\"outcome\":\"ok\""));
    assert!(json_output.contains("\"entryCount\":3"));
    assert!(json_output.contains(INITIAL_NEGATIVE_EVIDENCE_LEDGER_DIGEST));
    Ok(())
}

#[test]
fn test_cli_json_envelope_does_not_fabricate_contract_values() -> Result<(), Box<dyn Error>> {
    let cmd = parse_fss_args(argv(&["negative-evidence", "verify", "--json"]))
        .map_err(|e| format!("parse failed: {e:?}"))?;
    let (output, exit_id) = execute_fss_with_exit(cmd);
    assert_eq!(exit_id.code, 0);
    assert!(output.contains("\"operationId\":null"));
    assert!(!output.contains("AOP-"));
    assert!(output.contains("\"operationRegistryDigest\":null"));
    assert!(output.contains("\"schemaCatalogDigest\":null"));
    // sha256 of empty input and the former local schema-catalog constant must not reappear.
    assert!(!output.contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    assert!(!output.contains("631ac85e5dada50bd38afbc915d651dae69756fca252c65a16f9d994854c775b"));
    assert!(output.contains("\"inputAnchor\":null"));
    assert!(
        output.contains("\"budgets\":{\"requested\":null,\"consumed\":null,\"remaining\":null}")
    );
    assert!(output.contains("operation_unregistered"));
    assert!(output.contains("budget_unmetered"));
    Ok(())
}

#[test]
fn test_cli_verify_default_and_json() -> Result<(), Box<dyn Error>> {
    // Plaintext verify
    let cmd = parse_fss_args([
        OsString::from("negative-evidence"),
        OsString::from("verify"),
    ])
    .map_err(|e| format!("parse failed: {e:?}"))?;
    let (output, exit_id) = execute_fss_with_exit(cmd);
    assert_eq!(exit_id.code, 0);
    assert!(output.contains("Ledger verified"));
    assert!(output.contains("continuous coverage guarantees intact"));
    assert!(output.contains("3 entries are not locally certified"));
    assert!(output.contains(INITIAL_NEGATIVE_EVIDENCE_LEDGER_DIGEST));

    // JSON verify
    let cmd_json = parse_fss_args([
        OsString::from("negative-evidence"),
        OsString::from("verify"),
        OsString::from("--json"),
    ])
    .map_err(|e| format!("parse failed: {e:?}"))?;
    let (json_output, exit_id_json) = execute_fss_with_exit(cmd_json);
    assert_eq!(exit_id_json.code, 0);
    assert!(json_output.contains("\"schema\":\"fss.agent_response_envelope.v1\""));
    assert!(json_output.contains("\"verified\":true"));
    assert!(json_output.contains("\"formatVersion\":1"));
    assert!(json_output.contains("\"notLocallyCertified\":3"));
    Ok(())
}

#[test]
fn test_cli_verify_corrupted_file_refusal() -> Result<(), Box<dyn Error>> {
    let path = temp_file_path("corrupt_ledger");
    let _guard = TempFileGuard(path.clone());

    // Write corrupted bytes
    let mut corrupt_bytes = vec![0xAA; 128];
    corrupt_bytes[0..8].copy_from_slice(&NEGATIVE_EVIDENCE_LEDGER_MAGIC);
    fs::write(&path, &corrupt_bytes)?;

    let path_str = path
        .to_str()
        .ok_or_else(|| "non-unicode path".to_string())?;

    let cmd = parse_fss_args([
        OsString::from("negative-evidence"),
        OsString::from("verify"),
        OsString::from("--path"),
        OsString::from(path_str),
    ])
    .map_err(|e| format!("parse failed: {e:?}"))?;

    let (output, exit_id) = execute_fss_with_exit(cmd);
    assert_eq!(exit_id.code, 1);
    assert!(output.contains("Verification failed"));
    assert!(output.contains("ERR-NEG-CHECKSUM-MISMATCH-001"));

    // Verify JSON mode reports error envelope
    let cmd_json = parse_fss_args([
        OsString::from("negative-evidence"),
        OsString::from("verify"),
        OsString::from("--path"),
        OsString::from(path_str),
        OsString::from("--json"),
    ])
    .map_err(|e| format!("parse failed: {e:?}"))?;

    let (json_output, exit_id_json) = execute_fss_with_exit(cmd_json);
    assert_eq!(exit_id_json.code, 1);
    assert!(json_output.contains("\"outcome\":\"error\""));
    assert!(json_output.contains("ERR-NEG-CHECKSUM-MISMATCH-001"));
    assert!(json_output.contains("\"verified\":false"));
    Ok(())
}

#[test]
fn test_cli_append_with_witness_and_verify() -> Result<(), Box<dyn Error>> {
    let path = temp_file_path("append_ledger");
    let _guard = TempFileGuard(path.clone());

    // Initialize with normative seed ledger
    let initial_ledger = initial_negative_evidence_ledger()?;
    let canonical_bytes = initial_ledger.encode_canonical()?;
    fs::write(&path, &canonical_bytes)?;

    let path_str = path
        .to_str()
        .ok_or_else(|| "non-unicode path".to_string())?;

    // Append a new valid entry NEG-004 carrying a complete certifying witness
    let cmd = parse_fss_args([
        OsString::from("negative-evidence"),
        OsString::from("append"),
        OsString::from("--path"),
        OsString::from(path_str),
        OsString::from("--id"),
        OsString::from("NEG-004"),
        OsString::from("--date-commit"),
        OsString::from("2026-09-12 test-fixture"),
        OsString::from("--decision"),
        OsString::from("reject"),
        OsString::from("--disposition"),
        OsString::from("refuted"),
        OsString::from("--hypothesis"),
        OsString::from("Proprietary cloud notification endpoint is reliable"),
        OsString::from("--reasoning"),
        OsString::from("Endpoint is uncertified and subject to vendor rate limiting"),
        OsString::from("--result"),
        OsString::from("Observed 40% packet drops during peak load"),
        OsString::from("--revival"),
        OsString::from("Official SLA offering 99.99% availability guarantee"),
        OsString::from("--failure-domain"),
        OsString::from("vendor-cloud"),
        OsString::from("--coverage-domain"),
        OsString::from("domain:negative-evidence:cli-test"),
        OsString::from("--coverage-generation"),
        OsString::from("1"),
        OsString::from("--negative-predicate"),
        OsString::from("architectural-violation-absence:NEG-004"),
        OsString::from("--continuity"),
        OsString::from("continuous"),
        OsString::from("--completeness"),
        OsString::from("complete"),
        OsString::from("--stop-reason"),
        OsString::from("complete"),
        OsString::from("--json"),
    ])
    .map_err(|e| format!("parse failed: {e:?}"))?;

    let (output, exit_id) = execute_fss_with_exit(cmd);
    assert_eq!(exit_id.code, 0, "{output}");
    assert!(output.contains("\"outcome\":\"ok\""));
    assert!(output.contains("\"entryCount\":4"));
    assert!(output.contains("NEG-004"));

    // Verify updated ledger file
    let verify_cmd = parse_fss_args([
        OsString::from("negative-evidence"),
        OsString::from("verify"),
        OsString::from("--path"),
        OsString::from(path_str),
    ])
    .map_err(|e| format!("parse failed: {e:?}"))?;

    let (verify_output, verify_exit) = execute_fss_with_exit(verify_cmd);
    assert_eq!(verify_exit.code, 0);
    assert!(verify_output.contains("4 entries"));
    assert!(verify_output.contains("all 1 locally certified entries"));

    // The write went through a same-directory temp file that no longer exists.
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("non-unicode file name")?;
    let parent = path.parent().ok_or("temp file has no parent")?;
    for dir_entry in fs::read_dir(parent)? {
        let name = dir_entry?.file_name();
        let name = name.to_string_lossy();
        assert!(
            !name.starts_with(&format!(".{file_name}.tmp-")),
            "leftover temp file {name}"
        );
    }
    Ok(())
}

#[test]
fn test_cli_append_refuses_omitted_coverage_witness() -> Result<(), Box<dyn Error>> {
    let (guard, path_str) = seeded_ledger_file("nowitness_ledger")?;
    let before = fs::read(&guard.0)?;

    // Every required option is present; the coverage witness options are omitted entirely.
    let mut args = append_argv(&path_str, &[required_append_options("NEG-005")]);
    args.push(OsString::from("--json"));
    let cmd = parse_fss_args(args).map_err(|e| format!("parse failed: {e:?}"))?;

    let (output, exit_id) = execute_fss_with_exit(cmd);
    assert_eq!(exit_id.code, 1);
    assert!(output.contains("\"outcome\":\"error\""));
    assert!(output.contains("ERR-NEG-MISSING-COVERAGE-001"));
    assert!(output.contains("absence without coverage witness is never evidence"));
    assert!(output.contains("no coverage witness supplied"));
    assert_eq!(fs::read(&guard.0)?, before, "refused append must not write");
    Ok(())
}

#[test]
fn test_cli_append_refuses_incomplete_coverage_witness() -> Result<(), Box<dyn Error>> {
    let (guard, path_str) = seeded_ledger_file("partialwitness_ledger")?;
    let before = fs::read(&guard.0)?;
    let partial = vec![
        "--negative-predicate".to_owned(),
        "architectural-violation-absence:NEG-005".to_owned(),
    ];
    let cmd = parse_fss_args(append_argv(
        &path_str,
        &[required_append_options("NEG-005"), partial],
    ))
    .map_err(|e| format!("parse failed: {e:?}"))?;

    let (output, exit_id) = execute_fss_with_exit(cmd);
    assert_eq!(exit_id.code, 1);
    assert!(output.contains("ERR-NEG-MISSING-COVERAGE-001"));
    assert!(output.contains("incomplete coverage witness; missing --coverage-domain"));
    assert_eq!(fs::read(&guard.0)?, before);
    Ok(())
}

#[test]
fn test_cli_removed_options_are_unknown() -> Result<(), Box<dyn Error>> {
    for flag in ["--no-witness", "--entry-json", "--entry-file"] {
        let mut args = append_argv(
            "ledger.bin",
            &[
                required_append_options("NEG-005"),
                witness_options("NEG-005"),
            ],
        );
        args.push(OsString::from(flag));
        args.push(OsString::from("value"));
        let err = parse_error(args)?;
        assert_eq!(err.error_id(), ERR_CLI_UNKNOWN_OPTION, "{flag}");
    }
    Ok(())
}

#[test]
fn test_cli_append_requires_path_and_date_commit() -> Result<(), Box<dyn Error>> {
    let mut no_path = argv(&["negative-evidence", "append"]);
    no_path.extend(
        required_append_options("NEG-005")
            .iter()
            .map(OsString::from),
    );
    no_path.extend(witness_options("NEG-005").iter().map(OsString::from));
    match parse_error(no_path)? {
        CliError::MissingValue { ref option, .. } => assert_eq!(option, "--path"),
        other => return Err(format!("unexpected error {other:?}").into()),
    }

    let without_date: Vec<String> = required_append_options("NEG-005")
        .into_iter()
        .skip(4)
        .chain(["--id".to_owned(), "NEG-005".to_owned()])
        .collect();
    let err = parse_error(append_argv(
        "ledger.bin",
        &[without_date, witness_options("NEG-005")],
    ))?;
    assert_eq!(err.error_id(), ERR_CLI_MISSING_VALUE);
    match err {
        CliError::MissingValue { ref option, .. } => assert_eq!(option, "--date-commit"),
        other => return Err(format!("unexpected error {other:?}").into()),
    }

    match parse_error(argv(&["negative-evidence", "init"]))? {
        CliError::MissingValue { ref option, .. } => assert_eq!(option, "--path"),
        other => return Err(format!("unexpected error {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_cli_value_errors_are_usage_errors() -> Result<(), Box<dyn Error>> {
    for (flag, bad) in [
        ("--decision", "Reject"),
        ("--disposition", "maybe"),
        ("--continuity", "sometimes"),
        ("--completeness", "mostly"),
        ("--stop-reason", "interrupted"),
        ("--coverage-generation", "0"),
    ] {
        let mut args = append_argv(
            "ledger.bin",
            &[
                required_append_options("NEG-005"),
                witness_options("NEG-005"),
            ],
        );
        let pos = args
            .iter()
            .position(|a| a == flag)
            .ok_or_else(|| format!("{flag} not present"))?;
        args[pos + 1] = OsString::from(bad);
        let err = parse_error(args)?;
        assert_eq!(err.error_id(), ERR_CLI_MALFORMED_VALUE, "{flag} {bad}");
        assert_eq!(err.exit_identity().code, 2, "{flag} {bad}");
    }
    Ok(())
}

#[test]
fn test_cli_append_refuses_missing_ledger_file() -> Result<(), Box<dyn Error>> {
    let path = temp_file_path("missing_ledger");
    let _guard = TempFileGuard(path.clone());
    let path_str = path.to_str().ok_or("non-unicode path")?;
    let cmd = parse_fss_args(append_argv(
        path_str,
        &[
            required_append_options("NEG-009"),
            witness_options("NEG-009"),
        ],
    ))
    .map_err(|e| format!("parse failed: {e:?}"))?;

    let (output, exit_id) = execute_fss_with_exit(cmd);
    assert_eq!(exit_id.code, 1);
    assert!(output.contains("does not exist"));
    assert!(output.contains("negative-evidence init"));
    assert!(!path.exists(), "a refused append must not create a ledger");
    Ok(())
}

#[test]
fn test_cli_init_creates_seed_ledger_and_never_overwrites() -> Result<(), Box<dyn Error>> {
    let path = temp_file_path("init_ledger");
    let _guard = TempFileGuard(path.clone());
    let path_str = path.to_str().ok_or("non-unicode path")?;

    let cmd = parse_fss_args(argv(&["negative-evidence", "init", "--path", path_str]))
        .map_err(|e| format!("parse failed: {e:?}"))?;
    let (output, exit_id) = execute_fss_with_exit(cmd);
    assert_eq!(exit_id.code, 0, "{output}");
    let bytes = fs::read(&path)?;
    assert_eq!(
        ContentDigest::sha256(&bytes).to_text(),
        INITIAL_NEGATIVE_EVIDENCE_LEDGER_DIGEST
    );

    let again = parse_fss_args(argv(&["negative-evidence", "init", "--path", path_str]))
        .map_err(|e| format!("parse failed: {e:?}"))?;
    let (again_output, again_exit) = execute_fss_with_exit(again);
    assert_eq!(again_exit.code, 1);
    assert!(again_output.contains("already exists"));
    assert_eq!(fs::read(&path)?, bytes);

    // The initialized ledger accepts a witnessed append.
    let append = parse_fss_args(append_argv(
        path_str,
        &[
            required_append_options("NEG-004"),
            witness_options("NEG-004"),
        ],
    ))
    .map_err(|e| format!("parse failed: {e:?}"))?;
    let (append_output, append_exit) = execute_fss_with_exit(append);
    assert_eq!(append_exit.code, 0, "{append_output}");
    Ok(())
}

#[test]
fn test_cli_append_refuses_duplicate_id() -> Result<(), Box<dyn Error>> {
    let path = temp_file_path("duplicate_ledger");
    let _guard = TempFileGuard(path.clone());

    let initial_ledger = initial_negative_evidence_ledger()?;
    fs::write(&path, initial_ledger.encode_canonical()?)?;

    let path_str = path
        .to_str()
        .ok_or_else(|| "non-unicode path".to_string())?;

    // Attempt to append duplicate NEG-001
    let cmd = parse_fss_args(append_argv(
        path_str,
        &[
            required_append_options("NEG-001"),
            witness_options("NEG-001"),
        ],
    ))
    .map_err(|e| format!("parse failed: {e:?}"))?;

    let (output, exit_id) = execute_fss_with_exit(cmd);
    assert_eq!(exit_id.code, 1);
    assert!(output.contains("ERR-NEG-DUPLICATE-ID-001"));
    Ok(())
}

#[test]
fn test_cli_aliases_and_subcommand_dispatch() -> Result<(), Box<dyn Error>> {
    for alias in ["neg", "negative", "negative-evidence"] {
        let cmd = parse_fss_args([OsString::from(alias), OsString::from("list")])
            .map_err(|e| format!("alias parse failed: {e:?}"))?;
        match cmd {
            FssCommand::NegativeEvidence(ref action) => match &**action {
                NegativeEvidenceAction::List { path, json } => {
                    assert!(path.is_none());
                    assert!(!json);
                }
                other => return Err(format!("unexpected action: {other:?}").into()),
            },
            other => return Err(format!("unexpected command: {other:?}").into()),
        }
        let (output, exit_id) = execute_negative_evidence(match cmd {
            FssCommand::NegativeEvidence(ref action) => action,
            _ => return Err("expected NegativeEvidence".into()),
        });
        assert_eq!(exit_id.code, 0);
        assert!(output.contains("NEG-001"));
    }
    Ok(())
}
