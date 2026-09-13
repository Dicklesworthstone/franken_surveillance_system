#![forbid(unsafe_code)]
//! Deterministic contract tests for `fss negative-evidence` CLI (FSS-012).
//!
//! Enforces:
//! 1. Help, version, init, list, verify, and append command execution.
//! 2. `--json` emits `fss.negative_evidence_report.v1` exactly as the schema-validated goldens,
//!    and never claims the agent response envelope.
//! 3. Deterministic refusal of absence without a (complete) coverage witness or proof.
//! 4. Refusal of corrupt checksum, magic, duplicate entry ID, and missing ledger files.
//! 5. Exact exit identities: value errors are usage errors (exit 2), refusals exit 1.
//! 6. Concurrent appends from real processes never lose an entry; stale locks are refused.

use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use fss_cli::{
    CliError, ERR_CLI_MALFORMED_VALUE, ERR_CLI_MISSING_VALUE, ERR_CLI_UNKNOWN_OPTION, FssCommand,
    NegativeEvidenceAction, execute_fss_with_exit, execute_negative_evidence, parse_fss_args,
};
use fss_core::ContentDigest;
use fss_core::negative_evidence::{
    INITIAL_NEGATIVE_EVIDENCE_LEDGER_DIGEST, NEGATIVE_EVIDENCE_LEDGER_MAGIC,
    NegativeEvidenceLedger, initial_negative_evidence_ledger,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

const CLI_DOMAIN: &str = "domain:negative-evidence:cli-test";
const LEGACY_V1: &str = "../../tests/fixtures/negative_evidence_ledger_v1.bin";

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
        if let Ok(lock) = sidecar(&self.0, ".lock") {
            let _ = fs::remove_file(lock);
        }
    }
}

fn sidecar(ledger: &Path, suffix: &str) -> Result<PathBuf, Box<dyn Error>> {
    let name = ledger
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("non-unicode file name")?;
    let parent = ledger.parent().ok_or("ledger has no parent")?;
    Ok(parent.join(format!(".{name}{suffix}")))
}

fn assert_no_sidecars(ledger: &Path) -> Result<(), Box<dyn Error>> {
    let name = ledger
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("non-unicode file name")?;
    let parent = ledger.parent().ok_or("ledger has no parent")?;
    for dir_entry in fs::read_dir(parent)? {
        let entry_name = dir_entry?.file_name();
        let entry_name = entry_name.to_string_lossy();
        assert!(
            !entry_name.starts_with(&format!(".{name}.")),
            "leftover lock or temp file {entry_name}"
        );
    }
    Ok(())
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

fn anchor_text() -> String {
    format!(
        "site:fss:cli-test@0.1.0.0.0.0@{}",
        ContentDigest::sha256(b"cli-test-state-root").to_text()
    )
}

/// A complete certifying coverage witness bound to `id`, with separate observed coverage.
fn witness_options(id: &str) -> Vec<String> {
    vec![
        "--coverage-domain".to_owned(),
        CLI_DOMAIN.to_owned(),
        "--coverage-generation".to_owned(),
        "1".to_owned(),
        "--observed-domain".to_owned(),
        CLI_DOMAIN.to_owned(),
        "--observed-generation".to_owned(),
        "1".to_owned(),
        "--coverage-anchor".to_owned(),
        anchor_text(),
        "--negative-predicate".to_owned(),
        format!("absence-certified:{CLI_DOMAIN}:{id}"),
        "--continuity".to_owned(),
        "continuous".to_owned(),
        "--completeness".to_owned(),
        "complete".to_owned(),
        "--stop-reason".to_owned(),
        "complete".to_owned(),
    ]
}

fn proof_options() -> Vec<String> {
    vec![
        "--proof-hash".to_owned(),
        ContentDigest::sha256(b"cli-test-proof").to_text(),
        "--evidence-ref".to_owned(),
        "proof-bundle:cli-test".to_owned(),
    ]
}

fn append_argv(path: &str, extra: &[Vec<String>]) -> Vec<OsString> {
    let mut args = argv(&["negative-evidence", "append", "--path", path]);
    for group in extra {
        args.extend(group.iter().map(OsString::from));
    }
    args
}

fn full_append_argv(path: &str, id: &str) -> Vec<OsString> {
    append_argv(
        path,
        &[
            required_append_options(id),
            witness_options(id),
            proof_options(),
        ],
    )
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

fn run(args: Vec<OsString>) -> Result<(String, u8), Box<dyn Error>> {
    let cmd = parse_fss_args(args).map_err(|e| format!("parse failed: {e:?}"))?;
    let (output, exit_id) = execute_fss_with_exit(cmd);
    Ok((output, exit_id.code))
}

fn replace_option(args: &mut [OsString], flag: &str, value: &str) -> Result<(), Box<dyn Error>> {
    let pos = args
        .iter()
        .position(|a| a == flag)
        .ok_or_else(|| format!("{flag} not present"))?;
    args[pos + 1] = OsString::from(value);
    Ok(())
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
    assert!(output.contains("--observed-domain"));
    assert!(output.contains("--proof-hash"));
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
    assert!(output.contains("Knowledge: unknown (finding: vendor_claimed, decision: policy)"));

    // JSON report list
    let cmd_json = parse_fss_args([
        OsString::from("negative-evidence"),
        OsString::from("list"),
        OsString::from("--json"),
    ])
    .map_err(|e| format!("parse failed: {e:?}"))?;
    let (json_output, exit_id_json) = execute_fss_with_exit(cmd_json);
    assert_eq!(exit_id_json.code, 0);
    assert!(json_output.contains("\"schema\":\"fss.negative_evidence_report.v1\""));
    assert!(json_output.contains("\"outcome\":\"ok\""));
    assert!(json_output.contains("\"entryCount\":3"));
    assert!(json_output.contains(INITIAL_NEGATIVE_EVIDENCE_LEDGER_DIGEST));
    assert!(json_output.contains("\"epistemicState\":\"unknown\""));
    Ok(())
}

#[test]
fn test_cli_report_does_not_claim_the_agent_envelope() -> Result<(), Box<dyn Error>> {
    for args in [
        argv(&["negative-evidence", "verify", "--json"]),
        argv(&["negative-evidence", "list", "--json"]),
        argv(&["negative-evidence", "verify", "--path", LEGACY_V1, "--json"]),
    ] {
        let (output, _) = run(args)?;
        for fabricated in [
            "fss.agent_response_envelope.v1",
            "operationId",
            "AOP-",
            "AVIEW-",
            "CAP-AGENT",
            "principalId",
            "requestId",
            "traceId",
            "policy:gen:initial",
            "createdAtNs",
            "budgets",
        ] {
            assert!(!output.contains(fabricated), "{fabricated} in {output}");
        }
        assert!(output.contains("not_an_agent_response_envelope"));
    }
    Ok(())
}

#[test]
fn test_cli_json_reports_match_schema_goldens() -> Result<(), Box<dyn Error>> {
    // tests/test_negative_evidence_report_schema.py validates these goldens against
    // schemas/negative_evidence_report.v1.json, so the CLI output is schema-valid.
    let goldens = [
        (
            argv(&["negative-evidence", "list", "--json"]),
            include_str!("../../../tests/fixtures/negative_evidence_report/list_builtin.json"),
        ),
        (
            argv(&["negative-evidence", "verify", "--json"]),
            include_str!("../../../tests/fixtures/negative_evidence_report/verify_builtin.json"),
        ),
        (
            argv(&["negative-evidence", "verify", "--path", LEGACY_V1, "--json"]),
            include_str!(
                "../../../tests/fixtures/negative_evidence_report/verify_legacy_v1_refused.json"
            ),
        ),
    ];
    for (args, golden) in goldens {
        let (output, _) = run(args)?;
        assert_eq!(output.trim_end(), golden.trim_end());
    }

    let (guard, path) = seeded_ledger_file("golden_append")?;
    let mut args = full_append_argv(&path, "NEG-004");
    args.push(OsString::from("--json"));
    let (output, code) = run(args)?;
    assert_eq!(code, 0, "{output}");
    assert_eq!(
        output.replace(&path, "<LEDGER_PATH>").trim_end(),
        include_str!("../../../tests/fixtures/negative_evidence_report/append_witnessed.json")
            .trim_end()
    );
    drop(guard);
    Ok(())
}

#[test]
fn test_cli_verify_default_and_json() -> Result<(), Box<dyn Error>> {
    // Plaintext verify: with no locally certified entries, no coverage guarantee is claimed.
    let cmd = parse_fss_args([
        OsString::from("negative-evidence"),
        OsString::from("verify"),
    ])
    .map_err(|e| format!("parse failed: {e:?}"))?;
    let (output, exit_id) = execute_fss_with_exit(cmd);
    assert_eq!(exit_id.code, 0);
    assert!(output.contains("Ledger verified"));
    assert!(output.contains("none locally certified"));
    assert!(!output.contains("guarantees intact"));
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
    assert!(json_output.contains("\"schema\":\"fss.negative_evidence_report.v1\""));
    assert!(json_output.contains("\"verified\":true"));
    assert!(json_output.contains("\"formatVersion\":2"));
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

    // Verify JSON mode reports the refusal
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

    // Append a new valid entry NEG-004 carrying a complete certifying witness and proof
    let mut args = full_append_argv(path_str, "NEG-004");
    args.push(OsString::from("--json"));
    let (output, code) = run(args)?;
    assert_eq!(code, 0, "{output}");
    assert!(output.contains("\"outcome\":\"ok\""));
    assert!(output.contains("\"entryCount\":4"));
    assert!(output.contains("NEG-004"));
    assert!(output.contains("\"knowledgeState\":\"known\""));
    assert!(output.contains("\"provenanceClass\":\"operator_asserted\""));

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

    // The write went through a same-directory temp file and a lock that no longer exist.
    assert_no_sidecars(&path)?;
    Ok(())
}

#[test]
fn test_cli_append_refuses_omitted_coverage_witness() -> Result<(), Box<dyn Error>> {
    let (guard, path_str) = seeded_ledger_file("nowitness_ledger")?;
    let before = fs::read(&guard.0)?;

    // Every other option is present; the coverage witness options are omitted entirely.
    let mut args = append_argv(
        &path_str,
        &[required_append_options("NEG-005"), proof_options()],
    );
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
        format!("absence-certified:{CLI_DOMAIN}:NEG-005"),
    ];
    let cmd = parse_fss_args(append_argv(
        &path_str,
        &[required_append_options("NEG-005"), partial, proof_options()],
    ))
    .map_err(|e| format!("parse failed: {e:?}"))?;

    let (output, exit_id) = execute_fss_with_exit(cmd);
    assert_eq!(exit_id.code, 1);
    assert!(output.contains("ERR-NEG-MISSING-COVERAGE-001"));
    assert!(output.contains("incomplete coverage witness; missing --coverage-domain"));
    assert!(output.contains("--observed-domain"));
    assert_eq!(fs::read(&guard.0)?, before);
    Ok(())
}

#[test]
fn test_cli_append_refuses_missing_proof() -> Result<(), Box<dyn Error>> {
    let (guard, path_str) = seeded_ledger_file("noproof_ledger")?;
    let before = fs::read(&guard.0)?;
    for proof in [
        vec![],
        vec![
            "--proof-hash".to_owned(),
            ContentDigest::sha256(b"p").to_text(),
        ],
        vec!["--evidence-ref".to_owned(), "proof-bundle:x".to_owned()],
    ] {
        let (output, code) = run(append_argv(
            &path_str,
            &[
                required_append_options("NEG-005"),
                witness_options("NEG-005"),
                proof,
            ],
        ))?;
        assert_eq!(code, 1, "{output}");
        assert!(output.contains("ERR-NEG-MISSING-PROOF-001"), "{output}");
        assert_eq!(
            fs::read(&guard.0)?,
            before,
            "known is never stamped without proof"
        );
    }
    Ok(())
}

#[test]
fn test_cli_observed_coverage_is_separate_from_claimed() -> Result<(), Box<dyn Error>> {
    let (guard, path_str) = seeded_ledger_file("observed_ledger")?;
    let before = fs::read(&guard.0)?;
    for (flag, value) in [
        ("--observed-domain", "domain:negative-evidence:elsewhere"),
        ("--observed-generation", "2"),
    ] {
        let mut args = full_append_argv(&path_str, "NEG-005");
        replace_option(&mut args, flag, value)?;
        let (output, code) = run(args)?;
        assert_eq!(code, 1, "{flag}: {output}");
        assert!(
            output.contains("ERR-NEG-UNCERTIFIED-COVERAGE-001"),
            "{flag}: {output}"
        );
    }
    assert_eq!(fs::read(&guard.0)?, before);
    Ok(())
}

#[test]
fn test_cli_removed_options_are_unknown() -> Result<(), Box<dyn Error>> {
    for flag in ["--no-witness", "--entry-json", "--entry-file"] {
        let mut args = full_append_argv("ledger.bin", "NEG-005");
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
        ("--observed-generation", "0"),
        ("--coverage-anchor", "site-without-counters"),
        ("--coverage-anchor", "site@1.2.3@sha256:00"),
        ("--proof-hash", "not-a-digest"),
    ] {
        let mut args = full_append_argv("ledger.bin", "NEG-005");
        replace_option(&mut args, flag, bad)?;
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
    let (output, code) = run(full_append_argv(path_str, "NEG-009"))?;
    assert_eq!(code, 1);
    assert!(output.contains("ERR-NEG-LEDGER-NOT-FOUND-001"), "{output}");
    assert!(output.contains("negative-evidence init"));
    assert!(!path.exists(), "a refused append must not create a ledger");
    assert_no_sidecars(&path)?;
    Ok(())
}

#[test]
fn test_cli_init_creates_seed_ledger_and_never_overwrites() -> Result<(), Box<dyn Error>> {
    let path = temp_file_path("init_ledger");
    let _guard = TempFileGuard(path.clone());
    let path_str = path.to_str().ok_or("non-unicode path")?;

    let (output, code) = run(argv(&["negative-evidence", "init", "--path", path_str]))?;
    assert_eq!(code, 0, "{output}");
    let bytes = fs::read(&path)?;
    assert_eq!(
        ContentDigest::sha256(&bytes).to_text(),
        INITIAL_NEGATIVE_EVIDENCE_LEDGER_DIGEST
    );

    let (again_output, again_code) = run(argv(&[
        "negative-evidence",
        "init",
        "--path",
        path_str,
        "--json",
    ]))?;
    assert_eq!(again_code, 1);
    assert!(
        again_output.contains("ERR-NEG-LEDGER-EXISTS-001"),
        "{again_output}"
    );
    assert!(again_output.contains("already exists"));
    assert_eq!(fs::read(&path)?, bytes);

    // The initialized ledger accepts a witnessed append.
    let (append_output, append_code) = run(full_append_argv(path_str, "NEG-004"))?;
    assert_eq!(append_code, 0, "{append_output}");
    assert_no_sidecars(&path)?;
    Ok(())
}

#[test]
fn test_cli_stale_lock_is_refused_and_never_broken() -> Result<(), Box<dyn Error>> {
    let (guard, path_str) = seeded_ledger_file("stale_lock_ledger")?;
    let before = fs::read(&guard.0)?;
    let lock = sidecar(&guard.0, ".lock")?;
    fs::write(&lock, b"pid 1\n")?;

    let (output, code) = run(full_append_argv(&path_str, "NEG-004"))?;
    assert_eq!(code, 1);
    assert!(output.contains("ERR-NEG-LEDGER-LOCKED-001"), "{output}");
    assert!(output.contains("never removed automatically"));
    assert!(lock.exists(), "a stale lock must not be broken");
    assert_eq!(fs::read(&guard.0)?, before);
    Ok(())
}

#[test]
fn test_cli_concurrent_appends_never_lose_entries() -> Result<(), Box<dyn Error>> {
    let bin = env!("CARGO_BIN_EXE_fss");
    let mut both_succeeded = 0;
    for iteration in 0..20 {
        let (guard, path) = seeded_ledger_file(&format!("concurrent_{iteration}"))?;
        let spawn = |id: &str| {
            Command::new(bin)
                .args(full_append_argv(&path, id))
                .arg("--json")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
        };
        let first = spawn("NEG-004")?;
        let second = spawn("NEG-100")?;
        let outputs = [
            ("NEG-004", first.wait_with_output()?),
            ("NEG-100", second.wait_with_output()?),
        ];

        let ledger = NegativeEvidenceLedger::decode_canonical(&fs::read(&guard.0)?)?;
        ledger.verify()?;
        for seed in ["NEG-001", "NEG-002", "NEG-003"] {
            assert!(
                ledger.contains(seed),
                "iteration {iteration}: seed {seed} lost"
            );
        }
        let mut successes = 0;
        for (id, output) in &outputs {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            match output.status.code() {
                Some(0) => {
                    successes += 1;
                    assert!(
                        ledger.contains(id),
                        "iteration {iteration}: {id} exited 0 but is missing: {text}"
                    );
                }
                Some(1) => {
                    // A clean refusal: the other writer held the lock, or it already appended
                    // the higher identifier.
                    assert!(
                        text.contains("ERR-NEG-LEDGER-LOCKED-001")
                            || text.contains("ERR-NEG-NON-CANONICAL-ORDER-001"),
                        "iteration {iteration}: unexpected refusal for {id}: {text}"
                    );
                    assert!(
                        !ledger.contains(id),
                        "iteration {iteration}: refused {id} landed"
                    );
                }
                other => {
                    return Err(
                        format!("iteration {iteration}: {id} exited {other:?}: {text}").into(),
                    );
                }
            }
        }
        assert_eq!(ledger.len(), 3 + successes, "iteration {iteration}");
        if successes == 2 {
            both_succeeded += 1;
        }
        assert_no_sidecars(&guard.0)?;
    }
    // Diagnostic only; either outcome per iteration is correct.
    eprintln!("concurrent appends: both succeeded in {both_succeeded}/20 iterations");
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
    let (output, code) = run(full_append_argv(path_str, "NEG-001"))?;
    assert_eq!(code, 1);
    assert!(output.contains("ERR-NEG-DUPLICATE-ID-001"));
    assert_no_sidecars(&path)?;
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

struct TempDirGuard(PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A seeded ledger at `<base>/real/real.bin` and a symlink to it at `<base>/links/link.bin`,
/// in a different directory so lock and temp placement must follow the real file.
#[cfg(unix)]
fn symlinked_ledger(prefix: &str) -> Result<(TempDirGuard, PathBuf, PathBuf), Box<dyn Error>> {
    let base = temp_file_path(prefix).with_extension("d");
    let real_dir = base.join("real");
    let link_dir = base.join("links");
    fs::create_dir_all(&real_dir)?;
    fs::create_dir_all(&link_dir)?;
    let guard = TempDirGuard(base);
    let real = real_dir.join("real.bin");
    fs::write(
        &real,
        initial_negative_evidence_ledger()?.encode_canonical()?,
    )?;
    let link = link_dir.join("link.bin");
    std::os::unix::fs::symlink(&real, &link)?;
    Ok((guard, real, link))
}

#[cfg(unix)]
#[test]
fn test_cli_append_via_symlink_updates_the_real_ledger() -> Result<(), Box<dyn Error>> {
    let (_guard, real, link) = symlinked_ledger("symlink_single")?;
    let link_str = link.to_str().ok_or("non-unicode path")?;
    let (output, code) = run(full_append_argv(link_str, "NEG-004"))?;
    assert_eq!(code, 0, "{output}");
    assert!(
        fs::symlink_metadata(&link)?.file_type().is_symlink(),
        "the symlink must not be replaced by a regular file"
    );
    let ledger = NegativeEvidenceLedger::decode_canonical(&fs::read(&real)?)?;
    assert_eq!(ledger.len(), 4);
    assert!(ledger.contains("NEG-004"));
    assert_no_sidecars(&real)?;
    assert_no_sidecars(&link)?;

    // The next append through the real path builds on the first; both paths agree.
    let real_str = real.to_str().ok_or("non-unicode path")?;
    let (output, code) = run(full_append_argv(real_str, "NEG-005"))?;
    assert_eq!(code, 0, "{output}");
    assert_eq!(fs::read(&link)?, fs::read(&real)?);
    assert_eq!(
        NegativeEvidenceLedger::decode_canonical(&fs::read(&link)?)?.len(),
        5
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn test_cli_concurrent_appends_via_symlink_and_real_path_share_one_ledger()
-> Result<(), Box<dyn Error>> {
    let bin = env!("CARGO_BIN_EXE_fss");
    for iteration in 0..20 {
        let (_guard, real, link) = symlinked_ledger(&format!("symlink_concurrent_{iteration}"))?;
        let real_str = real.to_str().ok_or("non-unicode path")?.to_owned();
        let link_str = link.to_str().ok_or("non-unicode path")?.to_owned();
        let spawn = |path: &str, id: &str| {
            Command::new(bin)
                .args(full_append_argv(path, id))
                .arg("--json")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
        };
        let via_link = spawn(&link_str, "NEG-004")?;
        let via_real = spawn(&real_str, "NEG-100")?;
        let outputs = [
            ("NEG-004", via_link.wait_with_output()?),
            ("NEG-100", via_real.wait_with_output()?),
        ];

        assert!(
            fs::symlink_metadata(&link)?.file_type().is_symlink(),
            "iteration {iteration}: the symlink was replaced"
        );
        let ledger = NegativeEvidenceLedger::decode_canonical(&fs::read(&real)?)?;
        ledger.verify()?;
        let mut successes = 0;
        for (id, output) in &outputs {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            match output.status.code() {
                Some(0) => {
                    successes += 1;
                    assert!(
                        ledger.contains(id),
                        "iteration {iteration}: {id} exited 0 but is missing: {text}"
                    );
                }
                Some(1) => {
                    assert!(
                        text.contains("ERR-NEG-LEDGER-LOCKED-001")
                            || text.contains("ERR-NEG-NON-CANONICAL-ORDER-001"),
                        "iteration {iteration}: unexpected refusal for {id}: {text}"
                    );
                    assert!(
                        !ledger.contains(id),
                        "iteration {iteration}: refused {id} landed"
                    );
                }
                other => {
                    return Err(
                        format!("iteration {iteration}: {id} exited {other:?}: {text}").into(),
                    );
                }
            }
        }
        assert_eq!(ledger.len(), 3 + successes, "iteration {iteration}");
        assert_no_sidecars(&real)?;
        assert_no_sidecars(&link)?;
    }
    Ok(())
}
