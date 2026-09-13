#![forbid(unsafe_code)]
//! Deterministic contract tests for `fss negative-evidence` CLI (FSS-012).
//!
//! Enforces:
//! 1. Help, version, list, verify, and append command execution.
//! 2. Bounded agent response envelopes conforming to `fss.agent_response_envelope.v1`.
//! 3. Deterministic refusal of absence without coverage witness (`--no-witness`).
//! 4. Refusal of corrupt checksum, magic, or duplicate entry ID.
//! 5. Exact exit identities (`ExitIdentity::SUCCESS`, `ExitIdentity::RUNTIME_FAILURE`).

use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use fss_cli::{
    FssCommand, NegativeEvidenceAction, execute_fss_with_exit, execute_negative_evidence,
    parse_fss_args,
};
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
    assert!(output.contains("Continuous"));

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

    // Append a new valid entry NEG-004
    let cmd = parse_fss_args([
        OsString::from("negative-evidence"),
        OsString::from("append"),
        OsString::from("--path"),
        OsString::from(path_str),
        OsString::from("--id"),
        OsString::from("NEG-004"),
        OsString::from("--decision"),
        OsString::from("reject"),
        OsString::from("--hypothesis"),
        OsString::from("Proprietary cloud notification endpoint is reliable"),
        OsString::from("--reasoning"),
        OsString::from("Endpoint is uncertified and subject to vendor rate limiting"),
        OsString::from("--result"),
        OsString::from("Observed 40% packet drops during peak load"),
        OsString::from("--revival"),
        OsString::from("Official SLA offering 99.99% availability guarantee"),
        OsString::from("--negative-predicate"),
        OsString::from("architectural-violation-absence:NEG-004"),
        OsString::from("--json"),
    ])
    .map_err(|e| format!("parse failed: {e:?}"))?;

    let (output, exit_id) = execute_fss_with_exit(cmd);
    assert_eq!(exit_id.code, 0);
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
    Ok(())
}

#[test]
fn test_cli_append_refuses_omitted_coverage_witness() -> Result<(), Box<dyn Error>> {
    let path = temp_file_path("nowitness_ledger");
    let _guard = TempFileGuard(path.clone());

    let initial_ledger = initial_negative_evidence_ledger()?;
    fs::write(&path, initial_ledger.encode_canonical()?)?;

    let path_str = path
        .to_str()
        .ok_or_else(|| "non-unicode path".to_string())?;

    let cmd = parse_fss_args([
        OsString::from("negative-evidence"),
        OsString::from("append"),
        OsString::from("--path"),
        OsString::from(path_str),
        OsString::from("--id"),
        OsString::from("NEG-005"),
        OsString::from("--no-witness"),
        OsString::from("--json"),
    ])
    .map_err(|e| format!("parse failed: {e:?}"))?;

    let (output, exit_id) = execute_fss_with_exit(cmd);
    assert_eq!(exit_id.code, 1);
    assert!(output.contains("\"outcome\":\"error\""));
    assert!(output.contains("ERR-NEG-MISSING-COVERAGE-001"));
    assert!(output.contains("absence without coverage witness is never evidence"));
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
    let cmd = parse_fss_args([
        OsString::from("negative-evidence"),
        OsString::from("append"),
        OsString::from("--path"),
        OsString::from(path_str),
        OsString::from("--id"),
        OsString::from("NEG-001"),
        OsString::from("--negative-predicate"),
        OsString::from("architectural-violation-absence:NEG-001"),
    ])
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
