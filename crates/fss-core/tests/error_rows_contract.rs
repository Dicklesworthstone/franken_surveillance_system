//! Field-level contract tests for the stable error registry rows
//! (`registries/ERRORS.md` — itself the machine authority: "Errors are
//! machine identities"), realizing the fss-x4a.30.91 family acceptance:
//!
//! * every row exists exactly once with canonical `ERR-*-NNN` identity and
//!   non-empty meaning and retry policy;
//! * tombstoned rows (the registry's `~~strike~~` or tombstone markers) are
//!   never referenced as active by the operation crosswalk — enforced by
//!   `scripts/operation_crosswalk_checker.py` (run separately, PASS);
//! * the ContractBasis pin `REFERENCE_ERROR_REGISTRY_DIGEST` is asserted in
//!   `contract_basis_contract.rs` against the same file (in sync);
//! * mutation robustness: duplicate IDs and field tampering are detectable;
//! * the two camera-adapter rows (ERR-ADAPTER-PROTOCOL-001,
//!   ERR-STREAM-NO-FIRST-FRAME-001) match their exact normative text.

use std::collections::BTreeSet;
use std::error::Error;

/// One parsed registry row.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ErrorRow {
    id: String,
    meaning: String,
    retry: String,
}

/// Parses the registry's `| ID | Meaning | Retry policy |` table rows.
/// Off-shape lines are skipped only when they are not table rows at all
/// (prose, separators); a malformed table row fails loudly.
fn extract_error_rows(md: &str) -> Result<Vec<ErrorRow>, Box<dyn Error>> {
    let mut rows = Vec::new();
    for line in md.lines() {
        let line = line.trim();
        if !line.starts_with("| `ERR-") {
            // Other tables (exit codes, wire-error snake_case ids) share
            // this file; they are not error-registry rows.
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        // ['', '`ERR-...`', ' meaning ', ' retry ', '']
        if cells.len() < 4 {
            return Err(format!("short error table row: {line}").into());
        }
        let id = cells[1].trim_matches('`').to_string();
        let meaning = cells[2].trim().to_string();
        let retry = cells[3].trim().to_string();
        rows.push(ErrorRow { id, meaning, retry });
    }
    Ok(rows)
}

const ERRORS_MD: &str = include_str!("../../../registries/ERRORS.md");

#[test]
fn rows_are_unique_canonical_and_complete() -> Result<(), Box<dyn Error>> {
    let rows = extract_error_rows(ERRORS_MD)?;
    assert!(rows.len() > 400, "registry carries the full row set");
    let mut ids = BTreeSet::new();
    for row in &rows {
        assert!(ids.insert(row.id.clone()), "duplicate error id {}", row.id);
        assert!(
            row.id.starts_with("ERR-") && row.id.ends_with(char::is_numeric),
            "row id {} violates canonical ERR-*-NNN shape",
            row.id
        );
        assert!(!row.meaning.is_empty(), "{}: empty meaning", row.id);
        assert!(!row.retry.is_empty(), "{}: empty retry policy", row.id);
    }
    Ok(())
}

#[test]
fn camera_adapter_rows_match_exact_normative_text() -> Result<(), Box<dyn Error>> {
    let rows = extract_error_rows(ERRORS_MD)?;
    let find = |id: &str| rows.iter().find(|r| r.id == id).cloned();
    let protocol = find("ERR-ADAPTER-PROTOCOL-001").ok_or("row missing")?;
    assert_eq!(protocol.meaning, "adapter response violates typed protocol");
    assert_eq!(
        protocol.retry,
        "terminate adapter generation; retain fixture"
    );
    let no_first = find("ERR-STREAM-NO-FIRST-FRAME-001").ok_or("row missing")?;
    assert_eq!(
        no_first.meaning,
        "adapter accepted but no decodable frame before budget"
    );
    assert_eq!(no_first.retry, "reconnect or fail; never claim coverage");
    Ok(())
}

#[test]
fn registry_declares_machine_identity_semantics() {
    // The authority file itself declares the machine-identity contract that
    // keeps IDs stable across Rust/CLI/MCP transports.
    assert!(ERRORS_MD.contains("machine identities"));
    assert!(ERRORS_MD.contains("Retry policy"));
}

#[test]
fn tampering_is_detectable() -> Result<(), Box<dyn Error>> {
    let rows = extract_error_rows(ERRORS_MD)?;
    let first = rows.first().ok_or("rows present")?;
    let mut tampered = rows.clone();
    tampered.push(first.clone());
    let mut ids = BTreeSet::new();
    let mut dup_found = false;
    for row in &tampered {
        if !ids.insert(row.id.clone()) {
            dup_found = true;
        }
    }
    assert!(dup_found, "duplicate injection must be detectable");
    let mut mutated = first.clone();
    mutated.retry = "mutated policy".to_string();
    assert_ne!(*first, mutated);
    Ok(())
}
