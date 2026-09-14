#![forbid(unsafe_code)]
//! Repository guard test for world-fact authority constructor isolation (fss-sz0cc).
//!
//! Threat model: type-level discipline against accidental or stale authority.
//! The constructor `__durable_ledger_only_from_committed_anchor` must only be called
//! by `crates/fss-ledger/src/durable.rs` (`DurableReferenceLedger::authoritative_ledger()`).
//! It trusts the caller to hold the writer lock and the on-disk head; calling it anywhere
//! else is a bug.
//!
//! This test statically scans all Rust source files in workspace `crates/*/src` and
//! `crates/*/tests` and asserts that `__durable_ledger_only_from_committed_anchor` appears
//! outside `crates/fss-core/` in EXACTLY ONE place: `crates/fss-ledger/src/durable.rs`.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const CONSTRUCTOR_NAME: &str = "__durable_ledger_only_from_committed_anchor";
const ALLOWED_EXTERNAL_FILE: &str = "crates/fss-ledger/src/durable.rs";

#[derive(Debug)]
struct Finding {
    path: String,
    line: usize,
    content: String,
}

fn collect_rs_files(dir: &Path, acc: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, acc)?;
        } else if path.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            acc.push(path);
        }
    }
    Ok(())
}

#[test]
fn test_durable_ledger_constructor_isolated_to_durable_rs() -> Result<(), Box<dyn Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .ok_or("missing crates parent")?
        .parent()
        .ok_or("missing repo root")?;

    let crates_dir = repo_root.join("crates");
    let mut rs_files = Vec::new();

    for crate_entry in fs::read_dir(&crates_dir)? {
        let crate_entry = crate_entry?;
        let crate_path = crate_entry.path();
        if !crate_path.is_dir() {
            continue;
        }
        collect_rs_files(&crate_path.join("src"), &mut rs_files)?;
        collect_rs_files(&crate_path.join("tests"), &mut rs_files)?;
    }

    let mut external_findings: Vec<Finding> = Vec::new();

    for file_path in rs_files {
        let relative = file_path
            .strip_prefix(repo_root)?
            .to_str()
            .ok_or("invalid utf8 path")?
            .replace('\\', "/");

        // Skip files inside crates/fss-core/ (definition, re-exports, and core tests)
        if relative.starts_with("crates/fss-core/") {
            continue;
        }

        let contents = fs::read_to_string(&file_path)?;
        for (idx, line) in contents.lines().enumerate() {
            if line.contains(CONSTRUCTOR_NAME) {
                external_findings.push(Finding {
                    path: relative.clone(),
                    line: idx + 1,
                    content: line.trim().to_string(),
                });
            }
        }
    }

    // Must appear in EXACTLY ONE external file: crates/fss-ledger/src/durable.rs
    assert!(
        !external_findings.is_empty(),
        "Expected {CONSTRUCTOR_NAME} to appear in {ALLOWED_EXTERNAL_FILE}, but found no external occurrences"
    );

    let offending: Vec<&Finding> = external_findings
        .iter()
        .filter(|f| f.path != ALLOWED_EXTERNAL_FILE)
        .collect();

    if !offending.is_empty() {
        let mut msg = format!(
            "Repository violation: {CONSTRUCTOR_NAME} found in unauthorized external files:\n"
        );
        for f in &offending {
            msg.push_str(&format!("  {}:{}: {}\n", f.path, f.line, f.content));
        }
        panic!("{msg}");
    }

    assert_eq!(
        external_findings.len(),
        1,
        "Expected exactly 1 occurrence in {ALLOWED_EXTERNAL_FILE}, found {}: {:?}",
        external_findings.len(),
        external_findings
    );

    Ok(())
}
