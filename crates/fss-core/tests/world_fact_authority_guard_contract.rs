#![forbid(unsafe_code)]
//! Repository guard test for world-fact authority constructor isolation (fss-sz0cc).
//!
//! Threat model: type-level discipline against accidental or stale authority.
//! The constructor `__durable_ledger` followed by `_only_from_committed_anchor` must only
//! be called by `crates/fss-ledger/src/durable.rs` (`DurableReferenceLedger::authoritative_ledger()`).
//! It trusts the caller to hold the opened durable ledger and the on-disk head; calling it anywhere
//! else is a bug.
//!
//! This test statically scans all Rust source files under workspace `crates/*/{src,tests,examples,benches}`,
//! excluding `target/` and `.git/`.
//! The constructor is allowlisted ONLY in `crates/fss-core/src/abstraction/world_facts.rs` (definition)
//! and in EXACTLY ONE external file: `crates/fss-ledger/src/durable.rs` (authorized caller).

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const CONSTRUCTOR_NAME: &str = concat!("__durable_ledger", "_only_from_committed_anchor");
const ALLOWED_DEFINITION_FILE: &str = "crates/fss-core/src/abstraction/world_facts.rs";
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
        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy();
        if file_name_str == "target" || file_name_str == ".git" {
            continue;
        }
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
    let subdirs = ["src", "tests", "examples", "benches"];

    for crate_entry in fs::read_dir(&crates_dir)? {
        let crate_entry = crate_entry?;
        let crate_path = crate_entry.path();
        if !crate_path.is_dir() {
            continue;
        }
        for subdir in subdirs {
            collect_rs_files(&crate_path.join(subdir), &mut rs_files)?;
        }
    }

    let mut definition_count = 0;
    let mut external_findings: Vec<Finding> = Vec::new();
    let mut unauthorized_findings: Vec<Finding> = Vec::new();

    for file_path in rs_files {
        let relative = file_path
            .strip_prefix(repo_root)?
            .to_str()
            .ok_or("invalid utf8 path")?
            .replace('\\', "/");

        let contents = fs::read_to_string(&file_path)?;
        for (idx, line) in contents.lines().enumerate() {
            if line.contains(CONSTRUCTOR_NAME) {
                let finding = Finding {
                    path: relative.clone(),
                    line: idx + 1,
                    content: line.trim().to_string(),
                };
                if relative == ALLOWED_DEFINITION_FILE {
                    definition_count += 1;
                } else if relative == ALLOWED_EXTERNAL_FILE {
                    external_findings.push(finding);
                } else {
                    unauthorized_findings.push(finding);
                }
            }
        }
    }

    // Must be defined in the canonical definition file
    assert!(
        definition_count >= 1,
        "Expected {CONSTRUCTOR_NAME} definition in {ALLOWED_DEFINITION_FILE}, but none found"
    );

    // Must appear in EXACTLY ONE external caller: crates/fss-ledger/src/durable.rs
    assert_eq!(
        external_findings.len(),
        1,
        "Expected exactly 1 external occurrence in {ALLOWED_EXTERNAL_FILE}, found {}: {:?}",
        external_findings.len(),
        external_findings
    );

    // Must NOT appear in any other file across the workspace
    if !unauthorized_findings.is_empty() {
        let mut msg =
            format!("Repository violation: {CONSTRUCTOR_NAME} found in unauthorized files:\n");
        for f in &unauthorized_findings {
            msg.push_str(&format!("  {}:{}: {}\n", f.path, f.line, f.content));
        }
        assert!(unauthorized_findings.is_empty(), "{msg}");
    }

    Ok(())
}
