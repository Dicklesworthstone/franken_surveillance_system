//! Repository guard contract ensuring EffectJournal::replay_versioned and
//! EffectJournal::replay_durable remain unreachable outside the authorized durable journal path (fss-8dnfo).

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

/// Scans a directory recursively collecting all `.rs` source files.
fn collect_rust_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, files)?;
        } else if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            files.push(path);
        }
    }
    Ok(())
}

/// Normalizes a path relative to the repository root.
fn repo_relative(path: &Path, repo_root: &Path) -> Result<String, Box<dyn Error>> {
    let rel = path
        .strip_prefix(repo_root)
        .map_err(|e| format!("path {:?} not within repo root {:?}: {e}", path, repo_root))?;
    Ok(rel.to_str().ok_or("non-utf8 path")?.replace('\\', "/"))
}

/// Checks whether a given Rust file content has unauthorized calls/mentions of the guarded functions.
fn check_file_for_unauthorized_replay(rel_path: &str, content: &str) -> Result<(), String> {
    // This guard test itself is exempt from the literal string check.
    if rel_path.ends_with("effect_replay_guard_contract.rs") {
        return Ok(());
    }

    // replay_versioned is pub(crate) and restricted strictly to crates/fss-core/src/effect.rs
    if rel_path != "crates/fss-core/src/effect.rs" && content.contains("replay_versioned") {
        return Err(format!(
            "Unauthorized reference to replay_versioned in '{}'. \
             EffectJournal::replay_versioned must remain unreachable outside fss-core (fss-8dnfo).",
            rel_path
        ));
    }

    // replay_durable is restricted strictly to crates/fss-core/src/effect.rs (definition)
    // and crates/fss-reference/src/durable_effect.rs (durable journal replay)
    let is_authorized_durable = rel_path == "crates/fss-core/src/effect.rs"
        || rel_path == "crates/fss-reference/src/durable_effect.rs";
    if !is_authorized_durable && content.contains("replay_durable") {
        return Err(format!(
            "Unauthorized reference to replay_durable in '{}'. \
             EffectJournal::replay_durable must be called only by the durable journal path (fss-8dnfo).",
            rel_path
        ));
    }

    Ok(())
}

#[test]
fn repository_guard_replay_versioned_and_durable_callers_are_strictly_bounded()
-> Result<(), Box<dyn Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest_dir
        .parent()
        .ok_or("failed to find crates directory")?;
    let repo_root = crates_dir
        .parent()
        .ok_or("failed to find repository root")?;

    let mut scanned_files = Vec::new();

    for crate_entry in fs::read_dir(crates_dir)? {
        let crate_entry = crate_entry?;
        if !crate_entry.file_type()?.is_dir() {
            continue;
        }
        let crate_path = crate_entry.path();
        for sub in &["src", "tests", "examples", "benches"] {
            let target_dir = crate_path.join(sub);
            collect_rust_files(&target_dir, &mut scanned_files)?;
        }
    }

    assert!(
        scanned_files.len() > 50,
        "sanity check: expected to scan at least 50 rust files across crates, found {}",
        scanned_files.len()
    );

    let mut violations = Vec::new();
    for file in &scanned_files {
        let rel_path = repo_relative(file, repo_root)?;
        let content = fs::read_to_string(file)?;
        if let Err(violation) = check_file_for_unauthorized_replay(&rel_path, &content) {
            violations.push(violation);
        }
    }

    if !violations.is_empty() {
        return Err(format!(
            "Repository guard failed with {} violation(s):\n{}",
            violations.len(),
            violations.join("\n")
        )
        .into());
    }

    Ok(())
}

#[test]
fn repository_guard_planted_negatives_detect_unauthorized_callers() -> Result<(), Box<dyn Error>> {
    // Planted negative 1: unauthorized call to replay_versioned in an integration test
    let bad_code1 = r#"
        let _ = EffectJournal::replay_versioned([]);
    "#;
    let res1 =
        check_file_for_unauthorized_replay("crates/fss-reference/tests/some_test.rs", bad_code1);
    assert!(
        res1.is_err(),
        "Planted negative 1 failed: unauthorized replay_versioned was not detected"
    );

    // Planted negative 2: unauthorized call to replay_durable outside durable_effect.rs
    let bad_code2 = r#"
        let _ = EffectJournal::replay_durable([]);
    "#;
    let res2 = check_file_for_unauthorized_replay("crates/fss-core/tests/some_test.rs", bad_code2);
    assert!(
        res2.is_err(),
        "Planted negative 2 failed: unauthorized replay_durable was not detected"
    );

    // Planted negative 3: unauthorized call to replay_durable in fss-ledger or fss-cli
    let bad_code3 = r#"
        let journal = EffectJournal::replay_durable(transitions)?;
    "#;
    let res3 = check_file_for_unauthorized_replay("crates/fss-cli/src/main.rs", bad_code3);
    assert!(
        res3.is_err(),
        "Planted negative 3 failed: unauthorized replay_durable in cli was not detected"
    );

    // Authorized paths pass
    let ok_core = check_file_for_unauthorized_replay(
        "crates/fss-core/src/effect.rs",
        "pub(crate) fn replay_versioned() {}\npub fn replay_durable() {}",
    );
    assert!(ok_core.is_ok());

    let ok_ref = check_file_for_unauthorized_replay(
        "crates/fss-reference/src/durable_effect.rs",
        "EffectJournal::replay_durable(transitions)",
    );
    assert!(ok_ref.is_ok());

    Ok(())
}
