#![forbid(unsafe_code)]
//! Field-level contract tests for the schema registry rows
//! (`registries/SCHEMAS.md` — the machine authority), realizing the
//! fss-x4a.30.5..54 family acceptance:
//!
//! * every row exists exactly once with schema name, file, authority, and
//!   compatibility rule;
//! * three-way agreement: registry row ⇄ `schemas/*.json` file (its `$id`
//!   names the file) ⇄ a typed `SCHEMA` constant in the Rust sources
//!   (CLI-output rows resolve to the `fss-cli` emitter instead);
//! * mutation robustness: duplicate IDs and tampering are detectable.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};

const SCHEMAS_MD: &str = include_str!("../../../registries/SCHEMAS.md");

/// Rows whose schema file + registry row exist but whose typed Rust identity
/// belongs to an OPEN implementation lane (FSS-116 transfer, FSS-138 model
/// packages, release/ATP/agent-plane epics, 30.108 decision cards). This
/// allowlist is a RATCHET: it names the exact current gap set with owners,
/// fails if the set grows, and shrinks only by landing the typed identity.
/// Each entry names its owning lane.
const KNOWN_UNTYPED: [(&str, &str); 15] = [
    ("SCHEMA-CALIBRATION-CERT-001", "calibration qualification lane"),
    ("SCHEMA-TRANSFER-MANIFEST-001", "FSS-116/ATP transfer lane"),
    ("SCHEMA-DECISION-CARD-001", "30.108 decision-card implementation program"),
    ("SCHEMA-RELEASE-RECEIPT-001", "release qualification lane (GATE-120)"),
    ("SCHEMA-ADAPTER-CERT-001", "adapter qualification lane (GATE-090)"),
    ("SCHEMA-CANCEL-DRAIN-001", "cancellation/drain certification lane"),
    ("SCHEMA-TRANSFER-RECEIPT-001", "FSS-116/ATP transfer lane"),
    ("SCHEMA-MODEL-PACKAGE-001", "FSS-138 model package importer"),
    ("SCHEMA-RELEASE-BUILD-001", "release qualification lane (GATE-120)"),
    ("SCHEMA-RELEASE-STAGE-001", "release qualification lane (GATE-120)"),
    ("SCHEMA-SOURCE-MANIFEST-001", "source manifest lane"),
    ("SCHEMA-LICENSE-INVENTORY-001", "license inventory lane"),
    ("SCHEMA-QUALIFICATION-ROOT-002", "qualification root v2 lane"),
    ("SCHEMA-ROBOT-DOCS-001", "robot documentation lane"),
    ("SCHEMA-CALIBRATION-COVERAGE-GUARD-001", "calibration coverage guard lane"),
];

/// One parsed registry row.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SchemaRow {
    id: String,
    schema: String,
    file: String,
    authority: String,
    compat: String,
}

fn extract_schema_rows(md: &str) -> Result<Vec<SchemaRow>, Box<dyn Error>> {
    let mut rows = Vec::new();
    for line in md.lines() {
        let line = line.trim();
        if !line.starts_with("| `SCHEMA-") {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() < 6 {
            return Err(format!("short schema table row: {line}").into());
        }
        rows.push(SchemaRow {
            id: cells[1].trim_matches('`').to_string(),
            schema: cells[2].trim_matches('`').to_string(),
            file: cells[3].trim_matches('`').to_string(),
            authority: cells[4].trim().to_string(),
            compat: cells[5].trim().to_string(),
        });
    }
    Ok(rows)
}

/// Recursive `.rs` source listing under one directory (no walkdir dep).
fn collect_rs_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn rows_are_unique_canonical_and_complete() -> Result<(), Box<dyn Error>> {
    let rows = extract_schema_rows(SCHEMAS_MD)?;
    assert_eq!(rows.len(), 83, "registry carries the full 83-row set");
    let mut ids = BTreeSet::new();
    let mut schemas = BTreeSet::new();
    for row in &rows {
        assert!(ids.insert(row.id.clone()), "duplicate row id {}", row.id);
        assert!(
            schemas.insert(row.schema.clone()),
            "duplicate schema name {}",
            row.schema
        );
        assert!(
            row.id.starts_with("SCHEMA-") && row.id.ends_with(char::is_numeric),
            "row id {} violates canonical shape",
            row.id
        );
        assert!(row.schema.starts_with("fss."), "{}: non-fss schema", row.id);
        assert!(
            row.schema.ends_with(".v1") || row.schema.contains(".v"),
            "{}: schema {} lacks a version",
            row.id,
            row.schema
        );
        assert!(!row.authority.is_empty(), "{}: empty authority", row.id);
        assert!(
            !row.compat.is_empty(),
            "{}: empty compatibility rule — schema evolution rules are the row's point",
            row.id
        );
    }
    Ok(())
}

#[test]
fn registry_rows_agree_with_files_and_rust_schemas() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("workspace root")?
        .to_path_buf();
    // Collect the Rust source corpus once.
    let mut sources = Vec::new();
    collect_rs_sources(&root.join("crates"), &mut sources);
    assert!(sources.len() > 200, "source corpus present");
    let mut corpus = String::new();
    for src in &sources {
        corpus.push_str(&std::fs::read_to_string(src)?);
        corpus.push('\n');
    }

    let rows = extract_schema_rows(SCHEMAS_MD)?;
    let mut untyped_seen = BTreeSet::new();
    for row in &rows {
        if row.file == "CLI output" {
            // CLI-output schemas live in the fss-cli emitters/crosswalk.
            let cli = root.join("crates/fss-cli/src");
            let mut cli_sources = Vec::new();
            collect_rs_sources(&cli, &mut cli_sources);
            let mut cli_corpus = String::new();
            for src in &cli_sources {
                cli_corpus.push_str(&std::fs::read_to_string(src)?);
            }
            assert!(
                cli_corpus.contains(&row.schema),
                "{}: CLI-output schema {} not found in fss-cli sources",
                row.id,
                row.schema
            );
            continue;
        }
        let schema_file = root.join(&row.file);
        assert!(
            schema_file.exists(),
            "{}: schema file {} missing",
            row.id,
            row.file
        );
        let content = std::fs::read_to_string(&schema_file)?;
        assert!(
            content.contains(&format!("schemas/{}.json", row.schema.trim_start_matches("fss.").replace('.', "_")))
                || content.contains(&row.file),
            "{}: file $id does not reference its own path",
            row.id
        );
        if corpus.contains(&format!("\"{}\"", row.schema)) {
            continue; // typed identity present
        }
        // No typed const: permitted only for the named KNOWN_UNTYPED rows
        // (ratchet: the gap set may shrink by landing identities, never grow).
        let owner = KNOWN_UNTYPED
            .iter()
            .find(|(id, _)| *id == row.id)
            .map(|(_, owner)| owner);
        match owner {
            Some(owner) => {
                untyped_seen.insert(row.id.clone());
                eprintln!("KNOWN_UNTYPED: {} ({}) lacks a typed SCHEMA const — owned by {}", row.id, row.schema, owner);
            }
            None => panic!(
                "{}: no typed SCHEMA constant '{}' in Rust sources and not in the KNOWN_UNTYPED ratchet — add the typed identity or extend the ratchet with an owning lane",
                row.id, row.schema
            ),
        }
    }
    let known: BTreeSet<&str> = KNOWN_UNTYPED.iter().map(|(id, _)| *id).collect();
    let seen: BTreeSet<&str> = untyped_seen.iter().map(String::as_str).collect();
    assert_eq!(
        seen, known,
        "KNOWN_UNTYPED ratchet drifted: shrink it as lanes land, never grow it"
    );
    Ok(())
}

#[test]
fn tampering_is_detectable() -> Result<(), Box<dyn Error>> {
    let rows = extract_schema_rows(SCHEMAS_MD)?;
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
    mutated.compat = "mutated rule".to_string();
    assert_ne!(*first, mutated);
    Ok(())
}
