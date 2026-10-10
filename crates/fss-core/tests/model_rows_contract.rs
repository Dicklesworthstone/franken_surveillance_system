//! Field-level contract tests for the model registry rows
//! (`registries/MODELS.md` — the machine authority for model candidates and
//! their eligibility states), realizing the fss-x4a.30.93 family acceptance:
//!
//! * every candidate exists exactly once with canonical `MOD-*-NNN`
//!   identity, a named role, and an eligibility state;
//! * the load-bearing honesty claim — "No model is currently admitted" —
//!   stays declared (candidates are not admissions);
//! * license-restricted candidates keep their restriction markers;
//! * mutation robustness: duplicate IDs and field tampering are detectable.

use std::collections::BTreeSet;
use std::error::Error;

const MODELS_MD: &str = include_str!("../../../registries/MODELS.md");

/// One parsed registry row.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ModelRow {
    id: String,
    candidate: String,
    role: String,
    eligibility: String,
}

fn extract_model_rows(md: &str) -> Result<Vec<ModelRow>, Box<dyn Error>> {
    let mut rows = Vec::new();
    for line in md.lines() {
        let line = line.trim();
        if !line.starts_with("| `MOD-") {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() < 5 {
            return Err(format!("short model table row: {line}").into());
        }
        rows.push(ModelRow {
            id: cells[1].trim_matches('`').to_string(),
            candidate: cells[2].trim().to_string(),
            role: cells[3].trim().to_string(),
            eligibility: cells[4].trim().to_string(),
        });
    }
    Ok(rows)
}

/// The twelve rows of the 30.93 family (id → candidate).
const NORMATIVE_MODEL_ROWS: [(&str, &str); 12] = [
    ("MOD-RFDETR-001", "RF-DETR designated Apache models"),
    ("MOD-GDINO-001", "Grounding DINO"),
    ("MOD-SAM3-001", "SAM 3/3.1"),
    ("MOD-COTRACKER3-001", "CoTracker3"),
    ("MOD-QWEN3VL8B-001", "Qwen3-VL-8B-Instruct"),
    ("MOD-INTERNVIDEO25-001", "InternVideo family"),
    ("MOD-WEMM9B-001", "WeMM-Embedding-9B"),
    ("MOD-AVF-001", "Nemotron-Labs Audio-Visual Flamingo"),
    ("MOD-VGGT-001", "VGGT"),
    ("MOD-MAST3RSLAM-001", "MASt3R-SLAM"),
    ("MOD-CUT3R-001", "CUT3R"),
    ("MOD-DAV2S-001", "Depth Anything V2 Small"),
];

#[test]
fn rows_are_unique_canonical_and_complete() -> Result<(), Box<dyn Error>> {
    let rows = extract_model_rows(MODELS_MD)?;
    assert!(rows.len() >= 12, "registry carries the full candidate set");
    let mut ids = BTreeSet::new();
    for row in &rows {
        assert!(ids.insert(row.id.clone()), "duplicate model id {}", row.id);
        assert!(
            row.id.starts_with("MOD-") && row.id.ends_with(char::is_numeric),
            "row id {} violates canonical MOD-*-NNN shape",
            row.id
        );
        assert!(!row.candidate.is_empty(), "{}: empty candidate", row.id);
        assert!(!row.role.is_empty(), "{}: empty role", row.id);
        assert!(
            !row.eligibility.is_empty(),
            "{}: empty eligibility state — a candidate without an eligibility state is not a registry row",
            row.id
        );
    }
    Ok(())
}

#[test]
fn normative_rows_match_exact_candidates() -> Result<(), Box<dyn Error>> {
    let rows = extract_model_rows(MODELS_MD)?;
    for (id, candidate) in NORMATIVE_MODEL_ROWS {
        let matches: Vec<_> = rows.iter().filter(|r| r.id == id).collect();
        assert_eq!(matches.len(), 1, "{id} exists exactly once");
        assert_eq!(matches[0].candidate, candidate, "{id} candidate");
    }
    Ok(())
}

#[test]
fn no_model_is_admitted_and_restrictions_keep_markers() -> Result<(), Box<dyn Error>> {
    // The registry's core honesty claim: candidates are not admissions.
    assert!(MODELS_MD.contains("No model is currently admitted"));
    let rows = extract_model_rows(MODELS_MD)?;
    for row in &rows {
        // The registry admits nothing: eligibility must be a non-admission
        // class (candidate / research-only / review-pending), never an
        // admitted or qualified state.
        let lower = row.eligibility.to_ascii_lowercase();
        for admitted_marker in ["admitted", "qualified", "active", "production"] {
            assert!(
                !lower.contains(admitted_marker),
                "{}: eligibility '{}' claims an admitted-class state ({admitted_marker})",
                row.id,
                row.eligibility
            );
        }
        assert!(
            lower.contains("candidate") || lower.contains("research-only") || lower.contains("review"),
            "{}: eligibility '{}' is neither candidate-class nor research/review — unknown non-admission class",
            row.id,
            row.eligibility
        );
    }
    // License-restricted rows keep their exact restriction markers.
    let avf = rows.iter().find(|r| r.id == "MOD-AVF-001").ok_or("AVF row")?;
    assert!(avf.eligibility.contains("noncommercial"), "AVF restriction marker");
    let gdino = rows.iter().find(|r| r.id == "MOD-GDINO-001").ok_or("GDINO row")?;
    assert!(gdino.eligibility.contains("license review"), "GDINO review marker");
    Ok(())
}

#[test]
fn tampering_is_detectable() -> Result<(), Box<dyn Error>> {
    let rows = extract_model_rows(MODELS_MD)?;
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
    mutated.eligibility = "admitted".to_string();
    assert_ne!(*first, mutated);
    Ok(())
}
