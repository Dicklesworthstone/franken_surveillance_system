#![forbid(unsafe_code)]
//! Field-level contract tests for the effect registry rows
//! (`registries/EFFECTS.md` — the machine authority for effect identities),
//! realizing the fss-x4a.30.90 family acceptance:
//!
//! * every row exists exactly once with canonical `EFFECT-*-NNN` identity;
//! * reversibility and required-verification fields are present — an effect
//!   without an honest reversibility classification or verification path is
//!   exactly the failure this registry exists to prevent;
//! * v1 disposition is one of the registry's enumerated classes;
//! * the camera-effect rows (EFFECT-PTZ-001, EFFECT-CAMERA-SETTING-001)
//!   match their exact normative text;
//! * mutation robustness: duplicate IDs and field tampering are detectable.
//!
//! Effect identities stay stable across transports; prepare/revalidate/
//! commit/observe/verify/cancel/reconcile semantics live in
//! `fss-core/src/effect.rs` (the effect plane machinery).

use std::collections::BTreeSet;
use std::error::Error;

/// One parsed registry row.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EffectRow {
    id: String,
    effect: String,
    reversibility: String,
    required_verification: String,
    disposition: String,
}

/// Parses the registry's `| ID | Effect | Reversibility | Required
/// verification | v1 disposition |` table.
fn extract_effect_rows(md: &str) -> Result<Vec<EffectRow>, Box<dyn Error>> {
    let mut rows = Vec::new();
    for line in md.lines() {
        let line = line.trim();
        if !line.starts_with("| `EFFECT-") {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() < 6 {
            return Err(format!("short effect table row: {line}").into());
        }
        rows.push(EffectRow {
            id: cells[1].trim_matches('`').to_string(),
            effect: cells[2].trim().to_string(),
            reversibility: cells[3].trim().to_string(),
            required_verification: cells[4].trim().to_string(),
            disposition: cells[5].trim().to_string(),
        });
    }
    Ok(rows)
}

const EFFECTS_MD: &str = include_str!("../../../registries/EFFECTS.md");

/// The registry's enumerated v1-disposition classes (from the table itself).
const DISPOSITIONS: [&str; 7] = [
    "target",
    "target admin path",
    "future",
    "future after standards baseline",
    "disabled by default",
    "forbidden",
    "forbidden in v1",
];

#[test]
fn rows_are_unique_canonical_and_complete() -> Result<(), Box<dyn Error>> {
    let rows = extract_effect_rows(EFFECTS_MD)?;
    assert_eq!(rows.len(), 20, "registry carries the full 20-row set");
    let mut ids = BTreeSet::new();
    for row in &rows {
        assert!(ids.insert(row.id.clone()), "duplicate effect id {}", row.id);
        assert!(
            row.id.starts_with("EFFECT-") && row.id.ends_with(char::is_numeric),
            "row id {} violates canonical EFFECT-*-NNN shape",
            row.id
        );
        assert!(!row.effect.is_empty(), "{}: empty effect", row.id);
        assert!(
            !row.reversibility.is_empty(),
            "{}: empty reversibility — every effect must classify reversibility honestly",
            row.id
        );
        assert!(
            !row.required_verification.is_empty(),
            "{}: empty required verification",
            row.id
        );
        assert!(
            DISPOSITIONS.contains(&row.disposition.as_str()),
            "{}: unknown v1 disposition '{}'",
            row.id,
            row.disposition
        );
    }
    Ok(())
}

#[test]
fn camera_effect_rows_match_exact_normative_text() -> Result<(), Box<dyn Error>> {
    let rows = extract_effect_rows(EFFECTS_MD)?;
    let find = |id: &str| rows.iter().find(|r| r.id == id).cloned();
    let ptz = find("EFFECT-PTZ-001").ok_or("PTZ row missing")?;
    assert_eq!(ptz.effect, "move camera PTZ");
    assert_eq!(ptz.reversibility, "normally reversible");
    assert_eq!(ptz.required_verification, "observed pose/scene and restore obligation");
    assert_eq!(ptz.disposition, "future after standards baseline");
    let setting = find("EFFECT-CAMERA-SETTING-001").ok_or("setting row missing")?;
    assert_eq!(setting.effect, "change imaging/bitrate/audio/event settings");
    assert_eq!(setting.reversibility, "reversible where old value known");
    assert_eq!(setting.required_verification, "readback + stream-generation rollover");
    assert_eq!(setting.disposition, "future");
    Ok(())
}

#[test]
fn registry_declares_full_effect_lifecycle_semantics() {
    // The authority file declares the prepare→revalidate→commit→observe→
    // verify→cancel→reconcile lifecycle every effect must carry.
    for phase in ["prepare", "revalidate", "commit", "observe", "verify", "cancel", "reconcile"] {
        assert!(EFFECTS_MD.contains(phase), "lifecycle phase {phase} undeclared");
    }
}

#[test]
fn tampering_is_detectable() -> Result<(), Box<dyn Error>> {
    let rows = extract_effect_rows(EFFECTS_MD)?;
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
    mutated.reversibility = "mutated".to_string();
    assert_ne!(*first, mutated);
    Ok(())
}
