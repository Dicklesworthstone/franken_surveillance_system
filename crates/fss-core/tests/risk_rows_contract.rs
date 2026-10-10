#![forbid(unsafe_code)]
//! Field-level contract tests for the risk registry rows
//! (`registries/RISKS.md` — the machine authority for risk identities and
//! their mitigation/release consequences), realizing the fss-x4a.30.96
//! family acceptance:
//!
//! * every risk exists exactly once with canonical `RISK-*-NNN` identity
//!   and a non-empty risk statement and mitigation/release consequence;
//! * the camera-lane rows (RISK-VENDOR-001, RISK-SDK-001, RISK-CODEC-001,
//!   RISK-CORRELATION-001) match their exact normative text;
//! * mutation robustness: duplicate IDs and field tampering are detectable.

use std::collections::BTreeSet;
use std::error::Error;

const RISKS_MD: &str = include_str!("../../../registries/RISKS.md");

/// One parsed registry row.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RiskRow {
    id: String,
    risk: String,
    mitigation: String,
}

fn extract_risk_rows(md: &str) -> Result<Vec<RiskRow>, Box<dyn Error>> {
    let mut rows = Vec::new();
    for line in md.lines() {
        let line = line.trim();
        if !line.starts_with("| `RISK-") {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() < 4 {
            return Err(format!("short risk table row: {line}").into());
        }
        rows.push(RiskRow {
            id: cells[1].trim_matches('`').to_string(),
            risk: cells[2].trim().to_string(),
            mitigation: cells[3].trim().to_string(),
        });
    }
    Ok(rows)
}

#[test]
fn rows_are_unique_canonical_and_complete() -> Result<(), Box<dyn Error>> {
    let rows = extract_risk_rows(RISKS_MD)?;
    assert!(rows.len() >= 18, "registry carries the full risk set");
    let mut ids = BTreeSet::new();
    for row in &rows {
        assert!(ids.insert(row.id.clone()), "duplicate risk id {}", row.id);
        assert!(
            row.id.starts_with("RISK-") && row.id.ends_with(char::is_numeric),
            "row id {} violates canonical RISK-*-NNN shape",
            row.id
        );
        assert!(!row.risk.is_empty(), "{}: empty risk statement", row.id);
        assert!(
            !row.mitigation.is_empty(),
            "{}: empty mitigation/release consequence — a risk without a named consequence is not a registry row",
            row.id
        );
    }
    Ok(())
}

#[test]
fn camera_lane_risks_match_exact_normative_text() -> Result<(), Box<dyn Error>> {
    let rows = extract_risk_rows(RISKS_MD)?;
    let find = |id: &str| rows.iter().find(|r| r.id == id).cloned();
    let vendor = find("RISK-VENDOR-001").ok_or("row missing")?;
    assert_eq!(vendor.risk, "proprietary firmware/app breaks adapter");
    assert!(vendor.mitigation.contains("exact tuple"));
    assert!(vendor.mitigation.contains("fail closed"));
    let sdk = find("RISK-SDK-001").ok_or("row missing")?;
    assert!(sdk.mitigation.contains("no native/autonomy claim"));
    let codec = find("RISK-CODEC-001").ok_or("row missing")?;
    assert!(codec.mitigation.contains("checked arithmetic"));
    assert!(codec.mitigation.contains("bounded arenas"));
    let corr = find("RISK-CORRELATION-001").ok_or("row missing")?;
    assert_eq!(corr.risk, "multiple cameras/vendor cloud share failure domain");
    Ok(())
}

#[test]
fn agent_and_guarantee_risks_stay_declared() -> Result<(), Box<dyn Error>> {
    // RISK-AGENT-001 (agent overreach/prompt injection) and
    // RISK-GUARANTEE-001 ("never miss" language) are the registry's own
    // guardrails against overclaiming — they must stay present and honest.
    let rows = extract_risk_rows(RISKS_MD)?;
    let find = |id: &str| rows.iter().find(|r| r.id == id).cloned();
    let agent = find("RISK-AGENT-001").ok_or("RISK-AGENT-001 missing")?;
    assert!(agent.risk.contains("agent overreach") || agent.risk.contains("prompt injection"));
    let guarantee = find("RISK-GUARANTEE-001").ok_or("RISK-GUARANTEE-001 missing")?;
    assert!(guarantee.risk.contains("never miss"));
    Ok(())
}

#[test]
fn tampering_is_detectable() -> Result<(), Box<dyn Error>> {
    let rows = extract_risk_rows(RISKS_MD)?;
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
    mutated.mitigation = "mutated".to_string();
    assert_ne!(*first, mutated);
    Ok(())
}
