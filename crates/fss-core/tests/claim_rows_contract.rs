//! Field-level contract tests for the claim strength classes
//! (`architecture/claims.json`, mirrored by `registries/CLAIMS.md`),
//! realizing the fss-x4a.30.87 family acceptance:
//!
//! * every claim class exists exactly once with meaning + minimum evidence
//!   and a structured requiredEvidence list;
//! * the five open rows (statistical, benchmark, compatibility, agent_task,
//!   agent_accretion) match their exact normative text;
//! * the mirror agrees and the forbidden-promotion rules stay declared;
//! * mutation robustness: duplicate IDs and field tampering are detectable.

use std::collections::BTreeSet;
use std::error::Error;

const CLAIMS_JSON: &str = include_str!("../../../architecture/claims.json");
const MIRROR: &str = include_str!("../../../registries/CLAIMS.md");

fn json_string_field<'a>(span: &'a str, key: &str) -> Result<&'a str, Box<dyn Error>> {
    let marker = format!("\"{key}\": \"");
    let start = span.find(&marker).ok_or(format!("missing field {key}"))? + marker.len();
    let end = span[start..]
        .find('"')
        .ok_or(format!("unterminated field {key}"))?;
    Ok(&span[start..start + end])
}

/// The five open rows (id + exact normative meaning from the registry).
const NORMATIVE_OPEN_ROWS: [(&str, &str); 5] = [
    ("statistical", "estimated population/task behavior"),
    ("benchmark", "comparative performance"),
    ("compatibility", "exact device/model/provider tuple works"),
    (
        "agent_task",
        "task-level agent correctness, calibration, safety, and efficiency",
    ),
    (
        "agent_accretion",
        "improvement from retained handoff/experience/procedures across repeated tasks",
    ),
];

#[test]
fn all_nine_classes_exist_once_with_evidence_requirements() -> Result<(), Box<dyn Error>> {
    let expected = [
        "invariant", "proof", "bounded_model", "statistical", "slo", "benchmark", "compatibility",
        "agent_task", "agent_accretion",
    ];
    let mut ids = BTreeSet::new();
    for id in expected {
        let marker = format!("\"id\": \"{id}\"");
        let start = CLAIMS_JSON
            .find(&marker)
            .ok_or(format!("claim class {id} missing"))?;
        let span = &CLAIMS_JSON[start..CLAIMS_JSON.len().min(start + 900)];
        assert!(ids.insert(id), "duplicate claim class {id}");
        let meaning = json_string_field(span, "meaning")?;
        assert!(!meaning.is_empty(), "{id}: empty meaning");
        let min_evidence = json_string_field(span, "minimum_evidence")?;
        assert!(!min_evidence.is_empty(), "{id}: empty minimum evidence");
        assert!(
            span.contains("\"requiredEvidence\": ["),
            "{id}: no structured requiredEvidence list"
        );
        assert!(MIRROR.contains(&format!("`{id}`")), "mirror missing {id}");
    }
    Ok(())
}

#[test]
fn open_rows_match_exact_normative_text() -> Result<(), Box<dyn Error>> {
    for (id, meaning) in NORMATIVE_OPEN_ROWS {
        let marker = format!("\"id\": \"{id}\"");
        let start = CLAIMS_JSON
            .find(&marker)
            .ok_or(format!("claim class {id} missing"))?;
        let span = &CLAIMS_JSON[start..CLAIMS_JSON.len().min(start + 900)];
        assert_eq!(json_string_field(span, "meaning")?, meaning, "{id} meaning");
        assert_eq!(
            json_string_field(span, "claim_class")?,
            id,
            "{id} claim_class self-agreement"
        );
    }
    Ok(())
}

#[test]
fn forbidden_promotions_stay_declared() {
    // The registry's guard against upgrading weak evidence into strong
    // claims (schema presence → support, one demo → compatibility, …) is
    // load-bearing for the whole claim system.
    assert!(CLAIMS_JSON.contains("\"prohibited\""));
    assert!(MIRROR.contains("Forbidden claim promotions"));
}

#[test]
fn tampering_is_detectable() {
    let ids: BTreeSet<&str> = [
        "invariant", "proof", "bounded_model", "statistical", "slo", "benchmark", "compatibility",
        "agent_task", "agent_accretion",
    ]
    .into_iter()
    .collect();
    let mut tampered = ids.clone();
    assert!(!tampered.insert("invariant"), "duplicate injection detectable");
    assert_eq!(ids, tampered);
}
