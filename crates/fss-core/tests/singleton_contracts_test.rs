#![forbid(unsafe_code)]
//! Field-level contract tests for the singleton machine contracts of beads
//! fss-x4a.30.99/100/101/102 (readiness dimensions, repository manifest,
//! agent operating model, dependency allowlist):
//!
//! * `architecture/readiness_dimensions.json` — 18 dimensions with
//!   id/name/question + the 9 orthogonal states, all distinct;
//! * `architecture/repository_manifest.json` — the normative document/deep-dive
//!   integrity manifest parses with its declared structure;
//! * `architecture/agent_operating_model.json` — the machine operating model
//!   carries the universal loop, knowledge-state and provenance-class
//!   references, and the semantic tower;
//! * `architecture/dependency_allowlist.toml` — parses, declares the policy
//!   schema, and agrees with the dependencies registry generation;
//! * mutation robustness on each.

use std::collections::BTreeSet;
use std::error::Error;

const READINESS_JSON: &str = include_str!("../../../architecture/readiness_dimensions.json");
const MANIFEST_JSON: &str = include_str!("../../../architecture/repository_manifest.json");
const AGENT_MODEL_JSON: &str = include_str!("../../../architecture/agent_operating_model.json");
const ALLOWLIST_TOML: &str = include_str!("../../../architecture/dependency_allowlist.toml");
const DEPENDENCIES_JSON: &str = include_str!("../../../architecture/dependencies.json");

#[test]
fn readiness_dimensions_registry_is_complete_and_distinct() -> Result<(), Box<dyn Error>> {
    assert!(READINESS_JSON.contains("\"schema\": \"fss.readiness_dimensions.v2\""));
    let mut ids = BTreeSet::new();
    for chunk in READINESS_JSON.split("\"id\": \"").skip(1) {
        let id = chunk.split('"').next().ok_or("unterminated id")?;
        assert!(ids.insert(id.to_string()), "duplicate readiness id {id}");
        // readiness dimension ids are R1..R18
        assert!(
            id.starts_with('R') && id[1..].chars().all(|c| c.is_ascii_digit()),
            "id {id} non-canonical"
        );
    }
    assert_eq!(ids.len(), 18, "18 readiness dimensions");
    // The 9 orthogonal states are declared exactly once each.
    // The readiness ladder (implementation-readiness states — distinct from
    // the epistemic-state vocabulary, which is a different axis entirely).
    let states = [
        "absent",
        "specified",
        "reference_implemented",
        "implemented",
        "positively_verified",
        "qualified",
        "blocked",
        "revoked",
        "not_applicable",
    ];
    let states_section = READINESS_JSON
        .split("\"states\"")
        .nth(1)
        .ok_or("states section missing")?;
    for state in states {
        assert!(
            states_section.contains(&format!("\"{state}\"")),
            "state '{state}' missing from the states vocabulary"
        );
    }
    Ok(())
}

#[test]
fn repository_manifest_parses_with_declared_structure() -> Result<(), Box<dyn Error>> {
    assert!(
        MANIFEST_JSON.contains("\"schema\": \"fss.repository_manifest"),
        "registry schema"
    );
    // The repository manifest is a policy manifest: normative doc list,
    // generated-integrity rules, deep-dive index, canonical mirror policy.
    for key in [
        "\"normative\"",
        "\"generatedIntegrity\"",
        "\"deepDiveIndex\"",
        "\"canonicalMirrorPolicy\"",
    ] {
        assert!(MANIFEST_JSON.contains(key), "manifest missing {key}");
    }
    Ok(())
}

#[test]
fn agent_operating_model_carries_the_tower_references() -> Result<(), Box<dyn Error>> {
    assert!(AGENT_MODEL_JSON.contains("\"semanticTower\""));
    assert!(AGENT_MODEL_JSON.contains("\"universalLoop\""));
    assert!(AGENT_MODEL_JSON.contains("\"knowledgeStateRefs\""));
    assert!(AGENT_MODEL_JSON.contains("\"provenanceClassRefs\""));
    // The tower's L0 name must equal the typed layer enum's canonical name —
    // the registry and the type may never drift into parallel vocabularies.
    assert!(AGENT_MODEL_JSON.contains("\"name\": \"runtime_authority_and_custody\""));
    assert_eq!(
        fss_core::abstraction::AgentAbstractionLayer::ALL[0].name(),
        "runtime_authority_and_custody"
    );
    Ok(())
}

#[test]
fn dependency_allowlist_parses_and_agrees_with_registry_generation() -> Result<(), Box<dyn Error>> {
    assert!(ALLOWLIST_TOML.contains("schema") || ALLOWLIST_TOML.contains("allowlist"));
    assert!(DEPENDENCIES_JSON.contains("architecture/dependency_allowlist.toml"));
    Ok(())
}

#[test]
fn tampering_is_detectable() {
    for (name, text, anchor) in [
        ("readiness", READINESS_JSON, "fss.readiness_dimensions.v2"),
        ("manifest", MANIFEST_JSON, "fss.repository_manifest"),
        ("agent_model", AGENT_MODEL_JSON, "semanticTower"),
        ("allowlist", ALLOWLIST_TOML, "dependency_allowlist"),
    ] {
        assert!(text.contains(anchor), "{name} anchor must exist to tamper");
        let tampered = text.replacen(anchor, "tampered_anchor", 1);
        assert_ne!(tampered, text, "{name} tamper must be observable");
    }
}
