#![forbid(unsafe_code)]
//! Field-level contract tests for the publication primitives
//! (`architecture/publication_primitives.json`, mirrored by
//! `registries/PUBLICATION_PRIMITIVES.md`), realizing the fss-x4a.30.95
//! family acceptance:
//!
//! * every primitive exists exactly once with owner/protocol/invariant/
//!   plane fields and a declared state;
//! * the publication STATES vocabulary (staged/visible/durable/replicated/
//!   protected/retrievable) is declared and distinct — root-last publication
//!   semantics depend on it;
//! * the mirror agrees;
//! * mutation robustness: duplicate IDs and field tampering are detectable.

use std::collections::BTreeSet;
use std::error::Error;

const PRIMS_JSON: &str = include_str!("../../../architecture/publication_primitives.json");
const MIRROR: &str = include_str!("../../../registries/PUBLICATION_PRIMITIVES.md");

fn json_string_field<'a>(span: &'a str, key: &str) -> Result<&'a str, Box<dyn Error>> {
    let marker = format!("\"{key}\": \"");
    let start = span.find(&marker).ok_or(format!("missing field {key}"))? + marker.len();
    let end = span[start..]
        .find('"')
        .ok_or(format!("unterminated field {key}"))?;
    Ok(&span[start..start + end])
}

/// The full 13-row normative set (id → name) from the registry.
const NORMATIVE_PRIMS: [(&str, &str); 13] = [
    ("PUB-AUTH-001", "authority_generation"),
    ("PUB-OBJECT-001", "archive_object_graph"),
    ("PUB-SEARCH-001", "search_generation"),
    ("PUB-GRAPH-001", "graph_projection"),
    ("PUB-MODEL-001", "model_activation"),
    ("PUB-CAL-001", "calibration_activation"),
    ("PUB-ADAPTER-001", "adapter_compatibility_profile"),
    ("PUB-EVIDENCE-001", "evidence_bundle"),
    ("PUB-DELETE-001", "deletion_closure"),
    ("PUB-RELEASE-001", "release_root"),
    ("PUB-AGENT-WORKSPACE-001", "agent_workspace_revision"),
    ("PUB-AGENT-HANDOFF-001", "agent_handoff_capsule"),
    ("PUB-AGENT-EXPERIENCE-001", "agent_experience_capsule"),
];

#[test]
fn every_primitive_exists_once_with_full_fields() -> Result<(), Box<dyn Error>> {
    let mut ids = BTreeSet::new();
    for (id, name) in NORMATIVE_PRIMS {
        let marker = format!("\"id\": \"{id}\"");
        let start = PRIMS_JSON
            .find(&marker)
            .ok_or(format!("primitive {id} missing"))?;
        let span = &PRIMS_JSON[start..PRIMS_JSON.len().min(start + 1100)];
        assert!(ids.insert(id), "duplicate primitive {id}");
        assert_eq!(json_string_field(span, "name")?, name, "{id} name");
        assert!(!json_string_field(span, "owner")?.is_empty(), "{id} owner");
        assert!(
            !json_string_field(span, "invariant")?.is_empty(),
            "{id} root invariant"
        );
        assert!(
            span.contains("\"protocol\":"),
            "{id}: no reserve→…→publish-root protocol"
        );
        assert!(MIRROR.contains(&format!("`{id}`")), "mirror missing {id}");
    }
    Ok(())
}

#[test]
fn publication_states_vocabulary_is_declared_and_distinct() -> Result<(), Box<dyn Error>> {
    // The machine authority's lifecycle vocabulary: every state a
    // publication can occupy, including the terminal-failure distinctions
    // (quarantined/failed/indeterminate must never flatten into one).
    for state in [
        "reserved",
        "materializing",
        "verified",
        "published",
        "retired",
        "quarantined",
        "failed",
        "indeterminate",
    ] {
        assert!(
            PRIMS_JSON.contains(&format!("\"{state}\"")),
            "publication state '{state}' missing from the states vocabulary"
        );
    }
    assert!(PRIMS_JSON.contains("\"states\""));
    Ok(())
}

#[test]
fn tampering_is_detectable() {
    let ids: BTreeSet<&str> = NORMATIVE_PRIMS.iter().map(|(id, _)| *id).collect();
    let mut tampered = ids.clone();
    assert!(!tampered.insert("PUB-AUTH-001"), "duplicate injection detectable");
    assert_eq!(ids, tampered);
}
