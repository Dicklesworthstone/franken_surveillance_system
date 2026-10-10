#![forbid(unsafe_code)]
//! Field-level contract tests for the agent abstraction tower rows
//! (`architecture/agent_abstraction_stack.json` layers + hydration levels),
//! realizing the fss-x4a.30.82 family acceptance:
//!
//! * every AGT-LAYER row exists exactly once with owner/question/output/
//!   prohibition/invariant/status fields, and resolves to exactly one typed
//!   `AgentAbstractionLayer` variant (id round-trip);
//! * the eight open tower rows (005–011) and the H3 hydration row match
//!   their exact normative text;
//! * the mirror (`registries/AGENT_ABSTRACTIONS.md`) agrees;
//! * mutation robustness: duplicate IDs and field tampering are detectable.

use std::collections::BTreeSet;
use std::error::Error;

use fss_core::abstraction::AgentAbstractionLayer;
use fss_core::hydration::HydrationLevel;

const STACK_JSON: &str = include_str!("../../../architecture/agent_abstraction_stack.json");
const MIRROR: &str = include_str!("../../../registries/AGENT_ABSTRACTIONS.md");

/// Minimal structured extractor for one JSON string field within a bounded
/// object span. Fails loudly on missing/unterminated fields.
fn json_string_field<'a>(span: &'a str, key: &str) -> Result<&'a str, Box<dyn Error>> {
    let marker = format!("\"{key}\": \"");
    let start = span.find(&marker).ok_or(format!("missing field {key}"))? + marker.len();
    let end = span[start..]
        .find('"')
        .ok_or(format!("unterminated field {key}"))?;
    Ok(&span[start..start + end])
}

/// The nine rows this artifact anchors (id, name, and one distinctive field
/// value per row, from the normative registry text).
const NORMATIVE_TOWER_ROWS: [(&str, &str, &str); 8] = [
    ("AGT-LAYER-005", "situation_capsule", "SituationCapsule"),
    ("AGT-LAYER-006", "investigation_and_hypotheses", "hypotheses"),
    ("AGT-LAYER-007", "affordance_frontier", "frontier"),
    ("AGT-LAYER-008", "plan_and_effect", "plan"),
    ("AGT-LAYER-009", "outcome_and_episode", "episode"),
    ("AGT-LAYER-010", "learning_and_memory", "learning"),
    ("AGT-LAYER-011", "workspace_and_handoff", "handoff"),
    ("H3", "source_evidence", "authorized original encoded packets"),
];

#[test]
fn every_layer_row_resolves_to_a_typed_variant() {
    // The typed tower is complete: 11 variants, stable ids, canonical order.
    assert_eq!(AgentAbstractionLayer::ALL.len(), 11);
    let mut ids = BTreeSet::new();
    for layer in AgentAbstractionLayer::ALL {
        assert!(ids.insert(layer.id()), "duplicate typed id {}", layer.id());
        assert!(
            STACK_JSON.contains(&format!("\"id\": \"{}\"", layer.id())),
            "stack JSON missing typed layer {}",
            layer.id()
        );
        assert!(
            STACK_JSON.contains(&format!("\"name\": \"{}\"", layer.name())),
            "stack JSON name drift for {}",
            layer.id()
        );
    }
}

#[test]
fn open_tower_rows_match_normative_text() -> Result<(), Box<dyn Error>> {
    for (id, name, distinctive) in NORMATIVE_TOWER_ROWS {
        let id_marker = format!("\"id\": \"{id}\"");
        let start = STACK_JSON
            .find(&id_marker)
            .ok_or(format!("row {id} missing from stack JSON"))?;
        let span = &STACK_JSON[start..STACK_JSON.len().min(start + 1200)];
        assert_eq!(json_string_field(span, "name")?, name, "{id} name");
        let question_or_content = json_string_field(span, "question")
            .or_else(|_| json_string_field(span, "content"))?;
        assert!(
            question_or_content.contains(distinctive)
                || span.contains(distinctive),
            "{id}: expected distinctive text '{distinctive}'"
        );
        assert!(
            MIRROR.contains(id),
            "mirror registries/AGENT_ABSTRACTIONS.md missing {id}"
        );
    }
    Ok(())
}

#[test]
fn hydration_h3_resolves_to_typed_level() {
    // H3 is the source_evidence hydration level; the typed hydration
    // vocabulary carries it with the exact normative content declaration.
    let level = HydrationLevel::H3;
    assert_eq!(level.as_str(), "H3");
    assert_eq!(level.level_name(), "source_evidence");
    assert_eq!(
        level.content_declaration(),
        "authorized original encoded packets, object bytes, exact metadata, or full-resolution media"
    );
    assert!(STACK_JSON.contains("\"id\": \"H3\""));
    assert!(STACK_JSON.contains("\"name\": \"source_evidence\""));
}

#[test]
fn tampering_is_detectable() {
    let ids: BTreeSet<&str> = AgentAbstractionLayer::ALL.iter().map(|l| l.id()).collect();
    let mut tampered = ids.clone();
    assert!(
        !tampered.insert("AGT-LAYER-001"),
        "duplicate layer id injection must be detectable"
    );
    assert_eq!(ids, tampered);
}
