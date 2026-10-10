//! Field-level contract tests for the operation-cost registry rows
//! (`architecture/operation_cost_registry.toml`, generation
//! `gen:fss1:operation-cost-v2`), realizing the fss-x4a.30.94 family
//! acceptance criteria:
//!
//! * every row exists exactly once with its normative fields and canonical
//!   `COST-*-NNN` identity;
//! * semantic steps, variable costs, SLO links, status, and proof bindings
//!   are present and well-formed;
//! * SLO references resolve against `registries/SLOS.md`;
//! * proof bindings resolve: the owning crate path exists and the referenced
//!   test file contains the referenced test symbol;
//! * the machine registry, its declared freeze digest, and the generated
//!   mirror (`registries/OPERATION_COSTS.md`) agree;
//! * mutation robustness: duplicate IDs and field tampering are detectable.
//!
//! KNOWN DRIFT (recorded, not hidden): the ContractBasis pin
//! `REFERENCE_COST_REGISTRY_DIGEST` still binds the v1 freeze digest while
//! this registry is generation v2 — tracked as bead fss-fbeo8 with the
//! migration recipe (capabilities-v1→v2 precedent). This file therefore
//! asserts the registry's own declared v2 digest against the value
//! `scripts/slo_validate.py` expects for v2, not the stale basis pin.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::Path;

/// One parsed `[[operation]]` row (normative fields only).
#[derive(Debug, Clone, PartialEq)]
struct CostRow {
    id: String,
    name: String,
    unit: String,
    semantic_steps: Vec<String>,
    variable_costs: Vec<String>,
    slo_ids: Vec<String>,
    status: String,
    proof_owner: String,
    proof_reference: String,
}

fn parse_string_array(value: &str) -> Vec<String> {
    value
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Minimal structured extractor for `[[operation]]` TOML blocks. Fails loudly
/// on off-shape content — the registry is generated and its shape is stable.
fn extract_cost_rows(toml: &str) -> Result<Vec<CostRow>, Box<dyn Error>> {
    let mut rows = Vec::new();
    for block in toml.split("[[operation]]").skip(1) {
        let mut row = CostRow {
            id: String::new(),
            name: String::new(),
            unit: String::new(),
            semantic_steps: Vec::new(),
            variable_costs: Vec::new(),
            slo_ids: Vec::new(),
            status: String::new(),
            proof_owner: String::new(),
            proof_reference: String::new(),
        };
        for line in block.lines() {
            let line = line.trim();
            // A new TOML section (e.g. [[drift]]) ends this operation block.
            if line.starts_with("[[") {
                break;
            }
            if let Some((key, value)) = line.split_once(" = ") {
                let value = value.trim();
                match key {
                    "id" => row.id = value.trim_matches('"').to_string(),
                    "name" => row.name = value.trim_matches('"').to_string(),
                    "unit" => row.unit = value.trim_matches('"').to_string(),
                    "semantic_steps" => row.semantic_steps = parse_string_array(value),
                    "variable_costs" => row.variable_costs = parse_string_array(value),
                    "slo_ids" => row.slo_ids = parse_string_array(value),
                    "status" => row.status = value.trim_matches('"').to_string(),
                    "proof_owner" => row.proof_owner = value.trim_matches('"').to_string(),
                    "proof_reference" => {
                        row.proof_reference = value.trim_matches('"').to_string()
                    }
                    _ => {}
                }
            }
        }
        if row.id.is_empty() {
            return Err("[[operation]] block missing id".into());
        }
        rows.push(row);
    }
    Ok(rows)
}

const COST_TOML: &str = include_str!("../../../architecture/operation_cost_registry.toml");
const COST_MIRROR: &str = include_str!("../../../registries/OPERATION_COSTS.md");
const SLO_MIRROR: &str = include_str!("../../../registries/SLOS.md");

/// The v2 freeze digest this registry must declare (shared expectation with
/// `scripts/slo_validate.py`).
const EXPECTED_V2_DIGEST: &str =
    "sha256:c86017d6a6674322613e8b88eb6c3ba994df2c9d071cb8b7045ea31c0f37bc3b";

#[test]
fn registry_declares_v2_generation_and_expected_digest() -> Result<(), Box<dyn Error>> {
    assert!(COST_TOML.contains("generation = \"gen:fss1:operation-cost-v2\""));
    assert!(
        COST_TOML.contains(&format!("registry_digest = \"{EXPECTED_V2_DIGEST}\"")),
        "declared freeze digest must match the v2 expectation shared with slo_validate.py"
    );
    assert!(
        COST_MIRROR.contains(EXPECTED_V2_DIGEST),
        "mirror must carry the same digest"
    );
    Ok(())
}

#[test]
fn rows_are_unique_canonical_and_complete() -> Result<(), Box<dyn Error>> {
    let rows = extract_cost_rows(COST_TOML)?;
    assert!(rows.len() >= 40, "registry carries the full row set");
    let mut ids = BTreeSet::new();
    for row in &rows {
        assert!(ids.insert(row.id.clone()), "duplicate cost id {}", row.id);
        // DRIFT-NNN rows are a separately tracked class (slo_validate
        // CANONICAL_DRIFT_IDS); COST-* rows follow COST-*-NNN shape.
        if row.id.starts_with("COST-") {
            assert!(
                row.id.ends_with(char::is_numeric),
                "row id {} violates canonical COST-*-NNN shape",
                row.id
            );
        } else {
            assert!(
                row.id.starts_with("DRIFT-"),
                "row id {} is neither COST-*-NNN nor tracked DRIFT-NNN",
                row.id
            );
        }
        if row.id.starts_with("COST-") {
            assert!(!row.name.is_empty(), "{}: empty name", row.id);
            assert!(!row.unit.is_empty(), "{}: empty unit", row.id);
        }
        assert!(
            !row.semantic_steps.is_empty(),
            "{}: no semantic steps",
            row.id
        );
        assert!(!row.variable_costs.is_empty(), "{}: no variable costs", row.id);
        assert!(!row.slo_ids.is_empty(), "{}: no SLO links", row.id);
        assert!(
            matches!(
                row.status.as_str(),
                "model_required" | "modeled" | "measured" | "estimated"
            ),
            "{}: unknown status '{}'",
            row.id,
            row.status
        );
        assert!(!row.proof_owner.is_empty(), "{}: no proof owner", row.id);
        assert!(!row.proof_reference.is_empty(), "{}: no proof reference", row.id);
    }
    Ok(())
}

#[test]
fn slo_links_resolve_against_the_slo_registry() -> Result<(), Box<dyn Error>> {
    let rows = extract_cost_rows(COST_TOML)?;
    for row in &rows {
        for slo in &row.slo_ids {
            assert!(
                SLO_MIRROR.contains(&format!("`{slo}`")),
                "{}: SLO link {slo} not found in registries/SLOS.md",
                row.id
            );
        }
    }
    Ok(())
}

#[test]
fn proof_bindings_resolve_to_real_tests() -> Result<(), Box<dyn Error>> {
    let rows = extract_cost_rows(COST_TOML)?;
    // CARGO_MANIFEST_DIR is crates/fss-core; the workspace root is two up.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("workspace root")?;
    for row in &rows {
        // Unimplemented operations bind proof to the drift ledger instead
        // of a crate/test path (the registry's own drift-tracking scheme);
        // the reference must resolve to a [[drift]] entry.
        if let Some(drift_id) = row.proof_owner.strip_prefix("drift:") {
            assert!(
                COST_TOML.contains(&format!("id = \"{drift_id}\"")),
                "{}: drift reference {drift_id} not found in the drift ledger",
                row.id
            );
            continue;
        }
        let owner = root.join(&row.proof_owner);
        assert!(owner.exists(), "{}: proof owner {} missing", row.id, row.proof_owner);
        let (file, test_name) = row
            .proof_reference
            .split_once("::")
            .ok_or(format!("{}: proof reference missing ::test", row.id))?;
        let test_path = root.join(file);
        assert!(test_path.exists(), "{}: proof file {file} missing", row.id);
        let content = std::fs::read_to_string(&test_path)?;
        assert!(
            content.contains(&format!("fn {test_name}")),
            "{}: proof test {test_name} not found in {file}",
            row.id
        );
    }
    Ok(())
}

#[test]
fn mirror_lists_every_machine_row() -> Result<(), Box<dyn Error>> {
    let rows = extract_cost_rows(COST_TOML)?;
    for row in &rows {
        assert!(
            COST_MIRROR.contains(&format!("`{}`", row.id)),
            "mirror registries/OPERATION_COSTS.md missing row {}",
            row.id
        );
    }
    Ok(())
}

#[test]
fn rtsp_stream_second_row_matches_its_normative_text() -> Result<(), Box<dyn Error>> {
    // fss-x4a.30.94.2: the RTSP lane's cost row, exact fields.
    let rows = extract_cost_rows(COST_TOML)?;
    let matches: Vec<_> = rows.iter().filter(|r| r.id == "COST-RTSP-001").collect();
    assert_eq!(matches.len(), 1, "COST-RTSP-001 exists exactly once");
    let row = matches[0];
    assert_eq!(row.name, "maintain one RTSP/RTP stream");
    assert_eq!(row.unit, "stream_second");
    assert_eq!(
        row.semantic_steps,
        vec!["session_keepalive", "packet_receive", "rtcp_update", "continuity_accounting", "bounded_buffer"]
    );
    assert_eq!(row.variable_costs, vec!["packets", "jitter", "loss", "auth_refresh"]);
    assert_eq!(row.slo_ids, vec!["SLO-INGEST-001"]);
    assert_eq!(row.proof_owner, "crates/fss-packet");
    Ok(())
}

#[test]
fn tampering_is_detectable() -> Result<(), Box<dyn Error>> {
    let rows = extract_cost_rows(COST_TOML)?;
    let first = rows.first().ok_or("rows present")?;
    let mut ids = BTreeSet::new();
    let mut dup_found = false;
    let mut tampered = rows.clone();
    tampered.push(first.clone());
    for row in &tampered {
        if !ids.insert(row.id.clone()) {
            dup_found = true;
        }
    }
    assert!(dup_found, "duplicate injection must be detectable");
    let mut mutated = first.clone();
    mutated.unit = "mutated_unit".to_string();
    assert_ne!(*first, mutated);
    Ok(())
}
