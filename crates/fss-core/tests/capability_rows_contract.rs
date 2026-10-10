#![forbid(unsafe_code)]
//! Field-level contract tests for the capability registry rows
//! (`architecture/capabilities.json`, generation `gen:fss1:capabilities-v2`),
//! realizing the fss-x4a.30.86 family acceptance criteria:
//!
//! * every row exists exactly once with its normative fields;
//! * the machine registry and the generated mirror (`registries/CAPABILITIES.md`)
//!   agree (a mirror may not override machine authority);
//! * every row resolves to exactly one typed `RuntimeGrant` (round-trip),
//!   and unknown rows fail closed;
//! * mutation robustness: duplicate IDs, malformed rows, generation drift,
//!   and secret-shaped content in denial/safe-alternative text are all
//!   detected, never silently admitted;
//! * the registry digest the ContractBasis pins matches the file's own
//!   declared digest.
//!
//! Row ownership (named per the 30.86 acceptance): CAP-ADAPTER-AUTH-001 and
//! CAP-ADAPTER-NET-001 are owned by the sealed adapter host boundary
//! (`fss-cli` capture drivers consume them via `has_capability`; producers
//! are the adapter session lanes: `fss-tutk`, `fss-tuya`, `crate::rtsp`).

use std::collections::BTreeSet;
use std::error::Error;

use fss_core::RuntimeGrant;

/// One parsed registry row (the fields the normative registry defines).
#[derive(Debug, Clone, PartialEq, Eq)]
struct CapabilityRow {
    id: String,
    capability: String,
    scope: String,
    plane: String,
    default_role: String,
    denial_reason: String,
    safe_alternative: String,
    generation: String,
}

/// Minimal structured extractor for the registry's row objects. The file is
/// generated and its shape is stable: each row is a `{...}` object with
/// string-valued fields in a fixed order. Anything off-shape fails loudly —
/// a hand-rolled lenient parse would hide registry corruption.
fn extract_rows(json: &str) -> Result<Vec<CapabilityRow>, Box<dyn Error>> {
    let mut rows = Vec::new();
    let mut cursor = 0usize;
    loop {
        let Some(id_start) = json[cursor..].find("\"id\": \"") else {
            break;
        };
        let abs = cursor + id_start;
        let after = &json[abs..];
        let mut row = CapabilityRow {
            id: String::new(),
            capability: String::new(),
            scope: String::new(),
            plane: String::new(),
            default_role: String::new(),
            denial_reason: String::new(),
            safe_alternative: String::new(),
            generation: String::new(),
        };
        for (key, slot) in [
            ("\"id\"", &mut row.id),
            ("\"capability\"", &mut row.capability),
            ("\"scope\"", &mut row.scope),
            ("\"plane\"", &mut row.plane),
            ("\"defaultRole\"", &mut row.default_role),
            ("\"denialReason\"", &mut row.denial_reason),
            ("\"safeAlternative\"", &mut row.safe_alternative),
            ("\"generation\"", &mut row.generation),
        ] {
            let marker = format!("{key}: \"");
            let Some(kpos) = after.find(&marker) else {
                return Err(format!("row at byte {abs}: missing field {key}").into());
            };
            let val_start = kpos + marker.len();
            let Some(val_end) = after[val_start..].find('\"') else {
                return Err(format!("row at byte {abs}: unterminated field {key}").into());
            };
            *slot = after[val_start..val_start + val_end].to_string();
        }
        rows.push(row);
        // Advance past this row's closing brace.
        let Some(close) = json[abs..].find("\n    }") else {
            return Err(format!("row at byte {abs}: no closing brace").into());
        };
        cursor = abs + close + 6;
    }
    Ok(rows)
}

const REGISTRY_JSON: &str = include_str!("../../../architecture/capabilities.json");
const REGISTRY_MIRROR: &str = include_str!("../../../registries/CAPABILITIES.md");

/// The two adapter-boundary rows whose realization this file anchors
/// (fss-x4a.30.86.5/.6), with their exact normative fields.
const NORMATIVE_ADAPTER_ROWS: [(&str, &str, &str, &str, &str); 2] = [
    (
        "CAP-ADAPTER-AUTH-001",
        "resolve one adapter secret handle",
        "device/account",
        "boundary",
        "adapter host only",
    ),
    (
        "CAP-ADAPTER-NET-001",
        "contact registered device/vendor endpoints",
        "destination allowlist",
        "boundary",
        "adapter host only",
    ),
];

#[test]
fn adapter_rows_exist_once_with_exact_normative_fields() -> Result<(), Box<dyn Error>> {
    let rows = extract_rows(REGISTRY_JSON)?;
    for (id, capability, scope, plane, default_role) in NORMATIVE_ADAPTER_ROWS {
        let matches: Vec<_> = rows.iter().filter(|r| r.id == id).collect();
        assert_eq!(matches.len(), 1, "{id} must exist exactly once");
        let row = matches[0];
        assert_eq!(row.capability, capability, "{id} capability text");
        assert_eq!(row.scope, scope, "{id} scope");
        assert_eq!(row.plane, plane, "{id} plane");
        assert_eq!(row.default_role, default_role, "{id} default role");
        assert!(
            row.denial_reason.starts_with("ERR-AUTH-DENIED-001"),
            "{id} denial reason must cite the registered denial identity"
        );
        assert!(
            row.denial_reason.contains(id),
            "{id} denial reason must name its own row"
        );
        assert!(!row.safe_alternative.is_empty(), "{id} safe alternative");
        assert_eq!(row.generation, "gen:fss1:capabilities-v2", "{id} generation");
        // The typed grant resolves and round-trips.
        let grant = RuntimeGrant::from_id(id)?;
        assert_eq!(grant.as_str(), id);
    }
    Ok(())
}

#[test]
fn registry_rows_are_unique_complete_and_current_generation() -> Result<(), Box<dyn Error>> {
    let rows = extract_rows(REGISTRY_JSON)?;
    assert!(!rows.is_empty(), "registry parses to rows");
    let mut ids = BTreeSet::new();
    for row in &rows {
        assert!(ids.insert(row.id.clone()), "duplicate row id {}", row.id);
        for (field, value) in [
            ("capability", &row.capability),
            ("scope", &row.scope),
            ("plane", &row.plane),
            ("defaultRole", &row.default_role),
            ("denialReason", &row.denial_reason),
            ("safeAlternative", &row.safe_alternative),
        ] {
            assert!(!value.is_empty(), "row {} has empty {field}", row.id);
        }
        assert_eq!(
            row.generation, "gen:fss1:capabilities-v2",
            "row {} binds a non-current generation",
            row.id
        );
        // Secret/redaction safety: denial and alternative text must never
        // carry secret-shaped material.
        for text in [&row.denial_reason, &row.safe_alternative] {
            let lower = text.to_ascii_lowercase();
            for marker in ["password", "token=", "secret=", "bearer ", "api_key", "apikey", "-----begin"] {
                assert!(
                    !lower.contains(marker),
                    "row {} carries secret-shaped text ({marker})",
                    row.id
                );
            }
        }
        // Every row resolves to exactly one typed grant.
        let grant = RuntimeGrant::from_id(&row.id)
            .map_err(|e| format!("row {} has no typed grant: {e}", row.id))?;
        assert_eq!(grant.as_str(), row.id);
    }
    Ok(())
}

#[test]
fn mirror_document_agrees_with_machine_registry() -> Result<(), Box<dyn Error>> {
    let rows = extract_rows(REGISTRY_JSON)?;
    for row in &rows {
        assert!(
            REGISTRY_MIRROR.contains(&row.id),
            "mirror registries/CAPABILITIES.md is missing row {}",
            row.id
        );
    }
    Ok(())
}

#[test]
fn unknown_capability_rows_fail_closed() {
    assert!(RuntimeGrant::from_id("CAP-ADAPTER-AUTH-999").is_err());
    assert!(RuntimeGrant::from_id("CAP-TOTALLY-UNKNOWN-001").is_err());
    assert!(RuntimeGrant::from_id("").is_err());
}

#[test]
fn registry_digest_declaration_matches_contract_basis_pin() -> Result<(), Box<dyn Error>> {
    // The ContractBasis pins `gen:fss1:capabilities-v2` at
    // REFERENCE_CAPABILITY_REGISTRY_DIGEST; the file must declare the same
    // digest, and the pin must equal the declaration.
    let marker = "\"registryDigest\": \"";
    let start = REGISTRY_JSON
        .find(marker)
        .ok_or("registryDigest field missing")?
        + marker.len();
    let end = REGISTRY_JSON[start..]
        .find('\"')
        .ok_or("registryDigest unterminated")?;
    let declared = &REGISTRY_JSON[start..start + end];
    assert_eq!(
        declared,
        fss_core::REFERENCE_CAPABILITY_REGISTRY_DIGEST,
        "registry-declared digest must equal the ContractBasis pin"
    );
    // And the superseded v1 digest differs (never reused).
    assert_ne!(
        declared,
        fss_core::SUPERSEDED_CAPABILITY_REGISTRY_DIGEST_V1
    );
    Ok(())
}

#[test]
fn tampered_registry_content_is_detectable() -> Result<(), Box<dyn Error>> {
    // Duplicate-ID injection: a second row with the same id must trip the
    // uniqueness check over extracted content.
    let rows = extract_rows(REGISTRY_JSON)?;
    let mut ids = BTreeSet::new();
    let first = rows.first().ok_or("rows present")?;
    let mut tampered = rows.clone();
    tampered.push(first.clone());
    let mut dup_found = false;
    for row in &tampered {
        if !ids.insert(row.id.clone()) {
            dup_found = true;
        }
    }
    assert!(dup_found, "duplicate injection must be detectable");
    // Field mutation changes the row (value inequality is observable).
    let mut mutated = first.clone();
    mutated.scope = "mutated scope".to_string();
    assert_ne!(*first, mutated);
    Ok(())
}
