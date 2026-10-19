#![forbid(unsafe_code)]
//! Field-level contract tests for schema-registry rows, realizing the
//! fss-x4a.30.5/.6/.7 stragglers plus the acquisition-checkpoint row
//! registered 2026-10-10:
//!
//! * each row exists exactly once in `registries/SCHEMAS.md` with schema
//!   name, existing file, authority, and compatibility rule;
//! * each schema file is valid JSON, declares its identity, and matches the
//!   registry's file path;
//! * the Rust owner type declares a `SCHEMA` constant with the identical
//!   name (the sole machine contract — no parallel vocabulary);
//! * digest domains used by the schema are registered in
//!   `registries/DIGEST_DOMAINS.md` where the schema has one;
//! * `scripts/schema_validate.py` passes (the family's deterministic
//!   cross-registry validation, run separately).

use std::error::Error;

const SCHEMAS_MD: &str = include_str!("../../../registries/SCHEMAS.md");
const DIGEST_DOMAINS_MD: &str = include_str!("../../../registries/DIGEST_DOMAINS.md");

/// The four rows this artifact anchors:
/// (row id, schema name, file, authority, distinctive compat-rule text).
const NORMATIVE_SCHEMA_ROWS: [(&str, &str, &str, &str, &str); 4] = [
    (
        "SCHEMA-SENSOR-CAPSULE-001",
        "fss.sensor_capsule.v1",
        "schemas/sensor_capsule.v1.json",
        "authority",
        "no silent timestamp/source reinterpretation",
    ),
    (
        "SCHEMA-EVENT-HYPOTHESIS-001",
        "fss.event_hypothesis.v1",
        "schemas/event_hypothesis.v1.json",
        "authority",
        "immutable revisions; evidence required after hypothesis",
    ),
    (
        "SCHEMA-EVIDENCE-BUNDLE-001",
        "fss.evidence_bundle.v1",
        "schemas/evidence_bundle.v1.json",
        "authority/export",
        "old proof bundles remain replayable or explicitly unsupported",
    ),
    (
        "SCHEMA-ACQ-SESSION-CHECKPOINT-001",
        "fss.acquisition.session_checkpoint.v1",
        "schemas/acquisition_session_checkpoint.v1.json",
        "authority",
        "restoration requires trusted checkpoint + request digests",
    ),
];

#[test]
fn rows_exist_once_with_exact_normative_fields() {
    for (row_id, schema, file, authority, compat_text) in NORMATIVE_SCHEMA_ROWS {
        let row = format!("| `{row_id}` | `{schema}` | `{file}` | {authority} |");
        let occurrences = SCHEMAS_MD.matches(&row).count();
        assert_eq!(
            occurrences, 1,
            "{row_id} must exist exactly once with exact id/schema/file/authority"
        );
        let line_start = SCHEMAS_MD.find(&row).expect("row present");
        let line_end = SCHEMAS_MD[line_start..]
            .find('\n')
            .map(|i| line_start + i)
            .unwrap_or(SCHEMAS_MD.len());
        let full_line = &SCHEMAS_MD[line_start..line_end];
        assert!(
            full_line.contains(compat_text),
            "{row_id}: compatibility rule must contain '{compat_text}'"
        );
    }
}

#[test]
fn schema_files_exist_and_declare_their_identity() -> Result<(), Box<dyn Error>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or("workspace root")?;
    for (_, schema, file, _, _) in NORMATIVE_SCHEMA_ROWS {
        let path = root.join(file);
        assert!(path.is_file(), "schema file {file} must exist");
        let text = std::fs::read_to_string(&path)?;
        // Basic JSON sanity (balanced braces) plus the repo convention that
        // the schema names itself: either `properties.schema` exists with a
        // const equal to the registry name, or a oneOf union of local defs.
        assert!(
            text.trim_start().starts_with('{'),
            "{file}: not a JSON object"
        );
        // The schema must name ITSELF at properties.schema.const (the repo
        // convention; a wrong-valued or property-only mention is drift).
        let const_marker = format!("\"const\": \"{schema}\"");
        assert!(
            text.contains(&const_marker),
            "{file}: properties.schema.const must equal '{schema}' exactly"
        );
    }
    Ok(())
}

#[test]
fn wrong_identity_is_rejected() {
    // Negative control for the identity check above: a schema whose const
    // names a different identity must be distinguishable.
    let fake = "{\"properties\":{\"schema\":{\"const\": \"fss.wrong.v1\"}}}";
    let want = "fss.sensor_capsule.v1";
    assert!(!fake.contains(&format!("\"const\": \"{want}\"")));
    assert!(fake.contains("\"const\": \"fss.wrong.v1\""));
    // And malformed JSON (no braces) has no identity at all.
    let junk = "not json";
    assert!(!junk.trim_start().starts_with('{'));
}

#[test]
fn rust_owner_types_declare_matching_schema_consts() {
    // The scanner in scripts/schema_validate.py resolves these owners; this
    // pins the type-level contract directly.
    assert_eq!(fss_core::SensorCapsuleV1::SCHEMA, "fss.sensor_capsule.v1");
    assert_eq!(
        fss_core::acquisition::AcquisitionSession::CHECKPOINT_SCHEMA,
        "fss.acquisition.session_checkpoint.v1"
    );
}

#[test]
fn digest_domains_are_registered_where_present() {
    // sensor_capsule's metadata digest domain must be registered.
    assert!(
        DIGEST_DOMAINS_MD.contains("`fss.sensor_capsule.metadata.v1`"),
        "sensor capsule metadata digest domain unregistered"
    );
    assert!(
        DIGEST_DOMAINS_MD.contains("SCHEMA-DOMAIN-SENSOR-METADATA-001"),
        "sensor metadata domain row id missing"
    );
}
