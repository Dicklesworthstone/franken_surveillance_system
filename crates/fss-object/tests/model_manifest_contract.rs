#![forbid(unsafe_code)]
//! Contract tests for immutable model manifest v1 (FSS-070 / fss-x4a.14.1).

use std::error::Error;
use std::fs;
use std::path::Path;

use fss_core::{CalibrationGeneration, CanonicalEncoder, ContentDigest, ModelGeneration, SchemaId};
use fss_object::*;

type TestResult = Result<(), Box<dyn Error>>;

/// Construction inputs for one root manifest; tests vary one field and rebuild.
#[derive(Clone)]
struct Parts {
    model_id: ModelId,
    generation: ModelGeneration,
    weights_digest: ContentDigest,
    input_schema: SchemaId,
    output_schema: SchemaId,
    calibration_generation: CalibrationGeneration,
    license: ModelLicenseRecord,
}

impl Parts {
    fn build(self) -> Result<ModelManifestV1, ModelManifestError> {
        ModelManifestV1::new(
            self.model_id,
            self.generation,
            self.weights_digest,
            self.input_schema,
            self.output_schema,
            self.calibration_generation,
            self.license,
        )
    }
}

fn sample_license() -> ModelLicenseRecord {
    ModelLicenseRecord {
        spdx_or_identity: "Apache-2.0".to_string(),
        text_digest: Some(ContentDigest::sha256(b"Apache-2.0 text")),
        use_approved: true,
        restrictions: vec![
            "internal_evaluation_only".to_string(),
            "no_unredacted_retention".to_string(),
        ],
        source_identity: "https://github.com/org/rf-detr-weights".to_string(),
        artifact_digests: vec![
            ContentDigest::sha256(b"rfdetr-weights-part-1"),
            ContentDigest::sha256(b"rfdetr-weights-part-2"),
        ],
        upstream_revision: Some("commit:a1b2c3d4e5f6".to_string()),
    }
}

fn sample_parts() -> Result<Parts, Box<dyn Error>> {
    Ok(Parts {
        model_id: ModelId::parse("MOD-RFDETR-001")?,
        generation: ModelGeneration::parse("model:rfdetr:fp16:v1")?,
        weights_digest: ContentDigest::sha256(b"sample-model-weights-bytes-v1"),
        input_schema: SchemaId::parse("fss.model_input.v1")?,
        output_schema: SchemaId::parse("fss.model_output.v1")?,
        calibration_generation: CalibrationGeneration::parse("cal:camera-rig:v1")?,
        license: sample_license(),
    })
}

fn sample_manifest() -> Result<ModelManifestV1, Box<dyn Error>> {
    Ok(sample_parts()?.build()?)
}

/// Returns the text of one top-level schema property up to its own closing line.
fn schema_property<'a>(schema: &'a str, name: &str) -> Result<&'a str, Box<dyn Error>> {
    let key = format!("\"{name}\": {{");
    schema
        .split(key.as_str())
        .nth(1)
        .and_then(|rest| rest.split("\n    }").next())
        .ok_or_else(|| format!("schema property {name} missing").into())
}

#[test]
fn test_canonical_binary_roundtrip() -> TestResult {
    let original = sample_manifest()?;
    let bytes = original.to_canonical_bytes()?;

    assert!(bytes.len() > 6);
    assert_eq!(&bytes[0..4], &MODEL_MANIFEST_MAGIC);

    let decoded = ModelManifestV1::from_canonical_bytes(&bytes)?;
    assert_eq!(original, decoded);

    let re_encoded = decoded.to_canonical_bytes()?;
    assert_eq!(bytes, re_encoded);

    let digest1 = original.manifest_digest()?;
    let digest2 = decoded.manifest_digest()?;
    assert_eq!(digest1, digest2);
    Ok(())
}

#[test]
fn test_canonical_json_roundtrip_bit_identical() -> TestResult {
    let original = sample_manifest()?;
    let json_str = original.to_canonical_json();

    // Verify key sorting in canonical JSON
    let key_cal = json_str.find("\"calibrationGeneration\":");
    let key_gen = json_str.find("\"generation\":");
    let key_inp = json_str.find("\"inputSchema\":");
    let key_lic = json_str.find("\"license\":");
    let key_mod = json_str.find("\"modelId\":");
    let key_out = json_str.find("\"outputSchema\":");
    let key_sch = json_str.find("\"schema\":");
    let key_sup = json_str.find("\"supersedesGeneration\":");
    let key_wgt = json_str.find("\"weightsDigest\":");

    assert!(key_cal.is_some() && key_gen.is_some() && key_inp.is_some());
    assert!(key_lic.is_some() && key_mod.is_some() && key_out.is_some());
    assert!(key_sch.is_some() && key_sup.is_some() && key_wgt.is_some());

    assert!(key_cal < key_gen);
    assert!(key_gen < key_inp);
    assert!(key_inp < key_lic);
    assert!(key_lic < key_mod);
    assert!(key_mod < key_out);
    assert!(key_out < key_sch);
    assert!(key_sch < key_sup);
    assert!(key_sup < key_wgt);

    let decoded = ModelManifestV1::from_canonical_json(&json_str)?;
    assert_eq!(original, decoded);

    let re_json = decoded.to_canonical_json();
    assert_eq!(json_str, re_json);

    // Cross round-trip: JSON -> binary -> JSON
    let bytes = decoded.to_canonical_bytes()?;
    let from_bytes = ModelManifestV1::from_canonical_bytes(&bytes)?;
    assert_eq!(from_bytes.to_canonical_json(), json_str);
    Ok(())
}

#[test]
fn test_immutability_and_superseding() -> TestResult {
    let v1 = sample_manifest()?;

    let next_gen = ModelGeneration::parse("model:rfdetr:fp16:v2")?;
    let new_weights = ContentDigest::sha256(b"sample-model-weights-bytes-v2");
    let next_cal = CalibrationGeneration::parse("cal:camera-rig:v2")?;
    let mut next_license = v1.license().clone();
    next_license.upstream_revision = Some("commit:f7e8d9c0".to_string());

    let v2 = v1.create_successor(next_gen.clone(), new_weights, next_cal, next_license)?;

    assert_eq!(v2.model_id(), v1.model_id());
    assert_eq!(v2.generation(), &next_gen);
    assert_eq!(v2.supersedes_generation(), Some(v1.generation()));

    // Valid supersedes check
    v2.supersedes(&v1)?;

    // Calling supersedes in reverse direction must fail
    let rev_err = v1.supersedes(&v2);
    assert!(matches!(
        rev_err,
        Err(ModelManifestError::SupersedesMismatch { .. })
    ));

    // Different model ID cannot supersede, even when it names v1's generation as superseded
    let mut other_parts = sample_parts()?;
    other_parts.model_id = ModelId::parse("MOD-YOLO-002")?;
    let other_root = other_parts.build()?;
    let other_model = other_root.create_successor(
        v2.generation().clone(),
        v2.weights_digest(),
        v2.calibration_generation().clone(),
        v2.license().clone(),
    )?;
    assert_eq!(other_model.supersedes_generation(), Some(v1.generation()));
    let mm_err = other_model.supersedes(&v1);
    assert!(matches!(
        mm_err,
        Err(ModelManifestError::ModelIdMismatch { .. })
    ));

    // Identical generation cannot supersede itself
    let same_gen = v1.create_successor(
        v1.generation().clone(),
        v1.weights_digest(),
        v1.calibration_generation().clone(),
        v1.license().clone(),
    );
    assert!(matches!(
        same_gen,
        Err(ModelManifestError::GenerationNotAdvanced { .. })
    ));
    Ok(())
}

/// Review-526 finding 6: a self-superseding generation cannot enter through the decoder either.
#[test]
fn test_decoded_self_supersedes_rejected() -> TestResult {
    let v1 = sample_manifest()?;
    let mut bytes = v1.to_canonical_bytes()?;
    // The encoding ends with the supersedes presence flag; set it and append v1's own generation.
    let flag = bytes.len() - 1;
    assert_eq!(bytes[flag], 0);
    bytes[flag] = 1;
    let generation = v1.generation().as_str().as_bytes();
    bytes.extend_from_slice(&(generation.len() as u64).to_be_bytes());
    bytes.extend_from_slice(generation);
    assert!(matches!(
        ModelManifestV1::from_canonical_bytes(&bytes),
        Err(ModelManifestError::GenerationNotAdvanced { .. })
    ));
    Ok(())
}

#[test]
fn test_latest_resolution_rejected() {
    assert_eq!(
        ModelManifestV1::resolve_generation("latest"),
        Err(ModelManifestError::LatestNotResolvable)
    );
    assert_eq!(
        ModelManifestV1::resolve_generation("LATEST"),
        Err(ModelManifestError::LatestNotResolvable)
    );
    assert_eq!(
        ModelManifestV1::resolve_generation("Latest"),
        Err(ModelManifestError::LatestNotResolvable)
    );
    assert_eq!(
        ModelManifestV1::resolve_generation("latest:v1"),
        Err(ModelManifestError::LatestNotResolvable)
    );
    assert_eq!(
        ModelManifestV1::resolve_generation("model:detector:latest"),
        Err(ModelManifestError::LatestNotResolvable)
    );
    assert_eq!(
        ModelManifestV1::resolve_generation("latest.weights"),
        Err(ModelManifestError::LatestNotResolvable)
    );

    // Valid pinned generation succeeds
    let valid = ModelManifestV1::resolve_generation("model:yolo26:fp16:v1");
    assert!(valid.is_ok());
}

/// Review-526 finding 3: infix, mixed-case, and padded forms of `latest` are all refused.
#[test]
fn test_latest_resolution_rejects_every_form() {
    for requested in [
        "model:latest:v1",
        "gen:latest:weights",
        "Latest:v1",
        "model:LaTeSt:v1",
        "MODEL:LATEST",
        "model:detector:Latest",
        "latestv1-model",
        "model.latest.weights",
        " latest",
        "latest ",
        "model:v1:latest-stable",
    ] {
        assert_eq!(
            ModelManifestV1::resolve_generation(requested),
            Err(ModelManifestError::LatestNotResolvable),
            "{requested:?} was not refused as latest"
        );
    }

    // No trimming or normalization: a padded pinned generation is not silently accepted.
    assert!(matches!(
        ModelManifestV1::resolve_generation(" model:yolo26:fp16:v1"),
        Err(ModelManifestError::Contract(_))
    ));
}

/// Review-526 finding 3: no manifest can bind a generation, calibration, or supersedes pointer
/// that names `latest`, whether constructed, derived, or decoded.
#[test]
fn test_manifest_refuses_latest_bearing_generations() -> TestResult {
    assert_eq!(
        ModelGeneration::parse("model:latest:v1"),
        Err(fss_core::ContractError::LatestNotResolvable)
    );
    assert_eq!(
        CalibrationGeneration::parse("cal:rig:latest"),
        Err(fss_core::ContractError::LatestNotResolvable)
    );
    assert_eq!(
        ModelGeneration::parse("model:rfdetr:latest"),
        Err(fss_core::ContractError::LatestNotResolvable)
    );

    let mut latest_gen = sample_parts()?;
    latest_gen.generation = ModelGeneration::from_unvalidated_for_test("model:latest:v1");
    assert_eq!(
        latest_gen.build(),
        Err(ModelManifestError::LatestNotResolvable)
    );

    let mut latest_cal = sample_parts()?;
    latest_cal.calibration_generation =
        CalibrationGeneration::from_unvalidated_for_test("cal:rig:latest");
    assert_eq!(
        latest_cal.build(),
        Err(ModelManifestError::LatestNotResolvable)
    );

    let v1 = sample_manifest()?;
    let successor = v1.create_successor(
        ModelGeneration::from_unvalidated_for_test("model:rfdetr:latest"),
        v1.weights_digest(),
        v1.calibration_generation().clone(),
        v1.license().clone(),
    );
    assert_eq!(successor, Err(ModelManifestError::LatestNotResolvable));

    // Same-length substitution inside valid canonical bytes: the decoder refuses it too.
    let bytes = v1.to_canonical_bytes()?;
    let needle = b"model:rfdetr:fp16:v1";
    let replacement = b"model:latest:fp16:v1";
    assert_eq!(needle.len(), replacement.len());
    let at = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .ok_or("generation not found in canonical bytes")?;
    let mut tampered = bytes.clone();
    tampered[at..at + needle.len()].copy_from_slice(replacement);
    assert_eq!(
        ModelManifestV1::from_canonical_bytes(&tampered),
        Err(ModelManifestError::LatestNotResolvable)
    );
    Ok(())
}

#[test]
fn test_binary_decode_errors() -> TestResult {
    let original = sample_manifest()?;
    let bytes = original.to_canonical_bytes()?;

    // 1. Truncated
    assert!(matches!(
        ModelManifestV1::from_canonical_bytes(&bytes[..3]),
        Err(ModelManifestError::Truncated { .. })
    ));
    assert!(matches!(
        ModelManifestV1::from_canonical_bytes(&bytes[..20]),
        Err(ModelManifestError::Contract(_))
    ));

    // 2. Corrupt magic
    let mut bad_magic = bytes.clone();
    bad_magic[0] = b'X';
    assert!(matches!(
        ModelManifestV1::from_canonical_bytes(&bad_magic),
        Err(ModelManifestError::NonCanonicalEncoding { .. })
    ));

    // 3. Unknown version
    let mut bad_ver = bytes.clone();
    bad_ver[7] = 99;
    assert!(matches!(
        ModelManifestV1::from_canonical_bytes(&bad_ver),
        Err(ModelManifestError::UnknownVersion { .. })
    ));

    // 3b. A version above u16::MAX is reported exactly, never clamped to a stand-in value.
    let mut wide_ver = bytes.clone();
    wide_ver[4] = 1;
    assert_eq!(
        ModelManifestV1::from_canonical_bytes(&wide_ver),
        Err(ModelManifestError::UnknownVersion {
            version: 0x0100_0001
        })
    );

    // 4. Trailing bytes
    let mut trailing = bytes.clone();
    trailing.push(0xAA);
    trailing.push(0xBB);
    assert!(matches!(
        ModelManifestV1::from_canonical_bytes(&trailing),
        Err(ModelManifestError::TrailingBytes { count: 2 })
    ));
    Ok(())
}

#[test]
fn test_json_decode_errors_and_strictness() -> TestResult {
    let original = sample_manifest()?;
    let valid_json = original.to_canonical_json();

    // 1. Missing required field
    let missing_field = valid_json.replace("\"weightsDigest\":", "\"unused\":");
    assert!(matches!(
        ModelManifestV1::from_canonical_json(&missing_field),
        Err(ModelManifestError::JsonError { .. })
    ));

    // 2. Unexpected extra field
    let extra_field = valid_json.replace("\"modelId\":", "\"unknownProp\":\"val\",\"modelId\":");
    assert!(matches!(
        ModelManifestV1::from_canonical_json(&extra_field),
        Err(ModelManifestError::JsonError { .. })
    ));

    // 3. Duplicate key
    let dup_key = valid_json.replace("\"modelId\":", "\"modelId\":\"MOD-DUP\",\"modelId\":");
    assert!(matches!(
        ModelManifestV1::from_canonical_json(&dup_key),
        Err(ModelManifestError::JsonError { .. })
    ));

    // 4. Schema mismatch
    let bad_schema = valid_json.replace(MODEL_MANIFEST_SCHEMA, "fss.other_schema.v1");
    assert!(matches!(
        ModelManifestV1::from_canonical_json(&bad_schema),
        Err(ModelManifestError::SchemaMismatch { .. })
    ));

    // 5. Non-boolean string for boolean
    let bad_bool = valid_json.replace("\"useApproved\":true", "\"useApproved\":\"true\"");
    assert!(matches!(
        ModelManifestV1::from_canonical_json(&bad_bool),
        Err(ModelManifestError::JsonError { .. })
    ));

    // 6. Trailing bytes after JSON object
    let trailing_json = format!("{valid_json} trailing");
    assert!(matches!(
        ModelManifestV1::from_canonical_json(&trailing_json),
        Err(ModelManifestError::TrailingBytes { .. })
    ));
    Ok(())
}

/// Review-526 finding 7: optional properties are never omitted, so JSON and binary agree.
#[test]
fn test_json_optional_properties_are_explicit_and_round_trip() -> TestResult {
    let mut parts = sample_parts()?;
    parts.license.text_digest = None;
    parts.license.upstream_revision = None;
    let manifest = parts.build()?;
    let json = manifest.to_canonical_json();
    assert!(json.contains("\"supersedesGeneration\":null"));
    assert!(json.contains("\"textDigest\":null"));
    assert!(json.contains("\"upstreamRevision\":null"));

    // Explicit nulls decode and round-trip bit-identically through JSON and binary.
    let decoded = ModelManifestV1::from_canonical_json(&json)?;
    assert_eq!(decoded, manifest);
    assert_eq!(decoded.to_canonical_json(), json);
    let via_binary = ModelManifestV1::from_canonical_bytes(&decoded.to_canonical_bytes()?)?;
    assert_eq!(via_binary.to_canonical_json(), json);

    // Omitting any optional property is a typed missing-property error, never a default.
    for (omitted, key) in [
        (
            json.replace("\"supersedesGeneration\":null,", ""),
            "supersedesGeneration",
        ),
        (json.replace(",\"textDigest\":null", ""), "textDigest"),
        (
            json.replace(",\"upstreamRevision\":null", ""),
            "upstreamRevision",
        ),
    ] {
        assert_ne!(omitted, json);
        match ModelManifestV1::from_canonical_json(&omitted) {
            Err(ModelManifestError::JsonError { detail }) => {
                assert!(detail.contains(key), "{detail}");
            }
            other => return Err(format!("omitting {key} was not refused: {other:?}").into()),
        }
    }

    // Any non-canonical spelling of the same manifest is refused, so nothing accepted can fail
    // to round-trip.
    let spaced = json.replacen(
        "{\"calibrationGeneration\":",
        "{ \"calibrationGeneration\":",
        1,
    );
    assert!(matches!(
        ModelManifestV1::from_canonical_json(&spaced),
        Err(ModelManifestError::NonCanonicalEncoding { .. })
    ));
    let escaped = json.replacen(
        "\"schema\":\"fss.model_manifest.v1\"",
        "\"schema\":\"fss.model\\u005fmanifest.v1\"",
        1,
    );
    assert_ne!(escaped, json);
    assert!(matches!(
        ModelManifestV1::from_canonical_json(&escaped),
        Err(ModelManifestError::NonCanonicalEncoding { .. })
    ));
    Ok(())
}

#[test]
fn test_model_id_bounds_and_syntax() -> TestResult {
    // Min bound: 5 chars ("MOD-A")
    assert!(ModelId::parse("MOD-A").is_ok());
    assert!(matches!(
        ModelId::parse("MOD-"),
        Err(ModelManifestError::UnderLimitLength {
            minimum: MIN_MODEL_ID_LEN,
            actual: 4,
            ..
        })
    ));

    // Max bound: 64 chars
    let at_bound = format!("MOD-{}", "A".repeat(MAX_MODEL_ID_LEN - 4));
    assert_eq!(at_bound.len(), MAX_MODEL_ID_LEN);
    assert!(ModelId::parse(&at_bound).is_ok());

    let over_bound = format!("MOD-{}", "A".repeat(MAX_MODEL_ID_LEN - 3));
    assert_eq!(over_bound.len(), MAX_MODEL_ID_LEN + 1);
    assert!(matches!(
        ModelId::parse(&over_bound),
        Err(ModelManifestError::OverLimitLength {
            limit: MAX_MODEL_ID_LEN,
            actual: 65,
            ..
        })
    ));

    // Invalid prefix
    assert!(matches!(
        ModelId::parse("DEV-MODEL-001"),
        Err(ModelManifestError::InvalidIdentifier { .. })
    ));

    // Lowercase rejected
    assert!(matches!(
        ModelId::parse("MOD-lowercase-001"),
        Err(ModelManifestError::InvalidIdentifier { .. })
    ));
    Ok(())
}

#[test]
fn test_generation_bounds_at_bound_and_plus_one() -> TestResult {
    // Min bound: 8 chars
    let at_min = ModelGeneration::parse("model:v1")?;
    assert_eq!(at_min.len(), MIN_MODEL_GENERATION_LEN);
    let mut m_min = sample_parts()?;
    m_min.generation = at_min;
    assert!(m_min.build().is_ok());

    // Max bound: MAX_MODEL_GENERATION_LEN (256) chars
    let at_max_str = format!("model:{}:v1", "a".repeat(MAX_MODEL_GENERATION_LEN - 9));
    assert_eq!(at_max_str.len(), MAX_MODEL_GENERATION_LEN);
    let at_max = ModelGeneration::parse(&at_max_str)?;
    let mut m_max = sample_parts()?;
    m_max.generation = at_max;
    assert!(m_max.build().is_ok());

    // Over bound: 257 chars rejected by subsystem_generation parser
    let over_max_str = format!("model:{}:v1", "a".repeat(MAX_MODEL_GENERATION_LEN - 8));
    assert_eq!(over_max_str.len(), MAX_MODEL_GENERATION_LEN + 1);
    assert!(ModelGeneration::parse(&over_max_str).is_err());
    Ok(())
}

/// Review-526 finding 8: the schema and the code declare the same generation bounds.
#[test]
fn test_schema_generation_bounds_match_code() -> TestResult {
    let schema = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/model_manifest.v1.json"),
    )?;
    for (property, minimum, maximum) in [
        (
            "generation",
            MIN_MODEL_GENERATION_LEN,
            MAX_MODEL_GENERATION_LEN,
        ),
        (
            "supersedesGeneration",
            MIN_MODEL_GENERATION_LEN,
            MAX_MODEL_GENERATION_LEN,
        ),
        (
            "calibrationGeneration",
            MIN_CALIBRATION_GENERATION_LEN,
            MAX_CALIBRATION_GENERATION_LEN,
        ),
    ] {
        let block = schema_property(&schema, property)?;
        assert!(
            block.contains(&format!("\"maxLength\": {maximum}")),
            "{property}: {block}"
        );
        assert!(
            block.contains(&format!("\"minLength\": {minimum}")),
            "{property}: {block}"
        );
        let pattern = format!("{{{},{}}}$", minimum - 1, maximum - 1);
        assert!(block.contains(&pattern), "{property}: {block}");
    }

    // The code's own bound agrees at the bound and one past it.
    let at_max = "a".repeat(MAX_MODEL_GENERATION_LEN);
    assert!(ModelManifestV1::resolve_generation(&at_max).is_ok());
    let over_max = "a".repeat(MAX_MODEL_GENERATION_LEN + 1);
    assert!(ModelManifestV1::resolve_generation(&over_max).is_err());
    Ok(())
}

#[test]
fn test_schema_id_bounds_at_bound_and_plus_one() -> TestResult {
    // Max bound: 128 chars
    let at_max_str = format!("fss.{}.v1", "a".repeat(MAX_SCHEMA_ID_LEN - 7));
    assert_eq!(at_max_str.len(), MAX_SCHEMA_ID_LEN);
    let at_max = SchemaId::parse(&at_max_str)?;
    let mut m_max = sample_parts()?;
    m_max.input_schema = at_max;
    assert!(m_max.build().is_ok());

    // Over bound: 129 chars rejected by parser
    let over_max_str = format!("fss.{}.v1", "a".repeat(MAX_SCHEMA_ID_LEN - 6));
    assert_eq!(over_max_str.len(), MAX_SCHEMA_ID_LEN + 1);
    assert!(SchemaId::parse(&over_max_str).is_err());
    Ok(())
}

#[test]
fn test_calibration_generation_bounds_at_bound_and_plus_one() -> TestResult {
    // Min bound: 8 chars
    let at_min = CalibrationGeneration::parse("cal:rg:1")?;
    assert_eq!(at_min.len(), MIN_CALIBRATION_GENERATION_LEN);
    let mut m_min = sample_parts()?;
    m_min.calibration_generation = at_min;
    assert!(m_min.build().is_ok());

    // Max bound: MAX_CALIBRATION_GENERATION_LEN (256) chars
    let at_max_str = format!("cal:{}:v1", "a".repeat(MAX_CALIBRATION_GENERATION_LEN - 7));
    assert_eq!(at_max_str.len(), MAX_CALIBRATION_GENERATION_LEN);
    let at_max = CalibrationGeneration::parse(&at_max_str)?;
    let mut m_max = sample_parts()?;
    m_max.calibration_generation = at_max;
    assert!(m_max.build().is_ok());

    // Over bound: 257 chars rejected by subsystem_generation
    let over_max_str = format!("cal:{}:v1", "a".repeat(MAX_CALIBRATION_GENERATION_LEN - 6));
    assert_eq!(over_max_str.len(), MAX_CALIBRATION_GENERATION_LEN + 1);
    assert!(CalibrationGeneration::parse(&over_max_str).is_err());
    Ok(())
}

#[test]
fn test_license_restrictions_bounds_and_duplicates() -> TestResult {
    // 64 restrictions: at bound
    let mut at_bound_list = Vec::new();
    for i in 0..MAX_RESTRICTIONS_COUNT {
        at_bound_list.push(format!("restriction_{i}"));
    }
    let mut m_bound = sample_parts()?;
    m_bound.license.restrictions = at_bound_list.clone();
    assert!(m_bound.build().is_ok());

    // 65 restrictions: over bound
    let mut over_bound_list = at_bound_list;
    over_bound_list.push("restriction_overflow".to_string());
    let mut m_over = sample_parts()?;
    m_over.license.restrictions = over_bound_list;
    assert!(matches!(
        m_over.build(),
        Err(ModelManifestError::OverLimitLength {
            field: "license.restrictions",
            limit: MAX_RESTRICTIONS_COUNT,
            actual: 65
        })
    ));

    // Restriction length bound: 256 chars passes, 257 chars fails
    let at_len_str = "r".repeat(MAX_RESTRICTION_LEN);
    let mut m_len = sample_parts()?;
    m_len.license.restrictions = vec![at_len_str];
    assert!(m_len.build().is_ok());

    let over_len_str = "r".repeat(MAX_RESTRICTION_LEN + 1);
    let mut m_over_len = sample_parts()?;
    m_over_len.license.restrictions = vec![over_len_str];
    assert!(matches!(
        m_over_len.build(),
        Err(ModelManifestError::OverLimitLength {
            field: "license.restrictions[i]",
            limit: MAX_RESTRICTION_LEN,
            actual: 257
        })
    ));

    // Duplicate restriction rejected
    let mut m_dup = sample_parts()?;
    m_dup.license.restrictions = vec![
        "same_restriction".to_string(),
        "same_restriction".to_string(),
    ];
    assert!(matches!(
        m_dup.build(),
        Err(ModelManifestError::NonCanonicalEncoding { .. })
    ));
    Ok(())
}

#[test]
fn test_license_spdx_and_provenance_bounds() -> TestResult {
    // SPDX length: 128 passes, 129 fails
    let at_spdx = "S".repeat(MAX_SPDX_LEN);
    let mut m_spdx = sample_parts()?;
    m_spdx.license.spdx_or_identity = at_spdx;
    assert!(m_spdx.build().is_ok());

    let over_spdx = "S".repeat(MAX_SPDX_LEN + 1);
    let mut m_over_spdx = sample_parts()?;
    m_over_spdx.license.spdx_or_identity = over_spdx;
    assert!(matches!(
        m_over_spdx.build(),
        Err(ModelManifestError::OverLimitLength {
            field: "license.spdx_or_identity",
            limit: MAX_SPDX_LEN,
            actual: 129
        })
    ));

    // Source identity length: 256 passes, 257 fails
    let at_src = "https://example.com/".to_string() + &"a".repeat(MAX_SOURCE_IDENTITY_LEN - 20);
    assert_eq!(at_src.len(), MAX_SOURCE_IDENTITY_LEN);
    let mut m_src = sample_parts()?;
    m_src.license.source_identity = at_src;
    assert!(m_src.build().is_ok());

    let over_src = "https://example.com/".to_string() + &"a".repeat(MAX_SOURCE_IDENTITY_LEN - 19);
    assert_eq!(over_src.len(), MAX_SOURCE_IDENTITY_LEN + 1);
    let mut m_over_src = sample_parts()?;
    m_over_src.license.source_identity = over_src;
    assert!(matches!(
        m_over_src.build(),
        Err(ModelManifestError::OverLimitLength {
            field: "license.source_identity",
            limit: MAX_SOURCE_IDENTITY_LEN,
            actual: 257
        })
    ));

    // Artifact digests: 64 passes, 65 fails
    let mut digests_64 = Vec::new();
    for i in 0..MAX_ARTIFACT_DIGESTS_COUNT {
        digests_64.push(ContentDigest::sha256(format!("artifact_{i}").as_bytes()));
    }
    let mut m_digests = sample_parts()?;
    m_digests.license.artifact_digests = digests_64.clone();
    assert!(m_digests.build().is_ok());

    let mut digests_65 = digests_64;
    digests_65.push(ContentDigest::sha256(b"overflow"));
    let mut m_over_digests = sample_parts()?;
    m_over_digests.license.artifact_digests = digests_65;
    assert!(matches!(
        m_over_digests.build(),
        Err(ModelManifestError::OverLimitLength {
            field: "license.artifact_digests",
            limit: MAX_ARTIFACT_DIGESTS_COUNT,
            actual: 65
        })
    ));

    // Upstream revision: 128 passes, 129 fails
    let at_rev = "r".repeat(MAX_UPSTREAM_REVISION_LEN);
    let mut m_rev = sample_parts()?;
    m_rev.license.upstream_revision = Some(at_rev);
    assert!(m_rev.build().is_ok());

    let over_rev = "r".repeat(MAX_UPSTREAM_REVISION_LEN + 1);
    let mut m_over_rev = sample_parts()?;
    m_over_rev.license.upstream_revision = Some(over_rev);
    assert!(matches!(
        m_over_rev.build(),
        Err(ModelManifestError::OverLimitLength {
            field: "license.upstream_revision",
            limit: MAX_UPSTREAM_REVISION_LEN,
            actual: 129
        })
    ));
    Ok(())
}

/// Review-526 finding 5: the license encoder refuses an out-of-bound count with a typed error at
/// bound + 1 and writes nothing, instead of emitting a clamped count header.
#[test]
fn test_license_encoding_counts_bounded_and_typed() -> TestResult {
    let mut at_bound = sample_license();
    at_bound.restrictions = (0..MAX_RESTRICTIONS_COUNT)
        .map(|i| format!("restriction_{i}"))
        .collect();
    at_bound.artifact_digests = (0..MAX_ARTIFACT_DIGESTS_COUNT)
        .map(|i| ContentDigest::sha256(format!("artifact_{i}").as_bytes()))
        .collect();
    let mut encoder = CanonicalEncoder::new();
    at_bound.encode_canonical(&mut encoder)?;
    let encoded = encoder.finish_checked()?;
    let mut decoder = fss_core::CanonicalDecoder::new(&encoded);
    assert_eq!(
        ModelLicenseRecord::decode_canonical(&mut decoder)?,
        at_bound
    );

    let mut over_restrictions = at_bound.clone();
    over_restrictions
        .restrictions
        .push("restriction_overflow".to_string());
    let mut encoder = CanonicalEncoder::new();
    assert_eq!(
        over_restrictions.encode_canonical(&mut encoder),
        Err(ModelManifestError::OverLimitLength {
            field: "license.restrictions",
            limit: MAX_RESTRICTIONS_COUNT,
            actual: MAX_RESTRICTIONS_COUNT + 1,
        })
    );
    assert!(encoder.finish_checked()?.is_empty(), "bytes written");

    let mut over_digests = at_bound;
    over_digests
        .artifact_digests
        .push(ContentDigest::sha256(b"overflow"));
    let mut encoder = CanonicalEncoder::new();
    assert_eq!(
        over_digests.encode_canonical(&mut encoder),
        Err(ModelManifestError::OverLimitLength {
            field: "license.artifact_digests",
            limit: MAX_ARTIFACT_DIGESTS_COUNT,
            actual: MAX_ARTIFACT_DIGESTS_COUNT + 1,
        })
    );
    assert!(encoder.finish_checked()?.is_empty(), "bytes written");
    Ok(())
}
