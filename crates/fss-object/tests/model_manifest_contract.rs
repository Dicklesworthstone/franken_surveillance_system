#![forbid(unsafe_code)]
//! Contract tests for immutable model manifest v1 (FSS-070 / fss-x4a.14.1).

use fss_core::{CalibrationGeneration, ContentDigest, ModelGeneration, SchemaId};
use fss_object::*;

fn sample_manifest() -> Result<ModelManifestV1, Box<dyn std::error::Error>> {
    let model_id = ModelId::parse("MOD-RFDETR-001")?;
    let generation = ModelGeneration::parse("model:rfdetr:fp16:v1")?;
    let weights_digest = ContentDigest::sha256(b"sample-model-weights-bytes-v1");
    let input_schema = SchemaId::parse("fss.model_input.v1")?;
    let output_schema = SchemaId::parse("fss.model_output.v1")?;
    let calibration_generation = CalibrationGeneration::parse("cal:camera-rig:v1")?;

    let license = ModelLicenseRecord {
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
    };

    Ok(ModelManifestV1 {
        model_id,
        generation,
        weights_digest,
        input_schema,
        output_schema,
        calibration_generation,
        license,
        supersedes_generation: None,
    })
}

#[test]
fn test_canonical_binary_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let original = sample_manifest()?;
    let bytes = original.to_canonical_bytes();

    assert!(bytes.len() > 6);
    assert_eq!(&bytes[0..4], &MODEL_MANIFEST_MAGIC);

    let decoded = ModelManifestV1::from_canonical_bytes(&bytes)?;
    assert_eq!(original, decoded);

    let re_encoded = decoded.to_canonical_bytes();
    assert_eq!(bytes, re_encoded);

    let digest1 = original.manifest_digest();
    let digest2 = decoded.manifest_digest();
    assert_eq!(digest1, digest2);
    Ok(())
}

#[test]
fn test_canonical_json_roundtrip_bit_identical() -> Result<(), Box<dyn std::error::Error>> {
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
    let bytes = decoded.to_canonical_bytes();
    let from_bytes = ModelManifestV1::from_canonical_bytes(&bytes)?;
    assert_eq!(from_bytes.to_canonical_json(), json_str);
    Ok(())
}

#[test]
fn test_immutability_and_superseding() -> Result<(), Box<dyn std::error::Error>> {
    let v1 = sample_manifest()?;

    let next_gen = ModelGeneration::parse("model:rfdetr:fp16:v2")?;
    let new_weights = ContentDigest::sha256(b"sample-model-weights-bytes-v2");
    let next_cal = CalibrationGeneration::parse("cal:camera-rig:v2")?;
    let mut next_license = v1.license.clone();
    next_license.upstream_revision = Some("commit:f7e8d9c0".to_string());

    let v2 = v1.create_successor(next_gen.clone(), new_weights, next_cal, next_license)?;

    assert_eq!(v2.model_id, v1.model_id);
    assert_eq!(v2.generation, next_gen);
    assert_eq!(v2.supersedes_generation, Some(v1.generation.clone()));

    // Valid supersedes check
    v2.supersedes(&v1)?;

    // Calling supersedes in reverse direction must fail
    let rev_err = v1.supersedes(&v2);
    assert!(matches!(
        rev_err,
        Err(ModelManifestError::SupersedesMismatch { .. })
    ));

    // Different model ID cannot supersede
    let other_model = ModelManifestV1 {
        model_id: ModelId::parse("MOD-YOLO-002")?,
        ..v2.clone()
    };
    let mm_err = other_model.supersedes(&v1);
    assert!(matches!(
        mm_err,
        Err(ModelManifestError::ModelIdMismatch { .. })
    ));

    // Identical generation cannot supersede itself
    let same_gen = ModelManifestV1 {
        supersedes_generation: Some(v1.generation.clone()),
        ..v1.clone()
    };
    let same_err = same_gen.supersedes(&v1);
    assert!(matches!(
        same_err,
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

#[test]
fn test_binary_decode_errors() -> Result<(), Box<dyn std::error::Error>> {
    let original = sample_manifest()?;
    let bytes = original.to_canonical_bytes();

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
fn test_json_decode_errors_and_strictness() -> Result<(), Box<dyn std::error::Error>> {
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

#[test]
fn test_model_id_bounds_and_syntax() -> Result<(), Box<dyn std::error::Error>> {
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
fn test_generation_bounds_at_bound_and_plus_one() -> Result<(), Box<dyn std::error::Error>> {
    let valid_base = sample_manifest()?;

    // Min bound: 8 chars
    let at_min = ModelGeneration::parse("model:v1")?;
    assert_eq!(at_min.len(), MIN_MODEL_GENERATION_LEN);
    let mut m_min = valid_base.clone();
    m_min.generation = at_min;
    assert!(m_min.validate().is_ok());

    // Max bound: 255 chars
    let at_max_str = format!("model:{}:v1", "a".repeat(MAX_MODEL_GENERATION_LEN - 9));
    assert_eq!(at_max_str.len(), MAX_MODEL_GENERATION_LEN);
    let at_max = ModelGeneration::parse(&at_max_str)?;
    let mut m_max = valid_base.clone();
    m_max.generation = at_max;
    assert!(m_max.validate().is_ok());

    // Over bound: 256 chars rejected by subsystem_generation parser
    let over_max_str = format!("model:{}:v1", "a".repeat(MAX_MODEL_GENERATION_LEN - 8));
    assert_eq!(over_max_str.len(), MAX_MODEL_GENERATION_LEN + 1);
    assert!(ModelGeneration::parse(&over_max_str).is_err());
    Ok(())
}

#[test]
fn test_schema_id_bounds_at_bound_and_plus_one() -> Result<(), Box<dyn std::error::Error>> {
    let valid_base = sample_manifest()?;

    // Max bound: 128 chars
    let at_max_str = format!("fss.{}.v1", "a".repeat(MAX_SCHEMA_ID_LEN - 7));
    assert_eq!(at_max_str.len(), MAX_SCHEMA_ID_LEN);
    let at_max = SchemaId::parse(&at_max_str)?;
    let mut m_max = valid_base.clone();
    m_max.input_schema = at_max;
    assert!(m_max.validate().is_ok());

    // Over bound: 129 chars rejected by parser
    let over_max_str = format!("fss.{}.v1", "a".repeat(MAX_SCHEMA_ID_LEN - 6));
    assert_eq!(over_max_str.len(), MAX_SCHEMA_ID_LEN + 1);
    assert!(SchemaId::parse(&over_max_str).is_err());
    Ok(())
}

#[test]
fn test_calibration_generation_bounds_at_bound_and_plus_one()
-> Result<(), Box<dyn std::error::Error>> {
    let valid_base = sample_manifest()?;

    // Min bound: 8 chars
    let at_min = CalibrationGeneration::parse("cal:rg:1")?;
    assert_eq!(at_min.len(), MIN_CALIBRATION_GENERATION_LEN);
    let mut m_min = valid_base.clone();
    m_min.calibration_generation = at_min;
    assert!(m_min.validate().is_ok());

    // Max bound: 255 chars
    let at_max_str = format!("cal:{}:v1", "a".repeat(MAX_CALIBRATION_GENERATION_LEN - 7));
    assert_eq!(at_max_str.len(), MAX_CALIBRATION_GENERATION_LEN);
    let at_max = CalibrationGeneration::parse(&at_max_str)?;
    let mut m_max = valid_base.clone();
    m_max.calibration_generation = at_max;
    assert!(m_max.validate().is_ok());

    // Over bound: 256 chars rejected by subsystem_generation
    let over_max_str = format!("cal:{}:v1", "a".repeat(MAX_CALIBRATION_GENERATION_LEN - 6));
    assert_eq!(over_max_str.len(), MAX_CALIBRATION_GENERATION_LEN + 1);
    assert!(CalibrationGeneration::parse(&over_max_str).is_err());
    Ok(())
}

#[test]
fn test_license_restrictions_bounds_and_duplicates() -> Result<(), Box<dyn std::error::Error>> {
    let valid_base = sample_manifest()?;

    // 64 restrictions: at bound
    let mut at_bound_list = Vec::new();
    for i in 0..MAX_RESTRICTIONS_COUNT {
        at_bound_list.push(format!("restriction_{i}"));
    }
    let mut m_bound = valid_base.clone();
    m_bound.license.restrictions = at_bound_list;
    assert!(m_bound.validate().is_ok());

    // 65 restrictions: over bound
    let mut over_bound_list = m_bound.license.restrictions.clone();
    over_bound_list.push("restriction_overflow".to_string());
    let mut m_over = valid_base.clone();
    m_over.license.restrictions = over_bound_list;
    assert!(matches!(
        m_over.validate(),
        Err(ModelManifestError::OverLimitLength {
            field: "license.restrictions",
            limit: MAX_RESTRICTIONS_COUNT,
            actual: 65
        })
    ));

    // Restriction length bound: 256 chars passes, 257 chars fails
    let at_len_str = "r".repeat(MAX_RESTRICTION_LEN);
    let mut m_len = valid_base.clone();
    m_len.license.restrictions = vec![at_len_str];
    assert!(m_len.validate().is_ok());

    let over_len_str = "r".repeat(MAX_RESTRICTION_LEN + 1);
    let mut m_over_len = valid_base.clone();
    m_over_len.license.restrictions = vec![over_len_str];
    assert!(matches!(
        m_over_len.validate(),
        Err(ModelManifestError::OverLimitLength {
            field: "license.restrictions[i]",
            limit: MAX_RESTRICTION_LEN,
            actual: 257
        })
    ));

    // Duplicate restriction rejected
    let mut m_dup = valid_base.clone();
    m_dup.license.restrictions = vec![
        "same_restriction".to_string(),
        "same_restriction".to_string(),
    ];
    assert!(matches!(
        m_dup.validate(),
        Err(ModelManifestError::NonCanonicalEncoding { .. })
    ));
    Ok(())
}

#[test]
fn test_license_spdx_and_provenance_bounds() -> Result<(), Box<dyn std::error::Error>> {
    let valid_base = sample_manifest()?;

    // SPDX length: 128 passes, 129 fails
    let at_spdx = "S".repeat(MAX_SPDX_LEN);
    let mut m_spdx = valid_base.clone();
    m_spdx.license.spdx_or_identity = at_spdx;
    assert!(m_spdx.validate().is_ok());

    let over_spdx = "S".repeat(MAX_SPDX_LEN + 1);
    let mut m_over_spdx = valid_base.clone();
    m_over_spdx.license.spdx_or_identity = over_spdx;
    assert!(matches!(
        m_over_spdx.validate(),
        Err(ModelManifestError::OverLimitLength {
            field: "license.spdx_or_identity",
            limit: MAX_SPDX_LEN,
            actual: 129
        })
    ));

    // Source identity length: 256 passes, 257 fails
    let at_src = "https://example.com/".to_string() + &"a".repeat(MAX_SOURCE_IDENTITY_LEN - 20);
    assert_eq!(at_src.len(), MAX_SOURCE_IDENTITY_LEN);
    let mut m_src = valid_base.clone();
    m_src.license.source_identity = at_src;
    assert!(m_src.validate().is_ok());

    let over_src = "https://example.com/".to_string() + &"a".repeat(MAX_SOURCE_IDENTITY_LEN - 19);
    assert_eq!(over_src.len(), MAX_SOURCE_IDENTITY_LEN + 1);
    let mut m_over_src = valid_base.clone();
    m_over_src.license.source_identity = over_src;
    assert!(matches!(
        m_over_src.validate(),
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
    let mut m_digests = valid_base.clone();
    m_digests.license.artifact_digests = digests_64;
    assert!(m_digests.validate().is_ok());

    let mut digests_65 = m_digests.license.artifact_digests.clone();
    digests_65.push(ContentDigest::sha256(b"overflow"));
    let mut m_over_digests = valid_base.clone();
    m_over_digests.license.artifact_digests = digests_65;
    assert!(matches!(
        m_over_digests.validate(),
        Err(ModelManifestError::OverLimitLength {
            field: "license.artifact_digests",
            limit: MAX_ARTIFACT_DIGESTS_COUNT,
            actual: 65
        })
    ));

    // Upstream revision: 128 passes, 129 fails
    let at_rev = "r".repeat(MAX_UPSTREAM_REVISION_LEN);
    let mut m_rev = valid_base.clone();
    m_rev.license.upstream_revision = Some(at_rev);
    assert!(m_rev.validate().is_ok());

    let over_rev = "r".repeat(MAX_UPSTREAM_REVISION_LEN + 1);
    let mut m_over_rev = valid_base.clone();
    m_over_rev.license.upstream_revision = Some(over_rev);
    assert!(matches!(
        m_over_rev.validate(),
        Err(ModelManifestError::OverLimitLength {
            field: "license.upstream_revision",
            limit: MAX_UPSTREAM_REVISION_LEN,
            actual: 129
        })
    ));
    Ok(())
}
