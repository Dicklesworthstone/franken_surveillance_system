#![forbid(unsafe_code)]
//! Deterministic contract tests for hydration ladder level H0: identity (AGT-H0, fss-x4a.30.82.12).
//!
//! Enforces:
//! 1. Normative row identity and properties from registries/AGENT_ABSTRACTIONS.md
//! 2. Content completeness: digest, type, time/spatial bounds, source, availability, cost, and authority
//! 3. Pure metadata invariant: strictly prohibits raw bytes, decoded frames, and ungrounded cognition
//! 4. Invariant enforcement & planted bypasses (zero digest, inverted time, empty IDs, expired retention)
//! 5. Deterministic canonical binary encoding & decoding with exact roundtrip and canonical ordering
//! 6. Mutant kills: decode_canonical invokes validate(), checks schema magic, rejects unsorted sets
//! 7. HandleAvailability state machine and completeness mappings
//! 8. Integration with SemanticHandle extraction

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use fss_core::{
    BudgetVector, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    CaptureInterval, Completeness, ContentDigest, ContractBasis, ContractBasisRegistryBytes,
    ContractError, DigestAlgorithm, H0_CONTENT, H0_LEVEL_ID, H0_LEVEL_NAME, H0_SCHEMA, H0Identity,
    H0IdentityParams, HandleAvailability, HydrationError, HydrationLevel, LedgerAnchor,
    SemanticHandle, SemanticHandleSpec, TimestampNs,
};

fn sample_basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
        b"schemas",
        b"operations",
        b"views",
        b"capabilities",
        b"errors",
        b"costs",
        "fss:test",
    ))
}

fn sample_anchor(seq: u64) -> LedgerAnchor {
    let mut a = LedgerAnchor::genesis("site:us-east:h0");
    a.commit_sequence = seq;
    a
}

fn sample_digest(byte: u8) -> ContentDigest {
    ContentDigest::sha256(&[byte; 32])
}

fn sample_budget() -> Result<BudgetVector, Box<dyn Error>> {
    Ok(BudgetVector::builder()
        .latency_ms(25)
        .tokens(50)
        .bytes(512)
        .cpu_millis(10)
        .privacy_exposure(0.05)
        .build()?)
}

fn sample_h0_params() -> Result<H0IdentityParams, Box<dyn Error>> {
    let mut caps = BTreeSet::new();
    caps.insert("cap:read:identity".to_string());
    caps.insert("cap:read:metadata".to_string());

    Ok(H0IdentityParams {
        handle_id: "semantic-handle:sha256:abcd1234ef567890".to_string(),
        subject_id: "evidence:pkg-42".to_string(),
        subject_digest: sample_digest(0x42),
        semantic_type: "evidence_bundle".to_string(),
        source_id: "sensor:cam-front-01".to_string(),
        capture_interval: Some(CaptureInterval::new(
            TimestampNs(1_000_000_000),
            TimestampNs(1_000_000_100),
        )?),
        spatial_scope: Some("zone:perimeter:north".to_string()),
        availability: HandleAvailability::Available,
        estimated_cost: sample_budget()?,
        anchor: sample_anchor(10),
        contract_basis: sample_basis(),
        required_capabilities: caps,
        privacy_class: "privacy:operational_metadata".to_string(),
        published_at: TimestampNs(1_000_000_000),
        retention_until: TimestampNs(2_000_000_000),
    })
}

#[test]
fn test_h0_normative_constants_and_properties() -> Result<(), Box<dyn Error>> {
    // 1. Level ID and name
    assert_eq!(H0_LEVEL_ID, "H0");
    assert_eq!(H0_LEVEL_NAME, "identity");
    assert_eq!(H0_SCHEMA, "fss.h0_identity.v1");

    // 2. Normative content declaration
    assert_eq!(
        H0_CONTENT,
        "digest, type, time/spatial bounds, source, availability, cost, and authority"
    );

    // 3. HydrationLevel enum mappings
    let level = HydrationLevel::H0;
    assert_eq!(level.as_str(), "H0");
    assert_eq!(level.level_id(), "H0");
    assert_eq!(level.level_name(), "identity");
    assert_eq!(level.content(), H0_CONTENT);
    assert_eq!(level.owner(), "fss-core/hydration");
    assert_eq!(level.ordinal(), 0);

    // 4. FromStr resolution
    assert_eq!("H0".parse::<HydrationLevel>()?, HydrationLevel::H0);
    assert_eq!("h0".parse::<HydrationLevel>()?, HydrationLevel::H0);
    assert_eq!("identity".parse::<HydrationLevel>()?, HydrationLevel::H0);

    // Planted negative: unknown level string fails with InvalidIdentifier
    let Err(err) = "H99".parse::<HydrationLevel>() else {
        return Err("expected error on H99".into());
    };
    assert_eq!(err, ContractError::InvalidIdentifier);

    Ok(())
}

#[test]
fn test_h0_direct_construction_and_accessors() -> Result<(), Box<dyn Error>> {
    let params = sample_h0_params()?;
    let identity = H0Identity::new(params.clone())?;

    // Verify all 7 normative dimensions are queryable:
    // 1. digest
    assert_eq!(identity.subject_digest, params.subject_digest);
    // 2. type
    assert_eq!(identity.semantic_type, "evidence_bundle");
    // 3. time and spatial bounds
    assert_eq!(identity.capture_interval, params.capture_interval);
    assert_eq!(
        identity.spatial_scope.as_deref(),
        Some("zone:perimeter:north")
    );
    // 4. source
    assert_eq!(identity.source_id, "sensor:cam-front-01");
    // 5. availability
    assert_eq!(identity.availability, HandleAvailability::Available);
    // 6. cost
    assert_eq!(identity.estimated_cost, params.estimated_cost);
    // 7. authority (anchor + contract_basis)
    assert_eq!(identity.anchor, params.anchor);
    assert_eq!(identity.contract_basis, params.contract_basis);

    // Helper accessors
    assert_eq!(identity.level(), HydrationLevel::H0);
    assert_eq!(identity.level_id(), "H0");
    assert_eq!(identity.level_name(), "identity");
    assert_eq!(identity.content_declaration(), H0_CONTENT);
    assert!(identity.is_pure_metadata());
    assert!(!identity.is_expired_at(TimestampNs(1_500_000_000)));
    assert!(identity.is_expired_at(TimestampNs(2_500_000_000)));
    assert!(identity.requires_capability("cap:read:identity"));
    assert!(!identity.requires_capability("cap:unknown"));

    let generous_budget = BudgetVector::builder()
        .latency_ms(100)
        .tokens(100)
        .bytes(1024)
        .cpu_millis(50)
        .privacy_exposure(0.5)
        .build()?;
    assert!(identity.satisfies_budget(&generous_budget));

    let tight_budget = BudgetVector::builder()
        .latency_ms(5)
        .tokens(10)
        .bytes(100)
        .cpu_millis(1)
        .privacy_exposure(0.01)
        .build()?;
    assert!(!identity.satisfies_budget(&tight_budget));

    Ok(())
}

#[test]
fn test_h0_extraction_from_semantic_handle() -> Result<(), Box<dyn Error>> {
    let mut levels = BTreeSet::new();
    levels.insert(HydrationLevel::H0);
    levels.insert(HydrationLevel::H1);

    let mut required_capabilities = BTreeMap::new();
    let mut h0_caps = BTreeSet::new();
    h0_caps.insert("cap:h0".to_string());
    required_capabilities.insert(HydrationLevel::H0, h0_caps);
    required_capabilities.insert(HydrationLevel::H1, BTreeSet::new());

    let mut estimated_costs = BTreeMap::new();
    estimated_costs.insert(HydrationLevel::H0, sample_budget()?);
    estimated_costs.insert(HydrationLevel::H1, sample_budget()?);

    let spec = SemanticHandleSpec {
        contract_basis: sample_basis(),
        anchor: sample_anchor(5),
        subject_id: "evidence:test:42".to_string(),
        subject_digest: sample_digest(0x99),
        semantic_type: "evidence_packet".to_string(),
        source_id: "sensor:ir-01".to_string(),
        capture_interval: Some(CaptureInterval::new(TimestampNs(100), TimestampNs(200))?),
        spatial_scope: Some("zone:gate".to_string()),
        privacy_class: "privacy:redacted".to_string(),
        applied_transform: None,
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(1_000_000),
        levels: levels.clone(),
        required_capabilities,
        estimated_costs,
        laboratory_access: fss_core::LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(50),
    };

    let handle = SemanticHandle::publish(spec)?;
    let h0 = handle.to_h0_identity()?;

    assert_eq!(h0.subject_id, "evidence:test:42");
    assert_eq!(h0.subject_digest, sample_digest(0x99));
    assert_eq!(h0.semantic_type, "evidence_packet");
    assert_eq!(h0.source_id, "sensor:ir-01");
    assert_eq!(h0.availability, HandleAvailability::Available);
    assert_eq!(h0.anchor.commit_sequence, 5);
    assert!(h0.requires_capability("cap:h0"));

    // Planted negative: handle without H0 level fails with LevelUnavailable
    let mut no_h0_levels = BTreeSet::new();
    no_h0_levels.insert(HydrationLevel::H1);
    let mut no_h0_handle = handle.clone();
    no_h0_handle.levels = no_h0_levels;
    let Err(err) = no_h0_handle.to_h0_identity() else {
        return Err("expected error on missing H0".into());
    };
    assert_eq!(err, HydrationError::LevelUnavailable);

    Ok(())
}

#[test]
fn test_h0_planted_negative_validation_failures() -> Result<(), Box<dyn Error>> {
    let base = sample_h0_params()?;

    // 1. Prohibited evidence promotion / raw bytes bypasses
    for prohibited in &[
        "raw_bytes",
        "decoded_frame",
        "payload_stream",
        "unredacted_media",
        "model_weights",
        "vlm_features",
    ] {
        let mut p = base.clone();
        p.semantic_type = format!("evidence_{prohibited}");
        let Err(err) = H0Identity::new(p) else {
            return Err("expected error for prohibited semantic type".into());
        };
        assert_eq!(
            err,
            HydrationError::Contract(ContractError::ProhibitedEvidencePromotion)
        );
    }

    // Prohibited in spatial_scope
    let mut p_scope = base.clone();
    p_scope.spatial_scope = Some("scope_contains_decoded_frame_data".to_string());
    let Err(err) = H0Identity::new(p_scope) else {
        return Err("expected error for prohibited spatial scope".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::ProhibitedEvidencePromotion)
    );

    // 2. Zero subject digest
    let mut p_zero = base.clone();
    p_zero.subject_digest = ContentDigest::new(DigestAlgorithm::Sha256, [0u8; 32]);
    let Err(err) = H0Identity::new(p_zero) else {
        return Err("expected error for zero subject digest".into());
    };
    assert_eq!(err, HydrationError::Contract(ContractError::InvalidDigest));

    // 3. Empty identifiers
    let mut p_h = base.clone();
    p_h.handle_id = "   ".to_string();
    let Err(err) = H0Identity::new(p_h) else {
        return Err("expected error for empty handle_id".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    let mut p_sub = base.clone();
    p_sub.subject_id = "".to_string();
    let Err(err) = H0Identity::new(p_sub) else {
        return Err("expected error for empty subject_id".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    let mut p_sem = base.clone();
    p_sem.semantic_type = " ".to_string();
    let Err(err) = H0Identity::new(p_sem) else {
        return Err("expected error for empty semantic_type".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    let mut p_src = base.clone();
    p_src.source_id = "".to_string();
    let Err(err) = H0Identity::new(p_src) else {
        return Err("expected error for empty source_id".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    let mut p_priv = base.clone();
    p_priv.privacy_class = "".to_string();
    let Err(err) = H0Identity::new(p_priv) else {
        return Err("expected error for empty privacy_class".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    let mut p_sp = base.clone();
    p_sp.spatial_scope = Some("  ".to_string());
    let Err(err) = H0Identity::new(p_sp) else {
        return Err("expected error for empty spatial_scope".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    let mut p_cap = base.clone();
    p_cap.required_capabilities.insert("".to_string());
    let Err(err) = H0Identity::new(p_cap) else {
        return Err("expected error for empty required_capability".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 4. Inverted retention (retention_until < published_at)
    let mut p_ret = base.clone();
    p_ret.published_at = TimestampNs(2_000_000);
    p_ret.retention_until = TimestampNs(1_000_000);
    let Err(err) = H0Identity::new(p_ret) else {
        return Err("expected error for inverted retention".into());
    };
    assert_eq!(err, HydrationError::ContinuationExpired);

    // 5. Empty anchor site lineage
    let mut p_anc = base.clone();
    p_anc.anchor.site_lineage = "".to_string();
    let Err(err) = H0Identity::new(p_anc) else {
        return Err("expected error for empty site_lineage".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 6. Empty contract basis semantic protocol
    let mut p_cb = base.clone();
    p_cb.contract_basis.semantic_protocol = "".to_string();
    let Err(err) = H0Identity::new(p_cb) else {
        return Err("expected error for empty semantic_protocol".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    Ok(())
}

#[test]
fn test_h0_canonical_roundtrip_and_deterministic_digest() -> Result<(), Box<dyn Error>> {
    let identity = H0Identity::new(sample_h0_params()?)?;

    // 1. Deterministic canonical digest
    let digest1 = identity.canonical_digest();
    let digest2 = identity.canonical_digest();
    assert_eq!(digest1, digest2);
    assert_ne!(digest1.bytes(), [0u8; 32]);

    // 2. Binary roundtrip via CanonicalEncode and CanonicalDecode
    let mut encoder = CanonicalEncoder::new();
    identity.encode_canonical(&mut encoder);
    assert!(!encoder.has_error());
    let bytes = encoder.finish();

    let decoded = H0Identity::from_canonical_bytes(&bytes)?;
    assert_eq!(identity, decoded);
    assert_eq!(decoded.canonical_digest(), digest1);

    // 3. Trailing garbage bytes rejected via ensure_finished
    let mut corrupted = bytes.clone();
    corrupted.push(0xFF);
    let mut dec = CanonicalDecoder::new(&corrupted);
    let _ = H0Identity::decode_canonical(&mut dec)?;
    let Err(finished_err) = dec.ensure_finished() else {
        return Err("expected error for trailing bytes".into());
    };
    assert_eq!(finished_err, ContractError::NonCanonicalOrdering);

    Ok(())
}

#[test]
fn test_h0_canonical_decode_invariants_and_planted_corruptions() -> Result<(), Box<dyn Error>> {
    let identity = H0Identity::new(sample_h0_params()?)?;

    let mut encoder = CanonicalEncoder::new();
    identity.encode_canonical(&mut encoder);
    let valid_bytes = encoder.finish();

    // 1. Wrong schema tag
    let mut wrong_schema_encoder = CanonicalEncoder::new();
    wrong_schema_encoder.text("fss.wrong_schema.v1");
    let wrong_schema_bytes = wrong_schema_encoder.finish();
    let mut dec = CanonicalDecoder::new(&wrong_schema_bytes);
    let Err(err) = H0Identity::decode_canonical(&mut dec) else {
        return Err("expected error for wrong schema".into());
    };
    assert_eq!(err, ContractError::InvalidIdentifier);

    // 2. Non-canonical ordering in capabilities set
    // Build a payload with capabilities out of order: ["z_cap", "a_cap"]
    let mut bad_caps_encoder = CanonicalEncoder::new();
    bad_caps_encoder.text(H0_SCHEMA);
    bad_caps_encoder.text(&identity.handle_id);
    bad_caps_encoder.text(&identity.subject_id);
    bad_caps_encoder.digest(identity.subject_digest);
    bad_caps_encoder.text(&identity.semantic_type);
    bad_caps_encoder.text(&identity.source_id);
    if let Some(ci) = identity.capture_interval {
        bad_caps_encoder.bool(true);
        ci.encode_canonical(&mut bad_caps_encoder);
    } else {
        bad_caps_encoder.bool(false);
    }
    bad_caps_encoder.bool(false); // spatial_scope None
    identity
        .availability
        .encode_canonical(&mut bad_caps_encoder);
    identity
        .estimated_cost
        .encode_canonical(&mut bad_caps_encoder);
    identity.anchor.encode_canonical(&mut bad_caps_encoder);
    identity
        .contract_basis
        .encode_canonical(&mut bad_caps_encoder);
    // Write 2 capabilities in reverse order
    bad_caps_encoder.u64(2);
    bad_caps_encoder.text("z_cap");
    bad_caps_encoder.text("a_cap");
    bad_caps_encoder.text(&identity.privacy_class);
    identity
        .published_at
        .encode_canonical(&mut bad_caps_encoder);
    identity
        .retention_until
        .encode_canonical(&mut bad_caps_encoder);

    let bad_caps_bytes = bad_caps_encoder.finish();
    let mut dec_caps = CanonicalDecoder::new(&bad_caps_bytes);
    let Err(ord_err) = H0Identity::decode_canonical(&mut dec_caps) else {
        return Err("expected error for non-canonical ordering".into());
    };
    assert_eq!(ord_err, ContractError::NonCanonicalOrdering);

    // 3. Truncated payload
    let truncated = &valid_bytes[..valid_bytes.len() / 2];
    let mut dec_trunc = CanonicalDecoder::new(truncated);
    let Err(trunc_err) = H0Identity::decode_canonical(&mut dec_trunc) else {
        return Err("expected error for truncated payload".into());
    };
    assert_eq!(trunc_err, ContractError::InvalidDigest);

    // 4. Mutant kill: decode_canonical validates and catches prohibited types
    let mut prohibited_encoder = CanonicalEncoder::new();
    prohibited_encoder.text(H0_SCHEMA);
    prohibited_encoder.text(&identity.handle_id);
    prohibited_encoder.text(&identity.subject_id);
    prohibited_encoder.digest(identity.subject_digest);
    prohibited_encoder.text("raw_bytes_stream"); // Prohibited!
    prohibited_encoder.text(&identity.source_id);
    prohibited_encoder.bool(false);
    prohibited_encoder.bool(false);
    identity
        .availability
        .encode_canonical(&mut prohibited_encoder);
    identity
        .estimated_cost
        .encode_canonical(&mut prohibited_encoder);
    identity.anchor.encode_canonical(&mut prohibited_encoder);
    identity
        .contract_basis
        .encode_canonical(&mut prohibited_encoder);
    prohibited_encoder.u64(0);
    prohibited_encoder.text(&identity.privacy_class);
    identity
        .published_at
        .encode_canonical(&mut prohibited_encoder);
    identity
        .retention_until
        .encode_canonical(&mut prohibited_encoder);

    let proh_bytes = prohibited_encoder.finish();
    let mut dec_proh = CanonicalDecoder::new(&proh_bytes);
    let Err(proh_err) = H0Identity::decode_canonical(&mut dec_proh) else {
        return Err("expected error for prohibited evidence promotion".into());
    };
    assert_eq!(proh_err, ContractError::ProhibitedEvidencePromotion);

    Ok(())
}

#[test]
fn test_handle_availability_all_variants_and_roundtrip() -> Result<(), Box<dyn Error>> {
    assert_eq!(HandleAvailability::ALL.len(), 7);

    for &avail in &HandleAvailability::ALL {
        let spelling = avail.as_str();
        assert!(!spelling.is_empty());

        // Parse roundtrip
        let parsed: HandleAvailability = spelling.parse()?;
        assert_eq!(parsed, avail);

        // Display
        assert_eq!(format!("{avail}"), spelling);

        // Canonical roundtrip
        let mut encoder = CanonicalEncoder::new();
        avail.encode_canonical(&mut encoder);
        let bytes = encoder.finish();

        let mut decoder = CanonicalDecoder::new(&bytes);
        let decoded = HandleAvailability::decode_canonical(&mut decoder)?;
        assert_eq!(decoded, avail);
    }

    // Completeness mappings
    assert_eq!(
        HandleAvailability::Available.unavailable_completeness(),
        Completeness::Complete
    );
    assert_eq!(
        HandleAvailability::Superseded.unavailable_completeness(),
        Completeness::Stale
    );
    assert_eq!(
        HandleAvailability::Expired.unavailable_completeness(),
        Completeness::Stale
    );
    assert_eq!(
        HandleAvailability::Deleted.unavailable_completeness(),
        Completeness::NotObservable
    );
    assert_eq!(
        HandleAvailability::Corrupt.unavailable_completeness(),
        Completeness::NotObservable
    );
    assert_eq!(
        HandleAvailability::NotObservable.unavailable_completeness(),
        Completeness::NotObservable
    );
    assert_eq!(
        HandleAvailability::PrivacyTransformed.unavailable_completeness(),
        Completeness::Unauthorized
    );

    // Planted negative: invalid availability spelling
    let Err(err) = "nonexistent_state".parse::<HandleAvailability>() else {
        return Err("expected error for nonexistent_state".into());
    };
    assert_eq!(err, ContractError::InvalidIdentifier);

    Ok(())
}

#[test]
fn test_hydration_level_codec_and_monotonicity() -> Result<(), Box<dyn Error>> {
    assert_eq!(HydrationLevel::ALL.len(), 5);

    // Monotonic ladder
    assert!(HydrationLevel::H0 < HydrationLevel::H1);
    assert!(HydrationLevel::H1 < HydrationLevel::H2);
    assert!(HydrationLevel::H2 < HydrationLevel::H3);
    assert!(HydrationLevel::H3 < HydrationLevel::H4);

    for &level in &HydrationLevel::ALL {
        let spelling = level.as_str();

        // Parse roundtrip
        let parsed: HydrationLevel = spelling.parse()?;
        assert_eq!(parsed, level);

        // Canonical roundtrip
        let mut encoder = CanonicalEncoder::new();
        level.encode_canonical(&mut encoder);
        let bytes = encoder.finish();

        let mut decoder = CanonicalDecoder::new(&bytes);
        let decoded = HydrationLevel::decode_canonical(&mut decoder)?;
        assert_eq!(decoded, level);
    }

    Ok(())
}
