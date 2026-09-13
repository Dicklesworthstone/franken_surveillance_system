#![forbid(unsafe_code)]
//! Deterministic contract tests for hydration ladder level H0: identity (AGT-H0, fss-x4a.30.82.12).
//!
//! Enforces:
//! 1. Normative row identity and properties from registries/AGENT_ABSTRACTIONS.md
//! 2. Content completeness: digest, type, time/spatial bounds, source, availability, cost, and authority
//! 3. Pure metadata invariant: strictly prohibits raw bytes, decoded frames, and ungrounded cognition (structural normalization)
//! 4. Invariant enforcement & planted bypasses (zero digest, inverted time, empty IDs, expired retention, control characters, text bounding)
//! 5. Deterministic canonical binary encoding & decoding with exact roundtrip and canonical ordering
//! 6. Mutant kills: M3 (inverted capture interval), M5b (duplicate capabilities: >= -> >), M8 (expiry boundary: > -> >=)
//! 7. HandleAvailability state machine, exact matching (no whitespace or aliases), and completeness mappings
//! 8. Integration with SemanticHandle extraction (with verify(), typed error mappings, and swapped digest rejection)
//! 9. Pinned golden digest literal and canonical byte vector stability

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use fss_core::{
    BudgetVector, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    CaptureInterval, Completeness, ContentDigest, ContractBasis, ContractBasisRegistryBytes,
    ContractError, DigestAlgorithm, H0_CONTENT, H0_LEVEL_ID, H0_LEVEL_NAME, H0_SCHEMA,
    H0_SEMANTIC_OWNER, H0Identity, H0IdentityParams, HandleAvailability, HydrationError,
    HydrationLevel, LedgerAnchor, SEMANTIC_HYDRATION_OWNER, SemanticHandle, SemanticHandleSpec,
    TimestampNs, is_valid_h0_screened_field,
};

fn sample_basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
        b"schemas",
        b"operations",
        b"views",
        b"capabilities",
        b"errors",
        b"costs",
        "fss/1",
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

    let subject_id = "evidence:pkg-42".to_string();
    let subject_digest = sample_digest(0x42);
    let semantic_type = "evidence_bundle".to_string();
    let source_id = "sensor:cam-front-01".to_string();
    let capture_interval = Some(CaptureInterval::new(
        TimestampNs(1_000_000_000),
        TimestampNs(1_000_000_100),
    )?);
    let spatial_scope = Some("zone:perimeter:north".to_string());
    let applied_transform = None;

    let identity_digest = H0Identity::compute_identity_digest(
        &subject_id,
        subject_digest,
        &semantic_type,
        &source_id,
        capture_interval,
        spatial_scope.as_deref(),
        applied_transform.as_deref(),
    )?;
    let handle_id = format!("semantic-handle:{identity_digest}");

    Ok(H0IdentityParams {
        handle_id,
        subject_id,
        subject_digest,
        semantic_type,
        source_id,
        capture_interval,
        spatial_scope,
        applied_transform,
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

    // 3. HydrationLevel enum mappings & registered crate owners (Item 6)
    let level = HydrationLevel::H0;
    assert_eq!(level.as_str(), "H0");
    assert_eq!(level.level_id(), "H0");
    assert_eq!(level.level_name(), "identity");
    assert_eq!(level.content(), H0_CONTENT);
    assert_eq!(level.owner(), SEMANTIC_HYDRATION_OWNER);
    assert_eq!(level.ordinal(), 0);

    // Verify crate owners: all levels return fss-agent-core per architecture/semantic_hydration.json
    assert_eq!(HydrationLevel::H0.owner(), "fss-agent-core");
    assert_eq!(HydrationLevel::H1.owner(), "fss-agent-core");
    assert_eq!(HydrationLevel::H2.owner(), "fss-agent-core");
    assert_eq!(HydrationLevel::H3.owner(), "fss-agent-core");
    assert_eq!(HydrationLevel::H4.owner(), "fss-agent-core");
    assert_eq!(H0_SEMANTIC_OWNER, "fss-agent-core");

    // 4. FromStr exact resolution (Item 2: exact match only, no aliases, no trim)
    assert_eq!("H0".parse::<HydrationLevel>()?, HydrationLevel::H0);
    assert_eq!("H1".parse::<HydrationLevel>()?, HydrationLevel::H1);
    assert_eq!("H2".parse::<HydrationLevel>()?, HydrationLevel::H2);
    assert_eq!("H3".parse::<HydrationLevel>()?, HydrationLevel::H3);
    assert_eq!("H4".parse::<HydrationLevel>()?, HydrationLevel::H4);

    // Planted negatives: lowercase, aliases, whitespace fail with InvalidIdentifier
    for bad in &[
        "h0", "identity", " H0 ", "H0\t", "H0\n", "H99", "h1", "h2", "h3", "h4", "H0 ", " H0",
    ] {
        let Err(err) = bad.parse::<HydrationLevel>() else {
            return Err(format!("expected error on {bad}").into());
        };
        assert_eq!(err, ContractError::InvalidIdentifier);
    }

    Ok(())
}

#[test]
fn test_h0_direct_construction_and_accessors() -> Result<(), Box<dyn Error>> {
    let params = sample_h0_params()?;
    let identity = H0Identity::new(params.clone())?;

    // Verify all 7 normative dimensions are queryable via accessors (Item 4):
    // 1. digest
    assert_eq!(identity.subject_digest(), params.subject_digest);
    // 2. type
    assert_eq!(identity.semantic_type(), "evidence_bundle");
    // 3. time and spatial bounds
    assert_eq!(identity.capture_interval(), params.capture_interval);
    assert_eq!(identity.spatial_scope(), Some("zone:perimeter:north"));
    assert_eq!(identity.applied_transform(), None);
    // 4. source
    assert_eq!(identity.source_id(), "sensor:cam-front-01");
    // 5. availability
    assert_eq!(identity.availability(), HandleAvailability::Available);
    // 6. cost
    assert_eq!(identity.estimated_cost(), params.estimated_cost);
    // 7. authority (anchor + contract_basis)
    assert_eq!(identity.anchor(), &params.anchor);
    assert_eq!(identity.contract_basis(), &params.contract_basis);
    assert_eq!(identity.handle_id(), params.handle_id);
    assert_eq!(identity.subject_id(), "evidence:pkg-42");
    assert_eq!(identity.privacy_class(), "privacy:operational_metadata");
    assert_eq!(identity.published_at(), params.published_at);
    assert_eq!(identity.retention_until(), params.retention_until);

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

    assert_eq!(h0.subject_id(), "evidence:test:42");
    assert_eq!(h0.subject_digest(), sample_digest(0x99));
    assert_eq!(h0.semantic_type(), "evidence_packet");
    assert_eq!(h0.source_id(), "sensor:ir-01");
    assert_eq!(h0.availability(), HandleAvailability::Available);
    assert_eq!(h0.anchor().commit_sequence, 5);
    assert!(h0.requires_capability("cap:h0"));

    // Planted negative: handle without H0 level fails with LevelUnavailable (Item 3)
    let mut no_h0_handle = handle.clone();
    no_h0_handle.levels = BTreeSet::from([HydrationLevel::H1]);
    let Err(err) = no_h0_handle.to_h0_identity() else {
        return Err("expected error on missing H0 level".into());
    };
    assert_eq!(err, HydrationError::LevelUnavailable);

    // Planted negative: missing H0 cost returns LevelUnavailable (Item 3)
    let mut no_cost_handle = handle.clone();
    no_cost_handle.estimated_costs.remove(&HydrationLevel::H0);
    let Err(err) = no_cost_handle.to_h0_identity() else {
        return Err("expected error on missing H0 cost".into());
    };
    assert_eq!(err, HydrationError::LevelUnavailable);

    // Planted negative: missing H0 capabilities returns LevelUnavailable (Item 3)
    let mut no_caps_handle = handle.clone();
    no_caps_handle
        .required_capabilities
        .remove(&HydrationLevel::H0);
    let Err(err) = no_caps_handle.to_h0_identity() else {
        return Err("expected error on missing H0 capabilities".into());
    };
    assert_eq!(err, HydrationError::LevelUnavailable);

    // Planted negative: swapped subject_digest is rejected via handle verification / binding (Item 3)
    let mut swapped_handle = handle.clone();
    swapped_handle.subject_digest = sample_digest(0xEE);
    let Err(err) = swapped_handle.to_h0_identity() else {
        return Err("expected error on swapped subject digest".into());
    };
    assert_eq!(err, HydrationError::HandleRebound);

    // Planted negatives: tamper fields ONLY caught by handle.verify() (Item 1 mutant kill)
    // 1. Tampered privacy_class (leaves identity_digest unchanged, fails descriptor_digest)
    let mut tampered_privacy = handle.clone();
    tampered_privacy.privacy_class = "privacy:tampered".to_string();
    let Err(err) = tampered_privacy.to_h0_identity() else {
        return Err("expected error on tampered privacy class".into());
    };
    assert_eq!(err, HydrationError::Contract(ContractError::DigestMismatch));

    // 2. Tampered retention_until (leaves identity_digest unchanged, fails descriptor_digest)
    let mut tampered_retention = handle.clone();
    tampered_retention.retention_until = TimestampNs(9_999_999);
    let Err(err) = tampered_retention.to_h0_identity() else {
        return Err("expected error on tampered retention".into());
    };
    assert_eq!(err, HydrationError::Contract(ContractError::DigestMismatch));

    // 3. Tampered estimated_costs entry (leaves identity_digest unchanged, fails descriptor_digest)
    let mut tampered_cost = handle.clone();
    let mut modified_costs = tampered_cost.estimated_costs.clone();
    let modified_budget = BudgetVector::builder()
        .latency_ms(99)
        .tokens(50)
        .bytes(512)
        .cpu_millis(10)
        .privacy_exposure(0.05)
        .build()?;
    modified_costs.insert(HydrationLevel::H0, modified_budget);
    tampered_cost.estimated_costs = modified_costs;
    let Err(err) = tampered_cost.to_h0_identity() else {
        return Err("expected error on tampered estimated cost".into());
    };
    assert_eq!(err, HydrationError::Contract(ContractError::DigestMismatch));

    Ok(())
}

#[test]
fn test_h0_planted_negative_validation_failures() -> Result<(), Box<dyn Error>> {
    let base = sample_h0_params()?;

    // 1. Prohibited evidence promotion / raw bytes bypasses with structural normalization (Item 8)
    for prohibited in &[
        "raw_bytes",
        "raw bytes",
        "rawbytes",
        "RAW_BYTES",
        "decoded frame",
        "decoded_frame",
        "payload stream",
        "raw_payload",
        "decoded_image",
        "full_resolution_media",
        "original_encoded_packets",
        "object_bytes",
        "pixel_buffer",
        "keyframe_crops",
        "r\u{0430}w_bytes",
    ] {
        let mut p = base.clone();
        p.semantic_type = format!("evidence_{prohibited}");
        let digest = H0Identity::compute_identity_digest(
            &p.subject_id,
            p.subject_digest,
            &p.semantic_type,
            &p.source_id,
            p.capture_interval,
            p.spatial_scope.as_deref(),
            p.applied_transform.as_deref(),
        )?;
        p.handle_id = format!("semantic-handle:{digest}");
        let Err(err) = H0Identity::new(p) else {
            return Err("expected error for prohibited semantic type".into());
        };
        assert_eq!(
            err,
            HydrationError::Contract(ContractError::ProhibitedEvidencePromotion)
        );
    }

    // Prohibited terms screened in subject_id, source_id, privacy_class, spatial_scope, applied_transform
    // Cyrillic homoglyph in subject_id
    let mut p_homo_sub = base.clone();
    p_homo_sub.subject_id = "evidence:sensor:r\u{0430}w_bytes:1".to_string();
    let digest = H0Identity::compute_identity_digest(
        &p_homo_sub.subject_id,
        p_homo_sub.subject_digest,
        &p_homo_sub.semantic_type,
        &p_homo_sub.source_id,
        p_homo_sub.capture_interval,
        p_homo_sub.spatial_scope.as_deref(),
        p_homo_sub.applied_transform.as_deref(),
    )?;
    p_homo_sub.handle_id = format!("semantic-handle:{digest}");
    let Err(err) = H0Identity::new(p_homo_sub) else {
        return Err("expected error for Cyrillic raw_bytes homoglyph in subject_id".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::ProhibitedEvidencePromotion)
    );

    // Prohibited term in source_id
    let mut p_src_proh = base.clone();
    p_src_proh.source_id = "sensor:decoded_image:01".to_string();
    let digest = H0Identity::compute_identity_digest(
        &p_src_proh.subject_id,
        p_src_proh.subject_digest,
        &p_src_proh.semantic_type,
        &p_src_proh.source_id,
        p_src_proh.capture_interval,
        p_src_proh.spatial_scope.as_deref(),
        p_src_proh.applied_transform.as_deref(),
    )?;
    p_src_proh.handle_id = format!("semantic-handle:{digest}");
    let Err(err) = H0Identity::new(p_src_proh) else {
        return Err("expected error for prohibited term in source_id".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::ProhibitedEvidencePromotion)
    );

    // Prohibited term in privacy_class
    let mut p_priv_proh = base.clone();
    p_priv_proh.privacy_class = "privacy:raw_payload:unredacted".to_string();
    let digest = H0Identity::compute_identity_digest(
        &p_priv_proh.subject_id,
        p_priv_proh.subject_digest,
        &p_priv_proh.semantic_type,
        &p_priv_proh.source_id,
        p_priv_proh.capture_interval,
        p_priv_proh.spatial_scope.as_deref(),
        p_priv_proh.applied_transform.as_deref(),
    )?;
    p_priv_proh.handle_id = format!("semantic-handle:{digest}");
    let Err(err) = H0Identity::new(p_priv_proh) else {
        return Err("expected error for prohibited term in privacy_class".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::ProhibitedEvidencePromotion)
    );

    // Prohibited in spatial_scope
    let mut p_scope = base.clone();
    p_scope.spatial_scope = Some("scope_contains_decoded_frame_data".to_string());
    let digest = H0Identity::compute_identity_digest(
        &p_scope.subject_id,
        p_scope.subject_digest,
        &p_scope.semantic_type,
        &p_scope.source_id,
        p_scope.capture_interval,
        p_scope.spatial_scope.as_deref(),
        p_scope.applied_transform.as_deref(),
    )?;
    p_scope.handle_id = format!("semantic-handle:{digest}");
    let Err(err) = H0Identity::new(p_scope) else {
        return Err("expected error for prohibited spatial scope".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::ProhibitedEvidencePromotion)
    );

    // Prohibited in applied_transform
    let mut p_trans = base.clone();
    p_trans.applied_transform = Some("raw bytes transform".to_string());
    let digest = H0Identity::compute_identity_digest(
        &p_trans.subject_id,
        p_trans.subject_digest,
        &p_trans.semantic_type,
        &p_trans.source_id,
        p_trans.capture_interval,
        p_trans.spatial_scope.as_deref(),
        p_trans.applied_transform.as_deref(),
    )?;
    p_trans.handle_id = format!("semantic-handle:{digest}");
    let Err(err) = H0Identity::new(p_trans) else {
        return Err("expected error for prohibited applied transform".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::ProhibitedEvidencePromotion)
    );

    // Allowed valid spatial_scope test
    let mut p_allowed = base.clone();
    p_allowed.spatial_scope = Some("zone:safe_metric_01".to_string());
    let digest_allowed = H0Identity::compute_identity_digest(
        &p_allowed.subject_id,
        p_allowed.subject_digest,
        &p_allowed.semantic_type,
        &p_allowed.source_id,
        p_allowed.capture_interval,
        p_allowed.spatial_scope.as_deref(),
        p_allowed.applied_transform.as_deref(),
    )?;
    p_allowed.handle_id = format!("semantic-handle:{digest_allowed}");
    let allowed_res = H0Identity::new(p_allowed);
    assert!(allowed_res.is_ok());

    // Decision 2(c): harmless name "straw_bytes_metric" pinned to fail closed (stripped contains rawbytes)
    let mut p_straw = base.clone();
    p_straw.spatial_scope = Some("zone:straw_bytes_metric".to_string());
    let digest_straw = H0Identity::compute_identity_digest(
        &p_straw.subject_id,
        p_straw.subject_digest,
        &p_straw.semantic_type,
        &p_straw.source_id,
        p_straw.capture_interval,
        p_straw.spatial_scope.as_deref(),
        p_straw.applied_transform.as_deref(),
    )?;
    p_straw.handle_id = format!("semantic-handle:{digest_straw}");
    let Err(err) = H0Identity::new(p_straw) else {
        return Err("expected straw_bytes_metric to fail closed".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::ProhibitedEvidencePromotion)
    );

    // 2. Zero subject digest
    let mut p_zero = base.clone();
    p_zero.subject_digest = ContentDigest::new(DigestAlgorithm::Sha256, [0u8; 32]);
    let digest = H0Identity::compute_identity_digest(
        &p_zero.subject_id,
        p_zero.subject_digest,
        &p_zero.semantic_type,
        &p_zero.source_id,
        p_zero.capture_interval,
        p_zero.spatial_scope.as_deref(),
        p_zero.applied_transform.as_deref(),
    )?;
    p_zero.handle_id = format!("semantic-handle:{digest}");
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

    // 4. Inverted retention (retention_until <= published_at) returns InvertedTimeInterval (Item 4 & 7)
    let mut p_ret_lt = base.clone();
    p_ret_lt.published_at = TimestampNs(2_000_000);
    p_ret_lt.retention_until = TimestampNs(1_000_000);
    let Err(err) = H0Identity::new(p_ret_lt) else {
        return Err("expected error for retention < published".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvertedTimeInterval)
    );

    let mut p_ret_eq = base.clone();
    p_ret_eq.published_at = TimestampNs(2_000_000);
    p_ret_eq.retention_until = TimestampNs(2_000_000);
    let Err(err) = H0Identity::new(p_ret_eq) else {
        return Err("expected error for retention == published".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvertedTimeInterval)
    );

    // 5. Control, C1, and bidi characters rejected (Item 4, N-3)
    for bad_str in &[
        "invalid\x00null",
        "invalid\x1b[31mansi",
        "invalid\nnewline",
        "invalid\ttab",
        "invalid\rcarriage",
        "invalid\u{0080}c1_start",
        "invalid\u{009F}c1_end",
        "invalid\u{202A}bidi_lre",
        "invalid\u{202B}bidi_rle",
        "invalid\u{202C}bidi_pdf",
        "invalid\u{202D}bidi_lro",
        "invalid\u{202E}bidi_rlo",
        "invalid\u{2066}bidi_lri",
        "invalid\u{2067}bidi_rli",
        "invalid\u{2068}bidi_fsi",
        "invalid\u{2069}bidi_pdi",
    ] {
        let mut p_ctrl = base.clone();
        p_ctrl.subject_id = (*bad_str).to_string();
        let Err(err) = H0Identity::new(p_ctrl) else {
            return Err(format!("expected error for control char: {bad_str}").into());
        };
        assert_eq!(
            err,
            HydrationError::Contract(ContractError::InvalidIdentifier)
        );
    }

    // 6. Anchor site lineage validation (Item 4, N-2)
    // Empty site_lineage fails
    let mut p_anc = base.clone();
    p_anc.anchor.site_lineage = "".to_string();
    let Err(err) = H0Identity::new(p_anc) else {
        return Err("expected error for empty site_lineage".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 70 KB site_lineage fails
    let mut p_anc_70k = base.clone();
    p_anc_70k.anchor.site_lineage = "a".repeat(70_000);
    let Err(err) = H0Identity::new(p_anc_70k) else {
        return Err("expected error for 70 KB site_lineage".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 6b. ContractBasis validation (Item 4, N-4)
    let mut p_cb_empty_prod = base.clone();
    p_cb_empty_prod.contract_basis.producer_release_id = "".to_string();
    let Err(err) = H0Identity::new(p_cb_empty_prod) else {
        return Err("expected error for empty producer_release_id".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    let mut p_cb_empty_ont = base.clone();
    p_cb_empty_ont.contract_basis.ontology_generation_id = "   ".to_string();
    let Err(err) = H0Identity::new(p_cb_empty_ont) else {
        return Err("expected error for empty ontology_generation_id".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 7. Semantic protocol must be exact "fss/1" (Item 4)
    let mut p_proto = base.clone();
    p_proto.contract_basis.semantic_protocol = "fss:custom".to_string();
    let Err(err) = H0Identity::new(p_proto) else {
        return Err("expected error for non-fss/1 protocol".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 8. Rebound handle_id returns HandleRebound (Item 4)
    let mut p_rebound = base.clone();
    p_rebound.handle_id = "semantic-handle:arbitrary-text-not-bound-to-digest".to_string();
    let Err(err) = H0Identity::new(p_rebound) else {
        return Err("expected error for rebound handle_id".into());
    };
    assert_eq!(err, HydrationError::HandleRebound);

    Ok(())
}

#[test]
fn test_h0_canonical_roundtrip_and_deterministic_digest() -> Result<(), Box<dyn Error>> {
    let identity = H0Identity::new(sample_h0_params()?)?;

    // 1. Deterministic canonical digest
    let digest1 = identity.canonical_digest()?;
    let digest2 = identity.canonical_digest()?;
    assert_eq!(digest1, digest2);
    assert_ne!(digest1.bytes(), [0u8; 32]);

    // 2. Binary roundtrip via CanonicalEncode and CanonicalDecode
    let mut encoder = CanonicalEncoder::new();
    identity.encode_canonical(&mut encoder);
    assert!(!encoder.has_error());
    let bytes = encoder.finish_checked()?;

    let decoded = H0Identity::from_canonical_bytes(&bytes)?;
    assert_eq!(identity, decoded);
    assert_eq!(decoded.canonical_digest()?, digest1);

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
    let valid_bytes = encoder.finish_checked()?;

    // 1. Wrong schema tag
    let mut wrong_schema_encoder = CanonicalEncoder::new();
    wrong_schema_encoder.text("fss.wrong_schema.v1");
    let wrong_schema_bytes = wrong_schema_encoder.finish_checked()?;
    let mut dec = CanonicalDecoder::new(&wrong_schema_bytes);
    let Err(err) = H0Identity::decode_canonical(&mut dec) else {
        return Err("expected error for wrong schema".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 2. Non-canonical ordering in capabilities set
    // Build a payload with capabilities out of order: ["z_cap", "a_cap"]
    let mut bad_caps_encoder = CanonicalEncoder::new();
    bad_caps_encoder.text(H0_SCHEMA);
    bad_caps_encoder.text(identity.handle_id());
    bad_caps_encoder.text(identity.subject_id());
    bad_caps_encoder.digest(identity.subject_digest());
    bad_caps_encoder.text(identity.semantic_type());
    bad_caps_encoder.text(identity.source_id());
    if let Some(ci) = identity.capture_interval() {
        bad_caps_encoder.bool(true);
        ci.encode_canonical(&mut bad_caps_encoder);
    } else {
        bad_caps_encoder.bool(false);
    }
    if let Some(scope) = identity.spatial_scope() {
        bad_caps_encoder.bool(true);
        bad_caps_encoder.text(scope);
    } else {
        bad_caps_encoder.bool(false);
    }
    if let Some(transform) = identity.applied_transform() {
        bad_caps_encoder.bool(true);
        bad_caps_encoder.text(transform);
    } else {
        bad_caps_encoder.bool(false);
    }
    identity
        .availability()
        .encode_canonical(&mut bad_caps_encoder);
    identity
        .estimated_cost()
        .encode_canonical(&mut bad_caps_encoder);
    identity.anchor().encode_canonical(&mut bad_caps_encoder);
    identity
        .contract_basis()
        .encode_canonical(&mut bad_caps_encoder);
    // Write 2 capabilities in reverse order
    bad_caps_encoder.u64(2);
    bad_caps_encoder.text("z_cap");
    bad_caps_encoder.text("a_cap");
    bad_caps_encoder.text(identity.privacy_class());
    identity
        .published_at()
        .encode_canonical(&mut bad_caps_encoder);
    identity
        .retention_until()
        .encode_canonical(&mut bad_caps_encoder);

    let bad_caps_bytes = bad_caps_encoder.finish_checked()?;
    let mut dec_caps = CanonicalDecoder::new(&bad_caps_bytes);
    let Err(ord_err) = H0Identity::decode_canonical(&mut dec_caps) else {
        return Err("expected error for non-canonical ordering".into());
    };
    assert_eq!(
        ord_err,
        HydrationError::Contract(ContractError::NonCanonicalOrdering)
    );

    // 3. Truncated payload returns Truncated (Item 6)
    let truncated = &valid_bytes[..valid_bytes.len() / 2];
    let mut dec_trunc = CanonicalDecoder::new(truncated);
    let Err(trunc_err) = H0Identity::decode_canonical(&mut dec_trunc) else {
        return Err("expected error for truncated payload".into());
    };
    assert_eq!(trunc_err, HydrationError::Truncated);

    // 4. Mutant kill: decode_canonical validates and catches prohibited types (structural check)
    let proh_type = "evidence_bundle";
    let proh_source_id = "sensor:raw_payload_stream";
    let proh_digest = H0Identity::compute_identity_digest(
        identity.subject_id(),
        identity.subject_digest(),
        proh_type,
        proh_source_id,
        None,
        None,
        None,
    )?;
    let proh_handle_id = format!("semantic-handle:{proh_digest}");

    let mut prohibited_encoder = CanonicalEncoder::new();
    prohibited_encoder.text(H0_SCHEMA);
    prohibited_encoder.text(&proh_handle_id);
    prohibited_encoder.text(identity.subject_id());
    prohibited_encoder.digest(identity.subject_digest());
    prohibited_encoder.text(proh_type);
    prohibited_encoder.text(proh_source_id);
    prohibited_encoder.bool(false);
    prohibited_encoder.bool(false);
    prohibited_encoder.bool(false);
    identity
        .availability()
        .encode_canonical(&mut prohibited_encoder);
    identity
        .estimated_cost()
        .encode_canonical(&mut prohibited_encoder);
    identity.anchor().encode_canonical(&mut prohibited_encoder);
    identity
        .contract_basis()
        .encode_canonical(&mut prohibited_encoder);
    prohibited_encoder.u64(0);
    prohibited_encoder.text(identity.privacy_class());
    identity
        .published_at()
        .encode_canonical(&mut prohibited_encoder);
    identity
        .retention_until()
        .encode_canonical(&mut prohibited_encoder);

    let proh_bytes = prohibited_encoder.finish_checked()?;
    let mut dec_proh = CanonicalDecoder::new(&proh_bytes);
    let Err(proh_err) = H0Identity::decode_canonical(&mut dec_proh) else {
        return Err("expected error for prohibited evidence promotion".into());
    };
    assert_eq!(
        proh_err,
        HydrationError::Contract(ContractError::ProhibitedEvidencePromotion)
    );

    // 5. Inverted retention decoded from binary returns InvertedTimeInterval (Item 7)
    let mut inv_ret_encoder = CanonicalEncoder::new();
    inv_ret_encoder.text(H0_SCHEMA);
    inv_ret_encoder.text(identity.handle_id());
    inv_ret_encoder.text(identity.subject_id());
    inv_ret_encoder.digest(identity.subject_digest());
    inv_ret_encoder.text(identity.semantic_type());
    inv_ret_encoder.text(identity.source_id());
    if let Some(ci) = identity.capture_interval() {
        inv_ret_encoder.bool(true);
        ci.encode_canonical(&mut inv_ret_encoder);
    } else {
        inv_ret_encoder.bool(false);
    }
    if let Some(scope) = identity.spatial_scope() {
        inv_ret_encoder.bool(true);
        inv_ret_encoder.text(scope);
    } else {
        inv_ret_encoder.bool(false);
    }
    if let Some(transform) = identity.applied_transform() {
        inv_ret_encoder.bool(true);
        inv_ret_encoder.text(transform);
    } else {
        inv_ret_encoder.bool(false);
    }
    identity
        .availability()
        .encode_canonical(&mut inv_ret_encoder);
    identity
        .estimated_cost()
        .encode_canonical(&mut inv_ret_encoder);
    identity.anchor().encode_canonical(&mut inv_ret_encoder);
    identity
        .contract_basis()
        .encode_canonical(&mut inv_ret_encoder);
    inv_ret_encoder.u64(0);
    inv_ret_encoder.text(identity.privacy_class());
    TimestampNs(2_000_000).encode_canonical(&mut inv_ret_encoder);
    TimestampNs(1_000_000).encode_canonical(&mut inv_ret_encoder);

    let inv_ret_bytes = inv_ret_encoder.finish_checked()?;
    let mut dec_inv_ret = CanonicalDecoder::new(&inv_ret_bytes);
    let Err(inv_err) = H0Identity::decode_canonical(&mut dec_inv_ret) else {
        return Err("expected error for inverted retention".into());
    };
    assert_eq!(
        inv_err,
        HydrationError::Contract(ContractError::InvertedTimeInterval)
    );

    // 6. decode_text_set over-count returns CapacityExceeded (Item 6 & 7)
    let mut over_caps_encoder = CanonicalEncoder::new();
    over_caps_encoder.text(H0_SCHEMA);
    over_caps_encoder.text(identity.handle_id());
    over_caps_encoder.text(identity.subject_id());
    over_caps_encoder.digest(identity.subject_digest());
    over_caps_encoder.text(identity.semantic_type());
    over_caps_encoder.text(identity.source_id());
    over_caps_encoder.bool(false);
    over_caps_encoder.bool(false);
    over_caps_encoder.bool(false);
    identity
        .availability()
        .encode_canonical(&mut over_caps_encoder);
    identity
        .estimated_cost()
        .encode_canonical(&mut over_caps_encoder);
    identity.anchor().encode_canonical(&mut over_caps_encoder);
    identity
        .contract_basis()
        .encode_canonical(&mut over_caps_encoder);
    over_caps_encoder.u64(2000); // Exceeds MAX_REQUEST_SET_ITEMS (1024)
    over_caps_encoder.text(identity.privacy_class());
    identity
        .published_at()
        .encode_canonical(&mut over_caps_encoder);
    identity
        .retention_until()
        .encode_canonical(&mut over_caps_encoder);

    let over_bytes = over_caps_encoder.finish_checked()?;
    let mut dec_over = CanonicalDecoder::new(&over_bytes);
    let Err(over_err) = H0Identity::decode_canonical(&mut dec_over) else {
        return Err("expected error for over-count capabilities".into());
    };
    assert_eq!(over_err, HydrationError::CapacityExceeded);

    // 7. HandleRebound during decode preserves HandleRebound variant (Item 6)
    let mut rebound_encoder = CanonicalEncoder::new();
    rebound_encoder.text(H0_SCHEMA);
    rebound_encoder.text("semantic-handle:tampered-not-bound-to-digest");
    rebound_encoder.text(identity.subject_id());
    rebound_encoder.digest(identity.subject_digest());
    rebound_encoder.text(identity.semantic_type());
    rebound_encoder.text(identity.source_id());
    rebound_encoder.bool(false);
    rebound_encoder.bool(false);
    rebound_encoder.bool(false);
    identity
        .availability()
        .encode_canonical(&mut rebound_encoder);
    identity
        .estimated_cost()
        .encode_canonical(&mut rebound_encoder);
    identity.anchor().encode_canonical(&mut rebound_encoder);
    identity
        .contract_basis()
        .encode_canonical(&mut rebound_encoder);
    rebound_encoder.u64(0);
    rebound_encoder.text(identity.privacy_class());
    identity
        .published_at()
        .encode_canonical(&mut rebound_encoder);
    identity
        .retention_until()
        .encode_canonical(&mut rebound_encoder);

    let rebound_bytes = rebound_encoder.finish_checked()?;
    let mut dec_rebound = CanonicalDecoder::new(&rebound_bytes);
    let Err(rebound_err) = H0Identity::decode_canonical(&mut dec_rebound) else {
        return Err("expected error for rebound handle in decode".into());
    };
    assert_eq!(rebound_err, HydrationError::HandleRebound);

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
        let bytes = encoder.finish_checked()?;

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

    // Planted negatives: invalid availability spelling and non-exact strings (Item 2)
    for bad in &[
        "nonexistent_state",
        " available\t",
        "available ",
        " available",
        "Available",
        "AVAILABLE",
        "superseded ",
        "deleted\n",
    ] {
        let Err(err) = bad.parse::<HandleAvailability>() else {
            return Err(format!("expected error for {bad}").into());
        };
        assert_eq!(err, ContractError::InvalidIdentifier);
    }

    // Decode-level negative tests for HandleAvailability (Item 3)
    for bad in &[
        " available\t",
        "available ",
        " available",
        "Available",
        "AVAILABLE",
        "superseded ",
        "deleted\n",
        "\u{FEFF}available",
        "\u{FF41}\u{FF56}\u{FF41}\u{FF49}\u{FF4C}\u{FF41}\u{FF42}\u{FF4C}\u{FF45}",
        "nonexistent_state",
    ] {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(bad);
        let bytes = encoder.finish_checked()?;
        let mut decoder = CanonicalDecoder::new(&bytes);
        let res = HandleAvailability::decode_canonical(&mut decoder);
        assert_eq!(res, Err(ContractError::InvalidIdentifier));
    }

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
        let bytes = encoder.finish_checked()?;

        let mut decoder = CanonicalDecoder::new(&bytes);
        let decoded = HydrationLevel::decode_canonical(&mut decoder)?;
        assert_eq!(decoded, level);

        // Verify encode(decode(b)) == b invariant (Item 2)
        let mut re_encoder = CanonicalEncoder::new();
        decoded.encode_canonical(&mut re_encoder);
        let re_bytes = re_encoder.finish_checked()?;
        assert_eq!(bytes, re_bytes);
    }

    // Decode-level negative tests for HydrationLevel (Item 3)
    for bad in &[
        "h0",
        " H0 ",
        "H0\t",
        "\u{FEFF}H0",
        "\u{FF28}\u{FF10}",
        "h1",
        "h2",
        "h3",
        "h4",
        "H0\n",
        "H0 ",
        " H0",
        "identity",
        "H5",
    ] {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(bad);
        let bytes = encoder.finish_checked()?;
        let mut decoder = CanonicalDecoder::new(&bytes);
        let res = HydrationLevel::decode_canonical(&mut decoder);
        assert_eq!(res, Err(ContractError::InvalidIdentifier));
    }

    Ok(())
}

#[test]
fn test_h0_mutant_kills_m3_m5b_m8() -> Result<(), Box<dyn Error>> {
    let base = sample_h0_params()?;

    // M3: Inverted capture interval (earliest > latest) must fail with InvertedTimeInterval.
    // Point intervals (earliest == latest) and ordered intervals (earliest < latest) must succeed.
    let mut p_m3 = base.clone();
    p_m3.capture_interval = Some(CaptureInterval {
        earliest: TimestampNs(2_000_000_000),
        latest: TimestampNs(1_000_000_000),
    });
    let digest_m3 = H0Identity::compute_identity_digest(
        &p_m3.subject_id,
        p_m3.subject_digest,
        &p_m3.semantic_type,
        &p_m3.source_id,
        p_m3.capture_interval,
        p_m3.spatial_scope.as_deref(),
        p_m3.applied_transform.as_deref(),
    )?;
    p_m3.handle_id = format!("semantic-handle:{digest_m3}");
    let Err(err_m3) = H0Identity::new(p_m3) else {
        return Err("expected error for inverted capture interval".into());
    };
    assert_eq!(
        err_m3,
        HydrationError::Contract(ContractError::InvertedTimeInterval)
    );

    // Point interval (earliest == latest) is valid and must succeed
    let mut p_point = base.clone();
    p_point.capture_interval = Some(CaptureInterval::point(TimestampNs(1_000_000_000)));
    let digest_point = H0Identity::compute_identity_digest(
        &p_point.subject_id,
        p_point.subject_digest,
        &p_point.semantic_type,
        &p_point.source_id,
        p_point.capture_interval,
        p_point.spatial_scope.as_deref(),
        p_point.applied_transform.as_deref(),
    )?;
    p_point.handle_id = format!("semantic-handle:{digest_point}");
    let id_point = H0Identity::new(p_point)?;
    assert!(id_point.capture_interval().is_some_and(|ci| ci.is_point()));

    // M5b: Duplicate capabilities in decode (tests >= vs > in decode_text_set)
    let identity = H0Identity::new(base)?;
    let mut dup_encoder = CanonicalEncoder::new();
    dup_encoder.text(H0_SCHEMA);
    dup_encoder.text(identity.handle_id());
    dup_encoder.text(identity.subject_id());
    dup_encoder.digest(identity.subject_digest());
    dup_encoder.text(identity.semantic_type());
    dup_encoder.text(identity.source_id());
    dup_encoder.bool(false);
    dup_encoder.bool(false);
    dup_encoder.bool(false);
    identity.availability().encode_canonical(&mut dup_encoder);
    identity.estimated_cost().encode_canonical(&mut dup_encoder);
    identity.anchor().encode_canonical(&mut dup_encoder);
    identity.contract_basis().encode_canonical(&mut dup_encoder);
    // 2 capabilities with identical name (duplicate)
    dup_encoder.u64(2);
    dup_encoder.text("cap:same");
    dup_encoder.text("cap:same");
    dup_encoder.text(identity.privacy_class());
    identity.published_at().encode_canonical(&mut dup_encoder);
    identity
        .retention_until()
        .encode_canonical(&mut dup_encoder);

    let dup_bytes = dup_encoder.finish_checked()?;
    let mut dec_dup = CanonicalDecoder::new(&dup_bytes);
    let Err(dup_err) = H0Identity::decode_canonical(&mut dec_dup) else {
        return Err("expected error for duplicate capabilities in decode".into());
    };
    assert_eq!(
        dup_err,
        HydrationError::Contract(ContractError::NonCanonicalOrdering)
    );

    // M8: Expiry boundary (> vs >= in is_expired_at)
    // At now == retention_until, the descriptor is NOT yet expired (> boundary).
    // At now == retention_until + 1, it IS expired.
    // At now == retention_until - 1, it is NOT expired.
    let ret_ts = identity.retention_until();
    assert!(!identity.is_expired_at(ret_ts));
    assert!(identity.is_expired_at(TimestampNs(ret_ts.0 + 1)));
    assert!(!identity.is_expired_at(TimestampNs(ret_ts.0 - 1)));

    Ok(())
}

#[test]
fn test_h0_text_bounding_and_digest_collision_resistance() -> Result<(), Box<dyn Error>> {
    let base = sample_h0_params()?;

    // 70,000-byte string fails text bounding in valid_text (Item 1)
    let oversized = "a".repeat(70_000);
    let mut p_oversized = base.clone();
    p_oversized.source_id = oversized;
    let Err(err) = H0Identity::new(p_oversized) else {
        return Err("expected error for 70,000-byte text in H0Identity".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // Encoder error with finish_checked returns typed error, preventing sha256("") collision (Item 1)
    let mut encoder = CanonicalEncoder::new();
    encoder.text(&"x".repeat(70_000));
    assert!(encoder.has_error());
    let Err(err) = encoder.finish_checked() else {
        return Err("expected error on finish_checked for oversized text".into());
    };
    assert_eq!(err, ContractError::InvalidIdentifier);

    // Calling public compute_identity_digest with a 70 KB field asserts exact Err(ContractError::InvalidIdentifier) (Item 2 mutant kill)
    let oversized = "a".repeat(70_000);
    let Err(err) = H0Identity::compute_identity_digest(
        &oversized,
        base.subject_digest,
        &base.semantic_type,
        &base.source_id,
        base.capture_interval,
        base.spatial_scope.as_deref(),
        base.applied_transform.as_deref(),
    ) else {
        return Err("expected error from compute_identity_digest with 70 KB field".into());
    };
    assert_eq!(err, ContractError::InvalidIdentifier);

    Ok(())
}

#[test]
fn test_h0_golden_digest_and_canonical_bytes() -> Result<(), Box<dyn Error>> {
    let mut caps = BTreeSet::new();
    caps.insert("cap:read:identity".to_string());

    let subject_id = "evidence:pkg-golden-01".to_string();
    let subject_digest = ContentDigest::sha256(b"golden-evidence-bytes");
    let semantic_type = "evidence_bundle".to_string();
    let source_id = "sensor:cam-golden-01".to_string();
    let capture_interval = Some(CaptureInterval::new(
        TimestampNs(1_000_000_000),
        TimestampNs(1_000_000_500),
    )?);
    let spatial_scope = Some("zone:north:gate".to_string());
    let applied_transform = Some("transform:blur:v1".to_string());

    let identity_digest = H0Identity::compute_identity_digest(
        &subject_id,
        subject_digest,
        &semantic_type,
        &source_id,
        capture_interval,
        spatial_scope.as_deref(),
        applied_transform.as_deref(),
    )?;
    let handle_id = format!("semantic-handle:{identity_digest}");

    let budget = BudgetVector::builder()
        .latency_ms(10)
        .tokens(20)
        .bytes(256)
        .cpu_millis(5)
        .privacy_exposure(0.01)
        .build()?;

    let anchor = LedgerAnchor {
        site_lineage: "site:golden:h0".to_string(),
        ledger_epoch: 1,
        commit_sequence: 1,
        adapter_registry_epoch: 1,
        schema_epoch: 1,
        policy_epoch: 1,
        privacy_epoch: 1,
        state_root: ContentDigest::sha256(b"golden-anchor-state-root"),
    };

    let params = H0IdentityParams {
        handle_id,
        subject_id,
        subject_digest,
        semantic_type,
        source_id,
        capture_interval,
        spatial_scope,
        applied_transform,
        availability: HandleAvailability::Available,
        estimated_cost: budget,
        anchor,
        contract_basis: sample_basis(),
        required_capabilities: caps,
        privacy_class: "privacy:operational_metadata".to_string(),
        published_at: TimestampNs(1_000_000_000),
        retention_until: TimestampNs(2_000_000_000),
    };

    let identity = H0Identity::new(params)?;

    // Canonical encoding
    let mut encoder = CanonicalEncoder::new();
    identity.encode_canonical(&mut encoder);
    let canonical_bytes = encoder.finish_checked()?;

    // Assert exact canonical byte vector length (Item 8) and sha256
    assert_eq!(canonical_bytes.len(), 877);
    let bytes_digest = ContentDigest::sha256(&canonical_bytes);
    let id_digest = identity.canonical_digest()?;

    // Decode back and assert bit-exact roundtrip
    let decoded = H0Identity::from_canonical_bytes(&canonical_bytes)?;
    assert_eq!(decoded, identity);
    assert_eq!(decoded.canonical_digest()?, id_digest);

    // Verify pinned golden constants (Item 5)
    let golden_digest = ContentDigest::parse(
        "sha256:1c3400249d747c7970c1d3c04b9dfd76f88a4c32274d207232d92939509c30a4",
    )?;
    assert_eq!(bytes_digest, golden_digest);
    assert_eq!(id_digest, golden_digest);

    Ok(())
}

#[test]
fn test_h0_screened_fields_grammar_and_prohibited_roots_for_all_six_fields()
-> Result<(), Box<dyn Error>> {
    let base = sample_h0_params()?;

    // Review bypass vectors to screen across all 6 fields (Decision 2):
    // (a) Non-ASCII bytes: Greek α/ο, fullwidth, Latin ɑ, zero-width space, soft hyphen
    // (b) Exact ASCII token grammar: [A-Za-z0-9_.:/-]{1,256} with no leading or trailing separator
    // (c) Prohibited roots: rawbytes, rawpayload, decodedimage, decodedframe, fullresolution,
    //     originalencoded, objectbytes, pixelbuffer, keyframe
    // (d) Harmless names pinned as fail-closed: keyframe_index, straw_bytes_metric
    let test_cases = [
        // Greek homoglyphs
        ("evidence_rαwbytes", "Greek alpha bypass"),
        ("α", "isolated Greek alpha"),
        ("keyfrοme", "Greek omicron bypass"),
        ("ο", "isolated Greek omicron"),
        // Fullwidth
        ("\u{FF52}awbytes", "fullwidth Latin r bypass"),
        ("\u{FF41}", "isolated fullwidth a"),
        // Latin phonetic / IPA
        ("r\u{0251}wbytes", "Latin alpha ɑ bypass"),
        ("\u{0251}", "isolated Latin alpha ɑ"),
        // Zero-width space & invisible formatters
        ("raw\u{200B}bytes", "zero-width space bypass"),
        ("\u{200B}", "isolated zero-width space"),
        // Soft hyphen
        ("raw\u{00AD}bytes", "soft hyphen bypass"),
        ("\u{00AD}", "isolated soft hyphen"),
        // Prohibited root variants
        ("rawbytesstream", "rawbytes prefix with suffix"),
        ("RawBytesStream", "mixed-case rawbytes"),
        ("raw_bytes2", "separator-separated raw_bytes2"),
        ("fullresolutionmedia", "fullresolution root substring"),
        ("pixelbuffers", "pixelbuffer root plural"),
        ("decodedframes", "decodedframe root plural"),
        ("keyframes", "keyframe root plural"),
        // Harmless names pinned as fail-closed:
        // keyframe_index contains prohibited root "keyframe". Fails closed.
        (
            "keyframe_index",
            "harmless name containing keyframe root fails closed",
        ),
        // straw_bytes_metric after stripping separators becomes "strawbytesmetric"
        // which contains prohibited root "rawbytes" (st + rawbytes + metric). Fails closed.
        (
            "straw_bytes_metric",
            "harmless name containing stripped rawbytes root fails closed",
        ),
        // Leading / trailing separators
        ("_foo", "leading underscore separator"),
        ("foo_", "trailing underscore separator"),
        (":bar", "leading colon separator"),
        ("bar:", "trailing colon separator"),
        ("-baz", "leading hyphen separator"),
        ("baz-", "trailing hyphen separator"),
        (".qux", "leading dot separator"),
        ("qux.", "trailing dot separator"),
        ("/test", "leading slash separator"),
        ("test/", "trailing slash separator"),
    ];

    // Verify is_valid_h0_screened_field rejects every single test case
    for &(input, description) in &test_cases {
        assert!(
            !is_valid_h0_screened_field(input),
            "is_valid_h0_screened_field must reject {description} ({input:?})"
        );
    }

    // Now test EACH of the six screened fields:
    // 1. subject_id
    // 2. source_id
    // 3. privacy_class
    // 4. spatial_scope
    // 5. applied_transform
    // 6. semantic_type
    for &(input, description) in &test_cases {
        // 1. subject_id
        let mut p = base.clone();
        p.subject_id = input.to_string();
        if let Ok(digest) = H0Identity::compute_identity_digest(
            &p.subject_id,
            p.subject_digest,
            &p.semantic_type,
            &p.source_id,
            p.capture_interval,
            p.spatial_scope.as_deref(),
            p.applied_transform.as_deref(),
        ) {
            p.handle_id = format!("semantic-handle:{digest}");
        }
        assert!(
            H0Identity::new(p).is_err(),
            "subject_id must reject {description}"
        );

        // 2. source_id
        let mut p = base.clone();
        p.source_id = input.to_string();
        if let Ok(digest) = H0Identity::compute_identity_digest(
            &p.subject_id,
            p.subject_digest,
            &p.semantic_type,
            &p.source_id,
            p.capture_interval,
            p.spatial_scope.as_deref(),
            p.applied_transform.as_deref(),
        ) {
            p.handle_id = format!("semantic-handle:{digest}");
        }
        assert!(
            H0Identity::new(p).is_err(),
            "source_id must reject {description}"
        );

        // 3. privacy_class
        let mut p = base.clone();
        p.privacy_class = input.to_string();
        assert!(
            H0Identity::new(p).is_err(),
            "privacy_class must reject {description}"
        );

        // 4. spatial_scope
        let mut p = base.clone();
        p.spatial_scope = Some(input.to_string());
        if let Ok(digest) = H0Identity::compute_identity_digest(
            &p.subject_id,
            p.subject_digest,
            &p.semantic_type,
            &p.source_id,
            p.capture_interval,
            p.spatial_scope.as_deref(),
            p.applied_transform.as_deref(),
        ) {
            p.handle_id = format!("semantic-handle:{digest}");
        }
        assert!(
            H0Identity::new(p).is_err(),
            "spatial_scope must reject {description}"
        );

        // 5. applied_transform
        let mut p = base.clone();
        p.applied_transform = Some(input.to_string());
        if let Ok(digest) = H0Identity::compute_identity_digest(
            &p.subject_id,
            p.subject_digest,
            &p.semantic_type,
            &p.source_id,
            p.capture_interval,
            p.spatial_scope.as_deref(),
            p.applied_transform.as_deref(),
        ) {
            p.handle_id = format!("semantic-handle:{digest}");
        }
        assert!(
            H0Identity::new(p).is_err(),
            "applied_transform must reject {description}"
        );

        // 6. semantic_type
        let mut p = base.clone();
        p.semantic_type = input.to_string();
        if let Ok(digest) = H0Identity::compute_identity_digest(
            &p.subject_id,
            p.subject_digest,
            &p.semantic_type,
            &p.source_id,
            p.capture_interval,
            p.spatial_scope.as_deref(),
            p.applied_transform.as_deref(),
        ) {
            p.handle_id = format!("semantic-handle:{digest}");
        }
        assert!(
            H0Identity::new(p).is_err(),
            "semantic_type must reject {description}"
        );
    }

    Ok(())
}

fn encode_h0_with_step_override(
    identity: &H0Identity,
    target_step: &str,
    write_override: impl FnOnce(&mut CanonicalEncoder),
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encoder = CanonicalEncoder::new();
    let steps = [
        "schema",
        "handle_id",
        "subject_id",
        "subject_digest",
        "semantic_type",
        "source_id",
        "capture_interval",
        "spatial_scope",
        "applied_transform",
        "availability",
        "estimated_cost",
        "anchor",
        "contract_basis",
        "required_capabilities",
        "privacy_class",
        "published_at",
        "retention_until",
    ];

    let mut write_override = Some(write_override);
    for step in steps {
        if step == target_step {
            if let Some(op) = write_override.take() {
                op(&mut encoder);
            }
        } else {
            match step {
                "schema" => encoder.text(H0_SCHEMA),
                "handle_id" => encoder.text(identity.handle_id()),
                "subject_id" => encoder.text(identity.subject_id()),
                "subject_digest" => encoder.digest(identity.subject_digest()),
                "semantic_type" => encoder.text(identity.semantic_type()),
                "source_id" => encoder.text(identity.source_id()),
                "capture_interval" => {
                    if let Some(ci) = identity.capture_interval() {
                        encoder.bool(true);
                        ci.encode_canonical(&mut encoder);
                    } else {
                        encoder.bool(false);
                    }
                }
                "spatial_scope" => {
                    if let Some(scope) = identity.spatial_scope() {
                        encoder.bool(true);
                        encoder.text(scope);
                    } else {
                        encoder.bool(false);
                    }
                }
                "applied_transform" => {
                    if let Some(transform) = identity.applied_transform() {
                        encoder.bool(true);
                        encoder.text(transform);
                    } else {
                        encoder.bool(false);
                    }
                }
                "availability" => identity.availability().encode_canonical(&mut encoder),
                "estimated_cost" => identity.estimated_cost().encode_canonical(&mut encoder),
                "anchor" => identity.anchor().encode_canonical(&mut encoder),
                "contract_basis" => identity.contract_basis().encode_canonical(&mut encoder),
                "required_capabilities" => {
                    encoder.u64(identity.required_capabilities().len() as u64);
                    for cap in identity.required_capabilities() {
                        encoder.text(cap);
                    }
                }
                "privacy_class" => encoder.text(identity.privacy_class()),
                "published_at" => identity.published_at().encode_canonical(&mut encoder),
                "retention_until" => identity.retention_until().encode_canonical(&mut encoder),
                _ => {}
            }
        }
    }
    Ok(encoder.finish_checked()?)
}

#[test]
fn test_h0_decode_canonical_typed_errors_per_field() -> Result<(), Box<dyn Error>> {
    let identity = H0Identity::new(sample_h0_params()?)?;

    // Helper to write invalid UTF-8 bytes to an encoder
    let write_invalid_utf8 = |encoder: &mut CanonicalEncoder| {
        encoder.bytes(&[0xFF, 0xFF, 0xFF, 0xFF]);
    };

    let decode_err = |bytes: &[u8]| -> Result<HydrationError, Box<dyn Error>> {
        let mut dec = CanonicalDecoder::new(bytes);
        match H0Identity::decode_canonical(&mut dec) {
            Err(err) => Ok(err),
            Ok(_) => Err("expected decode error, got Ok".into()),
        }
    };

    // 1. schema: invalid text -> InvalidIdentifier
    let bytes = encode_h0_with_step_override(&identity, "schema", write_invalid_utf8)?;
    let err = decode_err(&bytes)?;
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 2. handle_id: invalid UTF-8 -> InvalidIdentifier
    let bytes = encode_h0_with_step_override(&identity, "handle_id", write_invalid_utf8)?;
    let err = decode_err(&bytes)?;
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 3. subject_id: invalid UTF-8 -> InvalidIdentifier
    let bytes = encode_h0_with_step_override(&identity, "subject_id", write_invalid_utf8)?;
    let err = decode_err(&bytes)?;
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 4. subject_digest: unsupported algo tag 99 -> UnsupportedDigestAlgorithm
    let bytes = encode_h0_with_step_override(&identity, "subject_digest", |encoder| {
        encoder.tag(99);
        encoder.bytes(&[0x42u8; 32]);
    })?;
    let err = decode_err(&bytes)?;
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::UnsupportedDigestAlgorithm)
    );

    // 5. semantic_type: invalid UTF-8 -> InvalidIdentifier
    let bytes = encode_h0_with_step_override(&identity, "semantic_type", write_invalid_utf8)?;
    let err = decode_err(&bytes)?;
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 6. source_id: invalid UTF-8 -> InvalidIdentifier
    let bytes = encode_h0_with_step_override(&identity, "source_id", write_invalid_utf8)?;
    let err = decode_err(&bytes)?;
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 7. capture_interval:
    // (a) invalid bool tag (tag 2) -> InvalidIdentifier
    let bytes = encode_h0_with_step_override(&identity, "capture_interval", |encoder| {
        encoder.tag(2);
    })?;
    let err = decode_err(&bytes)?;
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // (b) inverted interval (earliest 200 > latest 100) -> InvertedTimeInterval
    let bytes = encode_h0_with_step_override(&identity, "capture_interval", |encoder| {
        encoder.bool(true);
        TimestampNs(200).encode_canonical(encoder);
        TimestampNs(100).encode_canonical(encoder);
    })?;
    let err = decode_err(&bytes)?;
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvertedTimeInterval)
    );

    // 8. spatial_scope:
    // (a) invalid bool tag (tag 2) -> InvalidIdentifier
    let bytes = encode_h0_with_step_override(&identity, "spatial_scope", |encoder| {
        encoder.tag(2);
    })?;
    let err = decode_err(&bytes)?;
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // (b) invalid UTF-8 -> InvalidIdentifier
    let bytes = encode_h0_with_step_override(&identity, "spatial_scope", |encoder| {
        encoder.bool(true);
        write_invalid_utf8(encoder);
    })?;
    let err = decode_err(&bytes)?;
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 9. applied_transform:
    // (a) invalid bool tag (tag 2) -> InvalidIdentifier
    let bytes = encode_h0_with_step_override(&identity, "applied_transform", |encoder| {
        encoder.tag(2);
    })?;
    let err = decode_err(&bytes)?;
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // (b) invalid UTF-8 -> InvalidIdentifier
    let bytes = encode_h0_with_step_override(&identity, "applied_transform", |encoder| {
        encoder.bool(true);
        write_invalid_utf8(encoder);
    })?;
    let err = decode_err(&bytes)?;
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 10. availability: invalid text variant -> InvalidIdentifier
    let bytes = encode_h0_with_step_override(&identity, "availability", |encoder| {
        encoder.text("invalid_availability_state");
    })?;
    let err = decode_err(&bytes)?;
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 11. estimated_cost: invalid budget with negative zero privacy exposure -> InvalidBudget
    let bytes = encode_h0_with_step_override(&identity, "estimated_cost", |encoder| {
        encoder.u64(10); // latency_ms
        encoder.u64(20); // tokens
        encoder.u64(256); // bytes
        encoder.u32(1); // model_calls
        encoder.u64(5); // cpu_millis
        encoder.u64(0); // accelerator_millis
        encoder.u64(0); // energy_millijoules
        encoder.u64(0); // network_bytes
        encoder.u64(0); // storage_operations
        encoder.u64(0x8000_0000_0000_0000); // privacy_bits (rejected negative zero IEEE-754)
        encoder.u64(0); // attention_bits
    })?;
    let err = decode_err(&bytes)?;
    match err {
        HydrationError::Contract(ContractError::InvalidBudget(_)) => {}
        other => return Err(format!("expected InvalidBudget, got {other:?}").into()),
    }

    // 12. anchor: invalid UTF-8 in site_lineage -> InvalidIdentifier
    let bytes = encode_h0_with_step_override(&identity, "anchor", |encoder| {
        write_invalid_utf8(encoder); // site_lineage text
        encoder.u64(1);
        encoder.u64(1);
        encoder.u64(1);
        encoder.u64(1);
        encoder.u64(1);
        encoder.u64(1);
        encoder.digest(ContentDigest::sha256(b"state-root"));
    })?;
    let err = decode_err(&bytes)?;
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 13. contract_basis: invalid UTF-8 in semantic_protocol -> InvalidIdentifier
    let bytes = encode_h0_with_step_override(&identity, "contract_basis", |encoder| {
        write_invalid_utf8(encoder); // semantic_protocol text
        encoder.digest(ContentDigest::sha256(b"schema"));
        encoder.text("ontology:test");
        encoder.digest(ContentDigest::sha256(b"operations"));
        encoder.digest(ContentDigest::sha256(b"views"));
        encoder.digest(ContentDigest::sha256(b"capabilities"));
        encoder.digest(ContentDigest::sha256(b"errors"));
        encoder.digest(ContentDigest::sha256(b"costs"));
        encoder.text("producer:test");
        encoder.bool(false);
    })?;
    let err = decode_err(&bytes)?;
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 14. required_capabilities (decode_text_set): invalid UTF-8 in capability text -> InvalidIdentifier
    let bytes = encode_h0_with_step_override(&identity, "required_capabilities", |encoder| {
        encoder.u64(1); // count = 1
        write_invalid_utf8(encoder);
    })?;
    let err = decode_err(&bytes)?;
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 15. privacy_class: invalid UTF-8 -> InvalidIdentifier
    let bytes = encode_h0_with_step_override(&identity, "privacy_class", write_invalid_utf8)?;
    let err = decode_err(&bytes)?;
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 16. published_at / retention_until: retention_until <= published_at -> InvertedTimeInterval
    let bytes = encode_h0_with_step_override(&identity, "retention_until", |encoder| {
        // write retention_until earlier than published_at
        TimestampNs(500).encode_canonical(encoder);
    })?;
    let err = decode_err(&bytes)?;
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvertedTimeInterval)
    );

    Ok(())
}

#[test]
fn test_contract_basis_validate_ontology_and_producer_release_id() -> Result<(), Box<dyn Error>> {
    let basis = sample_basis();
    assert!(basis.validate().is_ok());

    // 1. Empty ontology_generation_id -> InvalidIdentifier (mutant M4d kill)
    let mut empty_ont = basis.clone();
    empty_ont.ontology_generation_id = String::new();
    assert_eq!(empty_ont.validate(), Err(ContractError::InvalidIdentifier));

    // 2. Whitespace-only ontology_generation_id -> InvalidIdentifier (mutant M4d kill)
    let mut ws_ont = basis.clone();
    ws_ont.ontology_generation_id = "   \t\n ".to_string();
    assert_eq!(ws_ont.validate(), Err(ContractError::InvalidIdentifier));

    // 3. Control character in ontology_generation_id -> InvalidIdentifier
    let mut ctrl_ont = basis.clone();
    ctrl_ont.ontology_generation_id = "ontology\x00generation".to_string();
    assert_eq!(ctrl_ont.validate(), Err(ContractError::InvalidIdentifier));

    // 4. Empty producer_release_id -> InvalidIdentifier
    let mut empty_prod = basis.clone();
    empty_prod.producer_release_id = String::new();
    assert_eq!(empty_prod.validate(), Err(ContractError::InvalidIdentifier));

    // 5. Whitespace-only producer_release_id -> InvalidIdentifier
    let mut ws_prod = basis.clone();
    ws_prod.producer_release_id = "   \t\n ".to_string();
    assert_eq!(ws_prod.validate(), Err(ContractError::InvalidIdentifier));

    // 6. Control character in producer_release_id -> InvalidIdentifier
    let mut ctrl_prod = basis.clone();
    ctrl_prod.producer_release_id = "release\x00id".to_string();
    assert_eq!(ctrl_prod.validate(), Err(ContractError::InvalidIdentifier));

    // 7. Verify that H0Identity::new rejects invalid basis through basis.validate()
    let mut p_bad_ont = sample_h0_params()?;
    p_bad_ont.contract_basis.ontology_generation_id = "   ".to_string();
    let Err(err) = H0Identity::new(p_bad_ont) else {
        return Err("expected error on empty ontology_generation_id".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    let mut p_bad_prod = sample_h0_params()?;
    p_bad_prod.contract_basis.producer_release_id = "   ".to_string();
    let Err(err) = H0Identity::new(p_bad_prod) else {
        return Err("expected error on empty producer_release_id".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    Ok(())
}

#[test]
fn test_hydration_level_owner_pinned_and_matches_registry() -> Result<(), Box<dyn Error>> {
    let registry_str = include_str!("../../../architecture/semantic_hydration.json");
    let mut extracted_owner = None;
    for line in registry_str.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("\"semantic_owner\":") {
            let val = rest.trim().trim_matches(',').trim().trim_matches('"');
            extracted_owner = Some(val);
            break;
        }
    }
    let Some(registry_owner) = extracted_owner else {
        return Err("semantic_owner present in architecture/semantic_hydration.json".into());
    };
    assert_eq!(registry_owner, "fss-agent-core");
    assert_eq!(SEMANTIC_HYDRATION_OWNER, registry_owner);
    assert_eq!(H0_SEMANTIC_OWNER, registry_owner);
    for level in HydrationLevel::ALL {
        assert_eq!(level.owner(), registry_owner);
    }
    Ok(())
}
