#![forbid(unsafe_code)]
//! Deterministic contract tests for hydration ladder level H2: decision_artifact (AGT-H2, fss-x4a.30.82.14).
//!
//! Enforces:
//! 1. Normative row identity and properties from registries/AGENT_ABSTRACTIONS.md
//! 2. Content completeness: authorized redacted keyframes, crops, trajectories, graph neighborhoods, or audio features
//! 3. Prohibition against unredacted raw media, raw camera streams, and ungrounded cognition
//! 4. Invariant enforcement & planted bypasses (zero digest, empty payload, digest mismatch, missing proof roots,
//!    forbidden completeness, expired retention, missing authorization grant, unredacted media keywords)
//! 5. Deterministic canonical binary encoding & decoding with exact roundtrip and trailing bytes refusal
//! 6. Spatial bounds validation for BoundingBox, RedactedRegion, and TrajectoryWaypoint
//! 7. Integration with SemanticHandle materialization

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use fss_core::{
    AudioFeaturesArtifact, BoundingBox, BudgetVector, CanonicalDecode, CanonicalDecoder,
    CanonicalEncode, CanonicalEncoder, CaptureInterval, Completeness, ContentDigest, ContractBasis,
    ContractBasisRegistryBytes, ContractError, CropArtifact, DecisionArtifactKind,
    GraphNeighborhoodArtifact, H2_CONTENT, H2_LEVEL_ID, H2_LEVEL_NAME, H2_OWNER, H2_SCHEMA,
    H2DecisionArtifact, H2DecisionArtifactParams, HandleAvailability, HydrationError,
    HydrationLevel, KeyframeArtifact, LaboratoryAccess, LedgerAnchor, RedactedRegion,
    SemanticHandle, SemanticHandleSpec, TimestampNs, TrajectoryArtifact, TrajectoryWaypoint,
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
    let mut a = LedgerAnchor::genesis("site:us-east:h2");
    a.commit_sequence = seq;
    a
}

fn sample_digest(byte: u8) -> ContentDigest {
    ContentDigest::sha256(&[byte; 32])
}

fn sample_budget() -> Result<BudgetVector, Box<dyn Error>> {
    let b = BudgetVector::builder()
        .latency_ms(50)
        .tokens(100)
        .bytes(4096)
        .cpu_millis(20)
        .privacy_exposure(0.1)
        .build()?;
    Ok(b)
}

fn sample_keyframe() -> Result<DecisionArtifactKind, Box<dyn Error>> {
    let region = RedactedRegion::new(100, 100, 50, 50, "gaussian_blur")?;
    let keyframe = KeyframeArtifact {
        timestamp_ns: TimestampNs(1_000_000_000),
        stream_id: "stream:cam-01".to_string(),
        width: 1920,
        height: 1080,
        format: "image/jpeg".to_string(),
        redacted_regions: vec![region],
    };
    keyframe.validate()?;
    Ok(DecisionArtifactKind::Keyframe(keyframe))
}

fn sample_crop() -> Result<DecisionArtifactKind, Box<dyn Error>> {
    let bbox = BoundingBox::new(0.1, 0.2, 0.5, 0.8)?;
    let region = RedactedRegion::new(10, 10, 20, 20, "solid_black_mask")?;
    let crop = CropArtifact {
        timestamp_ns: TimestampNs(1_000_000_000),
        source_stream_id: "stream:cam-01".to_string(),
        bounding_box: bbox,
        target_entity_anchor: Some("entity:vehicle-99".to_string()),
        format: "image/png".to_string(),
        redacted_regions: vec![region],
    };
    crop.validate()?;
    Ok(DecisionArtifactKind::Crop(crop))
}

fn sample_trajectory() -> Result<DecisionArtifactKind, Box<dyn Error>> {
    let interval = CaptureInterval::new(TimestampNs(1_000), TimestampNs(2_000))?;
    let wp1 = TrajectoryWaypoint::new(TimestampNs(1_200), 10.0, 20.0, 0.0)?;
    let wp2 = TrajectoryWaypoint::new(TimestampNs(1_800), 15.0, 25.0, 0.0)?;
    let traj = TrajectoryArtifact {
        entity_anchor: "entity:pedestrian-12".to_string(),
        time_window: interval,
        waypoints: vec![wp1, wp2],
        coordinate_frame: "frame:site_local:enu".to_string(),
        coarsened: true,
    };
    traj.validate()?;
    Ok(DecisionArtifactKind::Trajectory(traj))
}

fn sample_graph_neighborhood() -> Result<DecisionArtifactKind, Box<dyn Error>> {
    let mut masked = BTreeSet::new();
    masked.insert("pii:ssn".to_string());
    masked.insert("pii:true_name".to_string());
    let graph = GraphNeighborhoodArtifact {
        center_entity_id: "entity:node-42".to_string(),
        radius_hops: 2,
        node_count: 5,
        edge_count: 8,
        subgraph_digest: sample_digest(0x55),
        masked_attributes: masked,
    };
    graph.validate()?;
    Ok(DecisionArtifactKind::GraphNeighborhood(graph))
}

fn sample_audio_features() -> Result<DecisionArtifactKind, Box<dyn Error>> {
    let interval = CaptureInterval::new(TimestampNs(10_000), TimestampNs(20_000))?;
    let audio = AudioFeaturesArtifact {
        time_window: interval,
        source_channel_id: "channel:mic-03".to_string(),
        feature_type: "log_mel_spectrogram".to_string(),
        sample_count: 100,
        band_count: 80,
        voice_activity_masked: true,
    };
    audio.validate()?;
    Ok(DecisionArtifactKind::AudioFeatures(audio))
}

fn sample_h2_params(
    artifact_kind: DecisionArtifactKind,
) -> Result<H2DecisionArtifactParams, Box<dyn Error>> {
    let payload = b"authorized-redacted-artifact-payload-bytes".to_vec();
    let mut proof_roots = BTreeSet::new();
    proof_roots.insert(sample_digest(0xaa)); // external provenance root

    Ok(H2DecisionArtifactParams {
        handle_id: "semantic-handle:sha256:h2-test-handle".to_string(),
        subject_id: "evidence:cam-stream-01".to_string(),
        subject_digest: sample_digest(0xbb),
        artifact_kind,
        payload,
        proof_roots,
        completeness: Completeness::Complete,
        privacy_class: "privacy:redacted_operational".to_string(),
        applied_redaction_transform: "transform:face_blur_and_plate_mask".to_string(),
        authorization_grant_id: "grant:auth-oper-8891".to_string(),
        anchor: sample_anchor(42),
        contract_basis: sample_basis(),
        estimated_cost: sample_budget()?,
        published_at: TimestampNs(1_000_000_000),
        retention_until: TimestampNs(2_000_000_000),
    })
}

#[test]
fn test_h2_normative_row_constants() {
    assert_eq!(H2_LEVEL_ID, "H2");
    assert_eq!(H2_LEVEL_NAME, "decision_artifact");
    assert_eq!(
        H2_CONTENT,
        "authorized redacted keyframes, crops, trajectories, graph neighborhoods, or audio features"
    );
    assert_eq!(H2_OWNER, "fss-media/fss-privacy");
    assert_eq!(H2_SCHEMA, "fss.h2_decision_artifact.v1");

    assert_eq!(HydrationLevel::H2.as_str(), "H2");
    assert_eq!(HydrationLevel::H2.level_name(), "decision_artifact");
    assert_eq!(HydrationLevel::H2.content_declaration(), H2_CONTENT);
    assert_eq!(HydrationLevel::H2.owner(), H2_OWNER);
    assert_eq!(HydrationLevel::H2.ordinal(), 2);
}

#[test]
fn test_h2_bounding_box_valid_and_planted_bypasses() -> Result<(), Box<dyn Error>> {
    let valid_box = BoundingBox::new(0.0, 0.0, 1.0, 1.0)?;
    valid_box.validate()?;

    // Planted bypasses: inverted coordinates
    assert_eq!(
        BoundingBox::new(0.6, 0.1, 0.4, 0.8).err(),
        Some(ContractError::InvalidSpatialExtent)
    );
    assert_eq!(
        BoundingBox::new(0.1, 0.8, 0.4, 0.2).err(),
        Some(ContractError::InvalidSpatialExtent)
    );
    // Equal coordinates (zero width or height)
    assert_eq!(
        BoundingBox::new(0.5, 0.1, 0.5, 0.8).err(),
        Some(ContractError::InvalidSpatialExtent)
    );
    assert_eq!(
        BoundingBox::new(0.1, 0.5, 0.4, 0.5).err(),
        Some(ContractError::InvalidSpatialExtent)
    );
    // Out of bounds (< 0.0 or > 1.0)
    assert_eq!(
        BoundingBox::new(-0.1, 0.0, 0.5, 0.5).err(),
        Some(ContractError::InvalidSpatialExtent)
    );
    assert_eq!(
        BoundingBox::new(0.0, 0.0, 1.1, 0.5).err(),
        Some(ContractError::InvalidSpatialExtent)
    );
    // Non-finite
    assert_eq!(
        BoundingBox::new(f32::NAN, 0.0, 0.5, 0.5).err(),
        Some(ContractError::InvalidSpatialExtent)
    );
    assert_eq!(
        BoundingBox::new(0.0, 0.0, f32::INFINITY, 0.5).err(),
        Some(ContractError::InvalidSpatialExtent)
    );

    // Canonical roundtrip
    let mut encoder = CanonicalEncoder::new();
    valid_box.encode_canonical(&mut encoder);
    let bytes = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&bytes);
    let decoded = BoundingBox::decode_canonical(&mut decoder)?;
    decoder.ensure_finished()?;
    assert_eq!(valid_box, decoded);

    Ok(())
}

#[test]
fn test_h2_redacted_region_valid_and_planted_bypasses() -> Result<(), Box<dyn Error>> {
    let valid_region = RedactedRegion::new(10, 20, 100, 200, "blur")?;
    valid_region.validate()?;

    // Planted zero dimension
    assert_eq!(
        RedactedRegion::new(10, 20, 0, 200, "blur").err(),
        Some(ContractError::InvalidSpatialExtent)
    );
    assert_eq!(
        RedactedRegion::new(10, 20, 100, 0, "blur").err(),
        Some(ContractError::InvalidSpatialExtent)
    );
    // Planted empty method
    assert_eq!(
        RedactedRegion::new(10, 20, 100, 200, "").err(),
        Some(ContractError::InvalidSpatialExtent)
    );

    // Canonical roundtrip
    let mut encoder = CanonicalEncoder::new();
    valid_region.encode_canonical(&mut encoder);
    let bytes = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&bytes);
    let decoded = RedactedRegion::decode_canonical(&mut decoder)?;
    decoder.ensure_finished()?;
    assert_eq!(valid_region, decoded);

    Ok(())
}

#[test]
fn test_h2_trajectory_waypoint_valid_and_planted_bypasses() -> Result<(), Box<dyn Error>> {
    let valid_wp = TrajectoryWaypoint::new(TimestampNs(100), 1.0, 2.0, 3.0)?;
    valid_wp.validate()?;

    // Planted non-finite coordinates
    assert_eq!(
        TrajectoryWaypoint::new(TimestampNs(100), f64::NAN, 2.0, 3.0).err(),
        Some(ContractError::InvalidSpatialExtent)
    );
    assert_eq!(
        TrajectoryWaypoint::new(TimestampNs(100), 1.0, f64::INFINITY, 3.0).err(),
        Some(ContractError::InvalidSpatialExtent)
    );

    // Canonical roundtrip
    let mut encoder = CanonicalEncoder::new();
    valid_wp.encode_canonical(&mut encoder);
    let bytes = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&bytes);
    let decoded = TrajectoryWaypoint::decode_canonical(&mut decoder)?;
    decoder.ensure_finished()?;
    assert_eq!(valid_wp, decoded);

    Ok(())
}

#[test]
fn test_h2_all_5_kinds_roundtrip_and_properties() -> Result<(), Box<dyn Error>> {
    let kinds = vec![
        (sample_keyframe()?, 1u8, "application/x-fss-h2-keyframe"),
        (sample_crop()?, 2u8, "application/x-fss-h2-crop"),
        (sample_trajectory()?, 3u8, "application/x-fss-h2-trajectory"),
        (
            sample_graph_neighborhood()?,
            4u8,
            "application/x-fss-h2-graph-neighborhood",
        ),
        (
            sample_audio_features()?,
            5u8,
            "application/x-fss-h2-audio-features",
        ),
    ];

    for (kind, expected_tag, expected_content_type) in kinds {
        assert_eq!(kind.tag(), expected_tag);
        assert_eq!(kind.content_type(), expected_content_type);

        // Kind canonical roundtrip
        let mut enc = CanonicalEncoder::new();
        kind.encode_canonical(&mut enc);
        let bytes = enc.finish();
        let mut dec = CanonicalDecoder::new(&bytes);
        let dec_kind = DecisionArtifactKind::decode_canonical(&mut dec)?;
        dec.ensure_finished()?;
        assert_eq!(kind, dec_kind);

        // Full H2DecisionArtifact roundtrip
        let params = sample_h2_params(kind)?;
        let artifact = H2DecisionArtifact::new(params)?;
        artifact.verify()?;

        assert_eq!(artifact.level(), HydrationLevel::H2);
        assert_eq!(artifact.level_id(), "H2");
        assert_eq!(artifact.level_name(), "decision_artifact");
        assert_eq!(artifact.content_declaration(), H2_CONTENT);
        assert_eq!(artifact.owner(), "fss-media/fss-privacy");
        assert_eq!(artifact.content_type(), expected_content_type);

        let mut art_enc = CanonicalEncoder::new();
        artifact.encode_canonical(&mut art_enc);
        let art_bytes = art_enc.finish();

        let decoded_art = H2DecisionArtifact::from_canonical_bytes(&art_bytes)?;
        decoded_art.verify()?;
        assert_eq!(artifact, decoded_art);

        // Convert to universal HydrationArtifact
        let universal = artifact.to_hydration_artifact();
        assert_eq!(universal.level, HydrationLevel::H2);
        assert_eq!(universal.content_type, expected_content_type);
        assert_eq!(universal.payload, artifact.payload);
        assert_eq!(universal.payload_digest, artifact.payload_digest);
    }

    Ok(())
}

#[test]
fn test_h2_planted_bypasses_refusal() -> Result<(), Box<dyn Error>> {
    // 1. Zero subject digest refusal
    let mut p1 = sample_h2_params(sample_keyframe()?)?;
    p1.subject_digest = ContentDigest::new(fss_core::DigestAlgorithm::Sha256, [0u8; 32]);
    let err1 = H2DecisionArtifact::new(p1);
    assert!(matches!(
        err1,
        Err(HydrationError::Contract(ContractError::InvalidDigest))
    ));

    // 2. Empty payload refusal
    let mut p2 = sample_h2_params(sample_keyframe()?)?;
    p2.payload = Vec::new();
    let err2 = H2DecisionArtifact::new(p2);
    assert!(matches!(
        err2,
        Err(HydrationError::Contract(ContractError::EvidenceRequired))
    ));

    // 3. Proof roots missing distinct provenance root (payload digest only)
    let mut p3 = sample_h2_params(sample_keyframe()?)?;
    p3.proof_roots = BTreeSet::new(); // will only contain payload digest after insert
    let err3 = H2DecisionArtifact::new(p3);
    assert!(matches!(
        err3,
        Err(HydrationError::Contract(ContractError::EvidenceRequired))
    ));

    // 4. Forbidden completeness states
    let forbidden_completeness = [
        Completeness::Unknown,
        Completeness::NotObservable,
        Completeness::Unauthorized,
        Completeness::Stale,
    ];
    for comp in forbidden_completeness {
        let mut p4 = sample_h2_params(sample_keyframe()?)?;
        p4.completeness = comp;
        let err4 = H2DecisionArtifact::new(p4);
        assert!(
            matches!(
                err4,
                Err(HydrationError::Contract(ContractError::EvidenceRequired))
            ),
            "Expected EvidenceRequired for completeness {:?}",
            comp
        );
    }

    // 5. Expired retention (retention_until < published_at)
    let mut p5 = sample_h2_params(sample_keyframe()?)?;
    p5.published_at = TimestampNs(2_000);
    p5.retention_until = TimestampNs(1_000);
    let err5 = H2DecisionArtifact::new(p5);
    assert!(matches!(err5, Err(HydrationError::ContinuationExpired)));

    // 6. Prohibited unredacted media / raw stream bypasses
    let prohibited_redactions = [
        "unredacted_raw_media",
        "raw_undecoded_stream",
        "raw_camera_packets",
        "unmasked_pii",
        "unredacted",
        "none",
    ];
    for red in prohibited_redactions {
        let mut p6 = sample_h2_params(sample_keyframe()?)?;
        p6.applied_redaction_transform = red.to_string();
        let err6 = H2DecisionArtifact::new(p6);
        assert!(
            matches!(
                err6,
                Err(HydrationError::Contract(
                    ContractError::ProhibitedEvidencePromotion
                ))
            ),
            "Expected ProhibitedEvidencePromotion for applied redaction {:?}",
            red
        );

        let mut p6b = sample_h2_params(sample_keyframe()?)?;
        p6b.privacy_class = format!("privacy:level_{}", red);
        let err6b = H2DecisionArtifact::new(p6b);
        assert!(
            matches!(
                err6b,
                Err(HydrationError::Contract(
                    ContractError::ProhibitedEvidencePromotion
                ))
            ),
            "Expected ProhibitedEvidencePromotion for privacy class {:?}",
            red
        );
    }

    // 7. Empty authorization grant ID
    let mut p7 = sample_h2_params(sample_keyframe()?)?;
    p7.authorization_grant_id = "".to_string();
    let err7 = H2DecisionArtifact::new(p7);
    assert!(matches!(
        err7,
        Err(HydrationError::Contract(ContractError::InvalidIdentifier))
    ));

    Ok(())
}

#[test]
fn test_h2_trailing_bytes_refusal() -> Result<(), Box<dyn Error>> {
    let params = sample_h2_params(sample_crop()?)?;
    let artifact = H2DecisionArtifact::new(params)?;
    let mut enc = CanonicalEncoder::new();
    artifact.encode_canonical(&mut enc);
    let mut bytes = enc.finish();

    // Append extra rogue trailing byte
    bytes.push(0xff);

    let res = H2DecisionArtifact::from_canonical_bytes(&bytes);
    assert_eq!(res.err(), Some(ContractError::NonCanonicalOrdering));

    Ok(())
}

#[test]
fn test_h2_schema_discriminator_mismatch_refusal() -> Result<(), Box<dyn Error>> {
    let params = sample_h2_params(sample_crop()?)?;
    let artifact = H2DecisionArtifact::new(params)?;
    let mut enc = CanonicalEncoder::new();
    artifact.encode_canonical(&mut enc);
    let mut bytes = enc.finish();

    // Mutate the first schema string from fss.h2_decision_artifact.v1 to something else
    let mut custom_enc = CanonicalEncoder::new();
    custom_enc.text("fss.unauthorized_rogue_schema.v1");
    let custom_bytes = custom_enc.finish();
    // Replace schema bytes in payload
    if bytes.len() > custom_bytes.len() {
        bytes[0..custom_bytes.len()].copy_from_slice(&custom_bytes);
    }

    let res = H2DecisionArtifact::from_canonical_bytes(&bytes);
    assert_eq!(res.err(), Some(ContractError::InvalidIdentifier));

    Ok(())
}

#[test]
fn test_h2_semantic_handle_materialization() -> Result<(), Box<dyn Error>> {
    let levels = BTreeSet::from([HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2]);

    let mut required_capabilities = BTreeMap::new();
    let mut costs = BTreeMap::new();
    for &lvl in &levels {
        required_capabilities.insert(
            lvl,
            BTreeSet::from([format!("cap:hydrate:{}", lvl.as_str())]),
        );
        costs.insert(lvl, sample_budget()?);
    }

    let handle_spec = SemanticHandleSpec {
        contract_basis: sample_basis(),
        anchor: sample_anchor(1),
        subject_id: "subject:sensor-01".to_string(),
        subject_digest: sample_digest(0x11),
        semantic_type: "evidence_bundle".to_string(),
        source_id: "sensor:cam-01".to_string(),
        capture_interval: None,
        spatial_scope: None,
        privacy_class: "privacy:redacted_zone".to_string(),
        applied_transform: Some("transform:blur".to_string()),
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(10_000_000),
        required_capabilities,
        estimated_costs: costs,
        levels: levels.clone(),
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1_000),
    };

    let handle = SemanticHandle::publish(handle_spec)?;

    let artifact = handle.to_h2_decision_artifact(
        sample_keyframe()?,
        b"decision-keyframe-data".to_vec(),
        [sample_digest(0x77)],
        "transform:face_blur".to_string(),
        "grant:auth-oper-99".to_string(),
        Completeness::Complete,
    )?;

    artifact.verify()?;
    assert_eq!(artifact.handle_id, handle.handle_id);
    assert_eq!(artifact.subject_id, handle.subject_id);

    // Rejection when handle does not advertise H2
    let no_h2_levels = BTreeSet::from([HydrationLevel::H0]);
    let mut no_h2_caps = BTreeMap::new();
    no_h2_caps.insert(
        HydrationLevel::H0,
        BTreeSet::from(["cap:hydrate:H0".to_string()]),
    );
    let mut no_h2_costs = BTreeMap::new();
    no_h2_costs.insert(HydrationLevel::H0, sample_budget()?);

    let no_h2_handle_spec = SemanticHandleSpec {
        contract_basis: sample_basis(),
        anchor: sample_anchor(1),
        subject_id: "subject:sensor-02".to_string(),
        subject_digest: sample_digest(0x22),
        semantic_type: "evidence_bundle".to_string(),
        source_id: "sensor:cam-02".to_string(),
        capture_interval: None,
        spatial_scope: None,
        privacy_class: "privacy:redacted_zone".to_string(),
        applied_transform: Some("transform:blur".to_string()),
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(10_000_000),
        required_capabilities: no_h2_caps,
        estimated_costs: no_h2_costs,
        levels: no_h2_levels,
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1_000),
    };
    let no_h2_handle = SemanticHandle::publish(no_h2_handle_spec)?;

    let err = no_h2_handle.to_h2_decision_artifact(
        sample_keyframe()?,
        b"decision-keyframe-data".to_vec(),
        [sample_digest(0x77)],
        "transform:face_blur".to_string(),
        "grant:auth-oper-99".to_string(),
        Completeness::Complete,
    );
    assert!(matches!(err, Err(HydrationError::LevelUnavailable)));

    Ok(())
}

#[test]
fn test_h2_budget_and_expiration() -> Result<(), Box<dyn Error>> {
    let params = sample_h2_params(sample_audio_features()?)?;
    let artifact = H2DecisionArtifact::new(params)?;

    // Budget check
    let sufficient_budget = BudgetVector::builder()
        .latency_ms(100)
        .tokens(200)
        .bytes(8192)
        .cpu_millis(50)
        .privacy_exposure(0.5)
        .build()?;
    assert!(artifact.satisfies_budget(&sufficient_budget));

    let tight_budget = BudgetVector::builder()
        .latency_ms(10) // less than 50ms
        .tokens(200)
        .bytes(8192)
        .cpu_millis(50)
        .privacy_exposure(0.5)
        .build()?;
    assert!(!artifact.satisfies_budget(&tight_budget));

    // Expiration check
    assert!(!artifact.is_expired_at(TimestampNs(1_500_000_000)));
    assert!(artifact.is_expired_at(TimestampNs(2_500_000_000)));

    Ok(())
}
