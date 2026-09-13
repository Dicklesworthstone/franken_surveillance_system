#![forbid(unsafe_code)]
//! Deterministic contract tests for hydration ladder level H2: decision_artifact (AGT-H2, fss-x4a.30.82.14).
//!
//! Enforces:
//! 1. Normative row identity and properties from registries/AGENT_ABSTRACTIONS.md
//! 2. Content completeness: authorized redacted keyframes, crops, trajectories, graph neighborhoods, or audio features
//! 3. Pure redacted invariant: strictly prohibits raw media, unredacted streams, or ungrounded cognition
//! 4. Invariant enforcement & planted bypasses (zero digest, empty payload, digest mismatch, missing proof roots,
//!    forbidden completeness, expired retention, unauthorized / unredacted transforms, payload cap)
//! 5. Deterministic canonical binary encoding & decoding with exact roundtrip and canonical ordering
//! 6. Mutant kills: M2d (decode digest check), M2e (validate in decode), M2f (payload_digest mismatch),
//!    M2h (waypoint ordering), M2j (decode proof-root ordering)
//! 7. Integration with SemanticHandle extraction (with verify(), typed error mappings, and swapped digest rejection)
//! 8. Pinned golden digest literal and canonical byte vector stability
//! 9. Owner pinned to architecture/semantic_hydration.json (fss-agent-core)

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use fss_core::{
    AudioFeaturesArtifact, BoundingBox, BudgetVector, CanonicalDecode, CanonicalDecoder,
    CanonicalEncode, CanonicalEncoder, CaptureInterval, Completeness, ContentDigest, ContractBasis,
    ContractBasisRegistryBytes, ContractError, CropArtifact, DecisionArtifactKind,
    GraphNeighborhoodArtifact, H2_CONTENT, H2_LEVEL_ID, H2_LEVEL_NAME, H2_OWNER, H2_SCHEMA,
    H2DecisionArtifact, H2DecisionArtifactParams, HandleAvailability, HydrationArtifact,
    HydrationError, HydrationLevel, KeyframeArtifact, LaboratoryAccess, LedgerAnchor,
    MAX_CANONICAL_BYTES_LEN, RedactedRegion, RedactionTransform, SemanticHandle, SemanticHandleSpec,
    TimestampNs, TrajectoryArtifact, TrajectoryWaypoint, is_registered_redaction_transform,
};

fn sample_basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
        b"schemas",
        b"operations",
        b"views",
        b"capabilities",
        b"errors",
        b"costs",
        "fss-hydration-contract:test",
    ))
}

fn sample_anchor(epoch: u64) -> LedgerAnchor {
    LedgerAnchor {
        site_lineage: "site:test-h2-facility".to_string(),
        ledger_epoch: epoch,
        commit_sequence: 100,
        adapter_registry_epoch: epoch,
        schema_epoch: epoch,
        policy_epoch: epoch,
        privacy_epoch: epoch,
        state_root: sample_digest(0x42),
    }
}

fn sample_digest(byte: u8) -> ContentDigest {
    ContentDigest::new(fss_core::DigestAlgorithm::Sha256, [byte; 32])
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
    let keyframe = KeyframeArtifact::new(
        TimestampNs(1_000_000_000),
        "stream:cam-01",
        1920,
        1080,
        "image/jpeg",
        vec![region],
    )?;
    Ok(DecisionArtifactKind::Keyframe(keyframe))
}

fn sample_crop() -> Result<DecisionArtifactKind, Box<dyn Error>> {
    let bbox = BoundingBox::new(0.1, 0.2, 0.5, 0.8)?;
    let region = RedactedRegion::new(10, 10, 20, 20, "solid_black_mask")?;
    let crop = CropArtifact::new(
        TimestampNs(1_000_000_000),
        "stream:cam-01",
        bbox,
        Some("entity:vehicle-99".to_string()),
        "image/png",
        vec![region],
    )?;
    Ok(DecisionArtifactKind::Crop(crop))
}

fn sample_trajectory() -> Result<DecisionArtifactKind, Box<dyn Error>> {
    let interval = CaptureInterval::new(TimestampNs(1_000), TimestampNs(2_000))?;
    let wp1 = TrajectoryWaypoint::new(TimestampNs(1_200), 10.0, 20.0, 0.0)?;
    let wp2 = TrajectoryWaypoint::new(TimestampNs(1_800), 15.0, 25.0, 0.0)?;
    let traj = TrajectoryArtifact::new(
        "entity:pedestrian-12",
        interval,
        vec![wp1, wp2],
        "frame:site_local:enu",
        true,
    )?;
    Ok(DecisionArtifactKind::Trajectory(traj))
}

fn sample_graph_neighborhood() -> Result<DecisionArtifactKind, Box<dyn Error>> {
    let mut masked = BTreeSet::new();
    masked.insert("pii:ssn".to_string());
    masked.insert("pii:true_name".to_string());
    let graph = GraphNeighborhoodArtifact::new(
        "entity:node-42",
        2,
        5,
        8,
        sample_digest(0x55),
        masked,
    )?;
    Ok(DecisionArtifactKind::GraphNeighborhood(graph))
}

fn sample_audio_features() -> Result<DecisionArtifactKind, Box<dyn Error>> {
    let interval = CaptureInterval::new(TimestampNs(10_000), TimestampNs(20_000))?;
    let audio = AudioFeaturesArtifact::new(
        interval,
        "channel:mic-03",
        "log_mel_spectrogram",
        100,
        80,
        true,
    )?;
    Ok(DecisionArtifactKind::AudioFeatures(audio))
}

fn sample_h2_params(
    artifact_kind: DecisionArtifactKind,
) -> Result<H2DecisionArtifactParams, Box<dyn Error>> {
    let payload = b"authorized-redacted-artifact-payload-bytes".to_vec();
    let proof_roots = BTreeSet::new();

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
    assert_eq!(H2_OWNER, "fss-agent-core");
    assert_eq!(H2_SCHEMA, "fss.h2_decision_artifact.v1");

    assert_eq!(HydrationLevel::H2.as_str(), "H2");
    assert_eq!(HydrationLevel::H2.level_name(), "decision_artifact");
    assert_eq!(HydrationLevel::H2.content_declaration(), H2_CONTENT);
    assert_eq!(HydrationLevel::H2.owner(), H2_OWNER);
    assert_eq!(HydrationLevel::H2.ordinal(), 2);
}

#[test]
fn test_h2_owner_pinned_to_registry() -> Result<(), Box<dyn Error>> {
    let registry = include_str!("../../../architecture/semantic_hydration.json");
    let key = "\"semantic_owner\": \"";
    let pos = registry.find(key).ok_or("missing semantic_owner in registry")?;
    let start = pos + key.len();
    let end = registry[start..].find('"').ok_or("malformed semantic_owner string")? + start;
    let expected_owner = &registry[start..end];
    assert_eq!(expected_owner, "fss-agent-core");
    assert_eq!(H2_OWNER, expected_owner);
    assert_eq!(HydrationLevel::H2.owner(), expected_owner);

    let params = sample_h2_params(sample_keyframe()?)?;
    let artifact = H2DecisionArtifact::new(params)?;
    assert_eq!(artifact.owner(), expected_owner);
    Ok(())
}

#[test]
fn test_h2_bounding_box_valid_and_planted_bypasses() -> Result<(), Box<dyn Error>> {
    let valid_box = BoundingBox::new(0.0, 0.0, 1.0, 1.0)?;
    valid_box.validate()?;
    assert_eq!(valid_box.x_min(), 0.0);
    assert_eq!(valid_box.y_min(), 0.0);
    assert_eq!(valid_box.x_max(), 1.0);
    assert_eq!(valid_box.y_max(), 1.0);

    // Reject -0.0 in all coordinate positions
    assert_eq!(
        BoundingBox::new(-0.0_f32, 0.0, 1.0, 1.0).err(),
        Some(ContractError::InvalidSpatialExtent)
    );
    assert_eq!(
        BoundingBox::new(0.0, -0.0_f32, 1.0, 1.0).err(),
        Some(ContractError::InvalidSpatialExtent)
    );

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
    let bytes = encoder.finish_checked()?;
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
    assert_eq!(valid_region.x(), 10);
    assert_eq!(valid_region.y(), 20);
    assert_eq!(valid_region.width(), 100);
    assert_eq!(valid_region.height(), 200);
    assert_eq!(valid_region.method(), "blur");

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
    // Planted u32 overflow
    assert_eq!(
        RedactedRegion::new(u32::MAX, 10, 10, 10, "blur").err(),
        Some(ContractError::InvalidSpatialExtent)
    );

    // Canonical roundtrip
    let mut encoder = CanonicalEncoder::new();
    valid_region.encode_canonical(&mut encoder);
    let bytes = encoder.finish_checked()?;
    let mut decoder = CanonicalDecoder::new(&bytes);
    let decoded = RedactedRegion::decode_canonical(&mut decoder)?;
    decoder.ensure_finished()?;
    assert_eq!(valid_region, decoded);

    Ok(())
}

#[test]
fn test_h2_keyframe_redacted_regions_fit_frame() -> Result<(), Box<dyn Error>> {
    // Redacted region that exceeds frame bounds (100+50 > 16) fails validation
    let out_of_bounds_region = RedactedRegion::new(100, 100, 50, 50, "gaussian_blur")?;
    let res = KeyframeArtifact::new(
        TimestampNs(1_000_000_000),
        "stream:cam-01",
        16,
        16,
        "image/jpeg",
        vec![out_of_bounds_region],
    );
    assert_eq!(res.err(), Some(ContractError::InvalidSpatialExtent));

    // Valid region fitting inside 16x16 frame succeeds
    let valid_region = RedactedRegion::new(2, 2, 8, 8, "gaussian_blur")?;
    let keyframe = KeyframeArtifact::new(
        TimestampNs(1_000_000_000),
        "stream:cam-01",
        16,
        16,
        "image/jpeg",
        vec![valid_region],
    )?;
    keyframe.validate()?;
    assert_eq!(keyframe.width(), 16);
    assert_eq!(keyframe.height(), 16);
    assert_eq!(keyframe.stream_id(), "stream:cam-01");
    assert_eq!(keyframe.format(), "image/jpeg");
    assert_eq!(keyframe.redacted_regions().len(), 1);

    Ok(())
}

#[test]
fn test_h2_trajectory_waypoint_valid_and_planted_bypasses() -> Result<(), Box<dyn Error>> {
    let valid_wp = TrajectoryWaypoint::new(TimestampNs(100), 1.0, 2.0, 3.0)?;
    valid_wp.validate()?;
    assert_eq!(valid_wp.timestamp_ns(), TimestampNs(100));
    assert_eq!(valid_wp.x(), 1.0);
    assert_eq!(valid_wp.y(), 2.0);
    assert_eq!(valid_wp.z(), 3.0);

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
    let bytes = encoder.finish_checked()?;
    let mut decoder = CanonicalDecoder::new(&bytes);
    let decoded = TrajectoryWaypoint::decode_canonical(&mut decoder)?;
    decoder.ensure_finished()?;
    assert_eq!(valid_wp, decoded);

    Ok(())
}

#[test]
fn test_h2_trajectory_strictly_increasing_waypoints() -> Result<(), Box<dyn Error>> {
    let interval = CaptureInterval::new(TimestampNs(1_000), TimestampNs(3_000))?;
    let wp1 = TrajectoryWaypoint::new(TimestampNs(1_200), 10.0, 20.0, 0.0)?;
    let wp2_duplicate = TrajectoryWaypoint::new(TimestampNs(1_200), 15.0, 25.0, 0.0)?;
    let wp2_decreasing = TrajectoryWaypoint::new(TimestampNs(1_100), 15.0, 25.0, 0.0)?;
    let wp2_valid = TrajectoryWaypoint::new(TimestampNs(1_500), 15.0, 25.0, 0.0)?;

    // Duplicate timestamp rejected
    let dup_res = TrajectoryArtifact::new(
        "entity:pedestrian-12",
        interval,
        vec![wp1, wp2_duplicate],
        "frame:site_local:enu",
        true,
    );
    assert_eq!(dup_res.err(), Some(ContractError::NonCanonicalOrdering));

    // Decreasing timestamp rejected
    let dec_res = TrajectoryArtifact::new(
        "entity:pedestrian-12",
        interval,
        vec![wp1, wp2_decreasing],
        "frame:site_local:enu",
        true,
    );
    assert_eq!(dec_res.err(), Some(ContractError::NonCanonicalOrdering));

    // Strictly increasing succeeds
    let valid_traj = TrajectoryArtifact::new(
        "entity:pedestrian-12",
        interval,
        vec![wp1, wp2_valid],
        "frame:site_local:enu",
        true,
    )?;
    valid_traj.validate()?;
    assert_eq!(valid_traj.entity_anchor(), "entity:pedestrian-12");
    assert_eq!(valid_traj.coordinate_frame(), "frame:site_local:enu");
    assert!(valid_traj.coarsened());
    assert_eq!(valid_traj.waypoints().len(), 2);

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
        let bytes = enc.finish_checked()?;
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
        assert_eq!(artifact.owner(), "fss-agent-core");
        assert_eq!(artifact.content_type(), expected_content_type);

        let art_bytes = artifact.to_canonical_bytes()?;
        let decoded_art = H2DecisionArtifact::from_canonical_bytes(&art_bytes)?;
        decoded_art.verify()?;
        assert_eq!(artifact, decoded_art);

        // Convert to universal HydrationArtifact with re-validation
        let universal = artifact.to_hydration_artifact()?;
        assert_eq!(universal.level, HydrationLevel::H2);
        assert_eq!(universal.content_type, expected_content_type);
        assert_eq!(universal.payload, artifact.payload());
        assert_eq!(universal.payload_digest, artifact.payload_digest());

        // TryFrom conversion
        let from_try: HydrationArtifact = artifact.clone().try_into()?;
        assert_eq!(from_try, universal);
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

    // 3. Payload capped at <= MAX_CANONICAL_BYTES_LEN
    let mut p2_oversize = sample_h2_params(sample_keyframe()?)?;
    p2_oversize.payload = vec![0u8; MAX_CANONICAL_BYTES_LEN + 1];
    let err2_oversize = H2DecisionArtifact::new(p2_oversize);
    assert!(matches!(
        err2_oversize,
        Err(HydrationError::Contract(ContractError::EvidenceRequired))
    ));

    // 4. Proof roots must bind subject digest
    let p3 = sample_h2_params(sample_keyframe()?)?;
    let artifact3 = H2DecisionArtifact::new(p3)?;
    assert!(artifact3.proof_roots().contains(&artifact3.subject_digest()));
    assert!(artifact3.proof_roots().contains(&artifact3.payload_digest()));

    // 5. Forbidden completeness states
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

    // 6. Expired retention (retention_until < published_at)
    let mut p5 = sample_h2_params(sample_keyframe()?)?;
    p5.published_at = TimestampNs(2_000);
    p5.retention_until = TimestampNs(1_000);
    let err5 = H2DecisionArtifact::new(p5);
    assert!(matches!(err5, Err(HydrationError::ContinuationExpired)));

    // 7. Redaction allowlist enforcement: unregistered transforms refused
    let unregistered_transforms = [
        "unredacted_raw_media",
        "raw_undecoded_stream",
        "raw_camera_packets",
        "unmasked_pii",
        "unredacted",
        "unredacted ",
        "no_redaction",
        "passthrough",
        "identity",
        "none",
        "unknown:arbitrary_transform",
    ];
    for red in unregistered_transforms {
        assert!(!is_registered_redaction_transform(red));
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
    }

    // Registered transforms pass
    for t in RedactionTransform::ALL {
        assert!(is_registered_redaction_transform(t.as_str()));
        let mut p_ok = sample_h2_params(sample_keyframe()?)?;
        p_ok.applied_redaction_transform = t.as_str().to_string();
        let art_ok = H2DecisionArtifact::new(p_ok)?;
        assert_eq!(art_ok.applied_redaction_transform(), t.as_str());
    }

    // Privacy class "privacy:nonessential" is accepted (not falsely refused by naive substring matching)
    let mut p_nonessential = sample_h2_params(sample_keyframe()?)?;
    p_nonessential.privacy_class = "privacy:nonessential".to_string();
    let art_nonessential = H2DecisionArtifact::new(p_nonessential)?;
    assert_eq!(art_nonessential.privacy_class(), "privacy:nonessential");

    // 8. Empty authorization grant ID
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
    let mut bytes = artifact.to_canonical_bytes()?;

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
    let mut bytes = artifact.to_canonical_bytes()?;

    // Mutate the first schema string from fss.h2_decision_artifact.v1 to something else
    let mut custom_enc = CanonicalEncoder::new();
    custom_enc.text("fss.unauthorized_rogue_schema.v1");
    let custom_bytes = custom_enc.finish_checked()?;
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
    assert_eq!(artifact.handle_id(), handle.handle_id);
    assert_eq!(artifact.subject_id(), handle.subject_id);

    // Missing H2 cost in handle returns typed LevelUnavailable error
    let mut costs_missing_h2 = BTreeMap::new();
    costs_missing_h2.insert(HydrationLevel::H0, sample_budget()?);
    costs_missing_h2.insert(HydrationLevel::H1, sample_budget()?);
    let mut caps_for_handle = BTreeMap::new();
    caps_for_handle.insert(HydrationLevel::H0, BTreeSet::from(["cap:h0".to_string()]));
    caps_for_handle.insert(HydrationLevel::H1, BTreeSet::from(["cap:h1".to_string()]));
    caps_for_handle.insert(HydrationLevel::H2, BTreeSet::from(["cap:h2".to_string()]));

    let mut handle_missing_cost = handle.clone();
    handle_missing_cost.estimated_costs = costs_missing_h2;
    let err_cost = handle_missing_cost.to_h2_decision_artifact(
        sample_keyframe()?,
        b"data".to_vec(),
        [],
        "transform:face_blur",
        "grant:1",
        Completeness::Complete,
    );
    assert!(matches!(err_cost, Err(HydrationError::LevelUnavailable)));

    // Missing H2 capabilities in handle returns typed LevelUnavailable error
    let mut handle_missing_caps = handle.clone();
    handle_missing_caps.required_capabilities.remove(&HydrationLevel::H2);
    let err_caps = handle_missing_caps.to_h2_decision_artifact(
        sample_keyframe()?,
        b"data".to_vec(),
        [],
        "transform:face_blur",
        "grant:1",
        Completeness::Complete,
    );
    assert!(matches!(err_caps, Err(HydrationError::LevelUnavailable)));

    // Tampered handle (swapped subject digest) rejected by handle.verify()
    let mut tampered_handle = handle.clone();
    tampered_handle.subject_digest = sample_digest(0x99);
    let err_tampered = tampered_handle.to_h2_decision_artifact(
        sample_keyframe()?,
        b"data".to_vec(),
        [],
        "transform:face_blur",
        "grant:1",
        Completeness::Complete,
    );
    assert!(err_tampered.is_err());

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

#[test]
fn test_h2_exact_match_decoders() {
    // HydrationLevel exact match
    assert_eq!("H2".parse::<HydrationLevel>().ok(), Some(HydrationLevel::H2));
    assert_eq!(" H2 ".parse::<HydrationLevel>().err(), Some(ContractError::InvalidIdentifier));
    assert_eq!("h2".parse::<HydrationLevel>().err(), Some(ContractError::InvalidIdentifier));
    assert_eq!("decision_artifact".parse::<HydrationLevel>().err(), Some(ContractError::InvalidIdentifier));

    // HandleAvailability exact match
    assert_eq!("available".parse::<HandleAvailability>().ok(), Some(HandleAvailability::Available));
    assert_eq!(" available ".parse::<HandleAvailability>().err(), Some(ContractError::InvalidIdentifier));
    assert_eq!("AVAILABLE".parse::<HandleAvailability>().err(), Some(ContractError::InvalidIdentifier));
}

#[test]
fn test_h2_decode_level_negatives_kill_mutants() -> Result<(), Box<dyn Error>> {
    let params = sample_h2_params(sample_keyframe()?)?;
    let artifact = H2DecisionArtifact::new(params)?;
    let canonical_bytes = artifact.to_canonical_bytes()?;

    // 1. M2d: Tampered artifact digest at the tail of canonical bytes
    let mut tampered_digest_bytes = canonical_bytes.clone();
    let tail_len = tampered_digest_bytes.len();
    tampered_digest_bytes[tail_len - 1] ^= 0x01;
    let err_m2d = H2DecisionArtifact::from_canonical_bytes(&tampered_digest_bytes);
    assert_eq!(err_m2d.err(), Some(ContractError::DigestMismatch));

    // 2. M2e: Encoded bytes with invalid spatial bounds (negative zero in bounding box)
    let bad_box_bytes = {
        let mut enc = CanonicalEncoder::new();
        enc.text(H2_SCHEMA);
        enc.text("handle:bad");
        enc.text("subject:bad");
        enc.digest(sample_digest(0x01));
        enc.u8(2); // Crop tag
        enc.text("fss.h2_crop_artifact.v1"); // inner crop schema
        TimestampNs(100).encode_canonical(&mut enc);
        enc.text("stream:01");
        // Bad bounding box with -0.0
        enc.u32((-0.0_f32).to_bits());
        enc.u32(0.0_f32.to_bits());
        enc.u32(1.0_f32.to_bits());
        enc.u32(1.0_f32.to_bits());
        enc.bool(false); // target_entity_anchor None
        enc.text("image/png");
        enc.u64(0); // 0 redacted regions
        enc.finish_checked()?
    };
    let mut dec_bad_crop = CanonicalDecoder::new(&bad_box_bytes);
    assert!(DecisionArtifactKind::decode_canonical(&mut dec_bad_crop).is_err());

    // 3. M2f: Encoded bytes with payload_digest mismatch
    let mut tampered_payload_digest_bytes = canonical_bytes.clone();
    // Locate the payload_digest in canonical bytes: after payload bytes
    let payload_bytes = artifact.payload();
    if let Some(pos) = tampered_payload_digest_bytes
        .windows(payload_bytes.len())
        .position(|w| w == payload_bytes)
    {
        let digest_pos = pos + payload_bytes.len();
        if digest_pos + 36 < tampered_digest_bytes.len() {
            tampered_payload_digest_bytes[digest_pos + 10] ^= 0x02;
            let err_m2f = H2DecisionArtifact::from_canonical_bytes(&tampered_payload_digest_bytes);
            assert!(err_m2f.is_err());
        }
    }

    // 4. M2h: TrajectoryArtifact decode with non-increasing waypoints
    let wp_non_increasing_bytes = {
        let mut enc = CanonicalEncoder::new();
        enc.text("entity:track-1");
        CaptureInterval::new(TimestampNs(100), TimestampNs(500))?.encode_canonical(&mut enc);
        enc.u64(2); // 2 waypoints
        TrajectoryWaypoint::new(TimestampNs(300), 1.0, 2.0, 3.0)?.encode_canonical(&mut enc);
        TrajectoryWaypoint::new(TimestampNs(200), 4.0, 5.0, 6.0)?.encode_canonical(&mut enc); // Decreasing
        enc.text("frame:enu");
        enc.bool(false);
        enc.finish_checked()?
    };
    let mut dec_wp = CanonicalDecoder::new(&wp_non_increasing_bytes);
    let res_wp = TrajectoryArtifact::decode_canonical(&mut dec_wp);
    assert_eq!(res_wp.err(), Some(ContractError::NonCanonicalOrdering));

    // 5. M2j: Proof roots out of order in H2DecisionArtifact decode
    let bad_proof_roots_bytes = {
        let mut enc = CanonicalEncoder::new();
        enc.text(H2_SCHEMA);
        enc.text("handle:m2j");
        enc.text("subject:m2j");
        enc.digest(sample_digest(0x11));
        sample_keyframe()?.encode_canonical(&mut enc);
        enc.bytes(b"sample-payload");
        enc.digest(ContentDigest::sha256(b"sample-payload"));
        // 2 proof roots out of order
        enc.u64(2);
        enc.digest(sample_digest(0x99));
        enc.digest(sample_digest(0x11)); // out of order: 0x99 > 0x11
        enc.u8(Completeness::Complete.code());
        enc.text("privacy:operational");
        enc.text("transform:face_blur");
        enc.text("grant:m2j");
        sample_anchor(1).encode_canonical(&mut enc);
        sample_basis().encode_canonical(&mut enc);
        sample_budget()?.encode_canonical(&mut enc);
        TimestampNs(1_000).encode_canonical(&mut enc);
        TimestampNs(2_000).encode_canonical(&mut enc);
        enc.digest(sample_digest(0xaa));
        enc.finish_checked()?
    };
    let mut dec_roots = CanonicalDecoder::new(&bad_proof_roots_bytes);
    let res_roots = H2DecisionArtifact::decode_canonical(&mut dec_roots);
    assert_eq!(res_roots.err(), Some(ContractError::NonCanonicalOrdering));

    Ok(())
}

#[test]
fn test_h2_golden_digest_and_canonical_bytes() -> Result<(), Box<dyn Error>> {
    let keyframe = sample_keyframe()?;
    let params = sample_h2_params(keyframe)?;
    let artifact = H2DecisionArtifact::new(params)?;

    let canonical_bytes = artifact.to_canonical_bytes()?;

    // Pinned canonical byte vector length (Item 1)
    assert_eq!(canonical_bytes.len(), 1051);

    let bytes_digest = ContentDigest::sha256(&canonical_bytes);
    let canonical_digest = artifact.canonical_digest()?;
    let artifact_digest = artifact.artifact_digest();

    assert_eq!(bytes_digest, canonical_digest);

    // Independently derived golden digest literals (Item 1)
    let golden_canonical_digest = ContentDigest::parse(
        "sha256:0cfaf70a3fcf4309bd9314ecaae4187ad47dbf4ca330e251d62475abe26698e8",
    )?;
    let golden_artifact_digest = ContentDigest::parse(
        "sha256:67d7c9dc1b9122d7cfc1e04966bbe9b95b417c00b1e4bd55772b913bc88cc111",
    )?;

    assert_eq!(canonical_digest, golden_canonical_digest);
    assert_eq!(artifact_digest, golden_artifact_digest);

    // Verify bit-exact roundtrip
    let decoded = H2DecisionArtifact::from_canonical_bytes(&canonical_bytes)?;
    assert_eq!(decoded, artifact);
    assert_eq!(decoded.canonical_digest()?, golden_canonical_digest);
    assert_eq!(decoded.artifact_digest(), golden_artifact_digest);

    Ok(())
}
