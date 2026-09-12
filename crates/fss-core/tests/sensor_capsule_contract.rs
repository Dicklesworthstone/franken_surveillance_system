#![forbid(unsafe_code)]
//! Integration and property contract tests for SensorCapsuleV1 (FSS-006).
//!
//! Verifies:
//! - Canonical sensor capsule v1 binary and JSON round-trips (bit-identical).
//! - Source custody and "retained evidence" invariant.
//! - Explicit omission fields and all omission reason variants.
//! - Identity binding enforcement for source, device, and adapter identities.
//! - Typed decode errors for truncation, unknown version, trailing bytes,
//!   and non-canonical encodings without default-on-error.
//! - Hard size bounds tested at exactly bound and bound + 1.
//! - Domain-separated metadata digest computation.

use fss_core::{
    AdapterCapabilities, AdapterGeneration, AdapterId, AdapterIdentity, AdapterKind,
    AppGeneration, CaptureInterval, ClockBasis, ContentDigest, ContinuityState,
    ContractError, CredentialMethod, DecodeState, DeviceCapabilities, DeviceClass,
    DeviceGeneration, DeviceId, DeviceIdentity, ExplicitOmission, FirmwareGeneration,
    IntegrityWitness, IsolationMode, MediaDescriptor, MediaKind, ModelGeneration,
    OmissionReason, PrivacyDescriptor, PublicationDescriptor, PublicationState,
    RedactionState, SensorCapsuleV1, SourceCustody, SourceId, SourceIdentity,
    SourceKind, StreamGeneration, TimestampNs, CapsuleDecodeError, CapsuleId,
    SensorId, StreamId, MAX_CAPSULE_ID_LEN, MAX_CODEC_LEN, MAX_CONTAINER_LEN,
    MAX_STORAGE_HANDLE_LEN, MAX_POLICY_RULE_LEN, MAX_FIRMWARE_FINGERPRINT_LEN,
    MAX_RETENTION_CLASS_LEN, SENSOR_CAPSULE_SCHEMA, SENSOR_CAPSULE_METADATA_DOMAIN,
};

fn sample_identities() -> Result<(SourceIdentity, DeviceIdentity, AdapterIdentity), ContractError> {
    let device_id = DeviceId::parse("device:camera-entry-01")?;
    let generation = DeviceGeneration::parse("gen:dev:2026-09-11:rev1")?;
    let model_gen = ModelGeneration::parse("gen:model:yolo-pose-v4")?;
    let firmware_version = FirmwareGeneration::parse("gen:firmware:v1-2-64")?;
    let application_version = Some(AppGeneration::parse("gen:app:2026-09")?);

    let device = DeviceIdentity {
        device_id: device_id.clone(),
        generation,
        manufacturer: "Axis".to_string(),
        model: "P3245-V".to_string(),
        hardware_revision: "HW-2.0".to_string(),
        firmware_version,
        application_version,
        model_generation: Some(model_gen),
        device_class: DeviceClass::Camera,
        capabilities: DeviceCapabilities::OPTICAL_ZOOM.union(DeviceCapabilities::AUDIO_CAPTURE),
        failure_domain: "power:poe-switch-1".to_string(),
    };
    device.verify()?;

    let adapter_id = AdapterId::parse("adapter:rtsp-pure-rust-01")?;
    let adapter_gen = AdapterGeneration::parse("gen:adapter:rtsp-rust-v1")?;

    let adapter = AdapterIdentity {
        adapter_id: adapter_id.clone(),
        generation: adapter_gen,
        adapter_kind: AdapterKind::Rtsp,
        protocol_profile: "rtsp:1.0:tcp".to_string(),
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::Token,
        capabilities: AdapterCapabilities::STREAMING.union(AdapterCapabilities::TIME_SYNC),
        max_bandwidth_bytes_per_sec: 100_000_000,
        max_buffer_frames: 32,
        request_timeout_ns: 5_000_000_000,
    };
    adapter.verify()?;

    let source_id = SourceId::parse("src:camera-entry-01-main")?;
    let stream_generation = StreamGeneration::parse("gen:stream:1080p30-h264")?;

    let source = SourceIdentity {
        source_id,
        device_id,
        adapter_id,
        source_kind: SourceKind::PhysicalSensor,
        media_kind: MediaKind::Video,
        channel: "video_main".to_string(),
        nominal_clock_basis: ClockBasis::HostMonotonic,
        stream_generation,
        failure_domain: "net:vlan-10/switch-1".to_string(),
        is_live: true,
    };
    source.verify()?;

    Ok((source, device, adapter))
}

fn sample_capsule() -> Result<SensorCapsuleV1, CapsuleDecodeError> {
    let (source, device, adapter) = sample_identities().map_err(CapsuleDecodeError::Contract)?;

    let source_digest = ContentDigest::sha256(b"simulated-raw-video-bytes");
    let payload_bytes = 65536u64;

    let capsule = SensorCapsuleV1 {
        schema: SENSOR_CAPSULE_SCHEMA.to_string(),
        capsule_id: CapsuleId::parse("cap:camera-entry-01:seq0001").map_err(CapsuleDecodeError::Contract)?,
        source_id: source.source_id.clone(),
        device_id: device.device_id.clone(),
        adapter_id: adapter.adapter_id.clone(),
        sensor_id: SensorId::parse("sensor:cam01").map_err(CapsuleDecodeError::Contract)?,
        stream_id: StreamId::parse("stream:cam01-video").map_err(CapsuleDecodeError::Contract)?,
        source_identity: source,
        device_identity: device,
        adapter_identity: adapter,
        sequence: 1,
        capture_interval: CaptureInterval::new(TimestampNs(100_000_000), TimestampNs(133_333_333)).map_err(CapsuleDecodeError::Contract)?,
        receive_time_ns: TimestampNs(135_000_000),
        clock_basis: ClockBasis::HostMonotonic,
        custody: SourceCustody::Retained {
            source_digest,
            source_bytes: payload_bytes,
            storage_handle: "store://cas/sha256/feed-seg-0001".to_string(),
        },
        omission: ExplicitOmission::None,
        media: MediaDescriptor {
            kind: MediaKind::Video,
            codec: "h264".to_string(),
            container: Some("mp4".to_string()),
            width: Some(1920),
            height: Some(1080),
            source_bytes: payload_bytes,
            frame_count: 30,
            source_digest: Some(source_digest),
            proxy_digest: None,
        },
        integrity: IntegrityWitness {
            metadata_digest: ContentDigest::sha256(b"sample-metadata"),
            continuity: ContinuityState::Verified,
            decode: DecodeState::Verified,
            firmware_fingerprint: Some("sha256:abcd1234ef567890abcd1234ef567890".to_string()),
        },
        privacy: PrivacyDescriptor {
            mask_generation: None,
            redaction_state: RedactionState::NotRequired,
            retention_class: "standard_retention_30d".to_string(),
        },
        publication: PublicationDescriptor {
            state: PublicationState::Published,
            root_digest: ContentDigest::sha256(b"merkle-root-at-rev-42"),
            ledger_revision: Some(42),
        },
    };

    capsule.verify()?;
    Ok(capsule)
}

#[test]
fn test_schema_and_domain_constants() {
    assert_eq!(SensorCapsuleV1::SCHEMA, "fss.sensor_capsule.v1");
    assert_eq!(SensorCapsuleV1::METADATA_DOMAIN, "fss.sensor_capsule.metadata.v1");
    assert_eq!(SENSOR_CAPSULE_SCHEMA, "fss.sensor_capsule.v1");
    assert_eq!(SENSOR_CAPSULE_METADATA_DOMAIN, "fss.sensor_capsule.metadata.v1");
}

#[test]
fn test_binary_round_trip_bit_identical() -> Result<(), CapsuleDecodeError> {
    let capsule = sample_capsule()?;
    let bytes1 = capsule.to_versioned_bytes()?;

    // Starts with FSSC magic header and version 1
    assert!(bytes1.len() > 6);
    assert_eq!(&bytes1[0..4], b"FSSC");
    assert_eq!(&bytes1[4..6], &1u16.to_be_bytes());

    // Decodes cleanly to identical capsule
    let decoded = SensorCapsuleV1::from_versioned_bytes(&bytes1)?;
    assert_eq!(capsule, decoded);

    // Re-encodes bit-identically
    let bytes2 = decoded.to_versioned_bytes()?;
    assert_eq!(bytes1, bytes2);
    Ok(())
}

#[test]
fn test_json_round_trip_bit_identical() -> Result<(), CapsuleDecodeError> {
    let capsule = sample_capsule()?;
    let json1 = capsule.to_canonical_json();

    // Decodes cleanly from JSON
    let decoded = SensorCapsuleV1::from_json(&json1)?;
    assert_eq!(capsule, decoded);

    // Re-encodes bit-identically
    let json2 = decoded.to_canonical_json();
    assert_eq!(json1, json2);
    Ok(())
}

#[test]
fn test_cross_codec_round_trip() -> Result<(), CapsuleDecodeError> {
    let capsule = sample_capsule()?;

    // 1. Binary -> Capsule
    let bin1 = capsule.to_versioned_bytes()?;
    let from_bin = SensorCapsuleV1::from_versioned_bytes(&bin1)?;
    assert_eq!(capsule, from_bin);

    // 2. Capsule -> JSON
    let json1 = from_bin.to_canonical_json();
    let from_json = SensorCapsuleV1::from_json(&json1)?;
    assert_eq!(capsule, from_json);

    // 3. JSON decoded -> Binary
    let bin2 = from_json.to_versioned_bytes()?;
    assert_eq!(bin1, bin2);

    // 4. Binary decoded -> JSON
    let from_bin2 = SensorCapsuleV1::from_versioned_bytes(&bin2)?;
    let json2 = from_bin2.to_canonical_json();
    assert_eq!(json1, json2);
    Ok(())
}

#[test]
fn test_retained_evidence_invariant() -> Result<(), CapsuleDecodeError> {
    let mut capsule = sample_capsule()?;

    // Case 1: SourceCustody::Retained is retained evidence
    assert!(capsule.is_retained_evidence());
    assert!(capsule.require_retained_evidence().is_ok());

    // Case 2: SourceCustody::NotRetained is NOT retained evidence
    capsule.custody = SourceCustody::NotRetained;
    capsule.media.source_digest = None;
    assert!(!capsule.is_retained_evidence());
    assert_eq!(
        capsule.require_retained_evidence(),
        Err(CapsuleDecodeError::Contract(ContractError::EvidenceRequired))
    );

    Ok(())
}

#[test]
fn test_explicit_omission_all_reasons_round_trip() -> Result<(), CapsuleDecodeError> {
    let base_capsule = sample_capsule()?;

    // None is not omitted
    assert!(!base_capsule.omission.is_omitted());

    let omission_reasons = [
        OmissionReason::None,
        OmissionReason::PrivacyRedaction,
        OmissionReason::ResourcePressure,
        OmissionReason::RetentionPolicy,
        OmissionReason::CapabilityFiltered,
        OmissionReason::TransientPreviewOnly,
        OmissionReason::UpstreamMissing,
    ];

    for reason in omission_reasons {
        let mut capsule = base_capsule.clone();
        if reason == OmissionReason::None {
            capsule.omission = ExplicitOmission::None;
            assert!(!capsule.omission.is_omitted());
        } else {
            capsule.omission = ExplicitOmission::Omitted {
                reason,
                policy_rule: "rule:adaptive-bandwidth-shedding".to_string(),
                omitted_bytes: 1048576,
                omitted_frames: 30,
            };
            assert!(capsule.omission.is_omitted());
        }

        capsule.verify()?;

        // Binary round-trip
        let bin = capsule.to_versioned_bytes()?;
        let decoded_bin = SensorCapsuleV1::from_versioned_bytes(&bin)?;
        assert_eq!(capsule, decoded_bin);

        // JSON round-trip
        let json = capsule.to_canonical_json();
        let decoded_json = SensorCapsuleV1::from_json(&json)?;
        assert_eq!(capsule, decoded_json);
    }

    Ok(())
}

#[test]
fn test_identity_binding_enforcement() -> Result<(), CapsuleDecodeError> {
    let mut capsule = sample_capsule()?;

    // 1. Valid capsule verifies
    assert!(capsule.verify().is_ok());

    // 2. Mismatched source_id fails closed
    let original_source_id = capsule.source_id.clone();
    capsule.source_id = SourceId::parse("src:other-sensor-feed").map_err(CapsuleDecodeError::Contract)?;
    assert_eq!(
        capsule.verify(),
        Err(CapsuleDecodeError::Contract(ContractError::InvalidIdentifier))
    );
    capsule.source_id = original_source_id;

    // 3. Mismatched device_id fails closed
    let original_device_id = capsule.device_id.clone();
    capsule.device_id = DeviceId::parse("device:other-camera").map_err(CapsuleDecodeError::Contract)?;
    assert_eq!(
        capsule.verify(),
        Err(CapsuleDecodeError::Contract(ContractError::InvalidIdentifier))
    );
    capsule.device_id = original_device_id;

    // 4. Mismatched adapter_id fails closed
    let original_adapter_id = capsule.adapter_id.clone();
    capsule.adapter_id = AdapterId::parse("adapter:other-adapter").map_err(CapsuleDecodeError::Contract)?;
    assert_eq!(
        capsule.verify(),
        Err(CapsuleDecodeError::Contract(ContractError::InvalidIdentifier))
    );
    capsule.adapter_id = original_adapter_id;

    Ok(())
}

#[test]
fn test_temporal_invariants_enforcement() -> Result<(), CapsuleDecodeError> {
    let mut capsule = sample_capsule()?;

    // receive_time_ns before interval start fails closed
    let orig_receive = capsule.receive_time_ns;
    capsule.receive_time_ns = TimestampNs(capsule.capture_interval.earliest.0 - 1);
    assert_eq!(
        capsule.verify(),
        Err(CapsuleDecodeError::Contract(ContractError::InvertedTimeInterval))
    );
    capsule.receive_time_ns = orig_receive;

    Ok(())
}

#[test]
fn test_decode_errors_truncation() {
    // 0 bytes
    assert_eq!(
        SensorCapsuleV1::from_versioned_bytes(&[]),
        Err(CapsuleDecodeError::Truncated { expected_min: 6, actual: 0 })
    );

    // 4 bytes (magic only)
    assert_eq!(
        SensorCapsuleV1::from_versioned_bytes(b"FSSC"),
        Err(CapsuleDecodeError::Truncated { expected_min: 6, actual: 4 })
    );

    // Header ok, but empty payload
    let mut truncated = b"FSSC".to_vec();
    truncated.extend_from_slice(&1u16.to_be_bytes());
    assert_eq!(
        SensorCapsuleV1::from_versioned_bytes(&truncated),
        Err(CapsuleDecodeError::Truncated { expected_min: 1, actual: 0 })
    );
}

#[test]
fn test_decode_errors_unknown_magic_and_version() {
    // Invalid magic header
    let invalid_magic = b"NOPE\x00\x01";
    assert_eq!(
        SensorCapsuleV1::from_versioned_bytes(invalid_magic),
        Err(CapsuleDecodeError::NonCanonicalEncoding {
            detail: "invalid magic header: expected FSSC".to_string(),
        })
    );

    // Unknown version 2
    let unknown_version = b"FSSC\x00\x02";
    assert_eq!(
        SensorCapsuleV1::from_versioned_bytes(unknown_version),
        Err(CapsuleDecodeError::UnknownVersion { version: 2 })
    );
}

#[test]
fn test_decode_errors_trailing_bytes() -> Result<(), CapsuleDecodeError> {
    let capsule = sample_capsule()?;
    let mut bytes = capsule.to_versioned_bytes()?;

    // Append 1 trailing byte
    bytes.push(0xFF);
    assert_eq!(
        SensorCapsuleV1::from_versioned_bytes(&bytes),
        Err(CapsuleDecodeError::TrailingBytes { count: 1 })
    );

    // Append 3 trailing bytes
    bytes.extend_from_slice(&[0x01, 0x02]);
    assert_eq!(
        SensorCapsuleV1::from_versioned_bytes(&bytes),
        Err(CapsuleDecodeError::TrailingBytes { count: 3 })
    );

    // Trailing bytes in JSON
    let mut json = capsule.to_canonical_json();
    json.push(' ');
    json.push('X');
    assert!(SensorCapsuleV1::from_json(&json).is_err());

    Ok(())
}

#[test]
fn test_bounded_size_capsule_id() -> Result<(), CapsuleDecodeError> {
    let mut capsule = sample_capsule()?;

    // Exact bound: 128 bytes (with prefix "cap:" -> 4 prefix + 124 chars)
    let bound_id = format!("cap:{}", "a".repeat(MAX_CAPSULE_ID_LEN - 4));
    assert_eq!(bound_id.len(), MAX_CAPSULE_ID_LEN);
    capsule.capsule_id = CapsuleId::parse(&bound_id).map_err(CapsuleDecodeError::Contract)?;
    assert!(capsule.verify().is_ok());

    // Bound + 1: 129 bytes via JSON decoding
    let over_id = format!("cap:{}", "a".repeat(MAX_CAPSULE_ID_LEN - 3));
    assert_eq!(over_id.len(), MAX_CAPSULE_ID_LEN + 1);
    let json = capsule.to_canonical_json();
    let over_json = json.replace(&bound_id, &over_id);
    assert_eq!(
        SensorCapsuleV1::from_json(&over_json),
        Err(CapsuleDecodeError::OverLimitLength {
            field: "capsuleId",
            limit: MAX_CAPSULE_ID_LEN,
            actual: MAX_CAPSULE_ID_LEN + 1,
        })
    );

    Ok(())
}

#[test]
fn test_bounded_size_codec() -> Result<(), CapsuleDecodeError> {
    let mut capsule = sample_capsule()?;

    // Exact bound: 64 bytes
    let bound_codec = "c".repeat(MAX_CODEC_LEN);
    assert_eq!(bound_codec.len(), MAX_CODEC_LEN);
    capsule.media.codec = bound_codec;
    assert!(capsule.verify().is_ok());

    // Bound + 1: 65 bytes
    let over_codec = "c".repeat(MAX_CODEC_LEN + 1);
    assert_eq!(over_codec.len(), MAX_CODEC_LEN + 1);
    capsule.media.codec = over_codec;
    assert_eq!(
        capsule.verify(),
        Err(CapsuleDecodeError::OverLimitLength {
            field: "media.codec",
            limit: MAX_CODEC_LEN,
            actual: MAX_CODEC_LEN + 1,
        })
    );

    Ok(())
}

#[test]
fn test_bounded_size_container() -> Result<(), CapsuleDecodeError> {
    let mut capsule = sample_capsule()?;

    // Exact bound: 64 bytes
    let bound_container = "m".repeat(MAX_CONTAINER_LEN);
    assert_eq!(bound_container.len(), MAX_CONTAINER_LEN);
    capsule.media.container = Some(bound_container);
    assert!(capsule.verify().is_ok());

    // Bound + 1: 65 bytes
    let over_container = "m".repeat(MAX_CONTAINER_LEN + 1);
    assert_eq!(over_container.len(), MAX_CONTAINER_LEN + 1);
    capsule.media.container = Some(over_container);
    assert_eq!(
        capsule.verify(),
        Err(CapsuleDecodeError::OverLimitLength {
            field: "media.container",
            limit: MAX_CONTAINER_LEN,
            actual: MAX_CONTAINER_LEN + 1,
        })
    );

    Ok(())
}

#[test]
fn test_bounded_size_storage_handle() -> Result<(), CapsuleDecodeError> {
    let mut capsule = sample_capsule()?;

    // Exact bound: 256 bytes
    let bound_handle = "s".repeat(MAX_STORAGE_HANDLE_LEN);
    assert_eq!(bound_handle.len(), MAX_STORAGE_HANDLE_LEN);
    capsule.custody = SourceCustody::Retained {
        source_digest: ContentDigest::sha256(b"simulated-raw-video-bytes"),
        source_bytes: 65536,
        storage_handle: bound_handle,
    };
    assert!(capsule.verify().is_ok());

    // Bound + 1: 257 bytes in custody storage handle
    let over_handle = "s".repeat(MAX_STORAGE_HANDLE_LEN + 1);
    assert_eq!(over_handle.len(), MAX_STORAGE_HANDLE_LEN + 1);
    capsule.custody = SourceCustody::Retained {
        source_digest: ContentDigest::sha256(b"simulated-raw-video-bytes"),
        source_bytes: 65536,
        storage_handle: over_handle,
    };
    assert_eq!(
        capsule.verify(),
        Err(CapsuleDecodeError::OverLimitLength {
            field: "custody.storageHandle",
            limit: MAX_STORAGE_HANDLE_LEN,
            actual: MAX_STORAGE_HANDLE_LEN + 1,
        })
    );

    Ok(())
}

#[test]
fn test_bounded_size_policy_rule() -> Result<(), CapsuleDecodeError> {
    let mut capsule = sample_capsule()?;

    // Exact bound: 256 bytes in omission policy rule
    let bound_rule = "p".repeat(MAX_POLICY_RULE_LEN);
    assert_eq!(bound_rule.len(), MAX_POLICY_RULE_LEN);
    capsule.omission = ExplicitOmission::Omitted {
        reason: OmissionReason::PrivacyRedaction,
        policy_rule: bound_rule,
        omitted_bytes: 100,
        omitted_frames: 1,
    };
    assert!(capsule.verify().is_ok());

    // Bound + 1: 257 bytes in omission policy rule
    let over_rule = "p".repeat(MAX_POLICY_RULE_LEN + 1);
    assert_eq!(over_rule.len(), MAX_POLICY_RULE_LEN + 1);
    capsule.omission = ExplicitOmission::Omitted {
        reason: OmissionReason::PrivacyRedaction,
        policy_rule: over_rule,
        omitted_bytes: 100,
        omitted_frames: 1,
    };
    assert_eq!(
        capsule.verify(),
        Err(CapsuleDecodeError::OverLimitLength {
            field: "omission.policyRule",
            limit: MAX_POLICY_RULE_LEN,
            actual: MAX_POLICY_RULE_LEN + 1,
        })
    );

    Ok(())
}

#[test]
fn test_bounded_size_firmware_fingerprint() -> Result<(), CapsuleDecodeError> {
    let mut capsule = sample_capsule()?;

    // Exact bound: 256 bytes
    let bound_fp = "f".repeat(MAX_FIRMWARE_FINGERPRINT_LEN);
    assert_eq!(bound_fp.len(), MAX_FIRMWARE_FINGERPRINT_LEN);
    capsule.integrity.firmware_fingerprint = Some(bound_fp);
    assert!(capsule.verify().is_ok());

    // Bound + 1: 257 bytes
    let over_fp = "f".repeat(MAX_FIRMWARE_FINGERPRINT_LEN + 1);
    assert_eq!(over_fp.len(), MAX_FIRMWARE_FINGERPRINT_LEN + 1);
    capsule.integrity.firmware_fingerprint = Some(over_fp);
    assert_eq!(
        capsule.verify(),
        Err(CapsuleDecodeError::OverLimitLength {
            field: "integrity.firmwareFingerprint",
            limit: MAX_FIRMWARE_FINGERPRINT_LEN,
            actual: MAX_FIRMWARE_FINGERPRINT_LEN + 1,
        })
    );

    Ok(())
}

#[test]
fn test_bounded_size_retention_class() -> Result<(), CapsuleDecodeError> {
    let mut capsule = sample_capsule()?;

    // Exact bound: 64 bytes
    let bound_class = "r".repeat(MAX_RETENTION_CLASS_LEN);
    assert_eq!(bound_class.len(), MAX_RETENTION_CLASS_LEN);
    capsule.privacy.retention_class = bound_class;
    assert!(capsule.verify().is_ok());

    // Bound + 1: 65 bytes
    let over_class = "r".repeat(MAX_RETENTION_CLASS_LEN + 1);
    assert_eq!(over_class.len(), MAX_RETENTION_CLASS_LEN + 1);
    capsule.privacy.retention_class = over_class;
    assert_eq!(
        capsule.verify(),
        Err(CapsuleDecodeError::OverLimitLength {
            field: "privacy.retentionClass",
            limit: MAX_RETENTION_CLASS_LEN,
            actual: MAX_RETENTION_CLASS_LEN + 1,
        })
    );

    Ok(())
}

#[test]
fn test_metadata_digest_domain_and_separation() -> Result<(), CapsuleDecodeError> {
    let mut capsule = sample_capsule()?;

    let digest1 = capsule.metadata_digest();
    assert_eq!(digest1.bytes().len(), 32);

    // Changing sequence changes the metadata digest deterministically
    capsule.sequence += 1;
    let digest2 = capsule.metadata_digest();
    assert_ne!(digest1, digest2);

    // Modifying custody changes metadata digest
    capsule.custody = SourceCustody::NotRetained;
    capsule.media.source_digest = None;
    let digest3 = capsule.metadata_digest();
    assert_ne!(digest2, digest3);

    // Modifying omission changes metadata digest
    capsule.omission = ExplicitOmission::Omitted {
        reason: OmissionReason::RetentionPolicy,
        policy_rule: "rule:retention".to_string(),
        omitted_bytes: 512,
        omitted_frames: 1,
    };
    let digest4 = capsule.metadata_digest();
    assert_ne!(digest3, digest4);

    Ok(())
}
