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

use std::collections::BTreeSet;
use std::error::Error;

use fss_core::{
    AdapterCapabilities, AdapterGeneration, AdapterId, AdapterIdentity, AdapterKind, AppGeneration,
    CanonicalEncode, CapsuleDecodeError, CapsuleId, CaptureInterval, ClockBasis, ContentDigest,
    ContinuityState, ContractError, CredentialMethod, DecodeState, DeviceCapabilities, DeviceClass,
    DeviceGeneration, DeviceId, DeviceIdentity, ExplicitOmission, FirmwareGeneration,
    IntegrityWitness, IsolationMode, MAX_CAPSULE_ID_LEN, MAX_CODEC_LEN, MAX_CONTAINER_LEN,
    MAX_FIRMWARE_FINGERPRINT_LEN, MAX_POLICY_RULE_LEN, MAX_RETENTION_CLASS_LEN,
    MAX_STORAGE_HANDLE_LEN, MAX_STR_LEN, MAX_UNCERTAINTY_REASON_LEN, MediaDescriptor, MediaKind,
    ModelGeneration, OmissionReason, PrivacyDescriptor, PublicationDescriptor, PublicationState,
    RedactionState, SENSOR_CAPSULE_MAGIC, SENSOR_CAPSULE_METADATA_DOMAIN, SENSOR_CAPSULE_SCHEMA,
    SENSOR_CAPSULE_VERSION_1, SensorCapsuleV1, SensorId, SourceCustody, SourceId, SourceIdentity,
    SourceKind, StreamGeneration, StreamId, TimestampNs,
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

    let mut capsule = SensorCapsuleV1 {
        schema: SENSOR_CAPSULE_SCHEMA.to_string(),
        capsule_id: CapsuleId::parse("cap:camera-entry-01:seq0001")
            .map_err(CapsuleDecodeError::Contract)?,
        source_id: source.source_id.clone(),
        device_id: device.device_id.clone(),
        adapter_id: adapter.adapter_id.clone(),
        sensor_id: SensorId::parse("sensor:cam01").map_err(CapsuleDecodeError::Contract)?,
        stream_id: StreamId::parse("stream:cam01-video").map_err(CapsuleDecodeError::Contract)?,
        source_identity: source,
        device_identity: device,
        adapter_identity: adapter,
        sequence: 1,
        capture_interval: CaptureInterval::new(TimestampNs(100_000_000), TimestampNs(133_333_333))
            .map_err(CapsuleDecodeError::Contract)?,
        capture_uncertainty_reason: "conservative_capture_window".to_string(),
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

    capsule.seal_metadata_digest()?;
    capsule.verify()?;
    Ok(capsule)
}

#[test]
fn test_schema_and_domain_constants() {
    assert_eq!(SensorCapsuleV1::SCHEMA, "fss.sensor_capsule.v1");
    assert_eq!(
        SensorCapsuleV1::METADATA_DOMAIN,
        "fss.sensor_capsule.metadata.v1"
    );
    assert_eq!(SENSOR_CAPSULE_SCHEMA, "fss.sensor_capsule.v1");
    assert_eq!(
        SENSOR_CAPSULE_METADATA_DOMAIN,
        "fss.sensor_capsule.metadata.v1"
    );
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
        Err(CapsuleDecodeError::Contract(
            ContractError::EvidenceRequired
        ))
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

        capsule.seal_metadata_digest()?;
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
    capsule.source_id =
        SourceId::parse("src:other-sensor-feed").map_err(CapsuleDecodeError::Contract)?;
    assert_eq!(
        capsule.verify(),
        Err(CapsuleDecodeError::Contract(
            ContractError::InvalidIdentifier
        ))
    );
    capsule.source_id = original_source_id;

    // 3. Mismatched device_id fails closed
    let original_device_id = capsule.device_id.clone();
    capsule.device_id =
        DeviceId::parse("device:other-camera").map_err(CapsuleDecodeError::Contract)?;
    assert_eq!(
        capsule.verify(),
        Err(CapsuleDecodeError::Contract(
            ContractError::InvalidIdentifier
        ))
    );
    capsule.device_id = original_device_id;

    // 4. Mismatched adapter_id fails closed
    let original_adapter_id = capsule.adapter_id.clone();
    capsule.adapter_id =
        AdapterId::parse("adapter:other-adapter").map_err(CapsuleDecodeError::Contract)?;
    assert_eq!(
        capsule.verify(),
        Err(CapsuleDecodeError::Contract(
            ContractError::InvalidIdentifier
        ))
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
        Err(CapsuleDecodeError::Contract(
            ContractError::InvertedTimeInterval
        ))
    );
    capsule.receive_time_ns = orig_receive;

    Ok(())
}

#[test]
fn test_decode_errors_truncation() {
    // 0 bytes
    assert_eq!(
        SensorCapsuleV1::from_versioned_bytes(&[]),
        Err(CapsuleDecodeError::Truncated {
            expected_min: 6,
            actual: 0
        })
    );

    // 4 bytes (magic only)
    assert_eq!(
        SensorCapsuleV1::from_versioned_bytes(b"FSSC"),
        Err(CapsuleDecodeError::Truncated {
            expected_min: 6,
            actual: 4
        })
    );

    // Header ok, but empty payload
    let mut truncated = b"FSSC".to_vec();
    truncated.extend_from_slice(&1u16.to_be_bytes());
    assert_eq!(
        SensorCapsuleV1::from_versioned_bytes(&truncated),
        Err(CapsuleDecodeError::Truncated {
            expected_min: 1,
            actual: 0
        })
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
    capsule.seal_metadata_digest()?;
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
    capsule.seal_metadata_digest()?;
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
    capsule.seal_metadata_digest()?;
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
    capsule.seal_metadata_digest()?;
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
    capsule.seal_metadata_digest()?;
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
    capsule.seal_metadata_digest()?;
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
    capsule.seal_metadata_digest()?;
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

    let digest1 = capsule.metadata_digest()?;
    assert_eq!(digest1.bytes().len(), 32);

    // Changing sequence changes the metadata digest deterministically
    capsule.sequence += 1;
    let digest2 = capsule.metadata_digest()?;
    assert_ne!(digest1, digest2);

    // Modifying custody changes metadata digest
    capsule.custody = SourceCustody::NotRetained;
    capsule.media.source_digest = None;
    let digest3 = capsule.metadata_digest()?;
    assert_ne!(digest2, digest3);

    // Modifying omission changes metadata digest
    capsule.omission = ExplicitOmission::Omitted {
        reason: OmissionReason::RetentionPolicy,
        policy_rule: "rule:retention".to_string(),
        omitted_bytes: 512,
        omitted_frames: 1,
    };
    let digest4 = capsule.metadata_digest()?;
    assert_ne!(digest3, digest4);

    Ok(())
}

#[test]
fn test_json_decode_unpaired_surrogate_fails_typed() -> Result<(), CapsuleDecodeError> {
    let capsule = sample_capsule()?;
    let json = capsule.to_canonical_json();

    // High surrogate U+D800 without low surrogate must fail with InvalidUnicodeEscape
    let tampered_json = json.replace("standard_retention_30d", "standard_\\uD800_retention");
    assert_eq!(
        SensorCapsuleV1::from_json(&tampered_json),
        Err(CapsuleDecodeError::InvalidUnicodeEscape { codepoint: 0xD800 })
    );

    // Low surrogate U+DC00 without preceding high surrogate must fail with InvalidUnicodeEscape
    let tampered_low = json.replace("standard_retention_30d", "standard_\\uDC00_retention");
    assert_eq!(
        SensorCapsuleV1::from_json(&tampered_low),
        Err(CapsuleDecodeError::InvalidUnicodeEscape { codepoint: 0xDC00 })
    );

    // Valid surrogate pair U+D83D U+DE00 (😀) must decode correctly
    let mut emoji = sample_capsule()?;
    emoji.privacy.retention_class = "retention_😀_30d".to_string();
    emoji.seal_metadata_digest()?;
    let valid_surrogate_json = emoji
        .to_canonical_json()
        .replace("retention_😀_30d", "retention_\\uD83D\\uDE00_30d");
    let decoded = SensorCapsuleV1::from_json(&valid_surrogate_json)?;
    assert_eq!(decoded.privacy.retention_class, "retention_😀_30d");

    Ok(())
}

#[test]
fn test_json_decode_malformed_optional_fields_fail_closed() -> Result<(), CapsuleDecodeError> {
    let capsule = sample_capsule()?;
    let json = capsule.to_canonical_json();

    // 1. Negative width in media must fail closed as an error, never absent
    let json_neg_width = json.replace("\"width\":1920", "\"width\":-1");
    assert!(
        matches!(
            SensorCapsuleV1::from_json(&json_neg_width),
            Err(CapsuleDecodeError::JsonError { .. })
        ),
        "negative width must fail as JsonError"
    );

    // 2. String instead of number for width
    let json_str_width = json.replace("\"width\":1920", "\"width\":\"1920\"");
    assert!(
        matches!(
            SensorCapsuleV1::from_json(&json_str_width),
            Err(CapsuleDecodeError::JsonError { .. })
        ),
        "string width must fail as JsonError"
    );

    // 3. Number instead of string for applicationVersion
    let json_num_app = json.replace(
        "\"applicationVersion\":\"gen:app:2026-09\"",
        "\"applicationVersion\":12345",
    );
    assert!(
        matches!(
            SensorCapsuleV1::from_json(&json_num_app),
            Err(CapsuleDecodeError::JsonError { .. })
        ),
        "numeric applicationVersion must fail as JsonError"
    );

    // 4. Boolean instead of string for firmwareFingerprint
    let json_bool_fp = json.replace(
        "\"firmwareFingerprint\":\"sha256:abcd1234ef567890abcd1234ef567890\"",
        "\"firmwareFingerprint\":true",
    );
    assert!(
        matches!(
            SensorCapsuleV1::from_json(&json_bool_fp),
            Err(CapsuleDecodeError::JsonError { .. })
        ),
        "boolean firmwareFingerprint must fail as JsonError"
    );

    // 5. Negative ledger revision in publication
    let json_neg_rev = json.replace("\"ledgerRevision\":42", "\"ledgerRevision\":-42");
    assert!(
        matches!(
            SensorCapsuleV1::from_json(&json_neg_rev),
            Err(CapsuleDecodeError::JsonError { .. })
        ),
        "negative ledgerRevision must fail as JsonError"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// review-439 regression tests (fss-x4a.6.6)
// ---------------------------------------------------------------------------

type TestResult = Result<(), Box<dyn Error>>;

/// A valid capsule without source custody that declares an explicit omission.
fn sample_omitted_capsule() -> Result<SensorCapsuleV1, CapsuleDecodeError> {
    let mut capsule = sample_capsule()?;
    capsule.custody = SourceCustody::NotRetained;
    capsule.media.source_digest = None;
    capsule.omission = ExplicitOmission::Omitted {
        reason: OmissionReason::PrivacyRedaction,
        policy_rule: "rule:privacy-zone-7".to_string(),
        omitted_bytes: 65536,
        omitted_frames: 30,
    };
    capsule.seal_metadata_digest()?;
    capsule.verify()?;
    Ok(capsule)
}

/// Builds an `FSSC` v1 envelope WITHOUT running `verify()`, so decoders can be fed
/// deliberately invalid capsules.
fn raw_envelope(capsule: &SensorCapsuleV1) -> Result<Vec<u8>, Box<dyn Error>> {
    let payload = capsule.try_canonical_bytes()?;
    let mut out = SENSOR_CAPSULE_MAGIC.to_vec();
    out.extend_from_slice(&SENSOR_CAPSULE_VERSION_1.to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Canonical binary text encoding: 64-bit big-endian byte length, then UTF-8 bytes.
fn encoded_text(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut out = u64::try_from(text.len())?.to_be_bytes().to_vec();
    out.extend_from_slice(text.as_bytes());
    Ok(out)
}

fn count_bytes(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

fn replace_nth_bytes(
    haystack: &[u8],
    needle: &[u8],
    replacement: &[u8],
    n: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let start = haystack
        .windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle)
        .map(|(i, _)| i)
        .nth(n)
        .ok_or("fixture byte pattern occurrence not found")?;
    let mut out = haystack.get(..start).ok_or("prefix")?.to_vec();
    out.extend_from_slice(replacement);
    out.extend_from_slice(haystack.get(start + needle.len()..).ok_or("suffix")?);
    Ok(out)
}

fn replace_nth(
    haystack: &str,
    needle: &str,
    replacement: &str,
    n: usize,
) -> Result<String, Box<dyn Error>> {
    let (start, _) = haystack
        .match_indices(needle)
        .nth(n)
        .ok_or_else(|| format!("fixture pattern {needle:?} occurrence {n} not found"))?;
    let mut out = String::with_capacity(haystack.len() + replacement.len());
    out.push_str(haystack.get(..start).ok_or("prefix")?);
    out.push_str(replacement);
    out.push_str(haystack.get(start + needle.len()..).ok_or("suffix")?);
    Ok(out)
}

/// Replaces a fixture pattern that must occur exactly once.
fn replace_once(haystack: &str, needle: &str, replacement: &str) -> Result<String, Box<dyn Error>> {
    let count = haystack.matches(needle).count();
    if count != 1 {
        return Err(format!("fixture pattern {needle:?} occurs {count} times, expected 1").into());
    }
    Ok(haystack.replacen(needle, replacement, 1))
}

/// Seals, verifies, and round-trips a capsule through both codecs.
fn assert_accepted_by_all_codecs(capsule: &mut SensorCapsuleV1) -> TestResult {
    capsule.seal_metadata_digest()?;
    capsule.verify()?;
    let bytes = capsule.to_versioned_bytes()?;
    let from_bytes = SensorCapsuleV1::from_versioned_bytes(&bytes)?;
    assert_eq!(&from_bytes, capsule);
    assert_eq!(from_bytes.to_versioned_bytes()?, bytes);
    let json = capsule.to_canonical_json();
    let from_json = SensorCapsuleV1::from_json(&json)?;
    assert_eq!(&from_json, capsule);
    assert_eq!(from_json.to_canonical_json(), json);
    Ok(())
}

/// Asserts `verify()`, the binary decoder, and the JSON decoder all reject `capsule`
/// with exactly `OverLimitLength { field, limit, actual: limit + 1 }`.
fn assert_over_limit_everywhere(
    capsule: &SensorCapsuleV1,
    field: &'static str,
    limit: usize,
) -> TestResult {
    let expected = CapsuleDecodeError::OverLimitLength {
        field,
        limit,
        actual: limit + 1,
    };
    assert_eq!(capsule.verify(), Err(expected.clone()), "verify {field}");
    assert_eq!(
        SensorCapsuleV1::from_versioned_bytes(&raw_envelope(capsule)?),
        Err(expected.clone()),
        "binary {field}"
    );
    assert_eq!(
        SensorCapsuleV1::from_json(&capsule.to_canonical_json()),
        Err(expected),
        "json {field}"
    );
    Ok(())
}

// --- Finding 1: metadata digest must not cover itself --------------------------------

#[test]
fn review439_f1_metadata_digest_excludes_its_own_field() -> TestResult {
    let mut capsule = sample_capsule()?;
    let sealed = capsule.metadata_digest()?;
    assert_eq!(
        capsule.integrity.metadata_digest, sealed,
        "sealing must be a fixed point: the stored digest equals the recomputed digest"
    );

    // The stored digest is not an input of the digest.
    capsule.integrity.metadata_digest = ContentDigest::sha256(b"anything-at-all");
    assert_eq!(capsule.metadata_digest()?, sealed);

    // Every other metadata field is covered.
    let mut changed = capsule.clone();
    changed.privacy.retention_class.push('x');
    assert_ne!(changed.metadata_digest()?, sealed);
    let mut changed = capsule.clone();
    changed.integrity.continuity = ContinuityState::Gapped;
    assert_ne!(changed.metadata_digest()?, sealed);
    let mut changed = capsule.clone();
    changed.publication.ledger_revision = Some(43);
    assert_ne!(changed.metadata_digest()?, sealed);
    let mut changed = capsule;
    changed.source_identity.channel.push('x');
    assert_ne!(changed.metadata_digest()?, sealed);
    Ok(())
}

#[test]
fn review439_f1_verify_rejects_forged_and_stale_metadata_digest() -> TestResult {
    let capsule = sample_capsule()?;
    let mismatch = CapsuleDecodeError::Contract(ContractError::DigestMismatch);

    let mut forged = capsule.clone();
    forged.integrity.metadata_digest = ContentDigest::sha256(b"completely_fake_unverified_digest");
    let mut stale = capsule;
    stale.sequence += 1;

    for tampered in [&forged, &stale] {
        assert_eq!(tampered.verify(), Err(mismatch.clone()));
        assert_eq!(tampered.to_versioned_bytes(), Err(mismatch.clone()));
        assert_eq!(
            SensorCapsuleV1::from_versioned_bytes(&raw_envelope(tampered)?),
            Err(mismatch.clone())
        );
        assert_eq!(
            SensorCapsuleV1::from_json(&tampered.to_canonical_json()),
            Err(mismatch.clone())
        );
    }
    Ok(())
}

// --- Finding 2: custody or explicit omission, never neither ---------------------------

#[test]
fn review439_f2_capsule_without_custody_or_omission_is_rejected() -> TestResult {
    let mut capsule = sample_capsule()?;
    capsule.custody = SourceCustody::NotRetained;
    capsule.media.source_digest = None;
    capsule.omission = ExplicitOmission::None;
    capsule.media.frame_count = 30;
    capsule.integrity.decode = DecodeState::Verified;
    capsule.seal_metadata_digest()?;

    let required = CapsuleDecodeError::Contract(ContractError::EvidenceRequired);
    assert_eq!(capsule.verify(), Err(required.clone()));
    assert_eq!(capsule.to_versioned_bytes(), Err(required.clone()));
    assert_eq!(
        SensorCapsuleV1::from_versioned_bytes(&raw_envelope(&capsule)?),
        Err(required.clone())
    );
    assert_eq!(
        SensorCapsuleV1::from_json(&capsule.to_canonical_json()),
        Err(required)
    );

    // Positive control: no custody but an explicit omission is valid and round-trips.
    let mut omitted = sample_omitted_capsule()?;
    assert!(!omitted.is_retained_evidence());
    assert_accepted_by_all_codecs(&mut omitted)?;
    Ok(())
}

#[test]
fn review439_f2_omission_with_reason_none_is_contradictory() -> TestResult {
    let mut capsule = sample_omitted_capsule()?;
    capsule.omission = ExplicitOmission::Omitted {
        reason: OmissionReason::None,
        policy_rule: "rule:privacy-zone-7".to_string(),
        omitted_bytes: 1,
        omitted_frames: 1,
    };
    capsule.seal_metadata_digest()?;
    let is_contradiction = |r: &Result<(), CapsuleDecodeError>| {
        matches!(
            r,
            Err(CapsuleDecodeError::Contradiction {
                field: "omission.reason",
                ..
            })
        )
    };
    assert!(is_contradiction(&capsule.verify()));
    assert!(is_contradiction(
        &SensorCapsuleV1::from_versioned_bytes(&raw_envelope(&capsule)?).map(|_| ())
    ));
    assert!(is_contradiction(
        &SensorCapsuleV1::from_json(&capsule.to_canonical_json()).map(|_| ())
    ));
    Ok(())
}

// --- Finding 3: alias identifier prefixes are non-canonical ---------------------------

const ALIAS_CASES: [(&str, &str, usize); 3] = [
    ("src:camera-entry-01-main", "source:camera-entry-01-main", 2),
    ("device:camera-entry-01", "dev:camera-entry-01", 3),
    ("adapter:rtsp-pure-rust-01", "adp:rtsp-pure-rust-01", 3),
];

#[test]
fn review439_f3_binary_decode_rejects_alias_identifier_prefixes() -> TestResult {
    let bytes = sample_capsule()?.to_versioned_bytes()?;
    for (canonical, alias, occurrences) in ALIAS_CASES {
        let needle = encoded_text(canonical)?;
        assert_eq!(count_bytes(&bytes, &needle), occurrences, "{canonical}");
        for n in 0..occurrences {
            let mutated = replace_nth_bytes(&bytes, &needle, &encoded_text(alias)?, n)?;
            let result = SensorCapsuleV1::from_versioned_bytes(&mutated);
            assert!(
                matches!(result, Err(CapsuleDecodeError::NonCanonicalEncoding { .. })),
                "{alias} at occurrence {n} must be rejected, got {result:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn review439_f3_json_decode_rejects_alias_identifier_prefixes() -> TestResult {
    let json = sample_capsule()?.to_canonical_json();
    for (canonical, alias, occurrences) in ALIAS_CASES {
        let needle = format!("\"{canonical}\"");
        assert_eq!(json.matches(&needle).count(), occurrences, "{canonical}");
        for n in 0..occurrences {
            let mutated = replace_nth(&json, &needle, &format!("\"{alias}\""), n)?;
            let result = SensorCapsuleV1::from_json(&mutated);
            assert!(
                matches!(result, Err(CapsuleDecodeError::NonCanonicalEncoding { .. })),
                "{alias} at occurrence {n} must be rejected, got {result:?}"
            );
        }
    }
    Ok(())
}

// --- Finding 4: contradictory omission/custody JSON is a typed error -------------------

#[test]
fn review439_f4_json_rejects_omission_details_when_not_omitted() -> TestResult {
    let json = sample_capsule()?.to_canonical_json();
    let canonical = r#""omission":{"isOmitted":false,"omittedBytes":0,"omittedFrames":0,"policyRule":"","reason":"none"}"#;
    let cases = [
        (
            "omission.omittedBytes",
            r#""omission":{"isOmitted":false,"omittedBytes":1024,"omittedFrames":0,"policyRule":"","reason":"none"}"#,
        ),
        (
            "omission.omittedFrames",
            r#""omission":{"isOmitted":false,"omittedBytes":0,"omittedFrames":1,"policyRule":"","reason":"none"}"#,
        ),
        (
            "omission.policyRule",
            r#""omission":{"isOmitted":false,"omittedBytes":0,"omittedFrames":0,"policyRule":"rule:drop","reason":"none"}"#,
        ),
        (
            "omission.reason",
            r#""omission":{"isOmitted":false,"omittedBytes":0,"omittedFrames":0,"policyRule":"","reason":"resource_pressure"}"#,
        ),
    ];
    for (field, replacement) in cases {
        let mutated = replace_once(&json, canonical, replacement)?;
        let result = SensorCapsuleV1::from_json(&mutated);
        assert!(
            matches!(result, Err(CapsuleDecodeError::Contradiction { field: f, .. }) if f == field),
            "{field}: {result:?}"
        );
    }
    Ok(())
}

#[test]
fn review439_f4_json_rejects_custody_details_when_not_retained() -> TestResult {
    let json = sample_omitted_capsule()?.to_canonical_json();
    let canonical =
        r#""custody":{"isRetained":false,"sourceBytes":0,"sourceDigest":null,"storageHandle":""}"#;
    let digest = ContentDigest::sha256(b"not-retained").to_string();
    let with_digest = format!(
        r#""custody":{{"isRetained":false,"sourceBytes":0,"sourceDigest":"{digest}","storageHandle":""}}"#
    );
    let cases = [
        (
            "custody.sourceBytes",
            r#""custody":{"isRetained":false,"sourceBytes":65536,"sourceDigest":null,"storageHandle":""}"#
                .to_string(),
        ),
        ("custody.sourceDigest", with_digest),
        (
            "custody.storageHandle",
            r#""custody":{"isRetained":false,"sourceBytes":0,"sourceDigest":null,"storageHandle":"store://x"}"#
                .to_string(),
        ),
    ];
    for (field, replacement) in cases {
        let mutated = replace_once(&json, canonical, &replacement)?;
        let result = SensorCapsuleV1::from_json(&mutated);
        assert!(
            matches!(result, Err(CapsuleDecodeError::Contradiction { field: f, .. }) if f == field),
            "{field}: {result:?}"
        );
    }
    Ok(())
}

// --- Finding 5: JSON parser must be lossless and fail closed ---------------------------

#[test]
fn review439_f5_json_preserves_multibyte_utf8() -> TestResult {
    let mut capsule = sample_capsule()?;
    capsule.privacy.retention_class = "zone_\u{e4}_\u{533a}_\u{1f600}".to_string();
    assert_accepted_by_all_codecs(&mut capsule)?;
    Ok(())
}

#[test]
fn review439_f5_json_escapes_and_rejects_raw_control_characters() -> TestResult {
    let mut capsule = sample_capsule()?;
    capsule.privacy.retention_class = "keep\u{1}\u{8}\u{c}\u{1f}30d".to_string();
    capsule.seal_metadata_digest()?;
    let json = capsule.to_canonical_json();
    assert!(
        !json.bytes().any(|b| b < 0x20),
        "canonical JSON must escape every control character"
    );
    assert_accepted_by_all_codecs(&mut capsule)?;

    let clean = sample_capsule()?.to_canonical_json();
    for raw in [
        "standard\tretention",
        "standard\nretention",
        "standard\u{1}retention",
    ] {
        let mutated = replace_once(&clean, "standard_retention_30d", raw)?;
        let result = SensorCapsuleV1::from_json(&mutated);
        assert!(
            matches!(result, Err(CapsuleDecodeError::JsonError { .. })),
            "raw control character must be rejected, got {result:?}"
        );
    }
    Ok(())
}

#[test]
fn review439_f5_json_rejects_duplicate_and_unknown_keys() -> TestResult {
    let json = sample_capsule()?.to_canonical_json();
    let body = json.strip_prefix('{').ok_or("json object")?;

    let duplicate_root = format!("{{\"sequence\":7,{body}");
    let unknown_root = format!("{{\"bogus\":1,{body}");
    let duplicate_nested = replace_once(
        &json,
        "\"codec\":\"h264\"",
        "\"codec\":\"h264\",\"codec\":\"h265\"",
    )?;
    let unknown_nested = replace_once(
        &json,
        "\"codec\":\"h264\"",
        "\"codec\":\"h264\",\"bogus\":null",
    )?;
    let unknown_identity =
        replace_once(&json, "\"isLive\":true", "\"isLive\":true,\"bogus\":false")?;

    for mutated in [
        duplicate_root,
        unknown_root,
        duplicate_nested,
        unknown_nested,
        unknown_identity,
    ] {
        let result = SensorCapsuleV1::from_json(&mutated);
        assert!(
            matches!(result, Err(CapsuleDecodeError::JsonError { .. })),
            "duplicate/unknown key must be rejected, got {result:?}"
        );
    }
    Ok(())
}

#[test]
fn review439_f5_json_rejects_non_canonical_numbers() -> TestResult {
    let json = sample_capsule()?.to_canonical_json();
    for bad in ["01", "-0", "1.0", "1e0", "+1", "-", "1E0"] {
        let mutated = replace_once(&json, "\"sequence\":1,", &format!("\"sequence\":{bad},"))?;
        let result = SensorCapsuleV1::from_json(&mutated);
        assert!(
            matches!(result, Err(CapsuleDecodeError::JsonError { .. })),
            "number {bad:?} must be rejected, got {result:?}"
        );
    }
    let negative_zero = replace_once(&json, "\"omittedBytes\":0,", "\"omittedBytes\":-0,")?;
    assert!(matches!(
        SensorCapsuleV1::from_json(&negative_zero),
        Err(CapsuleDecodeError::JsonError { .. })
    ));
    Ok(())
}

#[test]
fn review439_f5_json_rejects_excessive_nesting_without_overflow() {
    for deep in ["[".repeat(200_000), "{\"a\":".repeat(200_000)] {
        let result = SensorCapsuleV1::from_json(&deep);
        assert!(
            matches!(result, Err(CapsuleDecodeError::JsonError { .. })),
            "deep nesting must be rejected as JsonError, got {result:?}"
        );
    }
}

// --- Finding 6: schema and Rust agree exactly ------------------------------------------

#[test]
fn review439_f6_media_dimensions_must_be_positive() -> TestResult {
    for height in [false, true] {
        let mut capsule = sample_capsule()?;
        let field = if height {
            capsule.media.height = Some(0);
            "media.height"
        } else {
            capsule.media.width = Some(0);
            "media.width"
        };
        capsule.seal_metadata_digest()?;
        let expected = CapsuleDecodeError::OutOfRange {
            field,
            minimum: 1,
            maximum: u64::from(u32::MAX),
            actual: 0,
        };
        assert_eq!(capsule.verify(), Err(expected.clone()));
        assert_eq!(
            SensorCapsuleV1::from_versioned_bytes(&raw_envelope(&capsule)?),
            Err(expected.clone())
        );
        assert_eq!(
            SensorCapsuleV1::from_json(&capsule.to_canonical_json()),
            Err(expected)
        );
    }
    let mut capsule = sample_capsule()?;
    capsule.media.width = Some(1);
    capsule.media.height = Some(u32::MAX);
    assert_accepted_by_all_codecs(&mut capsule)?;
    Ok(())
}

/// Minimal JSON reader used only to inspect the committed schema file.
#[derive(Clone, Debug, PartialEq)]
enum Jv {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<Jv>),
    Obj(Vec<(String, Jv)>),
}

struct Jp<'a> {
    src: &'a [u8],
    pos: usize,
}

impl Jp<'_> {
    fn ws(&mut self) {
        while matches!(self.src.get(self.pos), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, byte: u8) -> Option<()> {
        self.ws();
        if self.src.get(self.pos) == Some(&byte) {
            self.pos += 1;
            Some(())
        } else {
            None
        }
    }

    fn lit(&mut self, word: &[u8]) -> Option<()> {
        if self.src.get(self.pos..)?.starts_with(word) {
            self.pos += word.len();
            Some(())
        } else {
            None
        }
    }

    fn value(&mut self) -> Option<Jv> {
        self.ws();
        match *self.src.get(self.pos)? {
            b'{' => {
                self.pos += 1;
                let mut fields = Vec::new();
                if self.eat(b'}').is_some() {
                    return Some(Jv::Obj(fields));
                }
                loop {
                    self.ws();
                    let key = self.string()?;
                    self.eat(b':')?;
                    fields.push((key, self.value()?));
                    if self.eat(b',').is_none() {
                        self.eat(b'}')?;
                        return Some(Jv::Obj(fields));
                    }
                }
            }
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                if self.eat(b']').is_some() {
                    return Some(Jv::Arr(items));
                }
                loop {
                    items.push(self.value()?);
                    if self.eat(b',').is_none() {
                        self.eat(b']')?;
                        return Some(Jv::Arr(items));
                    }
                }
            }
            b'"' => self.string().map(Jv::Str),
            b't' => self.lit(b"true").map(|()| Jv::Bool(true)),
            b'f' => self.lit(b"false").map(|()| Jv::Bool(false)),
            b'n' => self.lit(b"null").map(|()| Jv::Null),
            _ => {
                let start = self.pos;
                while matches!(
                    self.src.get(self.pos),
                    Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                ) {
                    self.pos += 1;
                }
                if start == self.pos {
                    return None;
                }
                String::from_utf8(self.src.get(start..self.pos)?.to_vec())
                    .ok()
                    .map(Jv::Num)
            }
        }
    }

    fn string(&mut self) -> Option<String> {
        if self.src.get(self.pos) != Some(&b'"') {
            return None;
        }
        self.pos += 1;
        let mut out = Vec::new();
        loop {
            let byte = *self.src.get(self.pos)?;
            self.pos += 1;
            match byte {
                b'"' => return String::from_utf8(out).ok(),
                b'\\' => {
                    let esc = *self.src.get(self.pos)?;
                    self.pos += 1;
                    match esc {
                        b'"' | b'\\' | b'/' => out.push(esc),
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'u' => {
                            let hex =
                                std::str::from_utf8(self.src.get(self.pos..self.pos + 4)?).ok()?;
                            self.pos += 4;
                            let ch = char::from_u32(u32::from_str_radix(hex, 16).ok()?)?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return None,
                    }
                }
                other => out.push(other),
            }
        }
    }
}

impl Jv {
    fn parse(text: &str) -> Option<Self> {
        let mut parser = Jp {
            src: text.as_bytes(),
            pos: 0,
        };
        let value = parser.value()?;
        parser.ws();
        (parser.pos == parser.src.len()).then_some(value)
    }

    fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn pointer(&self, path: &str) -> Option<&Self> {
        path.split('/')
            .filter(|seg| !seg.is_empty())
            .try_fold(self, |node, seg| node.get(seg))
    }

    fn keys(&self) -> Option<BTreeSet<&str>> {
        match self {
            Self::Obj(fields) => Some(fields.iter().map(|(k, _)| k.as_str()).collect()),
            _ => None,
        }
    }

    fn str_set(&self) -> Option<BTreeSet<&str>> {
        match self {
            Self::Arr(items) => items
                .iter()
                .map(|item| match item {
                    Self::Str(s) => Some(s.as_str()),
                    _ => None,
                })
                .collect(),
            _ => None,
        }
    }
}

fn load_schema(file: &str) -> Result<Jv, Box<dyn Error>> {
    let path = format!("{}/../../schemas/{file}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path)?;
    Ok(Jv::parse(&text).ok_or_else(|| format!("{path}: not parseable JSON"))?)
}

/// Walks capsule-local schema objects alongside a canonical JSON instance, asserting that
/// emitted keys, declared properties, and required keys are identical sets.
fn assert_schema_matches_instance(
    root: &Jv,
    schema: &Jv,
    instance: &Jv,
    path: &str,
    checked: &mut usize,
) -> TestResult {
    let schema = match schema.get("$ref") {
        Some(Jv::Str(target)) => match target.strip_prefix('#') {
            Some(pointer) => root
                .pointer(pointer)
                .ok_or_else(|| format!("{path}: dangling $ref {target}"))?,
            None => return Ok(()),
        },
        _ => schema,
    };
    let Some(properties) = schema.get("properties") else {
        return Ok(());
    };
    let instance_keys = instance
        .keys()
        .ok_or_else(|| format!("{path}: instance is not an object"))?;
    let schema_keys = properties
        .keys()
        .ok_or_else(|| format!("{path}: properties"))?;
    assert_eq!(
        instance_keys, schema_keys,
        "{path}: emitted keys vs schema properties"
    );
    let required = schema
        .get("required")
        .and_then(Jv::str_set)
        .ok_or_else(|| format!("{path}: required"))?;
    assert_eq!(
        required, schema_keys,
        "{path}: every emitted key must be required"
    );
    assert_eq!(
        schema.get("additionalProperties"),
        Some(&Jv::Bool(false)),
        "{path}: additionalProperties"
    );
    *checked += 1;
    for key in schema_keys {
        let sub_schema = properties.get(key).ok_or("property")?;
        let sub_instance = instance.get(key).ok_or("instance")?;
        if matches!(sub_instance, Jv::Obj(_)) {
            assert_schema_matches_instance(
                root,
                sub_schema,
                sub_instance,
                &format!("{path}/{key}"),
                checked,
            )?;
        }
    }
    Ok(())
}

#[test]
fn review439_f6_schema_objects_match_canonical_json_exactly() -> TestResult {
    let schema = load_schema("sensor_capsule.v1.json")?;
    for capsule in [sample_capsule()?, sample_omitted_capsule()?] {
        let instance =
            Jv::parse(&capsule.to_canonical_json()).ok_or("canonical JSON must parse")?;
        let mut checked = 0;
        assert_schema_matches_instance(&schema, &schema, &instance, "", &mut checked)?;
        // root, captureInterval, custody, omission, media, integrity, privacy, publication
        assert_eq!(checked, 8, "capsule-local objects checked");

        for (key, file) in [
            ("sourceIdentity", "source_identity.v1.json"),
            ("deviceIdentity", "device_identity.v1.json"),
            ("adapterIdentity", "adapter_identity.v1.json"),
        ] {
            let identity_schema = load_schema(file)?;
            let emitted = instance.get(key).and_then(Jv::keys).ok_or(key)?;
            let declared = identity_schema
                .get("properties")
                .and_then(Jv::keys)
                .ok_or(file)?;
            assert_eq!(emitted, declared, "{key} keys vs {file}");
            let overlay = schema
                .pointer(&format!("/properties/{key}/allOf"))
                .ok_or_else(|| format!("{key}: canonical-identifier overlay missing"))?;
            assert!(
                matches!(overlay, Jv::Arr(items) if items.len() == 2),
                "{key}"
            );
        }
    }
    Ok(())
}

#[test]
fn review439_f6_schema_ranges_match_rust_bounds() -> TestResult {
    let schema = load_schema("sensor_capsule.v1.json")?;
    let num = |pointer: &str, expected: String| -> TestResult {
        let found = schema
            .pointer(pointer)
            .ok_or_else(|| format!("schema is missing {pointer}"))?;
        assert_eq!(found, &Jv::Num(expected), "{pointer}");
        Ok(())
    };
    let u32_max = u32::MAX.to_string();
    let u64_max = u64::MAX.to_string();
    let i128_min = i128::MIN.to_string();
    let i128_max = i128::MAX.to_string();

    num("/properties/capsuleId/minLength", "1".into())?;
    num(
        "/properties/capsuleId/maxLength",
        MAX_CAPSULE_ID_LEN.to_string(),
    )?;
    for id in ["sourceId", "deviceId", "adapterId", "sensorId", "streamId"] {
        num(&format!("/properties/{id}/minLength"), "1".into())?;
        num(
            &format!("/properties/{id}/maxLength"),
            MAX_STR_LEN.to_string(),
        )?;
    }
    num("/properties/sequence/minimum", "0".into())?;
    num("/properties/sequence/maximum", u64_max.clone())?;
    for pointer in [
        "/properties/receiveTimeNs",
        "/$defs/captureInterval/properties/earliestNs",
        "/$defs/captureInterval/properties/latestNs",
    ] {
        num(&format!("{pointer}/minimum"), i128_min.clone())?;
        num(&format!("{pointer}/maximum"), i128_max.clone())?;
    }
    num(
        "/$defs/captureInterval/properties/uncertaintyReason/minLength",
        "1".into(),
    )?;
    num(
        "/$defs/captureInterval/properties/uncertaintyReason/maxLength",
        MAX_UNCERTAINTY_REASON_LEN.to_string(),
    )?;
    num(
        "/$defs/custody/properties/sourceBytes/maximum",
        u64_max.clone(),
    )?;
    num(
        "/$defs/custody/properties/storageHandle/maxLength",
        MAX_STORAGE_HANDLE_LEN.to_string(),
    )?;
    num(
        "/$defs/omission/properties/policyRule/maxLength",
        MAX_POLICY_RULE_LEN.to_string(),
    )?;
    num(
        "/$defs/omission/properties/omittedBytes/maximum",
        u64_max.clone(),
    )?;
    num(
        "/$defs/omission/properties/omittedFrames/maximum",
        u32_max.clone(),
    )?;
    num("/$defs/media/properties/codec/minLength", "1".into())?;
    num(
        "/$defs/media/properties/codec/maxLength",
        MAX_CODEC_LEN.to_string(),
    )?;
    num(
        "/$defs/media/properties/container/maxLength",
        MAX_CONTAINER_LEN.to_string(),
    )?;
    for dim in ["width", "height"] {
        num(
            &format!("/$defs/media/properties/{dim}/minimum"),
            "1".into(),
        )?;
        num(
            &format!("/$defs/media/properties/{dim}/maximum"),
            u32_max.clone(),
        )?;
    }
    num(
        "/$defs/media/properties/sourceBytes/maximum",
        u64_max.clone(),
    )?;
    num("/$defs/media/properties/frameCount/maximum", u32_max)?;
    num(
        "/$defs/integrity/properties/firmwareFingerprint/maxLength",
        MAX_FIRMWARE_FINGERPRINT_LEN.to_string(),
    )?;
    num(
        "/$defs/privacy/properties/retentionClass/maxLength",
        MAX_RETENTION_CLASS_LEN.to_string(),
    )?;
    num(
        "/$defs/publication/properties/ledgerRevision/maximum",
        u64_max,
    )?;

    // Exact digest grammar accepted by ContentDigest::parse.
    assert_eq!(
        schema.pointer("/$defs/contentDigest/pattern"),
        Some(&Jv::Str("^(sha256|blake3):[0-9a-f]{64}$".to_string()))
    );
    // Alias prefixes are non-canonical in the capsule contract.
    for (id, alias) in [
        ("sourceId", "source:"),
        ("deviceId", "dev:"),
        ("adapterId", "adp:"),
    ] {
        assert_eq!(
            schema.pointer(&format!("/properties/{id}/pattern")),
            Some(&Jv::Str(format!("^(?!{alias})[A-Za-z0-9_.:-]+$"))),
            "{id}"
        );
    }

    // Enumerations are exactly the Rust string tags.
    let enum_set = |pointer: &str| -> Result<BTreeSet<&str>, Box<dyn Error>> {
        Ok(schema
            .pointer(pointer)
            .and_then(Jv::str_set)
            .ok_or_else(|| format!("schema is missing enum {pointer}"))?)
    };
    let set = |tags: &[&'static str]| tags.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(
        enum_set("/properties/clockBasis/enum")?,
        set(&[
            "utc_disciplined",
            "device_monotonic",
            "host_monotonic",
            "estimated"
        ])
    );
    assert_eq!(
        enum_set("/$defs/integrity/properties/continuity/enum")?,
        set(&[
            ContinuityState::Unverified.as_str(),
            ContinuityState::Verified.as_str(),
            ContinuityState::Gapped.as_str(),
            ContinuityState::Indeterminate.as_str(),
        ])
    );
    assert_eq!(
        enum_set("/$defs/integrity/properties/decode/enum")?,
        set(&[
            DecodeState::NotAttempted.as_str(),
            DecodeState::Verified.as_str(),
            DecodeState::ConcealedErrors.as_str(),
            DecodeState::Failed.as_str(),
        ])
    );
    assert_eq!(
        enum_set("/$defs/privacy/properties/redactionState/enum")?,
        set(&[
            RedactionState::NotRequired.as_str(),
            RedactionState::Applied.as_str(),
            RedactionState::Deferred.as_str(),
            RedactionState::FailedClosed.as_str(),
        ])
    );
    assert_eq!(
        enum_set("/$defs/publication/properties/state/enum")?,
        set(&[
            PublicationState::Reserved.as_str(),
            PublicationState::Materialized.as_str(),
            PublicationState::Published.as_str(),
            PublicationState::Aborted.as_str(),
            PublicationState::Indeterminate.as_str(),
        ])
    );
    assert_eq!(
        enum_set("/$defs/omission/properties/reason/enum")?,
        set(&[
            OmissionReason::None.as_str(),
            OmissionReason::PrivacyRedaction.as_str(),
            OmissionReason::ResourcePressure.as_str(),
            OmissionReason::RetentionPolicy.as_str(),
            OmissionReason::CapabilityFiltered.as_str(),
            OmissionReason::TransientPreviewOnly.as_str(),
            OmissionReason::UpstreamMissing.as_str(),
        ])
    );
    assert_eq!(
        enum_set("/$defs/media/properties/kind/enum")?,
        set(&[
            MediaKind::Video.as_str(),
            MediaKind::Audio.as_str(),
            MediaKind::Image.as_str(),
            MediaKind::Metadata.as_str(),
            MediaKind::Compound.as_str(),
        ])
    );

    // Conditional custody/omission shapes and the custody-or-omission invariant exist.
    for pointer in [
        "/$defs/custody/if",
        "/$defs/custody/then",
        "/$defs/custody/else",
        "/$defs/omission/if",
        "/$defs/omission/then",
        "/$defs/omission/else",
        "/anyOf",
    ] {
        assert!(
            schema.pointer(pointer).is_some(),
            "schema is missing {pointer}"
        );
    }
    Ok(())
}

// --- Finding 7: every length limit at bound and bound + 1 -----------------------------

fn id_of_len(prefix: &str, len: usize) -> String {
    let mut id = prefix.to_string();
    while id.len() < len {
        id.push('a');
    }
    id
}

type IdSetter = fn(&mut SensorCapsuleV1, &str) -> Result<(), ContractError>;

#[test]
fn review439_f7_identifier_fields_at_bound_and_bound_plus_one() -> TestResult {
    let cases: [(&'static str, usize, &str, IdSetter); 6] = [
        ("capsuleId", MAX_CAPSULE_ID_LEN, "cap:", |c, v| {
            c.capsule_id = CapsuleId::parse(v)?;
            Ok(())
        }),
        ("sourceId", MAX_STR_LEN, "src:", |c, v| {
            let id = SourceId::parse(v)?;
            c.source_identity.source_id = id.clone();
            c.source_id = id;
            Ok(())
        }),
        ("deviceId", MAX_STR_LEN, "device:", |c, v| {
            let id = DeviceId::parse(v)?;
            c.source_identity.device_id = id.clone();
            c.device_identity.device_id = id.clone();
            c.device_id = id;
            Ok(())
        }),
        ("adapterId", MAX_STR_LEN, "adapter:", |c, v| {
            let id = AdapterId::parse(v)?;
            c.source_identity.adapter_id = id.clone();
            c.adapter_identity.adapter_id = id.clone();
            c.adapter_id = id;
            Ok(())
        }),
        ("sensorId", MAX_STR_LEN, "sensor:", |c, v| {
            c.sensor_id = SensorId::parse(v)?;
            Ok(())
        }),
        ("streamId", MAX_STR_LEN, "stream:", |c, v| {
            c.stream_id = StreamId::parse(v)?;
            Ok(())
        }),
    ];
    for (field, limit, prefix, set) in cases {
        let bound = id_of_len(prefix, limit);
        let over = id_of_len(prefix, limit + 1);
        assert_eq!(bound.len(), limit);
        assert_eq!(over.len(), limit + 1);

        // Exactly at the bound: accepted by verify and both codecs.
        let mut capsule = sample_capsule()?;
        set(&mut capsule, &bound)?;
        assert_accepted_by_all_codecs(&mut capsule)?;

        // Bound + 1: the identifier type itself refuses construction...
        assert_eq!(
            set(&mut capsule.clone(), &over),
            Err(ContractError::InvalidIdentifier),
            "{field}"
        );

        // ...and both decoders report the typed bound violation.
        let expected = CapsuleDecodeError::OverLimitLength {
            field,
            limit,
            actual: limit + 1,
        };
        let json = capsule.to_canonical_json();
        let over_json = json.replace(&format!("\"{bound}\""), &format!("\"{over}\""));
        assert_ne!(over_json, json);
        assert_eq!(
            SensorCapsuleV1::from_json(&over_json),
            Err(expected.clone()),
            "json {field}"
        );
        let bytes = capsule.to_versioned_bytes()?;
        let over_bytes =
            replace_nth_bytes(&bytes, &encoded_text(&bound)?, &encoded_text(&over)?, 0)?;
        assert_eq!(
            SensorCapsuleV1::from_versioned_bytes(&over_bytes),
            Err(expected),
            "binary {field}"
        );
    }
    Ok(())
}

type TextSetter = fn(&mut SensorCapsuleV1, String);

#[test]
fn review439_f7_text_fields_at_bound_and_bound_plus_one() -> TestResult {
    let cases: [(&'static str, usize, TextSetter); 7] = [
        (
            "captureInterval.uncertaintyReason",
            MAX_UNCERTAINTY_REASON_LEN,
            |c, v| c.capture_uncertainty_reason = v,
        ),
        ("media.codec", MAX_CODEC_LEN, |c, v| c.media.codec = v),
        ("media.container", MAX_CONTAINER_LEN, |c, v| {
            c.media.container = Some(v);
        }),
        ("custody.storageHandle", MAX_STORAGE_HANDLE_LEN, |c, v| {
            if let SourceCustody::Retained { storage_handle, .. } = &mut c.custody {
                *storage_handle = v;
            }
        }),
        ("omission.policyRule", MAX_POLICY_RULE_LEN, |c, v| {
            c.omission = ExplicitOmission::Omitted {
                reason: OmissionReason::PrivacyRedaction,
                policy_rule: v,
                omitted_bytes: 1,
                omitted_frames: 1,
            };
        }),
        (
            "integrity.firmwareFingerprint",
            MAX_FIRMWARE_FINGERPRINT_LEN,
            |c, v| c.integrity.firmware_fingerprint = Some(v),
        ),
        ("privacy.retentionClass", MAX_RETENTION_CLASS_LEN, |c, v| {
            c.privacy.retention_class = v;
        }),
    ];
    for (field, limit, set) in cases {
        let mut at_bound = sample_capsule()?;
        set(&mut at_bound, "b".repeat(limit));
        assert_accepted_by_all_codecs(&mut at_bound)?;

        let mut over = sample_capsule()?;
        set(&mut over, "b".repeat(limit + 1));
        over.seal_metadata_digest()?;
        assert_over_limit_everywhere(&over, field, limit)?;
    }
    Ok(())
}

#[test]
fn review439_f7_required_text_fields_reject_empty() -> TestResult {
    let cases: [(&'static str, usize, TextSetter); 4] = [
        (
            "captureInterval.uncertaintyReason",
            MAX_UNCERTAINTY_REASON_LEN,
            |c, v| c.capture_uncertainty_reason = v,
        ),
        ("media.codec", MAX_CODEC_LEN, |c, v| c.media.codec = v),
        ("custody.storageHandle", MAX_STORAGE_HANDLE_LEN, |c, v| {
            if let SourceCustody::Retained { storage_handle, .. } = &mut c.custody {
                *storage_handle = v;
            }
        }),
        ("omission.policyRule", MAX_POLICY_RULE_LEN, |c, v| {
            c.omission = ExplicitOmission::Omitted {
                reason: OmissionReason::PrivacyRedaction,
                policy_rule: v,
                omitted_bytes: 1,
                omitted_frames: 1,
            };
        }),
    ];
    for (field, limit, set) in cases {
        let mut capsule = sample_capsule()?;
        set(&mut capsule, String::new());
        capsule.seal_metadata_digest()?;
        let expected = CapsuleDecodeError::OverLimitLength {
            field,
            limit,
            actual: 0,
        };
        assert_eq!(capsule.verify(), Err(expected.clone()), "verify {field}");
        assert_eq!(
            SensorCapsuleV1::from_versioned_bytes(&raw_envelope(&capsule)?),
            Err(expected.clone()),
            "binary {field}"
        );
        assert_eq!(
            SensorCapsuleV1::from_json(&capsule.to_canonical_json()),
            Err(expected),
            "json {field}"
        );
    }
    Ok(())
}

#[test]
fn review439_f6_capture_uncertainty_reason_round_trips_and_is_digested() -> TestResult {
    let mut capsule = sample_capsule()?;
    capsule.capture_uncertainty_reason = "ptp_holdover_skew_bound".to_string();
    assert_accepted_by_all_codecs(&mut capsule)?;
    let json = capsule.to_canonical_json();
    assert!(json.contains(r#""uncertaintyReason":"ptp_holdover_skew_bound""#));

    // The reason is metadata: editing it without re-sealing breaks the digest.
    let edited = replace_once(&json, "ptp_holdover_skew_bound", "some_other_reason")?;
    assert_eq!(
        SensorCapsuleV1::from_json(&edited),
        Err(CapsuleDecodeError::Contract(ContractError::DigestMismatch))
    );
    Ok(())
}
