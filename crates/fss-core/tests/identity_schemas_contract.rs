#![forbid(unsafe_code)]
//! Integration and property contract tests for FSS-005: Source, Device, and Adapter identity schemas.

use std::collections::BTreeSet;

use fss_core::{
    AdapterCapabilities, AdapterGeneration, AdapterId, AdapterIdentity, AdapterKind,
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ClockBasis,
    ContractError, CredentialMethod, DeviceCapabilities, DeviceClass, DeviceGeneration, DeviceId,
    DeviceIdentity, IsolationMode, MediaKind, ModelGeneration, SourceId, SourceIdentity,
    SourceKind, StreamGeneration,
};

fn sample_device() -> Result<DeviceIdentity, ContractError> {
    let device_id = DeviceId::parse("device:insta360-link-main")?;
    let generation = DeviceGeneration::parse("gen:dev:2026-09-11:rev1")?;
    let model_gen = ModelGeneration::parse("gen:model:yolo-pose-v4")?;

    let device = DeviceIdentity {
        device_id,
        generation,
        manufacturer: "Insta360".to_string(),
        model: "Link".to_string(),
        hardware_revision: "HW-REV-2.1".to_string(),
        firmware_version: "FW-1.2.64".to_string(),
        application_version: Some("APP-2026.9".to_string()),
        model_generation: Some(model_gen),
        device_class: DeviceClass::Camera,
        capabilities: DeviceCapabilities::PTZ
            .union(DeviceCapabilities::OPTICAL_ZOOM)
            .union(DeviceCapabilities::AUDIO_CAPTURE),
        failure_domain: "power:poe-switch-1/rack-a".to_string(),
    };
    device.verify()?;
    Ok(device)
}

fn sample_source() -> Result<SourceIdentity, ContractError> {
    let source_id = SourceId::parse("src:insta360-link-main-video")?;
    let device_id = DeviceId::parse("device:insta360-link-main")?;
    let adapter_id = AdapterId::parse("adapter:uvc-insta360-link")?;
    let stream_generation = StreamGeneration::parse("gen:stream:1080p60-nv12")?;

    let source = SourceIdentity {
        source_id,
        device_id,
        adapter_id,
        source_kind: SourceKind::PhysicalSensor,
        media_kind: MediaKind::Video,
        channel: "video_main".to_string(),
        nominal_clock_basis: ClockBasis::HostMonotonic,
        stream_generation,
        failure_domain: "net:vlan-20/switch-1".to_string(),
        is_live: true,
    };
    source.verify()?;
    Ok(source)
}

fn sample_adapter() -> Result<AdapterIdentity, ContractError> {
    let adapter_id = AdapterId::parse("adapter:uvc-insta360-link")?;
    let generation = AdapterGeneration::parse("gen:adapter:uvc-rust-v1")?;

    let adapter = AdapterIdentity {
        adapter_id,
        generation,
        adapter_kind: AdapterKind::Uvc,
        protocol_profile: "uvc:1.5:isochronous".to_string(),
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::None,
        capabilities: AdapterCapabilities::STREAMING
            .union(AdapterCapabilities::PTZ_CONTROL)
            .union(AdapterCapabilities::TIME_SYNC),
        max_bandwidth_bytes_per_sec: 150_000_000,
        max_buffer_frames: 32,
        request_timeout_ns: 5_000_000_000,
    };
    adapter.verify()?;
    Ok(adapter)
}

#[test]
fn test_stable_id_prefixes_and_parsing() -> Result<(), ContractError> {
    let src1 = SourceId::parse("src:camera-1-feed")?;
    let src2 = SourceId::from_suffix("camera-1-feed")?;
    if src1 != src2 {
        return Err(ContractError::InvalidIdentifier);
    }
    if !src1.has_source_prefix() {
        return Err(ContractError::InvalidIdentifier);
    }
    if src1.as_str() != "src:camera-1-feed" {
        return Err(ContractError::InvalidIdentifier);
    }

    let src_alt = SourceId::parse("source:perimeter-cam-02")?;
    if !src_alt.has_source_prefix() {
        return Err(ContractError::InvalidIdentifier);
    }

    let dev1 = DeviceId::parse("device:insta360-link-01")?;
    let dev2 = DeviceId::from_suffix("insta360-link-01")?;
    if dev1 != dev2 {
        return Err(ContractError::InvalidIdentifier);
    }
    if !dev1.has_device_prefix() {
        return Err(ContractError::InvalidIdentifier);
    }

    let adp1 = AdapterId::parse("adapter:rtsp-onvif-axis")?;
    let adp2 = AdapterId::from_suffix("rtsp-onvif-axis")?;
    if adp1 != adp2 {
        return Err(ContractError::InvalidIdentifier);
    }
    if !adp1.has_adapter_prefix() {
        return Err(ContractError::InvalidIdentifier);
    }

    // Prohibit empty IDs
    if SourceId::parse("").is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }
    if DeviceId::parse("").is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }
    if AdapterId::parse("").is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    // Prohibit whitespace and illegal characters
    if SourceId::parse("src:invalid space").is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }
    if DeviceId::parse("device:bad*char").is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }
    if AdapterId::parse("adapter:bad/slash").is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    // Prohibit oversized IDs (> 128 bytes)
    let long_suffix = "a".repeat(130);
    if SourceId::parse(&long_suffix).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }
    if DeviceId::parse(&long_suffix).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }
    if AdapterId::parse(&long_suffix).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    Ok(())
}

#[test]
fn test_device_identity_construction_and_bounds() -> Result<(), ContractError> {
    let device = sample_device()?;

    if device.device_id.as_str() != "device:insta360-link-main" {
        return Err(ContractError::InvalidIdentifier);
    }
    if device.device_class != DeviceClass::Camera {
        return Err(ContractError::InvalidIdentifier);
    }
    if !device.capabilities.contains(DeviceCapabilities::PTZ) {
        return Err(ContractError::InvalidIdentifier);
    }

    // Verify empty manufacturer fails closed
    let mut invalid = device.clone();
    invalid.manufacturer.clear();
    if invalid.verify().is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    // Verify empty model fails closed
    let mut invalid = device.clone();
    invalid.model.clear();
    if invalid.verify().is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    // Verify empty hardware_revision fails closed
    let mut invalid = device.clone();
    invalid.hardware_revision.clear();
    if invalid.verify().is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    // Verify empty firmware_version fails closed
    let mut invalid = device.clone();
    invalid.firmware_version.clear();
    if invalid.verify().is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    // Verify empty failure_domain fails closed
    let mut invalid = device.clone();
    invalid.failure_domain.clear();
    if invalid.verify().is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    // Verify oversized strings fail closed
    let mut invalid = device;
    invalid.manufacturer = "m".repeat(129);
    if invalid.verify().is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    Ok(())
}

#[test]
fn test_device_identity_canonical_encode_decode_roundtrip() -> Result<(), ContractError> {
    let device = sample_device()?;
    let bytes = device.canonical_bytes();

    let decoded = DeviceIdentity::from_canonical_bytes(&bytes)?;
    if decoded != device {
        return Err(ContractError::DigestMismatch);
    }

    let d1 = device.canonical_digest();
    let d2 = decoded.canonical_digest();
    if d1 != d2 {
        return Err(ContractError::DigestMismatch);
    }

    // Display implementation check
    let disp = format!("{device}");
    if !disp.contains("device:insta360-link-main") {
        return Err(ContractError::InvalidIdentifier);
    }

    Ok(())
}

#[test]
fn test_device_identity_generation_monotonicity() -> Result<(), ContractError> {
    let dev = sample_device()?;
    let new_gen = DeviceGeneration::parse("gen:dev:2026-09-11:rev2")?;

    // Transitioning with different generation produces new identity and distinct digest
    let updated = dev.transition_generation(new_gen)?;
    if updated == dev {
        return Err(ContractError::GenerationConflict);
    }
    if updated.canonical_digest() == dev.canonical_digest() {
        return Err(ContractError::GenerationConflict);
    }
    if !updated.is_same_hardware(&dev) {
        return Err(ContractError::InvalidIdentifier);
    }

    // Transitioning with IDENTICAL generation must fail closed
    let dup_res = dev.transition_generation(dev.generation.clone());
    match dup_res {
        Err(ContractError::GenerationConflict) => {}
        _ => return Err(ContractError::InvalidIdentifier),
    }

    Ok(())
}

#[test]
fn test_source_identity_construction_and_roundtrip() -> Result<(), ContractError> {
    let source = sample_source()?;
    let bytes = source.canonical_bytes();

    let decoded = SourceIdentity::from_canonical_bytes(&bytes)?;
    if decoded != source {
        return Err(ContractError::DigestMismatch);
    }

    let d1 = source.canonical_digest();
    let d2 = decoded.canonical_digest();
    if d1 != d2 {
        return Err(ContractError::DigestMismatch);
    }

    // Transition stream generation
    let new_stream_gen = StreamGeneration::parse("gen:stream:720p30-h264")?;
    let updated = source.transition_stream_generation(new_stream_gen)?;
    if updated == source {
        return Err(ContractError::GenerationConflict);
    }
    if updated.canonical_digest() == source.canonical_digest() {
        return Err(ContractError::GenerationConflict);
    }

    // Duplicate stream generation must fail closed
    match source.transition_stream_generation(source.stream_generation.clone()) {
        Err(ContractError::GenerationConflict) => {}
        _ => return Err(ContractError::InvalidIdentifier),
    }

    // Empty channel fails closed
    let mut invalid = source;
    invalid.channel.clear();
    if invalid.verify().is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    Ok(())
}

#[test]
fn test_adapter_identity_construction_and_roundtrip() -> Result<(), ContractError> {
    let adapter = sample_adapter()?;
    let bytes = adapter.canonical_bytes();

    let decoded = AdapterIdentity::from_canonical_bytes(&bytes)?;
    if decoded != adapter {
        return Err(ContractError::DigestMismatch);
    }

    let d1 = adapter.canonical_digest();
    let d2 = decoded.canonical_digest();
    if d1 != d2 {
        return Err(ContractError::DigestMismatch);
    }

    // Transition adapter generation
    let new_adapter_gen = AdapterGeneration::parse("gen:adapter:uvc-rust-v2")?;
    let updated = adapter.transition_generation(new_adapter_gen)?;
    if updated == adapter {
        return Err(ContractError::GenerationConflict);
    }
    if updated.canonical_digest() == adapter.canonical_digest() {
        return Err(ContractError::GenerationConflict);
    }

    // Duplicate generation must fail closed
    match adapter.transition_generation(adapter.generation.clone()) {
        Err(ContractError::GenerationConflict) => {}
        _ => return Err(ContractError::InvalidIdentifier),
    }

    // Zero bounds fail closed
    let mut inv1 = adapter.clone();
    inv1.max_bandwidth_bytes_per_sec = 0;
    if inv1.verify().is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    let mut inv2 = adapter.clone();
    inv2.max_buffer_frames = 0;
    if inv2.verify().is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    let mut inv3 = adapter;
    inv3.request_timeout_ns = 0;
    if inv3.verify().is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    Ok(())
}

#[test]
fn test_unknown_version_fails_closed() -> Result<(), ContractError> {
    let mut enc = CanonicalEncoder::new();
    enc.text("fss.device_identity.v2"); // Unknown version
    let dev = sample_device()?;
    dev.device_id.encode_canonical(&mut enc);
    dev.generation.encode_canonical(&mut enc);
    enc.text(&dev.manufacturer);
    enc.text(&dev.model);
    enc.text(&dev.hardware_revision);
    enc.text(&dev.firmware_version);
    enc.bool(false);
    enc.bool(false);
    dev.device_class.encode_canonical(&mut enc);
    dev.capabilities.encode_canonical(&mut enc);
    enc.text(&dev.failure_domain);

    let bytes = enc.finish();
    match DeviceIdentity::from_canonical_bytes(&bytes) {
        Err(ContractError::InvalidIdentifier) => {}
        _ => return Err(ContractError::InvalidIdentifier),
    }

    // Unknown schema for SourceIdentity
    let mut enc = CanonicalEncoder::new();
    enc.text("fss.source_identity.unknown_v99");
    let bytes = enc.finish();
    match SourceIdentity::from_canonical_bytes(&bytes) {
        Err(ContractError::InvalidIdentifier) => {}
        _ => return Err(ContractError::InvalidIdentifier),
    }

    // Unknown schema for AdapterIdentity
    let mut enc = CanonicalEncoder::new();
    enc.text("fss.adapter_identity.tampered");
    let bytes = enc.finish();
    match AdapterIdentity::from_canonical_bytes(&bytes) {
        Err(ContractError::InvalidIdentifier) => {}
        _ => return Err(ContractError::InvalidIdentifier),
    }

    Ok(())
}

#[test]
fn test_unknown_enum_tags_fail_closed() -> Result<(), ContractError> {
    // DeviceClass unknown tags
    let mut dec = CanonicalDecoder::new(&[0u8]);
    if DeviceClass::decode_canonical(&mut dec).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }
    let mut dec = CanonicalDecoder::new(&[99u8]);
    if DeviceClass::decode_canonical(&mut dec).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    // SourceKind unknown tags
    let mut dec = CanonicalDecoder::new(&[0u8]);
    if SourceKind::decode_canonical(&mut dec).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }
    let mut dec = CanonicalDecoder::new(&[77u8]);
    if SourceKind::decode_canonical(&mut dec).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    // MediaKind unknown tags
    let mut dec = CanonicalDecoder::new(&[0u8]);
    if MediaKind::decode_canonical(&mut dec).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }
    let mut dec = CanonicalDecoder::new(&[12u8]);
    if MediaKind::decode_canonical(&mut dec).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    // AdapterKind unknown tags
    let mut dec = CanonicalDecoder::new(&[0u8]);
    if AdapterKind::decode_canonical(&mut dec).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }
    let mut dec = CanonicalDecoder::new(&[88u8]);
    if AdapterKind::decode_canonical(&mut dec).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    // IsolationMode unknown tags
    let mut dec = CanonicalDecoder::new(&[0u8]);
    if IsolationMode::decode_canonical(&mut dec).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }
    let mut dec = CanonicalDecoder::new(&[5u8]);
    if IsolationMode::decode_canonical(&mut dec).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    // CredentialMethod unknown tags
    let mut dec = CanonicalDecoder::new(&[0u8]);
    if CredentialMethod::decode_canonical(&mut dec).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }
    let mut dec = CanonicalDecoder::new(&[9u8]);
    if CredentialMethod::decode_canonical(&mut dec).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    Ok(())
}

#[test]
fn test_malformed_canonical_bytes_fail_closed() -> Result<(), ContractError> {
    let dev = sample_device()?;
    let valid_bytes = dev.canonical_bytes();

    // Truncated bytes
    let truncated = &valid_bytes[..valid_bytes.len() / 2];
    match DeviceIdentity::from_canonical_bytes(truncated) {
        Err(_) => {}
        Ok(_) => return Err(ContractError::InvalidIdentifier),
    }

    // Extra trailing byte fails with NonCanonicalOrdering
    let mut trailing = valid_bytes;
    trailing.push(0xFF);
    match DeviceIdentity::from_canonical_bytes(&trailing) {
        Err(ContractError::NonCanonicalOrdering) => {}
        _ => return Err(ContractError::NonCanonicalOrdering),
    }

    Ok(())
}

#[test]
fn test_total_ordering_and_btree_collections() -> Result<(), ContractError> {
    let dev1 = sample_device()?;
    let mut dev2 = dev1.clone();
    dev2.device_id = DeviceId::parse("device:insta360-link-aux")?;

    let mut set = BTreeSet::new();
    set.insert(dev1.clone());
    set.insert(dev2.clone());

    if set.len() != 2 {
        return Err(ContractError::NonCanonicalOrdering);
    }

    let mut iter = set.into_iter();
    let first = iter.next().ok_or(ContractError::NotFound)?;
    let second = iter.next().ok_or(ContractError::NotFound)?;

    if first > second {
        return Err(ContractError::NonCanonicalOrdering);
    }

    Ok(())
}

#[test]
fn test_capabilities_bitflags() -> Result<(), ContractError> {
    let caps = DeviceCapabilities::PTZ.union(DeviceCapabilities::THERMAL);
    if !caps.contains(DeviceCapabilities::PTZ) {
        return Err(ContractError::InvalidIdentifier);
    }
    if !caps.contains(DeviceCapabilities::THERMAL) {
        return Err(ContractError::InvalidIdentifier);
    }
    if caps.contains(DeviceCapabilities::NIGHT_VISION) {
        return Err(ContractError::InvalidIdentifier);
    }

    let mut enc = CanonicalEncoder::new();
    caps.encode_canonical(&mut enc);
    let bytes = enc.finish();

    let mut dec = CanonicalDecoder::new(&bytes);
    let decoded = DeviceCapabilities::decode_canonical(&mut dec)?;
    if decoded != caps {
        return Err(ContractError::InvalidIdentifier);
    }

    let acaps = AdapterCapabilities::STREAMING.union(AdapterCapabilities::SNAPSHOT);
    if !acaps.contains(AdapterCapabilities::STREAMING) {
        return Err(ContractError::InvalidIdentifier);
    }
    if !acaps.contains(AdapterCapabilities::SNAPSHOT) {
        return Err(ContractError::InvalidIdentifier);
    }
    if acaps.contains(AdapterCapabilities::PTZ_CONTROL) {
        return Err(ContractError::InvalidIdentifier);
    }

    let mut enc = CanonicalEncoder::new();
    acaps.encode_canonical(&mut enc);
    let bytes = enc.finish();

    let mut dec = CanonicalDecoder::new(&bytes);
    let adecoded = AdapterCapabilities::decode_canonical(&mut dec)?;
    if adecoded != acaps {
        return Err(ContractError::InvalidIdentifier);
    }

    Ok(())
}
