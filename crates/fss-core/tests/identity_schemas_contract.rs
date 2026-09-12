#![forbid(unsafe_code)]
//! Integration and property contract tests for FSS-005: Source, Device, and Adapter identity schemas.

use std::collections::BTreeSet;

use fss_core::{
    AdapterCapabilities, AdapterGeneration, AdapterId, AdapterIdentity, AdapterKind, AppGeneration,
    ApplicationGeneration, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    ClockBasis, ContentDigest, ContractError, CredentialMethod, DeviceCapabilities, DeviceClass,
    DeviceGeneration, DeviceId, DeviceIdentity, FirmwareGeneration, IsolationMode, MediaKind,
    ModelGeneration, SourceId, SourceIdentity, SourceKind, StreamGeneration,
};

fn sample_device() -> Result<DeviceIdentity, ContractError> {
    let device_id = DeviceId::parse("device:insta360-link-main")?;
    let generation = DeviceGeneration::parse("gen:dev:2026-09-11:rev1")?;
    let model_gen = ModelGeneration::parse("gen:model:yolo-pose-v4")?;
    let firmware_version = FirmwareGeneration::parse("gen:firmware:v1-2-64")?;
    let application_version = Some(AppGeneration::parse("gen:app:2026-09")?);

    let device = DeviceIdentity {
        device_id,
        generation,
        manufacturer: "Insta360".to_string(),
        model: "Link".to_string(),
        hardware_revision: "HW-REV-2.1".to_string(),
        firmware_version,
        application_version,
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

    // Verify unknown capabilities fail closed in verify
    let mut invalid = device.clone();
    invalid.capabilities = DeviceCapabilities(1 << 31);
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
    dev.firmware_version.encode_canonical(&mut enc);
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

/// Finding 1: Prefix aliases normalize to canonical prefixes and produce identical canonical digests.
#[test]
fn test_prefix_aliases_canonical_normalization_and_digest_agreement() -> Result<(), ContractError> {
    let src_canonical = SourceId::parse("src:cam01")?;
    let src_alt = SourceId::parse("source:cam01")?;
    if src_canonical != src_alt {
        return Err(ContractError::InvalidIdentifier);
    }
    if src_alt.as_str() != "src:cam01" {
        return Err(ContractError::InvalidIdentifier);
    }
    let mut enc1 = CanonicalEncoder::new();
    src_canonical.encode_canonical(&mut enc1);
    let mut enc2 = CanonicalEncoder::new();
    src_alt.encode_canonical(&mut enc2);
    let bytes1 = enc1.finish();
    let bytes2 = enc2.finish();
    if bytes1 != bytes2 {
        return Err(ContractError::NonCanonicalOrdering);
    }
    if ContentDigest::sha256(&bytes1) != ContentDigest::sha256(&bytes2) {
        return Err(ContractError::DigestMismatch);
    }

    let dev_canonical = DeviceId::parse("device:cam-front")?;
    let dev_alt = DeviceId::parse("dev:cam-front")?;
    if dev_canonical != dev_alt {
        return Err(ContractError::InvalidIdentifier);
    }
    if dev_alt.as_str() != "device:cam-front" {
        return Err(ContractError::InvalidIdentifier);
    }
    let mut enc1 = CanonicalEncoder::new();
    dev_canonical.encode_canonical(&mut enc1);
    let mut enc2 = CanonicalEncoder::new();
    dev_alt.encode_canonical(&mut enc2);
    let bytes1 = enc1.finish();
    let bytes2 = enc2.finish();
    if bytes1 != bytes2 {
        return Err(ContractError::NonCanonicalOrdering);
    }
    if ContentDigest::sha256(&bytes1) != ContentDigest::sha256(&bytes2) {
        return Err(ContractError::DigestMismatch);
    }

    let adp_canonical = AdapterId::parse("adapter:onvif-01")?;
    let adp_alt = AdapterId::parse("adp:onvif-01")?;
    if adp_canonical != adp_alt {
        return Err(ContractError::InvalidIdentifier);
    }
    if adp_alt.as_str() != "adapter:onvif-01" {
        return Err(ContractError::InvalidIdentifier);
    }
    let mut enc1 = CanonicalEncoder::new();
    adp_canonical.encode_canonical(&mut enc1);
    let mut enc2 = CanonicalEncoder::new();
    adp_alt.encode_canonical(&mut enc2);
    let bytes1 = enc1.finish();
    let bytes2 = enc2.finish();
    if bytes1 != bytes2 {
        return Err(ContractError::NonCanonicalOrdering);
    }
    if ContentDigest::sha256(&bytes1) != ContentDigest::sha256(&bytes2) {
        return Err(ContractError::DigestMismatch);
    }

    Ok(())
}

/// Finding 2: Subsystem generation transitions enforce monotonicity and reject backward rollback.
#[test]
fn test_generation_transitions_reject_non_monotonic_rollback() -> Result<(), ContractError> {
    let dev = sample_device()?;
    let gen_older = DeviceGeneration::parse("gen:dev:2026-09-10:rev0")?;
    let gen_same = dev.generation.clone();
    let gen_newer = DeviceGeneration::parse("gen:dev:2026-09-12:rev2")?;

    match dev.transition_generation(gen_older) {
        Err(ContractError::GenerationConflict) => {}
        _ => return Err(ContractError::InvalidIdentifier),
    }
    match dev.transition_generation(gen_same) {
        Err(ContractError::GenerationConflict) => {}
        _ => return Err(ContractError::InvalidIdentifier),
    }
    let dev_updated = dev.transition_generation(gen_newer)?;
    if dev_updated.generation.as_str() != "gen:dev:2026-09-12:rev2" {
        return Err(ContractError::GenerationConflict);
    }

    let adapter = sample_adapter()?;
    let adp_older = AdapterGeneration::parse("gen:adapter:uvc-rust-v0")?;
    let adp_same = adapter.generation.clone();
    let adp_newer = AdapterGeneration::parse("gen:adapter:uvc-rust-v2")?;

    match adapter.transition_generation(adp_older) {
        Err(ContractError::GenerationConflict) => {}
        _ => return Err(ContractError::InvalidIdentifier),
    }
    match adapter.transition_generation(adp_same) {
        Err(ContractError::GenerationConflict) => {}
        _ => return Err(ContractError::InvalidIdentifier),
    }
    let adp_updated = adapter.transition_generation(adp_newer)?;
    if adp_updated.generation.as_str() != "gen:adapter:uvc-rust-v2" {
        return Err(ContractError::GenerationConflict);
    }

    let source = sample_source()?;
    let stm_older = StreamGeneration::parse("gen:stream:0480p30-nv12")?;
    let stm_same = source.stream_generation.clone();
    let stm_newer = StreamGeneration::parse("gen:stream:1440p60-nv12")?;

    match source.transition_stream_generation(stm_older) {
        Err(ContractError::GenerationConflict) => {}
        _ => return Err(ContractError::InvalidIdentifier),
    }
    match source.transition_stream_generation(stm_same) {
        Err(ContractError::GenerationConflict) => {}
        _ => return Err(ContractError::InvalidIdentifier),
    }
    let stm_updated = source.transition_stream_generation(stm_newer)?;
    if stm_updated.stream_generation.as_str() != "gen:stream:1440p60-nv12" {
        return Err(ContractError::GenerationConflict);
    }

    Ok(())
}

/// Finding 3: Capability bitfields reject unknown bits during decoding and verification.
#[test]
fn test_capabilities_reject_unknown_bits_in_decode_and_verify() -> Result<(), ContractError> {
    if DeviceCapabilities::from_bits(1 << 7).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }
    if DeviceCapabilities::from_bits(1 << 31).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }
    let valid_dev_caps = DeviceCapabilities::from_bits(0x7F)?;
    if valid_dev_caps != DeviceCapabilities::ALL {
        return Err(ContractError::InvalidIdentifier);
    }

    let mut enc = CanonicalEncoder::new();
    enc.u32(1 << 31);
    let bytes = enc.finish();
    let mut dec = CanonicalDecoder::new(&bytes);
    if DeviceCapabilities::decode_canonical(&mut dec).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    let mut enc = CanonicalEncoder::new();
    enc.u32(1 << 7);
    let bytes = enc.finish();
    let mut dec = CanonicalDecoder::new(&bytes);
    if DeviceCapabilities::decode_canonical(&mut dec).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    if AdapterCapabilities::from_bits(1 << 8).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }
    if AdapterCapabilities::from_bits(1 << 31).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }
    let valid_adp_caps = AdapterCapabilities::from_bits(0xFF)?;
    if valid_adp_caps != AdapterCapabilities::ALL {
        return Err(ContractError::InvalidIdentifier);
    }

    let mut enc = CanonicalEncoder::new();
    enc.u32(1 << 31);
    let bytes = enc.finish();
    let mut dec = CanonicalDecoder::new(&bytes);
    if AdapterCapabilities::decode_canonical(&mut dec).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    let mut enc = CanonicalEncoder::new();
    enc.u32(1 << 8);
    let bytes = enc.finish();
    let mut dec = CanonicalDecoder::new(&bytes);
    if AdapterCapabilities::decode_canonical(&mut dec).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    let mut dev = sample_device()?;
    dev.capabilities = DeviceCapabilities(1 << 31);
    if dev.verify().is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    let mut adapter = sample_adapter()?;
    adapter.capabilities = AdapterCapabilities(1 << 31);
    if adapter.verify().is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    Ok(())
}

/// Finding 4: Firmware and application versions are typed subsystem generations.
#[test]
fn test_firmware_and_app_generation_newtypes() -> Result<(), ContractError> {
    let fw = FirmwareGeneration::parse("fwgen:v0001:rev2")?;
    if fw.as_str() != "fwgen:v0001:rev2" {
        return Err(ContractError::InvalidIdentifier);
    }
    if FirmwareGeneration::parse("UPPERCASE:NOT:ALLOWED").is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }
    if FirmwareGeneration::parse("short").is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }
    if FirmwareGeneration::parse("").is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    let app = AppGeneration::parse("appgen:v0001:sec1")?;
    if app.as_str() != "appgen:v0001:sec1" {
        return Err(ContractError::InvalidIdentifier);
    }
    let app_alias: ApplicationGeneration = app;
    if app_alias.as_str() != "appgen:v0001:sec1" {
        return Err(ContractError::InvalidIdentifier);
    }
    if AppGeneration::parse("with whitespace").is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }
    if AppGeneration::parse("toolong:".to_string() + &"a".repeat(260)).is_ok() {
        return Err(ContractError::InvalidIdentifier);
    }

    let dev = sample_device()?;
    if dev.firmware_version.as_str() != "gen:firmware:v1-2-64" {
        return Err(ContractError::InvalidIdentifier);
    }
    if dev.application_version.as_ref().map(|a| a.as_str()) != Some("gen:app:2026-09") {
        return Err(ContractError::InvalidIdentifier);
    }

    Ok(())
}

/// Finding 5: Schemas match capability bitfield maximums and typed generation bounds.
#[test]
fn test_schemas_capability_and_version_bounds() -> Result<(), ContractError> {
    let dev_schema = include_str!("../../../schemas/device_identity.v1.json");
    let adp_schema = include_str!("../../../schemas/adapter_identity.v1.json");

    // Device capability maximum must match 7 defined bits (0x7F = 127)
    if !dev_schema.contains("\"maximum\": 127") {
        return Err(ContractError::InvalidIdentifier);
    }
    if dev_schema.contains("\"maximum\": 4294967295") {
        return Err(ContractError::InvalidIdentifier);
    }

    // Adapter capability maximum must match 8 defined bits (0xFF = 255)
    if !adp_schema.contains("\"maximum\": 255") {
        return Err(ContractError::InvalidIdentifier);
    }
    if adp_schema.contains("\"maximum\": 4294967295") {
        return Err(ContractError::InvalidIdentifier);
    }

    // Firmware version and application version must specify subsystem generation bounds
    if !dev_schema.contains("^[a-z0-9][a-z0-9:+._-]{7,255}$") {
        return Err(ContractError::InvalidIdentifier);
    }

    Ok(())
}
