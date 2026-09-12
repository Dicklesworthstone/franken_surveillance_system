#![forbid(unsafe_code)]
//! Integration contract tests for virtual encoded-camera fixture generator (FSS-014).
//!
//! Verifies:
//! - Deterministic, seeded encoded-frame fixtures (codec, container, keyframe cadence)
//! - Typed fixture variants: Corrupt, Truncated, and StaleFirmware
//! - Strict capsule binding (SensorCapsuleV1) ensuring no fixture is "retained evidence" without custody
//! - Integration with [`SequencedPacket`] and the FSS-015 [`PacketFaultInjector`]
//! - End-to-end pipeline: fixtures -> injector -> typed InjectedGapWitness
//! - Hard bounds tested at bound and bound+1
//! - Bit-identical replay from identical seeds

use std::collections::BTreeMap;
use std::error::Error;

use fss_core::{CapsuleId, ContinuityState, DecodeState, DeviceId, SensorId, SourceId};
use fss_reference::{
    ContainerFormat, EncodedCameraGenerator, EncodedCameraSpec, EncodedFixtureError,
    EncodedFixtureKind, EncodedFrameFixture, FaultStreamItem, FrameType, InjectedGapWitness,
    MAX_FIXTURE_FRAMES, MAX_FIXTURE_PAYLOAD_BYTES, MAX_FRAME_HEIGHT, MAX_FRAME_WIDTH,
    MAX_KEYFRAME_CADENCE, PacketFaultSchedule, SequencedPacket, VideoCodec, inject_stream,
};

fn create_valid_spec(
    seed: u64,
    frame_count: u32,
    cadence: u32,
) -> Result<EncodedCameraSpec, Box<dyn Error>> {
    EncodedCameraSpec::new(
        CapsuleId::parse("cap:fixture:e2e:cam01")?,
        SensorId::parse("sensor:cam:driveway-01")?,
        DeviceId::parse("device:axis-p3245-01")?,
        SourceId::parse("src:cam:driveway-01:main")?,
        seed,
        frame_count,
        1024,
        1_000_000_000,
        33_333_333,
        500_000,
        1920,
        1080,
        VideoCodec::H264,
        ContainerFormat::Mp4,
        cadence,
        "sha256:firmware-v1-production-active".to_string(),
    )
    .map_err(Into::into)
}

#[test]
fn encoded_fixture_nominal_generation_and_capsule_binding() -> Result<(), Box<dyn Error>> {
    let spec = create_valid_spec(42, 4, 2)?;
    let generator = EncodedCameraGenerator::new(spec.clone())?;
    let fixtures = generator.generate_all()?;

    assert_eq!(fixtures.len(), 4);

    for (idx, fixture) in fixtures.iter().enumerate() {
        let expected_seq = (idx + 1) as u64;
        assert_eq!(fixture.sequence(), expected_seq);
        assert_eq!(fixture.sensor_id(), &spec.sensor_id);
        assert_eq!(fixture.codec, VideoCodec::H264);
        assert_eq!(fixture.container, ContainerFormat::Mp4);
        assert_eq!(fixture.payload.len(), 1024);

        // Verify capsule binding and verified custody
        let capsule = &fixture.capsule;
        assert_eq!(capsule.sequence, expected_seq);
        assert_eq!(capsule.sensor_id, spec.sensor_id);
        assert_eq!(capsule.device_id, spec.device_id);
        assert_eq!(capsule.source_id, spec.source_id);
        assert_eq!(capsule.media.codec, "h264");
        assert_eq!(capsule.media.container.as_deref(), Some("mp4"));
        assert_eq!(capsule.media.width, Some(1920));
        assert_eq!(capsule.media.height, Some(1080));
        assert_eq!(capsule.media.source_bytes, 1024);

        // Strict custody is verified: payload digest matches custody
        assert_eq!(capsule.custody.is_retained(), true);
        assert_eq!(capsule.integrity.decode, DecodeState::Verified);
        assert_eq!(capsule.integrity.continuity, ContinuityState::Verified);

        // Verification of capsule contract
        capsule.verify()?;
    }

    Ok(())
}

#[test]
fn encoded_fixture_keyframe_cadence() -> Result<(), Box<dyn Error>> {
    // Cadence 3: frame 1=Keyframe, frame 2=Delta, frame 3=Delta, frame 4=Keyframe
    let spec = create_valid_spec(99, 6, 3)?;
    let generator = EncodedCameraGenerator::new(spec)?;
    let fixtures = generator.generate_all()?;

    assert_eq!(fixtures.len(), 6);
    assert_eq!(fixtures[0].frame_type, FrameType::Keyframe);
    assert_eq!(fixtures[1].frame_type, FrameType::Delta);
    assert_eq!(fixtures[2].frame_type, FrameType::Delta);
    assert_eq!(fixtures[3].frame_type, FrameType::Keyframe);
    assert_eq!(fixtures[4].frame_type, FrameType::Delta);
    assert_eq!(fixtures[5].frame_type, FrameType::Delta);

    Ok(())
}

#[test]
fn encoded_fixture_typed_variants_corrupt_truncated_stale() -> Result<(), Box<dyn Error>> {
    let spec = create_valid_spec(1234, 5, 10)?;
    let mut variants = BTreeMap::new();
    variants.insert(
        2,
        EncodedFixtureKind::Corrupt {
            byte_offset: 64,
            mutation: "bit_flip_xor_ff".to_string(),
        },
    );
    variants.insert(
        3,
        EncodedFixtureKind::Truncated {
            truncated_len: 256,
            expected_len: 1024,
        },
    );
    variants.insert(
        4,
        EncodedFixtureKind::StaleFirmware {
            stale_fingerprint: "sha256:deprecated-firmware-v0-9".to_string(),
            expected_fingerprint: "sha256:firmware-v1-production-active".to_string(),
        },
    );

    let generator = EncodedCameraGenerator::with_variants(spec, variants)?;
    let fixtures = generator.generate_all()?;

    // Frame 1: Nominal
    assert!(matches!(
        fixtures[0].fixture_kind,
        EncodedFixtureKind::Nominal
    ));
    assert_eq!(fixtures[0].capsule.integrity.decode, DecodeState::Verified);

    // Frame 2: Corrupt
    match &fixtures[1].fixture_kind {
        EncodedFixtureKind::Corrupt { byte_offset, .. } => {
            assert_eq!(*byte_offset, 64);
        }
        other => return Err(format!("expected Corrupt, got {other:?}").into()),
    }
    assert_eq!(
        fixtures[1].capsule.integrity.decode,
        DecodeState::ConcealedErrors
    );

    // Frame 3: Truncated
    match &fixtures[2].fixture_kind {
        EncodedFixtureKind::Truncated {
            truncated_len,
            expected_len,
        } => {
            assert_eq!(*truncated_len, 256);
            assert_eq!(*expected_len, 1024);
        }
        other => return Err(format!("expected Truncated, got {other:?}").into()),
    }
    assert_eq!(fixtures[2].payload.len(), 256);
    assert_eq!(fixtures[2].capsule.integrity.decode, DecodeState::Failed);

    // Frame 4: Stale Firmware
    match &fixtures[3].fixture_kind {
        EncodedFixtureKind::StaleFirmware {
            stale_fingerprint, ..
        } => {
            assert_eq!(stale_fingerprint, "sha256:deprecated-firmware-v0-9");
        }
        other => return Err(format!("expected StaleFirmware, got {other:?}").into()),
    }
    assert_eq!(
        fixtures[3]
            .capsule
            .integrity
            .firmware_fingerprint
            .as_deref(),
        Some("sha256:deprecated-firmware-v0-9")
    );

    // Verify all capsules satisfy schema invariants
    for fixture in &fixtures {
        fixture.capsule.verify()?;
    }

    Ok(())
}

#[test]
fn encoded_fixture_bit_identical_replay_from_seed() -> Result<(), Box<dyn Error>> {
    let spec1 = create_valid_spec(0xfeed_cafe_u64, 8, 4)?;
    let spec2 = create_valid_spec(0xfeed_cafe_u64, 8, 4)?;

    let fixtures1 = EncodedCameraGenerator::new(spec1)?.generate_all()?;
    let fixtures2 = EncodedCameraGenerator::new(spec2)?.generate_all()?;

    assert_eq!(fixtures1.len(), 8);
    assert_eq!(fixtures2.len(), 8);

    for (f1, f2) in fixtures1.iter().zip(fixtures2.iter()) {
        assert_eq!(f1.sequence(), f2.sequence());
        assert_eq!(f1.payload, f2.payload);
        assert_eq!(f1.payload_digest, f2.payload_digest);
        assert_eq!(f1.frame_type, f2.frame_type);
        assert_eq!(f1.capsule, f2.capsule);
    }

    // Changing seed produces distinct payload and digests
    let spec_diff = create_valid_spec(0x1122_3344_u64, 8, 4)?;
    let fixtures_diff = EncodedCameraGenerator::new(spec_diff)?.generate_all()?;
    assert_ne!(fixtures1[0].payload, fixtures_diff[0].payload);
    assert_ne!(fixtures1[0].payload_digest, fixtures_diff[0].payload_digest);

    Ok(())
}

#[test]
fn encoded_fixture_e2e_with_fault_injector_and_gap_witness() -> Result<(), Box<dyn Error>> {
    // 1. Generate 8 encoded camera fixtures
    let spec = create_valid_spec(777, 8, 4)?;
    let generator = EncodedCameraGenerator::new(spec)?;
    let fixtures: Vec<EncodedFrameFixture> = generator.generate_all()?;
    assert_eq!(fixtures.len(), 8);

    // 2. Build PacketFaultSchedule with:
    // - Drop sequence 2
    // - Duplicate sequence 4 (1 extra copy)
    // - Reorder sequence 7 (delayed 1 step)
    // - Injected coverage gap from sequence 5 to 6
    let mut schedule = PacketFaultSchedule::with_deterministic_rules(888, 4)?;
    schedule.add_drop_rule(2, "transmission_buffer_overrun")?;
    schedule.add_duplicate_rule(4, 1)?;
    schedule.add_gap(5, 6, "simulated_poe_power_blip")?;
    schedule.add_reorder_rule(7, 1)?;

    // 3. Run fault injector over the SequencedPacket encoded fixtures
    let (stream_items, journal) = inject_stream(fixtures, schedule)?;

    // 4. Validate downstream stream items
    let mut delivered_sequences = Vec::new();
    let mut found_gap_witness = false;

    for item in &stream_items {
        match item {
            FaultStreamItem::Packet {
                packet,
                is_duplicate,
                ..
            } => {
                delivered_sequences.push((packet.sequence(), *is_duplicate));
                // Fixture retained evidence invariant: every delivered frame carries verified capsule
                packet.capsule.verify()?;
            }
            FaultStreamItem::InjectedGap(witness) => {
                let witness: &InjectedGapWitness = witness;
                assert_eq!(witness.start_sequence, 5);
                assert_eq!(witness.end_sequence, 6);
                assert_eq!(witness.reason, "simulated_poe_power_blip");
                found_gap_witness = true;
            }
        }
    }

    // Sequence 2 dropped
    assert!(!delivered_sequences.iter().any(|(s, _)| *s == 2));
    // Sequence 4 duplicated
    let count_4 = delivered_sequences.iter().filter(|(s, _)| *s == 4).count();
    assert_eq!(count_4, 2);
    // Injected gap witness emitted in stream
    assert!(found_gap_witness);

    // Journal verifies all typed evidence
    assert_eq!(journal.lost_sequences.contains(&2), true);
    assert_eq!(journal.duplicated_sequences.contains(&4), true);
    assert_eq!(journal.gap_witnesses.len(), 1);
    assert_eq!(journal.gap_witnesses[0].start_sequence, 5);
    assert_eq!(journal.gap_witnesses[0].end_sequence, 6);

    Ok(())
}

#[test]
fn encoded_fixture_bounds_frame_count_at_and_above_bound() -> Result<(), Box<dyn Error>> {
    // Bound: MAX_FIXTURE_FRAMES (65_536) -> Ok
    let at_bound = create_valid_spec(1, MAX_FIXTURE_FRAMES, 30);
    assert!(at_bound.is_ok());

    // Bound + 1: MAX_FIXTURE_FRAMES + 1 (65_537) -> Err
    let above_bound = create_valid_spec(1, MAX_FIXTURE_FRAMES + 1, 30);
    match above_bound {
        Err(e) => {
            assert!(e.to_string().contains("frame count"));
        }
        Ok(_) => return Err("expected FrameCountExceedsBound error".into()),
    }

    // Zero frame count -> Err
    let zero_count = create_valid_spec(1, 0, 30);
    assert!(zero_count.is_err());

    Ok(())
}

#[test]
fn encoded_fixture_bounds_payload_bytes_at_and_above_bound() -> Result<(), Box<dyn Error>> {
    let mut spec = create_valid_spec(2, 5, 30)?;

    // Bound: MAX_FIXTURE_PAYLOAD_BYTES (1_048_576) -> Ok
    spec.frame_bytes = MAX_FIXTURE_PAYLOAD_BYTES;
    assert!(spec.validate().is_ok());

    // Bound + 1: MAX_FIXTURE_PAYLOAD_BYTES + 1 -> Err
    spec.frame_bytes = MAX_FIXTURE_PAYLOAD_BYTES + 1;
    match spec.validate() {
        Err(EncodedFixtureError::PayloadBytesExceedsBound { requested, max }) => {
            assert_eq!(requested, MAX_FIXTURE_PAYLOAD_BYTES + 1);
            assert_eq!(max, MAX_FIXTURE_PAYLOAD_BYTES);
        }
        other => return Err(format!("expected PayloadBytesExceedsBound, got {other:?}").into()),
    }

    // Zero payload bytes -> Err
    spec.frame_bytes = 0;
    assert!(matches!(
        spec.validate(),
        Err(EncodedFixtureError::ZeroPayloadBytes)
    ));

    Ok(())
}

#[test]
fn encoded_fixture_bounds_keyframe_cadence_at_and_above_bound() -> Result<(), Box<dyn Error>> {
    let mut spec = create_valid_spec(3, 5, 30)?;

    // Bound: MAX_KEYFRAME_CADENCE (600) -> Ok
    spec.keyframe_cadence = MAX_KEYFRAME_CADENCE;
    assert!(spec.validate().is_ok());

    // Bound + 1: MAX_KEYFRAME_CADENCE + 1 -> Err
    spec.keyframe_cadence = MAX_KEYFRAME_CADENCE + 1;
    match spec.validate() {
        Err(EncodedFixtureError::KeyframeCadenceExceedsBound { requested, max }) => {
            assert_eq!(requested, MAX_KEYFRAME_CADENCE + 1);
            assert_eq!(max, MAX_KEYFRAME_CADENCE);
        }
        other => return Err(format!("expected KeyframeCadenceExceedsBound, got {other:?}").into()),
    }

    // Zero cadence -> Err
    spec.keyframe_cadence = 0;
    assert!(matches!(
        spec.validate(),
        Err(EncodedFixtureError::ZeroKeyframeCadence)
    ));

    Ok(())
}

#[test]
fn encoded_fixture_bounds_dimensions_at_and_above_bound() -> Result<(), Box<dyn Error>> {
    let mut spec = create_valid_spec(4, 5, 30)?;

    // Width at bound
    spec.width = MAX_FRAME_WIDTH;
    assert!(spec.validate().is_ok());
    // Width at bound + 1
    spec.width = MAX_FRAME_WIDTH + 1;
    match spec.validate() {
        Err(EncodedFixtureError::DimensionExceedsBound {
            field,
            requested,
            max,
        }) => {
            assert_eq!(field, "width");
            assert_eq!(requested, MAX_FRAME_WIDTH + 1);
            assert_eq!(max, MAX_FRAME_WIDTH);
        }
        other => return Err(format!("expected DimensionExceedsBound, got {other:?}").into()),
    }

    // Height at bound
    spec.width = 1920;
    spec.height = MAX_FRAME_HEIGHT;
    assert!(spec.validate().is_ok());
    // Height at bound + 1
    spec.height = MAX_FRAME_HEIGHT + 1;
    match spec.validate() {
        Err(EncodedFixtureError::DimensionExceedsBound {
            field,
            requested,
            max,
        }) => {
            assert_eq!(field, "height");
            assert_eq!(requested, MAX_FRAME_HEIGHT + 1);
            assert_eq!(max, MAX_FRAME_HEIGHT);
        }
        other => return Err(format!("expected DimensionExceedsBound, got {other:?}").into()),
    }

    Ok(())
}
