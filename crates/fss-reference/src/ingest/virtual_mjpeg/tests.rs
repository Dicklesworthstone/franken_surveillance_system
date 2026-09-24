#![forbid(unsafe_code)]
use super::*;
use crate::DeliveryDirective;
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits, decode_luma};
use fss_ledger::IncompleteTailPolicy;
use fss_object::ObjectLimits;
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;
fn spec() -> Result<MjpegCameraSpec, Box<dyn Error>> {
    Ok(MjpegCameraSpec {
        capture_id: CapsuleId::parse("capture:virtual-mjpeg:1")?,
        sensor_id: SensorId::parse("sensor:virtual-mjpeg")?,
        seed: 7,
        frame_count: 5,
        width: 64,
        height: 48,
        start_ns: 1_000_000,
        period_ns: 33_000_000,
        uncertainty_ns: 500_000,
        packet_bytes: 17,
        warmup_frames: 2,
    })
}
fn generate(spec: &MjpegCameraSpec) -> Result<GeneratedMjpegSource, MjpegSourceError> {
    let mut clock = VirtualClock::new(spec.seed, TimestampNs(spec.start_ns));
    let cancelled = AtomicBool::new(false);
    generate_mjpeg_source(
        spec,
        &mut clock,
        &mut MjpegSourceBudget::new(MAX_SCENE_PIXELS, &cancelled),
    )
}

#[test]
fn every_reassembled_frame_decodes_to_the_declared_scene() -> TestResult {
    let spec = spec()?;
    let generated = generate(&spec)?;
    assert_eq!(generated.frames().len(), spec.frame_count as usize);
    for (index, span) in generated.frames().iter().enumerate() {
        let bytes = generated.frame_bytes(index).ok_or("missing frame")?;
        assert_eq!(ContentDigest::sha256(&bytes), span.encoded_digest);
        let decoded = decode_luma(
            &bytes,
            span.encoded_digest.bytes(),
            ComponentInterpretation::Grayscale,
            DecodeLimits::default(),
            &mut DecodeBudget::new(100_000_000),
        )?;
        assert_eq!(
            decoded.dimensions(),
            [u32::from(spec.width), u32::from(spec.height)]
        );
        let cancelled = AtomicBool::new(false);
        let expected = scene::render(
            &spec,
            span.rectangle,
            &mut MjpegSourceBudget::new(MAX_SCENE_PIXELS, &cancelled),
        )?;
        assert_eq!(
            decoded.pixels(),
            expected.as_slice(),
            "pixel-exact block scene at frame {index}"
        );
        assert!(
            decoded.receipt().metadata_segments >= 2,
            "JFIF plus retained synthetic recipe"
        );
    }
    assert!(generated.frame_bytes(spec.frame_count as usize).is_none());
    Ok(())
}
#[test]
fn fragmentation_preserves_every_byte_and_the_frame_capture_interval() -> TestResult {
    for packet_bytes in [1, 17, 64, MAX_VIRTUAL_PACKET_BYTES] {
        let mut spec = spec()?;
        spec.packet_bytes = packet_bytes;
        let generated = generate(&spec)?;
        let mut next = 0;
        for span in generated.frames() {
            assert_eq!(span.packet_range.start, next);
            let packets = &generated.packets()[span.packet_range.clone()];
            assert!(!packets.is_empty());
            for packet in packets {
                assert_eq!(packet.capture, span.capture);
                assert_eq!(packet.sensor_id, spec.sensor_id);
                assert!(!packet.bytes.is_empty() && packet.bytes.len() <= packet_bytes);
                assert_eq!(ContentDigest::sha256(&packet.bytes), packet.digest);
            }
            let earliest =
                spec.start_ns + i128::from(span.frame_index) * i128::from(spec.period_ns);
            assert_eq!(
                span.capture,
                CaptureInterval::new(
                    TimestampNs(earliest),
                    TimestampNs(earliest + i128::from(spec.uncertainty_ns))
                )?
            );
            next = span.packet_range.end;
        }
        assert_eq!(next, generated.packets().len());
        for (index, packet) in generated.packets().iter().enumerate() {
            assert_eq!(packet.sequence, index as u64 + 1);
        }
    }
    Ok(())
}
#[test]
fn equal_inputs_replay_exactly_and_sensor_seed_changes_are_bound() -> TestResult {
    let spec = spec()?;
    let first = generate(&spec)?;
    let second = generate(&spec)?;
    assert_eq!(first.packets(), second.packets());
    assert_eq!(first.frames(), second.frames());
    let mut changed = spec.clone();
    changed.seed += 1;
    assert_ne!(
        first.frames()[0].encoded_digest,
        generate(&changed)?.frames()[0].encoded_digest
    );
    changed = spec.clone();
    changed.sensor_id = SensorId::parse("sensor:other-virtual-camera")?;
    assert_ne!(
        first.frames()[0].encoded_digest,
        generate(&changed)?.frames()[0].encoded_digest
    );
    assert_ne!(
        first.frames()[0].recipe_digest,
        generate(&changed)?.frames()[0].recipe_digest
    );
    Ok(())
}
#[test]
fn quiet_warmup_then_motion_is_visible_in_decoded_pixels() -> TestResult {
    let spec = spec()?;
    let generated = generate(&spec)?;
    let mut centers = Vec::new();
    for (index, span) in generated.frames().iter().enumerate() {
        let bytes = generated.frame_bytes(index).ok_or("missing frame")?;
        let decoded = decode_luma(
            &bytes,
            span.encoded_digest.bytes(),
            ComponentInterpretation::Grayscale,
            DecodeLimits::default(),
            &mut DecodeBudget::new(100_000_000),
        )?;
        let foreground: Vec<_> = decoded
            .pixels()
            .iter()
            .enumerate()
            .filter(|(_, p)| **p > 128)
            .collect();
        if index < spec.warmup_frames as usize {
            assert!(foreground.is_empty());
        } else {
            assert_eq!(foreground.len(), 16 * 16);
            centers.push(
                foreground
                    .iter()
                    .map(|(i, _)| i % usize::from(spec.width))
                    .sum::<usize>(),
            );
        }
    }
    assert!(centers.windows(2).all(|pair| pair[0] != pair[1]));
    Ok(())
}
#[test]
fn all_supported_axis_extremes_round_trip() -> TestResult {
    for dimension in [24, 32, 64, 128, MAX_SCENE_DIMENSION] {
        let mut spec = spec()?;
        spec.width = dimension;
        spec.height = dimension;
        spec.frame_count = 1;
        spec.warmup_frames = 0;
        let generated = generate(&spec)?;
        let bytes = generated.frame_bytes(0).ok_or("missing frame")?;
        assert!(bytes.len() <= MAX_SCENE_FRAME_BYTES);
        let decoded = decode_luma(
            &bytes,
            ContentDigest::sha256(&bytes).bytes(),
            ComponentInterpretation::Grayscale,
            DecodeLimits::default(),
            &mut DecodeBudget::new(100_000_000),
        )?;
        assert_eq!(decoded.pixels().iter().filter(|p| **p == 224).count(), 256);
    }
    Ok(())
}
#[test]
fn cancellation_and_insufficient_budget_leave_clock_unchanged() -> TestResult {
    let spec = spec()?;
    let mut clock = VirtualClock::new(spec.seed, TimestampNs(spec.start_ns));
    let original = clock.clone();
    let cancelled = AtomicBool::new(true);
    let mut budget = MjpegSourceBudget::new(MAX_SCENE_PIXELS, &cancelled);
    assert!(matches!(
        generate_mjpeg_source(&spec, &mut clock, &mut budget),
        Err(MjpegSourceError::Cancelled)
    ));
    assert_eq!(budget.reserved(), 0);
    assert_eq!(clock, original);
    cancelled.store(false, Ordering::Release);
    let mut budget = MjpegSourceBudget::new(spec.rendered_pixels() - 1, &cancelled);
    assert!(matches!(
        generate_mjpeg_source(&spec, &mut clock, &mut budget),
        Err(MjpegSourceError::BudgetExhausted)
    ));
    assert_eq!(budget.reserved(), 0);
    assert_eq!(clock, original);
    let mut budget = MjpegSourceBudget::new(spec.rendered_pixels(), &cancelled);
    generate_mjpeg_source(&spec, &mut clock, &mut budget)?;
    assert_eq!(budget.reserved(), spec.rendered_pixels());
    assert_eq!(clock.step_count(), u64::from(spec.frame_count - 1));
    Ok(())
}
#[test]
fn late_clock_overflow_does_not_commit_jitter_or_partial_frames() -> TestResult {
    let mut spec = spec()?;
    spec.start_ns = i128::MAX - 100;
    spec.period_ns = 50;
    spec.uncertainty_ns = 10;
    spec.frame_count = 2;
    let mut clock = VirtualClock::new(spec.seed, TimestampNs(spec.start_ns));
    clock.inject_jitter(u64::MAX);
    let original = clock.clone();
    let cancelled = AtomicBool::new(false);
    let mut budget = MjpegSourceBudget::new(MAX_SCENE_PIXELS, &cancelled);
    assert!(matches!(
        generate_mjpeg_source(&spec, &mut clock, &mut budget),
        Err(MjpegSourceError::Clock(_))
    ));
    assert_eq!(clock, original);
    assert!(
        budget.reserved() > 0,
        "the failure occurs after rendering an earlier frame"
    );
    Ok(())
}
#[test]
fn packet_capacity_refuses_the_complete_session_without_clock_mutation() -> TestResult {
    let mut spec = spec()?;
    spec.width = 24;
    spec.height = 24;
    spec.packet_bytes = 1;
    spec.frame_count = 512;
    let mut clock = VirtualClock::new(spec.seed, TimestampNs(spec.start_ns));
    let original = clock.clone();
    let cancelled = AtomicBool::new(false);
    assert!(matches!(
        generate_mjpeg_source(
            &spec,
            &mut clock,
            &mut MjpegSourceBudget::new(MAX_SCENE_PIXELS, &cancelled)
        ),
        Err(MjpegSourceError::Limit("source packets"))
    ));
    assert_eq!(clock, original);
    Ok(())
}
#[test]
fn malformed_and_oversized_specifications_are_refused() -> TestResult {
    let good = spec()?;
    for dimension in [0, 8, 23, 25, 264, u16::MAX] {
        let mut bad = good.clone();
        bad.width = dimension;
        assert!(bad.validate().is_err());
    }
    let mut bad = good.clone();
    bad.frame_count = 0;
    assert!(bad.validate().is_err());
    bad = good.clone();
    bad.warmup_frames = bad.frame_count + 1;
    assert!(bad.validate().is_err());
    bad = good.clone();
    bad.period_ns = 0;
    assert!(bad.validate().is_err());
    bad = good.clone();
    bad.packet_bytes = MAX_VIRTUAL_PACKET_BYTES + 1;
    assert!(bad.validate().is_err());
    bad = good.clone();
    bad.start_ns = i128::MAX;
    assert!(bad.validate().is_err());
    bad = good;
    bad.frame_count = 4096;
    bad.width = 256;
    bad.height = 256;
    assert!(matches!(
        bad.validate(),
        Err(MjpegSourceError::Limit("aggregate rendered pixels"))
    ));
    Ok(())
}

struct JournalDirectory(std::path::PathBuf);
impl JournalDirectory {
    fn new() -> std::io::Result<Self> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("fss-mjpeg-source-{}-{id}", std::process::id()));
        std::fs::create_dir(&path)?; // Do not delete a preexisting path on a collision.
        Ok(Self(path))
    }
}
impl Drop for JournalDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn real_jpeg_capture_preserves_custody_through_delivery_faults() -> TestResult {
    let generated = generate(&spec()?)?;
    let expected = generated.packets().to_vec();
    let plan = DeliveryPlan::new(vec![
        DeliveryDirective::exact(2),
        DeliveryDirective::corrupt(1),
        DeliveryDirective::exact(2),
        DeliveryDirective::exact(expected.len() as u64),
    ])?;
    let journal = JournalDirectory::new()?;
    let mut ledger = DurableReferenceLedger::open(
        journal.0.join("capture.journal"),
        "site:mjpeg",
        IncompleteTailPolicy::Reject,
    )?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(4096, 4 * 1024 * 1024));
    let capture = generated.publish(&plan, &mut objects, &mut ledger)?;
    assert_eq!(capture.source_packets, expected);
    assert_eq!(capture.continuity.duplicate_sequences, vec![2]);
    assert_eq!(capture.continuity.corrupted_sequences, vec![1]);
    assert!(capture.continuity.reordered && !capture.continuity.exact_once_ordered);
    assert_eq!(capture.receipt.authority_anchor.commit_sequence, 1);
    assert_eq!(
        objects.verify_closure(capture.receipt.capture_root)?,
        capture.receipt.closure_object_count
    );
    for packet in &capture.source_packets {
        assert_eq!(objects.read_verified(packet.digest)?, packet.bytes);
    }
    assert_eq!(
        ledger.batches()[0].children,
        vec![capture.receipt.capture_root]
    );
    Ok(())
}
#[test]
fn invalid_delivery_plan_cannot_mutate_objects_or_authority() -> TestResult {
    let generated = generate(&spec()?)?;
    let plan = DeliveryPlan::new(vec![DeliveryDirective::exact(
        generated.packets().len() as u64 + 1,
    )])?;
    let journal = JournalDirectory::new()?;
    let mut ledger = DurableReferenceLedger::open(
        journal.0.join("capture.journal"),
        "site:mjpeg",
        IncompleteTailPolicy::Reject,
    )?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(4096, 4 * 1024 * 1024));
    assert!(generated.publish(&plan, &mut objects, &mut ledger).is_err());
    assert_eq!(objects.object_count(), 0);
    assert_eq!(ledger.current().anchor.commit_sequence, 0);
    Ok(())
}

#[test]
fn incremental_native_framing_handles_split_markers_and_multiple_frames_per_chunk() -> TestResult {
    use fss_codec_mjpeg::stream::{FramingLimits, JpegStream, StreamBasis};
    let spec = spec()?;
    let generated = generate(&spec)?;
    let bytes: Vec<_> = generated
        .packets()
        .iter()
        .flat_map(|p| p.bytes.iter().copied())
        .collect();
    for chunk_bytes in [1, 17, bytes.len()] {
        let basis = StreamBasis {
            source: ContentDigest::sha256(&bytes).bytes(),
            generation: 1,
        };
        let mut stream = JpegStream::new(basis, FramingLimits::default())?;
        let mut budget = DecodeBudget::new(100_000_000);
        let mut count = 0;
        for chunk in bytes.chunks(chunk_bytes) {
            let mut remaining = chunk;
            while !remaining.is_empty() {
                let step = stream.push(stream.next_offset(), remaining, &mut budget)?;
                assert!(step.consumed > 0);
                remaining = &remaining[step.consumed..];
                if let Some(frame) = step.frame {
                    assert_eq!(
                        frame.encoded_sha256(),
                        generated.frames()[count].encoded_digest.bytes()
                    );
                    frame.decode(
                        ComponentInterpretation::Grayscale,
                        DecodeLimits::default(),
                        &mut budget,
                    )?;
                    count += 1;
                }
            }
        }
        let end = stream.finish(&mut budget)?;
        assert_eq!(end.frames, u64::from(spec.frame_count));
        assert_eq!(end.bytes, bytes.len() as u64);
        assert_eq!(count, spec.frame_count as usize);
    }
    Ok(())
}

#[test]
fn repeated_source_bytes_share_objects_without_erasing_packet_multiplicity() -> TestResult {
    let mut spec = spec()?;
    spec.frame_count = 1;
    spec.warmup_frames = 0;
    spec.packet_bytes = 1;
    let generated = generate(&spec)?;
    assert!(generated.packets().len() > 256);
    let plan = DeliveryPlan::identity(generated.packets().len() as u32)?;
    let journal = JournalDirectory::new()?;
    let mut ledger = DurableReferenceLedger::open(
        journal.0.join("capture.journal"),
        "site:mjpeg",
        IncompleteTailPolicy::Reject,
    )?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(4096, 4 * 1024 * 1024));
    let capture = generated.publish(&plan, &mut objects, &mut ledger)?;
    let manifest = fss_object::ObjectManifest::from_canonical_bytes(
        objects.read_verified(capture.receipt.source_root)?,
    )?;
    assert!(
        manifest.children().len() <= 257,
        "at most 256 distinct single bytes and the complete trace"
    );
    assert_eq!(
        capture.receipt.source_packet_count,
        capture.source_packets.len()
    );
    assert_eq!(capture.delivery_packets.len(), capture.source_packets.len());
    assert!(capture.continuity.exact_once_ordered);
    Ok(())
}
