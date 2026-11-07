#![forbid(unsafe_code)]
//! Executes the exact source-time selector and native output core without a replay-runtime shim.

#[path = "../../fss-reference/src/ingest/recorded_decode/window.rs"]
mod window;
#[path = "../../fss-cli/src/bin/fss-file/jpeg_stream/encoder.rs"]
mod stream;

use fss_codec_jpeg_encode::{EncodeBudget, EncodeConfig, EncodeLimits, PixelFormat, encode_jpeg};
use fss_core::{
    CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, ContentDigest, DigestAlgorithm,
    SensorCapsule, SensorId, SensorSourceBytesSpec, StreamId, TimestampNs,
};
use window::{
    DecodedOutputWindow, FrameWindowError, FrameWindowReceipt, FrameWindowSelector,
    FrameWindowSource, FrameWindowTimeProvenance, MAX_FRAME_WINDOW_SEGMENTS,
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn source(first_segment: u64, segment_count: usize) -> FrameWindowSource {
    FrameWindowSource {
        import_identity: ContentDigest::sha256(b"retained window fixture import"),
        import_root: ContentDigest::sha256(b"retained window fixture root"),
        first_segment,
        segment_count,
        time_provenance: FrameWindowTimeProvenance::OperatorAssumption,
    }
}

fn request(start: i128, end: i128) -> Result<DecodedOutputWindow, FrameWindowError> {
    DecodedOutputWindow::new(TimestampNs(start), TimestampNs(end), ClockBasis::Estimated)
}

fn capsule(segment: u64, earliest: i128, latest: i128) -> Test<SensorCapsule> {
    Ok(SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
        capsule_id: CapsuleId::parse(format!("capsule:window-fixture:{segment}"))?,
        sensor_id: SensorId::parse("sensor:window-fixture")?,
        stream_id: StreamId::parse("stream:window-fixture:g1")?,
        sequence: segment,
        capture: CaptureInterval::new(TimestampNs(earliest), TimestampNs(latest))?,
        receive_time: TimestampNs(i128::MAX),
        clock_basis: ClockBasis::Estimated,
        source: &segment.to_be_bytes(),
        frame_count: 1,
        gap_before: false,
    })?)
}

fn pin(capsule: &SensorCapsule) -> ContentDigest {
    ContentDigest::sha256(&capsule.canonical_bytes())
}

fn observe(
    selector: &mut FrameWindowSelector,
    ordinal: u64,
    segment: u64,
    capsule: &SensorCapsule,
) -> Result<bool, FrameWindowError> {
    selector.observe(ordinal, segment, capsule, pin(capsule), false)
}

fn one_receipt(
    window: DecodedOutputWindow,
    source: FrameWindowSource,
    capsule: &SensorCapsule,
) -> Test<FrameWindowReceipt> {
    let mut selector = FrameWindowSelector::new(window, source)?;
    assert!(observe(&mut selector, 0, source.first_segment, capsule)?);
    Ok(selector.finish(1, false)?)
}

#[test]
fn closed_capture_half_open_window_matches_an_independent_discrete_oracle() -> Test {
    for start in -3..=3 {
        for end in start + 1..=4 {
            for first in -4..=4 {
                for last in first..=4 {
                    let frame = capsule(0, first, last)?;
                    let mut selector = FrameWindowSelector::new(request(start, end)?, source(0, 1))?;
                    let contained = (first..=last)
                        .filter(|time| *time >= start && *time < end)
                        .count();
                    let total = (first..=last).count();
                    let result = observe(&mut selector, 0, 0, &frame);
                    if contained == 0 {
                        assert_eq!(result, Ok(false), "window [{start},{end}), frame [{first},{last}]");
                        assert_eq!(selector.finish(1, false), Err(FrameWindowError::EmptySelection));
                    } else if contained == total {
                        assert_eq!(result, Ok(true), "window [{start},{end}), frame [{first},{last}]");
                        let receipt = selector.finish(1, false)?;
                        assert_eq!(receipt.selected_capture, frame.capture);
                        assert_eq!(receipt.selected_frames, 1);
                    } else {
                        assert_eq!(result, Err(FrameWindowError::BoundaryUncertain));
                        assert_eq!(selector.finish(1, false), Err(FrameWindowError::Fenced));
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn output_order_is_preserved_without_assuming_segment_or_capture_order() -> Test {
    let mut selector = FrameWindowSelector::new(request(15, 55)?, source(0, 4))?;
    let rows = [(0, 60), (3, 10), (1, 50), (2, 20)];
    let mut selected = Vec::new();
    for (ordinal, (segment, time)) in rows.into_iter().enumerate() {
        if observe(&mut selector, ordinal as u64, segment, &capsule(segment, time, time)?)? {
            selected.push(segment);
        }
    }
    assert_eq!(selected, [1, 2]);
    let receipt = selector.finish(4, false)?;
    assert_eq!((receipt.observed_frames, receipt.selected_frames, receipt.skipped_frames), (4, 2, 2));
    assert_eq!(receipt.selected_capture, CaptureInterval::new(TimestampNs(20), TimestampNs(50))?);
    Ok(())
}

#[test]
fn window_constructor_checks_signed_extremes_without_rounding_or_wrapping() -> Test {
    for (start, end) in [(0, 0), (5, -5), (i128::MIN, i128::MAX)] {
        assert_eq!(request(start, end), Err(FrameWindowError::InvalidWindow));
    }
    for (start, end, selected) in [
        (i128::MIN, i128::MIN + 10, i128::MIN),
        (i128::MAX - 10, i128::MAX, i128::MAX - 1),
        (-10, 0, -1),
    ] {
        let window = request(start, end)?;
        assert_eq!(window.start(), TimestampNs(start));
        assert_eq!(window.end(), TimestampNs(end));
        assert_eq!(window.clock_basis(), ClockBasis::Estimated);
        let receipt = one_receipt(window, source(0, 1), &capsule(0, selected, selected)?)?;
        assert_eq!(receipt.selected_capture, CaptureInterval::point(TimestampNs(selected)));
    }
    Ok(())
}

#[test]
fn unavailable_time_and_invalid_source_bounds_are_refused_before_observation() -> Test {
    let window = request(0, 20)?;
    let mut unknown = source(0, 1);
    unknown.time_provenance = FrameWindowTimeProvenance::Unknown;
    assert_eq!(FrameWindowSelector::new(window, unknown).err(), Some(FrameWindowError::UnknownTime));
    for invalid in [source(0, 0), source(0, MAX_FRAME_WINDOW_SEGMENTS + 1), source(u64::MAX, 1)] {
        assert_eq!(FrameWindowSelector::new(window, invalid).err(), Some(FrameWindowError::InvalidSource));
    }
    for digest in [
        ContentDigest::new(DigestAlgorithm::Sha256, [0; 32]),
        ContentDigest::new(DigestAlgorithm::Blake3, [1; 32]),
        ContentDigest::new_laboratory(DigestAlgorithm::Sha256, [1; 32]),
    ] {
        let mut invalid = source(0, 1);
        invalid.import_identity = digest;
        assert_eq!(FrameWindowSelector::new(window, invalid).err(), Some(FrameWindowError::InvalidSource));
        let mut invalid = source(0, 1);
        invalid.import_root = digest;
        assert_eq!(FrameWindowSelector::new(window, invalid).err(), Some(FrameWindowError::InvalidSource));
    }
    Ok(())
}

#[test]
fn clock_pin_is_required_even_for_excluded_frames_and_binds_request_identity() -> Test {
    let bases = [ClockBasis::Estimated, ClockBasis::HostMonotonic, ClockBasis::DeviceMonotonic, ClockBasis::UtcDisciplined];
    let mut requests = Vec::new();
    for basis in bases {
        let mut frame = capsule(0, 10, 10)?;
        frame.clock_basis = basis;
        let window = DecodedOutputWindow::new(TimestampNs(0), TimestampNs(20), basis)?;
        requests.push(one_receipt(window, source(0, 1), &frame)?.request_digest);
        for actual in bases.into_iter().filter(|actual| *actual != basis) {
            frame.clock_basis = actual;
            frame.capture = CaptureInterval::point(TimestampNs(100));
            let mut selector = FrameWindowSelector::new(window, source(0, 1))?;
            assert_eq!(observe(&mut selector, 0, 0, &frame), Err(FrameWindowError::ClockMismatch));
            assert_eq!(selector.finish(1, false), Err(FrameWindowError::Fenced));
        }
    }
    requests.sort();
    requests.dedup();
    assert_eq!(requests.len(), bases.len());
    Ok(())
}

#[test]
fn independently_pinned_capsules_and_single_sensor_stream_are_enforced() -> Test {
    let original = capsule(10, 10, 10)?;
    let mut changed = original.clone();
    changed.capture.latest = TimestampNs(11);
    let mut selector = FrameWindowSelector::new(request(0, 20)?, source(10, 2))?;
    assert_eq!(selector.observe(0, 10, &changed, pin(&original), false), Err(FrameWindowError::SourceMismatch));
    assert_eq!(observe(&mut selector, 0, 10, &original), Err(FrameWindowError::Fenced));

    for change_sensor in [true, false] {
        let mut selector = FrameWindowSelector::new(request(0, 20)?, source(10, 2))?;
        assert!(observe(&mut selector, 0, 10, &original)?);
        let mut other = capsule(11, 100, 100)?;
        if change_sensor {
            other.sensor_id = SensorId::parse("sensor:other")?;
        } else {
            other.stream_id = StreamId::parse("stream:window-fixture:g2")?;
        }
        assert_eq!(observe(&mut selector, 1, 11, &other), Err(FrameWindowError::SourceMismatch));
        assert_eq!(selector.finish(1, false), Err(FrameWindowError::Fenced));
    }
    Ok(())
}

#[test]
fn malformed_metadata_is_not_hidden_by_an_exclusion() -> Test {
    let original = capsule(0, 100, 110)?;
    for mutation in 0..6 {
        let mut frame = original.clone();
        match mutation {
            0 => frame.capture.latest = TimestampNs(90),
            1 => frame.frame_count = 0,
            2 => frame.frame_count = 2,
            3 => frame.source_bytes = 0,
            4 => frame.source_digest = ContentDigest::new(DigestAlgorithm::Sha256, [0; 32]),
            _ => frame.source_digest = frame.source_digest.with_laboratory(true),
        }
        let mut selector = FrameWindowSelector::new(request(0, 20)?, source(0, 1))?;
        assert_eq!(observe(&mut selector, 0, 0, &frame), Err(FrameWindowError::InvalidCapsule));
    }
    let mut selector = FrameWindowSelector::new(request(0, 20)?, source(0, 1))?;
    assert_eq!(selector.observe(0, 0, &original, ContentDigest::new(DigestAlgorithm::Sha256, [0; 32]), false), Err(FrameWindowError::InvalidCapsule));
    Ok(())
}

#[test]
fn duplicate_segments_reordered_ordinals_and_range_overruns_fence_the_selection() -> Test {
    let first = capsule(100, 10, 10)?;
    let next = capsule(101, 11, 11)?;
    for (ordinal, segment, expected) in [
        (1, 100, FrameWindowError::OutputOrder),
        (0, 99, FrameWindowError::Limit),
        (0, 102, FrameWindowError::Limit),
    ] {
        let mut selector = FrameWindowSelector::new(request(0, 20)?, source(100, 2))?;
        assert_eq!(observe(&mut selector, ordinal, segment, &first), Err(expected));
        assert_eq!(selector.finish(0, false), Err(FrameWindowError::Fenced));
    }
    for (ordinal, segment, expected) in [
        (0, 101, FrameWindowError::OutputOrder),
        (2, 101, FrameWindowError::OutputOrder),
        (1, 100, FrameWindowError::DuplicateSegment),
    ] {
        let mut selector = FrameWindowSelector::new(request(0, 20)?, source(100, 2))?;
        assert!(observe(&mut selector, 0, 100, &first)?);
        assert_eq!(observe(&mut selector, ordinal, segment, &next), Err(expected));
        assert_eq!(selector.finish(1, false), Err(FrameWindowError::Fenced));
    }
    let mut selector = FrameWindowSelector::new(request(0, 20)?, source(100, 1))?;
    assert!(observe(&mut selector, 0, 100, &first)?);
    assert_eq!(observe(&mut selector, 1, 101, &next), Err(FrameWindowError::Limit));
    assert_eq!(selector.finish(1, false), Err(FrameWindowError::Fenced));
    Ok(())
}

#[test]
fn cancellation_empty_selection_and_incomplete_counts_never_finish_successfully() -> Test {
    let frame = capsule(0, 10, 10)?;
    let mut selector = FrameWindowSelector::new(request(0, 20)?, source(0, 1))?;
    assert_eq!(selector.observe(0, 0, &frame, pin(&frame), true), Err(FrameWindowError::Cancelled));
    assert_eq!(observe(&mut selector, 0, 0, &frame), Err(FrameWindowError::Fenced));
    assert_eq!(selector.finish(0, false), Err(FrameWindowError::Fenced));

    let mut selector = FrameWindowSelector::new(request(0, 20)?, source(0, 1))?;
    assert!(observe(&mut selector, 0, 0, &frame)?);
    assert_eq!(selector.finish(1, true), Err(FrameWindowError::Cancelled));
    for completed in [0, 2] {
        let mut selector = FrameWindowSelector::new(request(0, 20)?, source(0, 2))?;
        assert!(observe(&mut selector, 0, 0, &frame)?);
        assert_eq!(selector.finish(completed, false), Err(FrameWindowError::IncompleteRange));
    }
    assert_eq!(FrameWindowSelector::new(request(0, 20)?, source(0, 1))?.finish(0, false), Err(FrameWindowError::EmptySelection));
    let mut selector = FrameWindowSelector::new(request(0, 10)?, source(0, 1))?;
    assert!(!observe(&mut selector, 0, 0, &frame)?);
    assert_eq!(selector.finish(1, false), Err(FrameWindowError::EmptySelection));
    Ok(())
}

#[test]
fn request_and_ordered_decisions_bind_source_generations_bounds_and_exclusions() -> Test {
    let frame = capsule(1, 10, 10)?;
    let baseline = one_receipt(request(0, 20)?, source(0, 2), &frame)?;
    let mut requests = vec![baseline.request_digest];
    for mutation in 0..5 {
        let mut selected_source = source(0, 2);
        let mut window = request(0, 20)?;
        match mutation {
            0 => selected_source.import_identity = ContentDigest::sha256(b"another import"),
            1 => selected_source.import_root = ContentDigest::sha256(b"another root"),
            2 => selected_source.first_segment = 1,
            3 => selected_source.segment_count = 3,
            _ => window = request(-1, 20)?,
        }
        requests.push(one_receipt(window, selected_source, &frame)?.request_digest);
    }
    requests.sort();
    requests.dedup();
    assert_eq!(requests.len(), 6);

    let mut receipts = Vec::new();
    for mutation in 0..3 {
        let mut selector = FrameWindowSelector::new(request(0, 20)?, source(0, 2))?;
        let mut excluded = capsule(0, 50, 50)?;
        if mutation == 1 {
            excluded.source_digest = ContentDigest::sha256(b"different excluded bytes");
        } else if mutation == 2 {
            excluded.gap_before = true;
        }
        assert!(!observe(&mut selector, 0, 0, &excluded)?);
        assert!(observe(&mut selector, 1, 1, &frame)?);
        receipts.push(selector.finish(2, false)?);
    }
    assert!(receipts.iter().all(|receipt| receipt.request_digest == baseline.request_digest));
    assert!(receipts.iter().all(|receipt| receipt.selected_capture == frame.capture));
    assert_ne!(receipts[0].selection_digest, receipts[1].selection_digest);
    assert_ne!(receipts[0].selection_digest, receipts[2].selection_digest);
    Ok(())
}

#[test]
fn maximum_range_uses_all_duplicate_bitmap_words_and_allows_declared_codec_skips() -> Test {
    let count = MAX_FRAME_WINDOW_SEGMENTS;
    let mut selector = FrameWindowSelector::new(request(0, 20)?, source(7, count))?;
    // Reverse source order covers the far end of every bitmap word without capture-order assumptions.
    for (ordinal, segment) in (7..7 + count as u64).rev().enumerate() {
        assert!(observe(&mut selector, ordinal as u64, segment, &capsule(segment, 10, 10)?)?);
    }
    let receipt = selector.finish(count as u64, false)?;
    assert_eq!(receipt.selected_frames, count as u64);
    assert_eq!(receipt.skipped_frames, 0);

    // An HEVC owner can report fewer complete outputs than access units due to declared RASL skips.
    let mut selector = FrameWindowSelector::new(request(0, 20)?, source(0, 3))?;
    assert!(observe(&mut selector, 0, 2, &capsule(2, 10, 10)?)?);
    assert_eq!(selector.finish(1, false)?.observed_frames, 1);
    Ok(())
}

#[test]
fn native_mjpeg_writes_and_charges_only_selected_frames_in_display_order() -> Test {
    let values = [16_u8, 80, 120, 200];
    let mut selector = FrameWindowSelector::new(request(10, 30)?, source(0, values.len()))?;
    let mut output = stream::Encoder::<Vec<u8>>::new(stream::DEFAULT_OUTPUT_BYTES, values.len(), stream::DEFAULT_QUALITY)?;
    let mut budget = EncodeBudget::new(stream::DEFAULT_ENCODE_WORK_UNITS);
    for (ordinal, value) in values.into_iter().enumerate() {
        let frame = capsule(ordinal as u64, ordinal as i128 * 10, ordinal as i128 * 10)?;
        if observe(&mut selector, ordinal as u64, ordinal as u64, &frame)? {
            let pixels = [value; 64];
            output.frame(
                stream::FrameInput {
                    dimensions: [8, 8],
                    pixels: &pixels,
                    luma_sha256: ContentDigest::sha256(&pixels).bytes(),
                    decode_receipt: ContentDigest::sha256(&[value]),
                },
                &mut budget,
                || Ok(Vec::new()),
                &mut || Ok(()),
            )?;
        }
    }
    let selection = selector.finish(4, false)?;
    let (bytes, receipt) = output.finish(&mut || Ok(()))?;
    let mut expected = Vec::new();
    let mut expected_budget = EncodeBudget::new(stream::DEFAULT_ENCODE_WORK_UNITS);
    for value in [80_u8, 120] {
        let pixels = [value; 64];
        expected.extend_from_slice(encode_jpeg(
            8, 8, &pixels, ContentDigest::sha256(&pixels).bytes(),
            EncodeConfig { quality: stream::DEFAULT_QUALITY, format: PixelFormat::Grayscale },
            &EncodeLimits::default(), &mut expected_budget,
        )?.bytes());
    }
    assert_eq!(bytes, expected);
    assert_eq!((selection.selected_frames, selection.skipped_frames), (2, 2));
    assert_eq!(receipt.frames, selection.selected_frames as usize);
    assert_eq!(receipt.bytes, expected.len() as u64);
    assert_eq!(receipt.digest, ContentDigest::sha256(&expected));
    assert_eq!(receipt.quality, stream::DEFAULT_QUALITY);
    assert_eq!(receipt.encoder.bytes(), fss_codec_jpeg_encode::encoder_identity());
    assert_eq!(receipt.work_units, budget.used());
    assert_eq!(budget.used(), expected_budget.used());
    assert_ne!(receipt.frame_receipts_digest, selection.selection_digest);
    assert_ne!(selection.request_digest, selection.selection_digest);
    Ok(())
}
