#![forbid(unsafe_code)]
use fss_codec_mjpeg::{ComponentInterpretation as Color, DecodeBudget, DecodeError, DecodeLimits};
use fss_codec_mjpeg::stream::{FramedJpeg, FramingError, FramingLimits, JpegStream, StreamBasis};
use fss_core::ContentDigest;
use std::sync::atomic::AtomicBool;

type Test = Result<(), Box<dyn std::error::Error>>;
const GRAY: &[u8] = include_bytes!("fixtures/gray.jpg");
const COLOR: &[u8] = include_bytes!("fixtures/y420_restart.jpg");
fn basis() -> StreamBasis { StreamBasis { source: [9; 32], generation: 7 } }
fn new() -> Result<JpegStream, FramingError> { JpegStream::new(basis(), FramingLimits::default()) }
fn collect(data: &[u8], chunk: usize) -> Result<Vec<FramedJpeg>, Box<dyn std::error::Error>> {
    let mut stream = new()?;
    let mut budget = DecodeBudget::new(10_000_000);
    let mut frames = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + chunk).min(data.len());
        let step = stream.push(offset as u64, &data[offset..end], &mut budget)?;
        assert!(step.consumed > 0);
        offset += step.consumed;
        if let Some(frame) = step.frame { frames.push(frame); }
    }
    let end = stream.finish(&mut budget)?;
    assert_eq!(end.frames, frames.len() as u64);
    assert_eq!(end.bytes, data.len() as u64);
    assert_eq!(end.basis, basis());
    Ok(frames)
}
fn metadata_frame() -> Vec<u8> {
    let metadata = b"before\xff\xd9\xff\xd8\xff\xdaafter";
    let mut data = vec![255, 216, 255, 225];
    data.extend_from_slice(&((metadata.len() + 2) as u16).to_be_bytes());
    data.extend_from_slice(metadata);
    data.extend_from_slice(&GRAY[2..]);
    data
}
#[test]
fn concatenated_real_images_keep_exact_source_ranges_and_decode() -> Test {
    let mut data = GRAY.to_vec(); data.extend_from_slice(COLOR);
    let frames = collect(&data, data.len())?;
    assert_eq!(frames.len(), 2);
    for (i, (frame, encoded)) in frames.iter().zip([GRAY, COLOR]).enumerate() {
        assert_eq!(frame.basis(), basis()); assert_eq!(frame.ordinal(), i as u64 + 1);
        assert_eq!(frame.bytes(), encoded);
        assert_eq!(frame.encoded_sha256(), ContentDigest::sha256(encoded).bytes());
        let decoded = frame.decode(if i == 0 { Color::Grayscale } else { Color::YCbCr },
            DecodeLimits::default(), &mut DecodeBudget::new(10_000_000))?;
        assert_eq!(decoded.dimensions(), [17, 13]);
    }
    assert_eq!(frames[0].byte_range(), [0, GRAY.len() as u64]);
    assert_eq!(frames[1].byte_range(), [GRAY.len() as u64, data.len() as u64]);
    Ok(())
}
#[test]
fn every_two_chunk_split_has_identical_bytes_and_offsets() -> Test {
    let data = metadata_frame();
    for split in 0..=data.len() {
        let mut stream = new()?; let mut budget = DecodeBudget::new(1_000_000);
        let first = stream.push(0, &data[..split], &mut budget)?;
        assert_eq!(first.consumed, split);
        let frame = if let Some(frame) = first.frame { frame } else {
            stream.push(split as u64, &data[split..], &mut budget)?.frame.ok_or("missing frame")?
        };
        assert_eq!(frame.bytes(), data); assert_eq!(frame.byte_range(), [0, data.len() as u64]);
        assert_eq!(stream.finish(&mut budget)?.frames, 1);
    }
    Ok(())
}
#[test]
fn bytewise_input_and_restart_splits_do_not_create_extra_frames() -> Test {
    let mut data = metadata_frame(); data.extend_from_slice(COLOR); data.extend_from_slice(GRAY);
    for chunk in 1..=23 {
        let frames = collect(&data, chunk)?;
        assert_eq!(frames.len(), 3); assert_eq!(frames[1].bytes(), COLOR);
        assert_eq!(frames[2].bytes(), GRAY);
    }
    Ok(())
}
#[test]
fn embedded_eoi_soi_and_sos_in_metadata_are_not_boundaries() -> Test {
    let data = metadata_frame(); let frames = collect(&data, 1)?;
    assert_eq!(frames.len(), 1); assert_eq!(frames[0].bytes(), data);
    let decoded = frames[0].decode(Color::Grayscale, DecodeLimits::default(), &mut DecodeBudget::new(1_000_000))?;
    assert_eq!(decoded.dimensions(), [17, 13]); Ok(())
}
#[test]
fn stops_before_next_frame_or_bad_suffix_without_dropping_it() -> Test {
    let mut stream = new()?; let mut budget = DecodeBudget::new(1_000_000);
    let mut data = GRAY.to_vec(); data.extend_from_slice(&[1, 2, 3]);
    let first = stream.push(0, &data, &mut budget)?;
    assert_eq!(first.consumed, GRAY.len()); assert!(first.frame.is_some());
    let failure = stream.push(first.consumed as u64, &data[first.consumed..], &mut budget).err().ok_or("accepted bad suffix")?;
    assert_eq!(failure.error, FramingError::Malformed); assert_eq!(failure.consumed, 1);
    assert_eq!(stream.completed_frames(), 1);
    assert!(stream.finish(&mut budget).is_err());
    let discarded = stream.abort(); assert_eq!(discarded.bytes(), &[1]);
    assert_eq!(discarded.byte_range, [GRAY.len() as u64, GRAY.len() as u64 + 1]); Ok(())
}
#[test]
fn every_incomplete_prefix_is_not_clean_eof() -> Test {
    for end in 1..GRAY.len() {
        let mut stream = new()?; let mut budget = DecodeBudget::new(1_000_000);
        assert!(stream.push(0, &GRAY[..end], &mut budget)?.frame.is_none());
        let failure = stream.finish(&mut budget).err().ok_or("partial frame accepted")?;
        assert_eq!(failure.error, FramingError::Truncated);
        let fragment = stream.abort(); assert_eq!(fragment.bytes(), &GRAY[..end]);
        assert_eq!(fragment.byte_range, [0, end as u64]);
    }
    Ok(())
}
#[test]
fn input_offset_mismatch_is_terminal_and_does_not_read_bytes() -> Test {
    let mut stream = new()?; let mut budget = DecodeBudget::new(1_000_000);
    stream.push(0, &GRAY[..20], &mut budget)?;
    let e = stream.push(19, &GRAY[20..], &mut budget).err().ok_or("replay accepted")?;
    assert_eq!((e.error, e.consumed, e.next_offset), (FramingError::OffsetMismatch, 0, 20));
    assert_eq!(stream.push(20, &GRAY[20..], &mut budget).err().ok_or("resumed")?.error, FramingError::Poisoned);
    assert_eq!(stream.abort().bytes(), &GRAY[..20]); Ok(())
}
#[test]
fn invalid_markers_and_lengths_never_resynchronize_silently() -> Test {
    for bad in [&[255, 216, 255, 217][..], &[255, 216, 255, 216], &[255, 216, 255, 208],
        &[255, 216, 255, 0], &[255, 216, 255, 219, 0, 1], &[255, 216, 255, 2]] {
        let mut data = bad.to_vec(); data.extend_from_slice(GRAY);
        let mut stream = new()?; let mut budget = DecodeBudget::new(1_000_000);
        assert!(stream.push(0, &data, &mut budget).is_err());
        assert_eq!(stream.completed_frames(), 0); assert!(stream.failure().is_some());
    }
    Ok(())
}
#[test]
fn malformed_entropy_fill_cannot_hide_stuffing() -> Test {
    let mut stream = new()?;
    let bytes = &[255, 216, 255, 218, 0, 2, 255, 255, 0, 255, 217];
    assert!(matches!(stream.push(0, bytes, &mut DecodeBudget::new(1000)).err().map(|e| e.error),
        Some(FramingError::Malformed))); Ok(())
}
#[test]
fn framing_success_does_not_claim_entropy_or_codec_validation() -> Test {
    let frames = collect(&[255, 216, 255, 218, 0, 2, 255, 217], 1)?;
    assert_eq!(frames.len(), 1);
    assert!(frames[0].decode(Color::Grayscale, DecodeLimits::default(), &mut DecodeBudget::new(10000)).is_err());
    Ok(())
}
#[test]
fn progressive_marker_remains_framed_but_unsupported_by_baseline_decoder() -> Test {
    let mut bytes = GRAY.to_vec();
    let index = bytes.windows(2).position(|v| v == [255, 192]).ok_or("missing SOF0")?;
    bytes[index + 1] = 194;
    let frames = collect(&bytes, 3)?;
    assert!(matches!(frames[0].decode(Color::Grayscale, DecodeLimits::default(),
        &mut DecodeBudget::new(1_000_000)), Err(DecodeError::Unsupported))); Ok(())
}
#[test]
fn frame_and_marker_ceilings_refuse_whole_result() -> Test {
    for limits in [FramingLimits { maximum_frame_bytes: GRAY.len()-1, ..FramingLimits::default() },
        FramingLimits { maximum_markers: 1, ..FramingLimits::default() }] {
        let mut stream = JpegStream::new(basis(), limits)?;
        let failure = stream.push(0, GRAY, &mut DecodeBudget::new(1_000_000)).err().ok_or("limit ignored")?;
        assert_eq!(failure.error, FramingError::Limit); assert_eq!(stream.completed_frames(), 0);
        assert_eq!(stream.abort().bytes(), &GRAY[..failure.consumed]);
    }
    Ok(())
}
#[test]
fn budget_failure_reports_consumed_prefix_and_abort_needs_no_budget() -> Test {
    let mut stream = new()?; let mut budget = DecodeBudget::new(40);
    let failure = stream.push(0, GRAY, &mut budget).err().ok_or("budget ignored")?;
    assert_eq!(failure.error, FramingError::Work(DecodeError::BudgetExhausted));
    assert_eq!((failure.consumed, failure.next_offset), (10, 10));
    let fragment = stream.abort(); assert_eq!(fragment.bytes(), &GRAY[..10]);
    assert!(stream.abort().bytes().is_empty()); Ok(())
}
#[test]
fn hash_budget_failure_does_not_emit_complete_but_unpublished_frame() -> Test {
    let mut stream = new()?; let mut budget = DecodeBudget::new(GRAY.len() as u64 * 4);
    let failure = stream.push(0, GRAY, &mut budget).err().ok_or("hash work omitted")?;
    assert_eq!(failure.consumed, GRAY.len()); assert_eq!(stream.completed_frames(), 0);
    assert_eq!(stream.abort().bytes(), GRAY); Ok(())
}
#[test]
fn cancellation_preserves_partial_source_without_emitting_a_frame() -> Test {
    let mut stream = new()?; stream.push(0, &GRAY[..20], &mut DecodeBudget::new(1000))?;
    let flag = AtomicBool::new(true); let mut budget = DecodeBudget::cancellable(1_000_000, &flag);
    let e = stream.push(20, &GRAY[20..], &mut budget).err().ok_or("cancellation ignored")?;
    assert_eq!(e.error, FramingError::Work(DecodeError::Cancelled)); assert_eq!(e.consumed, 0);
    assert_eq!(stream.abort().bytes(), &GRAY[..20]); Ok(())
}
#[test]
fn empty_input_is_not_eof_and_closed_stream_cannot_resume() -> Test {
    let mut stream = new()?; let mut budget = DecodeBudget::new(1000);
    let step = stream.push(0, &[], &mut budget)?; assert_eq!(step.consumed, 0); assert!(step.frame.is_none());
    assert_eq!(stream.finish(&mut budget)?.frames, 0);
    assert_eq!(stream.push(0, GRAY, &mut budget).err().ok_or("closed stream resumed")?.error, FramingError::Closed);
    assert!(stream.finish(&mut budget).is_err()); Ok(())
}
#[test]
fn invalid_configuration_is_rejected_before_accepting_input() {
    assert!(JpegStream::new(StreamBasis { source: [0; 32], generation: 1 }, FramingLimits::default()).is_err());
    assert!(JpegStream::new(StreamBasis { source: [1; 32], generation: 0 }, FramingLimits::default()).is_err());
    assert!(JpegStream::new(basis(), FramingLimits { maximum_frame_bytes: 0, ..FramingLimits::default() }).is_err());
    assert!(JpegStream::new(basis(), FramingLimits { maximum_markers: 4097, ..FramingLimits::default() }).is_err());
}
