#![forbid(unsafe_code)]

use super::*;
use crate::demux::AvcMp4;

#[path = "../../../tests/support/flv_fixture.rs"]
mod fixture;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const MP4: &[u8] = include_bytes!("../../../tests/fixtures/interleaved_av.mp4");

fn source() -> Test<Vec<u8>> {
    let mp4 = AvcMp4::parse(MP4, None, DemuxLimits::default())?;
    let mut bytes = fixture::header(true);
    fixture::tag(&mut bytes, 18, 0, b"opaque metadata, not a timing authority");
    fixture::configuration(&mut bytes, fixture::avcc(MP4)?);
    for sample in mp4.samples() {
        let dts = u32::try_from(sample.decode_time * 1000 / u64::from(mp4.timescale()))?;
        let cts = i32::try_from(sample.composition_offset * 1000 / i64::from(mp4.timescale()))?;
        fixture::sample(&mut bytes, &MP4[sample.source.clone()], dts, cts, sample.contains_idr);
        fixture::tag(&mut bytes, 8, dts, &[0xaf, 1, 0, 3, 9]);
    }
    Ok(bytes)
}

fn parse(bytes: &[u8]) -> Result<FlvVideo, DemuxError> {
    FlvVideo::parse(bytes, DemuxLimits::default())
}

#[test]
fn real_avc_samples_and_signed_timing_keep_exact_original_source_spans() -> Test {
    let bytes = source()?;
    let flv = parse(&bytes)?;
    let mp4 = AvcMp4::parse(MP4, None, DemuxLimits::default())?;
    assert_eq!(flv.nal_length_bytes(), mp4.nal_length_bytes());
    assert_eq!(flv.samples().len(), 10);
    assert_eq!(flv.parameter_sets().len(), mp4.parameter_sets().len());
    for (actual, expected) in flv.parameter_sets().iter().zip(mp4.parameter_sets()) {
        assert_eq!(&bytes[actual.clone()], &MP4[expected.clone()]);
    }
    let mut cursor = 0;
    for tag in flv.tags() {
        assert_eq!(tag.range.start, cursor);
        cursor = tag.range.end;
    }
    assert_eq!(cursor, bytes.len());
    for (index, (actual, expected)) in flv.samples().iter().zip(mp4.samples()).enumerate() {
        assert_eq!(actual.index, index);
        assert_eq!(&bytes[actual.source.clone()], &MP4[expected.source.clone()]);
        assert_eq!(actual.decode_time_ms, (expected.decode_time * 1000 / u64::from(mp4.timescale())) as u32);
        assert_eq!(i128::from(actual.presentation_time_ms()), expected.presentation_time() * 1000 / i128::from(mp4.timescale()));
        assert_eq!(actual.duration_ms, (index < 9).then_some(200));
        assert_eq!(actual.keyframe, expected.contains_idr);
        let mut next = actual.source.start;
        for nal in &actual.nals {
            assert_eq!(nal.start, next + flv.nal_length_bytes());
            assert!(nal.end <= actual.source.end);
            let length = bytes[next..nal.start].iter().fold(0_usize, |n, byte| (n << 8) | usize::from(*byte));
            assert_eq!(length, nal.len());
            next = nal.end;
        }
        assert_eq!(next, actual.source.end);
    }
    Ok(())
}

#[test]
fn variable_decode_intervals_and_negative_presentations_are_not_normalized() -> Test {
    let mp4 = AvcMp4::parse(MP4, None, DemuxLimits::default())?;
    let mut bytes = fixture::header(false);
    fixture::configuration(&mut bytes, fixture::avcc(MP4)?);
    for (index, (dts, cts)) in [(1, -3), (41, 7), (250, -25)].into_iter().enumerate() {
        let sample = &mp4.samples()[index];
        fixture::sample(&mut bytes, &MP4[sample.source.clone()], dts, cts, sample.contains_idr);
    }
    let video = parse(&bytes)?;
    assert_eq!(video.samples().iter().map(|s| s.presentation_time_ms()).collect::<Vec<_>>(), [-2, 48, 225]);
    assert_eq!(video.samples().iter().map(|s| s.duration_ms).collect::<Vec<_>>(), [Some(40), Some(209), None]);
    // Neither EOS nor a late script record licenses a fabricated last-frame duration.
    fixture::tag(&mut bytes, 9, 500, &[0x17, 2, 0, 0, 0]);
    fixture::tag(&mut bytes, 18, 900, b"duration=2000");
    assert_eq!(parse(&bytes)?.samples(), video.samples());
    Ok(())
}

#[test]
fn changed_or_late_configuration_and_inband_parameter_drift_refuse() -> Test {
    let bytes = source()?;
    let parsed = parse(&bytes)?;
    let mut repeated = bytes.clone();
    fixture::configuration(&mut repeated, fixture::avcc(MP4)?);
    assert_eq!(parse(&repeated)?.samples(), parsed.samples());
    let mut changed = fixture::avcc(MP4)?.to_vec();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    let mut drift = bytes.clone();
    fixture::configuration(&mut drift, &changed);
    assert_eq!(parse(&drift), Err(DemuxError::Unsupported));
    let mut late = fixture::header(false);
    let sample = &parsed.samples()[0];
    fixture::sample(&mut late, &bytes[sample.source.clone()], 0, 0, true);
    fixture::configuration(&mut late, fixture::avcc(MP4)?);
    assert_eq!(parse(&late), Err(DemuxError::MissingBox(*b"avcC")));
    // The complete configuration is immutable even when a changed SPS appears in a sample.
    let mut inband = fixture::header(false);
    fixture::configuration(&mut inband, fixture::avcc(MP4)?);
    let mut payload = Vec::new();
    let parameter = &parsed.parameter_sets()[0];
    payload.extend_from_slice(&(parameter.len() as u32).to_be_bytes());
    payload.extend_from_slice(&bytes[parameter.clone()]);
    let last = payload.len() - 1;
    payload[last] ^= 1;
    payload.extend_from_slice(&bytes[sample.source.clone()]);
    fixture::sample(&mut inband, &payload, 0, 0, true);
    assert_eq!(parse(&inband), Err(DemuxError::Unsupported));
    Ok(())
}

#[test]
fn timestamp_reversal_duplicate_and_wrap_never_gain_an_inferred_epoch() -> Test {
    let mp4 = AvcMp4::parse(MP4, None, DemuxLimits::default())?;
    for times in [[500, 500], [500, 499], [u32::MAX - 2, 1]] {
        let mut bytes = fixture::header(false);
        fixture::configuration(&mut bytes, fixture::avcc(MP4)?);
        for (sample, dts) in mp4.samples().iter().zip(times) {
            fixture::sample(&mut bytes, &MP4[sample.source.clone()], dts, 0, sample.contains_idr);
        }
        assert_eq!(parse(&bytes), Err(DemuxError::Timeline));
    }
    Ok(())
}

#[test]
fn malformed_tags_nals_frame_assertions_and_video_after_end_refuse() -> Test {
    let bytes = source()?;
    let video = parse(&bytes)?;
    let first = &video.samples()[0];
    for (at, value) in [
        (3, 2), (4, 0x81), (12, 1), (first.tag.start, 0x49),
        (first.tag.start + 8, 1), (first.tag.end - 1, 0),
        (first.tag.start + 11, 0x27), // Inter-frame assertion carrying an IDR.
        (first.source.start, 0xff), // NAL length exceeds exact sample.
    ] {
        let mut bad = bytes.clone();
        bad[at] = value;
        assert!(parse(&bad).is_err(), "mutation {at}");
    }
    for (at, value) in [(first.tag.start, 0x29), (first.tag.start + 11, 0x37), (first.tag.start + 11, 0x18)] {
        let mut bad = bytes.clone();
        bad[at] = value;
        assert_eq!(parse(&bad), Err(DemuxError::Unsupported));
    }
    let mut ended = bytes.clone();
    fixture::tag(&mut ended, 9, 9999, &[0x17, 2, 0, 0, 0]);
    fixture::sample(&mut ended, &bytes[first.source.clone()], 10000, 0, true);
    assert_eq!(parse(&ended), Err(DemuxError::Layout));
    Ok(())
}

#[test]
fn every_truncated_prefix_is_either_a_complete_observed_prefix_or_refused() -> Test {
    let bytes = source()?;
    let original = parse(&bytes)?;
    for end in 0..bytes.len() {
        if let Ok(prefix) = parse(&bytes[..end]) {
            assert!(original.tags().iter().any(|tag| tag.range.end == end));
            assert_eq!(prefix.tags().last().map(|tag| tag.range.end), Some(end));
            assert_eq!(prefix.samples().last().and_then(|sample| sample.duration_ms), None);
            for sample in prefix.samples() {
                assert_eq!(sample.source, original.samples()[sample.index].source);
                assert!(sample.source.end < end);
            }
        }
    }
    Ok(())
}

#[test]
fn independent_exact_bounds_and_every_cancellation_checkpoint_are_enforced() -> Test {
    let bytes = source()?;
    let original = parse(&bytes)?;
    let mut calls = 0;
    assert_eq!(FlvVideo::parse_with_checkpoint(&bytes, DemuxLimits::default(), &mut || { calls += 1; Ok(()) })?, original);
    for stop in 1..=calls {
        let mut at = 0;
        assert_eq!(FlvVideo::parse_with_checkpoint(&bytes, DemuxLimits::default(), &mut || {
            at += 1;
            if at == stop { Err(DemuxError::Cancelled) } else { Ok(()) }
        }), Err(DemuxError::Cancelled), "checkpoint {stop}");
    }
    let selected: usize = original.samples().iter().map(|sample| sample.source.len()).sum();
    let nals = original.parameter_sets().len() + original.samples().iter().map(|sample| sample.nals.len()).sum::<usize>();
    let exact = DemuxLimits {
        maximum_input_bytes: bytes.len(), maximum_metadata_bytes: bytes.len() - selected,
        maximum_boxes: original.tags().len(), maximum_samples: original.samples().len(),
        maximum_nals: nals, ..DemuxLimits::default()
    };
    assert_eq!(FlvVideo::parse(&bytes, exact)?, original);
    for limits in [
        DemuxLimits { maximum_input_bytes: exact.maximum_input_bytes - 1, ..exact },
        DemuxLimits { maximum_metadata_bytes: exact.maximum_metadata_bytes - 1, ..exact },
        DemuxLimits { maximum_boxes: exact.maximum_boxes - 1, ..exact },
        DemuxLimits { maximum_samples: exact.maximum_samples - 1, ..exact },
        DemuxLimits { maximum_nals: exact.maximum_nals - 1, ..exact },
        DemuxLimits { maximum_table_entries: 1, ..exact },
    ] {
        assert_eq!(FlvVideo::parse(&bytes, limits), Err(DemuxError::Limit));
    }
    Ok(())
}
