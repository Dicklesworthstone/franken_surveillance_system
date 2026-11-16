#![forbid(unsafe_code)]
//! Real Matroska planner -> native sample driver -> production cache/timing/writer contracts.
//!
//! These exercise the production synchronous implementations with retained laboratory media.
//! They do not qualify retained-source authentication, privacy ownership, the async runtime,
//! filesystem publication or CLI execution. Source and receipt pins remain fixture metadata.

#[path = "../../../fss-reference/src/review_media/render/timing.rs"]
mod movie_timing;

use super::*;
use fss_container::demux::MatroskaVideo;
use fss_container::matroska_gray::TimedGrayMatroskaConfig;
use movie_timing::MovieTiming;

const AVC_MKV: &[u8] = include_bytes!("../fixtures/avc_av.mkv");
const AVC_MP4: &[u8] = include_bytes!("../fixtures/interleaved_av.mp4");
const HEVC_MKV: &[u8] = include_bytes!("../fixtures/hevc_av.mkv");
const AVC_ORACLE: &str = include_str!("../fixtures/indexed_avc_i420.sha256");
const HEVC_ORACLE: &str = include_str!("../fixtures/hevc_av_i420.sha256");

fn matroska_frames(
    parsed: &MatroskaVideo<'_>,
    selection: &MovieSelection,
    mp4_source: &[u8],
) -> Test<(Vec<NativeFrame>, Vec<usize>)> {
    // The laboratory remux retains the same encoded pictures as its MP4 oracle. Check the
    // source ranges independently before feeding the Matroska bytes to the real decoders.
    let mp4 = AvcMp4::parse(mp4_source, None, DemuxLimits::default())?;
    assert_eq!(parsed.codec(), mp4.codec());
    assert_eq!(parsed.samples().len(), mp4.samples().len());
    assert_eq!(parsed.nal_length_bytes(), mp4.nal_length_bytes());
    assert_eq!(parsed.parameter_sets().len(), mp4.parameter_sets().len());
    for (mkv, iso) in parsed.parameter_sets().iter().zip(mp4.parameter_sets()) {
        assert_eq!(parsed.source()[mkv.clone()], mp4_source[iso.clone()]);
    }
    for (mkv, iso) in parsed.samples().iter().zip(mp4.samples()) {
        assert_eq!(
            parsed.source()[mkv.source.clone()],
            mp4_source[iso.source.clone()]
        );
    }
    for span in &selection.decode_spans {
        assert_eq!(
            span.annex_b_bytes,
            mp4.annex_b(span.first_sample, span.sample_count)?
                .bytes()
                .len() as u64
        );
    }
    let ranges: Vec<_> = parsed
        .samples()
        .iter()
        .map(|sample| sample.source.clone())
        .collect();
    native_frames_from_parts(
        parsed.source(),
        parsed.codec(),
        parsed.nal_length_bytes(),
        parsed.parameter_sets(),
        &ranges,
        selection,
    )
}

fn binding(parsed: &MatroskaVideo<'_>) -> SourceBinding {
    SourceBinding {
        track_id: parsed.track_number(),
        ..source(parsed.source(), parsed.codec())
    }
}

fn assert_oracle_prefix(frames: &[NativeFrame], oracle: &str) {
    let expected: Vec<_> = oracle
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_whitespace().nth(2))
        .collect();
    assert!(frames.len() <= expected.len());
    for (frame, expected) in frames.iter().zip(expected) {
        let actual: String = frame
            .i420_sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(actual, expected, "original segment {}", frame.segment);
    }
}

fn assert_pixels(
    complete: &CompleteMovieOutput,
    frames: &[NativeFrame],
    indices: &[usize],
) -> Test {
    assert_eq!(complete.frames(), indices.len());
    assert_eq!(complete.unique_frames(), indices.len());
    assert_eq!(complete.luma_bytes(), indices.len() as u64 * 64 * 48);
    for (ordinal, segment) in indices.iter().enumerate() {
        let expected = frames
            .iter()
            .find(|frame| frame.segment == *segment)
            .ok_or("missing native picture")?;
        let actual = complete
            .frame(ordinal)
            .ok_or("missing presentation occurrence")?;
        assert_eq!(actual.segment, *segment);
        assert_eq!(actual.dimensions, expected.dimensions);
        assert_eq!(actual.pixels(), expected.pixels);
        assert_eq!(
            actual.luma_sha256,
            ContentDigest::sha256(&expected.pixels).bytes()
        );
        assert_eq!(actual.decode_receipt, expected.input().decode_receipt);
    }
    assert!(complete.frame(indices.len()).is_none());
    Ok(())
}

fn assert_timed_stream(
    complete: &CompleteMovieOutput,
    selection: &MovieSelection,
    expected_intervals: &[(u64, u64)],
    duration_ns: u64,
) -> Test {
    let timing = MovieTiming::new(selection, &mut || Ok(()))?;
    assert_eq!(timing.duration_ns(), duration_ns);
    assert_eq!(timing.frames(), complete.frames());
    assert_eq!(timing.frames(), expected_intervals.len());
    let mut encoder = stream::Encoder::<Vec<u8>>::new_movie(
        stream::DEFAULT_OUTPUT_BYTES,
        complete.frames(),
        duration_ns,
        complete.lineage_digest(),
    )?;
    let first = complete.frame(0).ok_or("missing first occurrence")?;
    let config = TimedGrayMatroskaConfig::new(first.dimensions, duration_ns)?;
    let mut expected_bytes = config.initialization()?.bytes().to_vec();
    for (ordinal, &(start, end)) in expected_intervals.iter().enumerate() {
        let interval = timing.frame(ordinal).ok_or("missing timing")?;
        assert_eq!((interval.start_ns, interval.end_ns), (start, end));
        let frame = complete.frame(ordinal).ok_or("missing timed picture")?;
        encoder.frame_at(
            stream::FrameInput {
                dimensions: frame.dimensions,
                pixels: frame.pixels(),
                luma_sha256: frame.luma_sha256,
                decode_receipt: frame.decode_receipt,
            },
            interval.start_ns,
            interval.end_ns,
            || Ok(Vec::new()),
            &mut || Ok(()),
        )?;
        let framing = config.frame(ordinal as u64, start, end)?;
        assert_eq!(framing.timestamp_ns(), start);
        assert_eq!(framing.duration_ns(), end - start);
        expected_bytes.extend_from_slice(framing.prefix());
        expected_bytes.extend_from_slice(frame.pixels());
    }
    let (bytes, receipt) = encoder.finish(&mut || Ok(()))?;
    assert_eq!(bytes, expected_bytes);
    assert_eq!(receipt.frames, complete.frames());
    assert_eq!(receipt.bytes, bytes.len() as u64);
    assert_eq!(receipt.digest, ContentDigest::sha256(&bytes));
    assert_eq!(receipt.duration_ns, duration_ns);
    assert_eq!(
        receipt.last_frame_end_ns,
        expected_intervals.last().ok_or("empty intervals")?.1
    );
    assert_eq!(
        receipt.timing,
        stream::Timing::Movie {
            duration_ns,
            movie_lineage: complete.lineage_digest(),
        }
    );
    Ok(())
}

#[test]
fn reordered_matroska_avc_preserves_native_pixels_and_single_nanosecond_clipping() -> Test {
    let parsed = MatroskaVideo::parse(AVC_MKV, None, DemuxLimits::default())?;
    let selection =
        parsed.select_movie_interval(578_000_001..877_999_999, MovieSelectionLimits::default())?;
    assert_eq!(selection.movie_timescale, 1_000_000_000);
    assert_eq!(selection.media_timescale, 1_000_000_000);
    assert_eq!(
        selection
            .samples
            .iter()
            .map(|row| row.sample_index)
            .collect::<Vec<_>>(),
        [3, 1]
    );
    assert_eq!(selection.decode_spans[0].requested_samples, [1, 3]);
    assert_eq!(selection.decode_spans[0].sample_count, 4);
    let (frames, skipped) = matroska_frames(&parsed, &selection, AVC_MP4)?;
    assert!(skipped.is_empty());
    assert_eq!(
        frames.iter().map(|frame| frame.segment).collect::<Vec<_>>(),
        [0, 2, 3, 1]
    );
    assert_oracle_prefix(&frames, AVC_ORACLE);
    let complete = materialize(&selection, binding(&parsed), &frames)?;
    assert_pixels(&complete, &frames, &[3, 1])?;
    assert_timed_stream(
        &complete,
        &selection,
        &[(0, 149_999_999), (149_999_999, 299_999_998)],
        299_999_998,
    )?;
    Ok(())
}

#[test]
fn initial_idr_matroska_hevc_preserves_native_pixels_and_explicit_timing() -> Test {
    let parsed = MatroskaVideo::parse(HEVC_MKV, None, DemuxLimits::default())?;
    let selection =
        parsed.select_movie_interval(128_000_000..528_000_000, MovieSelectionLimits::default())?;
    assert_eq!(
        selection
            .samples
            .iter()
            .map(|row| row.sample_index)
            .collect::<Vec<_>>(),
        [0, 2]
    );
    assert_eq!(selection.decode_spans[0].requested_samples, [0, 2]);
    assert_eq!(selection.decode_spans[0].sample_count, 3);
    let (frames, skipped) = matroska_frames(&parsed, &selection, HEVC)?;
    assert!(skipped.is_empty());
    assert_eq!(
        frames.iter().map(|frame| frame.segment).collect::<Vec<_>>(),
        [0, 2, 1]
    );
    assert_oracle_prefix(&frames, HEVC_ORACLE);
    let complete = materialize(&selection, binding(&parsed), &frames)?;
    assert_pixels(&complete, &frames, &[0, 2])?;
    assert_timed_stream(
        &complete,
        &selection,
        &[(0, 200_000_000), (200_000_000, 400_000_000)],
        400_000_000,
    )?;
    Ok(())
}

#[test]
fn matroska_avc_preserves_leading_and_trailing_holes_without_synthetic_pictures() -> Test {
    let parsed = MatroskaVideo::parse(AVC_MKV, None, DemuxLimits::default())?;
    let selection =
        parsed.select_movie_interval(0..2_500_000_000, MovieSelectionLimits::default())?;
    let indices = [0, 2, 3, 1, 4, 5, 6, 8, 7, 9];
    assert_eq!(
        selection
            .samples
            .iter()
            .map(|row| row.sample_index)
            .collect::<Vec<_>>(),
        indices
    );
    assert_eq!(selection.gaps.len(), 2);
    assert!(
        selection
            .gaps
            .iter()
            .all(|gap| gap.kind == MovieGapKind::Unrepresented)
    );
    let (frames, skipped) = matroska_frames(&parsed, &selection, AVC_MP4)?;
    assert!(skipped.is_empty());
    assert_eq!(frames.len(), 10);
    assert_oracle_prefix(&frames, AVC_ORACLE);
    let complete = materialize(&selection, binding(&parsed), &frames)?;
    assert_pixels(&complete, &frames, &indices)?;
    let intervals: Vec<_> = (0..10)
        .map(|ordinal| {
            (
                128_000_000 + ordinal * 200_000_000,
                328_000_000 + ordinal * 200_000_000,
            )
        })
        .collect();
    assert_timed_stream(&complete, &selection, &intervals, 2_500_000_000)?;
    Ok(())
}

#[test]
fn matroska_hevc_leading_rasl_decodes_from_the_previous_idr_with_exact_pixels_and_timing() -> Test {
    let parsed = MatroskaVideo::parse(HEVC_MKV, None, DemuxLimits::default())?;
    let selection =
        parsed.select_movie_interval(728_000_000..928_000_000, MovieSelectionLimits::default())?;
    assert_eq!(
        selection
            .samples
            .iter()
            .map(|row| row.sample_index)
            .collect::<Vec<_>>(),
        [5]
    );
    assert_eq!(
        (
            selection.decode_spans[0].first_sample,
            selection.decode_spans[0].sample_count
        ),
        (0, 6)
    );
    let (frames, skipped) = matroska_frames(&parsed, &selection, HEVC)?;
    assert!(skipped.is_empty());
    assert_eq!(
        frames.iter().map(|frame| frame.segment).collect::<Vec<_>>(),
        [0, 2, 1, 5, 4, 3]
    );
    assert_oracle_prefix(&frames, HEVC_ORACLE);
    let complete = materialize(&selection, binding(&parsed), &frames)?;
    assert_pixels(&complete, &frames, &[5])?;
    assert_timed_stream(&complete, &selection, &[(0, 200_000_000)], 200_000_000)?;
    assert_eq!(
        parsed.select_movie_interval(
            728_000_000..928_000_000,
            MovieSelectionLimits {
                max_decode_samples: 5,
                ..MovieSelectionLimits::default()
            }
        ),
        Err(fss_container::demux::DemuxError::Limit)
    );
    Ok(())
}
