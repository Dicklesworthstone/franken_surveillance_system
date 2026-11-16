#![forbid(unsafe_code)]
#![allow(clippy::expect_used)] // exact laboratory fixtures and their synthetic EBML wrappers

use super::super::{
    BLOCK, BLOCK_DURATION, BLOCK_GROUP, CLUSTER, CLUSTER_TIMESTAMP, CODEC_DELAY, CODEC_ID,
    CODEC_PRIVATE, DEFAULT_DURATION, DOC_TYPE, EBML, INFO, PIXEL_HEIGHT, PIXEL_WIDTH,
    REFERENCE_BLOCK, SEEK_PRE_ROLL, SEGMENT, SIMPLE_BLOCK, TIMESTAMP_SCALE, TRACK_ENTRY,
    TRACK_NUMBER, TRACK_TIMESTAMP_SCALE, TRACK_TYPE, TRACKS, VIDEO, header,
};
use super::*;
use crate::demux::{AvcMp4, DemuxLimits};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const AVC: &[u8] = include_bytes!("../../../../tests/fixtures/avc_av.mkv");
const LIVE: &[u8] = include_bytes!("../../../../tests/fixtures/avc_live.mkv");
const HEVC: &[u8] = include_bytes!("../../../../tests/fixtures/hevc_av.mkv");
const AVC_MP4: &[u8] = include_bytes!("../../../../tests/fixtures/interleaved_av.mp4");
const HEVC_MP4: &[u8] = include_bytes!("../../../../tests/fixtures/hevc_av.mp4");

fn parse(bytes: &[u8]) -> Result<MatroskaVideo<'_>, DemuxError> {
    MatroskaVideo::parse(bytes, None, DemuxLimits::default())
}

fn select(video: &MatroskaVideo<'_>, query: Range<u64>) -> Result<MovieSelection, DemuxError> {
    video.select_movie_interval(query, MovieSelectionLimits::default())
}

fn indices(selection: &MovieSelection) -> Vec<usize> {
    selection.samples.iter().map(|s| s.sample_index).collect()
}

fn rows(selection: &MovieSelection) -> usize {
    selection.samples.len()
        + selection.edits.len()
        + selection.gaps.len()
        + selection.decode_spans.len()
        + selection
            .decode_spans
            .iter()
            .map(|s| s.requested_samples.len())
            .sum::<usize>()
}

/// The declared gap/sample intervals partition the query exactly, without rounding or overlap.
fn assert_partition(selection: &MovieSelection) {
    let mut covered: Vec<_> = selection
        .samples
        .iter()
        .map(|s| s.interval)
        .chain(selection.gaps.iter().map(|g| g.interval))
        .collect();
    covered.sort_by_key(|r| r.start_numerator);
    let mut cursor = interval(selection.query.start, selection.query.end).start_numerator;
    for row in covered {
        assert_eq!(row.denominator, NANOS_PER_SECOND);
        assert_eq!(row.start_numerator, cursor);
        assert!(row.start_numerator < row.end_numerator);
        cursor = row.end_numerator;
    }
    assert_eq!(
        cursor,
        interval(selection.query.start, selection.query.end).end_numerator
    );
}

#[test]
fn avc_reordering_selects_whole_original_frames_and_quotes_decode_prerequisites() -> Test {
    let video = parse(AVC)?;
    let mp4 = AvcMp4::parse(AVC_MP4, None, DemuxLimits::default())?;
    assert_eq!(video.default_duration_ns(), Some(200_000_000));
    assert!(
        video
            .samples()
            .iter()
            .all(|s| s.duration_ns == Some(200_000_000))
    );
    assert!(
        video
            .samples()
            .iter()
            .all(|s| s.block_duration_ticks.is_none())
    );
    let selection = select(&video, 528_000_001..927_999_999)?;
    assert_eq!(selection.movie_timescale, NANOS_PER_SECOND);
    assert_eq!(selection.media_timescale, NANOS_PER_SECOND);
    assert_eq!(indices(&selection), [3, 1]);
    assert_eq!(
        selection.samples[0].interval,
        interval(528_000_001, 728_000_000)
    );
    assert_eq!(
        selection.samples[1].interval,
        interval(728_000_000, 927_999_999)
    );
    assert_eq!(
        selection.edits,
        [MovieEditSelection {
            edit_index: None,
            interval: interval(528_000_001, 927_999_999),
            media_time: Some(0),
        }]
    );
    for row in &selection.samples {
        assert_eq!(row.source, video.samples()[row.sample_index].source);
        assert_eq!(
            AVC[row.source.clone()],
            AVC_MP4[mp4.samples()[row.sample_index].source.clone()]
        );
    }
    assert_eq!(selection.decode_spans.len(), 1);
    let span = &selection.decode_spans[0];
    assert_eq!((span.first_sample, span.sample_count), (0, 4));
    assert_eq!(span.requested_samples, [1, 3]);
    assert_eq!(span.annex_b_bytes, mp4.annex_b(0, 4)?.bytes().len() as u64);
    assert!(selection.decode_bytes > selection.sample_bytes);
    assert_partition(&selection);
    Ok(())
}

#[test]
fn avc_and_hevc_full_queries_preserve_gaps_and_repeat_each_span_bootstrap() -> Test {
    for (source, mp4_source) in [(AVC, AVC_MP4), (HEVC, HEVC_MP4)] {
        let video = parse(source)?;
        let mp4 = AvcMp4::parse(mp4_source, None, DemuxLimits::default())?;
        let selection = select(&video, 0..3_000_000_000)?;
        assert_eq!(selection.samples.len(), video.samples().len());
        assert!(!selection.gaps.is_empty());
        assert!(
            selection
                .gaps
                .iter()
                .all(|g| g.kind == MovieGapKind::Unrepresented)
        );
        assert_eq!(selection.decode_spans.len(), 2);
        let mut quoted = 0;
        for span in &selection.decode_spans {
            let first = &video.samples()[span.first_sample];
            assert!(first.keyframe && first.contains_idr);
            let actual = mp4
                .annex_b(span.first_sample, span.sample_count)?
                .bytes()
                .len() as u64;
            assert_eq!(span.annex_b_bytes, actual);
            quoted += actual;
        }
        assert_eq!(quoted, selection.annex_b_bytes);
        assert_partition(&selection);
    }
    Ok(())
}

#[test]
fn outside_the_index_and_exact_half_open_boundaries_have_honest_gaps() -> Test {
    let video = parse(AVC)?;
    for query in [
        0..128_000_000,
        2_128_000_000..3_000_000_000,
        u64::MAX - 1..u64::MAX,
    ] {
        let selection = select(&video, query.clone())?;
        assert!(selection.samples.is_empty());
        assert!(selection.decode_spans.is_empty());
        assert_eq!(
            (
                selection.sample_bytes,
                selection.decode_bytes,
                selection.annex_b_bytes
            ),
            (0, 0, 0)
        );
        assert_eq!(
            selection.gaps,
            [MovieGap {
                interval: interval(query.start, query.end),
                kind: MovieGapKind::Unrepresented,
            }]
        );
        assert_partition(&selection);
    }
    assert_eq!(indices(&select(&video, 328_000_000..528_000_000)?), [2]);
    assert_eq!(select(&video, 8..8), Err(DemuxError::Timeline));
    assert_eq!(
        select(&video, Range { start: 8, end: 7 }),
        Err(DemuxError::Timeline)
    );
    Ok(())
}

/// Tiny deterministic EBML wrappers retain real, parser-validated AVC configuration and NALs.
fn element(id: u32, body: &[u8]) -> Vec<u8> {
    let id = id.to_be_bytes();
    let first = id.iter().position(|b| *b != 0).expect("nonzero EBML ID");
    let mut out = id[first..].to_vec();
    let mut size = (body.len() as u64).to_be_bytes();
    size[0] |= 1; // eight-byte EBML size, no unknown-length sentinel
    out.extend_from_slice(&size);
    out.extend_from_slice(body);
    out
}

fn unsigned(id: u32, value: u64) -> Vec<u8> {
    element(id, &value.to_be_bytes())
}

struct Frame {
    timestamp: i16,
    source_index: usize,
    keyframe: bool,
    group: bool,
    duration: Option<u64>,
    extra: Vec<u8>,
}

fn simple(timestamp: i16, source_index: usize, keyframe: bool) -> Frame {
    Frame {
        timestamp,
        source_index,
        keyframe,
        group: false,
        duration: None,
        extra: Vec::new(),
    }
}

fn group(timestamp: i16, source_index: usize, duration: Option<u64>) -> Frame {
    Frame {
        timestamp,
        source_index,
        keyframe: source_index == 0,
        group: true,
        duration,
        extra: Vec::new(),
    }
}

fn fixture(
    scale: u64,
    default_duration: Option<u64>,
    base: u64,
    extra: &[u8],
    frames: &[Frame],
) -> Test<Vec<u8>> {
    let original = parse(AVC)?;
    let private_at = AVC
        .windows(2)
        .position(|b| b == [0x63, 0xA2])
        .expect("CodecPrivate");
    let (id, private_data, private_size) = header(AVC, private_at, AVC.len())?;
    assert_eq!(id, CODEC_PRIVATE);
    let private = &AVC[private_data..private_data + private_size.expect("known CodecPrivate size")];
    let mut entry = unsigned(TRACK_NUMBER, 1);
    entry.extend(unsigned(TRACK_TYPE, 1));
    entry.extend(element(CODEC_ID, b"V_MPEG4/ISO/AVC"));
    entry.extend(element(CODEC_PRIVATE, private));
    let mut dimensions = unsigned(PIXEL_WIDTH, 64);
    dimensions.extend(unsigned(PIXEL_HEIGHT, 48));
    entry.extend(element(VIDEO, &dimensions));
    if let Some(duration) = default_duration {
        entry.extend(unsigned(DEFAULT_DURATION, duration));
    }
    entry.extend_from_slice(extra);
    let mut cluster = unsigned(CLUSTER_TIMESTAMP, base);
    for frame in frames {
        let mut block = vec![0x81]; // track-number VINT
        block.extend_from_slice(&frame.timestamp.to_be_bytes());
        block.push(if !frame.group && frame.keyframe {
            0x80
        } else {
            0
        });
        block.extend_from_slice(&AVC[original.samples()[frame.source_index].source.clone()]);
        if frame.group {
            let mut body = element(BLOCK, &block);
            if let Some(duration) = frame.duration {
                body.extend(unsigned(BLOCK_DURATION, duration));
            }
            if !frame.keyframe {
                body.extend(element(REFERENCE_BLOCK, &[0xff]));
            }
            body.extend_from_slice(&frame.extra);
            cluster.extend(element(BLOCK_GROUP, &body));
        } else {
            cluster.extend(element(SIMPLE_BLOCK, &block));
        }
    }
    let mut segment = element(INFO, &unsigned(TIMESTAMP_SCALE, scale));
    segment.extend(element(TRACKS, &element(TRACK_ENTRY, &entry)));
    segment.extend(element(CLUSTER, &cluster));
    let mut out = element(EBML, &element(DOC_TYPE, b"matroska"));
    out.extend(element(SEGMENT, &segment));
    Ok(out)
}

#[test]
fn explicit_block_duration_overrides_default_and_nondivisor_scales_remain_exact() -> Test {
    let bytes = fixture(
        3,
        Some(999),
        0,
        &[],
        &[group(0, 0, Some(2)), group(3, 1, Some(1))],
    )?;
    let video = parse(&bytes)?;
    assert_eq!(video.default_duration_ns(), Some(999));
    assert_eq!(video.samples()[0].block_duration_ticks, Some(2));
    assert_eq!(video.samples()[0].duration_ns, Some(6));
    assert_eq!(video.samples()[1].duration_ns, Some(3));
    let selection = select(&video, 1..11)?;
    assert_eq!(indices(&selection), [0, 1]);
    assert_eq!(selection.samples[0].interval, interval(1, 6));
    assert_eq!(selection.samples[1].interval, interval(9, 11));
    assert_eq!(
        selection.gaps,
        [MovieGap {
            interval: interval(6, 9),
            kind: MovieGapKind::Unrepresented
        }]
    );
    assert_partition(&selection);
    Ok(())
}

#[test]
fn explicit_gaps_are_never_filled_using_the_next_timestamp() -> Test {
    let bytes = fixture(
        1,
        Some(10),
        0,
        &[],
        &[simple(0, 0, true), simple(30, 1, false)],
    )?;
    let video = parse(&bytes)?;
    let selection = select(&video, 0..50)?;
    assert_eq!(selection.samples[0].interval, interval(0, 10));
    assert_eq!(selection.samples[1].interval, interval(30, 40));
    assert_eq!(
        selection
            .gaps
            .iter()
            .map(|g| g.interval)
            .collect::<Vec<_>>(),
        [interval(10, 30), interval(40, 50)]
    );
    assert_eq!(selection.decode_spans[0].sample_count, 2);
    assert_partition(&selection);
    Ok(())
}

#[test]
fn unknown_duration_is_unsupported_even_when_a_later_timestamp_exists() -> Test {
    for (default_duration, frames) in [
        (None, vec![simple(0, 0, true), simple(30, 1, false)]),
        (Some(10), vec![group(0, 0, None)]),
        (None, vec![group(0, 0, None)]),
    ] {
        let bytes = fixture(1, default_duration, 0, &[], &frames)?;
        let video = parse(&bytes)?; // ordinal import remains available
        assert!(video.samples().iter().any(|s| s.duration_ns.is_none()));
        assert_eq!(select(&video, 0..100), Err(DemuxError::Unsupported));
    }
    Ok(())
}

#[test]
fn negative_presentations_are_decode_only_even_when_their_duration_crosses_zero() -> Test {
    let bytes = fixture(
        1,
        Some(20),
        0,
        &[],
        &[simple(-10, 0, true), simple(0, 1, false)],
    )?;
    let video = parse(&bytes)?;
    assert_eq!(video.samples()[0].timestamp, -10);
    let selection = select(&video, 0..20)?;
    assert_eq!(indices(&selection), [1]);
    assert_eq!(selection.decode_spans[0].requested_samples, [1]);
    assert_eq!(
        (
            selection.decode_spans[0].first_sample,
            selection.decode_spans[0].sample_count
        ),
        (0, 2)
    );
    assert_partition(&selection);
    Ok(())
}

#[test]
fn zero_overlap_duplicate_and_overflowing_durations_refuse_without_partial_reports() -> Test {
    for (scale, base, frames) in [
        (1, 0, vec![group(0, 0, Some(0))]),
        (1, 0, vec![group(0, 0, Some(10)), group(9, 1, Some(10))]),
        (1, 0, vec![group(0, 0, Some(10)), group(0, 1, Some(10))]),
        (u64::MAX, 0, vec![group(0, 0, Some(u64::MAX))]),
        (u64::MAX, i64::MAX as u64, vec![group(0, 0, Some(2))]),
    ] {
        let bytes = fixture(scale, None, base, &[], &frames)?;
        let video = parse(&bytes)?;
        assert_eq!(select(&video, 0..100), Err(DemuxError::Timeline));
    }
    let bytes = fixture(1, Some(0), 0, &[], &[simple(0, 0, true)])?;
    assert_eq!(select(&parse(&bytes)?, 0..100), Err(DemuxError::Timeline));
    let mut duplicate = group(0, 0, Some(1));
    duplicate.extra = unsigned(BLOCK_DURATION, 2);
    let bytes = fixture(1, None, 0, &[], &[duplicate])?;
    assert_eq!(
        select(&parse(&bytes)?, 0..100),
        Err(DemuxError::Unsupported)
    );
    Ok(())
}

#[test]
fn unimplemented_timing_transforms_refuse_selection_but_keep_ordinal_samples() -> Test {
    for extra in [
        element(TRACK_TIMESTAMP_SCALE, &2.0_f64.to_be_bytes()),
        unsigned(CODEC_DELAY, 1),
        unsigned(SEEK_PRE_ROLL, 1),
        element(0x537F, &[1]),
    ] {
        let bytes = fixture(1, Some(10), 0, &extra, &[simple(0, 0, true)])?;
        let video = parse(&bytes)?;
        assert_eq!(video.samples().len(), 1);
        assert_eq!(select(&video, 0..10), Err(DemuxError::Unsupported));
    }
    for id in [0x75A2, 0x75A1] {
        let mut frame = group(0, 0, Some(10));
        frame.extra = element(id, &[0]);
        let bytes = fixture(1, None, 0, &[], &[frame])?;
        let video = parse(&bytes)?;
        assert!(video.samples()[0].timeline_unsupported);
        assert_eq!(select(&video, 0..10), Err(DemuxError::Unsupported));
    }
    for unit in [
        1.0_f32.to_be_bytes().to_vec(),
        1.0_f64.to_be_bytes().to_vec(),
    ] {
        let mut extra = element(TRACK_TIMESTAMP_SCALE, &unit);
        extra.extend(unsigned(CODEC_DELAY, 0));
        extra.extend(unsigned(SEEK_PRE_ROLL, 0));
        extra.extend(element(0x537F, &[0]));
        let bytes = fixture(1, Some(10), 0, &extra, &[simple(0, 0, true)])?;
        assert_eq!(indices(&select(&parse(&bytes)?, 0..10)?), [0]);
    }
    Ok(())
}

#[test]
fn ambiguous_or_malformed_optional_timing_keeps_ordinal_import_admission() -> Test {
    for extra in [
        unsigned(DEFAULT_DURATION, 10), // duplicates the fixture's declared default
        element(DEFAULT_DURATION, &[0; 9]),
        element(CODEC_DELAY, &[0; 9]),
        element(SEEK_PRE_ROLL, &[0; 9]),
        element(TRACK_TIMESTAMP_SCALE, &[1]),
    ] {
        let bytes = fixture(1, Some(10), 0, &extra, &[simple(0, 0, true)])?;
        let video = parse(&bytes)?;
        assert_eq!(video.samples().len(), 1);
        assert_eq!(select(&video, 0..10), Err(DemuxError::Unsupported));
    }
    let mut frame = group(0, 0, None);
    frame.extra = element(BLOCK_DURATION, &[0; 9]);
    let bytes = fixture(1, None, 0, &[], &[frame])?;
    let video = parse(&bytes)?;
    assert_eq!(video.samples()[0].duration_ns, None);
    assert_eq!(select(&video, 0..10), Err(DemuxError::Unsupported));
    Ok(())
}

#[test]
fn bootstrap_requires_both_container_keyframe_and_random_access_nal() -> Test {
    for frame in [simple(0, 0, false), simple(0, 1, true)] {
        let bytes = fixture(1, Some(10), 0, &[], &[frame])?;
        let video = parse(&bytes)?;
        assert_eq!(select(&video, 0..10), Err(DemuxError::RandomAccessRequired));
        assert!(select(&video, 10..20)?.samples.is_empty());
    }
    Ok(())
}

#[test]
fn exact_limits_succeed_and_one_less_refuses_including_decode_preroll() -> Test {
    let video = parse(AVC)?;
    let query = 528_000_000..928_000_000;
    let selection = select(&video, query.clone())?;
    let exact = MovieSelectionLimits {
        max_work: selection.work,
        max_rows: rows(&selection),
        max_decode_samples: selection.decode_spans.iter().map(|s| s.sample_count).sum(),
        max_source_bytes: selection.decode_bytes,
        max_annex_b_bytes: selection.annex_b_bytes,
    };
    assert_eq!(
        video.select_movie_interval(query.clone(), exact)?,
        selection
    );
    for tight in [
        MovieSelectionLimits {
            max_work: exact.max_work - 1,
            ..exact
        },
        MovieSelectionLimits {
            max_rows: exact.max_rows - 1,
            ..exact
        },
        MovieSelectionLimits {
            max_decode_samples: exact.max_decode_samples - 1,
            ..exact
        },
        MovieSelectionLimits {
            max_source_bytes: exact.max_source_bytes - 1,
            ..exact
        },
        MovieSelectionLimits {
            max_annex_b_bytes: exact.max_annex_b_bytes - 1,
            ..exact
        },
    ] {
        assert_eq!(
            video.select_movie_interval(query.clone(), tight),
            Err(DemuxError::Limit)
        );
    }
    assert_eq!(
        video.select_movie_interval(
            query,
            MovieSelectionLimits {
                max_decode_samples: selection.samples.len(),
                ..MovieSelectionLimits::default()
            }
        ),
        Err(DemuxError::Limit)
    );
    Ok(())
}

#[test]
fn original_output_ceiling_and_aggregate_span_quotes_remain_authoritative() -> Test {
    let video = MatroskaVideo::parse(
        AVC,
        None,
        DemuxLimits {
            maximum_output_bytes: 1,
            ..DemuxLimits::default()
        },
    )?;
    assert_eq!(select(&video, 0..3_000_000_000), Err(DemuxError::Limit));

    let video = parse(AVC)?;
    let selection = select(&video, 0..3_000_000_000)?;
    assert_eq!(selection.decode_spans.len(), 2);
    assert!(
        selection
            .decode_spans
            .iter()
            .all(|s| s.annex_b_bytes < selection.annex_b_bytes - 1)
    );
    assert_eq!(
        video.select_movie_interval(
            0..3_000_000_000,
            MovieSelectionLimits {
                max_annex_b_bytes: selection.annex_b_bytes - 1,
                ..MovieSelectionLimits::default()
            }
        ),
        Err(DemuxError::Limit)
    );
    Ok(())
}

#[test]
fn every_work_boundary_is_cancellable_including_sort_and_nal_quote() -> Test {
    let video = parse(AVC)?;
    let mut calls = 0;
    video.select_movie_interval_with_checkpoint(
        0..3_000_000_000,
        MovieSelectionLimits::default(),
        &mut || {
            calls += 1;
            Ok(())
        },
    )?;
    for cancel_at in 1..=calls {
        let mut at = 0;
        assert_eq!(
            video.select_movie_interval_with_checkpoint(
                0..3_000_000_000,
                MovieSelectionLimits::default(),
                &mut || {
                    at += 1;
                    if at == cancel_at {
                        Err(DemuxError::Cancelled)
                    } else {
                        Ok(())
                    }
                }
            ),
            Err(DemuxError::Cancelled),
            "checkpoint {cancel_at}"
        );
    }
    Ok(())
}

#[test]
fn unfinished_live_file_selects_only_its_complete_prefix_and_preserves_tail_gap() -> Test {
    let full = parse(LIVE)?;
    let last = full.samples().last().expect("fixture frame");
    let cut = last.source.start + last.source.len() / 2;
    let video = MatroskaVideo::parse_recovering_tail(
        &LIVE[..cut],
        None,
        DemuxLimits::default(),
        &mut || Ok(()),
    )?;
    assert!(video.truncated_tail().is_some());
    assert!(video.samples().len() < full.samples().len());
    let selection = select(&video, 0..3_000_000_000)?;
    assert_eq!(selection.samples.len(), video.samples().len());
    let last_presentation_end = selection
        .samples
        .last()
        .expect("presented prefix")
        .interval
        .end_numerator;
    assert_eq!(
        selection
            .gaps
            .last()
            .expect("tail gap")
            .interval
            .start_numerator,
        last_presentation_end
    );
    assert_partition(&selection);
    Ok(())
}
