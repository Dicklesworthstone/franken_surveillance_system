#![forbid(unsafe_code)]
#![allow(clippy::expect_used)] // bounded checked-in fixture construction
use super::*;
use crate::demux::{AvcMp4, DemuxLimits, VideoCodec};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const AVC: &[u8] = include_bytes!("../../../../tests/fixtures/avc_av.mkv");
const HEVC: &[u8] = include_bytes!("../../../../tests/fixtures/hevc_av.mkv");
const MP4: &[u8] = include_bytes!("../../../../tests/fixtures/interleaved_av.mp4");
const NS: u64 = 1_000_000;

fn parse(bytes: &[u8]) -> Result<MatroskaVideo<'_>, DemuxError> {
    MatroskaVideo::parse(bytes, None, DemuxLimits::default())
}
fn select(video: &MatroskaVideo<'_>, query: Range<u64>) -> Result<MatroskaSelection, DemuxError> {
    video.select_presentation_interval(query, MatroskaSelectionLimits::default())
}
fn element(id: u32, body: &[u8]) -> Vec<u8> {
    let raw = id.to_be_bytes();
    let first = raw.iter().position(|b| *b != 0).expect("nonzero ID");
    let mut bytes = raw[first..].to_vec();
    let width = (1..=8)
        .find(|width| (body.len() as u64) < (1_u64 << (width * 7)) - 1)
        .expect("bounded size");
    let size = (body.len() as u64) | (1_u64 << (width * 7));
    bytes.extend_from_slice(&size.to_be_bytes()[8 - width..]);
    bytes.extend_from_slice(body);
    bytes
}
fn uint(id: u32, value: u64) -> Vec<u8> {
    element(id, &value.to_be_bytes())
}
/// Synthetic EBML structure around a real checked-in AVC IDR/configuration, with independently
/// controlled container timings. No external media runtime or fabricated NAL is used.
fn source(timings: &[(i16, Option<u64>)], track_fields: &[u8], group: bool) -> Test<Vec<u8>> {
    let mp4 = AvcMp4::parse(MP4, None, DemuxLimits::default())?;
    let mut track = uint(0xD7, 1);
    track.extend(uint(0x83, 1));
    track.extend(element(0x86, b"V_MPEG4/ISO/AVC"));
    track.extend(element(0x63A2, &MP4[mp4.configuration_record()]));
    let mut video = uint(0xB0, 64);
    video.extend(uint(0xBA, 48));
    track.extend(element(0xE0, &video));
    track.extend_from_slice(track_fields);
    let mut segment = element(0x1549_A966, &uint(0x2A_D7B1, NS));
    segment.extend(element(0x1654_AE6B, &element(0xAE, &track)));
    let mut cluster = uint(0xE7, 100);
    for &(offset, duration) in timings {
        let mut block = vec![0x81];
        block.extend_from_slice(&offset.to_be_bytes());
        block.push(if group { 0 } else { 0x80 });
        block.extend_from_slice(&MP4[mp4.samples()[0].source.clone()]);
        if group {
            let mut body = element(0xA1, &block);
            if let Some(duration) = duration {
                body.extend(uint(BLOCK_DURATION, duration));
            }
            cluster.extend(element(0xA0, &body));
        } else {
            cluster.extend(element(0xA3, &block));
        }
    }
    segment.extend(element(0x1F43_B675, &cluster));
    let mut bytes = element(0x1A45_DFA3, &element(0x4282, b"matroska"));
    bytes.extend(element(0x1853_8067, &segment));
    Ok(bytes)
}

#[test]
fn real_b_frames_select_in_display_order_and_quote_coding_preroll() -> Test {
    let video = parse(AVC)?;
    let result = select(&video, 300 * NS..800 * NS)?;
    assert_eq!(
        result
            .samples
            .iter()
            .map(|s| s.sample_index)
            .collect::<Vec<_>>(),
        [0, 2, 3, 1]
    );
    assert_eq!(result.samples[0].interval_ns, 300 * NS..328 * NS);
    assert_eq!(result.samples[3].interval_ns, 728 * NS..800 * NS);
    assert_eq!(result.decode_spans.len(), 1);
    assert_eq!(result.decode_spans[0].first_sample, 0);
    assert_eq!(result.decode_spans[0].sample_count, 4);
    assert_eq!(result.decode_spans[0].requested_samples, [0, 1, 2, 3]);
    assert!(result.gaps_ns.is_empty());
    assert!(result.unresolved_ns.is_empty());
    for sample in &result.samples {
        assert_eq!(
            sample.duration_source,
            MatroskaDurationSource::DefaultDuration
        );
        assert_eq!(
            sample.presentation_end_ns,
            Some(sample.presentation_start_ns + 200 * i128::from(NS))
        );
        assert_eq!(sample.source, video.samples()[sample.sample_index].source);
    }
    Ok(())
}

#[test]
fn real_hevc_and_a_later_avc_gop_keep_their_random_access_start() -> Test {
    let hevc = parse(HEVC)?;
    assert_eq!(hevc.codec(), VideoCodec::Hevc);
    assert!(!select(&hevc, 0..u64::MAX)?.samples.is_empty());
    let avc = parse(AVC)?;
    let selected = select(&avc, 1500 * NS..1600 * NS)?;
    assert_eq!(
        selected
            .samples
            .iter()
            .map(|s| s.sample_index)
            .collect::<Vec<_>>(),
        [6, 8]
    );
    assert_eq!(selected.decode_spans[0].first_sample, 5);
    assert_eq!(selected.decode_spans[0].sample_count, 4);
    assert_eq!(selected.decode_spans[0].requested_samples, [6, 8]);
    Ok(())
}

#[test]
fn block_durations_are_scaled_ticks_and_override_nanosecond_defaults() -> Test {
    let bytes = source(
        &[(0, Some(25)), (100, Some(50))],
        &uint(DEFAULT_DURATION, 999),
        true,
    )?;
    let video = parse(&bytes)?;
    let selected = select(&video, 100 * NS..300 * NS)?;
    assert_eq!(selected.samples.len(), 2);
    assert_eq!(selected.samples[0].interval_ns, 100 * NS..125 * NS);
    assert_eq!(selected.samples[1].interval_ns, 200 * NS..250 * NS);
    assert_eq!(selected.gaps_ns, [125 * NS..200 * NS, 250 * NS..300 * NS]);
    assert!(
        selected
            .samples
            .iter()
            .all(|s| s.duration_source == MatroskaDurationSource::BlockDuration)
    );
    Ok(())
}

#[test]
fn implicit_duration_uses_next_display_timestamp_and_never_invents_the_final_end() -> Test {
    let bytes = source(&[(0, None), (200, None), (100, None)], &[], false)?;
    let video = parse(&bytes)?;
    let selected = select(&video, 50 * NS..400 * NS)?;
    assert_eq!(
        selected
            .samples
            .iter()
            .map(|s| s.sample_index)
            .collect::<Vec<_>>(),
        [0, 2, 1]
    );
    assert_eq!(
        selected.samples[0].presentation_end_ns,
        Some(200 * i128::from(NS))
    );
    assert_eq!(
        selected.samples[1].presentation_end_ns,
        Some(300 * i128::from(NS))
    );
    assert_eq!(selected.samples[2].presentation_end_ns, None);
    assert_eq!(selected.gaps_ns, vec![50 * NS..100 * NS]);
    assert_eq!(selected.unresolved_ns, vec![300 * NS..400 * NS]);
    let later = select(&video, 800 * NS..900 * NS)?;
    assert_eq!(later.samples.len(), 1);
    assert_eq!(later.samples[0].sample_index, 1);
    assert_eq!(
        later.samples[0].duration_source,
        MatroskaDurationSource::Unknown
    );
    assert_eq!(later.unresolved_ns, vec![800 * NS..900 * NS]);
    assert!(later.gaps_ns.is_empty());
    Ok(())
}

#[test]
fn codec_delay_negative_presentations_are_preroll_only() -> Test {
    let mut fields = uint(DEFAULT_DURATION, 100 * NS);
    fields.extend(uint(CODEC_DELAY, 150 * NS));
    let bytes = source(&[(0, None), (100, None)], &fields, false)?;
    let mut video = parse(&bytes)?;
    // The second picture is not independently decodable; negative first picture remains a
    // required coding prerequisite even though its presentation must not be displayed.
    video.samples[1].keyframe = false;
    let selected = select(&video, 0..100 * NS)?;
    assert_eq!(selected.samples.len(), 1);
    assert_eq!(selected.samples[0].sample_index, 1);
    assert_eq!(
        selected.samples[0].presentation_start_ns,
        50 * i128::from(NS)
    );
    assert_eq!(selected.gaps_ns, vec![0..50 * NS]);
    assert_eq!(selected.decode_spans[0].first_sample, 0);
    assert_eq!(selected.decode_spans[0].sample_count, 2);
    Ok(())
}

#[test]
fn unsupported_temporal_metadata_does_not_change_byte_import_admission() -> Test {
    let cases = [
        element(TRACK_TIMESTAMP_SCALE, &2_f64.to_be_bytes()),
        uint(TRACK_OFFSET, 1),
        uint(SEEK_PRE_ROLL, 1),
        uint(DEFAULT_DURATION, 0),
        [uint(CODEC_DELAY, 0), uint(CODEC_DELAY, 1)].concat(),
    ];
    for fields in cases {
        let bytes = source(&[(0, None)], &fields, false)?;
        let video = parse(&bytes)?;
        assert_eq!(video.samples().len(), 1);
        assert_eq!(select(&video, 0..500 * NS), Err(DemuxError::Timeline));
    }
    let bytes = source(&[(0, None)], &uint(DEFAULT_DURATION, NS), true)?;
    assert_eq!(
        select(&parse(&bytes)?, 0..500 * NS),
        Err(DemuxError::Timeline)
    );
    let duplicate = source(&[(0, None), (0, None)], &[], false)?;
    assert_eq!(
        select(&parse(&duplicate)?, 0..500 * NS),
        Err(DemuxError::Timeline)
    );
    Ok(())
}

#[test]
fn aggregate_limits_include_preroll_and_have_exact_boundaries() -> Test {
    let video = parse(AVC)?;
    let query = 1500 * NS..1600 * NS;
    let selected = select(&video, query.clone())?;
    let rows = selected.samples.len()
        + selected.gaps_ns.len()
        + selected.unresolved_ns.len()
        + selected.decode_spans.len()
        + selected
            .decode_spans
            .iter()
            .map(|s| s.requested_samples.len())
            .sum::<usize>();
    let limits = MatroskaSelectionLimits {
        max_work: selected.work,
        max_rows: rows,
        max_decode_samples: 4,
        max_source_bytes: selected.decode_bytes,
    };
    assert_eq!(
        video.select_presentation_interval(query.clone(), limits)?,
        selected
    );
    for field in 0..4 {
        let mut limited = limits;
        match field {
            0 => limited.max_work -= 1,
            1 => limited.max_rows -= 1,
            2 => limited.max_decode_samples -= 1,
            _ => limited.max_source_bytes -= 1,
        }
        assert_eq!(
            video.select_presentation_interval(query.clone(), limited),
            Err(DemuxError::Limit)
        );
    }
    assert!(selected.decode_bytes > selected.sample_bytes);
    Ok(())
}

#[test]
fn cancellation_and_missing_bootstrap_never_release_partial_selection() -> Test {
    let mut video = parse(AVC)?;
    for stop in [1, 8, 30] {
        let mut calls = 0;
        let result = video.select_presentation_interval_with_checkpoint(
            0..u64::MAX,
            MatroskaSelectionLimits::default(),
            &mut || {
                calls += 1;
                if calls == stop {
                    Err(DemuxError::Cancelled)
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result, Err(DemuxError::Cancelled));
    }
    video.samples[0].contains_idr = false;
    assert_eq!(
        select(&video, 200 * NS..250 * NS),
        Err(DemuxError::RandomAccessRequired)
    );
    assert_eq!(select(&video, 3..3), Err(DemuxError::Timeline));
    Ok(())
}

#[test]
fn hevc_leading_rasl_keeps_the_idr_before_its_cra_and_refuses_without_it() -> Test {
    let mut video = parse(HEVC)?;
    // The real fixture's sample3 is a CRA at1128ms; sample5 is leading RASL at728ms.
    // Decoding from CRA would suppress that picture and omit previous-GOP references.
    let selected = select(&video, 728 * NS..800 * NS)?;
    assert_eq!(
        selected
            .samples
            .iter()
            .map(|s| s.sample_index)
            .collect::<Vec<_>>(),
        [5]
    );
    assert_eq!(selected.decode_spans.len(), 1);
    assert_eq!(selected.decode_spans[0].first_sample, 0);
    assert_eq!(selected.decode_spans[0].sample_count, 6);
    assert_eq!(selected.decode_spans[0].requested_samples, [5]);
    video.samples[0].keyframe = false;
    assert_eq!(
        select(&video, 728 * NS..800 * NS),
        Err(DemuxError::RandomAccessRequired)
    );
    Ok(())
}

#[test]
fn hevc_bla_breaks_the_earlier_idr_dependency_even_with_retained_bytes() -> Test {
    let original = parse(HEVC)?;
    let sample = &original.samples()[3];
    let cluster = original
        .elements()
        .iter()
        .find(|element| element.range.contains(&sample.source.start))
        .expect("frame cluster");
    let mut bytes = HEVC.to_vec();
    let mut at = sample.source.start;
    let mut changed = false;
    while at < sample.source.end {
        let data = at + original.nal_length_bytes();
        let length = bytes[at..data]
            .iter()
            .fold(0_usize, |value, byte| (value << 8) | usize::from(*byte));
        if (bytes[data] >> 1) & 0x3f == 21 {
            bytes[data] = (bytes[data] & 0x81) | (16 << 1);
            changed = true;
            break;
        }
        at = data + length;
    }
    assert!(changed, "fixture sample contains CRA");
    // Reseal only the changed Cluster so the test reaches temporal dependency admission.
    let (_, body, size) = super::super::header(&bytes, cluster.range.start, bytes.len())?;
    assert_eq!(&bytes[body..body + 2], &[0xBF, 0x84]);
    let end = body + size.expect("known-size fixture cluster");
    let crc = !super::super::crc32_update(!0, &bytes[body + 6..end]);
    bytes[body + 2..body + 6].copy_from_slice(&crc.to_le_bytes());
    let video = parse(&bytes)?;
    assert_eq!(
        select(&video, 728 * NS..800 * NS),
        Err(DemuxError::RandomAccessRequired)
    );
    // The earlier GOP remains independently selectable.
    assert!(!select(&video, 128 * NS..200 * NS)?.samples.is_empty());
    Ok(())
}
