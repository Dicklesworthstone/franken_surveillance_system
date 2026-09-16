#![forbid(unsafe_code)]
//! Deterministic layout, explicit time, byte provenance, and transactional refusal.
mod common;

use common::{Error, KEY, BASELINE, HIGH, groups, timed};
use fss_container::{AvcMuxer, Mp4Error, Mp4Limits, NalTarget};
use fss_packet::StreamKey;
use fss_packet::avc::AvcPictureGroup;

type TestResult = Result<(), Error>;
fn mux(group: &AvcPictureGroup, limits: Mp4Limits) -> Result<AvcMuxer, Mp4Error> {
    AvcMuxer::new(group.key(), group.sps().clone(), group.pps().clone(), 90_000, limits)
}

fn fixture(data: &[u8], pts: &[u64], init: &[u8], prefix: &[u8]) -> TestResult {
    let pictures = groups(data, KEY, true, false)?;
    let mut writer = mux(&pictures[0], Mp4Limits::default())?;
    assert_eq!(writer.initialization().bytes(), init);
    let fragment = writer.fragment(&timed(&pictures, pts))?;
    assert_eq!(&fragment.bytes()[..prefix.len()], prefix);
    assert_eq!(fragment.samples().len(), pts.len());
    for (i, sample) in fragment.samples().iter().enumerate() {
        assert_eq!(sample.decode_time, i as u64 * 3600);
        assert_eq!(sample.presentation_time, pts[i]);
        assert_eq!(sample.duration, 3600);
        let mut at = sample.range.start;
        for mapping in &fragment.mappings()[sample.mappings.clone()] {
            let nal = &pictures[mapping.sample].nals()[mapping.nal];
            assert_eq!(mapping.sources, nal.sources());
            match &mapping.target {
                NalTarget::Initialization(range) => {
                    assert!(matches!(nal.nal_type(), 7 | 8));
                    assert_eq!(&init[range.clone()], nal.bytes());
                }
                NalTarget::Media(range) => {
                    assert_eq!(range.start, at + 4);
                    assert_eq!(&fragment.bytes()[at..at + 4], &(nal.bytes().len() as u32).to_be_bytes());
                    assert_eq!(&fragment.bytes()[range.clone()], nal.bytes());
                    at = range.end;
                }
            }
        }
        assert_eq!(at, sample.range.end);
    }
    assert_eq!(fragment.sequence(), 1);
    assert_eq!(writer.next_sequence(), Some(2));
    assert!(fragment.timeline_gap().is_none());
    Ok(())
}

#[test]
fn baseline_matches_independent_layout_oracle_and_every_source_byte() -> TestResult {
    fixture(BASELINE, &[0, 3600, 7200, 10800], include_bytes!("fixtures/baseline_init.bin"),
        include_bytes!("fixtures/baseline_prefix.bin"))
}
#[test]
fn high_b_pictures_keep_exact_signed_composition_offsets_and_cropping() -> TestResult {
    fixture(HIGH, &[0, 10800, 3600, 7200, 18000, 14400], include_bytes!("fixtures/high_cropped_init.bin"),
        include_bytes!("fixtures/high_cropped_prefix.bin"))
}
#[test]
fn same_inputs_produce_identical_fragments_and_receipts() -> TestResult {
    let p = groups(BASELINE, KEY, true, false)?; let t = timed(&p, &[0, 3600, 7200, 10800]);
    let mut a = mux(&p[0], Mp4Limits::default())?; let mut b = mux(&p[0], Mp4Limits::default())?;
    assert_eq!(a.fragment(&t)?, b.fragment(&t)?);
    Ok(())
}
#[test]
fn refusal_never_consumes_fragment_number_timeline_or_source_cursor() -> TestResult {
    let p = groups(BASELINE, KEY, true, false)?; let good = timed(&p, &[0, 3600, 7200, 10800]);
    let mut m = mux(&p[0], Mp4Limits::default())?;
    for (index, decode_time, duration, offset) in [
        (0, 0, 0, 0), (1, 3601, 3600, 0), (0, 0, 3600, -1),
        (0, u64::MAX, 1, 0), (0, u64::MAX - 3600, 3600, i32::MAX),
    ] {
        let mut bad = good.clone(); bad[index].decode_time = decode_time;
        bad[index].duration = duration; bad[index].composition_offset = offset;
        assert_eq!(m.fragment(&bad), Err(Mp4Error::Timeline));
        assert_eq!(m.next_sequence(), Some(1));
    }
    assert_eq!(m.fragment(&good)?.sequence(), 1);
    Ok(())
}
#[test]
fn all_count_and_byte_limits_fail_before_state_change() -> TestResult {
    let p = groups(BASELINE, KEY, true, false)?; let t = timed(&p, &[0, 3600, 7200, 10800]);
    for limits in [
        Mp4Limits { max_samples: 1, ..Mp4Limits::default() },
        Mp4Limits { max_nals: 1, ..Mp4Limits::default() },
        Mp4Limits { max_source_spans: 1, ..Mp4Limits::default() },
        Mp4Limits { max_fragment_bytes: 8, ..Mp4Limits::default() },
    ] {
        let mut m = mux(&p[0], limits)?;
        assert_eq!(m.fragment(&t), Err(Mp4Error::Limit)); assert_eq!(m.next_sequence(), Some(1));
    }
    assert!(matches!(mux(&p[0], Mp4Limits { max_initialization_bytes: 8, ..Mp4Limits::default() }), Err(Mp4Error::Limit)));
    Ok(())
}
#[test]
fn non_idr_start_unverified_tail_and_discontinuity_are_not_playability_claims() -> TestResult {
    let p = groups(BASELINE, KEY, true, false)?; let mut m = mux(&p[0], Mp4Limits::default())?;
    assert_eq!(m.fragment(&timed(&p[1..], &[0, 3600, 7200])), Err(Mp4Error::RandomAccessRequired));
    let unmarked = groups(BASELINE, KEY, false, false)?;
    assert_eq!(m.fragment(&timed(&unmarked, &[0, 3600, 7200, 10800])), Err(Mp4Error::UnverifiedPicture));
    let interrupted = groups(BASELINE, KEY, true, true)?;
    assert_eq!(m.fragment(&timed(&interrupted, &[0, 3600, 7200, 10800])), Err(Mp4Error::Discontinuity));
    assert_eq!(m.next_sequence(), Some(1));
    Ok(())
}
#[test]
fn fragments_start_at_idr_and_timeline_gaps_are_explicit_not_filled() -> TestResult {
    let p = groups(BASELINE, KEY, true, false)?; let mut m = mux(&p[0], Mp4Limits::default())?;
    let first = m.fragment(&timed(&p[..3], &[0, 3600, 7200]))?;
    assert_eq!(first.sequence(), 1);
    let mut second = timed(&p[3..], &[18000]); second[0].decode_time = 18_000; second[0].composition_offset = 0;
    let last = m.fragment(&second)?;
    assert_eq!(last.sequence(), 2); assert_eq!(last.timeline_gap(), Some(10_800..18_000));
    assert_eq!(last.samples().len(), 1);
    Ok(())
}
#[test]
fn advancing_timestamps_cannot_replay_the_same_source() -> TestResult {
    let p = groups(BASELINE, KEY, true, false)?; let mut m = mux(&p[0], Mp4Limits::default())?;
    let mut t = timed(&p, &[0, 3600, 7200, 10800]); m.fragment(&t)?;
    for sample in &mut t { sample.decode_time += 14_400; }
    assert_eq!(m.fragment(&t), Err(Mp4Error::SourceOrder));
    assert_eq!(m.next_sequence(), Some(2));
    Ok(())
}
#[test]
fn wrong_epoch_or_exact_parameters_cannot_join_a_movie_track() -> TestResult {
    let p = groups(BASELINE, KEY, true, false)?; let mut m = mux(&p[0], Mp4Limits::default())?;
    let other = groups(BASELINE, StreamKey { generation: 2, ..KEY }, true, false)?;
    assert_eq!(m.fragment(&timed(&other, &[0, 3600, 7200, 10800])), Err(Mp4Error::StreamMismatch));
    let high = groups(HIGH, KEY, true, false)?;
    assert_eq!(m.fragment(&timed(&high, &[0, 10800, 3600, 7200, 18000, 14400])), Err(Mp4Error::ParameterSet));
    Ok(())
}
#[test]
fn track_identity_and_time_scale_must_be_explicit() -> TestResult {
    let p = groups(BASELINE, KEY, true, false)?;
    for (key, scale) in [(StreamKey { ingress: 0, ..KEY }, 90000), (StreamKey { generation: 0, ..KEY }, 90000), (KEY, 0)] {
        assert!(matches!(AvcMuxer::new(key, p[0].sps().clone(), p[0].pps().clone(), scale, Mp4Limits::default()), Err(Mp4Error::Configuration)));
    }
    assert_eq!(Mp4Limits { max_samples: 4097, ..Mp4Limits::default() }.validate(), Err(Mp4Error::Configuration));
    Ok(())
}
#[test]
fn debug_views_expose_counts_not_media() -> TestResult {
    let p = groups(BASELINE, KEY, true, false)?; let mut m = mux(&p[0], Mp4Limits::default())?;
    let f = m.fragment(&timed(&p, &[0, 3600, 7200, 10800]))?;
    for text in [format!("{m:?}"), format!("{:?}", m.initialization()), format!("{f:?}")] {
        assert!(text.len() < 500); assert!(!text.contains("[0, 0, 0,"));
    }
    Ok(())
}
