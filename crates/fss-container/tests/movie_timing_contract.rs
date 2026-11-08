#![forbid(unsafe_code)]
//! Production movie-interval conversion and Matroska framing, without a runtime or I/O.
//! Synthetic selections below test arithmetic/admission only, not authenticated custody.

#[path = "../../fss-cli/src/bin/fss-file/movie_timing.rs"]
mod movie_timing;

use fss_container::demux::{
    AvcMp4, DemuxLimits, MovieInterval, MovieSampleSelection, MovieSelection, MovieSelectionLimits,
};
use fss_container::matroska_gray::{MAX_TIMED_DURATION_NS, TimedGrayMatroskaConfig};
use movie_timing::{FrameTiming, MovieTiming, MovieTimingError};
use std::ops::Range;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn selection(
    query: Range<u64>,
    movie_timescale: u32,
    media_timescale: u32,
    intervals: &[(u128, u128)],
) -> MovieSelection {
    MovieSelection {
        query,
        movie_timescale,
        media_timescale,
        samples: intervals
            .iter()
            .enumerate()
            .map(
                |(sample_index, &(start_numerator, end_numerator))| MovieSampleSelection {
                    sample_index,
                    edit_index: None,
                    source: sample_index..sample_index + 1,
                    interval: MovieInterval {
                        start_numerator,
                        end_numerator,
                        denominator: media_timescale,
                    },
                },
            )
            .collect(),
        edits: Vec::new(),
        gaps: Vec::new(),
        decode_spans: Vec::new(),
        work: 0,
        sample_bytes: 0,
        decode_bytes: 0,
        annex_b_bytes: 0,
    }
}

fn intervals(timing: &MovieTiming) -> Test<Vec<(u64, u64)>> {
    (0..timing.frames())
        .map(|ordinal| {
            timing
                .frame(ordinal)
                .map(|frame| (frame.start_ns, frame.end_ns))
                .ok_or_else(|| "missing admitted frame timing".into())
        })
        .collect()
}

#[test]
fn real_b_picture_query_clips_both_edges_and_drives_native_timed_framing() -> Test {
    let source = include_bytes!("fixtures/indexed_avc.mp4");
    let movie = AvcMp4::parse(source, None, DemuxLimits::default())?;
    let selected = movie.select_movie_interval(450..750, MovieSelectionLimits::default())?;
    assert_eq!(
        selected
            .samples
            .iter()
            .map(|s| s.sample_index)
            .collect::<Vec<_>>(),
        [3, 1]
    );
    let timing = MovieTiming::new(&selected, &mut || Ok(()))?;
    assert_eq!(timing.duration_ns(), 300_000_000);
    assert_eq!(
        intervals(&timing)?,
        [(0, 150_000_000), (150_000_000, 300_000_000)]
    );
    assert!(timing.frame(2).is_none());
    assert!(timing.frame(usize::MAX).is_none());

    // Feed the production framing core directly. The payload is intentionally omitted:
    // this checks time/shape framing, not native pixel decoding or source custody.
    let config = TimedGrayMatroskaConfig::new([64, 48], timing.duration_ns())?;
    assert_eq!(config.duration_ns(), timing.duration_ns());
    assert!(!config.initialization()?.bytes().is_empty());
    for ordinal in 0..timing.frames() {
        let frame = timing.frame(ordinal).ok_or("missing timing")?;
        let framing = config.frame(ordinal as u64, frame.start_ns, frame.end_ns)?;
        assert_eq!(framing.timestamp_ns(), frame.start_ns);
        assert_eq!(framing.duration_ns(), 150_000_000);
        assert_eq!(framing.end_ns(), frame.end_ns);
        assert_eq!(framing.payload_bytes(), 64 * 48);
    }
    Ok(())
}

#[test]
fn rational_boundaries_are_rounded_independently_without_period_drift() -> Test {
    // Movie ticks are 1/30000 s; sample presentation lengths are 1001 ticks.
    let selected = selection(
        0..3003,
        30_000,
        30_000,
        &[
            (0, 30_030_000),
            (30_030_000, 60_060_000),
            (60_060_000, 90_090_000),
        ],
    );
    let timing = MovieTiming::new(&selected, &mut || Ok(()))?;
    assert_eq!(timing.duration_ns(), 100_100_000);
    assert_eq!(
        intervals(&timing)?,
        [
            (0, 33_366_666),
            (33_366_666, 66_733_333),
            (66_733_333, 100_100_000)
        ]
    );
    assert_ne!(timing.duration_ns(), 3 * 33_366_666);

    // Fractional MOVIE ticks use media_timescale as the denominator. Dividing only
    // by the movie timescale would produce a threefold error in this fixture.
    let fractional = selection(7..10, 1000, 3, &[(21, 22), (22, 26), (28, 30)]);
    let timing = MovieTiming::new(&fractional, &mut || Ok(()))?;
    assert_eq!(timing.duration_ns(), 3_000_000);
    assert_eq!(
        intervals(&timing)?,
        [(0, 333_333), (333_333, 1_666_666), (2_333_333, 3_000_000)]
    );
    Ok(())
}

#[test]
fn leading_internal_and_trailing_holes_preserve_full_query_duration() -> Test {
    let selected = selection(100..1100, 1000, 1, &[(300, 450), (700, 900)]);
    let timing = MovieTiming::new(&selected, &mut || Ok(()))?;
    assert_eq!(timing.duration_ns(), 1_000_000_000);
    assert_eq!(timing.frames(), 2);
    assert_eq!(
        intervals(&timing)?,
        [(200_000_000, 350_000_000), (600_000_000, 800_000_000)]
    );
    let config = TimedGrayMatroskaConfig::new([1, 1], timing.duration_ns())?;
    let last = timing.frame(1).ok_or("missing last timing")?;
    assert_eq!(
        config.frame(1, last.start_ns, last.end_ns)?.end_ns(),
        800_000_000
    );
    assert_eq!(config.duration_ns(), 1_000_000_000);
    Ok(())
}

#[test]
fn repeated_or_backward_source_indices_do_not_reorder_presentation_time() -> Test {
    let mut selected = selection(0..600, 1000, 1, &[(0, 200), (200, 350), (350, 600)]);
    for (row, original) in selected.samples.iter_mut().zip([19, 2, 19]) {
        row.sample_index = original;
    }
    let timing = MovieTiming::new(&selected, &mut || Ok(()))?;
    assert_eq!(
        intervals(&timing)?,
        [
            (0, 200_000_000),
            (200_000_000, 350_000_000),
            (350_000_000, 600_000_000)
        ]
    );
    Ok(())
}

#[test]
fn malformed_rational_plans_refuse_without_reordering_or_clamping() {
    let base = selection(10..30, 1000, 1, &[(10, 20), (20, 30)]);
    let mut cases = Vec::new();
    let mut push = |edit: fn(&mut MovieSelection)| {
        let mut candidate = base.clone();
        edit(&mut candidate);
        cases.push(candidate);
    };
    push(|s| s.samples.clear());
    push(|s| s.query.end = s.query.start);
    push(|s| s.query.start = s.query.end + 1);
    push(|s| s.movie_timescale = 0);
    push(|s| s.media_timescale = 0);
    push(|s| s.samples[0].interval.denominator = 0);
    push(|s| s.samples[0].interval.denominator = 2);
    push(|s| s.samples[0].interval.start_numerator = 9);
    push(|s| s.samples[0].interval.end_numerator = 10);
    push(|s| s.samples[0].interval.end_numerator = 9);
    push(|s| s.samples[1].interval.end_numerator = 31);
    push(|s| s.samples[1].interval.start_numerator = 19);
    push(|s| s.samples[1].interval = s.samples[0].interval);
    push(|s| s.samples.swap(0, 1));
    push(|s| s.samples[1].interval.end_numerator = u128::MAX);
    for selected in cases {
        assert_eq!(
            MovieTiming::new(&selected, &mut || Ok(())),
            Err(MovieTimingError::InvalidPlan)
        );
    }
}

#[test]
fn nanosecond_collapse_and_duration_limits_refuse_but_large_origins_remain_exact() -> Test {
    let collapsed_query = selection(0..1, u32::MAX, 1, &[(0, 1)]);
    assert_eq!(
        MovieTiming::new(&collapsed_query, &mut || Ok(())),
        Err(MovieTimingError::Timeline)
    );
    let collapsed_frame = selection(0..10, u32::MAX, 1, &[(0, 1), (1, 10)]);
    assert_eq!(
        MovieTiming::new(&collapsed_frame, &mut || Ok(())),
        Err(MovieTimingError::Timeline)
    );

    let maximum = selection(
        0..MAX_TIMED_DURATION_NS,
        1_000_000_000,
        1,
        &[(0, u128::from(MAX_TIMED_DURATION_NS))],
    );
    assert_eq!(
        MovieTiming::new(&maximum, &mut || Ok(()))?.duration_ns(),
        MAX_TIMED_DURATION_NS
    );
    let mut too_long = maximum.clone();
    too_long.query.end += 1;
    assert_eq!(
        MovieTiming::new(&too_long, &mut || Ok(())),
        Err(MovieTimingError::Limit)
    );
    let overflow = selection(0..u64::MAX, 1, 1, &[(0, 1)]);
    assert_eq!(
        MovieTiming::new(&overflow, &mut || Ok(())),
        Err(MovieTimingError::Timeline)
    );

    let start = u64::MAX - 1000;
    let scale = u128::from(u32::MAX);
    let large_origin = selection(
        start..u64::MAX,
        1000,
        u32::MAX,
        &[(u128::from(start) * scale, u128::from(u64::MAX) * scale)],
    );
    let timing = MovieTiming::new(&large_origin, &mut || Ok(()))?;
    assert_eq!(timing.duration_ns(), 1_000_000_000);
    assert_eq!(
        timing.frame(0),
        Some(FrameTiming {
            start_ns: 0,
            end_ns: 1_000_000_000
        })
    );
    Ok(())
}

#[test]
fn occurrence_ceiling_is_checked_before_any_unbounded_walk() -> Test {
    let intervals: Vec<_> = (0_u128..1024).map(|i| (i, i + 1)).collect();
    let mut selected = selection(0..1025, 1000, 1, &intervals);
    let timing = MovieTiming::new(&selected, &mut || Ok(()))?;
    assert_eq!(timing.frames(), 1024);
    assert_eq!(
        timing.frame(1023),
        Some(FrameTiming {
            start_ns: 1_023_000_000,
            end_ns: 1_024_000_000
        })
    );
    selected.samples.push(selected.samples[0].clone());
    let mut calls = 0;
    assert_eq!(
        MovieTiming::new(&selected, &mut || {
            calls += 1;
            Ok(())
        }),
        Err(MovieTimingError::Limit)
    );
    assert_eq!(calls, 1);
    Ok(())
}

#[test]
fn every_cancellation_cut_refuses_a_complete_timing_plan() -> Test {
    let selected = selection(0..3, 1, 1, &[(0, 1), (1, 2), (2, 3)]);
    let mut total = 0;
    MovieTiming::new(&selected, &mut || {
        total += 1;
        Ok(())
    })?;
    assert!(total >= selected.samples.len() + 2);
    for cut in 0..total {
        let mut visited = 0;
        let result = MovieTiming::new(&selected, &mut || {
            if visited == cut {
                return Err(MovieTimingError::Cancelled);
            }
            visited += 1;
            Ok(())
        });
        assert_eq!(result, Err(MovieTimingError::Cancelled));
        assert_eq!(visited, cut);
    }
    Ok(())
}
