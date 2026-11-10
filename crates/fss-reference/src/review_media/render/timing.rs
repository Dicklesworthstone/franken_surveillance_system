#![forbid(unsafe_code)]
//! Bounded, query-relative presentation time for an authenticated movie selection.
//!
//! The caller owns source authentication and the exact selection/gap proof. This helper
//! validates and converts selected occurrence intervals; it does not inspect media, infer
//! capture time, fill gaps or authorize output. Each endpoint is floored independently from
//! the original rational movie interval, so fractional periods never accumulate drift.

use fss_container::demux::MovieSelection;
use fss_container::matroska_gray::{MAX_FRAMES, MAX_TIMED_DURATION_NS};

const NS_PER_SECOND: u128 = 1_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// A refusal to express the complete selected movie timeline without ambiguity.
pub enum MovieTimingError {
    /// Empty, overlapping or inconsistent source intervals.
    InvalidPlan,
    /// Native timed-container duration or frame ceilings were exceeded.
    Limit,
    /// A rational source interval cannot be represented by nonempty nanoseconds.
    Timeline,
    /// The owner's cancellation checkpoint refused further work.
    Cancelled,
}

impl std::fmt::Display for MovieTimingError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(match self {
            Self::InvalidPlan => "invalid bounded movie timing plan",
            Self::Limit => "movie timing profile limit exceeded",
            Self::Timeline => "movie interval cannot be represented in nanoseconds",
            Self::Cancelled => "movie timing cancelled",
        })
    }
}
impl std::error::Error for MovieTimingError {}

/// One nonempty selected occurrence on the query-relative nanosecond timeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameTiming {
    /// Inclusive query-relative display start.
    pub start_ns: u64,
    /// Exclusive query-relative display end.
    pub end_ns: u64,
}

/// At most 1024 occurrence intervals and the duration of the complete requested query.
///
/// Leading, internal and trailing gaps remain holes. The total duration includes them;
/// this type neither invents gap pictures nor guarantees how a player displays a hole.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MovieTiming {
    duration_ns: u64,
    frames: Vec<FrameTiming>,
}

impl MovieTiming {
    /// Preserve complete selected intervals by independently flooring their rational endpoints.
    pub fn new(
        selection: &MovieSelection,
        checkpoint: &mut impl FnMut() -> Result<(), MovieTimingError>,
    ) -> Result<Self, MovieTimingError> {
        checkpoint()?;
        if selection.query.start >= selection.query.end
            || selection.movie_timescale == 0
            || selection.media_timescale == 0
            || selection.samples.is_empty()
        {
            return Err(MovieTimingError::InvalidPlan);
        }
        if selection.samples.len() as u128 > u128::from(MAX_FRAMES) {
            return Err(MovieTimingError::Limit);
        }
        let media_scale = u128::from(selection.media_timescale);
        let origin = u128::from(selection.query.start)
            .checked_mul(media_scale)
            .ok_or(MovieTimingError::Timeline)?;
        let end = u128::from(selection.query.end)
            .checked_mul(media_scale)
            .ok_or(MovieTimingError::Timeline)?;
        let scale = media_scale
            .checked_mul(u128::from(selection.movie_timescale))
            .ok_or(MovieTimingError::Timeline)?;
        let duration_ns = boundary(end, origin, scale)?;
        if duration_ns == 0 {
            return Err(MovieTimingError::Timeline);
        }
        // Check before allocating: every admitted integer nanosecond duration is exact
        // in the Matroska profile's binary64 Segment Duration element.
        if duration_ns > MAX_TIMED_DURATION_NS {
            return Err(MovieTimingError::Limit);
        }
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(selection.samples.len())
            .map_err(|_| MovieTimingError::Limit)?;
        let mut previous_end = origin;
        for sample in &selection.samples {
            checkpoint()?;
            let interval = sample.interval;
            if interval.denominator != selection.media_timescale
                || interval.start_numerator < previous_end
                || interval.start_numerator >= interval.end_numerator
                || interval.end_numerator > end
            {
                return Err(MovieTimingError::InvalidPlan);
            }
            let start_ns = boundary(interval.start_numerator, origin, scale)?;
            let end_ns = boundary(interval.end_numerator, origin, scale)?;
            if start_ns >= end_ns {
                return Err(MovieTimingError::Timeline);
            }
            frames.push(FrameTiming { start_ns, end_ns });
            previous_end = interval.end_numerator;
        }
        checkpoint()?;
        Ok(Self {
            duration_ns,
            frames,
        })
    }

    /// Complete requested duration, including leading, internal and trailing gaps.
    pub const fn duration_ns(&self) -> u64 {
        self.duration_ns
    }

    /// Number of selected presentation occurrences, with no synthesized gap pictures.
    pub fn frames(&self) -> usize {
        self.frames.len()
    }

    /// Exact query-relative interval of one selected occurrence.
    pub fn frame(&self, index: usize) -> Option<FrameTiming> {
        self.frames.get(index).copied()
    }
}

fn boundary(numerator: u128, origin: u128, scale: u128) -> Result<u64, MovieTimingError> {
    let relative = numerator
        .checked_sub(origin)
        .and_then(|value| value.checked_mul(NS_PER_SECOND))
        .ok_or(MovieTimingError::Timeline)?;
    u64::try_from(relative / scale).map_err(|_| MovieTimingError::Timeline)
}
