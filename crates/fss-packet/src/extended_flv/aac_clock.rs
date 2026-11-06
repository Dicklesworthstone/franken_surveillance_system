#![forbid(unsafe_code)]
//! Bounded AAC sample timing against one sender's wrapping FLV millisecond clock.
//!
//! The caller binds configuration, source order and epoch, chooses the initial
//! sample-clock position, and supplies every raw frame. This does not establish
//! sender identity, media completeness, UTC, audio/video clock alignment, or
//! that a compressed body contains exactly one decodable AAC access unit.

use std::fmt;

use super::aac::Configuration;

const MAX_SAMPLES: u64 = 16_000_000;
const HALF_WRAP: u32 = 1 << 31;

/// Payload-free refusal; a failed observation leaves the clock unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The supplied jitter, sample bound or clock origin is invalid.
    Configuration,
    /// An observation moved backward, repeated or exceeded the tolerance.
    Timeline,
    /// The epoch's configured sample count or arithmetic bound was exceeded.
    Limit,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AAC media clock refusal: {self:?}")
    }
}
impl std::error::Error for Error {}

/// One caller-relative sample-clock position and original sender timestamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SampleTime {
    /// Decode position in AAC sample-rate ticks, on the caller-selected origin.
    pub decode_ticks: u64,
    /// AAC-LC samples per configured access unit; compressed content is unverified.
    pub duration_ticks: u16,
    /// Original wrapping sender timestamp in milliseconds.
    pub sender_timestamp_ms: u32,
    /// Sender-relative elapsed milliseconds from the first accepted sample.
    pub elapsed_ms: u64,
}

/// One non-resampling clock for a caller-bound AAC connection/configuration epoch.
#[derive(Debug)]
pub struct Clock {
    rate: u32,
    frame_samples: u16,
    start_ticks: u64,
    jitter_ms: u32,
    max_samples: u64,
    count: u64,
    previous: Option<u32>,
    elapsed_ms: u64,
}
impl Clock {
    /// Start an epoch at an explicit output sample-clock position. The jitter
    /// must be strictly less than half a nominal frame. This restriction cannot
    /// prove that no frame is missing: timestamps and framing are untrusted.
    /// Long-running drift beyond the fixed bound is refused rather than
    /// corrected or resampled.
    pub fn new(
        config: &Configuration<'_>,
        start_ticks: u64,
        jitter_ms: u32,
        max_samples: u64,
    ) -> Result<Self, Error> {
        let rate = config.sample_rate();
        let frame_samples = config.frame_samples();
        if max_samples == 0
            || max_samples > MAX_SAMPLES
            || jitter_ms > 100
            || u64::from(jitter_ms) * 2 * u64::from(rate) >= u64::from(frame_samples) * 1000
            || start_ticks.checked_add(u64::from(frame_samples)).is_none()
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            rate,
            frame_samples,
            start_ticks,
            jitter_ms,
            max_samples,
            count: 0,
            previous: None,
            elapsed_ms: 0,
        })
    }

    /// Reconcile one complete caller-ordered raw tag. A successful result is a
    /// bounded timing hypothesis, not proof that no unobserved samples exist.
    pub fn observe(&mut self, timestamp_ms: u32) -> Result<SampleTime, Error> {
        if self.count >= self.max_samples {
            return Err(Error::Limit);
        }
        let elapsed = if let Some(previous) = self.previous {
            let delta = timestamp_ms.wrapping_sub(previous);
            if delta == 0 || delta >= HALF_WRAP {
                return Err(Error::Timeline);
            }
            self.elapsed_ms
                .checked_add(u64::from(delta))
                .ok_or(Error::Limit)?
        } else {
            0
        };
        let observed = u128::from(elapsed) * u128::from(self.rate);
        let expected = u128::from(self.count) * u128::from(self.frame_samples) * 1000;
        if observed.abs_diff(expected) > u128::from(self.jitter_ms) * u128::from(self.rate) {
            return Err(Error::Timeline);
        }
        let ticks = self
            .count
            .checked_mul(u64::from(self.frame_samples))
            .and_then(|n| self.start_ticks.checked_add(n))
            .ok_or(Error::Limit)?;
        ticks
            .checked_add(u64::from(self.frame_samples))
            .ok_or(Error::Limit)?;
        let value = SampleTime {
            decode_ticks: ticks,
            duration_ticks: self.frame_samples,
            sender_timestamp_ms: timestamp_ms,
            elapsed_ms: elapsed,
        };
        self.previous = Some(timestamp_ms);
        self.elapsed_ms = elapsed;
        self.count += 1;
        Ok(value)
    }
}
