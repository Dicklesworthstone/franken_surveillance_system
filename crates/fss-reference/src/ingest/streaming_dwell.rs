#![forbid(unsafe_code)]
//! Constant-space sampled occupancy across arbitrary caller batching.
//!
//! One instance owns one source/track/zone generation. Every decoded position must be supplied,
//! including misses. A caller must discard its accumulated report if any step refuses: earlier
//! returned episodes are not a complete inventory. No I/O, source custody or effect is acquired.

use fss_core::CaptureInterval;

use super::zone_dwell::{DwellError, DwellPolicy, DwellSample, MAX_DWELL_EPISODES};

/// Hard ceiling for one streaming analysis, independent of caller chunk boundaries.
pub const MAX_STREAM_DWELL_SAMPLES: usize = 65_536;

/// One completed episode in absolute source positions, not indices into a temporary chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamDwellSpan {
    /// First eligible sample, with its conservative capture interval.
    pub first: DwellSample,
    /// First sample satisfying both the duration and count thresholds.
    pub trigger: DwellSample,
    /// Final eligible sample before a break or the explicitly declared range end.
    pub last: DwellSample,
    /// Actual matched samples in the episode; predictions never contribute.
    pub observations: usize,
    /// Conservative endpoint separation at the threshold crossing.
    pub trigger_minimum_ns: u128,
    /// Conservative endpoint separation for the completed episode.
    pub minimum_duration_ns: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Run {
    first: DwellSample,
    last: DwellSample,
    observations: usize,
    trigger: Option<(DwellSample, u128)>,
}

/// Bounded online equivalent of `zone_dwell::dwell_spans`, without retaining a sample array.
///
/// Successful pushes are independent of how a caller partitions the input. A refused push leaves
/// this complete value unchanged. `finish` consumes the accumulator, so it cannot emit an episode
/// twice. There is deliberately no serialized checkpoint that could be detached from source,
/// decoder, foreground, tracker, privacy, or clock-generation custody.
#[derive(Debug, Eq, PartialEq)]
pub struct DwellAccumulator {
    policy: DwellPolicy,
    maximum_samples: usize,
    consumed: usize,
    completed: usize,
    last_position: Option<usize>,
    run: Option<Run>,
}

impl DwellAccumulator {
    /// Validate the immutable temporal rule and whole-analysis bound before accepting input.
    pub fn new(policy: DwellPolicy, maximum_samples: usize) -> Result<Self, DwellError> {
        policy.validate()?;
        if !(1..=MAX_STREAM_DWELL_SAMPLES).contains(&maximum_samples) {
            return Err(DwellError::Limit);
        }
        Ok(Self {
            policy,
            maximum_samples,
            consumed: 0,
            completed: 0,
            last_position: None,
            run: None,
        })
    }

    /// Number of successfully admitted samples, including explicit misses and unknowns.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Admit one position atomically, returning at most one completed qualifying episode.
    pub fn push(&mut self, sample: DwellSample) -> Result<Option<StreamDwellSpan>, DwellError> {
        let mut next = self.staged();
        let completed = next.push_checked(sample)?;
        *self = next;
        Ok(completed)
    }

    /// End the declared input range. No later input can reuse this accumulator.
    pub fn finish(mut self) -> Result<Option<StreamDwellSpan>, DwellError> {
        self.close_run()
    }

    // Private transaction snapshot; callers cannot implicitly copy or clone a finished episode.
    fn staged(&self) -> Self {
        Self {
            policy: self.policy,
            maximum_samples: self.maximum_samples,
            consumed: self.consumed,
            completed: self.completed,
            last_position: self.last_position,
            run: self.run,
        }
    }

    fn push_checked(&mut self, sample: DwellSample) -> Result<Option<StreamDwellSpan>, DwellError> {
        if self.consumed == self.maximum_samples {
            return Err(DwellError::Limit);
        }
        if self.last_position.is_some_and(|p| sample.position <= p)
            || sample.capture.is_some_and(|c| c.earliest > c.latest)
        {
            return Err(DwellError::InvalidSamples);
        }
        let adjacent = self.last_position.and_then(|p| p.checked_add(1)) == Some(sample.position);
        self.last_position = Some(sample.position);
        self.consumed += 1;
        let Some(capture) = sample.capture.filter(|_| sample.matched_inside) else {
            return self.close_run();
        };
        let mut completed = None;
        if sample.discontinuity || !adjacent {
            completed = self.close_run()?;
        }
        if let Some(run) = self.run {
            let previous = run.last.capture.ok_or(DwellError::InvalidSamples)?;
            if capture.earliest < previous.earliest || capture.latest < previous.latest {
                return Err(DwellError::ClockReversed);
            }
            if capture.latest.0.abs_diff(previous.earliest.0)
                > u128::from(self.policy.maximum_sample_gap_ns)
            {
                completed = self.close_run()?;
            }
        }
        let active = self.run.get_or_insert(Run {
            first: sample,
            last: sample,
            observations: 0,
            trigger: None,
        });
        active.last = sample;
        active.observations += 1;
        let duration = elapsed(
            active.first.capture.ok_or(DwellError::InvalidSamples)?,
            capture,
        );
        if active.trigger.is_none()
            && active.observations >= self.policy.minimum_observations
            && duration >= u128::from(self.policy.minimum_duration_ns)
        {
            active.trigger = Some((sample, duration));
        }
        Ok(completed)
    }

    fn close_run(&mut self) -> Result<Option<StreamDwellSpan>, DwellError> {
        let Some(run) = self.run.take() else {
            return Ok(None);
        };
        let Some((trigger, trigger_minimum_ns)) = run.trigger else {
            return Ok(None);
        };
        if self.completed == MAX_DWELL_EPISODES {
            return Err(DwellError::Limit);
        }
        self.completed += 1;
        Ok(Some(StreamDwellSpan {
            first: run.first,
            trigger,
            last: run.last,
            observations: run.observations,
            trigger_minimum_ns,
            minimum_duration_ns: elapsed(
                run.first.capture.ok_or(DwellError::InvalidSamples)?,
                run.last.capture.ok_or(DwellError::InvalidSamples)?,
            ),
        }))
    }
}

fn elapsed(first: CaptureInterval, last: CaptureInterval) -> u128 {
    if last.earliest < first.latest {
        0
    } else {
        last.earliest.0.abs_diff(first.latest.0)
    }
}

#[cfg(test)]
mod tests;
