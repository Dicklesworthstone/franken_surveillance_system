#![forbid(unsafe_code)]
//! Bounded sampled-occupancy episodes. This is cognition, not continuous-presence proof.
//!
//! The caller supplies one complete, ordered sequence for one source/track/zone generation.
//! A missing detection, unknown capture time, out-of-zone sample, discontinuity, or excessive
//! worst-case sampling gap ends the episode. Coasting predictions must never be eligible.
//! Each qualifying episode yields one span, with the first threshold-crossing sample retained.
//! No clock, I/O, custody, event publication, classification, or effect authority is acquired.

use fss_core::CaptureInterval;

/// Maximum decoded samples admitted for one track/zone analysis.
pub const MAX_DWELL_SAMPLES: usize = 128;
/// Maximum qualifying episodes; overflow refuses the entire result rather than truncating it.
pub const MAX_DWELL_EPISODES: usize = 32;
/// Largest owner-selected duration or sampling-gap bound (one day, in nanoseconds).
pub const MAX_DWELL_NS: u64 = 86_400_000_000_000;

/// Explicit, immutable sampled-occupancy rule. None of these values imply calibrated quality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DwellPolicy {
    /// Required lower bound from the first sample's latest to the last sample's earliest time.
    pub minimum_duration_ns: u64,
    /// Allowed worst-case time between consecutive samples: next latest minus previous earliest.
    pub maximum_sample_gap_ns: u64,
    /// Number of actually matched samples required, including both endpoint samples.
    pub minimum_observations: usize,
}

impl DwellPolicy {
    /// Validate before processing any samples.
    pub fn validate(self) -> Result<(), DwellError> {
        if !(1..=MAX_DWELL_NS).contains(&self.minimum_duration_ns)
            || !(1..=MAX_DWELL_NS).contains(&self.maximum_sample_gap_ns)
            || !(2..=MAX_DWELL_SAMPLES).contains(&self.minimum_observations)
        {
            return Err(DwellError::InvalidPolicy);
        }
        Ok(())
    }
}

/// One position in the full decoded sequence, including frames with no matching observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DwellSample {
    /// Ordinal in the complete sequence, not a count of selected observations.
    pub position: usize,
    /// None when the source's capture time is unknown or unreliable.
    pub capture: Option<CaptureInterval>,
    /// True only for an actual confirmed match conservatively inside the declared zone.
    pub matched_inside: bool,
    /// A source, decode, tracking, clock, or generation discontinuity before this sample.
    pub discontinuity: bool,
}

/// One maximal qualifying episode, indexed into the supplied sample slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DwellSpan {
    /// Index of the first eligible sample of this episode.
    pub first: usize,
    /// Index of the first sample satisfying both the duration and count thresholds.
    pub triggered: usize,
    /// Index of the last eligible sample of this episode.
    pub last: usize,
    /// Actual matched sample count; missing frames and predictions never contribute.
    pub observations: usize,
    /// Exact conservative lower bound on the endpoint separation at the trigger.
    pub trigger_minimum_ns: u128,
    /// Exact conservative lower bound on the complete episode's endpoint separation.
    pub minimum_duration_ns: u128,
}

/// Failures return no partial episodes and mutate no caller-owned state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DwellError {
    /// Duration, gap, or count is outside the admitted range.
    InvalidPolicy,
    /// Input or complete output exceeds a hard bound.
    Limit,
    /// Positions are duplicated or regress, or a capture interval is inverted.
    InvalidSamples,
    /// Capture bounds regress without an explicit discontinuity.
    ClockReversed,
}
impl std::fmt::Display for DwellError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid sampled-dwell duration, gap, or observation count",
            Self::Limit => "sampled-dwell input or episode bound exceeded",
            Self::InvalidSamples => "sampled-dwell samples are malformed or unordered",
            Self::ClockReversed => "sampled-dwell capture bounds regressed without a boundary",
        })
    }
}
impl std::error::Error for DwellError {}

// The largest signed-i128 separation is u128::MAX. Never subtract in signed arithmetic or
// narrow to u64; min/max timestamp fixtures exercise both ends of this exact comparison.
fn elapsed(first: CaptureInterval, last: CaptureInterval) -> u128 {
    if last.earliest < first.latest {
        0
    } else {
        last.earliest.0.abs_diff(first.latest.0)
    }
}

struct Run {
    first: usize,
    last: usize,
    count: usize,
    trigger: Option<(usize, u128)>,
}
fn finish(
    run: Option<Run>,
    samples: &[DwellSample],
    spans: &mut Vec<DwellSpan>,
) -> Result<(), DwellError> {
    if let Some(run) = run
        && let Some((triggered, trigger_minimum_ns)) = run.trigger
    {
        if spans.len() == MAX_DWELL_EPISODES {
            return Err(DwellError::Limit);
        }
        let first = samples[run.first].capture.ok_or(DwellError::InvalidSamples)?;
        let last = samples[run.last].capture.ok_or(DwellError::InvalidSamples)?;
        spans.push(DwellSpan {
            first: run.first,
            triggered,
            last: run.last,
            observations: run.count,
            trigger_minimum_ns,
            minimum_duration_ns: elapsed(first, last),
        });
    }
    Ok(())
}

/// Find maximal episodes of consecutive actual in-zone observations under `policy`.
///
/// Spatial membership, source identity, confirmation and custody belong to the calling owner.
/// The maximum gap is a sampling constraint, not evidence of occupancy between samples. A
/// duplicate image at distinct source times is not detected here; sensor-health screening is
/// separate. A refusal cannot be interpreted as an empty/negative result.
pub fn dwell_spans(
    samples: &[DwellSample],
    policy: DwellPolicy,
) -> Result<Vec<DwellSpan>, DwellError> {
    policy.validate()?;
    if samples.len() > MAX_DWELL_SAMPLES {
        return Err(DwellError::Limit);
    }
    for (i, sample) in samples.iter().enumerate() {
        if sample.capture.is_some_and(|c| c.earliest > c.latest)
            || (i > 0 && sample.position <= samples[i - 1].position)
        {
            return Err(DwellError::InvalidSamples);
        }
    }
    let mut spans = Vec::new();
    let mut run: Option<Run> = None;
    for (i, sample) in samples.iter().enumerate() {
        let Some(capture) = sample.capture.filter(|_| sample.matched_inside) else {
            finish(run.take(), samples, &mut spans)?;
            continue;
        };
        let adjacent = i > 0 && samples[i - 1].position.checked_add(1) == Some(sample.position);
        if sample.discontinuity || !adjacent {
            finish(run.take(), samples, &mut spans)?;
        }
        if let Some(active) = &run {
            let previous = samples[active.last].capture.ok_or(DwellError::InvalidSamples)?;
            if capture.earliest < previous.earliest || capture.latest < previous.latest {
                return Err(DwellError::ClockReversed);
            }
            let maximum_gap = capture.latest.0.abs_diff(previous.earliest.0);
            if maximum_gap > u128::from(policy.maximum_sample_gap_ns) {
                finish(run.take(), samples, &mut spans)?;
            }
        }
        let active = run.get_or_insert(Run { first: i, last: i, count: 0, trigger: None });
        active.last = i;
        active.count += 1;
        let first = samples[active.first].capture.ok_or(DwellError::InvalidSamples)?;
        let duration = elapsed(first, capture);
        if active.trigger.is_none()
            && active.count >= policy.minimum_observations
            && duration >= u128::from(policy.minimum_duration_ns)
        {
            active.trigger = Some((i, duration));
        }
    }
    finish(run, samples, &mut spans)?;
    Ok(spans)
}

#[cfg(test)]
mod tests;
