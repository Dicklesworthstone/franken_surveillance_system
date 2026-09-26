#![forbid(unsafe_code)]
//! Atomic bounded admission for the compatibility tracker's pure computation.
use super::{AssignedTrackerOutput, Detection, MultiObjectTracker, TrackerOutput};

/// Hard ceiling on admitted active tracks and per-frame detections.
pub const MAX_CHECKED_TRACKS: usize = 128;
/// Maximum Hungarian column relaxations admitted by the checked API.
pub const MAX_ASSIGNMENT_WORK: u64 = 4_194_304;

/// Owner-narrowable bounds. Temporary candidate state is at most tracks+detections.
#[derive(Clone, Copy, Debug)]
pub struct TrackerLimits {
    /// Maximum active tracks after a complete successful step.
    pub max_tracks: usize,
    /// Maximum detections in one complete frame; input is never truncated.
    pub max_detections: usize,
    /// Upper bound rows^2 * (rows+detections) on assignment column relaxations.
    pub max_assignment_work: u64,
}
impl Default for TrackerLimits {
    fn default() -> Self {
        Self {
            max_tracks: MAX_CHECKED_TRACKS,
            max_detections: MAX_CHECKED_TRACKS,
            max_assignment_work: MAX_ASSIGNMENT_WORK,
        }
    }
}

/// A complete-step refusal; the prior tracker remains exactly unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackerStepError {
    /// Invalid ceilings, excess input, active-track capacity or work admission.
    Limit,
    /// Nonfinite, nonpositive or unrepresentable input box.
    Detection,
    /// Kalman arithmetic produced nonfinite state or invalid covariance.
    Numeric,
    /// Advancing sequence, identity, hit or miss counts could wrap.
    CounterExhausted,
}
impl std::fmt::Display for TrackerStepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Limit => "tracker step exceeds configured bounds",
            Self::Detection => "tracker detection geometry is invalid",
            Self::Numeric => "tracker motion state is not finite",
            Self::CounterExhausted => "tracker sequence or count exhausted",
        })
    }
}
impl std::error::Error for TrackerStepError {}

fn valid_detection(d: &Detection) -> bool {
    [
        d.box_x,
        d.box_y,
        d.box_w,
        d.box_h,
        d.box_x + d.box_w,
        d.box_y + d.box_h,
        d.box_w * d.box_h,
    ]
    .iter()
    .all(|v| v.is_finite())
        && d.box_w > 0.0
        && d.box_h > 0.0
        && d.box_w * d.box_h > 0.0
        && d.box_x + d.box_w > d.box_x
        && d.box_y + d.box_h > d.box_y
}

impl MultiObjectTracker {
    /// Runs a complete bounded frame transaction. Refusal changes no identities,
    /// filter state, hit/miss counts or frame number; no partial output is returned.
    /// Bounds and boxes are validated before copying state or evaluating pairs.
    /// This is computation admission, not source continuity, custody or effect authority.
    pub fn try_step(
        &mut self,
        detections: &[Detection],
        limits: TrackerLimits,
    ) -> Result<TrackerOutput, TrackerStepError> {
        self.try_step_assigned(detections, limits)
            .map(|result| result.output)
    }

    /// Atomically advances one bounded frame and returns the exact input-to-track assignments.
    /// The witness is recorded by the same solve/update as the motion state, not reconstructed
    /// from the filtered boxes. It contains one entry per input detection, including newly
    /// created tentative tracks, and none for coasting or deleted tracks. No assignments escape
    /// a refused transaction. Witness space is O(detections); no second matching is performed.
    pub fn try_step_assigned(
        &mut self,
        detections: &[Detection],
        limits: TrackerLimits,
    ) -> Result<AssignedTrackerOutput, TrackerStepError> {
        if limits.max_tracks == 0
            || limits.max_tracks > MAX_CHECKED_TRACKS
            || limits.max_detections == 0
            || limits.max_detections > MAX_CHECKED_TRACKS
            || limits.max_assignment_work > MAX_ASSIGNMENT_WORK
            || detections.len() > limits.max_detections
            || self.tracks.len() > limits.max_tracks
        {
            return Err(TrackerStepError::Limit);
        }
        let rows = self.tracks.len() as u64;
        let work = if detections.is_empty() {
            0
        } else {
            rows * rows * (rows + detections.len() as u64)
        };
        if work > limits.max_assignment_work {
            return Err(TrackerStepError::Limit);
        }
        if detections.iter().any(|d| !valid_detection(d)) {
            return Err(TrackerStepError::Detection);
        }
        if self.frame.checked_add(1).is_none()
            || self.next_id.checked_add(detections.len() as u64).is_none()
            || self
                .tracks
                .iter()
                .any(|t| t.hits == u32::MAX || t.misses == u32::MAX)
        {
            return Err(TrackerStepError::CounterExhausted);
        }
        let mut candidate = self.clone();
        let result = candidate.step_assigned(detections);
        let output = &result.output;
        if output.tracks.len() > limits.max_tracks {
            return Err(TrackerStepError::Limit);
        }
        if candidate.kalman.iter().any(|k| {
            k.x.iter().any(|v| !v.is_finite())
                || k.p.iter().flatten().any(|v| !v.is_finite())
                || k.p.iter().enumerate().any(|(i, row)| row[i] < 0.0)
        }) || output.tracks.iter().any(|t| {
            !valid_detection(&Detection {
                box_x: t.cx - t.box_w / 2.0,
                box_y: t.cy - t.box_h / 2.0,
                box_w: t.box_w,
                box_h: t.box_h,
            })
        }) {
            return Err(TrackerStepError::Numeric);
        }
        *self = candidate;
        Ok(result)
    }
}
