#![forbid(unsafe_code)]
//! Interval-native temporal admission before global cross-camera assignment.
//!
//! A midpoint is a ranking coordinate, never permission to associate. An edge enters the
//! solver only when every pair of instants in its two capture intervals passes the time
//! gate. Exclusion solves use that same admissible graph, so a subsequently refused edge
//! cannot consume a counterpart or suppress a valid alternative. Uncertain edges remain
//! in the complete Cartesian report. Stability is conditional on these admission rules;
//! it is not a physical-identity, calibrated-clock, absence, or effect-authority claim.

use fss_core::CaptureInterval;
use fss_geometry::WorkBudget;

use super::global::{AssignmentResult, assign, charge, reserve, validate_request};
use super::{
    ASSOCIATION_SCORE_SCALE, AssociationDisposition, AssociationExclusion, AssociationScore,
    CrossCameraAlternative, CrossCameraCandidate, CrossCameraConfig, CrossCameraError,
    MAX_CAMERA_ID_BYTES,
};

/// One anonymous observation, retaining its full signed-128 capture coordinates.
#[derive(Clone, Debug, PartialEq)]
pub struct IntervalCameraObservation {
    /// One bounded camera identity per input slice.
    pub camera_id: String,
    /// Nonzero, unique camera-local track identity.
    pub track_id: u64,
    /// Inclusive capture bounds on the caller's explicitly supplied common clock.
    /// Unknown alignment must not be represented as a made-up point interval.
    pub capture: CaptureInterval,
    /// Finite x coordinate on the caller's shared ground plane.
    pub ground_x: f64,
    /// Finite y coordinate on the caller's shared ground plane.
    pub ground_y: f64,
}

/// Temporal admission is separate from geometry, rank, and assignment ambiguity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntervalTimeGate {
    /// All possible capture-time separations meet the inclusive time gate.
    Within,
    /// Some possible separations meet the gate and others do not. Not admissible.
    Uncertain,
    /// Every possible separation exceeds the gate. Not evidence of scene absence.
    Outside,
}

/// Exact attainable separation bounds for one Cartesian candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntervalSeparation {
    /// Smallest absolute separation between instants in the two intervals.
    pub minimum_ns: u128,
    /// Largest absolute separation between instants in the two intervals.
    pub maximum_ns: u128,
    /// Classification against the caller's inclusive time gate.
    pub gate: IntervalTimeGate,
}

/// Largest absolute separation without overflowing at signed timestamp extremes.
/// This helper does not validate interval ordering; association validates every input first.
#[must_use]
pub fn worst_case_separation(a: CaptureInterval, b: CaptureInterval) -> u128 {
    a.latest
        .0
        .abs_diff(b.earliest.0)
        .max(b.latest.0.abs_diff(a.earliest.0))
}

fn separation(a: CaptureInterval, b: CaptureInterval, gate: u128) -> IntervalSeparation {
    let minimum_ns = if a.latest < b.earliest {
        a.latest.0.abs_diff(b.earliest.0)
    } else if b.latest < a.earliest {
        b.latest.0.abs_diff(a.earliest.0)
    } else {
        0
    };
    let maximum_ns = worst_case_separation(a, b);
    let gate = if maximum_ns <= gate {
        IntervalTimeGate::Within
    } else if minimum_ns > gate {
        IntervalTimeGate::Outside
    } else {
        IntervalTimeGate::Uncertain
    };
    IntervalSeparation {
        minimum_ns,
        maximum_ns,
        gate,
    }
}

/// Floor midpoint. For an ordered interval half its unsigned width fits in i128,
/// and adding that half to its lower endpoint remains inside the original interval.
fn midpoint(capture: CaptureInterval) -> i128 {
    capture.earliest.0 + (capture.earliest.0.abs_diff(capture.latest.0) / 2) as i128
}

/// Complete bounded report, ordered by track ID. No input bounds are narrowed to i64.
#[derive(Clone, Debug, PartialEq)]
pub struct IntervalAssociationReport {
    config: CrossCameraConfig,
    requested_margin: u32,
    left: Vec<IntervalCameraObservation>,
    right: Vec<IntervalCameraObservation>,
    separations: Vec<IntervalSeparation>,
    uncertain_left: Vec<bool>,
    uncertain_right: Vec<bool>,
    assignment: AssignmentResult,
}

impl IntervalAssociationReport {
    /// Exact caller gates.
    #[must_use]
    pub fn config(&self) -> &CrossCameraConfig {
        &self.config
    }
    /// Requested global objective margin before the rounding guard.
    #[must_use]
    pub fn requested_margin(&self) -> u32 {
        self.requested_margin
    }
    /// Complete canonical left observations, including unmatched ones.
    #[must_use]
    pub fn left(&self) -> &[IntervalCameraObservation] {
        &self.left
    }
    /// Complete canonical right observations, including unmatched ones.
    #[must_use]
    pub fn right(&self) -> &[IntervalCameraObservation] {
        &self.right
    }
    /// Full row-major candidate graph; temporal exclusions remain explicit.
    #[must_use]
    pub fn candidates(&self) -> &[CrossCameraCandidate] {
        &self.assignment.candidates
    }
    /// Exact timing of each corresponding row-major candidate, including excluded edges.
    #[must_use]
    pub fn separations(&self) -> &[IntervalSeparation] {
        &self.separations
    }
    /// Stable matches, unresolved alternatives, or no admissible candidate for every left row.
    #[must_use]
    pub fn left_dispositions(&self) -> &[AssociationDisposition] {
        &self.assignment.left_dispositions
    }
    /// Same dispositions for every right row.
    #[must_use]
    pub fn right_dispositions(&self) -> &[AssociationDisposition] {
        &self.assignment.right_dispositions
    }
    /// True when a left row has a midpoint/geometry candidate refused by interval uncertainty.
    /// Such an edge is retained diagnostically, but cannot consume an assignment column.
    #[must_use]
    pub fn time_uncertain_left(&self, row: usize) -> bool {
        self.uncertain_left.get(row).copied().unwrap_or(false)
    }
    /// The analogous diagnostic for a right row.
    #[must_use]
    pub fn time_uncertain_right(&self, column: usize) -> bool {
        self.uncertain_right.get(column).copied().unwrap_or(false)
    }
    /// Complete competing admissible assignments inside the guarded margin.
    #[must_use]
    pub fn alternatives(&self) -> &[CrossCameraAlternative] {
        &self.assignment.alternatives
    }
    /// Integer cost including explicit unmatched choices.
    #[must_use]
    pub fn assignment_cost(&self) -> u64 {
        self.assignment.assignment_cost
    }
    /// Requested margin plus one quantization guard unit per left row.
    #[must_use]
    pub fn effective_margin(&self) -> u64 {
        self.assignment.effective_margin
    }
    /// Whether any selected edge has a competing admissible solution inside the margin.
    #[must_use]
    pub fn is_ambiguous(&self) -> bool {
        !self.assignment.alternatives.is_empty()
    }
}

/// Associate only interval-admissible edges using the existing global assignment solver.
///
/// The midpoint/geometry ranking, unmatched costs and quantization guard are unchanged.
/// For point intervals in i64 range, candidates, alternatives, scores and dispositions match
/// `associate_detailed`. Actual intervals are gated *before* optimization and every exclusion
/// solve. All rejected input, allocation, cancellation and budget paths fail without a partial
/// report. Capture bounds themselves remain caller assertions, not clock certification.
pub fn associate_intervals(
    config: &CrossCameraConfig,
    ambiguity_margin_units: u32,
    left: &[IntervalCameraObservation],
    right: &[IntervalCameraObservation],
    budget: &mut WorkBudget<'_>,
) -> Result<IntervalAssociationReport, CrossCameraError> {
    validate_request(
        config,
        ambiguity_margin_units,
        left.len(),
        right.len(),
        budget,
    )?;
    let left = ordered(left, budget)?;
    let right = ordered(right, budget)?;
    // Charge interval arithmetic and diagnostic output separately from the shared solver.
    charge(
        budget,
        (left.len() * right.len() * 8 + left.len() + right.len()) as u64,
    )?;
    let mut separations = reserve(left.len() * right.len())?;
    let mut uncertain_left = reserve(left.len())?;
    uncertain_left.resize(left.len(), false);
    let mut uncertain_right = reserve(right.len())?;
    uncertain_right.resize(right.len(), false);
    let assignment = assign(
        ambiguity_margin_units,
        left.len(),
        right.len(),
        |row, column| {
            let l = &left[row];
            let r = &right[column];
            let timing = separation(l.capture, r.capture, config.max_time_delta_ns as u128);
            separations.push(timing);
            let point_score = midpoint_score(config, l, r);
            if matches!(point_score, AssociationScore::Admissible { .. })
                && timing.gate != IntervalTimeGate::Within
            {
                // An admissible midpoint implies at least one possible separation in gate;
                // keep the explicit classification rather than treating it as a missing edge.
                uncertain_left[row] |= timing.gate == IntervalTimeGate::Uncertain;
                uncertain_right[column] |= timing.gate == IntervalTimeGate::Uncertain;
                AssociationScore::Excluded(AssociationExclusion::Time)
            } else {
                point_score
            }
        },
        budget,
    )?;
    Ok(IntervalAssociationReport {
        config: config.clone(),
        requested_margin: ambiguity_margin_units,
        left,
        right,
        separations,
        uncertain_left,
        uncertain_right,
        assignment,
    })
}

fn ordered(
    input: &[IntervalCameraObservation],
    budget: &mut WorkBudget<'_>,
) -> Result<Vec<IntervalCameraObservation>, CrossCameraError> {
    charge(
        budget,
        (input.len() * (MAX_CAMERA_ID_BYTES + input.len() + 1)) as u64,
    )?;
    let mut result = reserve(input.len())?;
    for observation in input {
        if observation.camera_id.len() > MAX_CAMERA_ID_BYTES {
            return Err(CrossCameraError::Limit);
        }
        if observation.camera_id.is_empty()
            || observation.camera_id.chars().any(char::is_control)
            || observation.track_id == 0
            || !observation.ground_x.is_finite()
            || !observation.ground_y.is_finite()
            || observation.capture.earliest > observation.capture.latest
        {
            return Err(CrossCameraError::InvalidObservation(
                "identity, position or capture bounds",
            ));
        }
        if input
            .first()
            .is_some_and(|first| first.camera_id != observation.camera_id)
        {
            return Err(CrossCameraError::InvalidObservation(
                "one camera is required per input slice",
            ));
        }
        let mut camera_id = String::new();
        camera_id
            .try_reserve_exact(observation.camera_id.len())
            .map_err(|_| CrossCameraError::Limit)?;
        camera_id.push_str(&observation.camera_id);
        result.push(IntervalCameraObservation {
            camera_id,
            track_id: observation.track_id,
            capture: observation.capture,
            ground_x: observation.ground_x,
            ground_y: observation.ground_y,
        });
    }
    result.sort_unstable_by_key(|observation| observation.track_id);
    if result
        .windows(2)
        .any(|pair| pair[0].track_id == pair[1].track_id)
    {
        return Err(CrossCameraError::DuplicateObservation);
    }
    Ok(result)
}

fn midpoint_score(
    config: &CrossCameraConfig,
    l: &IntervalCameraObservation,
    r: &IntervalCameraObservation,
) -> AssociationScore {
    if l.camera_id == r.camera_id {
        return AssociationScore::Excluded(AssociationExclusion::SameCamera);
    }
    let delta = midpoint(l.capture).abs_diff(midpoint(r.capture));
    if delta > config.max_time_delta_ns as u128 {
        return AssociationScore::Excluded(AssociationExclusion::Time);
    }
    let distance = (l.ground_x - r.ground_x).hypot(l.ground_y - r.ground_y);
    if distance > config.max_position_distance {
        return AssociationScore::Excluded(AssociationExclusion::Position);
    }
    let confidence = (1.0 - delta as f64 / config.max_time_delta_ns as f64)
        * (1.0 - distance / config.max_position_distance);
    if confidence < config.min_confidence {
        AssociationScore::Excluded(AssociationExclusion::Confidence)
    } else {
        let units = (confidence * f64::from(ASSOCIATION_SCORE_SCALE)).round() as u32;
        AssociationScore::Admissible { confidence, units }
    }
}

#[cfg(test)]
mod tests;
