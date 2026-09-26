#![forbid(unsafe_code)]
//! Global cross-camera association of anonymous, already-rectified observations.
//!
//! Time and geometry gates build the complete bipartite candidate graph. The
//! shared image-tracking Hungarian solver maximizes total quantized confidence,
//! including an explicit unmatched option for every left observation. Exclusion
//! solves identify unstable pairs; deterministic tie-breaking never proves identity.
//! This module does not establish calibration, clock alignment, corroboration,
//! person identity, source custody, observability, or authority to publish effects.

mod global;
/// Full-width uncertain capture times gated before global assignment.
pub mod intervals;

use fss_geometry::WorkBudget;
use fss_twin::image_tracking::ImageTrackingError;

pub use global::associate_detailed;

/// Hard bound per camera; complete input is refused rather than truncated.
pub const MAX_CROSS_CAMERA_OBSERVATIONS: usize = 64;
/// Integer objective units per confidence point; not calibrated probabilities.
pub const ASSOCIATION_SCORE_SCALE: u32 = 1_000_000;
/// Bound on the UTF-8 bytes of each caller-supplied camera identity.
pub const MAX_CAMERA_ID_BYTES: usize = 256;
/// Finite work budget used by the compatibility API. Use `associate_detailed`
/// for caller-owned work accounting and cooperative cancellation.
pub const DEFAULT_ASSOCIATION_WORK: u64 = 100_000_000;

/// Conditional gates for observations already resolved into one ground plane.
#[derive(Clone, Debug, PartialEq)]
pub struct CrossCameraConfig {
    /// Maximum absolute capture timestamp separation in nanoseconds.
    pub max_time_delta_ns: i64,
    /// Maximum Euclidean distance in the owner's shared ground-plane units.
    pub max_position_distance: f64,
    /// Minimum product of time proximity and geometric proximity, in [0, 1].
    pub min_confidence: f64,
}

impl CrossCameraConfig {
    /// Validates hard bounds, including non-finite floating-point values.
    pub fn validate(&self) -> Result<(), CrossCameraError> {
        if self.max_time_delta_ns <= 0 {
            return Err(CrossCameraError::InvalidConfig(
                "max_time_delta_ns must be positive",
            ));
        }
        if !self.max_position_distance.is_finite() || self.max_position_distance <= 0.0 {
            return Err(CrossCameraError::InvalidConfig(
                "max_position_distance must be finite and positive",
            ));
        }
        if !self.min_confidence.is_finite() || !(0.0..=1.0).contains(&self.min_confidence) {
            return Err(CrossCameraError::InvalidConfig(
                "min_confidence must be finite and in [0, 1]",
            ));
        }
        Ok(())
    }
}

/// Typed failure; no error is returned as an empty or partially matched scene.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrossCameraError {
    /// Configuration or ambiguity margin is invalid.
    InvalidConfig(&'static str),
    /// Invalid identity, non-finite position, or mixed cameras in one input slice.
    InvalidObservation(&'static str),
    /// The same camera-local track appears twice in one input slice.
    DuplicateObservation,
    /// Complete input, bounded identity storage, or allocation limit exceeded.
    Limit,
    /// The pair-only compatibility API cannot represent competing assignments.
    AmbiguousAssignment,
    /// Shared solver failure, including cooperative cancellation and work exhaustion.
    Assignment(ImageTrackingError),
}

impl From<ImageTrackingError> for CrossCameraError {
    fn from(error: ImageTrackingError) -> Self {
        Self::Assignment(error)
    }
}

impl std::fmt::Display for CrossCameraError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(f, "invalid cross-camera config: {reason}"),
            Self::InvalidObservation(reason) => {
                write!(f, "invalid cross-camera observation: {reason}")
            }
            Self::DuplicateObservation => f.write_str("duplicate camera-local observation"),
            Self::Limit => f.write_str("cross-camera complete-input or allocation limit"),
            Self::AmbiguousAssignment => {
                f.write_str("cross-camera assignment is ambiguous; retain the detailed report")
            }
            Self::Assignment(error) => write!(f, "cross-camera assignment: {error}"),
        }
    }
}
impl std::error::Error for CrossCameraError {}

/// One anonymous tracked-object observation already in the shared ground plane.
#[derive(Clone, Debug, PartialEq)]
pub struct CameraObservation {
    /// Camera identity; each input slice must contain just one camera.
    pub camera_id: String,
    /// Nonzero camera-local track ID, unique within its input slice.
    pub track_id: u64,
    /// Capture timestamp under the caller's explicitly resolved common clock.
    pub timestamp_ns: i64,
    /// Finite ground-plane x coordinate in the caller's shared scene units.
    pub ground_x: f64,
    /// Finite ground-plane y coordinate in the caller's shared scene units.
    pub ground_y: f64,
}

/// An unambiguous pair under the declared gates and assignment policy only.
#[derive(Clone, Debug, PartialEq)]
pub struct AssociatedPair {
    /// Original observation from the left camera.
    pub first: CameraObservation,
    /// Original observation from the right camera.
    pub second: CameraObservation,
    /// Unquantized time/geometry ranking score, not identity or corroboration proof.
    pub confidence: f64,
}

/// Why one Cartesian candidate failed the conditional gates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssociationExclusion {
    /// Two observations from the same camera cannot cross-associate.
    SameCamera,
    /// Capture timestamp separation exceeded the configured window.
    Time,
    /// Ground-plane distance exceeded the configured limit.
    Position,
    /// The combined score fell below the owner's configured threshold.
    Confidence,
}

/// Complete candidate score or explicit gate exclusion.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AssociationScore {
    /// Excluded by a named conditional gate, not proof of physical absence.
    Excluded(AssociationExclusion),
    /// An admissible hypothesis with both numeric representations retained.
    Admissible {
        /// Original bounded f64 ranking score.
        confidence: f64,
        /// Score rounded to nearest integer at `ASSOCIATION_SCORE_SCALE` resolution.
        units: u32,
    },
}

/// Candidate indices refer to the report's canonically ordered input arrays.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CrossCameraCandidate {
    /// Index into the report's left observations.
    pub left: usize,
    /// Index into the report's right observations.
    pub right: usize,
    /// Complete gate decision and score.
    pub score: AssociationScore,
    /// Selected by one deterministic globally minimum-cost assignment.
    pub selected: bool,
    /// Selected edge has a competing solution inside the effective margin.
    pub ambiguous: bool,
    /// Minimum total cost when this selected edge is forbidden; None if not selected.
    pub exclusion_cost: Option<u64>,
}

/// Local association disposition; no outcome is evidence of scene absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssociationDisposition {
    /// Stable selected edge; index into the opposite report input array.
    Matched(usize),
    /// Plausible candidates remain, but none is a stable selected edge.
    Unresolved,
    /// No candidate passed the conditional gates for this observation.
    NoCandidate,
}

/// A retained competing global solution, not just a local second-best edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossCameraAlternative {
    /// Selected edge whose exclusion produced this alternative.
    pub excluded: (usize, usize),
    /// One right index per left row; None is an explicit unmatched choice.
    pub columns: Vec<Option<usize>>,
    /// Total objective cost, including unmatched choices.
    pub cost: u64,
}

/// Complete bounded association result. Read-only access prevents changing the
/// report's pair dispositions independently of its retained candidate decisions.
#[derive(Clone, Debug, PartialEq)]
pub struct CrossCameraReport {
    config: CrossCameraConfig,
    requested_margin: u32,
    left: Vec<CameraObservation>,
    right: Vec<CameraObservation>,
    candidates: Vec<CrossCameraCandidate>,
    left_dispositions: Vec<AssociationDisposition>,
    right_dispositions: Vec<AssociationDisposition>,
    alternatives: Vec<CrossCameraAlternative>,
    assignment_cost: u64,
    effective_margin: u64,
}

impl CrossCameraReport {
    /// Exact caller-supplied time, geometry and score gates.
    pub fn config(&self) -> &CrossCameraConfig {
        &self.config
    }
    /// Requested global margin before the explicit quantization guard.
    pub fn requested_margin(&self) -> u32 {
        self.requested_margin
    }
    /// Complete left input, sorted by camera-local track ID.
    pub fn left(&self) -> &[CameraObservation] {
        &self.left
    }
    /// Complete right input, sorted by camera-local track ID.
    pub fn right(&self) -> &[CameraObservation] {
        &self.right
    }
    /// Complete Cartesian candidate table, including rejected edges.
    pub fn candidates(&self) -> &[CrossCameraCandidate] {
        &self.candidates
    }
    /// Outcome for every original left observation.
    pub fn left_dispositions(&self) -> &[AssociationDisposition] {
        &self.left_dispositions
    }
    /// Outcome for every original right observation.
    pub fn right_dispositions(&self) -> &[AssociationDisposition] {
        &self.right_dispositions
    }
    /// Competing solutions for every ambiguous selected edge.
    pub fn alternatives(&self) -> &[CrossCameraAlternative] {
        &self.alternatives
    }
    /// Global integer objective: left count * scale minus sum of selected score units.
    pub fn assignment_cost(&self) -> u64 {
        self.assignment_cost
    }
    /// Requested global margin plus one rounding-error guard unit per left row.
    pub fn effective_margin(&self) -> u64 {
        self.effective_margin
    }
    /// Copies only stable pairs, even when a different component is ambiguous.
    /// These are conditional associations, not physical identity or effect authority.
    pub fn stable_pairs(
        &self,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Vec<AssociatedPair>, CrossCameraError> {
        global::pairs(self, budget)
    }
    /// Whether at least one selected pair cannot be resolved inside this margin.
    pub fn is_ambiguous(&self) -> bool {
        !self.alternatives.is_empty()
    }
}

/// Compatibility API using global assignment and a zero requested ambiguity margin.
/// Ties (including quantization uncertainty) return `AmbiguousAssignment`, never
/// arbitrary pairs or an empty success. Use `associate_detailed` to retain partial
/// stable matches alongside alternatives and unresolved observations. Returned
/// pairs are in stable left-track order; unmatched tracks do not prove absence.
pub fn associate(
    config: &CrossCameraConfig,
    left: &[CameraObservation],
    right: &[CameraObservation],
) -> Result<Vec<AssociatedPair>, CrossCameraError> {
    let mut budget = WorkBudget::new(DEFAULT_ASSOCIATION_WORK);
    let report = associate_detailed(config, 0, left, right, &mut budget)?;
    if report.is_ambiguous() {
        return Err(CrossCameraError::AmbiguousAssignment);
    }
    report.stable_pairs(&mut budget)
}

#[cfg(test)]
mod tests;
