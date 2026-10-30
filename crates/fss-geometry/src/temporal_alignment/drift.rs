#![forbid(unsafe_code)]
//! Finite affine clock hypotheses, not clock activation or continuous estimation.
//!
//! `skew_ppb` describes target ticks per reference tick minus one, in parts per
//! billion. At the declared target anchor, target minus reference is `offset_ns`.
//! The exact mapping is anchor - offset + (target - anchor) * 1e9 / (1e9 + skew).
//! Only checked relative integers enter this calculation. Validation intervals
//! round outward; nominal training times round to nearest, with ties to earlier.
//! Every training rounding envelope is retained and is NOT fit covariance.

use super::{
    ClockAlignmentError, ClockAlignmentPair, MAX_CLOCK_OFFSET_HYPOTHESES, copy_bounded,
    validate_membership,
};
use crate::temporal_triangulation::{
    MAX_TEMPORAL_SPAN_NS, MAX_TEMPORAL_VIEWS, TemporalTriangulationError,
    TemporalTriangulationOptions, TimedCalibratedView,
};
use crate::temporal_validation::{
    IntervalCalibratedView, MotionValidation, TemporalValidationError,
    triangulate_motion_validated,
};
use crate::{GeometryError, WorkBudget};

const SCALE: i128 = 1_000_000_000;
/// Reference profile admits at most 1000 ppm of either sign, not arbitrary clocks.
pub const MAX_CLOCK_SKEW_PPB: i64 = 1_000_000;

/// One explicitly requested affine mapping, ordered by offset then skew.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ClockRateHypothesis {
    /// Target minus reference at `target_anchor_ns`, bounded to +/- sixty seconds.
    pub offset_ns: i128,
    /// Target ticks per reference tick minus one, in parts per billion.
    pub skew_ppb: i64,
}

/// Exact rational mapping enclosed in integer nanoseconds, with a nominal point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappedClockTime {
    /// Nearest integer time; exact half-nanosecond ties choose the earlier integer.
    pub nominal_ns: i128,
    /// Floor and ceiling of the exact rational time. Width is zero or one ns.
    pub enclosure_ns: [i128; 2],
}

impl ClockRateHypothesis {
    fn validate(self) -> Result<(), ClockDriftError> {
        if !(-MAX_TEMPORAL_SPAN_NS..=MAX_TEMPORAL_SPAN_NS).contains(&self.offset_ns)
            || !(-MAX_CLOCK_SKEW_PPB..=MAX_CLOCK_SKEW_PPB).contains(&self.skew_ppb)
        {
            return Err(ClockDriftError::InvalidHypotheses);
        }
        Ok(())
    }

    /// Maps a target timestamp within sixty seconds of the declared target anchor.
    /// No absolute timestamp is converted to floating point; overflow is refusal.
    pub fn map_time(
        self,
        target_anchor_ns: i128,
        target_time_ns: i128,
    ) -> Result<MappedClockTime, ClockDriftError> {
        self.validate()?;
        let delta = target_time_ns
            .checked_sub(target_anchor_ns)
            .filter(|v| (-MAX_TEMPORAL_SPAN_NS..=MAX_TEMPORAL_SPAN_NS).contains(v))
            .ok_or(ClockDriftError::OutsideAnchorWindow)?;
        let denominator = SCALE + i128::from(self.skew_ppb);
        // The delta bound makes this product fit i128; checked math keeps that
        // safety property explicit if this profile's bounds ever change.
        let numerator = delta.checked_mul(SCALE).ok_or(ClockDriftError::TimestampOverflow)?;
        let quotient = numerator.div_euclid(denominator);
        let remainder = numerator.rem_euclid(denominator);
        let reference_anchor = target_anchor_ns.checked_sub(self.offset_ns)
            .ok_or(ClockDriftError::TimestampOverflow)?;
        let lower = reference_anchor.checked_add(quotient)
            .ok_or(ClockDriftError::TimestampOverflow)?;
        let upper = lower.checked_add(i128::from(remainder != 0))
            .ok_or(ClockDriftError::TimestampOverflow)?;
        Ok(MappedClockTime {
            nominal_ns: if remainder * 2 > denominator { upper } else { lower },
            enclosure_ns: [lower, upper],
        })
    }

    /// Encloses the ENTIRE inclusive interval. A positive rate makes endpoint
    /// mapping sufficient; no midpoint, inward rounding or range clipping occurs.
    pub fn map_interval(
        self,
        target_anchor_ns: i128,
        interval_ns: [i128; 2],
    ) -> Result<[i128; 2], ClockDriftError> {
        if interval_ns[0] > interval_ns[1] {
            return Err(ClockDriftError::InvalidInterval);
        }
        Ok([
            self.map_time(target_anchor_ns, interval_ns[0])?.enclosure_ns[0],
            self.map_time(target_anchor_ns, interval_ns[1])?.enclosure_ns[1],
        ])
    }
}

/// Original local time and exact rational enclosure for every training observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockTrainingMapping {
    /// Logical camera ID, not an independence or authentication assertion.
    pub camera: u64,
    /// Unchanged source-clock timestamp.
    pub local_time_ns: i128,
    /// Time actually supplied to the nominal motion fit and its rounding enclosure.
    pub mapped: MappedClockTime,
}

/// Every sampled rate/offset trial survives, including numerical refusals.
#[derive(Clone, Debug, PartialEq)]
pub struct ClockRateTrial {
    /// Exact requested mapping parameters.
    pub hypothesis: ClockRateHypothesis,
    /// Canonical camera/local-time membership, including training rounding bounds.
    pub training_mappings: Vec<ClockTrainingMapping>,
    /// Conditional fit and complete interval diagnostics, or an unresolved refusal.
    pub result: Result<MotionValidation, TemporalValidationError>,
    /// Units consumed by this trial from the shared caller budget.
    pub work_units: u64,
}
impl ClockRateTrial {
    /// Conditional support for this sampled mapping, never total timing accuracy.
    pub fn consistent_for_all_capture_times(&self) -> bool {
        self.result.as_ref().is_ok_and(MotionValidation::consistent_for_all_capture_times)
    }
}

/// Complete finite rate inventory, not a selected or activated clock model.
#[derive(Clone, Debug, PartialEq)]
pub struct ClockDriftScan {
    /// Camera and clock generation scope, with the reference camera fixing the gauge.
    pub pair: ClockAlignmentPair,
    /// Exact target-clock anchor shared by every hypothesis.
    pub target_anchor_ns: i128,
    /// Complete inventory in ascending (offset, skew) order; no best-score pruning.
    pub trials: Vec<ClockRateTrial>,
    /// Admission, mappings and all native fits charged by this invocation.
    pub work_units: u64,
}

/// Whole-scan admission/resource failure: no successful prefix is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockDriftError {
    /// Existing geometry budget, allocation or cancellation refusal.
    Geometry(GeometryError),
    /// Invalid camera/clock scope, camera changes or original evidence reuse.
    Alignment(ClockAlignmentError),
    /// Empty, duplicate or out-of-range requested rate/offset inventory.
    InvalidHypotheses,
    /// A local target timestamp is outside the sixty-second anchor neighborhood.
    OutsideAnchorWindow,
    /// A checked signed timestamp calculation cannot be represented.
    TimestampOverflow,
    /// An interval's earliest endpoint follows its latest endpoint.
    InvalidInterval,
    /// Native resource failure or invalid fit policy refuses the entire scan.
    Native(TemporalValidationError),
}
impl From<GeometryError> for ClockDriftError {
    fn from(error: GeometryError) -> Self { Self::Geometry(error) }
}
impl From<ClockAlignmentError> for ClockDriftError {
    fn from(error: ClockAlignmentError) -> Self { Self::Alignment(error) }
}
impl std::fmt::Display for ClockDriftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Geometry(_) => "clock drift geometry or work refusal",
            Self::Alignment(_) => "clock drift camera or evidence admission refused",
            Self::InvalidHypotheses => "invalid finite rate and offset inventory",
            Self::OutsideAnchorWindow => "target time outside clock anchor window",
            Self::TimestampOverflow => "clock drift timestamp overflow",
            Self::InvalidInterval => "reversed clock interval",
            Self::Native(_) => "clock drift native policy or work refusal",
        })
    }
}
impl std::error::Error for ClockDriftError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Geometry(error) => Some(error),
            Self::Alignment(error) => Some(error),
            Self::Native(error) => Some(error),
            _ => None,
        }
    }
}

/// Evaluate every requested affine clock hypothesis without activating any of them.
///
/// Exact input membership is checked before mapping; rounding-induced collisions
/// remain unresolved trial refusals rather than being deduplicated. Validation
/// times are conservatively enclosed, while training remains an explicitly nominal
/// fit. Clock, camera, association and rounding uncertainty is not fit covariance.
/// Validation participates in the search and is NOT independent qualification of
/// a selected clock. Complexity/scratch have the constant-offset scan's bounds.
pub fn scan_clock_drift(
    pair: ClockAlignmentPair,
    target_anchor_ns: i128,
    training: &[TimedCalibratedView],
    validation: &[IntervalCalibratedView],
    hypotheses: &[ClockRateHypothesis],
    options: TemporalTriangulationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<ClockDriftScan, ClockDriftError> {
    budget.charge(0)?;
    let started = budget.used();
    if training.len() > MAX_TEMPORAL_VIEWS || validation.len() > MAX_TEMPORAL_VIEWS
        || hypotheses.len() > MAX_CLOCK_OFFSET_HYPOTHESES
    {
        return Err(GeometryError::LimitExceeded.into());
    }
    if pair.reference_camera == 0 || pair.target_camera == 0
        || pair.reference_camera == pair.target_camera || pair.reference_clock == 0
        || pair.target_clock == 0 || pair.reference_clock == pair.target_clock
    {
        return Err(ClockAlignmentError::InvalidPair.into());
    }
    if hypotheses.is_empty() { return Err(ClockDriftError::InvalidHypotheses); }
    budget.charge(256 * (training.len() + validation.len() + hypotheses.len()) as u64)?;
    let mut ordered = copy_bounded(hypotheses)?;
    ordered.sort_unstable();
    if ordered.windows(2).any(|rows| rows[0] == rows[1]) {
        return Err(ClockDriftError::InvalidHypotheses);
    }
    validate_membership(pair, training, validation, budget)?;
    // Check the COMPLETE mapping inventory before any fitting result is admitted.
    for hypothesis in &ordered {
        hypothesis.validate()?;
        budget.charge(16 * (training.len() + 2 * validation.len()) as u64)?;
        for item in training.iter().filter(|item| item.view.camera == pair.target_camera) {
            hypothesis.map_time(target_anchor_ns, item.capture_time_ns)?;
        }
        for item in validation.iter().filter(|item| item.view.camera == pair.target_camera) {
            hypothesis.map_interval(target_anchor_ns, item.capture_interval_ns)?;
        }
    }
    let mut trials = Vec::new();
    trials.try_reserve_exact(ordered.len()).map_err(|_| GeometryError::LimitExceeded)?;
    for hypothesis in ordered {
        let trial_started = budget.used();
        budget.charge(128 * (training.len() + validation.len()) as u64)?;
        let mut mapped_training = copy_bounded(training)?;
        mapped_training.sort_by_key(|item| (item.view.camera, item.capture_time_ns));
        let mut mapped_validation = copy_bounded(validation)?;
        let mut training_mappings = Vec::new();
        training_mappings.try_reserve_exact(training.len()).map_err(|_| GeometryError::LimitExceeded)?;
        for item in &mut mapped_training {
            let local_time_ns = item.capture_time_ns;
            let mapped = if item.view.camera == pair.target_camera {
                hypothesis.map_time(target_anchor_ns, local_time_ns)?
            } else {
                MappedClockTime { nominal_ns: local_time_ns, enclosure_ns: [local_time_ns; 2] }
            };
            item.capture_time_ns = mapped.nominal_ns;
            training_mappings.push(ClockTrainingMapping { camera: item.view.camera, local_time_ns, mapped });
        }
        for item in &mut mapped_validation {
            if item.view.camera == pair.target_camera {
                item.capture_interval_ns = hypothesis.map_interval(target_anchor_ns, item.capture_interval_ns)?;
            }
        }
        let result = triangulate_motion_validated(&mapped_training, &mapped_validation, options, budget);
        if let Err(error) = result.as_ref() {
            match *error {
                TemporalValidationError::Geometry(GeometryError::BudgetExhausted
                    | GeometryError::Cancelled | GeometryError::LimitExceeded)
                | TemporalValidationError::Fit(TemporalTriangulationError::Geometry(
                    GeometryError::BudgetExhausted | GeometryError::Cancelled | GeometryError::LimitExceeded))
                | TemporalValidationError::Fit(TemporalTriangulationError::InvalidOptions) => {
                    return Err(ClockDriftError::Native(*error));
                }
                // Rounding collisions, range failures and numerical refusals are
                // hypothesis-dependent and remain in the complete inventory.
                _ => {}
            }
        }
        trials.push(ClockRateTrial { hypothesis, training_mappings, result,
            work_units: budget.used() - trial_started });
    }
    budget.charge(0)?;
    Ok(ClockDriftScan { pair, target_anchor_ns, trials, work_units: budget.used() - started })
}
