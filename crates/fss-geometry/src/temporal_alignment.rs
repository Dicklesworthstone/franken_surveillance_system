#![forbid(unsafe_code)]
//! Finite clock-offset hypotheses for an already-associated moving feature.
//!
//! The reference camera fixes the clock gauge. For each explicitly supplied
//! offset, target times are mapped by `reference = target - offset`, then the
//! existing native motion fitter and full-interval validator are run. No best
//! score removes an alternative. A failed numerical fit is unresolved, not a
//! proof that its offset is impossible. A single surviving sampled hypothesis
//! does not establish a unique continuous offset or authorize clock activation.
//!
//! Training times remain nominal caller inputs. Validation intervals are shifted
//! exactly, never collapsed to midpoints. Validation observations do not fit the
//! trajectory, but they DO constrain this search and are not an independent test
//! of the selected clock hypothesis. Constant offset excludes drift, rolling
//! shutter, acceleration, camera uncertainty and incorrect feature association.

use crate::temporal_triangulation::{
    MAX_TEMPORAL_SPAN_NS, MAX_TEMPORAL_VIEWS, TemporalTriangulationError,
    TemporalTriangulationOptions, TimedCalibratedView,
};
use crate::temporal_validation::{
    IntervalCalibratedView, MotionValidation, TemporalValidationError,
    triangulate_motion_validated,
};
use crate::triangulation::CalibratedView;
use crate::{GeometryError, WorkBudget};

/// Hard bound on the COMPLETE explicit offset hypothesis inventory.
pub const MAX_CLOCK_OFFSET_HYPOTHESES: usize = 64;

/// Two fixed cameras with distinct explicitly named source clock generations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockAlignmentPair {
    /// Nonzero camera whose local clock is the output reference axis.
    pub reference_camera: u64,
    /// Nonzero different camera whose capture times need an offset hypothesis.
    pub target_camera: u64,
    /// Nonzero owner-resolved reference clock generation, not an authentication claim.
    pub reference_clock: u64,
    /// Nonzero different target clock generation. A reset requires new input scope.
    pub target_clock: u64,
}

/// Complete result of one hypothesis, including explicit numerical refusals.
#[derive(Clone, Debug, PartialEq)]
pub struct ClockOffsetTrial {
    /// Target minus reference time, in exact signed integer nanoseconds.
    pub target_minus_reference_ns: i128,
    /// Native fit and complete validation inventory, or an unresolved fit refusal.
    /// Resource/cancellation and malformed-input errors never become trial results.
    pub result: Result<MotionValidation, TemporalValidationError>,
    /// Work consumed by this trial, from the shared, nonrefillable caller budget.
    pub work_units: u64,
}

impl ClockOffsetTrial {
    /// Conditional support from every validation interval, not a clock certificate.
    pub fn consistent_for_all_capture_times(&self) -> bool {
        self.result
            .as_ref()
            .is_ok_and(MotionValidation::consistent_for_all_capture_times)
    }
}

/// Complete finite search in ascending offset order. No winner is chosen.
#[derive(Clone, Debug, PartialEq)]
pub struct ClockAlignmentScan {
    /// Exact camera/clock gauge supplied by the caller.
    pub pair: ClockAlignmentPair,
    /// Every requested hypothesis, including ambiguous, contradicted and unresolved trials.
    pub trials: Vec<ClockOffsetTrial>,
    /// Admission, mapping and all native solver work charged by this invocation.
    pub work_units: u64,
}

/// A whole-scan refusal never returns a successful prefix of hypotheses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockAlignmentError {
    /// Geometry work, allocation or cancellation failed.
    Geometry(GeometryError),
    /// Camera/clock IDs are zero, equal, or not members of the selected pair.
    InvalidPair,
    /// An observation is malformed or changes a fixed camera's pose/intrinsics.
    InvalidObservation,
    /// At least three training and one validation observation per camera are required.
    InsufficientEvidence,
    /// Repeated training timestamps, overlapping validation intervals or fit/validation reuse.
    ReusedObservation,
    /// Empty, duplicate, or out-of-range offsets; absolute offsets may not exceed sixty seconds.
    InvalidOffsets,
    /// An exact target-to-reference integer timestamp conversion overflowed.
    TimestampOverflow,
    /// Native solver options or structural admission failed.
    Native(TemporalValidationError),
}

impl From<GeometryError> for ClockAlignmentError {
    fn from(error: GeometryError) -> Self {
        Self::Geometry(error)
    }
}
impl std::fmt::Display for ClockAlignmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Geometry(_) => "clock alignment geometry or work failure",
            Self::InvalidPair => "invalid clock alignment camera or clock pair",
            Self::InvalidObservation => "invalid or changed clock alignment camera observation",
            Self::InsufficientEvidence => "clock alignment needs training and validation per camera",
            Self::ReusedObservation => "clock alignment observation membership overlaps",
            Self::InvalidOffsets => "invalid finite clock offset inventory",
            Self::TimestampOverflow => "clock alignment timestamp overflow",
            Self::Native(_) => "clock alignment native admission refused",
        })
    }
}
impl std::error::Error for ClockAlignmentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Geometry(error) => Some(error),
            Self::Native(error) => Some(error),
            _ => None,
        }
    }
}

/// Search a COMPLETE explicit set of constant clock offsets with native motion fits.
///
/// Observations use their own camera's local capture clock. Input membership must
/// already represent one physical feature in one qualified world/image frame;
/// this function performs neither association nor calibration activation.
///
/// The caller's same work budget spans preflight and every trial. Complexity is
/// O((N+H)^2 + K*(native_fit(N)+H*N)); scratch/result storage is O(K*(N+H)), with
/// K <= 64 and N,H <= 128. Cancellation, exhausted work or allocation failure
/// refuses the entire search, even after a promising earlier candidate. Static
/// features can support many offsets; all such alternatives remain in the result.
pub fn scan_clock_offsets(
    pair: ClockAlignmentPair,
    training: &[TimedCalibratedView],
    validation: &[IntervalCalibratedView],
    offsets_ns: &[i128],
    options: TemporalTriangulationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<ClockAlignmentScan, ClockAlignmentError> {
    budget.charge(0)?;
    let started_work = budget.used();
    if pair.reference_camera == 0
        || pair.target_camera == 0
        || pair.reference_camera == pair.target_camera
        || pair.reference_clock == 0
        || pair.target_clock == 0
        || pair.reference_clock == pair.target_clock
    {
        return Err(ClockAlignmentError::InvalidPair);
    }
    if training.len() > MAX_TEMPORAL_VIEWS
        || validation.len() > MAX_TEMPORAL_VIEWS
        || offsets_ns.len() > MAX_CLOCK_OFFSET_HYPOTHESES
    {
        return Err(GeometryError::LimitExceeded.into());
    }
    if offsets_ns.is_empty()
        || offsets_ns.iter().any(|offset| {
            !(-MAX_TEMPORAL_SPAN_NS..=MAX_TEMPORAL_SPAN_NS).contains(offset)
        })
    {
        return Err(ClockAlignmentError::InvalidOffsets);
    }
    budget.charge(256 * (training.len() + validation.len() + offsets_ns.len()) as u64)?;
    let mut offsets = copy_bounded(offsets_ns)?;
    offsets.sort_unstable();
    if offsets.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ClockAlignmentError::InvalidOffsets);
    }
    validate_membership(pair, training, validation, budget)?;
    // Check EVERY integer mapping before running any solver. A bad late hypothesis
    // cannot turn an earlier fitting result into an apparently complete search.
    for offset in &offsets {
        budget.charge((training.len() + 2 * validation.len()) as u64)?;
        for item in training {
            map_time(pair, item.view.camera, item.capture_time_ns, *offset)?;
        }
        for item in validation {
            for time in item.capture_interval_ns {
                map_time(pair, item.view.camera, time, *offset)?;
            }
        }
    }
    let mut trials = Vec::new();
    trials.try_reserve_exact(offsets.len()).map_err(|_| GeometryError::LimitExceeded)?;
    for offset in offsets {
        let trial_started = budget.used();
        budget.charge(64 * (training.len() + validation.len()) as u64)?;
        let mut mapped_training = copy_bounded(training)?;
        let mut mapped_validation = copy_bounded(validation)?;
        for item in &mut mapped_training {
            item.capture_time_ns = map_time(pair, item.view.camera, item.capture_time_ns, offset)?;
        }
        for item in &mut mapped_validation {
            for time in &mut item.capture_interval_ns {
                *time = map_time(pair, item.view.camera, *time, offset)?;
            }
        }
        let result = triangulate_motion_validated(
            &mapped_training, &mapped_validation, options, budget,
        );
        if let Err(error) = result.as_ref() {
            match *error {
                TemporalValidationError::Geometry(GeometryError::BudgetExhausted
                    | GeometryError::Cancelled | GeometryError::LimitExceeded)
                | TemporalValidationError::Fit(TemporalTriangulationError::Geometry(
                    GeometryError::BudgetExhausted | GeometryError::Cancelled
                    | GeometryError::LimitExceeded)) => {
                    return Err(ClockAlignmentError::Native(*error));
                }
                TemporalValidationError::EmptyHoldout
                | TemporalValidationError::InvalidHoldout
                | TemporalValidationError::OverlappingHoldouts
                | TemporalValidationError::HoldoutLeak
                | TemporalValidationError::Fit(TemporalTriangulationError::InvalidOptions
                    | TemporalTriangulationError::InvalidObservation
                    | TemporalTriangulationError::DuplicateObservation
                    | TemporalTriangulationError::InsufficientObservations
                    | TemporalTriangulationError::InsufficientCameras) => {
                    return Err(ClockAlignmentError::Native(*error));
                }
                // Nonconvergence, weak geometry, no consensus and inadmissible time
                // windows remain explicit unresolved trials, never impossible offsets.
                _ => {}
            }
        }
        trials.push(ClockOffsetTrial {
            target_minus_reference_ns: offset,
            result,
            work_units: budget.used() - trial_started,
        });
    }
    budget.charge(0)?;
    Ok(ClockAlignmentScan { pair, trials, work_units: budget.used() - started_work })
}

fn copy_bounded<T: Copy>(items: &[T]) -> Result<Vec<T>, GeometryError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(items.len()).map_err(|_| GeometryError::LimitExceeded)?;
    copy.extend_from_slice(items);
    Ok(copy)
}

fn map_time(pair: ClockAlignmentPair, camera: u64, time: i128, offset: i128)
    -> Result<i128, ClockAlignmentError>
{
    if camera == pair.target_camera {
        time.checked_sub(offset).ok_or(ClockAlignmentError::TimestampOverflow)
    } else {
        Ok(time)
    }
}

fn validate_membership(
    pair: ClockAlignmentPair,
    training: &[TimedCalibratedView],
    validation: &[IntervalCalibratedView],
    budget: &mut WorkBudget<'_>,
) -> Result<(), ClockAlignmentError> {
    let mut cameras: [Option<CalibratedView>; 2] = [None, None];
    let mut counts = [[0_usize; 2]; 2];
    for (is_validation, view) in training.iter().map(|row| (false, row.view))
        .chain(validation.iter().map(|row| (true, row.view)))
    {
        budget.charge(32)?;
        let camera = if view.camera == pair.reference_camera { 0 }
            else if view.camera == pair.target_camera { 1 }
            else { return Err(ClockAlignmentError::InvalidPair); };
        if !view.intrinsics.contains(view.pixel) || !view.sigma_pixels.is_finite()
            || !(1e-3..=1e3).contains(&view.sigma_pixels)
        {
            return Err(ClockAlignmentError::InvalidObservation);
        }
        if let Some(original) = cameras[camera] {
            if original.pose != view.pose || original.intrinsics != view.intrinsics {
                return Err(ClockAlignmentError::InvalidObservation);
            }
        } else {
            cameras[camera] = Some(view);
        }
        counts[camera][usize::from(is_validation)] += 1;
    }
    if counts.iter().any(|count| count[0] < 3 || count[1] == 0) {
        return Err(ClockAlignmentError::InsufficientEvidence);
    }
    for (index, item) in training.iter().enumerate() {
        for prior in &training[..index] {
            budget.charge(1)?;
            if prior.view.camera == item.view.camera && prior.capture_time_ns == item.capture_time_ns {
                return Err(ClockAlignmentError::ReusedObservation);
            }
        }
    }
    for (index, item) in validation.iter().enumerate() {
        let [lo, hi] = item.capture_interval_ns;
        if !hi.checked_sub(lo).is_some_and(|span| (0..=MAX_TEMPORAL_SPAN_NS).contains(&span)) {
            return Err(ClockAlignmentError::InvalidObservation);
        }
        for fitted in training {
            budget.charge(1)?;
            if fitted.view.camera == item.view.camera && (lo..=hi).contains(&fitted.capture_time_ns) {
                return Err(ClockAlignmentError::ReusedObservation);
            }
        }
        for prior in &validation[..index] {
            budget.charge(1)?;
            if prior.view.camera == item.view.camera && prior.capture_interval_ns[0] <= hi
                && lo <= prior.capture_interval_ns[1]
            {
                return Err(ClockAlignmentError::ReusedObservation);
            }
        }
    }
    Ok(())
}
