#![forbid(unsafe_code)]
//! Held-out reprojection checks over complete capture-time intervals.
//!
//! A fixed camera maps a front-facing straight trajectory segment to an image
//! segment. Endpoint residuals give its maximum; the closest point on that image
//! segment gives its minimum. No sampled midpoint or best timestamp replaces the
//! interval. These checks are conditional on the nominal fitted trajectory, not
//! a bound on calibration, association, motion-model or shared clock errors.

use crate::temporal_triangulation::{
    MAX_TEMPORAL_SPAN_NS, MAX_TEMPORAL_VIEWS, TemporalTriangulationError,
    TemporalTriangulationOptions, TimedCalibratedView, TriangulatedMotion, triangulate_motion,
};
use crate::triangulation::CalibratedView;
use crate::{GeometryError, WorkBudget};

/// An observation reserved for validation, never used to estimate the trajectory.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct IntervalCalibratedView {
    /// Qualified undistorted image observation and camera fixed throughout the interval.
    pub view: CalibratedView,
    /// Inclusive [earliest, latest] capture times in the fit's common signed clock.
    /// No distribution, independence or most-likely instant is implied.
    pub capture_interval_ns: [i128; 2],
}

/// An entire interval's relationship to the explicit Euclidean reprojection gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemporalCompatibility {
    /// Every modeled capture time satisfies the gate, conditional on the fixed fit.
    ConsistentForAllTimes,
    /// Some modeled times satisfy the gate and others do not, or rounding straddles it.
    TimingAmbiguous,
    /// No modeled capture time satisfies the gate.
    Inconsistent,
}

/// Why a full interval cannot supply an observable validation constraint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemporalVisibilityRefusal {
    /// At least one endpoint is at or behind the camera's near plane.
    BehindCamera,
    /// At least one endpoint exceeds the explicit camera-distance limit.
    BeyondDistance,
    /// At least one endpoint projects outside the declared half-open image domain.
    OutsideImage,
}

/// Either complete conditional residual diagnostics or an explicit visibility refusal.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TemporalValidationOutcome {
    /// Both endpoints and the intervening modeled image segment are observable.
    Observable {
        /// Pixel-edge coordinates at the earliest and latest capture times.
        projected_endpoints: [[f64; 2]; 2],
        /// Minimum and maximum residual, expanded by a scale-aware rounding margin.
        /// This is not a confidence interval or a total physical-error bound.
        residual_bounds_pixels: [f64; 2],
        /// Relationship of the full interval to the caller's residual gate.
        compatibility: TemporalCompatibility,
    },
    /// The full interval fails an observability precondition; it is never clipped.
    NotObservable(TemporalVisibilityRefusal),
}

/// Every holdout is retained in canonical camera/interval order, including failures.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TemporalValidationCheck {
    /// Logical camera identity, not an independent failure-domain certificate.
    pub camera: u64,
    /// Original complete inclusive capture-time interval.
    pub capture_interval_ns: [i128; 2],
    /// Full-interval diagnostics without optimizing away timing uncertainty.
    pub outcome: TemporalValidationOutcome,
}

/// Nominal fit and separate held-out constraints; failed checks never refit the data.
#[derive(Clone, Debug, PartialEq)]
pub struct MotionValidation {
    /// Fit made only from the supplied training observations.
    pub fit: TriangulatedMotion,
    /// Complete holdout inventory, including ambiguous/inconsistent/unobservable rows.
    pub checks: Vec<TemporalValidationCheck>,
}

impl MotionValidation {
    /// Whether every holdout satisfies the gate for all of its modeled times.
    /// This grants neither identity, calibration/clock validity nor effect authority.
    pub fn consistent_for_all_capture_times(&self) -> bool {
        !self.checks.is_empty()
            && self.checks.iter().all(|check| {
                matches!(
                    check.outcome,
                    TemporalValidationOutcome::Observable {
                        compatibility: TemporalCompatibility::ConsistentForAllTimes,
                        ..
                    }
                )
            })
    }
}

/// Admission/work failures return no partial fit or partial validation inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemporalValidationError {
    /// The nominal training fit refused its data or resource budget.
    Fit(TemporalTriangulationError),
    /// Geometry, allocation, work or cancellation failed.
    Geometry(GeometryError),
    /// An empty holdout set cannot establish validation.
    EmptyHoldout,
    /// A camera, pixel, noise assumption or capture interval is invalid.
    InvalidHoldout,
    /// Intervals from the same camera overlap, so distinct observation membership is unclear.
    OverlappingHoldouts,
    /// A holdout interval contains a training timestamp from the same camera.
    HoldoutLeak,
    /// Validation would extrapolate beyond the observed nominal fitting window.
    OutsideFitWindow,
}

impl From<GeometryError> for TemporalValidationError {
    fn from(error: GeometryError) -> Self {
        Self::Geometry(error)
    }
}
impl From<TemporalTriangulationError> for TemporalValidationError {
    fn from(error: TemporalTriangulationError) -> Self {
        Self::Fit(error)
    }
}
impl std::fmt::Display for TemporalValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Fit(_) => "temporal training fit refused",
            Self::Geometry(_) => "temporal validation geometry or work failure",
            Self::EmptyHoldout => "temporal validation needs held-out observations",
            Self::InvalidHoldout => "invalid temporal holdout observation or interval",
            Self::OverlappingHoldouts => "same-camera holdout intervals overlap",
            Self::HoldoutLeak => "temporal validation reuses fitting evidence",
            Self::OutsideFitWindow => "temporal holdout exceeds the fitted observation window",
        })
    }
}
impl std::error::Error for TemporalValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Fit(error) => Some(error),
            Self::Geometry(error) => Some(error),
            _ => None,
        }
    }
}

/// Fit training observations, then check independent-in-membership holdouts over
/// their complete capture intervals. Input order fixes neither a chosen time nor
/// an identity. No holdout contributes to the fit or shrinks its covariance.
///
/// Beyond the fit's own cost, admission is O(H log H + H N), reprojection O(H)
/// and scratch O(H), with H,N <= 128. Every phase charges the same caller budget.
/// All intervals must lie within the fitted window. Missing visibility, ambiguous
/// timing and contradictory measurements remain explicit rows, not dropped data.
/// Camera/time non-overlap alone does not prove statistical or source independence.
pub fn triangulate_motion_validated(
    training: &[TimedCalibratedView],
    holdouts: &[IntervalCalibratedView],
    options: TemporalTriangulationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<MotionValidation, TemporalValidationError> {
    budget.charge(0)?;
    if training.len() > MAX_TEMPORAL_VIEWS || holdouts.len() > MAX_TEMPORAL_VIEWS {
        return Err(GeometryError::LimitExceeded.into());
    }
    if holdouts.is_empty() {
        return Err(TemporalValidationError::EmptyHoldout);
    }
    budget.charge(256 * holdouts.len() as u64)?;
    let mut ordered = Vec::new();
    ordered
        .try_reserve_exact(holdouts.len())
        .map_err(|_| GeometryError::LimitExceeded)?;
    ordered.extend_from_slice(holdouts);
    ordered.sort_by_key(|item| (item.view.camera, item.capture_interval_ns));
    for (index, item) in ordered.iter().enumerate() {
        let [earliest, latest] = item.capture_interval_ns;
        if item.view.camera == 0
            || !item.view.intrinsics.contains(item.view.pixel)
            || !item.view.sigma_pixels.is_finite()
            || !(1e-3..=1e3).contains(&item.view.sigma_pixels)
            || !latest
                .checked_sub(earliest)
                .is_some_and(|span| (0..=MAX_TEMPORAL_SPAN_NS).contains(&span))
        {
            return Err(TemporalValidationError::InvalidHoldout);
        }
        if index > 0
            && ordered[index - 1].view.camera == item.view.camera
            && ordered[index - 1].capture_interval_ns[1] >= earliest
        {
            return Err(TemporalValidationError::OverlappingHoldouts);
        }
        for fitted in training {
            budget.charge(16)?;
            if fitted.view.camera == item.view.camera
                && (earliest..=latest).contains(&fitted.capture_time_ns)
            {
                return Err(TemporalValidationError::HoldoutLeak);
            }
        }
    }
    let fit = triangulate_motion(training, options, budget)?;
    let mut checks = Vec::new();
    checks
        .try_reserve_exact(ordered.len())
        .map_err(|_| GeometryError::LimitExceeded)?;
    for item in ordered {
        budget.charge(512)?;
        if item.capture_interval_ns[0] < fit.observed_time_range_ns[0]
            || item.capture_interval_ns[1] > fit.observed_time_range_ns[1]
        {
            return Err(TemporalValidationError::OutsideFitWindow);
        }
        checks.push(TemporalValidationCheck {
            camera: item.view.camera,
            capture_interval_ns: item.capture_interval_ns,
            outcome: check_interval(&fit, item, options)?,
        });
    }
    budget.charge(0)?;
    Ok(MotionValidation { fit, checks })
}

fn check_interval(
    fit: &TriangulatedMotion,
    item: IntervalCalibratedView,
    options: TemporalTriangulationOptions,
) -> Result<TemporalValidationOutcome, TemporalValidationError> {
    let mut endpoints = [[0.0; 3]; 2];
    for (point, time) in endpoints.iter_mut().zip(item.capture_interval_ns) {
        let offset = time
            .checked_sub(fit.reference_time_ns)
            .ok_or(TemporalValidationError::InvalidHoldout)?;
        let seconds = offset as f64 * 1e-9;
        let world = std::array::from_fn(|axis| {
            fit.position[axis] + fit.velocity_per_second[axis] * seconds
        });
        *point = item.view.pose.transform(world)?;
    }
    // Depth is affine and norm convex along a straight segment: endpoints cover
    // the entire interval for these two gates, rather than a finite time sample.
    if endpoints.iter().any(|point| point[2] <= 1e-9) {
        return Ok(TemporalValidationOutcome::NotObservable(
            TemporalVisibilityRefusal::BehindCamera,
        ));
    }
    if endpoints
        .iter()
        .any(|p| p[0].hypot(p[1]).hypot(p[2]) > options.max_distance)
    {
        return Ok(TemporalValidationOutcome::NotObservable(
            TemporalVisibilityRefusal::BeyondDistance,
        ));
    }
    let pixels = [
        item.view.intrinsics.project(endpoints[0])?,
        item.view.intrinsics.project(endpoints[1])?,
    ];
    if pixels
        .iter()
        .any(|pixel| !item.view.intrinsics.contains(*pixel))
    {
        return Ok(TemporalValidationOutcome::NotObservable(
            TemporalVisibilityRefusal::OutsideImage,
        ));
    }
    let delta = [pixels[1][0] - pixels[0][0], pixels[1][1] - pixels[0][1]];
    let toward = [
        item.view.pixel[0] - pixels[0][0],
        item.view.pixel[1] - pixels[0][1],
    ];
    let squared_length = delta[0] * delta[0] + delta[1] * delta[1];
    let along = if squared_length == 0.0 {
        0.0
    } else {
        ((toward[0] * delta[0] + toward[1] * delta[1]) / squared_length).clamp(0.0, 1.0)
    };
    let minimum = (toward[0] - along * delta[0]).hypot(toward[1] - along * delta[1]);
    let maximum = pixels
        .iter()
        .map(|p| (p[0] - item.view.pixel[0]).hypot(p[1] - item.view.pixel[1]))
        .fold(0.0_f64, f64::max);
    // Classify close floating-point boundary cases conservatively. This margin is
    // numerical caution, not a certificate of physical error or interval arithmetic.
    let scale = pixels
        .iter()
        .flatten()
        .chain(item.view.pixel.iter())
        .fold(1.0_f64, |scale, value| scale.max(value.abs()));
    let margin = 64.0 * f64::EPSILON * scale;
    let bounds = [(minimum - margin).max(0.0), maximum + margin];
    let compatibility = if bounds[1] <= options.max_reprojection_pixels {
        TemporalCompatibility::ConsistentForAllTimes
    } else if bounds[0] > options.max_reprojection_pixels {
        TemporalCompatibility::Inconsistent
    } else {
        TemporalCompatibility::TimingAmbiguous
    };
    Ok(TemporalValidationOutcome::Observable {
        projected_endpoints: pixels,
        residual_bounds_pixels: bounds,
        compatibility,
    })
}
