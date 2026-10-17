#![forbid(unsafe_code)]
//! Constant-velocity reconstruction of an already-associated physical feature.
//!
//! Unlike a simultaneous-point triangulation, this fit evaluates each camera at
//! that observation's own nominal capture time. Inputs must already share an
//! owner-resolved world frame and clock, undistorted image domains, and a qualified
//! common-feature association. This module neither estimates clock offsets nor
//! establishes identity, physical calibration, visibility, or evidence custody.
//!
//! The result is a conditional model fit, NOT a certificate of the motion model.
//! Covariance assumes independent isotropic pixel noise and exact input times and
//! poses. Camera, timestamp, correspondence, rolling-shutter, acceleration, and
//! shared-mode uncertainties must remain separate in any downstream admission.
//! In particular, an interval's midpoint must not silently become an exact time.

use crate::triangulation::CalibratedView;
use crate::{GeometryError, WorkBudget};

type V6 = [f64; 6];
type M6 = [[f64; 6]; 6];

/// Hard observation bound, including repeated observations of a camera.
pub const MAX_TEMPORAL_VIEWS: usize = 128;
/// Hard reference-window bound: sixty seconds, not a motion-validity guarantee.
pub const MAX_TEMPORAL_SPAN_NS: i128 = 60_000_000_000;
const MAX_ITERATIONS: usize = 32;
const MAX_BACKTRACKS: usize = 8;

/// An already-associated feature observation on an explicitly common time axis.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TimedCalibratedView {
    /// Image point, logical camera, qualified pose/intrinsics, and pixel noise.
    pub view: CalibratedView,
    /// Nominal capture time in nanoseconds, not packet receive time.
    /// The caller must retain any capture-interval/clock uncertainty separately.
    pub capture_time_ns: i128,
}

/// Explicit limits for a conditional constant-velocity fit.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TemporalTriangulationOptions {
    /// Maximum Euclidean residual of EVERY observation, in pixels; no silent outliers.
    pub max_reprojection_pixels: f64,
    /// Maximum distance from the observation-time point to its camera, in world units.
    pub max_distance: f64,
    /// Maximum fitted speed, in world units per second (world units need not be metres).
    pub max_speed: f64,
    /// Infinity-norm condition-number ceiling in centered, normalized-time coordinates.
    pub max_condition_number: f64,
    /// Bounded Gauss-Newton iterations; one through 32, with at most eight line-search trials.
    pub max_iterations: usize,
}

impl Default for TemporalTriangulationOptions {
    fn default() -> Self {
        Self {
            max_reprojection_pixels: 3.0,
            max_distance: 1000.0,
            max_speed: 20.0,
            max_condition_number: 1e10,
            max_iterations: 16,
        }
    }
}

/// No guessed trajectory is returned on refusal, work exhaustion, or cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemporalTriangulationError {
    /// Existing geometry validation, work accounting, or cooperative cancellation failed.
    Geometry(GeometryError),
    /// Fewer than four observations leave no residual degrees of freedom for this profile.
    InsufficientObservations,
    /// At least two distinct logical cameras are required by this reference profile.
    InsufficientCameras,
    /// Camera ID, image point, or pixel-noise assumption is invalid.
    InvalidObservation,
    /// The same camera and capture time was supplied twice.
    DuplicateObservation,
    /// Fit options are nonfinite or outside this profile's bounds.
    InvalidOptions,
    /// Timestamps have zero span, overflow their difference, or exceed sixty seconds.
    InvalidTimeSpan,
    /// The data cannot independently constrain position and velocity well enough.
    UnobservableMotion,
    /// A point is behind a camera, beyond the distance limit, or outside a residual gate.
    NoConsensus,
    /// The nominal fitted speed exceeds the explicit bound.
    SpeedLimit,
    /// Refinement did not converge within its finite iteration/line-search bounds.
    NotConverged,
}

impl From<GeometryError> for TemporalTriangulationError {
    fn from(error: GeometryError) -> Self {
        Self::Geometry(error)
    }
}

impl std::fmt::Display for TemporalTriangulationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Geometry(_) => "temporal triangulation geometry or work failure",
            Self::InsufficientObservations => "insufficient temporal observations",
            Self::InsufficientCameras => "temporal reconstruction needs distinct cameras",
            Self::InvalidObservation => "invalid temporal observation",
            Self::DuplicateObservation => "duplicate camera and capture time",
            Self::InvalidOptions => "invalid temporal triangulation options",
            Self::InvalidTimeSpan => "invalid or unbounded capture-time span",
            Self::UnobservableMotion => "position and velocity are not sufficiently observable",
            Self::NoConsensus => "temporal observations do not support the admitted trajectory",
            Self::SpeedLimit => "fitted speed exceeds the admitted bound",
            Self::NotConverged => "bounded temporal triangulation did not converge",
        })
    }
}

impl std::error::Error for TemporalTriangulationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Geometry(error) => Some(error),
            _ => None,
        }
    }
}

/// Every admitted observation remains in the result, in camera/time order.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TemporalResidual {
    /// Logical camera identity.
    pub camera: u64,
    /// Original nominal capture time, preserved as an exact integer.
    pub capture_time_ns: i128,
    /// Euclidean reprojection residual, in pixels.
    pub pixels: f64,
}

/// Conditional position/velocity fit, not an association or calibration certificate.
#[derive(Clone, Debug, PartialEq)]
pub struct TriangulatedMotion {
    /// Integer midpoint of the input time range, rounding toward its earliest endpoint.
    pub reference_time_ns: i128,
    /// Inclusive nominal input-time range; no extrapolation is certified.
    pub observed_time_range_ns: [i128; 2],
    /// World-space position at `reference_time_ns`.
    pub position: [f64; 3],
    /// World units per second, in the same coordinate frame as position.
    pub velocity_per_second: [f64; 3],
    /// Conditional first-order pixel-noise covariance of [position, velocity].
    /// Includes cross-covariances and residual-variance inflation, but NOT clock,
    /// camera, association, rolling-shutter, acceleration, or shared-mode errors.
    pub pixel_noise_covariance: [[f64; 6]; 6],
    /// Infinity-norm condition number before covariance inflation and time-unit conversion.
    pub normalized_condition_number: f64,
    /// Unweighted RMS of Euclidean pixel residuals across all observations.
    pub rms_reprojection_pixels: f64,
    /// Complete original camera/time membership and residuals, never a selected subset.
    pub residuals: Vec<TemporalResidual>,
}

struct Sample {
    input: TimedCalibratedView,
    tau: f64,
}

/// Reconstruct one moving feature from staggered calibrated camera observations.
///
/// A weighted bearing-line fit initializes position plus displacement over the
/// observed time span. Analytic, weighted pixel Gauss-Newton refinement then fits
/// the original image measurements. Centering world coordinates and converting
/// only checked relative integer timestamps avoids losing short intervals at a
/// large timestamp epoch. Camera/time sorting fixes arithmetic order.
///
/// Work is O(N (1 + I B)) and scratch O(N), with N <= 128, I <= 32, B <= 8;
/// six-dimensional solves have fixed size. Work is charged before loops, and no
/// partial result escapes an error. There is no I/O or durable format change.
pub fn triangulate_motion(
    observations: &[TimedCalibratedView],
    options: TemporalTriangulationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<TriangulatedMotion, TemporalTriangulationError> {
    budget.charge(0)?;
    validate_options(options)?;
    if observations.len() > MAX_TEMPORAL_VIEWS {
        return Err(GeometryError::LimitExceeded.into());
    }
    if observations.len() < 4 {
        return Err(TemporalTriangulationError::InsufficientObservations);
    }
    // This also prices validation, bounded allocation and canonical ordering.
    budget.charge(512 * observations.len() as u64)?;
    let mut ordered = Vec::new();
    ordered
        .try_reserve_exact(observations.len())
        .map_err(|_| GeometryError::LimitExceeded)?;
    ordered.extend_from_slice(observations);
    ordered.sort_by_key(|item| (item.view.camera, item.capture_time_ns));
    let mut cameras = 0;
    let mut earliest = ordered[0].capture_time_ns;
    let mut latest = earliest;
    for (index, item) in ordered.iter().enumerate() {
        if item.view.camera == 0
            || !item.view.intrinsics.contains(item.view.pixel)
            || !item.view.sigma_pixels.is_finite()
            || !(1e-3..=1e3).contains(&item.view.sigma_pixels)
        {
            return Err(TemporalTriangulationError::InvalidObservation);
        }
        if index == 0 || ordered[index - 1].view.camera != item.view.camera {
            cameras += 1;
        } else if ordered[index - 1].capture_time_ns == item.capture_time_ns {
            return Err(TemporalTriangulationError::DuplicateObservation);
        }
        earliest = earliest.min(item.capture_time_ns);
        latest = latest.max(item.capture_time_ns);
    }
    if cameras < 2 {
        return Err(TemporalTriangulationError::InsufficientCameras);
    }
    let span = latest
        .checked_sub(earliest)
        .filter(|span| (1..=MAX_TEMPORAL_SPAN_NS).contains(span))
        .ok_or(TemporalTriangulationError::InvalidTimeSpan)?;
    let reference_time_ns = earliest
        .checked_add(span / 2)
        .ok_or(TemporalTriangulationError::InvalidTimeSpan)?;
    let span_seconds = span as f64 * 1e-9;
    let origin = ordered[0].view.pose.center();
    let mut samples = Vec::new();
    samples
        .try_reserve_exact(ordered.len())
        .map_err(|_| GeometryError::LimitExceeded)?;
    for input in ordered {
        let offset = input
            .capture_time_ns
            .checked_sub(reference_time_ns)
            .ok_or(TemporalTriangulationError::InvalidTimeSpan)?;
        samples.push(Sample {
            input,
            tau: offset as f64 / span as f64,
        });
    }

    let mut state = initialize(&samples, origin, options, budget)?;
    let mut converged = false;
    for _ in 0..options.max_iterations {
        let (information, gradient, cost) =
            normal_system(&samples, origin, state, options, budget)?;
        let (inverse, _) = inverse_information(information, options.max_condition_number, budget)?;
        let step = multiply(inverse, gradient.map(|value| -value));
        check_finite(&step)?;
        let tolerance = 1e-10 * (1.0 + length(&state));
        if cost <= 1e-20 || length(&step) <= tolerance {
            converged = true;
            break;
        }
        let mut alpha = 1.0;
        let mut accepted = false;
        for _ in 0..MAX_BACKTRACKS {
            budget.charge(32)?;
            let trial = std::array::from_fn(|axis| state[axis] + alpha * step[axis]);
            check_finite(&trial)?;
            match normal_system(&samples, origin, trial, options, budget) {
                Ok((_, _, trial_cost)) if trial_cost <= cost => {
                    state = trial;
                    accepted = true;
                    converged = trial_cost <= 1e-20 || alpha * length(&step) <= tolerance;
                    break;
                }
                Ok(_) | Err(TemporalTriangulationError::NoConsensus) => {}
                Err(error) => return Err(error),
            }
            alpha *= 0.5;
        }
        if !accepted {
            return Err(TemporalTriangulationError::NotConverged);
        }
        if converged {
            break;
        }
    }
    if !converged {
        return Err(TemporalTriangulationError::NotConverged);
    }
    let velocity_per_second = std::array::from_fn(|axis| state[axis + 3] / span_seconds);
    check_finite(&velocity_per_second)?;
    if length(&velocity_per_second) > options.max_speed {
        return Err(TemporalTriangulationError::SpeedLimit);
    }
    let position = std::array::from_fn(|axis| origin[axis] + state[axis]);
    check_finite(&position)?;
    let (information, _, cost) = normal_system(&samples, origin, state, options, budget)?;
    let (mut covariance, condition) =
        inverse_information(information, options.max_condition_number, budget)?;
    budget.charge(128)?;
    let inflation = (cost / (2 * samples.len() - 6) as f64).max(1.0);
    for (row_index, row) in covariance.iter_mut().enumerate() {
        for (column_index, entry) in row.iter_mut().enumerate() {
            *entry *= inflation;
            if row_index >= 3 {
                *entry /= span_seconds;
            }
            if column_index >= 3 {
                *entry /= span_seconds;
            }
        }
        check_finite(row)?;
    }
    let mut residuals = Vec::new();
    residuals
        .try_reserve_exact(samples.len())
        .map_err(|_| GeometryError::LimitExceeded)?;
    let mut squared = 0.0;
    for sample in &samples {
        budget.charge(256)?;
        let predicted = sample.input.view.pose.project(
            sample.input.view.intrinsics,
            point_at(origin, state, sample.tau),
        )?;
        let pixels = length(&[
            predicted[0] - sample.input.view.pixel[0],
            predicted[1] - sample.input.view.pixel[1],
        ]);
        if !pixels.is_finite() || pixels > options.max_reprojection_pixels {
            return Err(TemporalTriangulationError::NoConsensus);
        }
        squared += pixels * pixels;
        residuals.push(TemporalResidual {
            camera: sample.input.view.camera,
            capture_time_ns: sample.input.capture_time_ns,
            pixels,
        });
    }
    budget.charge(0)?;
    Ok(TriangulatedMotion {
        reference_time_ns,
        observed_time_range_ns: [earliest, latest],
        position,
        velocity_per_second,
        pixel_noise_covariance: covariance,
        normalized_condition_number: condition,
        rms_reprojection_pixels: (squared / samples.len() as f64).sqrt(),
        residuals,
    })
}

fn validate_options(
    options: TemporalTriangulationOptions,
) -> Result<(), TemporalTriangulationError> {
    if !(1..=MAX_ITERATIONS).contains(&options.max_iterations)
        || !options.max_reprojection_pixels.is_finite()
        || !(1e-6..=1e6).contains(&options.max_reprojection_pixels)
        || !options.max_distance.is_finite()
        || !(1e-6..=1e12).contains(&options.max_distance)
        || !options.max_speed.is_finite()
        || !(1e-9..=1e12).contains(&options.max_speed)
        || !options.max_condition_number.is_finite()
        || !(1.0..=1e12).contains(&options.max_condition_number)
    {
        return Err(TemporalTriangulationError::InvalidOptions);
    }
    Ok(())
}

fn check_finite(values: &[f64]) -> Result<(), TemporalTriangulationError> {
    if values.iter().any(|value| !value.is_finite()) {
        Err(GeometryError::NonFinite.into())
    } else {
        Ok(())
    }
}

fn length(values: &[f64]) -> f64 {
    values.iter().fold(0.0_f64, |sum, value| sum.hypot(*value))
}

fn point_at(origin: [f64; 3], state: V6, tau: f64) -> [f64; 3] {
    std::array::from_fn(|axis| origin[axis] + state[axis] + tau * state[axis + 3])
}

fn multiply(matrix: M6, vector: V6) -> V6 {
    std::array::from_fn(|row| {
        (0..6)
            .map(|column| matrix[row][column] * vector[column])
            .sum()
    })
}

fn accumulate(information: &mut M6, rhs: &mut V6, row: V6, value: f64) {
    for i in 0..6 {
        rhs[i] += row[i] * value;
        for j in 0..6 {
            information[i][j] += row[i] * row[j];
        }
    }
}

fn initialize(
    samples: &[Sample],
    origin: [f64; 3],
    options: TemporalTriangulationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<V6, TemporalTriangulationError> {
    let mut information = [[0.0; 6]; 6];
    let mut rhs = [0.0; 6];
    for sample in samples {
        budget.charge(1024)?;
        let view = sample.input.view;
        let ray = view.pose.ray(view.intrinsics, view.pixel)?;
        let direction = ray.direction();
        let center = ray.origin();
        for axis in 0..3 {
            let mut row = [0.0; 6];
            let mut value = 0.0;
            for coordinate in 0..3 {
                let identity = if axis == coordinate { 1.0 } else { 0.0 };
                let projected = identity - direction[axis] * direction[coordinate];
                row[coordinate] = projected / view.sigma_pixels;
                row[coordinate + 3] = row[coordinate] * sample.tau;
                value += projected * (center[coordinate] - origin[coordinate]) / view.sigma_pixels;
            }
            accumulate(&mut information, &mut rhs, row, value);
        }
    }
    check_finite(&rhs)?;
    let (inverse, _) = inverse_information(information, options.max_condition_number, budget)?;
    let state = multiply(inverse, rhs);
    check_finite(&state)?;
    Ok(state)
}

fn normal_system(
    samples: &[Sample],
    origin: [f64; 3],
    state: V6,
    options: TemporalTriangulationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<(M6, V6, f64), TemporalTriangulationError> {
    let mut information = [[0.0; 6]; 6];
    let mut gradient = [0.0; 6];
    let mut cost = 0.0;
    for sample in samples {
        budget.charge(1024)?;
        let view = sample.input.view;
        let camera_point = view.pose.transform(point_at(origin, state, sample.tau))?;
        if camera_point[2] <= 1e-9 || length(&camera_point) > options.max_distance {
            return Err(TemporalTriangulationError::NoConsensus);
        }
        let predicted = view.intrinsics.project(camera_point)?;
        let rotation = view.pose.rotation();
        let focal = view.intrinsics.focal_lengths();
        for axis in 0..2 {
            let residual = (predicted[axis] - view.pixel[axis]) / view.sigma_pixels;
            let mut row = [0.0; 6];
            for coordinate in 0..3 {
                row[coordinate] = focal[axis] / camera_point[2]
                    * (rotation[axis][coordinate]
                        - camera_point[axis] / camera_point[2] * rotation[2][coordinate])
                    / view.sigma_pixels;
                row[coordinate + 3] = row[coordinate] * sample.tau;
            }
            check_finite(&row)?;
            accumulate(&mut information, &mut gradient, row, residual);
            cost += residual * residual;
        }
    }
    check_finite(&gradient)?;
    check_finite(&[cost])?;
    Ok((information, gradient, cost))
}

/// Diagonal scaling improves factorization without changing the reported condition
/// of the unscaled matrix. A failed pivot is NOT repaired with fabricated information.
fn inverse_information(
    matrix: M6,
    max_condition: f64,
    budget: &mut WorkBudget<'_>,
) -> Result<(M6, f64), TemporalTriangulationError> {
    budget.charge(4096)?;
    let mut scaling = [0.0; 6];
    for (index, row) in matrix.iter().enumerate() {
        check_finite(row)?;
        if row[index] <= 0.0 {
            return Err(TemporalTriangulationError::UnobservableMotion);
        }
        scaling[index] = 1.0 / row[index].sqrt();
    }
    let mut lower = [[0.0; 6]; 6];
    for i in 0..6 {
        for j in 0..=i {
            let mut value = matrix[i][j] * scaling[i] * scaling[j];
            for k in 0..j {
                value -= lower[i][k] * lower[j][k];
            }
            if !value.is_finite() {
                return Err(GeometryError::NonFinite.into());
            }
            if i == j {
                if value <= 1e-12 {
                    return Err(TemporalTriangulationError::UnobservableMotion);
                }
                lower[i][j] = value.sqrt();
            } else {
                lower[i][j] = value / lower[j][j];
            }
        }
    }
    let mut inverse = [[0.0; 6]; 6];
    for column in 0..6 {
        let mut forward = [0.0; 6];
        for i in 0..6 {
            let mut value = if i == column { 1.0 } else { 0.0 };
            for k in 0..i {
                value -= lower[i][k] * forward[k];
            }
            forward[i] = value / lower[i][i];
        }
        let mut backward = [0.0; 6];
        for i in (0..6).rev() {
            let mut value = forward[i];
            for k in i + 1..6 {
                value -= lower[k][i] * backward[k];
            }
            backward[i] = value / lower[i][i];
            inverse[i][column] = backward[i] * scaling[i] * scaling[column];
        }
    }
    let infinity_norm = |m: &M6| {
        m.iter()
            .map(|row| row.iter().map(|entry| entry.abs()).sum::<f64>())
            .fold(0.0_f64, f64::max)
    };
    for row in &inverse {
        check_finite(row)?;
    }
    let condition = infinity_norm(&matrix) * infinity_norm(&inverse);
    if !condition.is_finite() || condition > max_condition {
        return Err(TemporalTriangulationError::UnobservableMotion);
    }
    // Do not export one-triangle rounding differences as asymmetric covariance.
    for i in 0..6 {
        for j in i + 1..6 {
            let value = inverse[i][j] * 0.5 + inverse[j][i] * 0.5;
            inverse[i][j] = value;
            inverse[j][i] = value;
        }
    }
    Ok((inverse, condition))
}
