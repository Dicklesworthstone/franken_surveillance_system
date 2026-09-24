#![forbid(unsafe_code)]
//! Conditional image-motion estimates over the active anonymous trajectory tracker.
//!
//! This is a pure derived view, not another association/lifecycle implementation.
//! Each estimate initializes a Gaussian constant-velocity filter at the previous
//! actual observation, updates with the latest actual observation, then optionally
//! predicts to the current report. It deliberately uses only that retained pair;
//! it is not a full-history smoother. Covariance is conditional on declared priors,
//! not a calibration certificate, physical speed bound, or identity confidence.
//! Partial silhouettes, uncertain capture times and unavailable frames stay unknown.

use crate::image_tracking::{
    ImageTrackObservation, ImageTracker, ImageTrackingFrame, ImageTrackingReport,
    TrackingAvailability,
};
use fss_geometry::{GeometryError, WorkBudget};

/// Explicit statistical assumptions; no implicit trained or calibrated noise model.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ImageMotionPolicy {
    /// Independent centroid measurement variance per axis, in pixels squared.
    pub measurement_variance: f64,
    /// Per-step constant acceleration variance, in pixels squared / seconds^4.
    pub acceleration_variance: f64,
    /// Initial velocity variance per axis, in pixels squared / seconds^2.
    pub initial_velocity_variance: f64,
    /// Maximum separation of the actual fitting observations, at most one hour.
    pub maximum_pair_gap_ns: u64,
    /// Maximum extrapolation from the latest observation, at most one hour.
    pub maximum_prediction_ns: u64,
}
impl ImageMotionPolicy {
    fn validate(self) -> Result<(), ImageMotionError> {
        if [self.measurement_variance, self.initial_velocity_variance]
            .iter()
            .any(|v| !v.is_finite() || !(1e-6..=1e8).contains(v))
            || !self.acceleration_variance.is_finite()
            || !(0.0..=1e8).contains(&self.acceleration_variance)
            || !(1..=3_600_000_000_000).contains(&self.maximum_pair_gap_ns)
            || self.maximum_prediction_ns > 3_600_000_000_000
        {
            return Err(ImageMotionError::InvalidPolicy);
        }
        Ok(())
    }
}

/// A failed derivation changes neither the tracker nor its accepted report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageMotionError {
    /// Invalid numerical prior or time horizon.
    InvalidPolicy,
    /// The report is no longer the tracker's exact current receipt.
    StaleReport,
    /// Arithmetic became nonfinite or covariance ceased to be positive semidefinite.
    Numeric,
    /// The complete result allocation was refused.
    Limit,
    /// Cooperative cancellation or deterministic work exhaustion.
    Geometry(GeometryError),
}
impl From<GeometryError> for ImageMotionError {
    fn from(error: GeometryError) -> Self {
        Self::Geometry(error)
    }
}
impl std::fmt::Display for ImageMotionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid image motion policy",
            Self::StaleReport => "image motion report is stale",
            Self::Numeric => "invalid image motion arithmetic",
            Self::Limit => "image motion result allocation failed",
            Self::Geometry(_) => "image motion work interrupted",
        })
    }
}
impl std::error::Error for ImageMotionError {}

/// Why no statistical trajectory estimate is justified by this retained source pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MotionUnavailable {
    /// A trajectory needs two accepted, actual observations; zero velocity is not invented.
    MissingPair,
    /// A truncated/unknown silhouette does not supply a stable centroid measurement.
    PartialObservation,
    /// At least one capture time is an interval rather than an exact timestamp.
    CaptureUncertainty,
    /// The actual source pair exceeds the declared fitting interval.
    PairHorizon,
    /// Extrapolation would exceed the explicitly admitted horizon.
    PredictionHorizon,
    /// The current report declares unavailable or disturbed measurements.
    FrameUnavailable,
}

/// Conditional mean/covariance derived from exactly two accepted image observations.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ImageMotionEstimate {
    track: u64,
    observations: [ImageTrackObservation; 2],
    at_ns: u64,
    predicted: bool,
    axes: [Axis; 2],
}
impl ImageMotionEstimate {
    /// Anonymous handle scoped by the enclosing tracking receipt, not a person identity.
    pub fn track(&self) -> u64 {
        self.track
    }
    /// Unchanged source pair; predictions never fabricate an additional observation.
    pub fn observations(&self) -> &[ImageTrackObservation; 2] {
        &self.observations
    }
    /// Exact source-clock timestamp at which the output state is represented.
    pub fn at_ns(&self) -> u64 {
        self.at_ns
    }
    /// True means extrapolated after the latest actual measurement.
    pub fn predicted(&self) -> bool {
        self.predicted
    }
    /// Mean centroid in full-image pixel-edge coordinates; never a ground contact.
    pub fn centre(&self) -> [f64; 2] {
        self.axes.map(|a| a.position)
    }
    /// Conditional velocity mean in image pixels per second.
    pub fn velocity(&self) -> [f64; 2] {
        self.axes.map(|a| a.velocity)
    }
    /// Per axis [position variance, position/velocity covariance, velocity variance].
    /// These are statistical model values, not certified geometric error intervals.
    pub fn covariance(&self) -> [[f64; 3]; 2] {
        self.axes.map(|a| [a.pp, a.pv, a.vv])
    }
}
/// Complete per-track outcome; unsupported observations are retained as explicit unknowns.
// Bounded inline source pairs avoid an unbudgeted allocation per trajectory.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ImageMotionOutcome {
    /// Conditional source-pair filter result.
    Estimated(ImageMotionEstimate),
    /// The available evidence does not support this model's estimate.
    Unavailable {
        /// Anonymous handle in the exact current tracking receipt.
        track: u64,
        /// Explicit missing assumption, not absence or lack of motion.
        reason: MotionUnavailable,
    },
}
/// Complete immutable derived view bound to the current tracker, source and numerical policy.
#[derive(Debug)]
pub struct ImageMotionReport {
    tracking: [u8; 32],
    frame: ImageTrackingFrame,
    policy: ImageMotionPolicy,
    outcomes: Vec<ImageMotionOutcome>,
}
impl ImageMotionReport {
    /// Exact local tracking receipt, not a durable canonical ledger root.
    pub fn tracking_digest(&self) -> [u8; 32] {
        self.tracking
    }
    /// Original report frame with observation availability and all generation identities.
    pub fn frame(&self) -> ImageTrackingFrame {
        self.frame
    }
    /// Explicit fitting/extrapolation assumptions used for every outcome.
    pub fn policy(&self) -> ImageMotionPolicy {
        self.policy
    }
    /// Every live track in tracker order; no top-k pruning or missing-result elision.
    pub fn outcomes(&self) -> &[ImageMotionOutcome] {
        &self.outcomes
    }
}

/// Derive image motion from the exact current tracker/report without changing either.
///
/// One-observation paths, ambiguous/coasting paths without a usable pair, partial
/// silhouettes and uncertain clocks stay explicit. Coasting with a valid pair may
/// produce a labelled prediction; it never increments the observed-source count.
/// Integer timestamp subtraction precedes float conversion, preserving small deltas
/// on large source clocks. Errors return no partial result and never consume evidence.
pub fn estimate_image_motion(
    tracker: &ImageTracker,
    report: &ImageTrackingReport,
    policy: ImageMotionPolicy,
    budget: &mut WorkBudget<'_>,
) -> Result<ImageMotionReport, ImageMotionError> {
    budget.charge(1)?;
    policy.validate()?;
    if tracker.digest() != report.digest() {
        return Err(ImageMotionError::StaleReport);
    }
    budget.charge(tracker.tracks().len() as u64)?;
    let mut outcomes = Vec::new();
    outcomes
        .try_reserve_exact(tracker.tracks().len())
        .map_err(|_| ImageMotionError::Limit)?;
    let frame = report.frame();
    for track in tracker.tracks() {
        budget.charge(192)?;
        let latest = track.latest();
        let reason = if frame.availability != TrackingAvailability::Available {
            Some(MotionUnavailable::FrameUnavailable)
        } else if let Some(previous) = track.previous() {
            if previous.detection.partial || latest.detection.partial {
                Some(MotionUnavailable::PartialObservation)
            } else if [
                previous.frame.source.capture,
                latest.frame.source.capture,
                frame.source.capture,
            ]
            .iter()
            .any(|t| t[0] != t[1])
            {
                Some(MotionUnavailable::CaptureUncertainty)
            } else if latest.frame.source.capture[0] - previous.frame.source.capture[0]
                > policy.maximum_pair_gap_ns
            {
                Some(MotionUnavailable::PairHorizon)
            } else if frame.source.capture[0] - latest.frame.source.capture[0]
                > policy.maximum_prediction_ns
            {
                Some(MotionUnavailable::PredictionHorizon)
            } else {
                None
            }
        } else {
            Some(MotionUnavailable::MissingPair)
        };
        if let Some(reason) = reason {
            outcomes.push(ImageMotionOutcome::Unavailable {
                track: track.id(),
                reason,
            });
            continue;
        }
        let previous = track.previous().ok_or(ImageMotionError::Numeric)?;
        let fit_dt =
            (latest.frame.source.capture[0] - previous.frame.source.capture[0]) as f64 * 1e-9;
        let forecast_ns = frame.source.capture[0] - latest.frame.source.capture[0];
        let start = centroid(previous);
        let end = centroid(latest);
        let mut axes = start.map(|position| Axis::new(position, policy));
        for (axis, measurement) in axes.iter_mut().zip(end) {
            *axis = axis
                .predict(fit_dt, policy.acceleration_variance)?
                .update(measurement, policy.measurement_variance)?;
            if forecast_ns > 0 {
                *axis = axis.predict(forecast_ns as f64 * 1e-9, policy.acceleration_variance)?;
            }
        }
        outcomes.push(ImageMotionOutcome::Estimated(ImageMotionEstimate {
            track: track.id(),
            observations: [previous, latest],
            at_ns: frame.source.capture[0],
            predicted: forecast_ns > 0,
            axes,
        }));
    }
    budget.charge(0)?;
    Ok(ImageMotionReport {
        tracking: report.digest(),
        frame,
        policy,
        outcomes,
    })
}
fn centroid(observation: ImageTrackObservation) -> [f64; 2] {
    let d = observation.detection;
    [
        0.5 * (f64::from(d.min[0]) + f64::from(d.max[0])),
        0.5 * (f64::from(d.min[1]) + f64::from(d.max[1])),
    ]
}

/// Independent per-axis constant-velocity filter with Joseph-form measurement update.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Axis {
    position: f64,
    velocity: f64,
    pp: f64,
    pv: f64,
    vv: f64,
}
impl Axis {
    fn new(position: f64, policy: ImageMotionPolicy) -> Self {
        Self {
            position,
            velocity: 0.0,
            pp: policy.measurement_variance,
            pv: 0.0,
            vv: policy.initial_velocity_variance,
        }
    }
    fn validate(self) -> Result<Self, ImageMotionError> {
        if [self.position, self.velocity, self.pp, self.pv, self.vv]
            .iter()
            .any(|v| !v.is_finite())
            || self.pp <= 0.0
            || self.vv < 0.0
            || self.pv.abs() > self.pp.sqrt() * self.vv.sqrt() * (1.0 + 64.0 * f64::EPSILON)
        {
            return Err(ImageMotionError::Numeric);
        }
        Ok(self)
    }
    fn predict(self, dt: f64, q: f64) -> Result<Self, ImageMotionError> {
        let dt2 = dt * dt;
        Self {
            position: self.position + dt * self.velocity,
            velocity: self.velocity,
            pp: self.pp + 2.0 * dt * self.pv + dt2 * self.vv + 0.25 * dt2 * dt2 * q,
            pv: self.pv + dt * self.vv + 0.5 * dt2 * dt * q,
            vv: self.vv + dt2 * q,
        }
        .validate()
    }
    fn update(self, measurement: f64, variance: f64) -> Result<Self, ImageMotionError> {
        let innovation = measurement - self.position;
        let denominator = self.pp + variance;
        let kp = self.pp / denominator;
        let kv = self.pv / denominator;
        let a = 1.0 - kp;
        Self {
            position: self.position + kp * innovation,
            velocity: self.velocity + kv * innovation,
            pp: a * a * self.pp + kp * kp * variance,
            pv: a * (self.pv - kv * self.pp) + kp * kv * variance,
            vv: self.vv - 2.0 * kv * self.pv + kv * kv * self.pp + kv * kv * variance,
        }
        .validate()
    }
}

/// Actual raw-luma and native-JPEG composition with explicit stage completion.
pub mod pipeline;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::foreground::ForegroundSource;
    use crate::image_tracking::{ImageDetection, ImageTrackingPolicy};
    use crate::localization::ImageIdentity;
    use fss_core::ContentDigest;

    fn policy() -> ImageMotionPolicy {
        ImageMotionPolicy {
            measurement_variance: 1.0,
            acceleration_variance: 0.1,
            initial_velocity_variance: 100.0,
            maximum_pair_gap_ns: 10_000_000_000,
            maximum_prediction_ns: 10_000_000_000,
        }
    }
    fn frame(time: u64) -> ImageTrackingFrame {
        ImageTrackingFrame {
            source: ForegroundSource {
                image: ImageIdentity {
                    exposure: ContentDigest::sha256(&time.to_le_bytes()).bytes(),
                    pixels: [4; 32],
                    image_domain: [5; 32],
                    dimensions: [64, 16],
                },
                camera: 1,
                calibration: [6; 32],
                clock: 1,
                capture: [time, time],
            },
            detector: [7; 32],
            permission_mask: [8; 32],
            evidence: [9; 32],
            availability: TrackingAvailability::Available,
        }
    }
    fn detection(left: u32, evidence: u8) -> ImageDetection {
        ImageDetection {
            id: 1,
            evidence: [evidence; 32],
            min: [left, 4],
            max: [left + 4, 8],
            partial: false,
        }
    }
    fn tracker() -> ImageTracker {
        ImageTracker::new(
            [10; 32],
            ImageTrackingPolicy {
                maximum_tracks: 8,
                maximum_detections: 8,
                maximum_exposures: 100,
                minimum_observations: 2,
                maximum_misses: 2,
                maximum_gap_ns: 10_000_000_000,
                maximum_speed: 100,
                gate_padding: 2,
                miss_cost: 1000,
                ambiguity_margin: 0,
            },
            &mut WorkBudget::new(100_000),
        )
        .unwrap()
    }
    fn estimate(tracker: &ImageTracker, report: &ImageTrackingReport) -> ImageMotionReport {
        estimate_image_motion(tracker, report, policy(), &mut WorkBudget::new(100_000)).unwrap()
    }
    fn fitted() -> (ImageTracker, ImageTrackingReport) {
        let mut tracker = tracker();
        tracker
            .update(
                frame(1_000_000_000),
                &[detection(4, 20)],
                &mut WorkBudget::new(100_000),
            )
            .unwrap();
        let report = tracker
            .update(
                frame(2_000_000_000),
                &[detection(9, 21)],
                &mut WorkBudget::new(100_000),
            )
            .unwrap();
        (tracker, report)
    }
    #[test]
    fn actual_tracker_pair_learns_velocity_and_coasting_retains_sources() {
        let (mut tracker, report) = fitted();
        let model = estimate(&tracker, &report);
        let ImageMotionOutcome::Estimated(observed) = model.outcomes()[0] else {
            unreachable!()
        };
        assert!(observed.velocity()[0] > 4.0);
        assert!(!observed.predicted());
        let coast = tracker
            .update(frame(3_000_000_000), &[], &mut WorkBudget::new(100_000))
            .unwrap();
        let model = estimate(&tracker, &coast);
        let ImageMotionOutcome::Estimated(predicted) = model.outcomes()[0] else {
            unreachable!()
        };
        assert!(predicted.predicted());
        assert_eq!(predicted.observations(), observed.observations());
        assert!(predicted.centre()[0] > observed.centre()[0]);
        assert!(predicted.covariance()[0][0] > observed.covariance()[0][0]);
        assert_eq!(model.tracking_digest(), tracker.digest());
    }
    #[test]
    fn stale_report_is_refused_without_changing_tracker() {
        let (mut tracker, report) = fitted();
        tracker
            .update(frame(3_000_000_000), &[], &mut WorkBudget::new(100_000))
            .unwrap();
        let digest = tracker.digest();
        assert!(matches!(
            estimate_image_motion(&tracker, &report, policy(), &mut WorkBudget::new(100_000)),
            Err(ImageMotionError::StaleReport)
        ));
        assert_eq!(tracker.digest(), digest);
    }
    #[test]
    fn missing_partial_uncertain_and_unavailable_remain_explicit() {
        let mut tracker = tracker();
        let mut first = frame(1_000_000_000);
        first.source.capture[1] += 1;
        let report = tracker
            .update(first, &[detection(4, 20)], &mut WorkBudget::new(100_000))
            .unwrap();
        assert!(matches!(
            estimate(&tracker, &report).outcomes()[0],
            ImageMotionOutcome::Unavailable {
                reason: MotionUnavailable::MissingPair,
                ..
            }
        ));
        let report = tracker
            .update(
                frame(2_000_000_000),
                &[detection(9, 21)],
                &mut WorkBudget::new(100_000),
            )
            .unwrap();
        assert!(matches!(
            estimate(&tracker, &report).outcomes()[0],
            ImageMotionOutcome::Unavailable {
                reason: MotionUnavailable::CaptureUncertainty,
                ..
            }
        ));
        let mut partial = detection(10, 22);
        partial.partial = true;
        let report = tracker
            .update(
                frame(3_000_000_000),
                &[partial],
                &mut WorkBudget::new(100_000),
            )
            .unwrap();
        assert!(matches!(
            estimate(&tracker, &report).outcomes()[0],
            ImageMotionOutcome::Unavailable {
                reason: MotionUnavailable::PartialObservation,
                ..
            }
        ));
        let mut disturbed = frame(4_000_000_000);
        disturbed.availability = TrackingAvailability::Disturbed;
        let report = tracker
            .update(disturbed, &[], &mut WorkBudget::new(100_000))
            .unwrap();
        assert!(matches!(
            estimate(&tracker, &report).outcomes()[0],
            ImageMotionOutcome::Unavailable {
                reason: MotionUnavailable::FrameUnavailable,
                ..
            }
        ));
    }
    #[test]
    fn fitting_and_prediction_horizons_are_not_silently_extrapolated() {
        let (mut tracker, report) = fitted();
        let mut p = policy();
        p.maximum_pair_gap_ns = 1;
        let model =
            estimate_image_motion(&tracker, &report, p, &mut WorkBudget::new(100_000)).unwrap();
        assert!(matches!(
            model.outcomes()[0],
            ImageMotionOutcome::Unavailable {
                reason: MotionUnavailable::PairHorizon,
                ..
            }
        ));
        let report = tracker
            .update(frame(3_000_000_000), &[], &mut WorkBudget::new(100_000))
            .unwrap();
        p = policy();
        p.maximum_prediction_ns = 0;
        let model =
            estimate_image_motion(&tracker, &report, p, &mut WorkBudget::new(100_000)).unwrap();
        assert!(matches!(
            model.outcomes()[0],
            ImageMotionOutcome::Unavailable {
                reason: MotionUnavailable::PredictionHorizon,
                ..
            }
        ));
    }
    #[test]
    fn every_budget_cut_leaves_source_state_unchanged_and_retryable() {
        let (tracker, report) = fitted();
        let digest = tracker.digest();
        let mut full = WorkBudget::new(100_000);
        let expected = estimate_image_motion(&tracker, &report, policy(), &mut full).unwrap();
        for limit in 0..full.used() {
            assert!(matches!(
                estimate_image_motion(&tracker, &report, policy(), &mut WorkBudget::new(limit)),
                Err(ImageMotionError::Geometry(GeometryError::BudgetExhausted))
            ));
            assert_eq!(tracker.digest(), digest);
            assert_eq!(estimate(&tracker, &report).outcomes(), expected.outcomes());
        }
    }
    #[test]
    fn covariance_stays_valid_under_irregular_measurements() {
        let mut axis = Axis::new(0.0, policy());
        for i in 0..10_000 {
            let dt = if i % 7 == 0 { 0.001 } else { 0.1 };
            axis = axis
                .predict(dt, 0.1)
                .unwrap()
                .update(f64::from(i % 200), 1.0)
                .unwrap();
            axis.validate().unwrap();
        }
    }
    #[test]
    fn invalid_priors_and_cancellation_fail_explicitly() {
        let (tracker, report) = fitted();
        for value in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let mut p = policy();
            p.measurement_variance = value;
            assert!(matches!(
                estimate_image_motion(&tracker, &report, p, &mut WorkBudget::new(1000)),
                Err(ImageMotionError::InvalidPolicy)
            ));
        }
        let cancellation = std::sync::atomic::AtomicBool::new(true);
        assert!(matches!(
            estimate_image_motion(
                &tracker,
                &report,
                policy(),
                &mut WorkBudget::cancellable(1000, &cancellation)
            ),
            Err(ImageMotionError::Geometry(GeometryError::Cancelled))
        ));
    }
    #[test]
    fn integer_time_differences_preserve_large_clock_small_steps() {
        let mut tracker = tracker();
        let time = u64::MAX - 10;
        tracker
            .update(
                frame(time),
                &[detection(4, 20)],
                &mut WorkBudget::new(100_000),
            )
            .unwrap();
        let report = tracker
            .update(
                frame(time + 1),
                &[detection(5, 21)],
                &mut WorkBudget::new(100_000),
            )
            .unwrap();
        let model = estimate(&tracker, &report);
        let ImageMotionOutcome::Estimated(result) = model.outcomes()[0] else {
            unreachable!()
        };
        assert!(result.velocity()[0] > 0.0);
        assert_eq!(result.at_ns(), time + 1);
    }
}
