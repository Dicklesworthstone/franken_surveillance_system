#![forbid(unsafe_code)]
//! Read-only validity monitoring for a frozen camera pose against current static landmarks.
//!
//! This module never refits or activates calibration. It compares current image-to-map
//! matches with one exact frozen pose and returns Valid, Invalidate, or Indeterminate.

use fss_geometry::{GeometryError, RigidPose, WorkBudget};
use crate::PropertyTwin;
use crate::localization::{FeatureFrame, LocalizationAtlas, LocalizationCamera, LocalizationError,
    MatchOptions, MatchReport};

/// Exact calibration generation being checked. The digest is owner-supplied identity,
/// not proof that the calibration is physically correct.
#[derive(Clone, Copy, Debug)]
pub struct FrozenCalibration {
    pub id: [u8; 32],
    pub camera: LocalizationCamera,
    pub pose: RigidPose,
}

/// Explicit admission thresholds. No deployment defaults are inferred from image content.
#[derive(Clone, Copy, Debug)]
pub struct CalibrationMonitorPolicy {
    /// Residual threshold used to count a geometrically consistent landmark.
    pub inlier_threshold_px: f64,
    /// RMS ceiling over retained inliers.
    pub maximum_rms_px: f64,
    /// Minimum number of accepted descriptor correspondences and inlier projections.
    pub minimum_support: usize,
    /// Minimum inlier fraction among accepted descriptor correspondences, in (0,1].
    pub minimum_inlier_fraction: f64,
    /// Minimum inlier span on each image axis as a fraction of image dimensions.
    pub minimum_image_span: f64,
}
impl Default for CalibrationMonitorPolicy {
    fn default() -> Self {
        Self { inlier_threshold_px: 3.0, maximum_rms_px: 1.5, minimum_support: 8,
            minimum_inlier_fraction: 0.7, minimum_image_span: 0.08 }
    }
}
impl CalibrationMonitorPolicy {
    fn validate(self) -> Result<(), CalibrationMonitorError> {
        if !self.inlier_threshold_px.is_finite() || !(0.001..=128.0).contains(&self.inlier_threshold_px)
            || !self.maximum_rms_px.is_finite() || !(0.001..=128.0).contains(&self.maximum_rms_px)
            || !(4..=512).contains(&self.minimum_support)
            || !self.minimum_inlier_fraction.is_finite() || self.minimum_inlier_fraction <= 0.0
            || self.minimum_inlier_fraction > 1.0
            || !self.minimum_image_span.is_finite() || !(0.0..=1.0).contains(&self.minimum_image_span) {
            return Err(CalibrationMonitorError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationDisposition {
    /// Current observations remain geometrically consistent under the supplied policy.
    ValidUnderPolicy,
    /// Sufficient current support exists and materially contradicts the frozen pose.
    Invalidate,
    /// Current evidence cannot safely confirm or invalidate the pose.
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationMonitorError {
    InvalidInput,
    BasisMismatch,
    ReferenceExposure,
    Localization(LocalizationError),
    Geometry(GeometryError),
}
impl From<LocalizationError> for CalibrationMonitorError {
    fn from(value: LocalizationError) -> Self { Self::Localization(value) }
}
impl From<GeometryError> for CalibrationMonitorError {
    fn from(value: GeometryError) -> Self { Self::Geometry(value) }
}
impl std::fmt::Display for CalibrationMonitorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid calibration monitor input",
            Self::BasisMismatch => "calibration monitor basis mismatch",
            Self::ReferenceExposure => "calibration monitor reuses a reference exposure",
            Self::Localization(_) => "calibration monitor matching failed",
            Self::Geometry(_) => "calibration monitor geometry failed",
        })
    }
}
impl std::error::Error for CalibrationMonitorError {}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CalibrationResidual {
    pub landmark: u64,
    /// None means the landmark was behind the frozen camera or otherwise not projectable.
    pub error_px: Option<f64>,
    pub in_image: bool,
    pub inlier: bool,
}

/// Complete current comparison. The original match report is retained so an invalidate
/// decision cannot hide descriptor ambiguity or rejected image features.
#[derive(Debug)]
pub struct CalibrationMonitorReport {
    pub calibration: [u8; 32],
    pub twin_digest: [u8; 32],
    pub atlas_digest: [u8; 32],
    pub matches: MatchReport,
    pub residuals: Vec<CalibrationResidual>,
    pub projected: usize,
    pub inliers: usize,
    pub rms_inlier_px: Option<f64>,
    pub maximum_inlier_error_px: Option<f64>,
    pub image_span_fraction: [f64; 2],
    pub disposition: CalibrationDisposition,
}

/// Compare one current feature frame against one frozen pose without changing either.
/// Descriptor scarcity or narrow/local support is Indeterminate, not evidence of drift.
/// Once sufficient distributed support exists, failing the inlier fraction/RMS policy
/// produces Invalidate. This is a typed recommendation; the calibration owner still
/// controls generation invalidation and replacement.
pub fn monitor_calibration(twin: &PropertyTwin, atlas: &LocalizationAtlas,
    query: &FeatureFrame, frozen: FrozenCalibration, matching: MatchOptions,
    policy: CalibrationMonitorPolicy, budget: &mut WorkBudget<'_>)
    -> Result<CalibrationMonitorReport, CalibrationMonitorError> {
    budget.charge(0)?;
    policy.validate()?;
    if frozen.id == [0; 32] { return Err(CalibrationMonitorError::InvalidInput); }
    if query.identity().dimensions != frozen.camera.intrinsics.dimensions()
        || query.identity().image_domain != frozen.camera.image_domain {
        return Err(CalibrationMonitorError::BasisMismatch);
    }
    if atlas.references().iter().any(|reference| reference.frame.identity().exposure == query.identity().exposure) {
        return Err(CalibrationMonitorError::ReferenceExposure);
    }
    let matches = atlas.match_frame(twin, query, matching, budget)?;
    let mut residuals = Vec::new();
    residuals.try_reserve_exact(matches.correspondences.len()).map_err(|_| CalibrationMonitorError::InvalidInput)?;
    let mut projected = 0usize;
    let mut inliers = 0usize;
    let mut squared = 0.0;
    let mut maximum = 0.0_f64;
    let mut minimum = [f64::INFINITY; 2];
    let mut maximum_pixel = [f64::NEG_INFINITY; 2];
    for point in &matches.correspondences {
        budget.charge(4)?;
        match frozen.pose.project(frozen.camera.intrinsics, point.world) {
            Ok(expected) => {
                let in_image = frozen.camera.intrinsics.contains(expected);
                let error = (expected[0] - point.pixel[0]).hypot(expected[1] - point.pixel[1]);
                let inlier = in_image && error <= policy.inlier_threshold_px;
                projected += usize::from(in_image);
                if inlier {
                    inliers += 1; squared += error * error; maximum = maximum.max(error);
                    for axis in 0..2 {
                        minimum[axis] = minimum[axis].min(point.pixel[axis]);
                        maximum_pixel[axis] = maximum_pixel[axis].max(point.pixel[axis]);
                    }
                }
                residuals.push(CalibrationResidual { landmark: point.landmark, error_px: Some(error), in_image, inlier });
            }
            Err(GeometryError::BehindCamera | GeometryError::OutOfRange) => {
                residuals.push(CalibrationResidual { landmark: point.landmark, error_px: None, in_image: false, inlier: false });
            }
            Err(error) => return Err(error.into()),
        }
    }
    let dimensions = frozen.camera.intrinsics.dimensions();
    let span = if inliers == 0 { [0.0; 2] } else { [
        (maximum_pixel[0] - minimum[0]).max(0.0) / f64::from(dimensions[0]),
        (maximum_pixel[1] - minimum[1]).max(0.0) / f64::from(dimensions[1]),
    ] };
    let rms = (inliers != 0).then(|| (squared / inliers as f64).sqrt());
    let max_error = (inliers != 0).then_some(maximum);
    let enough_matches = matches.correspondences.len() >= policy.minimum_support;
    let enough_inliers = inliers >= policy.minimum_support;
    let distributed = span.iter().all(|value| *value >= policy.minimum_image_span);
    let fraction = if matches.correspondences.is_empty() { 0.0 } else { inliers as f64 / matches.correspondences.len() as f64 };
    let disposition = if !enough_matches || !enough_inliers || !distributed {
        CalibrationDisposition::Indeterminate
    } else if fraction >= policy.minimum_inlier_fraction && rms.is_some_and(|value| value <= policy.maximum_rms_px) {
        CalibrationDisposition::ValidUnderPolicy
    } else {
        CalibrationDisposition::Invalidate
    };
    budget.charge(0)?;
    Ok(CalibrationMonitorReport { calibration: frozen.id, twin_digest: twin.digest(),
        atlas_digest: atlas.digest(), matches, residuals, projected, inliers,
        rms_inlier_px: rms, maximum_inlier_error_px: max_error,
        image_span_fraction: span, disposition })
}
