#![forbid(unsafe_code)]
//! Read-only validity monitoring for a frozen camera pose against current static landmarks.
//!
//! This module never refits or activates calibration. It compares current image-to-map
//! matches with one exact frozen pose and returns Valid, Invalidate, or Indeterminate.

use crate::PropertyTwin;
use crate::localization::{
    FeatureFrame, LocalizationAtlas, LocalizationCamera, LocalizationError, MatchOptions,
    MatchReport,
};
use fss_geometry::{GeometryError, RigidPose, WorkBudget};

/// A frozen camera calibration snapshot under validity monitoring: its identifier plus the exact
/// camera intrinsics/image domain and pose the monitor compares incoming matches against.
#[derive(Clone, Copy, Debug)]
pub struct FrozenCalibration {
    /// Digest identifying this frozen calibration snapshot; must be nonzero.
    pub id: [u8; 32],
    /// Camera intrinsics, clock, and image domain the query frame must match exactly.
    pub camera: LocalizationCamera,
    /// World-to-image pose reprojected onto every matched landmark.
    pub pose: RigidPose,
}

/// Tunable thresholds controlling how live calibration residuals are judged.
#[derive(Clone, Copy, Debug)]
pub struct CalibrationMonitorPolicy {
    /// Per-correspondence reprojection error under which a projected point counts as an inlier, in pixels; validated to `[0.001, 128]`.
    pub inlier_threshold_px: f64,
    /// Maximum tolerated root-mean-square inlier reprojection error in pixels; validated to `[0.001, 128]`.
    pub maximum_rms_px: f64,
    /// Minimum number of correspondences and of projected inliers required to reach any verdict; validated to `[4, 512]`.
    pub minimum_support: usize,
    /// Minimum ratio of inliers to total correspondences required for `ValidUnderPolicy`; validated to `(0, 1]`.
    pub minimum_inlier_fraction: f64,
    /// Minimum fraction of the image width and height spanned by matched pixels below which the evidence is `Indeterminate`; validated to `[0, 1]`.
    pub minimum_image_span: f64,
}
impl Default for CalibrationMonitorPolicy {
    fn default() -> Self {
        Self {
            inlier_threshold_px: 3.0,
            maximum_rms_px: 1.5,
            minimum_support: 8,
            minimum_inlier_fraction: 0.7,
            minimum_image_span: 0.08,
        }
    }
}
impl CalibrationMonitorPolicy {
    fn validate(self) -> Result<(), CalibrationMonitorError> {
        if !self.inlier_threshold_px.is_finite()
            || !(0.001..=128.0).contains(&self.inlier_threshold_px)
            || !self.maximum_rms_px.is_finite()
            || !(0.001..=128.0).contains(&self.maximum_rms_px)
            || !(4..=512).contains(&self.minimum_support)
            || !self.minimum_inlier_fraction.is_finite()
            || self.minimum_inlier_fraction <= 0.0
            || self.minimum_inlier_fraction > 1.0
            || !self.minimum_image_span.is_finite()
            || !(0.0..=1.0).contains(&self.minimum_image_span)
        {
            return Err(CalibrationMonitorError::InvalidInput);
        }
        Ok(())
    }
}

/// Verdict on the frozen calibration given the current monitor evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationDisposition {
    /// Calibration still passes every policy threshold.
    ValidUnderPolicy,
    /// Evidence was sufficient and rejected the frozen calibration.
    Invalidate,
    /// Evidence was too sparse or unevenly distributed to judge.
    Indeterminate,
}

/// Errors raised while monitoring a frozen calibration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationMonitorError {
    /// Policy or frozen snapshot fields failed validation.
    InvalidInput,
    /// Query frame dimensions or image domain disagree with the frozen camera.
    BasisMismatch,
    /// A reference frame in the atlas shares the query frame's exposure.
    ReferenceExposure,
    /// Atlas matching of the query frame failed.
    Localization(LocalizationError),
    /// Reprojection geometry failed (other than points behind the camera or out of range).
    Geometry(GeometryError),
}
impl From<LocalizationError> for CalibrationMonitorError {
    fn from(value: LocalizationError) -> Self {
        Self::Localization(value)
    }
}
impl From<GeometryError> for CalibrationMonitorError {
    fn from(value: GeometryError) -> Self {
        Self::Geometry(value)
    }
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

/// Reprojection outcome for one matched landmark against the frozen pose.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CalibrationResidual {
    /// Identifier of the matched landmark the residual was computed for.
    pub landmark: u64,
    /// Reprojection error in pixels, or `None` when the landmark projects behind the camera or out of range.
    pub error_px: Option<f64>,
    /// Whether the projected point falls inside the camera image.
    pub in_image: bool,
    /// Whether the point is in-frame and its error is within `inlier_threshold_px`.
    pub inlier: bool,
}

/// Full monitor verdict for one comparison of current matches against a frozen calibration.
#[derive(Debug)]
pub struct CalibrationMonitorReport {
    /// Identifier of the frozen calibration that was monitored.
    pub calibration: [u8; 32],
    /// Digest of the property twin the matches were computed against.
    pub twin_digest: [u8; 32],
    /// Digest of the localization atlas generation the matches came from.
    pub atlas_digest: [u8; 32],
    /// Raw atlas match report for the query frame.
    pub matches: MatchReport,
    /// Per-landmark residuals in match order.
    pub residuals: Vec<CalibrationResidual>,
    /// Number of correspondences whose landmark projected inside the image.
    pub projected: usize,
    /// Number of in-frame correspondences within the inlier threshold.
    pub inliers: usize,
    /// Root-mean-square inlier error in pixels, or `None` when there are no inliers.
    pub rms_inlier_px: Option<f64>,
    /// Largest inlier reprojection error in pixels, or `None` when there are no inliers.
    pub maximum_inlier_error_px: Option<f64>,
    /// Fraction of the image width and height spanned by matched pixels, per axis in `[0, 1]`.
    pub image_span_fraction: [f64; 2],
    /// Final verdict from applying the policy to the statistics above.
    pub disposition: CalibrationDisposition,
}

/// Matches the query frame against the atlas, reprojects each correspondence through the frozen
/// pose, and returns a [`CalibrationMonitorReport`] with residuals, statistics, and the policy
/// verdict. Fails fast on invalid policy or snapshot, basis mismatch, or a reused reference exposure.
pub fn monitor_calibration(
    twin: &PropertyTwin,
    atlas: &LocalizationAtlas,
    query: &FeatureFrame,
    frozen: FrozenCalibration,
    matching: MatchOptions,
    policy: CalibrationMonitorPolicy,
    budget: &mut WorkBudget<'_>,
) -> Result<CalibrationMonitorReport, CalibrationMonitorError> {
    budget.charge(0)?;
    policy.validate()?;
    if frozen.id == [0; 32] {
        return Err(CalibrationMonitorError::InvalidInput);
    }
    if query.identity().dimensions != frozen.camera.intrinsics.dimensions()
        || query.identity().image_domain != frozen.camera.image_domain
    {
        return Err(CalibrationMonitorError::BasisMismatch);
    }
    if atlas
        .references()
        .iter()
        .any(|reference| reference.frame.identity().exposure == query.identity().exposure)
    {
        return Err(CalibrationMonitorError::ReferenceExposure);
    }
    let matches = atlas.match_frame(twin, query, matching, budget)?;
    let mut residuals = Vec::new();
    residuals
        .try_reserve_exact(matches.correspondences.len())
        .map_err(|_| CalibrationMonitorError::InvalidInput)?;
    let mut projected = 0usize;
    let mut inliers = 0usize;
    let mut squared = 0.0;
    let mut maximum = 0.0_f64;
    let mut support_min = [f64::INFINITY; 2];
    let mut support_max = [f64::NEG_INFINITY; 2];
    for point in &matches.correspondences {
        budget.charge(4)?;
        for axis in 0..2 {
            support_min[axis] = support_min[axis].min(point.pixel[axis]);
            support_max[axis] = support_max[axis].max(point.pixel[axis]);
        }
        match frozen.pose.project(frozen.camera.intrinsics, point.world) {
            Ok(expected) => {
                let in_image = frozen.camera.intrinsics.contains(expected);
                let error = (expected[0] - point.pixel[0]).hypot(expected[1] - point.pixel[1]);
                let inlier = in_image && error <= policy.inlier_threshold_px;
                projected += usize::from(in_image);
                if inlier {
                    inliers += 1;
                    squared += error * error;
                    maximum = maximum.max(error);
                }
                residuals.push(CalibrationResidual {
                    landmark: point.landmark,
                    error_px: Some(error),
                    in_image,
                    inlier,
                });
            }
            Err(GeometryError::BehindCamera | GeometryError::OutOfRange) => {
                residuals.push(CalibrationResidual {
                    landmark: point.landmark,
                    error_px: None,
                    in_image: false,
                    inlier: false,
                });
            }
            Err(error) => return Err(error.into()),
        }
    }
    let dimensions = frozen.camera.intrinsics.dimensions();
    let span = if matches.correspondences.is_empty() {
        [0.0; 2]
    } else {
        [
            (support_max[0] - support_min[0]).max(0.0) / f64::from(dimensions[0]),
            (support_max[1] - support_min[1]).max(0.0) / f64::from(dimensions[1]),
        ]
    };
    let rms = (inliers != 0).then(|| (squared / inliers as f64).sqrt());
    let max_error = (inliers != 0).then_some(maximum);
    let enough_matches = matches.correspondences.len() >= policy.minimum_support;
    let enough_projected = projected >= policy.minimum_support;
    let distributed = span.iter().all(|value| *value >= policy.minimum_image_span);
    let fraction = if matches.correspondences.is_empty() {
        0.0
    } else {
        inliers as f64 / matches.correspondences.len() as f64
    };
    let disposition = if !enough_matches || !enough_projected || !distributed {
        CalibrationDisposition::Indeterminate
    } else if inliers >= policy.minimum_support
        && fraction >= policy.minimum_inlier_fraction
        && rms.is_some_and(|value| value <= policy.maximum_rms_px)
    {
        CalibrationDisposition::ValidUnderPolicy
    } else {
        CalibrationDisposition::Invalidate
    };
    budget.charge(0)?;
    Ok(CalibrationMonitorReport {
        calibration: frozen.id,
        twin_digest: twin.digest(),
        atlas_digest: atlas.digest(),
        matches,
        residuals,
        projected,
        inliers,
        rms_inlier_px: rms,
        maximum_inlier_error_px: max_error,
        image_span_fraction: span,
        disposition,
    })
}
