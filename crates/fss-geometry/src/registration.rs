use crate::math::{V3, checked};
use crate::{GeometryBasis, GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};
mod focal;
mod planar;
mod search;

pub use focal::{
    FocalCandidateValidation, FocalPoseScan, FocalSample, FocalSampleOutcome, FocalScanOptions,
    FocalValidationSet, scan_camera_focal_length,
};
pub use planar::estimate_camera_pose_adaptive as estimate_camera_pose;
pub use planar::{
    DEFAULT_PLANAR_RESIDUAL_RATIO, PlanarSupport, estimate_camera_pose_adaptive,
    estimate_planar_camera_pose,
};
pub use search::estimate_camera_pose as estimate_nonplanar_camera_pose;

/// One 2D-3D point correspondence: a world landmark observed in a camera pixel.
#[derive(Clone, Copy, PartialEq)]
pub struct Correspondence {
    /// Unique landmark identifier; must be non-zero.
    pub landmark: u64,
    /// Physical installation group the landmark belongs to; must be non-zero. Distinct landmarks in the same group can never appear in both fit and holdout sets.
    pub physical_group: u64,
    /// Landmark position in world coordinates (meters); must be finite.
    pub world: V3,
    /// Observed pixel location `[x, y]` in pixels; must lie inside the intrinsics image bounds.
    pub pixel: [f64; 2],
}
impl std::fmt::Debug for Correspondence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Correspondence")
            .field("landmark", &self.landmark)
            .finish_non_exhaustive()
    }
}

/// Tuning parameters for RANSAC pose estimation and its refinement stage.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PoseSolverOptions {
    /// Number of random minimal-sample trials drawn by RANSAC (1..=1024).
    pub ransac_trials: usize,
    /// Nonlinear refinement iterations after each trial; 1..=100.
    pub refinement_iterations: usize,
    /// Seed for the deterministic trial RNG; identical inputs yield identical candidates.
    pub seed: u64,
    /// Reprojection error in pixels below which a correspondence counts as an inlier; 0.001..=128.0.
    pub inlier_threshold_px: f64,
    /// Minimum inlier count required to accept a pose; at least 6 and at most the correspondence count.
    pub minimum_inliers: usize,
    /// Minimum inliers divided by correspondences, a fraction in (0, 1].
    pub minimum_inlier_fraction: f64,
    /// Lower bound on the world-space extent ratio of the inlier set used to reject degenerate geometry; 1e-10..=0.1.
    pub minimum_axis_ratio: f64,
    /// Minimum span of the inlier set relative to the scene extent, rejecting poses fit to near-collinear points; 0.0..=1.0.
    pub minimum_image_span: f64,
}
impl Default for PoseSolverOptions {
    fn default() -> Self {
        Self {
            ransac_trials: 128,
            refinement_iterations: 30,
            seed: 481_993,
            inlier_threshold_px: 3.0,
            minimum_inliers: 8,
            minimum_inlier_fraction: 0.6,
            minimum_axis_ratio: 1e-6,
            minimum_image_span: 0.05,
        }
    }
}
impl PoseSolverOptions {
    pub(crate) fn validate(self, count: usize) -> Result<(), GeometryError> {
        if self.ransac_trials > 1024
            || !(1..=100).contains(&self.refinement_iterations)
            || self.minimum_inliers < 6
            || self.minimum_inliers > count
            || !self.inlier_threshold_px.is_finite()
            || !(0.001..=128.0).contains(&self.inlier_threshold_px)
            || !self.minimum_inlier_fraction.is_finite()
            || self.minimum_inlier_fraction <= 0.0
            || self.minimum_inlier_fraction > 1.0
            || !self.minimum_axis_ratio.is_finite()
            || !(1e-10..=0.1).contains(&self.minimum_axis_ratio)
            || !self.minimum_image_span.is_finite()
            || !(0.0..=1.0).contains(&self.minimum_image_span)
        {
            return Err(GeometryError::InvalidSolverOptions);
        }
        Ok(())
    }
}

/// A single estimated camera pose with its RANSAC inlier set and reprojection quality.
#[derive(Clone, Debug)]
pub struct PoseCandidate {
    pub(crate) pose: RigidPose,
    pub(crate) inlier_landmarks: Vec<u64>,
    pub(crate) rms_px: f64,
    pub(crate) maximum_error_px: f64,
    pub(crate) support_scale: f64,
}
impl PoseCandidate {
    /// The estimated camera-to-world pose.
    pub fn pose(&self) -> RigidPose {
        self.pose
    }
    /// Identifiers of the landmarks that voted for this pose as RANSAC inliers.
    pub fn inlier_landmarks(&self) -> &[u64] {
        &self.inlier_landmarks
    }
    /// Root-mean-square reprojection error in pixels over the inlier set.
    pub fn rms_px(&self) -> f64 {
        self.rms_px
    }
    /// Largest single reprojection error in pixels over the inlier set.
    pub fn maximum_error_px(&self) -> f64 {
        self.maximum_error_px
    }
}

/// Outcome of a pose search: the basis and intrinsics used, the fit correspondences, and every surviving pose candidate.
#[derive(Debug)]
pub struct PoseSearch {
    pub(crate) basis: GeometryBasis,
    pub(crate) intrinsics: PinholeIntrinsics,
    pub(crate) fit: Vec<Correspondence>,
    pub(crate) candidates: Vec<PoseCandidate>,
    pub(crate) trials_attempted: usize,
    pub(crate) work_units: u64,
    pub(crate) planar_support: Option<PlanarSupport>,
}
impl PoseSearch {
    /// All pose candidates produced by the search, ordered as the solver ranked them.
    pub fn candidates(&self) -> &[PoseCandidate] {
        &self.candidates
    }
    /// Detected planar support configuration, if the solver recognized a dominant plane among the fit points.
    pub fn planar_support(&self) -> Option<PlanarSupport> {
        self.planar_support
    }
    /// The geometry basis the fit correspondences were expressed in.
    pub fn basis(&self) -> GeometryBasis {
        self.basis
    }
    /// Number of RANSAC trials actually executed, which may fall short of the configured budget on early termination.
    pub fn trials_attempted(&self) -> usize {
        self.trials_attempted
    }
    /// Work-budget units consumed by the search.
    pub fn work_units(&self) -> u64 {
        self.work_units
    }

    /// Validates every candidate against a holdout set, returning per-candidate reports plus the indices of those whose maximum holdout error is within `maximum_error_px`.
    pub fn validate_all_candidates(
        &self,
        basis: GeometryBasis,
        holdout: &[Correspondence],
        maximum_error_px: f64,
        budget: &mut WorkBudget<'_>,
    ) -> Result<PoseValidationSet<'_>, GeometryError> {
        budget.charge(0)?;
        if basis != self.basis {
            return Err(GeometryError::BasisMismatch);
        }
        let holdout = validate_points(holdout, self.intrinsics, 4, budget)?;
        let mut reports = Vec::new();
        let mut passing = Vec::new();
        reports
            .try_reserve_exact(self.candidates.len())
            .map_err(|_| GeometryError::LimitExceeded)?;
        passing
            .try_reserve_exact(self.candidates.len())
            .map_err(|_| GeometryError::LimitExceeded)?;
        for index in 0..self.candidates.len() {
            let report =
                self.validate_candidate(index, basis, &holdout, maximum_error_px, budget)?;
            if report.passed {
                passing.push(index);
            }
            reports.push(report);
        }
        budget.charge(0)?;
        Ok(PoseValidationSet {
            search: self,
            holdout,
            maximum_error_px,
            reports,
            passing,
        })
    }

    /// Projects the holdout set through one candidate's pose, reporting per-landmark reprojection residuals and whether every projection lands in-frame within `maximum_error_px`. Rejects holdout points that overlap the fit set (leakage).
    pub fn validate_candidate(
        &self,
        candidate: usize,
        basis: GeometryBasis,
        holdout: &[Correspondence],
        maximum_error_px: f64,
        budget: &mut WorkBudget<'_>,
    ) -> Result<PoseValidation, GeometryError> {
        budget.charge(0)?;
        if basis != self.basis {
            return Err(GeometryError::BasisMismatch);
        }
        if !maximum_error_px.is_finite() || !(0.001..=128.0).contains(&maximum_error_px) {
            return Err(GeometryError::InvalidSolverOptions);
        }
        let candidate = self
            .candidates
            .get(candidate)
            .ok_or(GeometryError::InvalidIndex)?;
        let holdout = validate_points(holdout, self.intrinsics, 4, budget)?;
        for point in &holdout {
            for fit in &self.fit {
                budget.charge(1)?;
                if overlaps(*point, *fit) {
                    return Err(GeometryError::HoldoutLeak);
                }
            }
        }
        let mut residuals = Vec::new();
        residuals
            .try_reserve_exact(holdout.len())
            .map_err(|_| GeometryError::LimitExceeded)?;
        let mut sum = 0.0;
        let mut maximum = 0.0_f64;
        let mut invalid_projection_count = 0;
        for point in &holdout {
            budget.charge(1)?;
            match candidate.pose.project(self.intrinsics, point.world) {
                Ok(pixel) => {
                    let error = (point.pixel[0] - pixel[0]).hypot(point.pixel[1] - pixel[1]);
                    sum += error * error;
                    maximum = maximum.max(error);
                    if !self.intrinsics.contains(pixel) {
                        invalid_projection_count += 1;
                    }
                    residuals.push(LandmarkResidual {
                        landmark: point.landmark,
                        error_px: Some(error),
                    });
                }
                Err(GeometryError::BehindCamera) => {
                    invalid_projection_count += 1;
                    residuals.push(LandmarkResidual {
                        landmark: point.landmark,
                        error_px: None,
                    });
                }
                Err(error) => return Err(error),
            }
        }
        let projected = residuals.iter().filter(|r| r.error_px.is_some()).count();
        let rms_px = if projected == 0 {
            None
        } else {
            Some((sum / projected as f64).sqrt())
        };
        let maximum_error = if projected == 0 { None } else { Some(maximum) };
        budget.charge(0)?;
        Ok(PoseValidation {
            passed: invalid_projection_count == 0 && maximum <= maximum_error_px,
            rms_px,
            maximum_error_px: maximum_error,
            invalid_projection_count,
            residuals,
        })
    }
}

/// Result of validating all candidates of a [`PoseSearch`] against one holdout set.
#[derive(Debug)]
pub struct PoseValidationSet<'a> {
    search: &'a PoseSearch,
    holdout: Vec<Correspondence>,
    maximum_error_px: f64,
    reports: Vec<PoseValidation>,
    passing: Vec<usize>,
}
impl<'a> PoseValidationSet<'a> {
    /// The search whose candidates were validated.
    pub fn search(&self) -> &'a PoseSearch {
        self.search
    }
    /// The (sorted, validated) holdout correspondences used for every report.
    pub fn holdout(&self) -> &[Correspondence] {
        &self.holdout
    }
    /// The per-projection error ceiling in pixels applied during validation.
    pub fn maximum_error_px(&self) -> f64 {
        self.maximum_error_px
    }
    /// One report per candidate, in candidate order.
    pub fn reports(&self) -> &[PoseValidation] {
        &self.reports
    }
    /// Indices (into [`PoseSearch::candidates`]) of candidates that passed validation.
    pub fn passing_candidates(&self) -> &[usize] {
        &self.passing
    }
}

/// Reprojection residual of one holdout landmark.
#[derive(Clone, Debug, PartialEq)]
pub struct LandmarkResidual {
    /// Landmark identifier.
    pub landmark: u64,
    /// Reprojection error in pixels, or `None` when the landmark projected behind the camera.
    pub error_px: Option<f64>,
}

/// Validation report for a single pose candidate against a holdout set.
#[derive(Clone, Debug, PartialEq)]
pub struct PoseValidation {
    /// True when every projection landed in-frame with error at most the requested `maximum_error_px`.
    pub passed: bool,
    /// Root-mean-square reprojection error in pixels over the projected holdout points; `None` if none projected.
    pub rms_px: Option<f64>,
    /// Largest holdout reprojection error in pixels; `None` if no point projected in front of the camera.
    pub maximum_error_px: Option<f64>,
    /// Number of holdout points whose projection failed or fell behind the camera.
    pub invalid_projection_count: usize,
    /// Per-landmark residuals, in holdout order.
    pub residuals: Vec<LandmarkResidual>,
}

pub(crate) fn validate_points(
    points: &[Correspondence],
    k: PinholeIntrinsics,
    minimum: usize,
    budget: &mut WorkBudget<'_>,
) -> Result<Vec<Correspondence>, GeometryError> {
    if points.len() < minimum {
        return Err(GeometryError::InsufficientCorrespondences);
    }
    if points.len() > 512 {
        return Err(GeometryError::LimitExceeded);
    }
    for (i, point) in points.iter().enumerate() {
        budget.charge(1)?;
        checked(point.world)?;
        if point.landmark == 0 || point.physical_group == 0 || !k.contains(point.pixel) {
            return Err(GeometryError::InvalidCorrespondence);
        }
        for other in &points[..i] {
            budget.charge(1)?;
            if overlaps(*point, *other) {
                return Err(GeometryError::InvalidCorrespondence);
            }
        }
    }
    let mut sorted = Vec::new();
    sorted
        .try_reserve_exact(points.len())
        .map_err(|_| GeometryError::LimitExceeded)?;
    sorted.extend_from_slice(points);
    sorted.sort_by_key(|p| p.landmark);
    Ok(sorted)
}

fn overlaps(a: Correspondence, b: Correspondence) -> bool {
    a.landmark == b.landmark
        || a.physical_group == b.physical_group
        || a.world == b.world
        || a.pixel == b.pixel
}
