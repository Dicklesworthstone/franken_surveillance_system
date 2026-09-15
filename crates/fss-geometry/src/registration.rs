use crate::{GeometryBasis, GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};
use crate::math::{V3, checked};
mod search;
mod planar;

pub use search::estimate_camera_pose as estimate_nonplanar_camera_pose;
pub use planar::estimate_camera_pose_adaptive as estimate_camera_pose;
pub use planar::{DEFAULT_PLANAR_RESIDUAL_RATIO, PlanarSupport,
    estimate_camera_pose_adaptive, estimate_planar_camera_pose};

#[derive(Clone, Copy, PartialEq)]
pub struct Correspondence {
    pub landmark: u64,
    pub physical_group: u64,
    pub world: V3,
    pub pixel: [f64; 2],
}
impl std::fmt::Debug for Correspondence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Correspondence").field("landmark", &self.landmark).finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PoseSolverOptions {
    pub ransac_trials: usize,
    pub refinement_iterations: usize,
    pub seed: u64,
    pub inlier_threshold_px: f64,
    pub minimum_inliers: usize,
    pub minimum_inlier_fraction: f64,
    pub minimum_axis_ratio: f64,
    pub minimum_image_span: f64,
}
impl Default for PoseSolverOptions {
    fn default() -> Self {
        Self { ransac_trials: 128, refinement_iterations: 30, seed: 481_993,
            inlier_threshold_px: 3.0, minimum_inliers: 8, minimum_inlier_fraction: 0.6,
            minimum_axis_ratio: 1e-6, minimum_image_span: 0.05 }
    }
}
impl PoseSolverOptions {
    pub(crate) fn validate(self, count: usize) -> Result<(), GeometryError> {
        if self.ransac_trials > 1024 || !(1..=100).contains(&self.refinement_iterations)
            || self.minimum_inliers < 6 || self.minimum_inliers > count
            || !self.inlier_threshold_px.is_finite() || !(0.001..=128.0).contains(&self.inlier_threshold_px)
            || !self.minimum_inlier_fraction.is_finite() || self.minimum_inlier_fraction <= 0.0 || self.minimum_inlier_fraction > 1.0
            || !self.minimum_axis_ratio.is_finite() || !(1e-10..=0.1).contains(&self.minimum_axis_ratio)
            || !self.minimum_image_span.is_finite() || !(0.0..=1.0).contains(&self.minimum_image_span) {
            return Err(GeometryError::InvalidSolverOptions);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct PoseCandidate {
    pub(crate) pose: RigidPose,
    pub(crate) inlier_landmarks: Vec<u64>,
    pub(crate) rms_px: f64,
    pub(crate) maximum_error_px: f64,
    pub(crate) support_scale: f64,
}
impl PoseCandidate {
    pub fn pose(&self) -> RigidPose { self.pose }
    pub fn inlier_landmarks(&self) -> &[u64] { &self.inlier_landmarks }
    pub fn rms_px(&self) -> f64 { self.rms_px }
    pub fn maximum_error_px(&self) -> f64 { self.maximum_error_px }
}

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
    pub fn candidates(&self) -> &[PoseCandidate] { &self.candidates }
    pub fn planar_support(&self) -> Option<PlanarSupport> { self.planar_support }
    pub fn basis(&self) -> GeometryBasis { self.basis }
    pub fn trials_attempted(&self) -> usize { self.trials_attempted }
    pub fn work_units(&self) -> u64 { self.work_units }

    pub fn validate_all_candidates(&self, basis: GeometryBasis, holdout: &[Correspondence],
        maximum_error_px: f64, budget: &mut WorkBudget<'_>) -> Result<PoseValidationSet<'_>, GeometryError> {
        budget.charge(0)?;
        if basis != self.basis { return Err(GeometryError::BasisMismatch); }
        let holdout = validate_points(holdout, self.intrinsics, 4, budget)?;
        let mut reports = Vec::new();
        let mut passing = Vec::new();
        reports.try_reserve_exact(self.candidates.len()).map_err(|_| GeometryError::LimitExceeded)?;
        passing.try_reserve_exact(self.candidates.len()).map_err(|_| GeometryError::LimitExceeded)?;
        for index in 0..self.candidates.len() {
            let report = self.validate_candidate(index, basis, &holdout, maximum_error_px, budget)?;
            if report.passed { passing.push(index); }
            reports.push(report);
        }
        budget.charge(0)?;
        Ok(PoseValidationSet { search: self, holdout, maximum_error_px, reports, passing })
    }

    pub fn validate_candidate(&self, candidate: usize, basis: GeometryBasis,
        holdout: &[Correspondence], maximum_error_px: f64, budget: &mut WorkBudget<'_>)
        -> Result<PoseValidation, GeometryError> {
        budget.charge(0)?;
        if basis != self.basis { return Err(GeometryError::BasisMismatch); }
        if !maximum_error_px.is_finite() || !(0.001..=128.0).contains(&maximum_error_px) {
            return Err(GeometryError::InvalidSolverOptions);
        }
        let candidate = self.candidates.get(candidate).ok_or(GeometryError::InvalidIndex)?;
        let holdout = validate_points(holdout, self.intrinsics, 4, budget)?;
        for point in &holdout {
            for fit in &self.fit {
                budget.charge(1)?;
                if overlaps(*point, *fit) { return Err(GeometryError::HoldoutLeak); }
            }
        }
        let mut residuals = Vec::new();
        residuals.try_reserve_exact(holdout.len()).map_err(|_| GeometryError::LimitExceeded)?;
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
                    if !self.intrinsics.contains(pixel) { invalid_projection_count += 1; }
                    residuals.push(LandmarkResidual { landmark: point.landmark, error_px: Some(error) });
                }
                Err(GeometryError::BehindCamera) => {
                    invalid_projection_count += 1;
                    residuals.push(LandmarkResidual { landmark: point.landmark, error_px: None });
                }
                Err(error) => return Err(error),
            }
        }
        let projected = residuals.iter().filter(|r| r.error_px.is_some()).count();
        let rms_px = if projected == 0 { None } else { Some((sum / projected as f64).sqrt()) };
        let maximum_error = if projected == 0 { None } else { Some(maximum) };
        budget.charge(0)?;
        Ok(PoseValidation { passed: invalid_projection_count == 0 && maximum <= maximum_error_px,
            rms_px, maximum_error_px: maximum_error, invalid_projection_count, residuals })
    }
}

#[derive(Debug)]
pub struct PoseValidationSet<'a> {
    search: &'a PoseSearch,
    holdout: Vec<Correspondence>,
    maximum_error_px: f64,
    reports: Vec<PoseValidation>,
    passing: Vec<usize>,
}
impl<'a> PoseValidationSet<'a> {
    pub fn search(&self) -> &'a PoseSearch { self.search }
    pub fn holdout(&self) -> &[Correspondence] { &self.holdout }
    pub fn maximum_error_px(&self) -> f64 { self.maximum_error_px }
    pub fn reports(&self) -> &[PoseValidation] { &self.reports }
    pub fn passing_candidates(&self) -> &[usize] { &self.passing }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LandmarkResidual { pub landmark: u64, pub error_px: Option<f64> }

#[derive(Clone, Debug, PartialEq)]
pub struct PoseValidation {
    pub passed: bool,
    pub rms_px: Option<f64>,
    pub maximum_error_px: Option<f64>,
    pub invalid_projection_count: usize,
    pub residuals: Vec<LandmarkResidual>,
}

pub(crate) fn validate_points(points: &[Correspondence], k: PinholeIntrinsics, minimum: usize,
    budget: &mut WorkBudget<'_>) -> Result<Vec<Correspondence>, GeometryError> {
    if points.len() < minimum { return Err(GeometryError::InsufficientCorrespondences); }
    if points.len() > 512 { return Err(GeometryError::LimitExceeded); }
    for (i, point) in points.iter().enumerate() {
        budget.charge(1)?;
        checked(point.world)?;
        if point.landmark == 0 || point.physical_group == 0 || !k.contains(point.pixel) {
            return Err(GeometryError::InvalidCorrespondence);
        }
        for other in &points[..i] {
            budget.charge(1)?;
            if overlaps(*point, *other) { return Err(GeometryError::InvalidCorrespondence); }
        }
    }
    let mut sorted = Vec::new();
    sorted.try_reserve_exact(points.len()).map_err(|_| GeometryError::LimitExceeded)?;
    sorted.extend_from_slice(points);
    sorted.sort_by_key(|p| p.landmark);
    Ok(sorted)
}

fn overlaps(a: Correspondence, b: Correspondence) -> bool {
    a.landmark == b.landmark || a.physical_group == b.physical_group || a.world == b.world || a.pixel == b.pixel
}
