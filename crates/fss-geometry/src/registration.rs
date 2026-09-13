use crate::{GeometryBasis, GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};
use crate::math::{V3, checked};
mod search;

pub use search::estimate_camera_pose;

/// A supplied association between a static image landmark and a property point.
///
/// The caller must bind both to their source evidence. Matching, distortion
/// correction, map-error modeling, and assigning physical groups are not inferred.
#[derive(Clone, Copy, PartialEq)]
pub struct Correspondence {
    /// Nonzero owner-resolved landmark identity within the pinned map.
    pub landmark: u64,
    /// Nonzero physical-point group, shared by duplicate exposures/aliases.
    pub physical_group: u64,
    /// Property-world coordinates in the declared geometry basis and units.
    pub world: V3,
    /// Observed undistorted pinhole coordinates in the exact pixel-edge grid.
    pub pixel: [f64; 2],
}

impl std::fmt::Debug for Correspondence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Correspondence").field("landmark", &self.landmark).finish_non_exhaustive()
    }
}

/// Bounded controls for the nonplanar, known-intrinsics PnP reference solver.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PoseSolverOptions {
    /// Deterministic six-point trials after the initial all-point fit; 0..=1024.
    pub ransac_trials: usize,
    /// Maximum LM iterations per local fit; 1..=100.
    pub refinement_iterations: usize,
    /// Seed for the explicitly reproducible subset schedule, never ambient randomness.
    pub seed: u64,
    /// Absolute image error required for an inlier; 0.001..=128 pixels.
    pub inlier_threshold_px: f64,
    /// Minimum inlier count, at least six and at most the supplied count.
    pub minimum_inliers: usize,
    /// Minimum inlier fraction in addition to the count floor; (0,1].
    pub minimum_inlier_fraction: f64,
    /// Smallest/largest 3D covariance eigenvalue floor; [1e-10,0.1].
    pub minimum_axis_ratio: f64,
    /// Minimum inlier image span along both axes, as a fraction of image size.
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
    fn validate(self, count: usize) -> Result<(), GeometryError> {
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

/// A retained geometric hypothesis, not a calibration or accuracy certificate.
#[derive(Clone, Debug)]
pub struct PoseCandidate {
    pose: RigidPose,
    inlier_landmarks: Vec<u64>,
    rms_px: f64,
    maximum_error_px: f64,
    support_scale: f64,
}

impl PoseCandidate {
    /// Estimated world-to-camera pose under the supplied fixed map and intrinsics.
    pub fn pose(&self) -> RigidPose { self.pose }
    /// Sorted inlier identities; rejected observations remain in the search input.
    pub fn inlier_landmarks(&self) -> &[u64] { &self.inlier_landmarks }
    /// Inlier reprojection RMS in pixels; not physical position uncertainty.
    pub fn rms_px(&self) -> f64 { self.rms_px }
    /// Largest inlier reprojection error, not the error of excluded observations.
    pub fn maximum_error_px(&self) -> f64 { self.maximum_error_px }
}

/// Search result retaining distinct successful pose modes instead of guessing one.
///
/// The bounded sampled search cannot prove that every possible pose was explored.
/// Near-identical modes are clustered within 0.01 times the smaller inlier-support RMS extent and 0.02
/// radians. Those are numerical clustering thresholds, not accuracy guarantees.
#[derive(Debug)]
pub struct PoseSearch {
    basis: GeometryBasis,
    intrinsics: PinholeIntrinsics,
    fit: Vec<Correspondence>,
    candidates: Vec<PoseCandidate>,
    trials_attempted: usize,
    work_units: u64,
}

impl PoseSearch {
    /// Surviving modes, ordered by descending support then ascending fit error.
    pub fn candidates(&self) -> &[PoseCandidate] { &self.candidates }
    /// Exact supplied geometry frame/revision.
    pub fn basis(&self) -> GeometryBasis { self.basis }
    /// Number of all-point and minimal-subset seeds attempted.
    pub fn trials_attempted(&self) -> usize { self.trials_attempted }
    /// Charged reference work, excluding any earlier work on the same budget.
    pub fn work_units(&self) -> u64 { self.work_units }

    /// Score an explicitly selected candidate against at least four held landmarks.
    ///
    /// No refitting occurs. All fitting inputs, including rejected outliers, are
    /// barred from the holdout by identity, physical group, exact world position,
    /// or exact observed pixel. These guards do not prove remaining independence.
    /// The result measures fixed-map consistency, never absolute metric accuracy.
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

/// An excluded physical landmark's measured image residual.
#[derive(Clone, Debug, PartialEq)]
pub struct LandmarkResidual {
    /// Owner-resolved landmark identity.
    pub landmark: u64,
    /// Image error, or None when no positive-depth projection exists.
    pub error_px: Option<f64>,
}

/// Immutable holdout result; failure preserves its numerical evidence.
#[derive(Clone, Debug, PartialEq)]
pub struct PoseValidation {
    /// Every held point projects in-domain and meets the caller's pixel bound.
    pub passed: bool,
    /// RMS over projectable points, not including missing projections as zeros.
    pub rms_px: Option<f64>,
    /// Maximum over projectable points.
    pub maximum_error_px: Option<f64>,
    /// Behind-camera or out-of-image projections.
    pub invalid_projection_count: usize,
    /// Every supplied held landmark, in canonical identity order.
    pub residuals: Vec<LandmarkResidual>,
}


fn validate_points(points: &[Correspondence], k: PinholeIntrinsics, minimum: usize,
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
