#![forbid(unsafe_code)]
//! Bounded multi-view triangulation of an already-associated physical point.
//!
//! This is not an identity matcher. Inputs must depict the same physical feature,
//! in qualified undistorted image domains and one owner-resolved world frame.
//! The covariance is conditional on fixed cameras and independent isotropic pixel
//! noise. It excludes calibration, clock, correspondence and shared-mode errors;
//! callers must retain those uncertainties separately. No ground plane is assumed.

use crate::math::{M3, V3, add, checked, cross, dot, norm, scale, sub};
use crate::{GeometryError, PinholeIntrinsics, Ray, RigidPose, WorkBudget};

/// Hard bound on cameras participating in one point solve.
pub const MAX_TRIANGULATION_VIEWS: usize = 32;

/// One selected, undistorted observation of a common physical point.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CalibratedView {
    /// Nonzero logical camera ID. Repeated cameras are not independent views.
    pub camera: u64,
    /// World-to-camera transform, in the common source-world units.
    pub pose: RigidPose,
    /// Exact qualified image mode; raw distorted pixels are inadmissible.
    pub intrinsics: PinholeIntrinsics,
    /// Pixel-edge coordinate inside the half-open image domain.
    pub pixel: [f64; 2],
    /// Assumed isotropic pixel-noise standard deviation, not a calibration bound.
    pub sigma_pixels: f64,
}

/// Explicit work, consensus, distance and observability policy.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TriangulationOptions {
    /// Minimum distinct cameras in a retained consensus, at least two.
    pub min_views: usize,
    /// Maximum explicitly rejected cameras. Zero requires agreement of all views.
    pub max_outliers: usize,
    /// Euclidean reprojection gate in pixels, independent of statistical weights.
    pub max_reprojection_pixels: f64,
    /// Minimum angle between undirected bearing lines, in (0, pi/2) radians.
    pub min_ray_angle_radians: f64,
    /// Maximum point-to-camera distance, in source-world units, not assumed metres.
    pub max_distance: f64,
    /// Maximum spectral condition number of the pixel information matrix.
    pub max_condition_number: f64,
    /// Maximum nonlinear iterations, between one and 32.
    pub max_iterations: usize,
}
impl Default for TriangulationOptions {
    fn default() -> Self {
        Self {
            min_views: 2,
            max_outliers: 0,
            max_reprojection_pixels: 3.0,
            min_ray_angle_radians: 0.001,
            max_distance: 1000.0,
            max_condition_number: 1e10,
            max_iterations: 16,
        }
    }
}

/// A typed refusal never publishes a guessed 3D point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TriangulationError {
    /// Invalid geometry, resource exhaustion or cooperative cancellation.
    Geometry(GeometryError),
    /// Too few views to satisfy the requested consensus.
    InsufficientViews,
    /// A camera ID, observation or noise assumption is invalid.
    InvalidView,
    /// Multiple observations from one camera would double-count that view.
    DuplicateCamera,
    /// Coincident, parallel or poorly conditioned views do not constrain depth.
    WeakGeometry,
    /// No front-facing point satisfies the distance and consensus gates.
    NoConsensus,
    /// Equally large but different camera subsets support competing explanations.
    AmbiguousConsensus,
    /// Refinement changed the consensus membership; a fresh association is needed.
    UnstableConsensus,
    /// The bounded nonlinear refinement did not converge.
    NotConverged,
}
impl From<GeometryError> for TriangulationError {
    fn from(error: GeometryError) -> Self {
        Self::Geometry(error)
    }
}
impl std::fmt::Display for TriangulationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Geometry(_) => "triangulation geometry or work failure",
            Self::InsufficientViews => "insufficient triangulation views",
            Self::InvalidView => "invalid triangulation observation",
            Self::DuplicateCamera => "duplicate triangulation camera",
            Self::WeakGeometry => "triangulation depth is weakly observable",
            Self::NoConsensus => "no admissible triangulation consensus",
            Self::AmbiguousConsensus => "competing triangulation camera subsets",
            Self::UnstableConsensus => "triangulation consensus changed during refinement",
            Self::NotConverged => "bounded triangulation did not converge",
        })
    }
}
impl std::error::Error for TriangulationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Geometry(error) => Some(error),
            _ => None,
        }
    }
}

/// Per-camera diagnostic, retained for inliers and rejected views alike.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TriangulationResidual {
    /// Logical camera identity, in canonical ascending order.
    pub camera: u64,
    /// Whether this camera belongs to the unique retained consensus.
    pub inlier: bool,
    /// Euclidean pixel residual; absent behind the camera or beyond the distance limit.
    pub pixels: Option<f64>,
}

/// Nominal common point and conditional pixel-noise uncertainty, not metric truth.
#[derive(Clone, Debug, PartialEq)]
pub struct TriangulatedPoint {
    /// Nominal point in the caller's source-world frame.
    pub position: [f64; 3],
    /// Inverse reprojection information, inflated for excess residual variance.
    /// This excludes camera, clock and correspondence uncertainty.
    pub pixel_noise_covariance: [[f64; 3]; 3],
    /// Spectral condition number before residual-variance inflation.
    pub condition_number: f64,
    /// Unweighted RMS Euclidean reprojection residual of retained views.
    pub rms_reprojection_pixels: f64,
    /// Largest acute angle between retained bearing lines.
    pub max_ray_angle_radians: f64,
    /// Canonical camera diagnostics, including explicitly rejected views.
    pub residuals: Vec<TriangulationResidual>,
}

/// Fit one common point using exhaustive bounded two-view consensus and weighted
/// reprojection refinement. Equal-size different consensuses are refused, not
/// tie-broken by camera order or an arbitrarily small residual difference.
///
/// The work bound is O(V^3 + I V), V <= 32 and I <= 32, with no I/O. Every loop
/// charges the caller's budget before its work. Input order cannot change the
/// arithmetic order, consensus choice or diagnostic order.
pub fn triangulate(
    views: &[CalibratedView],
    options: TriangulationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<TriangulatedPoint, TriangulationError> {
    budget.charge(0)?;
    validate_options(options)?;
    if views.len() > MAX_TRIANGULATION_VIEWS {
        return Err(GeometryError::LimitExceeded.into());
    }
    if views.len() < options.min_views {
        return Err(TriangulationError::InsufficientViews);
    }
    budget.charge(256 * views.len() as u64)?;
    let mut ordered = Vec::new();
    ordered
        .try_reserve_exact(views.len())
        .map_err(|_| GeometryError::LimitExceeded)?;
    ordered.extend_from_slice(views);
    ordered.sort_by_key(|view| view.camera);
    let mut rays = Vec::new();
    rays.try_reserve_exact(views.len())
        .map_err(|_| GeometryError::LimitExceeded)?;
    for (i, view) in ordered.iter().enumerate() {
        if view.camera == 0
            || !view.sigma_pixels.is_finite()
            || !(1e-3..=1e3).contains(&view.sigma_pixels)
            || !view.intrinsics.contains(view.pixel)
        {
            return Err(TriangulationError::InvalidView);
        }
        if i > 0 && ordered[i - 1].camera == view.camera {
            return Err(TriangulationError::DuplicateCamera);
        }
        rays.push(view.pose.ray(view.intrinsics, view.pixel)?);
    }

    let min_sine = options.min_ray_angle_radians.sin();
    let mut best: Option<(u32, V3, f64)> = None;
    let mut ambiguous = false;
    let mut nonparallel = false;
    for i in 0..rays.len() {
        for j in i + 1..rays.len() {
            budget.charge(128)?;
            if norm(cross(rays[i].direction(), rays[j].direction())) < min_sine {
                continue;
            }
            nonparallel = true;
            let Some(point) = pair_seed(rays[i], rays[j], options.max_distance) else {
                continue;
            };
            let (mask, cost) = classify(&ordered, point, options, budget)?;
            let count = mask.count_ones() as usize;
            if count < options.min_views || ordered.len() - count > options.max_outliers {
                continue;
            }
            match best {
                None => best = Some((mask, point, cost)),
                Some((previous, _, _)) if mask.count_ones() > previous.count_ones() => {
                    best = Some((mask, point, cost));
                    ambiguous = false;
                }
                Some((previous, _, previous_cost))
                    if mask.count_ones() == previous.count_ones() =>
                {
                    if mask != previous {
                        ambiguous = true;
                    } else if cost < previous_cost {
                        best = Some((mask, point, cost));
                    }
                }
                _ => {}
            }
        }
    }
    let Some((mask, seed, _)) = best else {
        return Err(if nonparallel {
            TriangulationError::NoConsensus
        } else {
            TriangulationError::WeakGeometry
        });
    };
    if ambiguous {
        return Err(TriangulationError::AmbiguousConsensus);
    }
    let position = refine(&ordered, mask, seed, options, budget)?;
    let (final_mask, _) = classify(&ordered, position, options, budget)?;
    if final_mask != mask {
        return Err(TriangulationError::UnstableConsensus);
    }
    let (information, _, cost) = normal_system(&ordered, mask, position, budget)?;
    let (mut covariance, condition) = invert_information(information, options, budget)?;
    let degrees = f64::from(2 * mask.count_ones() - 3);
    let inflation = (cost / degrees).max(1.0);
    for row in &mut covariance {
        for value in row {
            *value *= inflation;
            if !value.is_finite() {
                return Err(GeometryError::NonFinite.into());
            }
        }
    }
    let mut max_sine: f64 = 0.0;
    for i in 0..rays.len() {
        for j in i + 1..rays.len() {
            budget.charge(32)?;
            if mask & (1 << i) != 0 && mask & (1 << j) != 0 {
                max_sine = max_sine.max(norm(cross(rays[i].direction(), rays[j].direction())));
            }
        }
    }
    if max_sine < min_sine {
        return Err(TriangulationError::WeakGeometry);
    }
    let mut residuals = Vec::new();
    residuals
        .try_reserve_exact(ordered.len())
        .map_err(|_| GeometryError::LimitExceeded)?;
    let mut squared = 0.0;
    for (i, view) in ordered.iter().enumerate() {
        budget.charge(128)?;
        let pixels = residual(*view, position, options.max_distance)?;
        let inlier = mask & (1 << i) != 0;
        if inlier {
            let value = pixels.ok_or(TriangulationError::NoConsensus)?;
            squared += value * value;
        }
        residuals.push(TriangulationResidual {
            camera: view.camera,
            inlier,
            pixels,
        });
    }
    budget.charge(0)?;
    Ok(TriangulatedPoint {
        position,
        pixel_noise_covariance: covariance,
        condition_number: condition,
        rms_reprojection_pixels: (squared / f64::from(mask.count_ones())).sqrt(),
        max_ray_angle_radians: max_sine.clamp(0.0, 1.0).asin(),
        residuals,
    })
}

fn validate_options(options: TriangulationOptions) -> Result<(), TriangulationError> {
    if !(2..=MAX_TRIANGULATION_VIEWS).contains(&options.min_views)
        || options.max_outliers > MAX_TRIANGULATION_VIEWS - 2
        || !(1..=32).contains(&options.max_iterations)
        || !options.max_reprojection_pixels.is_finite()
        || !(1e-6..=1e4).contains(&options.max_reprojection_pixels)
        || !options.min_ray_angle_radians.is_finite()
        || !(1e-6..std::f64::consts::FRAC_PI_2).contains(&options.min_ray_angle_radians)
        || !options.max_distance.is_finite()
        || !(1e-6..=1e12).contains(&options.max_distance)
        || !options.max_condition_number.is_finite()
        || !(1.0..=1e12).contains(&options.max_condition_number)
    {
        return Err(GeometryError::InvalidSolverOptions.into());
    }
    Ok(())
}

fn pair_seed(a: Ray, b: Ray, far: f64) -> Option<V3> {
    let u = a.direction();
    let v = b.direction();
    let w = sub(a.origin(), b.origin());
    let cosine = dot(u, v);
    // Cross-product form avoids cancellation in 1 - cosine^2 at small angles.
    let normal = cross(u, v);
    let denominator = dot(normal, normal);
    if denominator <= 0.0 || norm(w) <= 1e-12 {
        return None;
    }
    let du = dot(u, w);
    let dv = dot(v, w);
    let ta = (cosine * dv - du) / denominator;
    let tb = (dv - cosine * du) / denominator;
    if !(1e-9..=far).contains(&ta) || !(1e-9..=far).contains(&tb) {
        return None;
    }
    // Average in the first camera's local frame to preserve small baselines.
    checked(add(
        a.origin(),
        scale(add(scale(u, ta), sub(scale(v, tb), w)), 0.5),
    ))
    .ok()
}

fn residual(view: CalibratedView, point: V3, far: f64) -> Result<Option<f64>, TriangulationError> {
    if norm(sub(point, view.pose.center())) > far {
        return Ok(None);
    }
    match view.pose.project(view.intrinsics, point) {
        Ok(pixel) => Ok(Some(
            (pixel[0] - view.pixel[0]).hypot(pixel[1] - view.pixel[1]),
        )),
        Err(GeometryError::BehindCamera) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn classify(
    views: &[CalibratedView],
    point: V3,
    options: TriangulationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<(u32, f64), TriangulationError> {
    let mut mask = 0;
    let mut cost = 0.0;
    for (i, view) in views.iter().enumerate() {
        budget.charge(128)?;
        if let Some(error) = residual(*view, point, options.max_distance)?
            && error <= options.max_reprojection_pixels
        {
            mask |= 1 << i;
            cost += (error / view.sigma_pixels).powi(2);
        }
    }
    Ok((mask, cost))
}

fn normal_system(
    views: &[CalibratedView],
    mask: u32,
    point: V3,
    budget: &mut WorkBudget<'_>,
) -> Result<(M3, V3, f64), TriangulationError> {
    let mut h = [[0.0; 3]; 3];
    let mut g = [0.0; 3];
    let mut cost = 0.0;
    for (i, view) in views.iter().enumerate() {
        budget.charge(256)?;
        if mask & (1 << i) == 0 {
            continue;
        }
        let p = view.pose.transform(point)?;
        let pixel = view.intrinsics.project(p)?;
        let r = view.pose.rotation();
        let focal = view.intrinsics.focal_lengths();
        for axis in 0..2 {
            let error = (pixel[axis] - view.pixel[axis]) / view.sigma_pixels;
            let mut jacobian = [0.0; 3];
            for j in 0..3 {
                jacobian[j] = focal[axis] / (p[2] * view.sigma_pixels)
                    * (r[axis][j] - p[axis] / p[2] * r[2][j]);
            }
            cost += error * error;
            for j in 0..3 {
                g[j] += jacobian[j] * error;
                for k in 0..3 {
                    h[j][k] += jacobian[j] * jacobian[k];
                }
            }
        }
    }
    if !cost.is_finite() || g.iter().chain(h.iter().flatten()).any(|x| !x.is_finite()) {
        return Err(GeometryError::NonFinite.into());
    }
    Ok((h, g, cost))
}

fn refine(
    views: &[CalibratedView],
    mask: u32,
    seed: V3,
    options: TriangulationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<V3, TriangulationError> {
    let mut point = seed;
    for _ in 0..options.max_iterations {
        let (h, g, cost) = normal_system(views, mask, point, budget)?;
        let (inverse, _) = invert_information(h, options, budget)?;
        let step = scale(crate::math::mv(inverse, g), -1.0);
        let tolerance = 1e-10 * (1.0 + norm(sub(point, views[0].pose.center())));
        if norm(step) <= tolerance {
            return Ok(point);
        }
        let mut accepted = None;
        let mut fraction = 1.0;
        for _ in 0..12 {
            budget.charge(32)?;
            let candidate = checked(add(point, scale(step, fraction)))?;
            let mut next_cost = 0.0;
            let mut valid = true;
            for (i, view) in views.iter().enumerate() {
                budget.charge(128)?;
                if mask & (1 << i) != 0 {
                    if let Some(error) = residual(*view, candidate, options.max_distance)? {
                        next_cost += (error / view.sigma_pixels).powi(2);
                    } else {
                        valid = false;
                    }
                }
            }
            if valid && next_cost <= cost {
                accepted = Some((candidate, next_cost));
                break;
            }
            fraction *= 0.5;
        }
        let Some((candidate, next_cost)) = accepted else {
            return Err(TriangulationError::NotConverged);
        };
        point = candidate;
        if cost - next_cost <= 1e-12 * (1.0 + cost) {
            return Ok(point);
        }
    }
    Err(TriangulationError::NotConverged)
}

// Fixed-size symmetric Jacobi eigensolve: no determinant cancellation, dynamic
// matrices, hidden regularization or invented depth for a rank-deficient rig.
fn invert_information(
    information: M3,
    options: TriangulationOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<(M3, f64), TriangulationError> {
    budget.charge(4096)?;
    let magnitude = information
        .iter()
        .flatten()
        .fold(0.0_f64, |m, x| m.max(x.abs()));
    if !magnitude.is_finite() || magnitude <= 0.0 {
        return Err(TriangulationError::WeakGeometry);
    }
    let mut a = information.map(|row| row.map(|x| x / magnitude));
    let mut v = crate::math::IDENTITY;
    for _ in 0..16 {
        for (p, q) in [(0, 1), (0, 2), (1, 2)] {
            let off = a[p][q];
            if off.abs() <= 1e-15 * (a[p][p].abs() + a[q][q].abs()) {
                continue;
            }
            let tau = (a[q][q] - a[p][p]) / (2.0 * off);
            let tangent = if tau == 0.0 {
                1.0
            } else {
                tau.signum() / (tau.abs() + tau.hypot(1.0))
            };
            let cosine = 1.0 / tangent.hypot(1.0);
            let sine = tangent * cosine;
            a[p][p] -= tangent * off;
            a[q][q] += tangent * off;
            a[p][q] = 0.0;
            a[q][p] = 0.0;
            for k in 0..3 {
                if k != p && k != q {
                    let kp = a[k][p];
                    let kq = a[k][q];
                    a[k][p] = cosine * kp - sine * kq;
                    a[p][k] = a[k][p];
                    a[k][q] = sine * kp + cosine * kq;
                    a[q][k] = a[k][q];
                }
                let kp = v[k][p];
                let kq = v[k][q];
                v[k][p] = cosine * kp - sine * kq;
                v[k][q] = sine * kp + cosine * kq;
            }
        }
    }
    let eigenvalues = [a[0][0], a[1][1], a[2][2]];
    let minimum = eigenvalues.into_iter().fold(f64::INFINITY, f64::min);
    let maximum = eigenvalues.into_iter().fold(0.0_f64, f64::max);
    if minimum <= 0.0 || maximum / minimum > options.max_condition_number {
        return Err(TriangulationError::WeakGeometry);
    }
    let mut inverse = [[0.0; 3]; 3];
    for i in 0..3 {
        for j in 0..3 {
            for k in 0..3 {
                inverse[i][j] += v[i][k] * v[j][k] / eigenvalues[k] / magnitude;
            }
        }
    }
    if inverse.iter().flatten().any(|x| !x.is_finite()) {
        return Err(GeometryError::NonFinite.into());
    }
    Ok((inverse, maximum / minimum))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn view(camera: u64, center: V3, point: V3) -> Result<CalibratedView, TriangulationError> {
        let intrinsics = PinholeIntrinsics::new(1280, 720, 800.0, 800.0, 640.0, 360.0)?;
        let pose = RigidPose::from_center(crate::math::IDENTITY, center)?;
        Ok(CalibratedView {
            camera,
            pose,
            intrinsics,
            pixel: pose.project(intrinsics, point)?,
            sigma_pixels: 1.0,
        })
    }
    fn rig(point: V3) -> Result<Vec<CalibratedView>, TriangulationError> {
        Ok(vec![
            view(1, [-2.0, 0.0, 0.0], point)?,
            view(2, [2.0, 0.0, 0.0], point)?,
            view(3, [0.0, 2.0, 0.0], point)?,
        ])
    }
    fn solve(views: &[CalibratedView]) -> Result<TriangulatedPoint, TriangulationError> {
        triangulate(
            views,
            TriangulationOptions::default(),
            &mut WorkBudget::new(1_000_000),
        )
    }

    #[test]
    fn recovers_elevated_point_without_ground_assumption() -> Result<(), TriangulationError> {
        let point = [0.3, -0.2, 8.0];
        let result = solve(&rig(point)?)?;
        assert!(norm(sub(point, result.position)) < 1e-8);
        assert!(result.rms_reprojection_pixels < 1e-8);
        assert!(result.residuals.iter().all(|row| row.inlier));
        assert!((0..3).all(|i| result.pixel_noise_covariance[i][i] > 0.0));
        Ok(())
    }

    #[test]
    fn input_permutation_is_exactly_deterministic() -> Result<(), TriangulationError> {
        let mut views = rig([0.3, -0.2, 8.0])?;
        views[0].pixel[0] += 0.3;
        views[2].pixel[1] -= 0.2;
        let result = solve(&views)?;
        views.reverse();
        assert_eq!(result, solve(&views)?);
        Ok(())
    }

    #[test]
    fn rejects_bad_view_but_retains_its_residual() -> Result<(), TriangulationError> {
        let point = [0.3, -0.2, 8.0];
        let mut views = rig(point)?;
        let mut outlier = view(4, [0.0, -2.0, 0.0], point)?;
        outlier.pixel[1] += 100.0;
        views.push(outlier);
        let options = TriangulationOptions {
            min_views: 3,
            max_outliers: 1,
            ..Default::default()
        };
        let result = triangulate(&views, options, &mut WorkBudget::new(1_000_000))?;
        assert!(norm(sub(point, result.position)) < 1e-8);
        assert!(!result.residuals[3].inlier);
        assert!(
            result.residuals[3]
                .pixels
                .is_some_and(|pixels| pixels > 90.0)
        );
        assert!(
            triangulate(
                &views,
                TriangulationOptions::default(),
                &mut WorkBudget::new(1_000_000)
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn competing_subsets_are_not_broken_by_residual_or_camera_id() -> Result<(), TriangulationError>
    {
        let views = vec![
            view(1, [-2.0, 0.0, 0.0], [0.0, 0.0, 8.0])?,
            view(2, [2.0, 0.0, 0.0], [0.0, 0.0, 8.0])?,
            view(3, [0.0, -2.0, 0.0], [0.0, 1.0, 8.0])?,
            view(4, [0.0, 2.0, 0.0], [0.0, 1.0, 8.0])?,
        ];
        let options = TriangulationOptions {
            max_outliers: 2,
            ..Default::default()
        };
        assert_eq!(
            triangulate(&views, options, &mut WorkBudget::new(1_000_000)),
            Err(TriangulationError::AmbiguousConsensus)
        );
        Ok(())
    }

    #[test]
    fn parallel_and_coincident_cameras_do_not_invent_depth() -> Result<(), TriangulationError> {
        let mut views = rig([0.0, 0.0, 8.0])?;
        views.truncate(2);
        views[1].pixel = views[0].pixel;
        assert_eq!(
            triangulate(
                &views,
                TriangulationOptions::default(),
                &mut WorkBudget::new(1_000_000)
            ),
            Err(TriangulationError::WeakGeometry)
        );
        views[1] = CalibratedView {
            camera: 2,
            ..views[0]
        };
        assert_eq!(
            triangulate(
                &views,
                TriangulationOptions::default(),
                &mut WorkBudget::new(1_000_000)
            ),
            Err(TriangulationError::WeakGeometry)
        );
        Ok(())
    }

    #[test]
    fn invalid_and_duplicate_views_fail_closed() -> Result<(), TriangulationError> {
        let mut views = rig([0.0, 0.0, 8.0])?;
        views[1].camera = views[0].camera;
        assert_eq!(
            triangulate(
                &views,
                TriangulationOptions::default(),
                &mut WorkBudget::new(1_000_000)
            ),
            Err(TriangulationError::DuplicateCamera)
        );
        views[1].camera = 2;
        views[1].sigma_pixels = f64::NAN;
        assert_eq!(
            triangulate(
                &views,
                TriangulationOptions::default(),
                &mut WorkBudget::new(1_000_000)
            ),
            Err(TriangulationError::InvalidView)
        );
        Ok(())
    }

    #[test]
    fn covariance_does_not_shrink_when_pixel_noise_widens() -> Result<(), TriangulationError> {
        let mut views = rig([0.3, -0.2, 8.0])?;
        let first = solve(&views)?;
        for view in &mut views {
            view.sigma_pixels *= 2.0;
        }
        let second = solve(&views)?;
        assert!(norm(sub(first.position, second.position)) < 1e-8);
        for i in 0..3 {
            assert!(
                (second.pixel_noise_covariance[i][i] / first.pixel_noise_covariance[i][i] - 4.0)
                    .abs()
                    < 1e-8
            );
        }
        Ok(())
    }

    #[test]
    fn work_exhaustion_and_cancellation_publish_no_point() -> Result<(), TriangulationError> {
        let views = rig([0.0, 0.0, 8.0])?;
        assert_eq!(
            triangulate(
                &views,
                TriangulationOptions::default(),
                &mut WorkBudget::new(0)
            ),
            Err(TriangulationError::Geometry(GeometryError::BudgetExhausted))
        );
        let cancelled = AtomicBool::new(true);
        assert_eq!(
            triangulate(
                &views,
                TriangulationOptions::default(),
                &mut WorkBudget::cancellable(1_000_000, &cancelled)
            ),
            Err(TriangulationError::Geometry(GeometryError::Cancelled))
        );
        Ok(())
    }

    #[test]
    fn common_world_translation_preserves_geometry() -> Result<(), TriangulationError> {
        let point = [0.3, -0.2, 8.0];
        let views = rig(point)?;
        let first = solve(&views)?;
        let offset = [1000.0, -800.0, 90.0];
        let shifted: Vec<_> = views
            .iter()
            .map(|v| {
                Ok::<_, TriangulationError>(CalibratedView {
                    pose: RigidPose::from_center(v.pose.rotation(), add(v.pose.center(), offset))?,
                    ..*v
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let second = solve(&shifted)?;
        assert!(norm(sub(add(first.position, offset), second.position)) < 1e-7);
        assert!((first.condition_number / second.condition_number - 1.0).abs() < 1e-8);
        Ok(())
    }
}
