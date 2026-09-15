#![forbid(unsafe_code)]
//! Two-branch planar pose seeds, refined against the ORIGINAL world coordinates.

use super::{Correspondence, PoseCandidate, PoseSearch, PoseSolverOptions, validate_points};
use super::search::{better, control_failure, equivalent_pose, image_spread, next_random, score};
use crate::linear::{multiply, symmetric_eigen};
use crate::math::{M3, V3, add, cross, dot, mv, normalize, scale, sub};
use crate::refine::refine;
use crate::{GeometryBasis, GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};

pub const DEFAULT_PLANAR_RESIDUAL_RATIO: f64 = 1e-8;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PlanarSupport {
    pub origin: V3,
    pub normal: V3,
    pub rms_extent: f64,
    pub maximum_off_plane: f64,
    pub in_plane_axis_ratio: f64,
    pub admitted_residual_ratio: f64,
}

struct PlaneFrame { support: PlanarSupport, axes: M3 }
impl PlaneFrame {
    fn point(&self, point: V3) -> V3 {
        scale(mv(self.axes, sub(point, self.support.origin)), 1.0 / self.support.rms_extent)
    }
}

pub fn estimate_camera_pose_adaptive(basis: GeometryBasis, intrinsics: PinholeIntrinsics,
    correspondences: &[Correspondence], options: PoseSolverOptions, budget: &mut WorkBudget<'_>)
    -> Result<PoseSearch, GeometryError> {
    let started = budget.used();
    match super::search::estimate_camera_pose(basis, intrinsics, correspondences, options, budget) {
        Err(GeometryError::UnsupportedGeometry) => {
            let mut result = estimate_planar_camera_pose(basis, intrinsics, correspondences, options,
                DEFAULT_PLANAR_RESIDUAL_RATIO, budget)?;
            result.work_units = budget.used() - started;
            Ok(result)
        }
        other => other,
    }
}

pub fn estimate_planar_camera_pose(basis: GeometryBasis, intrinsics: PinholeIntrinsics,
    correspondences: &[Correspondence], options: PoseSolverOptions,
    maximum_residual_ratio: f64, budget: &mut WorkBudget<'_>) -> Result<PoseSearch, GeometryError> {
    budget.charge(0)?;
    let started = budget.used();
    if !maximum_residual_ratio.is_finite() || !(1e-12..=1e-4).contains(&maximum_residual_ratio) {
        return Err(GeometryError::InvalidSolverOptions);
    }
    let points = validate_points(correspondences, intrinsics, 6, budget)?;
    options.validate(points.len())?;
    let frame = plane_frame(&points, options.minimum_axis_ratio, maximum_residual_ratio, budget)?;
    let required = options.minimum_inliers.max((options.minimum_inlier_fraction * points.len() as f64).ceil() as usize);
    let mut candidates = Vec::<PoseCandidate>::new();
    candidates.try_reserve_exact(8).map_err(|_| GeometryError::LimitExceeded)?;
    let mut indices: [usize; 512] = std::array::from_fn(|i| i);
    let mut random = options.seed;
    for trial in 0..=options.ransac_trials {
        budget.charge(1)?;
        let mut small = [points[0]; 6];
        let sample = if trial == 0 { points.as_slice() } else {
            for i in 0..6 {
                let j = i + (next_random(&mut random) % (points.len() - i) as u64) as usize;
                indices.swap(i, j);
            }
            indices[..6].sort_unstable();
            for i in 0..6 { small[i] = points[indices[i]]; }
            &small[..]
        };
        let sample_frame = match plane_frame(sample, options.minimum_axis_ratio, maximum_residual_ratio, budget) {
            Ok(frame) => frame,
            Err(error) if control_failure(error) => return Err(error),
            Err(_) => continue,
        };
        let seeds = match planar_seeds(sample, intrinsics, &sample_frame, budget) {
            Ok(seeds) => seeds,
            Err(error) if control_failure(error) => return Err(error),
            Err(_) => continue,
        };
        for seed in seeds {
            let initial = match refine(sample, intrinsics, seed, sample_frame.support.rms_extent,
                options.refinement_iterations.min(10), options.inlier_threshold_px, budget) {
                Ok(pose) => pose,
                Err(error) if control_failure(error) => return Err(error),
                Err(_) => continue,
            };
            let (inliers, _, _) = score(&points, intrinsics, initial, options.inlier_threshold_px, budget)?;
            if inliers.len() < required { continue; }
            let selected = gather(&points, &inliers, budget)?;
            let support = match plane_frame(&selected, options.minimum_axis_ratio, maximum_residual_ratio, budget) {
                Ok(frame) => frame.support,
                Err(error) if control_failure(error) => return Err(error),
                Err(_) => continue,
            };
            let pose = match refine(&selected, intrinsics, initial, support.rms_extent,
                options.refinement_iterations, options.inlier_threshold_px, budget) {
                Ok(pose) => pose,
                Err(error) if control_failure(error) => return Err(error),
                Err(_) => continue,
            };
            let (inliers, rms_px, maximum_error_px) = score(&points, intrinsics, pose, options.inlier_threshold_px, budget)?;
            if inliers.len() < required || !image_spread(&points, &inliers, intrinsics, options.minimum_image_span) { continue; }
            let selected = gather(&points, &inliers, budget)?;
            let support_scale = match plane_frame(&selected, options.minimum_axis_ratio, maximum_residual_ratio, budget) {
                Ok(frame) => frame.support.rms_extent,
                Err(error) if control_failure(error) => return Err(error),
                Err(_) => continue,
            };
            let mut landmarks = Vec::new();
            landmarks.try_reserve_exact(selected.len()).map_err(|_| GeometryError::LimitExceeded)?;
            landmarks.extend(selected.iter().map(|p| p.landmark));
            let candidate = PoseCandidate { pose, inlier_landmarks: landmarks, rms_px, maximum_error_px, support_scale };
            if let Some(existing) = candidates.iter_mut().find(|c| equivalent_pose(c.pose, pose, c.support_scale.min(support_scale))) {
                if better(&candidate, existing) { *existing = candidate; }
            } else {
                if candidates.len() == 8 { return Err(GeometryError::TooManyPoseCandidates); }
                candidates.push(candidate);
            }
        }
    }
    if candidates.is_empty() { return Err(GeometryError::NoPoseConsensus); }
    candidates.sort_by(|a, b| b.inlier_landmarks.len().cmp(&a.inlier_landmarks.len()).then(a.rms_px.total_cmp(&b.rms_px)));
    budget.charge(0)?;
    Ok(PoseSearch { basis, intrinsics, fit: points, candidates,
        trials_attempted: options.ransac_trials + 1, work_units: budget.used() - started,
        planar_support: Some(frame.support) })
}

fn gather(points: &[Correspondence], indices: &[usize], budget: &mut WorkBudget<'_>) -> Result<Vec<Correspondence>, GeometryError> {
    budget.charge(indices.len() as u64)?;
    let mut output = Vec::new();
    output.try_reserve_exact(indices.len()).map_err(|_| GeometryError::LimitExceeded)?;
    output.extend(indices.iter().map(|i| points[*i]));
    Ok(output)
}

fn signed_axis(mut axis: V3) -> Result<V3, GeometryError> {
    axis = normalize(axis)?;
    let mut largest = 0;
    for i in 1..3 { if axis[i].abs() > axis[largest].abs() { largest = i; } }
    if axis[largest] < 0.0 { axis = scale(axis, -1.0); }
    Ok(axis)
}

fn plane_frame(points: &[Correspondence], minimum_ratio: f64, maximum_residual_ratio: f64,
    budget: &mut WorkBudget<'_>) -> Result<PlaneFrame, GeometryError> {
    let first = points.first().ok_or(GeometryError::EmptyInput)?.world;
    let count = points.len() as f64;
    let mut offset = [0.0; 3];
    for point in points { budget.charge(4)?; offset = add(offset, scale(sub(point.world, first), 1.0 / count)); }
    let origin = add(first, offset);
    let mut squared = 0.0;
    for point in points { budget.charge(4)?; let delta = sub(point.world, origin); squared += dot(delta, delta) / count; }
    let extent = squared.sqrt();
    if !extent.is_finite() || extent <= 1e-9 { return Err(GeometryError::Degenerate); }
    let mut covariance = [[0.0; 3]; 3];
    for point in points {
        budget.charge(12)?;
        let q = scale(sub(point.world, origin), 1.0 / extent);
        for i in 0..3 { for j in 0..3 { covariance[i][j] += q[i] * q[j]; } }
    }
    let eigen = symmetric_eigen(covariance, budget)?;
    let mut order = [0, 1, 2];
    order.sort_by(|a, b| eigen.values[*a].total_cmp(&eigen.values[*b]).then(a.cmp(b)));
    let largest = eigen.values[order[2]];
    if largest <= 0.0 || eigen.values[order[1]] <= largest * minimum_ratio { return Err(GeometryError::UnsupportedGeometry); }
    let x = signed_axis(std::array::from_fn(|i| eigen.vectors[i][order[2]]))?;
    let normal = signed_axis(std::array::from_fn(|i| eigen.vectors[i][order[0]]))?;
    let y = normalize(cross(normal, x))?;
    let normal = cross(x, y);
    let mut residual = 0.0_f64;
    for point in points { budget.charge(4)?; residual = residual.max(dot(sub(point.world, origin), normal).abs()); }
    if residual / extent > maximum_residual_ratio { return Err(GeometryError::UnsupportedGeometry); }
    Ok(PlaneFrame { support: PlanarSupport { origin, normal, rms_extent: extent,
        maximum_off_plane: residual, in_plane_axis_ratio: eigen.values[order[1]] / largest,
        admitted_residual_ratio: maximum_residual_ratio }, axes: [x, y, normal] })
}

fn planar_seeds(points: &[Correspondence], k: PinholeIntrinsics, frame: &PlaneFrame,
    budget: &mut WorkBudget<'_>) -> Result<[RigidPose; 2], GeometryError> {
    let h = homography(points, k, frame, budget)?;
    let g = [h[0][2], h[1][2], 1.0];
    let g2 = dot(g, g);
    let a = [h[0][0] - g[0]*h[2][0], h[1][0] - g[1]*h[2][0], 0.0];
    let b = [h[0][1] - g[0]*h[2][1], h[1][1] - g[1]*h[2][1], 0.0];
    let a = sub(a, scale(g, dot(a, g)/g2));
    let b = sub(b, scale(g, dot(b, g)/g2));
    let aa = dot(a,a); let bb = dot(b,b); let ab = dot(a,b);
    let lambda = (aa + bb + (aa-bb).hypot(2.0*ab)) * 0.5;
    if !lambda.is_finite() || lambda <= 1e-24 { return Err(GeometryError::Degenerate); }
    let alpha2 = ((lambda-aa)/g2).max(0.0);
    let beta2 = ((lambda-bb)/g2).max(0.0);
    let (alpha, beta) = if alpha2.max(beta2) <= lambda*1e-28 { (0.0, 0.0) }
        else if alpha2 >= beta2 { let alpha = alpha2.sqrt(); (alpha, -ab/(g2*alpha)) }
        else { let beta = beta2.sqrt(); (-ab/(g2*beta), beta) };
    let mut seeds = [RigidPose::new(crate::math::IDENTITY, [0.0;3])?; 2];
    for (index, sign) in [1.0, -1.0].into_iter().enumerate() {
        budget.charge(128)?;
        let r1 = normalize(scale(add(a, scale(g, sign*alpha)), 1.0/lambda.sqrt()))?;
        let raw2 = scale(add(b, scale(g, sign*beta)), 1.0/lambda.sqrt());
        let r2 = normalize(sub(raw2, scale(r1, dot(r1,raw2))))?;
        let r3 = cross(r1,r2);
        let rp: M3 = std::array::from_fn(|i| [r1[i],r2[i],r3[i]]);
        let shift = translation(points, k, frame, rp, budget)?;
        let rotation = multiply(rp, frame.axes);
        let shift = sub(scale(shift, frame.support.rms_extent), mv(rotation, frame.support.origin));
        seeds[index] = RigidPose::new(rotation, shift)?;
    }
    Ok(seeds)
}

fn image_point(point: &Correspondence, k: PinholeIntrinsics) -> Result<[f64; 2], GeometryError> {
    let focal = k.focal_lengths(); let center = k.principal_point();
    let uv = [(point.pixel[0]-center[0])/focal[0], (point.pixel[1]-center[1])/focal[1]];
    if uv.iter().any(|x| !x.is_finite() || x.abs() > 1e4) { return Err(GeometryError::OutOfRange); }
    Ok(uv)
}

fn homography(points: &[Correspondence], k: PinholeIntrinsics, frame: &PlaneFrame,
    budget: &mut WorkBudget<'_>) -> Result<M3, GeometryError> {
    let mut center = [0.0; 2];
    let count = points.len() as f64;
    for point in points { budget.charge(8)?; let uv = image_point(point,k)?; for i in 0..2 { center[i] += uv[i]/count; } }
    let mut squared = 0.0;
    for point in points { budget.charge(8)?; let uv = image_point(point,k)?; squared += ((uv[0]-center[0]).powi(2) + (uv[1]-center[1]).powi(2))/count; }
    let extent = squared.sqrt();
    if !extent.is_finite() || extent <= 1e-12 { return Err(GeometryError::Degenerate); }
    let mut normal = [[0.0; 9]; 9];
    for point in points {
        let q = frame.point(point.world);
        let uv = image_point(point,k)?;
        let base = [q[0],q[1],1.0];
        for axis in 0..2 {
            budget.charge(100)?;
            let coordinate = (uv[axis]-center[axis])/extent;
            let mut row = [0.0; 9];
            for j in 0..3 { row[axis*3+j]=base[j]; row[6+j]=-coordinate*base[j]; }
            for i in 0..9 { for j in 0..9 { normal[i][j] += row[i]*row[j]; } }
        }
    }
    let eigen = symmetric_eigen(normal,budget)?;
    let mut order: [usize; 9] = std::array::from_fn(|i| i);
    order.sort_by(|a,b| eigen.values[*a].total_cmp(&eigen.values[*b]).then(a.cmp(b)));
    if eigen.values[order[1]] <= eigen.values[order[8]]*1e-10 { return Err(GeometryError::Degenerate); }
    let h: M3 = std::array::from_fn(|i| std::array::from_fn(|j| eigen.vectors[i*3+j][order[0]]));
    let mut h = multiply([[extent,0.0,center[0]],[0.0,extent,center[1]],[0.0,0.0,1.0]],h);
    let denominator=h[2][2];
    if !denominator.is_finite() || denominator.abs() <= 1e-12 { return Err(GeometryError::Degenerate); }
    for row in &mut h { for value in row { *value/=denominator; } }
    Ok(h)
}

fn translation(points: &[Correspondence], k: PinholeIntrinsics, frame: &PlaneFrame,
    rotation: M3, budget: &mut WorkBudget<'_>) -> Result<V3, GeometryError> {
    let mut normal = [[0.0;3];3]; let mut rhs = [0.0;3];
    for point in points {
        budget.charge(40)?;
        let [x,y,z]=mv(rotation,frame.point(point.world));
        let [u,v]=image_point(point,k)?;
        for (row, residual) in [([1.0,0.0,-u],u*z-x),([0.0,1.0,-v],v*z-y)] {
            for i in 0..3 { rhs[i]+=row[i]*residual; for j in 0..3 { normal[i][j]+=row[i]*row[j]; } }
        }
    }
    let eigen=symmetric_eigen(normal,budget)?;
    let maximum=eigen.values.into_iter().fold(0.0_f64,f64::max);
    if eigen.values.iter().any(|x| *x<=maximum*1e-12) { return Err(GeometryError::Degenerate); }
    let mut output=[0.0;3];
    for i in 0..3 {
        let axis: V3=std::array::from_fn(|j| eigen.vectors[j][i]);
        output=add(output,scale(axis,dot(axis,rhs)/eigen.values[i]));
    }
    if output.iter().any(|x| !x.is_finite()) { return Err(GeometryError::NonFinite); }
    Ok(output)
}
