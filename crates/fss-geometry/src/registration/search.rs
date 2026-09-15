use super::{Correspondence, PoseCandidate, PoseSearch, PoseSolverOptions, validate_points};
use crate::{GeometryBasis, GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};
use crate::linear::{linear_pose, map_normalization};
use crate::math::{norm, sub};
use crate::refine::refine;

pub fn estimate_camera_pose(basis: GeometryBasis, intrinsics: PinholeIntrinsics,
    correspondences: &[Correspondence], options: PoseSolverOptions, budget: &mut WorkBudget<'_>)
    -> Result<PoseSearch, GeometryError> {
    budget.charge(0)?;
    let started = budget.used();
    let points = validate_points(correspondences, intrinsics, 6, budget)?;
    options.validate(points.len())?;
    map_normalization(&points, options.minimum_axis_ratio, budget)?;
    let required = options.minimum_inliers.max((options.minimum_inlier_fraction * points.len() as f64).ceil() as usize);
    let mut candidates: Vec<PoseCandidate> = Vec::new();
    candidates.try_reserve_exact(8).map_err(|_| GeometryError::LimitExceeded)?;
    let mut indices: [usize; 512] = std::array::from_fn(|i| i);
    let mut random = options.seed;
    for trial in 0..=options.ransac_trials {
        budget.charge(1)?;
        let sample: Vec<Correspondence> = if trial == 0 { points.clone() } else {
            for i in 0..6 {
                let j = i + (next_random(&mut random) % (points.len() - i) as u64) as usize;
                indices.swap(i, j);
            }
            indices[..6].sort_unstable();
            indices[..6].iter().map(|i| points[*i]).collect()
        };
        let initial = match linear_pose(&sample, intrinsics, options.minimum_axis_ratio, budget) {
            Ok(pose) => pose,
            Err(error) if control_failure(error) => return Err(error),
            Err(_) => continue,
        };
        let (_, sample_size) = map_normalization(&sample, options.minimum_axis_ratio, budget)?;
        let initial = match refine(&sample, intrinsics, initial, sample_size,
            options.refinement_iterations.min(10), options.inlier_threshold_px, budget) {
            Ok(pose) => pose,
            Err(error) if control_failure(error) => return Err(error),
            Err(_) => continue,
        };
        let (inliers, _, _) = score(&points, intrinsics, initial, options.inlier_threshold_px, budget)?;
        if inliers.len() < required { continue; }
        let selected: Vec<Correspondence> = inliers.iter().map(|i| points[*i]).collect();
        let support_size = match map_normalization(&selected, options.minimum_axis_ratio, budget) {
            Ok((_, size)) => size,
            Err(error) if control_failure(error) => return Err(error),
            Err(_) => continue,
        };
        let pose = match refine(&selected, intrinsics, initial, support_size,
            options.refinement_iterations, options.inlier_threshold_px, budget) {
            Ok(pose) => pose,
            Err(error) if control_failure(error) => return Err(error),
            Err(_) => continue,
        };
        let (inliers, rms_px, maximum_error_px) = score(&points, intrinsics, pose, options.inlier_threshold_px, budget)?;
        if inliers.len() < required || !image_spread(&points, &inliers, intrinsics, options.minimum_image_span) { continue; }
        let selected: Vec<Correspondence> = inliers.iter().map(|i| points[*i]).collect();
        let support_scale = match map_normalization(&selected, options.minimum_axis_ratio, budget) {
            Ok((_, size)) => size,
            Err(error) if control_failure(error) => return Err(error),
            Err(_) => continue,
        };
        let candidate = PoseCandidate { pose, inlier_landmarks: selected.iter().map(|p| p.landmark).collect(), rms_px, maximum_error_px, support_scale };
        if let Some(existing) = candidates.iter_mut().find(|c| equivalent_pose(c.pose, pose, c.support_scale.min(support_scale))) {
            if better(&candidate, existing) { *existing = candidate; }
        } else {
            if candidates.len() == 8 { return Err(GeometryError::TooManyPoseCandidates); }
            candidates.push(candidate);
        }
    }
    if candidates.is_empty() { return Err(GeometryError::NoPoseConsensus); }
    candidates.sort_by(|a, b| b.inlier_landmarks.len().cmp(&a.inlier_landmarks.len()).then(a.rms_px.total_cmp(&b.rms_px)));
    budget.charge(0)?;
    Ok(PoseSearch { basis, intrinsics, fit: points, candidates,
        trials_attempted: options.ransac_trials + 1, work_units: budget.used() - started, planar_support: None })
}

pub(super) fn control_failure(error: GeometryError) -> bool {
    matches!(error, GeometryError::Cancelled | GeometryError::BudgetExhausted | GeometryError::LimitExceeded)
}

pub(super) fn score(points: &[Correspondence], k: PinholeIntrinsics, pose: RigidPose, threshold: f64,
    budget: &mut WorkBudget<'_>) -> Result<(Vec<usize>, f64, f64), GeometryError> {
    let mut inliers = Vec::new();
    inliers.try_reserve_exact(points.len()).map_err(|_| GeometryError::LimitExceeded)?;
    let mut squared = 0.0;
    let mut maximum = 0.0_f64;
    for (index, point) in points.iter().enumerate() {
        budget.charge(1)?;
        let pixel = match pose.project(k, point.world) {
            Ok(pixel) => pixel,
            Err(GeometryError::BehindCamera | GeometryError::OutOfRange) => continue,
            Err(error) => return Err(error),
        };
        let error = (pixel[0] - point.pixel[0]).hypot(pixel[1] - point.pixel[1]);
        if k.contains(pixel) && error <= threshold {
            inliers.push(index);
            squared += error * error;
            maximum = maximum.max(error);
        }
    }
    let rms = if inliers.is_empty() { f64::INFINITY } else { (squared / inliers.len() as f64).sqrt() };
    Ok((inliers, rms, maximum))
}

pub(super) fn image_spread(points: &[Correspondence], indices: &[usize], k: PinholeIntrinsics, floor: f64) -> bool {
    let mut minimum = [f64::INFINITY; 2];
    let mut maximum = [f64::NEG_INFINITY; 2];
    for &i in indices {
        for axis in 0..2 { minimum[axis] = minimum[axis].min(points[i].pixel[axis]); maximum[axis] = maximum[axis].max(points[i].pixel[axis]); }
    }
    let dimensions = k.dimensions();
    (0..2).all(|axis| maximum[axis] - minimum[axis] >= floor * f64::from(dimensions[axis]))
}

pub(super) fn equivalent_pose(a: RigidPose, b: RigidPose, size: f64) -> bool {
    if norm(sub(a.center(), b.center())) > 0.01 * size { return false; }
    let ra = a.rotation();
    let rb = b.rotation();
    let mut trace = 0.0;
    for i in 0..3 { for j in 0..3 { trace += ra[i][j] * rb[i][j]; } }
    ((trace - 1.0) * 0.5).clamp(-1.0, 1.0).acos() <= 0.02
}

pub(super) fn better(a: &PoseCandidate, b: &PoseCandidate) -> bool {
    a.inlier_landmarks.len() > b.inlier_landmarks.len()
        || (a.inlier_landmarks.len() == b.inlier_landmarks.len() && a.rms_px < b.rms_px)
}

pub(super) fn next_random(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}
