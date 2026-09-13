use crate::{GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};
use crate::linear::{multiply, rotation_step, solve_six};
use crate::math::{add, mv, norm, scale};
use crate::registration::Correspondence;

fn huber(error: f64, threshold: f64) -> f64 {
    if error <= threshold { 0.5 * error * error }
    else { threshold * (error - 0.5 * threshold) }
}

fn cost(points: &[Correspondence], k: PinholeIntrinsics, pose: RigidPose,
    threshold: f64, budget: &mut WorkBudget<'_>) -> Result<f64, GeometryError> {
    let mut total = 0.0;
    for point in points {
        budget.charge(1)?;
        let pixel = pose.project(k, point.world)?;
        total += huber((point.pixel[0] - pixel[0]).hypot(point.pixel[1] - pixel[1]), threshold);
    }
    if !total.is_finite() { return Err(GeometryError::NonFinite); }
    Ok(total)
}

pub(crate) fn refine(points: &[Correspondence], k: PinholeIntrinsics, mut pose: RigidPose,
    size: f64, iterations: usize, threshold: f64, budget: &mut WorkBudget<'_>) -> Result<RigidPose, GeometryError> {
    let [fx, fy] = k.focal_lengths();
    let mut damping = 1e-3_f64;
    let mut current_cost = cost(points, k, pose, threshold, budget)?;
    for _ in 0..iterations {
        budget.charge(1)?;
        let mut normal = [[0.0; 6]; 6];
        let mut rhs = [0.0; 6];
        for point in points {
            budget.charge(72)?;
            let [x, y, z] = pose.transform(point.world)?;
            if z <= 1e-9 { return Err(GeometryError::BehindCamera); }
            let pixel = k.project([x, y, z])?;
            let residual = [point.pixel[0] - pixel[0], point.pixel[1] - pixel[1]];
            let error = residual[0].hypot(residual[1]);
            let weight = if error <= threshold { 1.0 } else { threshold / error };
            let nx = x / z;
            let ny = y / z;
            // Left SE(3) update: dP = size * dv + dw cross P.
            let jacobian = [
                [fx / z * size, 0.0, -fx * nx / z * size, -fx * nx * ny, fx * (1.0 + nx * nx), -fx * ny],
                [0.0, fy / z * size, -fy * ny / z * size, -fy * (1.0 + ny * ny), fy * nx * ny, fy * nx],
            ];
            for axis in 0..2 {
                for i in 0..6 {
                    rhs[i] += weight * jacobian[axis][i] * residual[axis];
                    for j in 0..6 { normal[i][j] += weight * jacobian[axis][i] * jacobian[axis][j]; }
                }
            }
        }
        for (i, row) in normal.iter_mut().enumerate() { row[i] += damping * row[i].max(1e-12); }
        let step = solve_six(normal, rhs, budget)?;
        let translation = [step[0], step[1], step[2]];
        let rotation = [step[3], step[4], step[5]];
        if norm(translation).hypot(norm(rotation)) < 1e-10 { break; }
        if norm(rotation) > 0.35 || norm(translation) > 2.0 {
            damping = (damping * 10.0).min(1e12);
            continue;
        }
        let delta = rotation_step(rotation);
        let candidate = RigidPose::new(multiply(delta, pose.rotation()),
            add(mv(delta, pose.translation()), scale(translation, size)))?;
        let candidate_cost = match cost(points, k, candidate, threshold, budget) {
            Ok(value) => value,
            Err(GeometryError::BehindCamera) => {
                damping = (damping * 10.0).min(1e12);
                continue;
            }
            Err(error) => return Err(error),
        };
        if candidate_cost < current_cost {
            pose = candidate;
            current_cost = candidate_cost;
            damping = (damping * 0.3).max(1e-12);
        } else { damping = (damping * 10.0).min(1e12); }
    }
    budget.charge(0)?;
    Ok(pose)
}
