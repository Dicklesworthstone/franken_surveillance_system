//! Levenberg-Marquardt over the Schur-complement (reduced camera) system.
//!
//! Each observation touches exactly one camera block and one landmark, so the
//! normal matrix is `[[U, W], [W^T, V]]` with block-diagonal `U` (cameras) and
//! `V` (3x3 per landmark). Landmarks are eliminated per step:
//! `S = U - W V^-1 W^T`, `S dc = gc - W V^-1 gp`, `dp = V^-1 (gp - W^T dc)`.
//! All accumulation runs in canonical (landmark, camera) order. Fixed control
//! points contribute only to `U` and the camera gradient, after every free
//! observation, in canonical (control point, camera) order.

use super::dense::{Factor, FactorError};
use super::{
    AdjustedCamera, AdjustedLandmark, BudgetKind, BundleAdjustment, BundleAdjustmentError,
    BundleGaugeChoice, BundleOptions, BundleParameter, BundleReport, CAMERA_BLOCK_PARAMETERS,
    CameraCovariance, Canonical, Convergence, FocalRefinement, RadialDistortion, SingularStage,
};
use crate::linear::{multiply, rotation_step};
use crate::math::{M3, V3};
use crate::{GeometryBasis, GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};

const MIN_DAMPING: f64 = 1e-12;
const MAX_DAMPING: f64 = 1e16;
const ZERO_RMS_PX: f64 = 1e-10;
const DIAGONAL_FLOOR: f64 = 1e-12;

#[derive(Clone, Copy)]
struct CameraState {
    rotation: M3,
    translation: V3,
    /// `fx, fy, cx, cy`.
    pinhole: [f64; 4],
    radial: [f64; 2],
    /// Held `fy / fx` when the focal length is a single aspect-held unknown.
    aspect: Option<f64>,
}

#[derive(Clone)]
struct State {
    cameras: Vec<CameraState>,
    points: Vec<V3>,
}

/// Why an inner computation stopped; converted to a public error with a report.
enum Stop {
    Budget(GeometryError),
    Breakdown,
    Singular(SingularStage),
}
impl From<GeometryError> for Stop {
    fn from(error: GeometryError) -> Self {
        Self::Budget(error)
    }
}

struct Layout {
    /// Free block slots per camera, ascending.
    slots: Vec<Vec<usize>>,
    offsets: Vec<usize>,
    total: usize,
}
impl Layout {
    fn new(free: &[[bool; CAMERA_BLOCK_PARAMETERS]]) -> Self {
        let mut slots = Vec::with_capacity(free.len());
        let mut offsets = Vec::with_capacity(free.len());
        let mut total = 0;
        for mask in free {
            let camera_slots: Vec<usize> =
                (0..CAMERA_BLOCK_PARAMETERS).filter(|s| mask[*s]).collect();
            offsets.push(total);
            total += camera_slots.len();
            slots.push(camera_slots);
        }
        Self {
            slots,
            offsets,
            total,
        }
    }
}

struct Projected {
    pixel: [f64; 2],
    camera: [[f64; CAMERA_BLOCK_PARAMETERS]; 2],
    point: [[f64; 3]; 2],
}

fn project(camera: &CameraState, world: V3) -> Option<Projected> {
    let q = crate::math::mv(camera.rotation, world);
    let p = crate::math::add(q, camera.translation);
    if p.iter().any(|x| !x.is_finite()) || p[2] <= 1e-9 {
        return None;
    }
    let [fx, fy, cx, cy] = camera.pinhole;
    let [k1, k2] = camera.radial;
    let inverse_depth = 1.0 / p[2];
    let xn = p[0] * inverse_depth;
    let yn = p[1] * inverse_depth;
    let r2 = xn * xn + yn * yn;
    let d = 1.0 + k1 * r2 + k2 * r2 * r2;
    let pixel = [fx * d * xn + cx, fy * d * yn + cy];
    if pixel.iter().any(|x| !x.is_finite()) {
        return None;
    }
    let slope = 2.0 * (k1 + 2.0 * k2 * r2);
    let du = [fx * (d + xn * xn * slope), fx * xn * yn * slope];
    let dv = [fy * yn * xn * slope, fy * (d + yn * yn * slope)];
    let dxn = [inverse_depth, 0.0, -xn * inverse_depth];
    let dyn_ = [0.0, inverse_depth, -yn * inverse_depth];
    let duv_dp: [[f64; 3]; 2] = [
        std::array::from_fn(|k| du[0] * dxn[k] + du[1] * dyn_[k]),
        std::array::from_fn(|k| dv[0] * dxn[k] + dv[1] * dyn_[k]),
    ];
    // Left perturbation: d(R x)/dw = -[q]x.
    let minus_skew = [[0.0, q[2], -q[1]], [-q[2], 0.0, q[0]], [q[1], -q[0], 0.0]];
    let mut camera_jacobian = [[0.0; CAMERA_BLOCK_PARAMETERS]; 2];
    for (row, jac) in camera_jacobian.iter_mut().zip(&duv_dp) {
        for k in 0..3 {
            row[k] =
                jac[0] * minus_skew[0][k] + jac[1] * minus_skew[1][k] + jac[2] * minus_skew[2][k];
            row[3 + k] = jac[k];
        }
    }
    camera_jacobian[0][6] = d * xn;
    camera_jacobian[0][8] = 1.0;
    camera_jacobian[0][10] = fx * xn * r2;
    camera_jacobian[0][11] = fx * xn * r2 * r2;
    camera_jacobian[1][7] = d * yn;
    if let Some(aspect) = camera.aspect {
        // Slot 6 is the single focal unknown: fy = aspect * fx.
        camera_jacobian[1][6] = aspect * d * yn;
    }
    camera_jacobian[1][9] = 1.0;
    camera_jacobian[1][10] = fy * yn * r2;
    camera_jacobian[1][11] = fy * yn * r2 * r2;
    let r = camera.rotation;
    let point: [[f64; 3]; 2] = [
        std::array::from_fn(|k| {
            duv_dp[0][0] * r[0][k] + duv_dp[0][1] * r[1][k] + duv_dp[0][2] * r[2][k]
        }),
        std::array::from_fn(|k| {
            duv_dp[1][0] * r[0][k] + duv_dp[1][1] * r[1][k] + duv_dp[1][2] * r[2][k]
        }),
    ];
    Some(Projected {
        pixel,
        camera: camera_jacobian,
        point,
    })
}

/// Observations of free landmarks plus observations of fixed control points.
fn residual_blocks(problem: &Canonical) -> u64 {
    (problem.observations.len() + problem.control_observations.len()) as u64
}

/// Half the sum of squared residuals, or `None` if any point leaves the model.
fn cost(
    problem: &Canonical,
    state: &State,
    budget: &mut WorkBudget<'_>,
) -> Result<Option<f64>, Stop> {
    budget.charge(24 * residual_blocks(problem))?;
    let mut total = 0.0;
    for &(l, c, pixel) in &problem.observations {
        let Some(projected) = project(&state.cameras[c], state.points[l]) else {
            return Ok(None);
        };
        let du = pixel[0] - projected.pixel[0];
        let dv = pixel[1] - projected.pixel[1];
        total += 0.5 * (du * du + dv * dv);
    }
    for &(k, c, pixel) in &problem.control_observations {
        let Some(projected) = project(&state.cameras[c], problem.control_points[k].position) else {
            return Ok(None);
        };
        let du = pixel[0] - projected.pixel[0];
        let dv = pixel[1] - projected.pixel[1];
        total += 0.5 * (du * du + dv * dv);
    }
    Ok(total.is_finite().then_some(total))
}

struct Linearized {
    cost: f64,
    /// Per camera, row-major `k x k` normal block.
    u: Vec<Vec<f64>>,
    /// Camera gradient `J_c^T r`, laid out by [`Layout`].
    gc: Vec<f64>,
    v: Vec<[[f64; 3]; 3]>,
    gp: Vec<V3>,
    /// Per observation, row-major `k x 3` coupling block `J_c^T J_p`.
    w: Vec<Vec<f64>>,
}

fn linearize(
    problem: &Canonical,
    layout: &Layout,
    state: &State,
    budget: &mut WorkBudget<'_>,
) -> Result<Linearized, Stop> {
    budget.charge(200 * residual_blocks(problem))?;
    let mut lin = Linearized {
        cost: 0.0,
        u: layout
            .slots
            .iter()
            .map(|s| vec![0.0; s.len() * s.len()])
            .collect(),
        gc: vec![0.0; layout.total],
        v: vec![[[0.0; 3]; 3]; problem.landmarks.len()],
        gp: vec![[0.0; 3]; problem.landmarks.len()],
        w: Vec::with_capacity(problem.observations.len()),
    };
    for &(l, c, pixel) in &problem.observations {
        let projected = project(&state.cameras[c], state.points[l]).ok_or(Stop::Breakdown)?;
        let residual = [pixel[0] - projected.pixel[0], pixel[1] - projected.pixel[1]];
        lin.cost += 0.5 * (residual[0] * residual[0] + residual[1] * residual[1]);
        let slots = &layout.slots[c];
        let k = slots.len();
        let offset = layout.offsets[c];
        let mut coupling = vec![0.0; k * 3];
        for axis in 0..2 {
            let jc = &projected.camera[axis];
            let jp = &projected.point[axis];
            let r = residual[axis];
            for (a, &sa) in slots.iter().enumerate() {
                lin.gc[offset + a] += jc[sa] * r;
                for (b, &sb) in slots.iter().enumerate() {
                    lin.u[c][a * k + b] += jc[sa] * jc[sb];
                }
                for t in 0..3 {
                    coupling[a * 3 + t] += jc[sa] * jp[t];
                }
            }
            for s in 0..3 {
                lin.gp[l][s] += jp[s] * r;
                for t in 0..3 {
                    lin.v[l][s][t] += jp[s] * jp[t];
                }
            }
        }
        lin.w.push(coupling);
    }
    // Fixed control points: camera-only residuals (no W, V, or point gradient).
    for &(k, c, pixel) in &problem.control_observations {
        let projected = project(&state.cameras[c], problem.control_points[k].position)
            .ok_or(Stop::Breakdown)?;
        let residual = [pixel[0] - projected.pixel[0], pixel[1] - projected.pixel[1]];
        lin.cost += 0.5 * (residual[0] * residual[0] + residual[1] * residual[1]);
        let slots = &layout.slots[c];
        let k = slots.len();
        let offset = layout.offsets[c];
        for axis in 0..2 {
            let jc = &projected.camera[axis];
            let r = residual[axis];
            for (a, &sa) in slots.iter().enumerate() {
                lin.gc[offset + a] += jc[sa] * r;
                for (b, &sb) in slots.iter().enumerate() {
                    lin.u[c][a * k + b] += jc[sa] * jc[sb];
                }
            }
        }
    }
    if !lin.cost.is_finite() {
        return Err(Stop::Breakdown);
    }
    Ok(lin)
}

/// Contiguous observation ranges per landmark (observations are landmark-sorted).
fn landmark_groups(problem: &Canonical) -> Vec<(usize, usize)> {
    let mut groups = Vec::with_capacity(problem.landmarks.len());
    let mut start = 0;
    while start < problem.observations.len() {
        let mut end = start;
        while end < problem.observations.len()
            && problem.observations[end].0 == problem.observations[start].0
        {
            end += 1;
        }
        groups.push((start, end));
        start = end;
    }
    groups
}

fn damp(value: f64, lambda: f64) -> f64 {
    value + lambda * value.max(DIAGONAL_FLOOR)
}

struct Reduced {
    factor: Factor,
    /// Per landmark `V^-1`, row-major.
    v_inverse: Vec<Vec<f64>>,
    /// Per observation `Z = W V^-1`, row-major `k x 3`.
    z: Vec<Vec<f64>>,
    rhs: Vec<f64>,
}

enum ReduceOutcome {
    Ready(Reduced),
    NotPositiveDefinite(SingularStage),
}

/// Build and factor the (optionally damped) reduced camera system.
fn reduce(
    problem: &Canonical,
    layout: &Layout,
    groups: &[(usize, usize)],
    lin: &Linearized,
    lambda: f64,
    budget: &mut WorkBudget<'_>,
) -> Result<ReduceOutcome, Stop> {
    let n = layout.total;
    let mut s = vec![0.0; n * n];
    for (c, block) in lin.u.iter().enumerate() {
        let k = layout.slots[c].len();
        let o = layout.offsets[c];
        for a in 0..k {
            for b in 0..k {
                let value = block[a * k + b];
                s[(o + a) * n + o + b] = if a == b { damp(value, lambda) } else { value };
            }
        }
    }
    let mut rhs = lin.gc.clone();
    let mut v_inverse = Vec::with_capacity(groups.len());
    let mut z_all: Vec<Vec<f64>> = vec![Vec::new(); problem.observations.len()];
    for (l, &(start, end)) in groups.iter().enumerate() {
        let mut v = [0.0; 9];
        for s_ in 0..3 {
            for t in 0..3 {
                let value = lin.v[l][s_][t];
                v[s_ * 3 + t] = if s_ == t { damp(value, lambda) } else { value };
            }
        }
        let factor = match Factor::new(&v, 3, budget) {
            Ok(factor) => factor,
            Err(FactorError::Budget(error)) => return Err(Stop::Budget(error)),
            Err(FactorError::NotPositiveDefinite(_)) => {
                return Ok(ReduceOutcome::NotPositiveDefinite(
                    SingularStage::LandmarkCovariance {
                        landmark: problem.landmarks[l].landmark,
                    },
                ));
            }
        };
        let inverse = factor.inverse(budget)?;
        for o in start..end {
            let c = problem.observations[o].1;
            let k = layout.slots[c].len();
            let w = &lin.w[o];
            let mut z = vec![0.0; k * 3];
            for a in 0..k {
                for t in 0..3 {
                    z[a * 3 + t] = (0..3).map(|m| w[a * 3 + m] * inverse[m * 3 + t]).sum();
                }
            }
            let oc = layout.offsets[c];
            for a in 0..k {
                rhs[oc + a] -= (0..3).map(|t| z[a * 3 + t] * lin.gp[l][t]).sum::<f64>();
            }
            z_all[o] = z;
        }
        for a_obs in start..end {
            let ca = problem.observations[a_obs].1;
            let ka = layout.slots[ca].len();
            let oa = layout.offsets[ca];
            let z = &z_all[a_obs];
            for b_obs in start..end {
                let cb = problem.observations[b_obs].1;
                let kb = layout.slots[cb].len();
                let ob = layout.offsets[cb];
                budget.charge((3 * ka * kb) as u64 + 1)?;
                let w = &lin.w[b_obs];
                for a in 0..ka {
                    for b in 0..kb {
                        s[(oa + a) * n + ob + b] -=
                            (0..3).map(|t| z[a * 3 + t] * w[b * 3 + t]).sum::<f64>();
                    }
                }
            }
        }
        v_inverse.push(inverse);
    }
    let factor = match Factor::new(&s, n, budget) {
        Ok(factor) => factor,
        Err(FactorError::Budget(error)) => return Err(Stop::Budget(error)),
        Err(FactorError::NotPositiveDefinite(_)) => {
            return Ok(ReduceOutcome::NotPositiveDefinite(
                SingularStage::CameraCovariance,
            ));
        }
    };
    Ok(ReduceOutcome::Ready(Reduced {
        factor,
        v_inverse,
        z: z_all,
        rhs,
    }))
}

fn back_substitute(
    problem: &Canonical,
    layout: &Layout,
    groups: &[(usize, usize)],
    lin: &Linearized,
    reduced: &Reduced,
) -> (Vec<f64>, Vec<V3>) {
    let dc = reduced.factor.solve(&reduced.rhs);
    let mut dp = Vec::with_capacity(groups.len());
    for (l, &(start, end)) in groups.iter().enumerate() {
        let mut g = lin.gp[l];
        for o in start..end {
            let c = problem.observations[o].1;
            let oc = layout.offsets[c];
            let w = &lin.w[o];
            for (a, value) in dc[oc..oc + layout.slots[c].len()].iter().enumerate() {
                for (t, entry) in g.iter_mut().enumerate() {
                    *entry -= w[a * 3 + t] * value;
                }
            }
        }
        let vi = &reduced.v_inverse[l];
        dp.push(std::array::from_fn(|s| {
            vi[s * 3] * g[0] + vi[s * 3 + 1] * g[1] + vi[s * 3 + 2] * g[2]
        }));
    }
    (dc, dp)
}

fn apply(
    problem: &Canonical,
    layout: &Layout,
    state: &State,
    dc: &[f64],
    dp: &[V3],
) -> Option<State> {
    let mut next = state.clone();
    for (c, camera) in next.cameras.iter_mut().enumerate() {
        let mut block = [0.0; CAMERA_BLOCK_PARAMETERS];
        for (a, &slot) in layout.slots[c].iter().enumerate() {
            block[slot] = dc[layout.offsets[c] + a];
        }
        let w = [block[0], block[1], block[2]];
        if w != [0.0; 3] {
            camera.rotation = multiply(rotation_step(w), camera.rotation);
        }
        for k in 0..3 {
            camera.translation[k] += block[3 + k];
        }
        camera.pinhole[0] += block[6];
        match camera.aspect {
            Some(aspect) => camera.pinhole[1] = aspect * camera.pinhole[0],
            None => camera.pinhole[1] += block[7],
        }
        camera.pinhole[2] += block[8];
        camera.pinhole[3] += block[9];
        camera.radial[0] += block[10];
        camera.radial[1] += block[11];
        let [width, height] = problem.cameras[c].intrinsics.dimensions();
        let [fx, fy, cx, cy] = camera.pinhole;
        PinholeIntrinsics::new(width, height, fx, fy, cx, cy).ok()?;
        if camera
            .radial
            .iter()
            .any(|x| !x.is_finite() || x.abs() > 1e3)
            || camera.translation.iter().any(|x| !x.is_finite())
        {
            return None;
        }
    }
    for (point, delta) in next.points.iter_mut().zip(dp) {
        for k in 0..3 {
            point[k] += delta[k];
        }
        if point.iter().any(|x| !x.is_finite() || x.abs() > 1e9) {
            return None;
        }
    }
    Some(next)
}

fn parameter_norm(layout: &Layout, state: &State) -> f64 {
    let mut total = 0.0;
    for (c, camera) in state.cameras.iter().enumerate() {
        for &slot in &layout.slots[c] {
            let value = match slot {
                0..=2 => 1.0,
                3..=5 => camera.translation[slot - 3],
                6..=9 => camera.pinhole[slot - 6],
                _ => camera.radial[slot - 10],
            };
            total += value * value;
        }
    }
    for point in &state.points {
        total += point[0] * point[0] + point[1] * point[1] + point[2] * point[2];
    }
    total.sqrt()
}

fn gradient_converged(layout: &Layout, lin: &Linearized, tolerance: f64) -> bool {
    for (c, block) in lin.u.iter().enumerate() {
        let k = layout.slots[c].len();
        for a in 0..k {
            let diagonal = block[a * k + a];
            let g = lin.gc[layout.offsets[c] + a];
            if diagonal > 0.0 && g.abs() > tolerance * diagonal.sqrt() {
                return false;
            }
        }
    }
    for (v, g) in lin.v.iter().zip(&lin.gp) {
        for s in 0..3 {
            if v[s][s] > 0.0 && g[s].abs() > tolerance * v[s][s].sqrt() {
                return false;
            }
        }
    }
    true
}

pub(super) fn run(
    basis: GeometryBasis,
    gauge: BundleGaugeChoice,
    problem: Canonical,
    options: BundleOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<BundleAdjustment, BundleAdjustmentError> {
    let start_used = budget.used();
    let layout = Layout::new(&problem.free);
    let groups = landmark_groups(&problem);
    let residual_count = 2 * (problem.observations.len() + problem.control_observations.len());
    let parameter_count = layout.total + 3 * problem.landmarks.len();
    let rms = |cost: f64| (2.0 * cost / residual_count as f64).sqrt();
    let mut report = BundleReport {
        max_iterations: options.max_iterations,
        iterations: 0,
        accepted_steps: 0,
        rejected_steps: 0,
        work_units: 0,
        work_units_remaining: budget.remaining(),
        initial_rms_px: f64::NAN,
        final_rms_px: f64::NAN,
        residual_count,
        parameter_count,
        final_damping: options.initial_damping,
        convergence: None,
    };
    let fail = |stop: Stop, report: &mut BundleReport, budget: &WorkBudget<'_>| {
        report.work_units = budget.used() - start_used;
        report.work_units_remaining = budget.remaining();
        match stop {
            Stop::Budget(GeometryError::Cancelled) => BundleAdjustmentError::Cancelled,
            Stop::Budget(_) => BundleAdjustmentError::BudgetExhausted {
                kind: BudgetKind::WorkUnits,
                report: *report,
            },
            Stop::Breakdown => BundleAdjustmentError::NumericalBreakdown,
            Stop::Singular(stage) => BundleAdjustmentError::Singular(stage),
        }
    };

    let mut state = State {
        cameras: problem
            .cameras
            .iter()
            .map(|c| {
                let [fx, fy] = c.intrinsics.focal_lengths();
                let [cx, cy] = c.intrinsics.principal_point();
                CameraState {
                    rotation: c.pose.rotation(),
                    translation: c.pose.translation(),
                    pinhole: [fx, fy, cx, cy],
                    radial: [c.distortion.k1, c.distortion.k2],
                    aspect: (c.refinement.focal == FocalRefinement::AspectHeld).then_some(fy / fx),
                }
            })
            .collect(),
        points: problem.landmarks.iter().map(|l| l.position).collect(),
    };
    let mut lin = linearize(&problem, &layout, &state, budget)
        .map_err(|stop| fail(stop, &mut report, budget))?;
    report.initial_rms_px = rms(lin.cost);
    report.final_rms_px = report.initial_rms_px;
    let mut lambda = options.initial_damping;
    let mut convergence = if rms(lin.cost) <= ZERO_RMS_PX {
        Some(Convergence::ZeroResidual)
    } else if gradient_converged(&layout, &lin, options.gradient_tolerance_px) {
        Some(Convergence::Gradient)
    } else {
        None
    };
    while convergence.is_none() {
        report.final_damping = lambda;
        if report.iterations == options.max_iterations {
            report.work_units = budget.used() - start_used;
            report.work_units_remaining = budget.remaining();
            return Err(BundleAdjustmentError::BudgetExhausted {
                kind: BudgetKind::Iterations,
                report,
            });
        }
        report.iterations += 1;
        let reduced = match reduce(&problem, &layout, &groups, &lin, lambda, budget) {
            Ok(ReduceOutcome::Ready(reduced)) => reduced,
            Ok(ReduceOutcome::NotPositiveDefinite(_)) => {
                report.rejected_steps += 1;
                lambda *= 10.0;
                if lambda > MAX_DAMPING {
                    return Err(fail(
                        Stop::Singular(SingularStage::DampedStep),
                        &mut report,
                        budget,
                    ));
                }
                continue;
            }
            Err(stop) => return Err(fail(stop, &mut report, budget)),
        };
        let (dc, dp) = back_substitute(&problem, &layout, &groups, &lin, &reduced);
        let step_norm = (dc.iter().map(|x| x * x).sum::<f64>()
            + dp.iter()
                .map(|p| p[0] * p[0] + p[1] * p[1] + p[2] * p[2])
                .sum::<f64>())
        .sqrt();
        if !step_norm.is_finite() {
            return Err(fail(Stop::Breakdown, &mut report, budget));
        }
        let tolerance = options.step_tolerance;
        if step_norm <= tolerance * (parameter_norm(&layout, &state) + tolerance) {
            convergence = Some(Convergence::StepTolerance);
            break;
        }
        let candidate_cost = match apply(&problem, &layout, &state, &dc, &dp) {
            None => None,
            Some(candidate) => cost(&problem, &candidate, budget)
                .map_err(|stop| fail(stop, &mut report, budget))?
                .map(|value| (candidate, value)),
        };
        match candidate_cost {
            Some((candidate, value)) if value < lin.cost => {
                report.accepted_steps += 1;
                let relative = (lin.cost - value) / lin.cost;
                state = candidate;
                lin = linearize(&problem, &layout, &state, budget)
                    .map_err(|stop| fail(stop, &mut report, budget))?;
                report.final_rms_px = rms(lin.cost);
                lambda = (lambda / 3.0).max(MIN_DAMPING);
                convergence = if rms(lin.cost) <= ZERO_RMS_PX {
                    Some(Convergence::ZeroResidual)
                } else if relative <= options.cost_tolerance {
                    Some(Convergence::CostStalled)
                } else if gradient_converged(&layout, &lin, options.gradient_tolerance_px) {
                    Some(Convergence::Gradient)
                } else {
                    None
                };
            }
            _ => {
                report.rejected_steps += 1;
                lambda *= 10.0;
                if lambda > MAX_DAMPING {
                    report.work_units = budget.used() - start_used;
                    report.work_units_remaining = budget.remaining();
                    return Err(BundleAdjustmentError::Stalled(report));
                }
            }
        }
    }
    report.final_damping = lambda;
    report.convergence = convergence;

    // Covariance from the undamped normal matrix at the accepted solution.
    let reduced = match reduce(&problem, &layout, &groups, &lin, 0.0, budget) {
        Ok(ReduceOutcome::Ready(reduced)) => reduced,
        Ok(ReduceOutcome::NotPositiveDefinite(stage)) => {
            return Err(fail(Stop::Singular(stage), &mut report, budget));
        }
        Err(stop) => return Err(fail(stop, &mut report, budget)),
    };
    let s_inverse = reduced
        .factor
        .inverse(budget)
        .map_err(|e| fail(Stop::Budget(e), &mut report, budget))?;
    let (sigma, estimated) = match options.observation_sigma_px {
        Some(sigma) => (sigma, false),
        None => (
            (2.0 * lin.cost / (residual_count - parameter_count) as f64).sqrt(),
            true,
        ),
    };
    let variance = sigma * sigma;
    let n = layout.total;
    let mut cameras = Vec::with_capacity(problem.cameras.len());
    for (c, (input, camera)) in problem.cameras.iter().zip(&state.cameras).enumerate() {
        let [width, height] = input.intrinsics.dimensions();
        let [fx, fy, cx, cy] = camera.pinhole;
        let intrinsics = PinholeIntrinsics::new(width, height, fx, fy, cx, cy)
            .map_err(|_| BundleAdjustmentError::NumericalBreakdown)?;
        let pose = RigidPose::new(camera.rotation, camera.translation)
            .map_err(|_| BundleAdjustmentError::NumericalBreakdown)?;
        let slots = &layout.slots[c];
        let k = slots.len();
        let o = layout.offsets[c];
        let mut matrix = Vec::with_capacity(k * k);
        for a in 0..k {
            for b in 0..k {
                matrix.push(variance * s_inverse[(o + a) * n + o + b]);
            }
        }
        cameras.push(AdjustedCamera {
            identity: input.identity,
            intrinsics,
            distortion: RadialDistortion {
                k1: camera.radial[0],
                k2: camera.radial[1],
            },
            pose,
            covariance: CameraCovariance {
                parameters: slots
                    .iter()
                    .map(|s| BundleParameter::from_slot(*s, camera.aspect.is_some()))
                    .collect(),
                matrix,
                fixed: (0..CAMERA_BLOCK_PARAMETERS)
                    .filter(|s| !problem.free[c][*s])
                    .map(|s| BundleParameter::from_slot(s, camera.aspect.is_some()))
                    .collect(),
            },
        });
    }
    let mut landmarks = Vec::with_capacity(problem.landmarks.len());
    for (l, &(start, end)) in groups.iter().enumerate() {
        budget
            .charge(((end - start) * (end - start) * 300) as u64 + 9)
            .map_err(|e| fail(Stop::Budget(e), &mut report, budget))?;
        let vi = &reduced.v_inverse[l];
        let mut covariance = [[0.0; 3]; 3];
        for s in 0..3 {
            for t in 0..3 {
                covariance[s][t] = vi[s * 3 + t];
            }
        }
        for a_obs in start..end {
            let ca = problem.observations[a_obs].1;
            let (oa, ka) = (layout.offsets[ca], layout.slots[ca].len());
            let za = &reduced.z[a_obs];
            for b_obs in start..end {
                let cb = problem.observations[b_obs].1;
                let (ob, kb) = (layout.offsets[cb], layout.slots[cb].len());
                let zb = &reduced.z[b_obs];
                for s in 0..3 {
                    for t in 0..3 {
                        let mut value = 0.0;
                        for a in 0..ka {
                            for b in 0..kb {
                                value += za[a * 3 + s]
                                    * s_inverse[(oa + a) * n + ob + b]
                                    * zb[b * 3 + t];
                            }
                        }
                        covariance[s][t] += value;
                    }
                }
            }
        }
        for row in &mut covariance {
            for value in row.iter_mut() {
                *value *= variance;
            }
        }
        landmarks.push(AdjustedLandmark {
            landmark: problem.landmarks[l].landmark,
            position: state.points[l],
            covariance,
        });
    }
    report.work_units = budget.used() - start_used;
    report.work_units_remaining = budget.remaining();
    Ok(BundleAdjustment {
        basis,
        gauge,
        control_points: problem.control_points,
        cameras,
        landmarks,
        report,
        sigma_px: sigma,
        sigma_estimated: estimated,
    })
}
