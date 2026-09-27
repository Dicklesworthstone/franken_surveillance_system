//! Conditional image-space uncertainty from a bundle-adjusted camera.
//!
//! Propagates the complete within-camera marginal covariance, including pose / lens
//! cross terms, through the declared pinhole plus two-term radial model. The world
//! point is held exact. This is NOT the uncertainty of a jointly fitted landmark:
//! the bundle API does not retain camera / landmark cross covariance. Nor does this
//! certify visibility, calibrated probability, coverage, or evidence of absence.
//!
//! Rotation uses `R' = exp([w]x) R`, with translation perturbed independently. The
//! rotation derivative is therefore based on `R * world`, NOT `R * world + t`.
//! Fixed parameters and the bundle's gauge remain conditioning assumptions.

use crate::{
    AdjustedCamera, BundleAdjustment, BundleGaugeChoice, BundleParameter, BundleValidity,
    CAMERA_BLOCK_PARAMETERS, CameraGeneration, CameraInvalidation, GeometryBasis, GeometryError,
    MAX_BUNDLE_CAMERAS, WorkBudget,
};

const N: usize = CAMERA_BLOCK_PARAMETERS;
/// Fixed charge for a bounded, at-most-12-parameter projection and covariance factorization.
/// This is a reference accounting unit, not a measured instruction count or latency claim.
pub const CAMERA_UNCERTAINTY_WORK_UNITS: u64 = 12_000;

/// A projection was refused; no partial estimate or substitute confidence is returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionUncertaintyError {
    /// Coordinate, budget, or cancellation failure from the geometry kernel.
    Geometry(GeometryError),
    /// A camera / intrinsics / extrinsics handle was zero.
    InvalidGeneration,
    /// The bounded current-dependency set contains duplicate or zero handles.
    InvalidDependencySet,
    /// At least one dependency of the joint solve changed or disappeared.
    InvalidatedBundle(Vec<CameraInvalidation>),
    /// The requested camera did not participate in the joint solve.
    UnknownCamera(u64),
    /// The linearized contour multiplier must be finite and in `(0, 1e6]`.
    InvalidSigmaMultiplier,
    /// The caller's current generation is not the estimate's generation.
    GenerationMismatch {
        /// Generation used by the estimate.
        estimated: CameraGeneration,
        /// Current generation supplied by the caller.
        current: CameraGeneration,
    },
    /// Free and fixed parameters do not form one complete, disjoint camera block.
    InvalidParameterPartition,
    /// Aspect-held focal length and independently free `fy` cannot coexist.
    ConflictingFocalModel,
    /// Covariance storage is not exactly `k * k` for `k` free parameters.
    InvalidMatrixShape,
    /// The covariance contains a NaN or an infinity.
    NonFiniteCovariance,
    /// The covariance is not symmetric within floating-point roundoff.
    AsymmetricCovariance,
    /// A variance is negative or the normalized matrix has no PSD factorization.
    /// Numerically unresolved near-singular matrices are refused, never repaired.
    NotPositiveSemidefinite,
}
impl From<GeometryError> for ProjectionUncertaintyError {
    fn from(error: GeometryError) -> Self {
        Self::Geometry(error)
    }
}
impl std::fmt::Display for ProjectionUncertaintyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Geometry(error) => std::fmt::Display::fmt(error, f),
            Self::InvalidGeneration => f.write_str("zero camera generation handle"),
            Self::InvalidDependencySet => f.write_str("invalid current bundle dependency set"),
            Self::InvalidatedBundle(changes) => write!(f, "bundle uncertainty invalidated: {changes:?}"),
            Self::UnknownCamera(camera) => write!(f, "camera {camera} absent from bundle"),
            Self::InvalidSigmaMultiplier => f.write_str("invalid linearized contour multiplier"),
            Self::GenerationMismatch { estimated, current } => write!(
                f,
                "camera uncertainty generation mismatch: {estimated:?} != {current:?}"
            ),
            Self::InvalidParameterPartition => f.write_str("invalid camera parameter partition"),
            Self::ConflictingFocalModel => f.write_str("aspect-held focal model has free fy"),
            Self::InvalidMatrixShape => f.write_str("invalid camera covariance dimensions"),
            Self::NonFiniteCovariance => f.write_str("nonfinite camera covariance"),
            Self::AsymmetricCovariance => f.write_str("asymmetric camera covariance"),
            Self::NotPositiveSemidefinite => f.write_str("camera covariance is not numerically PSD"),
        }
    }
}
impl std::error::Error for ProjectionUncertaintyError {}

/// Local linearized pixel distribution, conditional on an exact world point and
/// the supplied gauge / fixed-parameter assumptions. Not a coverage witness.
#[derive(Clone, Debug, PartialEq)]
pub struct CameraProjectionUncertainty {
    identity: CameraGeneration,
    dimensions: [u32; 2],
    world_point: [f64; 3],
    pixel: [f64; 2],
    covariance: [[f64; 2]; 2],
    camera_depth: f64,
    depth_variance: f64,
    fixed_parameters: Vec<BundleParameter>,
}
impl CameraProjectionUncertainty {
    /// Exact immutable camera generations consumed.
    pub fn identity(&self) -> CameraGeneration {
        self.identity
    }
    /// Image mode in whose raw, declared radial-model pixel coordinates this result lives.
    pub fn dimensions(&self) -> [u32; 2] {
        self.dimensions
    }
    /// World point held exact; no landmark-position uncertainty was included.
    pub fn world_point(&self) -> [f64; 3] {
        self.world_point
    }
    /// Projected pixel. It may be outside the image; it is never clipped.
    pub fn pixel(&self) -> [f64; 2] {
        self.pixel
    }
    /// Full symmetric `J Sigma J^T` in squared pixels, including correlation.
    pub fn covariance_px2(&self) -> [[f64; 2]; 2] {
        self.covariance
    }
    /// Mean optical-axis depth, in the declared world units.
    pub fn camera_depth(&self) -> f64 {
        self.camera_depth
    }
    /// Conditional variance of optical-axis depth, in squared world units.
    pub fn depth_variance(&self) -> f64 {
        self.depth_variance
    }
    /// Original solver declarations, not evidence of zero physical uncertainty.
    /// With aspect-held `Focal`, the fixed `Fy` slot means the aspect is held:
    /// `fy` still changes with `fx`, which the propagated Jacobian accounts for.
    pub fn fixed_parameters(&self) -> &[BundleParameter] {
        &self.fixed_parameters
    }
}

impl AdjustedCamera {
    /// Propagate this camera's full marginal covariance to a held-exact world point.
    ///
    /// The caller must resolve the current generation from authority, not copy it
    /// from this estimate. A bundle-level consumer must additionally check ALL
    /// [`crate::BundleAdjustment::dependencies`] and the geometry basis: this
    /// single-camera helper cannot certify the other inputs to a joint solve.
    ///
    /// Covariance is normalized before factorization so radians, world units and
    /// pixels do not share an absolute pivot threshold. Negative pivots are never
    /// clipped or repaired. Exact zero / semidefinite covariance is admitted when
    /// a factor exists; ill-conditioned cases may conservatively refuse.
    pub fn project_uncertainty(
        &self,
        current: CameraGeneration,
        world_point: [f64; 3],
        budget: &mut WorkBudget<'_>,
    ) -> Result<CameraProjectionUncertainty, ProjectionUncertaintyError> {
        budget.charge(0)?;
        for identity in [self.identity, current] {
            if identity.camera == 0 || identity.intrinsics == 0 || identity.extrinsics == 0 {
                return Err(ProjectionUncertaintyError::InvalidGeneration);
            }
        }
        if current != self.identity {
            return Err(ProjectionUncertaintyError::GenerationMismatch {
                estimated: self.identity,
                current,
            });
        }
        // Check bounds before iterating caller-owned vectors or multiplying lengths.
        let k = self.covariance.parameters.len();
        if k > N || self.covariance.fixed.len() > N || k + self.covariance.fixed.len() != N {
            return Err(ProjectionUncertaintyError::InvalidParameterPartition);
        }
        if self.covariance.matrix.len() != k * k {
            return Err(ProjectionUncertaintyError::InvalidMatrixShape);
        }
        budget.charge(CAMERA_UNCERTAINTY_WORK_UNITS)?;
        let mut seen = [false; N];
        for &parameter in self.covariance.parameters.iter().chain(&self.covariance.fixed) {
            let slot = parameter_slot(parameter)?;
            if seen[slot] {
                return Err(ProjectionUncertaintyError::InvalidParameterPartition);
            }
            seen[slot] = true;
        }
        if self.covariance.parameters.contains(&BundleParameter::Focal)
            && self.covariance.parameters.contains(&BundleParameter::Fy)
        {
            return Err(ProjectionUncertaintyError::ConflictingFocalModel);
        }
        let factor = covariance_factor(&self.covariance.matrix, k)?;
        let (pixel, jacobian) = projection_jacobian(self, world_point)?;
        let [fx, fy] = self.intrinsics.focal_lengths();
        // Compute A = J L, then A A^T. The positive factor avoids cancellation
        // producing negative output variances for valid strongly correlated inputs.
        let camera_depth = self.pose.transform(world_point)?[2];
        let rotation = self.pose.rotation();
        let rotate = |row: usize| -> f64 {
            rotation[row].iter().zip(world_point).map(|(r, w)| r * w).sum()
        };
        let mut depth_jacobian = [0.0; N];
        depth_jacobian[0] = rotate(1);
        depth_jacobian[1] = -rotate(0);
        depth_jacobian[5] = 1.0;
        let mut a = [[0.0; N]; 3];
        for (i, &parameter) in self.covariance.parameters.iter().enumerate() {
            let slot = parameter_slot(parameter)?;
            let column = if parameter == BundleParameter::Focal {
                [jacobian[0][6], jacobian[1][7] * (fy / fx), 0.0]
            } else {
                [jacobian[0][slot], jacobian[1][slot], depth_jacobian[slot]]
            };
            for (row, output) in a.iter_mut().enumerate() {
                for (j, cell) in output.iter_mut().enumerate().take(i + 1) {
                    *cell += column[row] * factor[i][j];
                }
            }
        }
        let dot = |left: &[f64; N], right: &[f64; N]| -> f64 {
            left.iter().zip(right).map(|(l, r)| l * r).sum()
        };
        let xx = dot(&a[0], &a[0]);
        let xy = dot(&a[0], &a[1]);
        let yy = dot(&a[1], &a[1]);
        let depth_variance = dot(&a[2], &a[2]);
        if [xx, xy, yy, depth_variance].iter().any(|v| !v.is_finite()) {
            return Err(GeometryError::NonFinite.into());
        }
        budget.charge(0)?;
        Ok(CameraProjectionUncertainty {
            identity: self.identity,
            dimensions: self.intrinsics.dimensions(),
            world_point,
            pixel,
            covariance: [[xx, xy], [xy, yy]],
            camera_depth,
            depth_variance,
            fixed_parameters: self.covariance.fixed.clone(),
        })
    }
}

fn parameter_slot(parameter: BundleParameter) -> Result<usize, ProjectionUncertaintyError> {
    use BundleParameter::{Cx, Cy, Focal, Fx, Fy, K1, K2, Rotation, Translation};
    match parameter {
        Rotation(axis) if axis < 3 => Ok(axis),
        Translation(axis) if axis < 3 => Ok(3 + axis),
        Focal | Fx => Ok(6),
        Fy => Ok(7),
        Cx => Ok(8),
        Cy => Ok(9),
        K1 => Ok(10),
        K2 => Ok(11),
        _ => Err(ProjectionUncertaintyError::InvalidParameterPartition),
    }
}

// Indices express a triangular matrix factorization, not independent slice iteration.
#[allow(clippy::needless_range_loop)]
fn covariance_factor(
    matrix: &[f64],
    k: usize,
) -> Result<[[f64; N]; N], ProjectionUncertaintyError> {
    use ProjectionUncertaintyError::{
        AsymmetricCovariance, NonFiniteCovariance, NotPositiveSemidefinite,
    };
    if matrix.iter().any(|v| !v.is_finite()) {
        return Err(NonFiniteCovariance);
    }
    let mut sigma = [0.0; N];
    for i in 0..k {
        if matrix[i * k + i] < 0.0 {
            return Err(NotPositiveSemidefinite);
        }
        sigma[i] = matrix[i * k + i].sqrt();
    }
    let mut l = [[0.0; N]; N];
    for i in 0..k {
        for j in 0..=i {
            let (a, b) = (matrix[i * k + j], matrix[j * k + i]);
            let mut value = if sigma[i] == 0.0 || sigma[j] == 0.0 {
                if a != 0.0 || b != 0.0 {
                    return Err(NotPositiveSemidefinite);
                }
                0.0
            } else {
                let (a, b) = (a / sigma[i] / sigma[j], b / sigma[i] / sigma[j]);
                if !a.is_finite() || !b.is_finite() {
                    return Err(NotPositiveSemidefinite);
                }
                if (a - b).abs() > 64.0 * f64::EPSILON * a.abs().max(b.abs()).max(1.0) {
                    return Err(AsymmetricCovariance);
                }
                // Average within roundoff only; materially asymmetric input was refused.
                0.5 * a + 0.5 * b
            };
            for h in 0..j {
                value -= l[i][h] * l[j][h];
            }
            if i == j {
                if value < 0.0 || !value.is_finite() {
                    return Err(NotPositiveSemidefinite);
                }
                l[i][j] = value.sqrt();
            } else if l[j][j] == 0.0 {
                if value != 0.0 {
                    return Err(NotPositiveSemidefinite);
                }
            } else {
                l[i][j] = value / l[j][j];
                if !l[i][j].is_finite() {
                    return Err(NotPositiveSemidefinite);
                }
            }
        }
    }
    for i in 0..k {
        for j in 0..=i {
            l[i][j] *= sigma[i];
        }
    }
    Ok(l)
}

fn projection_jacobian(
    camera: &AdjustedCamera,
    world: [f64; 3],
) -> Result<([f64; 2], [[f64; N]; 2]), ProjectionUncertaintyError> {
    let q = camera.pose.transform(world)?;
    // Reuse the established positive-depth and admitted coordinate checks.
    camera.intrinsics.project(q)?;
    let [fx, fy] = camera.intrinsics.focal_lengths();
    let [cx, cy] = camera.intrinsics.principal_point();
    let (k1, k2) = (camera.distortion.k1, camera.distortion.k2);
    if !k1.is_finite() || !k2.is_finite() {
        return Err(GeometryError::NonFinite.into());
    }
    let (x, y) = (q[0] / q[2], q[1] / q[2]);
    let r2 = x * x + y * y;
    let r4 = r2 * r2;
    let radial = 1.0 + k1 * r2 + k2 * r4;
    let slope = k1 + 2.0 * k2 * r2;
    let pixel = [fx * x * radial + cx, fy * y * radial + cy];
    let normalized = [
        [fx * (radial + 2.0 * x * x * slope), fx * 2.0 * x * y * slope],
        [fy * 2.0 * x * y * slope, fy * (radial + 2.0 * y * y * slope)],
    ];
    // Compute R * world directly rather than subtracting t from q: subtraction
    // loses the rotation signal when translation dominates the coordinates.
    let rotation = camera.pose.rotation();
    let mut turned = [0.0; 3];
    for (axis, row) in rotation.iter().enumerate() {
        turned[axis] = row.iter().zip(world).map(|(r, w)| r * w).sum();
    }
    let mut jacobian = [[0.0; N]; 2];
    for (row, j) in jacobian.iter_mut().enumerate() {
        let [dx, dy] = normalized[row];
        let d = [dx / q[2], dy / q[2], -(dx * x + dy * y) / q[2]];
        j[0] = -d[1] * turned[2] + d[2] * turned[1];
        j[1] = d[0] * turned[2] - d[2] * turned[0];
        j[2] = -d[0] * turned[1] + d[1] * turned[0];
        j[3..6].copy_from_slice(&d);
    }
    jacobian[0][6] = x * radial;
    jacobian[1][7] = y * radial;
    jacobian[0][8] = 1.0;
    jacobian[1][9] = 1.0;
    jacobian[0][10] = fx * x * r2;
    jacobian[1][10] = fy * y * r2;
    jacobian[0][11] = fx * x * r4;
    jacobian[1][11] = fy * y * r4;
    if pixel.iter().chain(jacobian.iter().flatten()).any(|v| !v.is_finite()) {
        return Err(GeometryError::NonFinite.into());
    }
    Ok((pixel, jacobian))
}


/// Fixed reference charge for validating the at-most-32-camera dependency set.
pub const BUNDLE_UNCERTAINTY_VALIDATION_WORK_UNITS: u64 = 4_096;
/// Fixed reference charge for a linearized image/depth contour assessment.
pub const FRUSTUM_UNCERTAINTY_WORK_UNITS: u64 = 64;

/// A projected estimate bound to the joint solve's complete generation dependencies.
#[derive(Clone, Debug, PartialEq)]
pub struct BundleProjectionUncertainty {
    basis: GeometryBasis,
    gauge: BundleGaugeChoice,
    dependencies: Vec<CameraGeneration>,
    observation_sigma_px: (f64, bool),
    projection: CameraProjectionUncertainty,
}
impl BundleProjectionUncertainty {
    /// Property and immutable twin revision checked against the caller's current basis.
    pub fn basis(&self) -> GeometryBasis {
        self.basis
    }
    /// Gauge held by the solve; its reference / survey accuracy is NOT in this covariance.
    pub fn gauge(&self) -> BundleGaugeChoice {
        self.gauge
    }
    /// All joint-solve dependencies, in canonical camera order.
    pub fn dependencies(&self) -> &[CameraGeneration] {
        &self.dependencies
    }
    /// Observation sigma and whether it was estimated from residuals, not externally supplied.
    pub fn observation_sigma_px(&self) -> (f64, bool) {
        self.observation_sigma_px
    }
    /// Conditional pixel and depth estimate, retaining its fixed-parameter assumptions.
    pub fn projection(&self) -> &CameraProjectionUncertainty {
        &self.projection
    }
}

impl BundleAdjustment {
    /// Project one held-exact world point after checking the entire joint solve.
    ///
    /// `current` is the authority-resolved generation set for this solve's camera
    /// dependencies, not an unbounded inventory of the deployment. Extra entries
    /// are harmless within the hard limit; missing, duplicate or stale entries are
    /// not. The caller must invalidate `current_basis` when survey/control geometry
    /// changes. No cross-camera or camera/landmark covariance is invented.
    pub fn project_camera_uncertainty(
        &self,
        camera: u64,
        current_basis: GeometryBasis,
        current: &[CameraGeneration],
        world_point: [f64; 3],
        budget: &mut WorkBudget<'_>,
    ) -> Result<BundleProjectionUncertainty, ProjectionUncertaintyError> {
        budget.charge(0)?;
        if current.len() > MAX_BUNDLE_CAMERAS {
            return Err(ProjectionUncertaintyError::InvalidDependencySet);
        }
        if current_basis != self.basis() {
            return Err(GeometryError::BasisMismatch.into());
        }
        budget.charge(BUNDLE_UNCERTAINTY_VALIDATION_WORK_UNITS)?;
        for (i, generation) in current.iter().enumerate() {
            if generation.camera == 0 || generation.intrinsics == 0 || generation.extrinsics == 0
                || current[..i].iter().any(|other| other.camera == generation.camera)
            {
                return Err(ProjectionUncertaintyError::InvalidDependencySet);
            }
        }
        if let BundleValidity::Invalidated(changes) = self.validity(current) {
            return Err(ProjectionUncertaintyError::InvalidatedBundle(changes));
        }
        let adjusted = self.camera(camera).ok_or(ProjectionUncertaintyError::UnknownCamera(camera))?;
        // Equality with the caller-resolved set was established above for every dependency.
        let projection = adjusted.project_uncertainty(adjusted.identity, world_point, budget)?;
        budget.charge(0)?;
        Ok(BundleProjectionUncertainty {
            basis: self.basis(),
            gauge: self.gauge(),
            dependencies: self.dependencies(),
            observation_sigma_px: self.observation_sigma_px(),
            projection,
        })
    }
}

/// Relation of an axis-aligned enclosure of a LOCAL LINEARIZED contour to the image.
/// These names describe that enclosure only, never physical observability or absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinearizedFrustumRelation {
    /// The whole linearized enclosure is inside the half-open image domain.
    Inside,
    /// The enclosure is wholly beyond at least one image edge.
    Outside,
    /// The enclosure meets an image edge; the mean alone cannot decide membership.
    Boundary,
    /// The depth contour reaches the camera plane, where perspective linearization
    /// cannot support an inside/outside assessment, even with zero pixel variance.
    CrossesCameraPlane,
}

/// Axis-aligned enclosure of a sigma-scaled linearized contour, never a calibrated
/// confidence interval. A two-dimensional contour multiplier is not a 1D tail probability.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LinearizedFrustumAssessment {
    /// Multiplier supplied by the caller, not selected from a hidden policy.
    pub sigma_multiplier: f64,
    /// Inclusive per-axis minima in declared raw pixel coordinates; never clipped.
    pub pixel_min: [f64; 2],
    /// Inclusive per-axis maxima; the IMAGE's upper edges remain exclusive.
    pub pixel_max: [f64; 2],
    /// Inclusive depth bounds, in the geometry's declared world units.
    pub depth_interval: [f64; 2],
    /// Typed conditional relation; cannot be promoted to a `CoverageWitness`.
    pub relation: LinearizedFrustumRelation,
}

impl CameraProjectionUncertainty {
    /// Assess an explicit sigma-scaled local contour without substituting a mean
    /// point for uncertain image membership. Occlusion, privacy, timing, point
    /// uncertainty, model error and detection quality remain outside this method.
    /// Even `Inside` does not establish physical visibility or authorize negative evidence.
    pub fn linearized_frustum(
        &self,
        sigma_multiplier: f64,
        budget: &mut WorkBudget<'_>,
    ) -> Result<LinearizedFrustumAssessment, ProjectionUncertaintyError> {
        budget.charge(0)?;
        if !sigma_multiplier.is_finite() || sigma_multiplier <= 0.0 || sigma_multiplier > 1e6 {
            return Err(ProjectionUncertaintyError::InvalidSigmaMultiplier);
        }
        budget.charge(FRUSTUM_UNCERTAINTY_WORK_UNITS)?;
        let radius = [
            sigma_multiplier * self.covariance[0][0].sqrt(),
            sigma_multiplier * self.covariance[1][1].sqrt(),
        ];
        let pixel_min = [self.pixel[0] - radius[0], self.pixel[1] - radius[1]];
        let pixel_max = [self.pixel[0] + radius[0], self.pixel[1] + radius[1]];
        let depth_radius = sigma_multiplier * self.depth_variance.sqrt();
        let depth_interval = [self.camera_depth - depth_radius, self.camera_depth + depth_radius];
        if pixel_min.iter().chain(&pixel_max).chain(&depth_interval).any(|v| !v.is_finite()) {
            return Err(GeometryError::NonFinite.into());
        }
        let [width, height] = self.dimensions.map(f64::from);
        let relation = if depth_interval[0] <= 1e-9 {
            LinearizedFrustumRelation::CrossesCameraPlane
        } else if pixel_max[0] < 0.0 || pixel_max[1] < 0.0
            || pixel_min[0] >= width || pixel_min[1] >= height
        {
            LinearizedFrustumRelation::Outside
        } else if pixel_min[0] >= 0.0 && pixel_min[1] >= 0.0
            && pixel_max[0] < width && pixel_max[1] < height
        {
            LinearizedFrustumRelation::Inside
        } else {
            LinearizedFrustumRelation::Boundary
        };
        budget.charge(0)?;
        Ok(LinearizedFrustumAssessment {
            sigma_multiplier, pixel_min, pixel_max, depth_interval, relation,
        })
    }
}

#[cfg(test)]
mod tests;
