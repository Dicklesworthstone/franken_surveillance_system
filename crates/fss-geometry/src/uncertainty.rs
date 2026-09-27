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
    AdjustedCamera, BundleParameter, CAMERA_BLOCK_PARAMETERS, CameraGeneration, GeometryError,
    WorkBudget,
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
        let mut a = [[0.0; N]; 2];
        for (i, &parameter) in self.covariance.parameters.iter().enumerate() {
            let slot = parameter_slot(parameter)?;
            let column = if parameter == BundleParameter::Focal {
                [jacobian[0][6], jacobian[1][7] * (fy / fx)]
            } else {
                [jacobian[0][slot], jacobian[1][slot]]
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
        if [xx, xy, yy].iter().any(|v| !v.is_finite()) {
            return Err(GeometryError::NonFinite.into());
        }
        budget.charge(0)?;
        Ok(CameraProjectionUncertainty {
            identity: self.identity,
            dimensions: self.intrinsics.dimensions(),
            world_point,
            pixel,
            covariance: [[xx, xy], [xy, yy]],
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

#[cfg(test)]
mod tests;
