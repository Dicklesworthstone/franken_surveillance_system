#![forbid(unsafe_code)]
//! Pose-uncertainty propagation into ground-zone visibility (fss-x8j0v, covariance propagation to
//! coverage certificates).
//!
//! A calibrated pose is a point estimate; the site calibration also carries the bundle adjuster's
//! local covariance of every camera's free parameters. This module asks one question of it: would
//! the zone's visibility class (observable, occluded, outside the frustum, privacy masked) change
//! if the pose moved within that covariance?
//!
//! * **Perturbation set (deterministic).** The 6-DoF pose block of the covariance (rotation about
//!   world-to-camera X, Y, Z in the adjuster's left-perturbation tangent space `R' = exp([w]x) R`,
//!   then world-to-camera translation X, Y, Z) is factored `Sigma = L L^T` by a lower Cholesky
//!   factorization that admits positive-semidefinite blocks (a pivot at or below
//!   `1e-12 * max diagonal` is a zero column; a clearly negative pivot is refused). The sigma
//!   points are the scaled unscented set for `n = 6` with `n + lambda = 9`: the nominal pose plus
//!   `nominal (+/-) 3 * L[:, j]` for `j = 0..6`, in the order `+L0, -L0, +L1, -L1, ..., -L5`.
//!   The nominal pose is the centre point (already assessed); the 12 displaced poses are the
//!   perturbations. The same inputs always give the same poses, bit for bit, on one platform.
//! * **Classification.** Each perturbed pose is assessed with the exact sampling, mesh and
//!   privacy mask of the nominal assessment. The zone is `robust` when every perturbation has the
//!   nominal class, otherwise `pose_sensitive`, with the count of each class that occurs.
//! * **Budget.** One [`WorkBudget`] per camera ([`MAX_POSE_SENSITIVITY_WORK`], the existing
//!   per-assessment visibility bound) is charged across all its zones and perturbations: one unit
//!   per projected sample and the mesh's per-triangle charges. A zone whose
//!   `perturbations x samples` exceeds the remaining budget, or whose mesh tests exhaust it, is a
//!   typed [`VisibilityError::PoseSensitivityBudget`] refusal; nothing is partially classified.
//!
//! Non-claims: the covariance is a local Gauss-Newton linearization, not a calibrated posterior,
//! and sigma points probe 12 directions of it, so `robust` is not a guarantee that no pose inside
//! (or outside) the covariance changes the class. Intrinsics uncertainty and the cross-covariance
//! between pose and intrinsics are not propagated (the pose block is the marginal).

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContractError};
use fss_geometry::{GeometryError, WorkBudget};

use super::{
    CameraPose, NotVisibleCause, PixelMask, SceneMesh, VisibilityCamera, VisibilityError,
    VisibilityPolicy, ZoneVisibility, assess_samples, ground_samples,
};

/// Registered perturbation and classification policy of this module.
pub const POSE_SENSITIVITY_POLICY: &str = "fss.pose_sensitivity_policy.v1:\
unscented-sigma-points:n=6:n+lambda=9:radius-3:psd-lower-cholesky:left-perturbation-rotation:\
additive-world-to-camera-translation:classes-observable-occluded-outside_frustum-privacy_masked:\
intrinsics-uncertainty-not-propagated";
/// Mahalanobis radius of every sigma point: `sqrt(n + lambda) = sqrt(9)`.
pub const POSE_SIGMA_RADIUS: f64 = 3.0;
/// Displaced poses assessed per zone (`2n`, the centre point being the nominal pose).
pub const POSE_SENSITIVITY_PERTURBATIONS: u32 = 12;
/// Work units the pose-sensitivity pass of one camera may charge across all its zones.
pub const MAX_POSE_SENSITIVITY_WORK: u64 = super::MAX_VISIBILITY_WORK;
/// Relative symmetry tolerance of a pose covariance (against its largest diagonal entry).
const SYMMETRY_TOLERANCE: f64 = 1e-9;
/// Relative pivot below which a Cholesky column is treated as zero (semidefinite direction).
const PIVOT_TOLERANCE: f64 = 1e-12;
/// Relative residual a zero column may leave below the diagonal before the block is refused.
const RESIDUAL_TOLERANCE: f64 = 1e-6;

/// The 6-DoF pose block of a calibration covariance, in the bundle adjuster's order: rotation
/// X, Y, Z (radians, left perturbation), then world-to-camera translation X, Y, Z (world units).
#[derive(Clone, Copy, Debug)]
pub struct PoseCovariance {
    matrix: [[f64; 6]; 6],
}

impl PartialEq for PoseCovariance {
    fn eq(&self, other: &Self) -> bool {
        self.bits() == other.bits()
    }
}

impl Eq for PoseCovariance {}

impl PoseCovariance {
    /// Validated covariance: finite, symmetric (relative [`SYMMETRY_TOLERANCE`]) and positive
    /// semidefinite under the documented Cholesky rule.
    pub fn new(matrix: [[f64; 6]; 6]) -> Result<Self, VisibilityError> {
        let covariance = Self { matrix };
        covariance.factor()?;
        Ok(covariance)
    }

    /// The row-major matrix.
    #[must_use]
    pub const fn matrix(&self) -> [[f64; 6]; 6] {
        self.matrix
    }

    /// The covariance multiplied by `factor` (finite, non-negative).
    pub fn scaled(&self, factor: f64) -> Result<Self, VisibilityError> {
        if !factor.is_finite() || factor < 0.0 {
            return Err(VisibilityError::InvalidCovariance);
        }
        Self::new(self.matrix.map(|row| row.map(|value| value * factor)))
    }

    /// Exact bits, row-major.
    #[must_use]
    pub fn bits(&self) -> [u64; 36] {
        let mut bits = [0_u64; 36];
        for (index, value) in self.matrix.iter().flatten().enumerate() {
            bits[index] = value.to_bits();
        }
        bits
    }

    /// Canonical encoding: the 36 entries' bits, row-major.
    pub fn encode(&self, e: &mut CanonicalEncoder) {
        for bits in self.bits() {
            e.u64(bits);
        }
    }

    /// Decodes and validates [`Self::encode`].
    pub fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let mut matrix = [[0.0_f64; 6]; 6];
        for row in &mut matrix {
            for value in row.iter_mut() {
                *value = f64::from_bits(d.u64()?);
            }
        }
        Self::new(matrix).map_err(|_| ContractError::InvalidIdentifier)
    }

    /// Lower factor `L` with `Sigma = L L^T` (semidefinite columns zero).
    fn factor(&self) -> Result<[[f64; 6]; 6], VisibilityError> {
        let a = &self.matrix;
        if a.iter().flatten().any(|value| !value.is_finite()) {
            return Err(VisibilityError::InvalidCovariance);
        }
        let scale = (0..6).fold(0.0_f64, |m, i| m.max(a[i][i].abs()));
        for i in 0..6 {
            for j in 0..i {
                if (a[i][j] - a[j][i]).abs() > SYMMETRY_TOLERANCE * scale {
                    return Err(VisibilityError::InvalidCovariance);
                }
            }
        }
        let mut lower = [[0.0_f64; 6]; 6];
        for j in 0..6 {
            let pivot = a[j][j] - (0..j).map(|k| lower[j][k] * lower[j][k]).sum::<f64>();
            if pivot > PIVOT_TOLERANCE * scale {
                let root = pivot.sqrt();
                lower[j][j] = root;
                for i in j + 1..6 {
                    let residual = a[i][j] - (0..j).map(|k| lower[i][k] * lower[j][k]).sum::<f64>();
                    lower[i][j] = residual / root;
                }
            } else if pivot >= -PIVOT_TOLERANCE * scale {
                // A zero direction: nothing below it may still need explaining.
                for i in j + 1..6 {
                    let residual = a[i][j] - (0..j).map(|k| lower[i][k] * lower[j][k]).sum::<f64>();
                    if residual.abs() > RESIDUAL_TOLERANCE * scale {
                        return Err(VisibilityError::InvalidCovariance);
                    }
                }
            } else {
                return Err(VisibilityError::InvalidCovariance);
            }
        }
        if lower.iter().flatten().any(|value| !value.is_finite()) {
            return Err(VisibilityError::InvalidCovariance);
        }
        Ok(lower)
    }
}

/// The 12 displaced sigma-point poses of `pose` under `covariance`, in the documented order
/// (`+L0, -L0, ..., +L5, -L5` at radius [`POSE_SIGMA_RADIUS`]); the nominal centre point is not
/// repeated. Intrinsics are the nominal ones.
pub fn pose_sigma_points(
    pose: &CameraPose,
    covariance: &PoseCovariance,
) -> Result<Vec<CameraPose>, VisibilityError> {
    let lower = covariance.factor()?;
    let mut poses = Vec::with_capacity(POSE_SENSITIVITY_PERTURBATIONS as usize);
    // Columns of the factor, in order.
    let columns: [[f64; 6]; 6] = std::array::from_fn(|column| lower.map(|row| row[column]));
    for column in &columns {
        for sign in [1.0_f64, -1.0] {
            let step: [f64; 6] = column.map(|value| sign * POSE_SIGMA_RADIUS * value);
            let displaced = pose
                .pose
                .left_perturbed([step[0], step[1], step[2]], [step[3], step[4], step[5]])
                .map_err(|_| VisibilityError::InvalidCovariance)?;
            poses.push(CameraPose {
                intrinsics: pose.intrinsics,
                pose: displaced,
            });
        }
    }
    Ok(poses)
}

/// Visibility class of one assessment.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PoseRobustnessClass {
    /// At or above the threshold, no masked sample.
    Observable,
    /// Not observable, mostly hidden by the mesh.
    Occluded,
    /// Not observable, mostly behind the camera or outside the image.
    OutsideFrustum,
    /// Not observable, some in-view sample on a privacy-masked pixel.
    PrivacyMasked,
}

impl PoseRobustnessClass {
    /// The class of one assessment.
    #[must_use]
    pub fn of(visibility: &ZoneVisibility) -> Self {
        match visibility.cause() {
            None => Self::Observable,
            Some(NotVisibleCause::Occluded) => Self::Occluded,
            Some(NotVisibleCause::OutsideFrustum) => Self::OutsideFrustum,
            Some(NotVisibleCause::PrivacyMasked) => Self::PrivacyMasked,
        }
    }

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observable => "observable",
            Self::Occluded => "occluded",
            Self::OutsideFrustum => "outside_frustum",
            Self::PrivacyMasked => "privacy_masked",
        }
    }
}

/// How the visibility class of one zone behaved over the sigma-point perturbations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoseRobustness {
    /// Class under the nominal pose (derived from the zone's visibility, not encoded).
    pub nominal: PoseRobustnessClass,
    /// Perturbations assessed ([`POSE_SENSITIVITY_PERTURBATIONS`]).
    pub perturbations: u32,
    /// Perturbations under which the zone was observable.
    pub observable: u32,
    /// Perturbations under which it was occluded.
    pub occluded: u32,
    /// Perturbations under which it was outside the frustum.
    pub outside_frustum: u32,
    /// Perturbations under which it was privacy masked.
    pub privacy_masked: u32,
}

impl PoseRobustness {
    /// Count of perturbations in `class`.
    #[must_use]
    pub const fn count(&self, class: PoseRobustnessClass) -> u32 {
        match class {
            PoseRobustnessClass::Observable => self.observable,
            PoseRobustnessClass::Occluded => self.occluded,
            PoseRobustnessClass::OutsideFrustum => self.outside_frustum,
            PoseRobustnessClass::PrivacyMasked => self.privacy_masked,
        }
    }

    /// Perturbations with the nominal class.
    #[must_use]
    pub const fn agreeing(&self) -> u32 {
        self.count(self.nominal)
    }

    /// Whether every perturbation has the nominal class.
    #[must_use]
    pub const fn robust(&self) -> bool {
        self.agreeing() == self.perturbations
    }

    /// `robust` or `pose_sensitive`.
    #[must_use]
    pub const fn state(&self) -> &'static str {
        if self.robust() {
            "robust"
        } else {
            "pose_sensitive"
        }
    }

    /// Whether the nominal zone is observable but some perturbation is not: such a zone must not
    /// be reported as plainly observable and never carries an absence witness.
    #[must_use]
    pub const fn observable_but_sensitive(&self) -> bool {
        matches!(self.nominal, PoseRobustnessClass::Observable) && !self.robust()
    }

    /// Fraction of perturbations that disagree with the nominal class, in parts per million
    /// (floor).
    #[must_use]
    pub fn disagreeing_ppm(&self) -> u32 {
        if self.perturbations == 0 {
            return 0;
        }
        let disagreeing = u64::from(self.perturbations - self.agreeing().min(self.perturbations));
        u32::try_from(disagreeing * 1_000_000 / u64::from(self.perturbations)).unwrap_or(1_000_000)
    }

    /// The classes that occur, in registered order.
    #[must_use]
    pub fn classes(&self) -> Vec<PoseRobustnessClass> {
        [
            PoseRobustnessClass::Observable,
            PoseRobustnessClass::Occluded,
            PoseRobustnessClass::OutsideFrustum,
            PoseRobustnessClass::PrivacyMasked,
        ]
        .into_iter()
        .filter(|class| self.count(*class) > 0)
        .collect()
    }

    /// Counts add up to the registered perturbation count.
    pub fn validate(&self) -> Result<(), ContractError> {
        let total = u64::from(self.observable)
            + u64::from(self.occluded)
            + u64::from(self.outside_frustum)
            + u64::from(self.privacy_masked);
        if self.perturbations != POSE_SENSITIVITY_PERTURBATIONS
            || total != u64::from(self.perturbations)
        {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(())
    }

    /// One-line summary, for example `pose_sensitive: 4 of 12 sigma-point poses disagree with
    /// the nominal observable (333333 ppm; observable 8, outside_frustum 4)`.
    #[must_use]
    pub fn summary(&self) -> String {
        let classes: Vec<String> = self
            .classes()
            .into_iter()
            .map(|class| format!("{} {}", class.as_str(), self.count(class)))
            .collect();
        format!(
            "{}: {} of {} sigma-point poses disagree with the nominal {} ({} ppm; {})",
            self.state(),
            self.perturbations - self.agreeing().min(self.perturbations),
            self.perturbations,
            self.nominal.as_str(),
            self.disagreeing_ppm(),
            classes.join(", ")
        )
    }

    /// Canonical encoding (the nominal class is the zone visibility's and is not repeated).
    pub fn encode(&self, e: &mut CanonicalEncoder) {
        e.u32(self.perturbations);
        e.u32(self.observable);
        e.u32(self.occluded);
        e.u32(self.outside_frustum);
        e.u32(self.privacy_masked);
    }

    /// Decodes and validates [`Self::encode`] against the zone's nominal visibility.
    pub fn decode(
        d: &mut CanonicalDecoder<'_>,
        nominal: &ZoneVisibility,
    ) -> Result<Self, ContractError> {
        let robustness = Self {
            nominal: PoseRobustnessClass::of(nominal),
            perturbations: d.u32()?,
            observable: d.u32()?,
            occluded: d.u32()?,
            outside_frustum: d.u32()?,
            privacy_masked: d.u32()?,
        };
        robustness.validate()?;
        Ok(robustness)
    }
}

/// Assesses `polygon` under every sigma-point perturbation of `pose` and classifies the result
/// against `nominal` (the zone's assessment under `pose` itself, with the same `mesh`, `policy`
/// and `masked`). Charges `budget` (shared by all zones of one camera); refuses with
/// [`VisibilityError::PoseSensitivityBudget`] before assessing when `perturbations x samples`
/// exceeds what remains, or when mesh tests exhaust it.
#[allow(clippy::too_many_arguments)]
pub fn assess_pose_robustness(
    pose: &CameraPose,
    covariance: &PoseCovariance,
    dimensions: [u32; 2],
    polygon: &[(f64, f64)],
    mesh: Option<SceneMesh<'_>>,
    policy: VisibilityPolicy,
    masked: Option<PixelMask<'_>>,
    nominal: &ZoneVisibility,
    budget: &mut WorkBudget<'_>,
) -> Result<PoseRobustness, VisibilityError> {
    let samples = ground_samples(polygon, policy)?;
    let required = u64::from(POSE_SENSITIVITY_PERTURBATIONS).saturating_mul(samples.len() as u64);
    if required > budget.remaining() {
        return Err(VisibilityError::PoseSensitivityBudget);
    }
    let mut robustness = PoseRobustness {
        nominal: PoseRobustnessClass::of(nominal),
        perturbations: 0,
        observable: 0,
        occluded: 0,
        outside_frustum: 0,
        privacy_masked: 0,
    };
    for displaced in pose_sigma_points(pose, covariance)? {
        let visibility = assess_samples(
            VisibilityCamera::Pose(&displaced),
            dimensions,
            &samples,
            mesh,
            policy,
            masked,
            budget,
        )
        .map_err(|error| match error {
            VisibilityError::Geometry(GeometryError::BudgetExhausted) => {
                VisibilityError::PoseSensitivityBudget
            }
            other => other,
        })?;
        robustness.perturbations += 1;
        match PoseRobustnessClass::of(&visibility) {
            PoseRobustnessClass::Observable => robustness.observable += 1,
            PoseRobustnessClass::Occluded => robustness.occluded += 1,
            PoseRobustnessClass::OutsideFrustum => robustness.outside_frustum += 1,
            PoseRobustnessClass::PrivacyMasked => robustness.privacy_masked += 1,
        }
    }
    robustness
        .validate()
        .map_err(|_| VisibilityError::InvalidCovariance)?;
    Ok(robustness)
}

#[cfg(test)]
mod tests;
