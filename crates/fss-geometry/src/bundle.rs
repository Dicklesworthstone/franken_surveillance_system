//! Deterministic reference bundle adjustment for multi-view shuttle reconstruction.
//!
//! Jointly refines, by first-party Levenberg-Marquardt over a Schur-complement
//! normal equation, per-camera pinhole intrinsics (`fx`, `fy`, `cx`, `cy`),
//! optional typed two-term radial distortion (`k1`, `k2`), world-to-camera
//! extrinsics (rotation updated through a minimal three-parameter axis-angle
//! increment on SO(3), translation additively), and 3D landmark positions.
//!
//! Scope and non-claims:
//! - Landmarks are static and observations are treated as simultaneous. There is
//!   **no per-camera time offset** parameter: with static landmarks it is not
//!   observable, and moving-target synchronization is a separate, unbuilt solver.
//! - The gauge (7-DoF similarity ambiguity) is fixed explicitly by a typed
//!   [`BundleGaugeChoice`]. Either one reference camera's full pose is held at its
//!   supplied value and one caller-named world-to-camera translation component of
//!   a second camera is held at its supplied value (the scale anchor; metric scale
//!   is exactly as good as the anchor value), or at least three non-collinear
//!   surveyed control points ([`BundleControlPoint`]) are held fixed. Control
//!   points contribute residuals but no parameters; every camera pose is then
//!   free, no reference pose or scale anchor exists, and the result is expressed
//!   in the control points' (metric) frame, exactly as good as their survey.
//! - Covariance is the Gauss-Newton approximation `sigma^2 (J^T J)^-1` at the
//!   solution, restricted to free parameters. Rotation covariance lives in the
//!   left-perturbation tangent space `R' = exp([w]x) R`. It is a local
//!   linearization, not a calibrated posterior, and says nothing about gross
//!   outliers or model misspecification.
//! - Green synthetic fixtures do not establish accuracy on real camera footage.
//!
//! Results name the exact camera intrinsics/extrinsics generations they depend on;
//! a camera move, crop, or zoom must mint a new generation, which invalidates the
//! result through [`BundleAdjustment::validity`].

mod anchor;
mod dense;
mod solve;

use std::collections::BTreeMap;

use crate::{GeometryBasis, PinholeIntrinsics, RigidPose, WorkBudget};

/// Hard bound on cameras in one reference problem. Overflow fails without pruning.
pub const MAX_BUNDLE_CAMERAS: usize = 32;
/// Hard bound on landmarks in one reference problem.
pub const MAX_BUNDLE_LANDMARKS: usize = 4096;
/// Hard bound on observations in one reference problem.
pub const MAX_BUNDLE_OBSERVATIONS: usize = 65_536;
/// Number of parameters in a full camera block (pose 6, pinhole 4, radial 2).
pub const CAMERA_BLOCK_PARAMETERS: usize = 12;

/// Owner-resolved identity of the exact camera configuration a solve consumed.
///
/// A camera move must mint a new `extrinsics` generation; a crop, zoom, focus, or
/// lens change must mint a new `intrinsics` generation. All handles are nonzero.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CameraGeneration {
    /// Property-local camera handle.
    pub camera: u64,
    /// Immutable intrinsics generation (image mode, crop, zoom, lens).
    pub intrinsics: u64,
    /// Immutable extrinsics generation (mounting pose).
    pub extrinsics: u64,
}

/// Two-term Brown radial distortion on normalized coordinates:
/// `pixel = f * (1 + k1 r^2 + k2 r^4) * xn + c`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RadialDistortion {
    /// Second-order radial coefficient.
    pub k1: f64,
    /// Fourth-order radial coefficient.
    pub k2: f64,
}
impl RadialDistortion {
    /// The explicitly undistorted model.
    pub const NONE: Self = Self { k1: 0.0, k2: 0.0 };
}

/// How a camera's focal length enters the unknowns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FocalRefinement {
    /// `fx` and `fy` held at their supplied values.
    Fixed,
    /// One focal unknown `f = fx`; `fy = f * aspect`, with the supplied aspect held.
    AspectHeld,
    /// `fx` and `fy` are independent unknowns.
    Independent,
}

/// Which intrinsic parameters a camera contributes as free unknowns.
///
/// Observability warning: with zero skew as the only intrinsic prior, free
/// `fx`/`fy`/`cx`/`cy` in every camera leave the projective-to-metric
/// (self-calibration) ambiguity unresolved for small camera counts. The solver
/// does not hide this: it refuses with [`SingularStage::CameraCovariance`]. Hold
/// the aspect ratio, pre-calibrate a camera, or add distortion evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntrinsicsRefinement {
    /// Focal-length unknowns.
    pub focal: FocalRefinement,
    /// Whether `cx`, `cy` are unknowns.
    pub principal_point: bool,
    /// Whether radial `k1`, `k2` are unknowns.
    pub radial: bool,
}
impl IntrinsicsRefinement {
    /// Intrinsics and distortion held at their supplied values (pre-calibrated).
    pub const FIXED: Self = Self {
        focal: FocalRefinement::Fixed,
        principal_point: false,
        radial: false,
    };
    /// Common bundle-adjustment default: one focal unknown (aspect held) plus principal point.
    pub const FOCAL_AND_PRINCIPAL_POINT: Self = Self {
        focal: FocalRefinement::AspectHeld,
        principal_point: true,
        radial: false,
    };
    /// Independent `fx`, `fy`, principal point, and radial `k1`, `k2`.
    pub const FULL: Self = Self {
        focal: FocalRefinement::Independent,
        principal_point: true,
        radial: true,
    };
}

/// One camera's identity and initial guess.
#[derive(Clone, Copy, Debug)]
pub struct BundleCamera {
    /// Exact generation identity this initial guess belongs to.
    pub identity: CameraGeneration,
    /// Initial intrinsics; image dimensions are fixed and bound observations.
    pub intrinsics: PinholeIntrinsics,
    /// Initial radial distortion (use [`RadialDistortion::NONE`] for pinhole).
    pub distortion: RadialDistortion,
    /// Initial world-to-camera pose.
    pub pose: RigidPose,
    /// Free intrinsic parameters.
    pub refinement: IntrinsicsRefinement,
}

/// One landmark's initial position in the basis world frame.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BundleLandmark {
    /// Nonzero landmark handle.
    pub landmark: u64,
    /// Initial world position.
    pub position: [f64; 3],
}

/// One raw (distorted when distortion is declared) pixel observation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BundleObservation {
    /// Observing camera handle.
    pub camera: u64,
    /// Observed landmark handle.
    pub landmark: u64,
    /// Pixel-edge coordinates inside the camera's declared image.
    pub pixel: [f64; 2],
}

/// Explicit gauge: a fixed reference pose plus one fixed translation component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundleGauge {
    /// Camera whose full pose is held at its supplied value.
    pub reference_camera: u64,
    /// Different camera whose world-to-camera translation component is held.
    pub scale_camera: u64,
    /// Which component (0, 1, 2) of `scale_camera`'s translation is held.
    pub scale_axis: usize,
}

/// A surveyed landmark held at its supplied position: it contributes reprojection
/// residuals from every observing camera but no parameters. Its handle shares the
/// landmark handle space and must not collide with a free [`BundleLandmark`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BundleControlPoint {
    /// Nonzero landmark handle.
    pub landmark: u64,
    /// Fixed (surveyed) world position; not refined and not covariance-bearing.
    pub position: [f64; 3],
}

/// Minimum observed, non-collinear control points for the control-point gauge.
pub const MIN_CONTROL_POINTS: usize = 3;
/// Control points are collinear when the largest distance of any of them from the
/// line through the first point and the point farthest from it is below this
/// fraction of that farthest distance.
pub const CONTROL_COLLINEARITY_RATIO: f64 = 1e-3;

/// How the 7-DoF similarity gauge is fixed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleGaugeChoice {
    /// A held reference pose plus a held scale-anchor translation component. No
    /// control points are admitted with this gauge (they would over-fix it).
    ReferencePose(BundleGauge),
    /// Observed, non-collinear [`BundleControlPoint`]s fix rotation, translation, and
    /// scale; every camera pose is free and nothing is fabricated as a reference.
    ControlPoints,
}

/// Complete bundle-adjustment input.
#[derive(Clone, Debug)]
pub struct BundleProblem {
    /// Property and immutable twin revision the world frame belongs to.
    pub basis: GeometryBasis,
    /// Cameras (order is irrelevant; they are canonicalized by handle).
    pub cameras: Vec<BundleCamera>,
    /// Landmarks (canonicalized by handle).
    pub landmarks: Vec<BundleLandmark>,
    /// Observations (canonicalized by landmark, then camera).
    pub observations: Vec<BundleObservation>,
    /// Explicit gauge fixing.
    pub gauge: BundleGauge,
}

/// Bundle-adjustment input with an explicit gauge choice and optional fixed
/// control points. [`BundleProblem`] is the reference-pose special case with no
/// control points; both run through the same canonicalization and solver.
#[derive(Clone, Debug)]
pub struct AnchoredBundleProblem {
    /// Property and immutable twin revision the world frame belongs to.
    pub basis: GeometryBasis,
    /// Cameras (order is irrelevant; they are canonicalized by handle).
    pub cameras: Vec<BundleCamera>,
    /// Free landmarks (canonicalized by handle); each needs two or more views.
    pub landmarks: Vec<BundleLandmark>,
    /// Fixed control points (canonicalized by handle); may be seen by one camera.
    pub control_points: Vec<BundleControlPoint>,
    /// Observations of free landmarks or control points (resolved by handle).
    pub observations: Vec<BundleObservation>,
    /// Explicit gauge fixing.
    pub gauge: BundleGaugeChoice,
}

/// Levenberg-Marquardt controls. Every bound is explicit and reported.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BundleOptions {
    /// Linear-solve attempts (accepted plus rejected); 1..=10_000.
    pub max_iterations: usize,
    /// Initial Marquardt damping, relative to the normal-matrix diagonal; (0, 1e6].
    pub initial_damping: f64,
    /// Stop when an accepted step lowers the cost by at most this fraction; (0, 1).
    pub cost_tolerance: f64,
    /// Stop when the step norm is at most this times the parameter norm; (0, 1).
    pub step_tolerance: f64,
    /// Stop when every Jacobi-scaled gradient component is at most this (pixels).
    pub gradient_tolerance_px: f64,
    /// A-priori observation sigma in pixels; `None` estimates it from residuals.
    pub observation_sigma_px: Option<f64>,
}
impl Default for BundleOptions {
    fn default() -> Self {
        Self {
            max_iterations: 200,
            initial_damping: 1e-3,
            cost_tolerance: 1e-12,
            step_tolerance: 1e-12,
            gradient_tolerance_px: 1e-10,
            observation_sigma_px: None,
        }
    }
}
impl BundleOptions {
    fn validate(self) -> Result<(), BundleAdjustmentError> {
        let unit = |x: f64| x.is_finite() && x > 0.0 && x < 1.0;
        if [
            self.initial_damping,
            self.cost_tolerance,
            self.step_tolerance,
            self.gradient_tolerance_px,
        ]
        .iter()
        .any(|x| !x.is_finite())
            || self.observation_sigma_px.is_some_and(|x| !x.is_finite())
        {
            return Err(BundleAdjustmentError::NonFiniteInput(
                NonFiniteInput::Options,
            ));
        }
        if !(1..=10_000).contains(&self.max_iterations)
            || !(self.initial_damping > 0.0 && self.initial_damping <= 1e6)
            || !unit(self.cost_tolerance)
            || !unit(self.step_tolerance)
            || !(self.gradient_tolerance_px > 0.0 && self.gradient_tolerance_px < 1.0)
            || self
                .observation_sigma_px
                .is_some_and(|x| !(x > 0.0 && x <= 1e4))
        {
            return Err(BundleAdjustmentError::InvalidInput(
                BundleInputError::InvalidOptions,
            ));
        }
        Ok(())
    }
}

/// Where a non-finite input value was found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonFiniteInput {
    /// A solver option.
    Options,
    /// A camera's distortion coefficient.
    Distortion {
        /// Camera handle.
        camera: u64,
    },
    /// A landmark's initial position.
    Landmark {
        /// Landmark handle.
        landmark: u64,
    },
    /// A control point's fixed position.
    ControlPoint {
        /// Control-point handle.
        landmark: u64,
    },
    /// An observed pixel.
    Observation {
        /// Camera handle.
        camera: u64,
        /// Landmark handle.
        landmark: u64,
    },
}

/// Structurally invalid (not merely weak) input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleInputError {
    /// Options outside their admitted ranges.
    InvalidOptions,
    /// A `MAX_BUNDLE_*` bound was exceeded.
    LimitExceeded,
    /// A camera, generation, or landmark handle is zero.
    ZeroHandle,
    /// Two cameras share a handle.
    DuplicateCamera(u64),
    /// Two landmarks share a handle.
    DuplicateLandmark(u64),
    /// The same camera observes the same landmark twice.
    DuplicateObservation {
        /// Camera handle.
        camera: u64,
        /// Landmark handle.
        landmark: u64,
    },
    /// An observation names an unknown camera.
    UnknownCamera(u64),
    /// An observation names an unknown landmark.
    UnknownLandmark(u64),
    /// The gauge names an unknown camera, reuses the reference, or an axis > 2, or
    /// control points were supplied with the reference-pose gauge.
    InvalidGauge,
    /// A landmark coordinate or distortion magnitude is outside admitted range.
    OutOfRange,
    /// An observation lies outside its camera's declared image.
    ObservationOutsideImage {
        /// Camera handle.
        camera: u64,
        /// Landmark handle.
        landmark: u64,
    },
    /// An initial landmark is at or behind an observing camera.
    BehindCamera {
        /// Camera handle.
        camera: u64,
        /// Landmark handle.
        landmark: u64,
    },
}

/// Why the problem cannot determine a unique solution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnderConstrainedReason {
    /// Fewer than two cameras: depth and scale are unobservable.
    TooFewCameras {
        /// Supplied cameras.
        cameras: usize,
    },
    /// A landmark is seen by fewer than two cameras and cannot be triangulated.
    LandmarkUnderObserved {
        /// Landmark handle.
        landmark: u64,
        /// Observing cameras.
        cameras: usize,
    },
    /// A camera has no more residuals than its free parameters.
    CameraUnderObserved {
        /// Camera handle.
        camera: u64,
        /// Observations of that camera.
        observations: usize,
        /// Its free parameters.
        parameters: usize,
    },
    /// Total residuals do not exceed total free parameters.
    TooFewResiduals {
        /// Scalar residuals (two per observation).
        residuals: usize,
        /// Free parameters.
        parameters: usize,
    },
    /// A camera shares no landmark path with the reference camera; its gauge is free.
    DisconnectedCamera {
        /// Camera handle.
        camera: u64,
    },
    /// The scale anchor component is (near) zero, so it does not fix scale.
    DegenerateScaleAnchor,
    /// Control-point gauge: fewer than [`MIN_CONTROL_POINTS`] control points are observed.
    TooFewControlPoints {
        /// Distinct observed control points.
        observed: usize,
    },
    /// Control-point gauge: every observed control point lies on one line, leaving
    /// rotation about that line (and hence the gauge) free.
    CollinearControlPoints,
    /// Control-point gauge: this camera's component (cameras linked through shared
    /// free landmarks) does not observe three non-collinear control points, so its
    /// similarity gauge is free.
    UnanchoredCamera {
        /// Smallest camera handle of the unanchored component.
        camera: u64,
    },
}

/// Which solve met a numerically singular system.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SingularStage {
    /// Even maximal damping could not produce a positive-definite step system.
    DampedStep,
    /// The undamped normal matrix at the solution is rank deficient in a camera block.
    CameraCovariance,
    /// The undamped normal matrix is rank deficient for this landmark.
    LandmarkCovariance {
        /// Landmark handle.
        landmark: u64,
    },
}

/// Which explicit budget ran out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetKind {
    /// `BundleOptions::max_iterations` was reached before convergence.
    Iterations,
    /// The caller's [`WorkBudget`] refused a charge.
    WorkUnits,
}

/// Why the solver declared convergence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Convergence {
    /// Every Jacobi-scaled gradient component is below tolerance.
    Gradient,
    /// An accepted step lowered the cost by at most the relative tolerance.
    CostStalled,
    /// The proposed step is negligible relative to the parameters.
    StepTolerance,
    /// The residual RMS is at floating-point zero (exact synthetic data).
    ZeroResidual,
}

/// Explicit accounting of one solve; returned on success and on budget failure.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BundleReport {
    /// Configured iteration cap.
    pub max_iterations: usize,
    /// Linear-solve attempts made.
    pub iterations: usize,
    /// Accepted LM steps.
    pub accepted_steps: usize,
    /// Rejected LM steps.
    pub rejected_steps: usize,
    /// Work units charged to the caller's budget by this solve.
    pub work_units: u64,
    /// Work units still available in the caller's budget.
    pub work_units_remaining: u64,
    /// RMS reprojection error (pixels) of the initial guess.
    pub initial_rms_px: f64,
    /// RMS reprojection error (pixels) of the last accepted state.
    pub final_rms_px: f64,
    /// Scalar residuals (two per observation).
    pub residual_count: usize,
    /// Free parameters after gauge fixing.
    pub parameter_count: usize,
    /// Final relative Marquardt damping.
    pub final_damping: f64,
    /// Convergence reason, or `None` if the solve stopped without converging.
    pub convergence: Option<Convergence>,
}

/// Typed refusal. No variant carries adjusted parameters.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BundleAdjustmentError {
    /// An input value is NaN or infinite.
    NonFiniteInput(NonFiniteInput),
    /// Input is structurally invalid.
    InvalidInput(BundleInputError),
    /// Input cannot determine a unique, gauge-fixed solution.
    UnderConstrained(UnderConstrainedReason),
    /// A normal system is numerically singular.
    Singular(SingularStage),
    /// An explicit budget ran out before convergence.
    BudgetExhausted {
        /// Which budget.
        kind: BudgetKind,
        /// Accounting up to the stop.
        report: BundleReport,
    },
    /// Damping saturated with no cost-reducing step and no convergence criterion met.
    Stalled(BundleReport),
    /// The caller's cancellation flag was observed.
    Cancelled,
    /// Iterates became non-finite or left the admitted camera model.
    NumericalBreakdown,
}
impl std::fmt::Display for BundleAdjustmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonFiniteInput(at) => write!(f, "non-finite bundle input at {at:?}"),
            Self::InvalidInput(error) => write!(f, "invalid bundle input: {error:?}"),
            Self::UnderConstrained(reason) => write!(f, "under-constrained bundle: {reason:?}"),
            Self::Singular(stage) => write!(f, "singular bundle system at {stage:?}"),
            Self::BudgetExhausted { kind, report } => write!(
                f,
                "bundle budget {kind:?} exhausted after {} iterations (rms {} px)",
                report.iterations, report.final_rms_px
            ),
            Self::Stalled(report) => write!(
                f,
                "bundle damping saturated after {} iterations without convergence",
                report.iterations
            ),
            Self::Cancelled => f.write_str("bundle adjustment cancelled"),
            Self::NumericalBreakdown => f.write_str("bundle iterates became non-finite"),
        }
    }
}
impl std::error::Error for BundleAdjustmentError {}

/// Named scalar parameter of a camera block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleParameter {
    /// Left-perturbation rotation about world-to-camera X, Y, Z (radians).
    Rotation(usize),
    /// World-to-camera translation component (world units).
    Translation(usize),
    /// Aspect-held focal length `fx` (pixels); `fy` follows at the held aspect.
    Focal,
    /// Focal length in x (pixels).
    Fx,
    /// Focal length in y (pixels).
    Fy,
    /// Principal point x (pixels).
    Cx,
    /// Principal point y (pixels).
    Cy,
    /// Radial `k1`.
    K1,
    /// Radial `k2`.
    K2,
}
impl BundleParameter {
    pub(crate) fn from_slot(slot: usize, aspect_held: bool) -> Self {
        match slot {
            6 if aspect_held => Self::Focal,
            0..=2 => Self::Rotation(slot),
            3..=5 => Self::Translation(slot - 3),
            6 => Self::Fx,
            7 => Self::Fy,
            8 => Self::Cx,
            9 => Self::Cy,
            10 => Self::K1,
            _ => Self::K2,
        }
    }
}

/// Covariance of one camera's free parameters (row-major, gauge-fixed ones absent).
#[derive(Clone, Debug, PartialEq)]
pub struct CameraCovariance {
    /// Free parameters, in block order.
    pub parameters: Vec<BundleParameter>,
    /// Row-major `k x k` covariance, `k = parameters.len()`.
    pub matrix: Vec<f64>,
    /// Parameters held fixed by the gauge or the refinement choice.
    pub fixed: Vec<BundleParameter>,
}
impl CameraCovariance {
    /// Marginal variance of one free parameter, if it is free.
    pub fn variance(&self, parameter: BundleParameter) -> Option<f64> {
        let k = self.parameters.len();
        self.parameters
            .iter()
            .position(|p| *p == parameter)
            .map(|i| self.matrix[i * k + i])
    }
}

/// One adjusted camera with its covariance.
#[derive(Clone, Debug)]
pub struct AdjustedCamera {
    /// Generation this estimate depends on.
    pub identity: CameraGeneration,
    /// Adjusted intrinsics.
    pub intrinsics: PinholeIntrinsics,
    /// Adjusted (or held) distortion.
    pub distortion: RadialDistortion,
    /// Adjusted world-to-camera pose.
    pub pose: RigidPose,
    /// Covariance over free parameters.
    pub covariance: CameraCovariance,
}

/// One adjusted landmark with its 3x3 marginal covariance.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AdjustedLandmark {
    /// Landmark handle.
    pub landmark: u64,
    /// Adjusted world position.
    pub position: [f64; 3],
    /// Marginal position covariance (world units squared).
    pub covariance: [[f64; 3]; 3],
}

/// Why a result no longer applies to one camera.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidationCause {
    /// Intrinsics generation changed (crop, zoom, lens).
    IntrinsicsChanged,
    /// Extrinsics generation changed (camera moved).
    ExtrinsicsChanged,
    /// Both generations changed.
    IntrinsicsAndExtrinsicsChanged,
    /// The camera is absent from the current configuration.
    CameraMissing,
}

/// Invalidation of one dependency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CameraInvalidation {
    /// Camera handle.
    pub camera: u64,
    /// Cause.
    pub cause: InvalidationCause,
}

/// Validity of a result against the current camera configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundleValidity {
    /// Every dependency generation is unchanged.
    Current,
    /// At least one dependency changed; the result must not be used.
    Invalidated(Vec<CameraInvalidation>),
}

/// A converged, gauge-fixed bundle adjustment. Only constructed on convergence.
#[derive(Clone, Debug)]
pub struct BundleAdjustment {
    pub(crate) basis: GeometryBasis,
    pub(crate) gauge: BundleGaugeChoice,
    pub(crate) control_points: Vec<BundleControlPoint>,
    pub(crate) cameras: Vec<AdjustedCamera>,
    pub(crate) landmarks: Vec<AdjustedLandmark>,
    pub(crate) report: BundleReport,
    pub(crate) sigma_px: f64,
    pub(crate) sigma_estimated: bool,
}
impl BundleAdjustment {
    /// Geometry basis of the world frame.
    pub fn basis(&self) -> GeometryBasis {
        self.basis
    }
    /// Gauge the result is expressed in.
    pub fn gauge(&self) -> BundleGaugeChoice {
        self.gauge
    }
    /// Fixed control points the result was anchored to, sorted by handle (empty for
    /// the reference-pose gauge). They are inputs, never adjusted.
    pub fn control_points(&self) -> &[BundleControlPoint] {
        &self.control_points
    }
    /// Adjusted cameras sorted by handle.
    pub fn cameras(&self) -> &[AdjustedCamera] {
        &self.cameras
    }
    /// Adjusted camera by handle.
    pub fn camera(&self, camera: u64) -> Option<&AdjustedCamera> {
        self.cameras
            .binary_search_by_key(&camera, |c| c.identity.camera)
            .ok()
            .map(|i| &self.cameras[i])
    }
    /// Adjusted landmarks sorted by handle.
    pub fn landmarks(&self) -> &[AdjustedLandmark] {
        &self.landmarks
    }
    /// Adjusted landmark by handle.
    pub fn landmark(&self, landmark: u64) -> Option<&AdjustedLandmark> {
        self.landmarks
            .binary_search_by_key(&landmark, |l| l.landmark)
            .ok()
            .map(|i| &self.landmarks[i])
    }
    /// Solve accounting and convergence reason.
    pub fn report(&self) -> BundleReport {
        self.report
    }
    /// Observation sigma used to scale covariance, and whether it was estimated.
    pub fn observation_sigma_px(&self) -> (f64, bool) {
        (self.sigma_px, self.sigma_estimated)
    }
    /// Exact camera generations this result depends on, sorted by camera.
    pub fn dependencies(&self) -> Vec<CameraGeneration> {
        self.cameras.iter().map(|c| c.identity).collect()
    }
    /// Check the result against the current camera configuration.
    pub fn validity(&self, current: &[CameraGeneration]) -> BundleValidity {
        let mut invalidations = Vec::new();
        for camera in &self.cameras {
            let dependency = camera.identity;
            let cause = match current.iter().find(|c| c.camera == dependency.camera) {
                None => Some(InvalidationCause::CameraMissing),
                Some(now) => match (
                    now.intrinsics != dependency.intrinsics,
                    now.extrinsics != dependency.extrinsics,
                ) {
                    (false, false) => None,
                    (true, false) => Some(InvalidationCause::IntrinsicsChanged),
                    (false, true) => Some(InvalidationCause::ExtrinsicsChanged),
                    (true, true) => Some(InvalidationCause::IntrinsicsAndExtrinsicsChanged),
                },
            };
            if let Some(cause) = cause {
                invalidations.push(CameraInvalidation {
                    camera: dependency.camera,
                    cause,
                });
            }
        }
        if invalidations.is_empty() {
            BundleValidity::Current
        } else {
            BundleValidity::Invalidated(invalidations)
        }
    }
    /// Whether any dependency generation changed or disappeared.
    pub fn is_invalidated_by(&self, current: &[CameraGeneration]) -> bool {
        self.validity(current) != BundleValidity::Current
    }
}

/// Canonicalized, validated problem shared with the solver.
pub(crate) struct Canonical {
    pub cameras: Vec<BundleCamera>,
    pub landmarks: Vec<BundleLandmark>,
    /// `(landmark index, camera index, pixel)`, sorted by landmark then camera.
    pub observations: Vec<(usize, usize, [f64; 2])>,
    /// Fixed control points sorted by handle.
    pub control_points: Vec<BundleControlPoint>,
    /// `(control index, camera index, pixel)`, sorted by control point then camera.
    pub control_observations: Vec<(usize, usize, [f64; 2])>,
    /// Per camera: which of the 12 block slots are free.
    pub free: Vec<[bool; CAMERA_BLOCK_PARAMETERS]>,
}

fn free_slots(
    camera: &BundleCamera,
    is_reference: bool,
    scale_axis: Option<usize>,
) -> [bool; CAMERA_BLOCK_PARAMETERS] {
    let mut free = [false; CAMERA_BLOCK_PARAMETERS];
    if !is_reference {
        free[..6].fill(true);
        if let Some(axis) = scale_axis {
            free[3 + axis] = false;
        }
    }
    let refinement = camera.refinement;
    match refinement.focal {
        FocalRefinement::Fixed => {}
        FocalRefinement::AspectHeld => free[6] = true,
        FocalRefinement::Independent => free[6..8].fill(true),
    }
    if refinement.principal_point {
        free[8..10].fill(true);
    }
    if refinement.radial {
        free[10..12].fill(true);
    }
    free
}

/// Borrowed problem shared by both public entry points.
struct ProblemView<'a> {
    cameras: &'a [BundleCamera],
    landmarks: &'a [BundleLandmark],
    control_points: &'a [BundleControlPoint],
    observations: &'a [BundleObservation],
    gauge: BundleGaugeChoice,
}

fn canonicalize(problem: &ProblemView<'_>) -> Result<Canonical, BundleAdjustmentError> {
    use BundleAdjustmentError::{InvalidInput, NonFiniteInput as NonFinite, UnderConstrained};
    // Non-finite inputs are reported before any other defect.
    for camera in problem.cameras {
        let d = camera.distortion;
        if !d.k1.is_finite() || !d.k2.is_finite() {
            return Err(NonFinite(NonFiniteInput::Distortion {
                camera: camera.identity.camera,
            }));
        }
    }
    for landmark in problem.landmarks {
        if landmark.position.iter().any(|x| !x.is_finite()) {
            return Err(NonFinite(NonFiniteInput::Landmark {
                landmark: landmark.landmark,
            }));
        }
    }
    for control in problem.control_points {
        if control.position.iter().any(|x| !x.is_finite()) {
            return Err(NonFinite(NonFiniteInput::ControlPoint {
                landmark: control.landmark,
            }));
        }
    }
    for o in problem.observations {
        if o.pixel.iter().any(|x| !x.is_finite()) {
            return Err(NonFinite(NonFiniteInput::Observation {
                camera: o.camera,
                landmark: o.landmark,
            }));
        }
    }
    if problem.cameras.len() > MAX_BUNDLE_CAMERAS
        || problem.landmarks.len() + problem.control_points.len() > MAX_BUNDLE_LANDMARKS
        || problem.observations.len() > MAX_BUNDLE_OBSERVATIONS
    {
        return Err(InvalidInput(BundleInputError::LimitExceeded));
    }
    let mut cameras = problem.cameras.to_vec();
    cameras.sort_by_key(|c| c.identity.camera);
    for (i, camera) in cameras.iter().enumerate() {
        let id = camera.identity;
        if id.camera == 0 || id.intrinsics == 0 || id.extrinsics == 0 {
            return Err(InvalidInput(BundleInputError::ZeroHandle));
        }
        if i > 0 && cameras[i - 1].identity.camera == id.camera {
            return Err(InvalidInput(BundleInputError::DuplicateCamera(id.camera)));
        }
        if camera.distortion.k1.abs() > 1e3 || camera.distortion.k2.abs() > 1e3 {
            return Err(InvalidInput(BundleInputError::OutOfRange));
        }
    }
    let mut landmarks = problem.landmarks.to_vec();
    landmarks.sort_by_key(|l| l.landmark);
    for (i, landmark) in landmarks.iter().enumerate() {
        if landmark.landmark == 0 {
            return Err(InvalidInput(BundleInputError::ZeroHandle));
        }
        if i > 0 && landmarks[i - 1].landmark == landmark.landmark {
            return Err(InvalidInput(BundleInputError::DuplicateLandmark(
                landmark.landmark,
            )));
        }
        if landmark.position.iter().any(|x| x.abs() > 1e9) {
            return Err(InvalidInput(BundleInputError::OutOfRange));
        }
    }
    let mut control_points = problem.control_points.to_vec();
    control_points.sort_by_key(|c| c.landmark);
    for (i, control) in control_points.iter().enumerate() {
        if control.landmark == 0 {
            return Err(InvalidInput(BundleInputError::ZeroHandle));
        }
        if (i > 0 && control_points[i - 1].landmark == control.landmark)
            || landmarks
                .binary_search_by_key(&control.landmark, |l| l.landmark)
                .is_ok()
        {
            return Err(InvalidInput(BundleInputError::DuplicateLandmark(
                control.landmark,
            )));
        }
        if control.position.iter().any(|x| x.abs() > 1e9) {
            return Err(InvalidInput(BundleInputError::OutOfRange));
        }
    }
    let camera_index: BTreeMap<u64, usize> = cameras
        .iter()
        .enumerate()
        .map(|(i, c)| (c.identity.camera, i))
        .collect();
    let landmark_index: BTreeMap<u64, usize> = landmarks
        .iter()
        .enumerate()
        .map(|(i, l)| (l.landmark, i))
        .collect();
    let control_index: BTreeMap<u64, usize> = control_points
        .iter()
        .enumerate()
        .map(|(i, l)| (l.landmark, i))
        .collect();
    let mut observations = Vec::with_capacity(problem.observations.len());
    let mut control_observations = Vec::new();
    for o in problem.observations {
        let &c = camera_index
            .get(&o.camera)
            .ok_or(InvalidInput(BundleInputError::UnknownCamera(o.camera)))?;
        let target = match (
            landmark_index.get(&o.landmark),
            control_index.get(&o.landmark),
        ) {
            (Some(&l), _) => Target::Free(l),
            (None, Some(&k)) => Target::Control(k),
            (None, None) => {
                return Err(InvalidInput(BundleInputError::UnknownLandmark(o.landmark)));
            }
        };
        if !cameras[c].intrinsics.contains(o.pixel) {
            return Err(InvalidInput(BundleInputError::ObservationOutsideImage {
                camera: o.camera,
                landmark: o.landmark,
            }));
        }
        match target {
            Target::Free(l) => observations.push((l, c, o.pixel)),
            Target::Control(k) => control_observations.push((k, c, o.pixel)),
        }
    }
    observations.sort_by_key(|&(l, c, _)| (l, c));
    for pair in observations.windows(2) {
        if pair[0].0 == pair[1].0 && pair[0].1 == pair[1].1 {
            return Err(InvalidInput(BundleInputError::DuplicateObservation {
                camera: cameras[pair[0].1].identity.camera,
                landmark: landmarks[pair[0].0].landmark,
            }));
        }
    }
    control_observations.sort_by_key(|&(k, c, _)| (k, c));
    for pair in control_observations.windows(2) {
        if pair[0].0 == pair[1].0 && pair[0].1 == pair[1].1 {
            return Err(InvalidInput(BundleInputError::DuplicateObservation {
                camera: cameras[pair[0].1].identity.camera,
                landmark: control_points[pair[0].0].landmark,
            }));
        }
    }

    // Structural observability, before any gauge validation.
    let reference_gauge = match problem.gauge {
        BundleGaugeChoice::ReferencePose(gauge) => {
            if cameras.len() < 2 {
                return Err(UnderConstrained(UnderConstrainedReason::TooFewCameras {
                    cameras: cameras.len(),
                }));
            }
            let reference = camera_index.get(&gauge.reference_camera).copied();
            let scale = camera_index.get(&gauge.scale_camera).copied();
            let (Some(reference), Some(scale)) = (reference, scale) else {
                return Err(InvalidInput(BundleInputError::InvalidGauge));
            };
            if reference == scale || gauge.scale_axis > 2 || !control_points.is_empty() {
                return Err(InvalidInput(BundleInputError::InvalidGauge));
            }
            Some((reference, scale, gauge.scale_axis))
        }
        BundleGaugeChoice::ControlPoints => {
            if cameras.is_empty() {
                return Err(UnderConstrained(UnderConstrainedReason::TooFewCameras {
                    cameras: 0,
                }));
            }
            None
        }
    };
    let mut landmark_views = vec![0_usize; landmarks.len()];
    let mut camera_views = vec![0_usize; cameras.len()];
    for &(l, c, _) in &observations {
        landmark_views[l] += 1;
        camera_views[c] += 1;
    }
    for &(_, c, _) in &control_observations {
        camera_views[c] += 1;
    }
    for (landmark, &views) in landmarks.iter().zip(&landmark_views) {
        if views < 2 {
            return Err(UnderConstrained(
                UnderConstrainedReason::LandmarkUnderObserved {
                    landmark: landmark.landmark,
                    cameras: views,
                },
            ));
        }
    }
    let free: Vec<_> = cameras
        .iter()
        .enumerate()
        .map(|(i, camera)| match reference_gauge {
            Some((reference, scale, axis)) => {
                free_slots(camera, i == reference, (i == scale).then_some(axis))
            }
            None => free_slots(camera, false, None),
        })
        .collect();
    let mut parameters = 3 * landmarks.len();
    for ((camera, slots), &views) in cameras.iter().zip(&free).zip(&camera_views) {
        let count = slots.iter().filter(|x| **x).count();
        parameters += count;
        if 2 * views <= count || views == 0 {
            return Err(UnderConstrained(
                UnderConstrainedReason::CameraUnderObserved {
                    camera: camera.identity.camera,
                    observations: views,
                    parameters: count,
                },
            ));
        }
    }
    let residuals = 2 * (observations.len() + control_observations.len());
    if residuals <= parameters {
        return Err(UnderConstrained(UnderConstrainedReason::TooFewResiduals {
            residuals,
            parameters,
        }));
    }
    match reference_gauge {
        Some((reference, scale, axis)) => {
            if let Some(i) = anchor::unreached_camera(cameras.len(), &observations, reference) {
                return Err(UnderConstrained(
                    UnderConstrainedReason::DisconnectedCamera {
                        camera: cameras[i].identity.camera,
                    },
                ));
            }
            // Scale anchor: scaling about the reference center changes t_s[axis] by
            // (R_s (c_ref - c_s))[axis]; that component must be materially nonzero.
            let reference_center = cameras[reference].pose.center();
            let scale_pose = cameras[scale].pose;
            let baseline = crate::math::sub(reference_center, scale_pose.center());
            let lever = crate::math::mv(scale_pose.rotation(), baseline);
            let length = crate::math::norm(baseline);
            if length <= 1e-9 || lever[axis].abs() < 0.05 * length {
                return Err(UnderConstrained(
                    UnderConstrainedReason::DegenerateScaleAnchor,
                ));
            }
        }
        None => anchor::check_control_anchoring(
            &cameras,
            &control_points,
            &observations,
            &control_observations,
        )
        .map_err(UnderConstrained)?,
    }
    for &(l, c, _) in &observations {
        behind_check(&cameras[c], landmarks[l].landmark, landmarks[l].position)?;
    }
    for &(k, c, _) in &control_observations {
        behind_check(
            &cameras[c],
            control_points[k].landmark,
            control_points[k].position,
        )?;
    }
    Ok(Canonical {
        cameras,
        landmarks,
        observations,
        control_points,
        control_observations,
        free,
    })
}

/// Which landmark set an observation resolved into.
enum Target {
    Free(usize),
    Control(usize),
}

fn behind_check(
    camera: &BundleCamera,
    landmark: u64,
    position: [f64; 3],
) -> Result<(), BundleAdjustmentError> {
    let point = camera
        .pose
        .transform(position)
        .map_err(|_| BundleAdjustmentError::InvalidInput(BundleInputError::OutOfRange))?;
    if point[2] <= 1e-9 {
        return Err(BundleAdjustmentError::InvalidInput(
            BundleInputError::BehindCamera {
                camera: camera.identity.camera,
                landmark,
            },
        ));
    }
    Ok(())
}

/// Run deterministic reference bundle adjustment in the reference-pose gauge.
///
/// Returns a result only when a convergence criterion is met and the undamped
/// normal matrix at the solution is nonsingular; every other outcome is a typed
/// [`BundleAdjustmentError`]. The same input on the same platform produces
/// bit-identical output: all accumulations run in canonical handle order.
pub fn bundle_adjust(
    problem: &BundleProblem,
    options: BundleOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<BundleAdjustment, BundleAdjustmentError> {
    options.validate()?;
    let gauge = BundleGaugeChoice::ReferencePose(problem.gauge);
    let canonical = canonicalize(&ProblemView {
        cameras: &problem.cameras,
        landmarks: &problem.landmarks,
        control_points: &[],
        observations: &problem.observations,
        gauge,
    })?;
    solve::run(problem.basis, gauge, canonical, options, budget)
}

/// Run deterministic reference bundle adjustment with an explicit gauge choice.
///
/// With [`BundleGaugeChoice::ControlPoints`], at least [`MIN_CONTROL_POINTS`]
/// observed non-collinear control points must anchor every camera component;
/// otherwise the solve is refused with a typed [`UnderConstrainedReason`] rather
/// than fabricating a reference pose or scale anchor. Same success, failure, and
/// determinism contract as [`bundle_adjust`].
pub fn bundle_adjust_anchored(
    problem: &AnchoredBundleProblem,
    options: BundleOptions,
    budget: &mut WorkBudget<'_>,
) -> Result<BundleAdjustment, BundleAdjustmentError> {
    options.validate()?;
    let canonical = canonicalize(&ProblemView {
        cameras: &problem.cameras,
        landmarks: &problem.landmarks,
        control_points: &problem.control_points,
        observations: &problem.observations,
        gauge: problem.gauge,
    })?;
    solve::run(problem.basis, problem.gauge, canonical, options, budget)
}

/// Whether these control-point positions span more than a line under the exact
/// criterion the control-point gauge applies ([`CONTROL_COLLINEARITY_RATIO`]).
/// Callers that pre-screen control sets reuse this rather than a private variant.
pub fn control_points_span_plane(points: &[[f64; 3]]) -> bool {
    anchor::spans_plane(points)
}
