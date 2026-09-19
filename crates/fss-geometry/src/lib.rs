#![forbid(unsafe_code)]
//! Bounded, synchronous reference geometry for imported property twins.
//!
//! Inputs are already evaluated in one owner-resolved property frame. This crate
//! performs no file, device, model, or network I/O. It neither reads `.blend`
//! files nor certifies that supplied geometry is physically correct. Cameras use
//! explicitly undistorted pinhole pixel-edge coordinates, with pixel centers at
//! `(column + 0.5, row + 0.5)`. Distorted or dewarped images need a separately
//! qualified conversion before entering this interface.

mod camera;
mod handoff;
mod handoff_scenarios;
mod linear;
mod math;
mod mesh;
mod motion;
mod refine;
mod registration;

use std::sync::atomic::{AtomicBool, Ordering};

pub use camera::{PinholeIntrinsics, Ray, RigidPose};
pub use handoff::{
    BodySamples, CameraAvailability, CameraHandoffForecast, CaptureSchedule, HandoffCamera,
    HandoffCameraScope, HandoffOptions, ImageRect, MAX_BODY_SAMPLES, MAX_HANDOFF_CAMERAS,
    NanosecondInterval, NextCameraOutcome, PredictedObservation, RouteBody, RouteHandoff,
    predict_camera_handoffs,
};
pub use handoff_scenarios::{
    HandoffScenario, MAX_HANDOFF_SCENARIOS, ScenarioCameraEnvelope, ScenarioHandoffForecast,
    ScenarioRouteEnvelope, predict_camera_handoff_scenarios,
};
pub use mesh::{GeometryBasis, IndexedTriangle, MeshLimits, SurfaceHit, TriangleMesh};
pub use motion::{
    ForecastBasis, MAX_FORECAST_NS, MAX_MOTION_ROUTES, MAX_ROUTE_POINTS, MotionForecast,
    MotionHypothesis, MotionKnot, RouteCandidate, RouteEnd, RoutePriors, RouteSurface,
    forecast_routes,
};
pub use registration::{
    Correspondence, DEFAULT_PLANAR_RESIDUAL_RATIO, FocalCandidateValidation, FocalPoseScan,
    FocalSample, FocalSampleOutcome, FocalScanOptions, FocalValidationSet, LandmarkResidual,
    PlanarSupport, PoseCandidate, PoseSearch, PoseSolverOptions, PoseValidation, PoseValidationSet,
    estimate_camera_pose, estimate_camera_pose_adaptive, estimate_nonplanar_camera_pose,
    estimate_planar_camera_pose, scan_camera_focal_length,
};

/// Error returned by every fallible operation in this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeometryError {
    /// A coordinate or quantity is NaN or infinite.
    NonFinite,
    /// A coordinate or quantity falls outside the admitted numeric range.
    OutOfRange,
    /// The supplied pinhole image model is invalid.
    InvalidCamera,
    /// The supplied rotation is not a proper rotation.
    InvalidRotation,
    /// The point lies at or behind the camera plane.
    BehindCamera,
    /// The observation falls outside the declared image bounds.
    OutOfImage,
    /// The geometric constraints are degenerate (e.g. collinear or coplanar evidence).
    Degenerate,
    /// The supplied geometry input is empty.
    EmptyInput,
    /// A fixed geometry resource limit (e.g. `MAX_*` constant) was exceeded.
    LimitExceeded,
    /// The caller-supplied [`WorkBudget`] ran out of units or refused a charge.
    BudgetExhausted,
    /// The caller-supplied cancellation flag was observed set.
    Cancelled,
    /// A forecast or result was computed against a different basis than expected.
    BasisMismatch,
    /// A mesh vertex/triangle index or route reference does not resolve.
    InvalidIndex,
    /// Pose solver options are inconsistent or out of range.
    InvalidSolverOptions,
    /// A correspondence is invalid, duplicate, or internally inconsistent.
    InvalidCorrespondence,
    /// Too few correspondences to constrain the requested pose.
    InsufficientCorrespondences,
    /// The geometry is planar or otherwise unsuitable for this solver.
    UnsupportedGeometry,
    /// The bounded pose solver iterated to its limit without converging.
    SolverDidNotConverge,
    /// No admissible pose achieved the required consensus.
    NoPoseConsensus,
    /// Pose ambiguity produced more candidates than the candidate limit admits.
    TooManyPoseCandidates,
    /// A validation landmark was also used as fitting evidence.
    HoldoutLeak,
}
impl std::fmt::Display for GeometryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NonFinite => "nonfinite geometry",
            Self::OutOfRange => "geometry outside admitted numeric range",
            Self::InvalidCamera => "invalid pinhole image model",
            Self::InvalidRotation => "invalid proper rotation",
            Self::BehindCamera => "point not in front of camera",
            Self::OutOfImage => "observation outside declared image",
            Self::Degenerate => "degenerate geometric constraint",
            Self::EmptyInput => "empty geometry",
            Self::LimitExceeded => "geometry resource limit exceeded",
            Self::BudgetExhausted => "geometry work budget exhausted",
            Self::Cancelled => "geometry operation cancelled",
            Self::BasisMismatch => "geometry basis mismatch",
            Self::InvalidIndex => "invalid geometry reference",
            Self::HoldoutLeak => "validation landmark overlaps fitting evidence",
            Self::TooManyPoseCandidates => "pose ambiguity exceeds candidate limit",
            Self::NoPoseConsensus => "no admissible pose consensus",
            Self::SolverDidNotConverge => "bounded pose solver did not converge",
            Self::UnsupportedGeometry => "planar or weak geometry requires another solver",
            Self::InsufficientCorrespondences => "insufficient pose correspondences",
            Self::InvalidCorrespondence => "invalid or duplicate correspondence",
            Self::InvalidSolverOptions => "invalid pose solver options",
        })
    }
}
impl std::error::Error for GeometryError {}

/// Caller-supplied work accounting with optional cooperative cancellation.
///
/// Operations charge integer units before doing work; exceeding `limit` fails with
/// [`GeometryError::BudgetExhausted`], never by truncating results.
#[derive(Debug)]
pub struct WorkBudget<'a> {
    limit: u64,
    used: u64,
    cancellation: Option<&'a AtomicBool>,
}
impl WorkBudget<'_> {
    /// Creates a budget admitting exactly `limit` chargeable units with no cancellation flag.
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            used: 0,
            cancellation: None,
        }
    }
    /// Units already charged; never exceeds `limit`.
    pub fn used(&self) -> u64 {
        self.used
    }
    /// Units still chargeable (`limit - used`); zero means every further charge fails.
    pub fn remaining(&self) -> u64 {
        self.limit - self.used
    }
    /// Charges `units`, first honoring the cancellation flag; fails with
    /// [`GeometryError::Cancelled`] or [`GeometryError::BudgetExhausted`] without partial charging.
    pub fn charge(&mut self, units: u64) -> Result<(), GeometryError> {
        if self
            .cancellation
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            return Err(GeometryError::Cancelled);
        }
        if units > self.remaining() {
            return Err(GeometryError::BudgetExhausted);
        }
        self.used += units;
        Ok(())
    }
}
impl<'a> WorkBudget<'a> {
    /// Creates a budget that refuses all work with [`GeometryError::Cancelled`] once
    /// `cancellation` is observed set (acquire ordering).
    pub fn cancellable(limit: u64, cancellation: &'a AtomicBool) -> Self {
        Self {
            limit,
            used: 0,
            cancellation: Some(cancellation),
        }
    }
}
