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
mod math;
mod mesh;
mod linear;
mod refine;
mod registration;
mod motion;
mod handoff;

use std::sync::atomic::{AtomicBool, Ordering};

pub use camera::{PinholeIntrinsics, Ray, RigidPose};
pub use mesh::{GeometryBasis, IndexedTriangle, MeshLimits, SurfaceHit, TriangleMesh};
pub use registration::{Correspondence, LandmarkResidual, PoseCandidate, PoseSearch,
    PoseSolverOptions, PoseValidation, PoseValidationSet, estimate_camera_pose, PlanarSupport,
    estimate_nonplanar_camera_pose, DEFAULT_PLANAR_RESIDUAL_RATIO, estimate_camera_pose_adaptive,
    estimate_planar_camera_pose, FocalPoseScan, FocalSample, FocalSampleOutcome,
    FocalScanOptions, scan_camera_focal_length};

pub use motion::{ForecastBasis, MAX_FORECAST_NS, MAX_MOTION_ROUTES, MAX_ROUTE_POINTS,
    MotionForecast, MotionHypothesis, MotionKnot, RouteCandidate, RouteEnd, RoutePriors,
    RouteSurface, forecast_routes};

pub use handoff::{BodySamples, CameraAvailability, CameraHandoffForecast, CaptureSchedule,
    HandoffCamera, HandoffCameraScope, HandoffOptions, ImageRect, MAX_BODY_SAMPLES,
    MAX_HANDOFF_CAMERAS, NanosecondInterval, NextCameraOutcome, PredictedObservation,
    RouteBody, RouteHandoff, predict_camera_handoffs};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeometryError {
    NonFinite,
    OutOfRange,
    InvalidCamera,
    InvalidRotation,
    BehindCamera,
    OutOfImage,
    Degenerate,
    EmptyInput,
    LimitExceeded,
    BudgetExhausted,
    Cancelled,
    BasisMismatch,
    InvalidIndex,
    InvalidSolverOptions,
    InvalidCorrespondence,
    InsufficientCorrespondences,
    UnsupportedGeometry,
    SolverDidNotConverge,
    NoPoseConsensus,
    TooManyPoseCandidates,
    HoldoutLeak,
}

impl std::fmt::Display for GeometryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
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
        };
        f.write_str(message)
    }
}
impl std::error::Error for GeometryError {}

#[derive(Debug)]
pub struct WorkBudget<'a> {
    limit: u64,
    used: u64,
    cancellation: Option<&'a AtomicBool>,
}
impl WorkBudget<'_> {
    pub fn new(limit: u64) -> Self { Self { limit, used: 0, cancellation: None } }
    pub fn used(&self) -> u64 { self.used }
    pub fn remaining(&self) -> u64 { self.limit - self.used }
    pub fn charge(&mut self, units: u64) -> Result<(), GeometryError> {
        if self.cancellation.is_some_and(|flag| flag.load(Ordering::Acquire)) { return Err(GeometryError::Cancelled); }
        if units > self.remaining() { return Err(GeometryError::BudgetExhausted); }
        self.used += units;
        Ok(())
    }
}
impl<'a> WorkBudget<'a> {
    pub fn cancellable(limit: u64, cancellation: &'a AtomicBool) -> Self {
        Self { limit, used: 0, cancellation: Some(cancellation) }
    }
}
