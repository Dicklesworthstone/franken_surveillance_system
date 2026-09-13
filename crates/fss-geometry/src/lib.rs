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

use std::sync::atomic::{AtomicBool, Ordering};

pub use camera::{PinholeIntrinsics, Ray, RigidPose};
pub use mesh::{GeometryBasis, IndexedTriangle, MeshLimits, SurfaceHit, TriangleMesh};

/// Stable, non-disclosing failures at the numerical boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeometryError {
    /// A supplied value or an intermediate result is not finite.
    NonFinite,
    /// A numerical value lies outside the reference kernel's admitted range.
    OutOfRange,
    /// Image dimensions, focal lengths, or intrinsic parameters are invalid.
    InvalidCamera,
    /// A transform is not a proper orthonormal rotation.
    InvalidRotation,
    /// A point is behind or too close to the optical center.
    BehindCamera,
    /// A requested observation lies outside its declared image domain.
    OutOfImage,
    /// A direction, triangle, or geometric constraint is degenerate.
    Degenerate,
    /// Required input geometry is empty.
    EmptyInput,
    /// A count, allocation, or output bound was exceeded.
    LimitExceeded,
    /// The caller's deterministic work allowance was exhausted.
    BudgetExhausted,
    /// The owner requested cancellation; no partial result is published.
    Cancelled,
    /// The supplied query refers to another property or geometry revision.
    BasisMismatch,
    /// A mesh triangle references an absent vertex or invalid feature handle.
    InvalidIndex,
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
        };
        f.write_str(message)
    }
}

impl std::error::Error for GeometryError {}

/// A deterministic work counter with an optional owner-owned cancellation flag.
///
/// Units count bounded scalar operations/iterations, not elapsed time or joules.
/// An Asupersync adapter can narrow the allowance and own the cancellation flag;
/// this synchronous kernel never creates a competing runtime or worker thread.
#[derive(Debug)]
pub struct WorkBudget<'a> {
    limit: u64,
    used: u64,
    cancellation: Option<&'a AtomicBool>,
}

impl WorkBudget<'_> {
    /// Start a work allowance without a cancellation flag.
    pub fn new(limit: u64) -> Self {
        Self { limit, used: 0, cancellation: None }
    }

    /// Consumed units, including work preceding an unsuccessful call.
    pub fn used(&self) -> u64 { self.used }

    /// Units still available.
    pub fn remaining(&self) -> u64 { self.limit - self.used }

    /// Poll cancellation and reserve work before performing it.
    pub fn charge(&mut self, units: u64) -> Result<(), GeometryError> {
        if self.cancellation.is_some_and(|flag| flag.load(Ordering::Acquire)) {
            return Err(GeometryError::Cancelled);
        }
        if units > self.remaining() { return Err(GeometryError::BudgetExhausted); }
        self.used += units;
        Ok(())
    }
}

impl<'a> WorkBudget<'a> {
    /// Start an allowance attached to a flag whose lifetime belongs to the owner.
    pub fn cancellable(limit: u64, cancellation: &'a AtomicBool) -> Self {
        Self { limit, used: 0, cancellation: Some(cancellation) }
    }
}
