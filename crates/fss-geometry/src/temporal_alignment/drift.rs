#![forbid(unsafe_code)]
//! Finite affine clock hypotheses and disjoint-session validation.
//!
//! The original solver and public API remain unchanged. Validation composes its
//! complete inventories without selecting or activating a clock. Relative integer
//! mapping, outward interval rounding and nominal training-time enclosures retain
//! their original semantics; physical calibration and custody are not implied.

use super::{
    ClockAlignmentError, ClockAlignmentPair, MAX_CLOCK_OFFSET_HYPOTHESES, copy_bounded,
    validate_membership,
};

mod solver;
pub use solver::*;

/// Separate capture-session checks and unpruned target-to-reference interval envelopes.
pub mod validation;
