#![forbid(unsafe_code)]
//! Independent original-frame replay of native activity computations.
//!
//! The native replay checks the exact two JPEG decodes, committed model computation and complete
//! result/receipt pair. The concrete belief engine adds independently selected evidence roles and
//! authority-revision checks before invoking that replay through the existing provenance boundary.
//! Neither interface grants read access, certifies presence or absence, or authorizes effects.

/// Statically selected first-party activity derivation over verified retained evidence.
pub mod belief;
mod native;

pub use native::{
    ActivityReplayError, ActivityReplayInputs, ActivityReplayLimits, ActivityReplayPlan,
    ReplayedActivityResult, replay_activity_result,
};
