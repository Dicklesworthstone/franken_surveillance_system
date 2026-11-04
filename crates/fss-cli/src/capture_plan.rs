#![forbid(unsafe_code)]
//! Read-only access to the existing native RTSP planner.
//!
//! The binary and this adapter compile the same planner source. Approval encoding,
//! validation, resource defaults and preview semantics therefore have one owner.
//! This module neither opens a socket nor inspects paths, credentials or clocks.

use std::ffi::OsString;

use fss_core::ContentDigest;

// Execution-only methods of the original modules are deliberately private here. The
// public surface below returns values, never an executor or credential capability.
#[allow(dead_code, unused_imports)]
#[path = "bin/fss-capture-rtsp/authentication.rs"]
mod authentication;
#[allow(dead_code)]
#[path = "bin/fss-capture-rtsp/plan.rs"]
mod plan;

/// The exact native approval and complete JSON preview for an unapproved request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRtspPlan {
    /// The native capture plan digest. Possessing it is not an effect grant.
    pub approval: ContentDigest,
    /// Byte-identical output of the native planner for the same argument values.
    pub preview: String,
}

/// Validate and prepare an AVC/HEVC capture request without any I/O.
///
/// `--approve` is refused at this planning-only boundary. All other validation and
/// effective limits come directly from the existing native capture owner. Error
/// strings are static and never interpolate untrusted arguments or private paths.
pub fn prepare_rtsp(args: &[OsString]) -> Result<PreparedRtspPlan, &'static str> {
    if args.chunks_exact(2).any(|pair| pair[0] == "--approve") {
        return Err("approval is not accepted by the pure planning adapter");
    }
    let native = plan::Options::parse(args)?;
    Ok(PreparedRtspPlan {
        approval: native.digest()?,
        preview: native.preview()?,
    })
}
