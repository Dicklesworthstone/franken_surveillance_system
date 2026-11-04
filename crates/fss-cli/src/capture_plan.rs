#![forbid(unsafe_code)]
//! Read-only access to the existing native RTSP planner.
//!
//! The binary and this adapter compile the same planner source. Approval encoding,
//! validation, resource defaults and preview semantics therefore have one owner.
//! This module neither opens a socket nor inspects paths, credentials or clocks.

use std::ffi::OsString;

use fss_core::ContentDigest;

// Share only the credential-reference planner, never the credential or entropy
// owners. The public surface returns values, not an executor or I/O capability.
#[allow(dead_code)]
#[path = "bin/fss-capture-rtsp/authentication_plan.rs"]
mod authentication;
#[allow(dead_code)]
#[path = "bin/fss-capture-rtsp/jpeg/plan.rs"]
mod jpeg;
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

/// Validate and prepare a native JPEG capture request without any I/O.
///
/// Supply the option/value pairs following `fss-capture-rtsp jpeg`. Approval and
/// cold replay are refused: this boundary prepares a new bounded source capture.
/// The exact native JPEG parser owns all limits, including its 256-picture ceiling,
/// selected RTP payload and channels, retention evidence, and Digest policy.
pub fn prepare_jpeg(args: &[OsString]) -> Result<PreparedRtspPlan, &'static str> {
    if args.first().is_some_and(|arg| arg == "replay") {
        return Err("cold replay is not accepted by the pure capture planning adapter");
    }
    if args.chunks_exact(2).any(|pair| pair[0] == "--approve") {
        return Err("approval is not accepted by the pure planning adapter");
    }
    let native = jpeg::Options::parse(args)?;
    Ok(PreparedRtspPlan {
        approval: native.digest()?,
        preview: native.preview()?,
    })
}
