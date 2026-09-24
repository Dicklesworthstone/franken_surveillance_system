#![forbid(unsafe_code)]
//! Complete, source-range-bound stream frames entering the existing image pipeline.
use super::{JpegBackground, JpegForeground, JpegFrameBinding, JpegPipelineError};
use crate::foreground::ForegroundPolicy;
use crate::foreground::pipeline::FrameCapture;
use crate::rectification::RectificationPlan;
use fss_codec_mjpeg::stream::{FramedJpeg, StreamBasis};
use fss_codec_mjpeg::{DecodeBudget, DecodeLimits};
use fss_geometry::WorkBudget;

/// Explicit input scope. Frame ordinal and arrival order are never capture time.
#[derive(Clone, Copy)]
pub struct FramedQuery<'a> {
    /// Independently expected source generation, checked against the framed object.
    pub expected_stream: StreamBasis,
    /// Actual completed output of the incremental byte framer, not fabricated bytes.
    pub frame: &'a FramedJpeg,
    /// Complete coded-grid permission mask.
    pub mask: &'a [u8],
    /// Original exposure and admitted calibration; encoded hash must match the frame.
    pub binding: JpegFrameBinding,
    /// Independently established capture interval, never inferred from frame ordinal.
    pub capture: FrameCapture,
    /// Existing foreground model policy, retained by its output report.
    pub policy: ForegroundPolicy,
    /// Narrowable existing decoder bounds.
    pub limits: DecodeLimits,
}

/// Source-range lineage for exactly one frame, not proof of whole-stream continuity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamFrameReceipt {
    /// Owner-resolved original stream and generation.
    pub basis: StreamBasis,
    /// One-based frame index in that contiguous stream input.
    pub ordinal: u64,
    /// Half-open original byte range, including SOI and EOI.
    pub byte_range: [u64; 2],
    /// Exact original compressed-frame hash.
    pub encoded_sha256: [u8; 32],
}

/// Framing lineage and fully decoded/rectified foreground result published together.
pub struct FramedForeground {
    source: StreamFrameReceipt,
    foreground: JpegForeground,
}
impl FramedForeground {
    /// Exact original stream byte-range binding.
    pub fn source(&self) -> StreamFrameReceipt {
        self.source
    }
    /// Full codec/image/model receipts and existing masked crop/contact API.
    pub fn foreground(&self) -> &JpegForeground {
        &self.foreground
    }
}

/// Decode, rectify and analyze one independently scoped completed stream frame.
/// No successful result escapes unless the complete JPEG and downstream masks pass.
pub fn detect_framed(
    model: &JpegBackground,
    plan: &RectificationPlan,
    query: FramedQuery<'_>,
    decode_budget: &mut DecodeBudget<'_>,
    geometry_budget: &mut WorkBudget<'_>,
) -> Result<FramedForeground, JpegPipelineError> {
    geometry_budget.charge(0)?;
    if query.expected_stream != query.frame.basis()
        || query.binding.encoded_sha256 != query.frame.encoded_sha256()
    {
        return Err(JpegPipelineError::BasisMismatch);
    }
    let foreground = model.detect(
        plan,
        query.frame.bytes(),
        query.mask,
        query.binding,
        query.capture,
        query.policy,
        query.limits,
        decode_budget,
        geometry_budget,
    )?;
    geometry_budget.charge(0)?;
    Ok(FramedForeground {
        source: StreamFrameReceipt {
            basis: query.frame.basis(),
            ordinal: query.frame.ordinal(),
            byte_range: query.frame.byte_range(),
            encoded_sha256: query.frame.encoded_sha256(),
        },
        foreground,
    })
}
