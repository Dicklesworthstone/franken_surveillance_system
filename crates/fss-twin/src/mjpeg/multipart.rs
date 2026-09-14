#![forbid(unsafe_code)]
//! A MIME-framed JPEG enters the same complete native image-analysis path.
use fss_codec_mjpeg::{DecodeBudget, DecodeLimits};
use fss_codec_mjpeg::multipart::{MultipartFrame, MultipartReceipt};
use fss_codec_mjpeg::stream::StreamBasis;
use fss_geometry::WorkBudget;
use crate::foreground::ForegroundPolicy;
use crate::foreground::pipeline::FrameCapture;
use crate::rectification::RectificationPlan;
use super::{JpegBackground, JpegForeground, JpegFrameBinding, JpegPipelineError};

/// Owner-supplied source, time and processing policy; no timestamp header is trusted.
#[derive(Clone, Copy)]
pub struct MultipartQuery<'a> {
    /// Independently expected dechunked-entity source generation.
    pub expected_entity: StreamBasis,
    /// A successfully delimited part, still requiring full JPEG decoding.
    pub frame: &'a MultipartFrame,
    /// Exact coded-grid 0/1 permission mask.
    pub mask: &'a [u8],
    /// Independent frame, exposure, calibration and image-domain bindings.
    pub binding: JpegFrameBinding,
    /// Capture interval supplied by the time/evidence owner, not a MIME header.
    pub capture: FrameCapture,
    /// Existing immutable foreground policy.
    pub policy: ForegroundPolicy,
    /// Complete native decoder resource ceilings.
    pub limits: DecodeLimits,
}
/// Original entity ranges travel with every decoded/image-derived result.
pub struct MultipartForeground { source: MultipartReceipt, foreground: JpegForeground }
impl MultipartForeground {
    /// Exact MIME, header, payload and delimiter source binding.
    pub fn source(&self) -> MultipartReceipt { self.source }
    /// Native decoder, rectification and foreground/crop/contact-proposal result.
    pub fn foreground(&self) -> &JpegForeground { &self.foreground }
}
/// Validate the expected entity/frame, decode completely, and run existing image analysis.
/// This cannot open a camera, infer contact, mutate a track or certify stream completion.
pub fn detect_multipart(model: &JpegBackground, plan: &RectificationPlan, query: MultipartQuery<'_>,
    decoder: &mut DecodeBudget<'_>, geometry: &mut WorkBudget<'_>) -> Result<MultipartForeground,JpegPipelineError> {
    geometry.charge(0)?;
    let source = query.frame.receipt();
    if source.basis != query.expected_entity || source.encoded_sha256 != query.binding.encoded_sha256 {
        return Err(JpegPipelineError::BasisMismatch);
    }
    let foreground = model.detect(plan, query.frame.bytes(), query.mask, query.binding,
        query.capture, query.policy, query.limits, decoder, geometry)?;
    geometry.charge(0)?;
    Ok(MultipartForeground { source, foreground })
}
