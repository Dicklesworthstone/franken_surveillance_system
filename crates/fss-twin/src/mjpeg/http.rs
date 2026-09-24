#![forbid(unsafe_code)]
//! Source-mapped HTTP JPEG frames through the existing complete analysis path.
use super::multipart::{MultipartForeground, MultipartQuery, detect_multipart};
use super::{JpegBackground, JpegForeground, JpegFrameBinding, JpegPipelineError};
use crate::foreground::ForegroundPolicy;
use crate::foreground::pipeline::FrameCapture;
use crate::rectification::RectificationPlan;
use fss_codec_mjpeg::http_mjpeg::HttpJpegFrame;
use fss_codec_mjpeg::stream::StreamBasis;
use fss_codec_mjpeg::{DecodeBudget, DecodeLimits};
use fss_geometry::WorkBudget;
/// Independently admitted response identity and original camera/exposure policy.
#[derive(Clone, Copy)]
pub struct HttpQuery<'a> {
    /// Expected plaintext HTTP stream identity, not the derived MIME entity identity.
    pub expected_response: StreamBasis,
    /// Complete source-mapped MIME frame; HTTP response termination remains separate.
    pub frame: &'a HttpJpegFrame,
    /// Explicit coded-pixel-grid privacy mask.
    pub mask: &'a [u8],
    /// Independently expected frame, exposure, lens and image-mode identities.
    pub binding: JpegFrameBinding,
    /// Actual externally supported capture interval, not server header text.
    pub capture: FrameCapture,
    /// Existing numerical foreground policy.
    pub policy: ForegroundPolicy,
    /// Complete decoder resource ceilings.
    pub limits: DecodeLimits,
}
/// Borrows exact HTTP/MIME/JPEG source evidence alongside owned image analysis.
pub struct HttpForeground<'a> {
    source: &'a HttpJpegFrame,
    result: MultipartForeground,
}
impl HttpForeground<'_> {
    /// Original HTTP identity and complete JPEG-to-wire spans; not a completion claim.
    pub fn source(&self) -> &HttpJpegFrame {
        self.source
    }
    /// Existing source-bound decoded, rectified, masked foreground/crop result.
    pub fn foreground(&self) -> &JpegForeground {
        self.result.foreground()
    }
}
/// Revalidate expected response/frame, then reuse the existing decoder and detector.
/// No socket, clock, semantic classification, contact or track mutation is inferred.
pub fn detect_http<'a>(
    model: &JpegBackground,
    plan: &RectificationPlan,
    query: HttpQuery<'a>,
    decoder: &mut DecodeBudget<'_>,
    geometry: &mut WorkBudget<'_>,
) -> Result<HttpForeground<'a>, JpegPipelineError> {
    geometry.charge(0)?;
    if query.frame.head().wire != query.expected_response {
        return Err(JpegPipelineError::BasisMismatch);
    }
    let result = detect_multipart(
        model,
        plan,
        MultipartQuery {
            expected_entity: query.frame.head().entity,
            frame: query.frame.part(),
            mask: query.mask,
            binding: query.binding,
            capture: query.capture,
            policy: query.policy,
            limits: query.limits,
        },
        decoder,
        geometry,
    )?;
    Ok(HttpForeground {
        source: query.frame,
        result,
    })
}
