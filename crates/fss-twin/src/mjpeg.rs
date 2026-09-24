#![forbid(unsafe_code)]
//! Complete JPEG bytes -> native luma -> rectification -> image-region proposals.
//! The owner frames compressed input and supplies capture, calibration and permission.

use crate::foreground::pipeline::{
    ForegroundPipelineError, FrameCapture, RectifiedBackground, RectifiedForeground,
    RectifiedReference,
};
use crate::foreground::{BackgroundPolicy, ForegroundPolicy, MAX_BACKGROUND_FRAMES};
use crate::rectification::{
    LumaRange, RawFrameIdentity, RawGrayFrame, RectificationError, RectificationPlan,
    RectifiedFrame,
};
use fss_codec_mjpeg::{
    ComponentInterpretation, DecodeBudget, DecodeError, DecodeLimits, DecodeReceipt, DecodedLuma,
    decode_luma, decoder_identity,
};
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};

/// Exact source declaration. Hashes identify records, never authenticate them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JpegFrameBinding {
    /// Complete encoded frame bytes, including headers and metadata.
    pub encoded_sha256: [u8; 32],
    /// Original capture/source/PTS identity; decoding never creates a new exposure.
    pub exposure: [u8; 32],
    /// Exact coded-pixel-grid 0/1 mask, supplied by the owner.
    pub allowed_mask: [u8; 32],
    /// Original coded-grid image-domain identity, before the decoder-generation binding.
    pub camera_image_domain: [u8; 32],
    /// Exact admitted lens/calibration record.
    pub calibration: [u8; 32],
    /// Explicit grayscale or YCbCr interpretation, not inferred from image appearance.
    pub interpretation: ComponentInterpretation,
}

/// Bind the decoded raw-image domain to its camera grid AND exact decoder generation.
/// Use this as `RectificationSpec::source_domain` when compiling the downstream map.
pub fn decoded_image_domain(
    camera_domain: [u8; 32],
    interpretation: ComponentInterpretation,
) -> [u8; 32] {
    let mut bytes = [0_u8; 97];
    bytes[..32].copy_from_slice(
        &ContentDigest::sha256(b"fss/mjpeg-decoded-image-domain/reference/1").bytes(),
    );
    bytes[32..64].copy_from_slice(&camera_domain);
    bytes[64..96].copy_from_slice(&decoder_identity());
    bytes[96] = match interpretation {
        ComponentInterpretation::Grayscale => 0,
        ComponentInterpretation::YCbCr => 1,
    };
    ContentDigest::sha256(&bytes).bytes()
}

/// Complete coupled source/codec/raw-plane receipt, retained with downstream results.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JpegReceipt {
    /// Original encoded source and owner bindings.
    pub source: JpegFrameBinding,
    /// Actual decoding identity and accounting.
    pub decode: DecodeReceipt,
    /// Actual verified raw luma/mask identity supplied to the rectifier.
    pub raw: RawFrameIdentity,
}

/// No error returns a partially decoded, rectified or classified success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JpegPipelineError {
    /// Full compressed frame failed native decoding or its work/cancellation boundary.
    Decode(DecodeError),
    /// Raw-frame layout, mask, lens or image-domain validation failed.
    Rectification(RectificationError),
    /// Background or downstream foreground operation failed.
    Foreground(ForegroundPipelineError),
    /// Source identity, range, dimension or generation contradicts the admitted map.
    BasisMismatch,
    /// Bounded source/reference allocation failed.
    Limit,
}
impl From<DecodeError> for JpegPipelineError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}
impl From<RectificationError> for JpegPipelineError {
    fn from(e: RectificationError) -> Self {
        Self::Rectification(e)
    }
}
impl From<ForegroundPipelineError> for JpegPipelineError {
    fn from(e: ForegroundPipelineError) -> Self {
        Self::Foreground(e)
    }
}
impl From<GeometryError> for JpegPipelineError {
    fn from(e: GeometryError) -> Self {
        Self::Rectification(e.into())
    }
}
impl std::fmt::Display for JpegPipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Decode(_) => "compressed JPEG frame failed",
            Self::Rectification(_) => "JPEG luma rectification failed",
            Self::Foreground(_) => "JPEG foreground operation failed",
            Self::BasisMismatch => "JPEG pipeline basis mismatch",
            Self::Limit => "JPEG pipeline allocation limit",
        })
    }
}
impl std::error::Error for JpegPipelineError {}

fn decode_source(
    plan: &RectificationPlan,
    bytes: &[u8],
    mask: &[u8],
    source: JpegFrameBinding,
    limits: DecodeLimits,
    decode_budget: &mut DecodeBudget<'_>,
    geometry_budget: &mut WorkBudget<'_>,
) -> Result<(DecodedLuma, JpegReceipt), JpegPipelineError> {
    geometry_budget.charge(0)?;
    let spec = plan.spec();
    if [
        source.encoded_sha256,
        source.exposure,
        source.allowed_mask,
        source.camera_image_domain,
        source.calibration,
    ]
    .contains(&[0; 32])
        || spec.calibration != source.calibration
        || spec.range != LumaRange::Full
        || spec.source_domain
            != decoded_image_domain(source.camera_image_domain, source.interpretation)
    {
        return Err(JpegPipelineError::BasisMismatch);
    }
    let size = spec.source.dimensions();
    if mask.len() != size[0] as usize * size[1] as usize {
        return Err(JpegPipelineError::BasisMismatch);
    }
    geometry_budget.charge(mask.len() as u64 * 2)?;
    if mask.iter().any(|v| *v > 1) || ContentDigest::sha256(mask).bytes() != source.allowed_mask {
        return Err(JpegPipelineError::BasisMismatch);
    }
    let decoded = decode_luma(
        bytes,
        source.encoded_sha256,
        source.interpretation,
        limits,
        decode_budget,
    )?;
    if decoded.dimensions() != size {
        return Err(JpegPipelineError::BasisMismatch);
    }
    let raw = RawFrameIdentity {
        exposure: source.exposure,
        storage: decoded.receipt().luma_sha256,
        allowed_mask: source.allowed_mask,
        image_domain: spec.source_domain,
        calibration: source.calibration,
        dimensions: size,
        row_stride: size[0],
        range: LumaRange::Full,
    };
    let receipt = JpegReceipt {
        source,
        decode: decoded.receipt(),
        raw,
    };
    geometry_budget.charge(0)?;
    Ok((decoded, receipt))
}

/// Actual native decoded/rectified frame, retaining compressed source identity.
pub struct JpegRectified {
    frame: RectifiedFrame,
    receipt: JpegReceipt,
}
impl JpegRectified {
    /// Permission-masked pinhole pixels and actual sampling receipt.
    pub fn frame(&self) -> &RectifiedFrame {
        &self.frame
    }
    /// Original JPEG, decoder and decoded-luma identities.
    pub fn receipt(&self) -> JpegReceipt {
        self.receipt
    }
}
/// Decode and rectify one complete owner-framed JPEG, suitable as a reference or query.
/// Both budgets belong to the same owning task and may share its cancellation flag.
pub fn decode_rectified(
    plan: &RectificationPlan,
    bytes: &[u8],
    mask: &[u8],
    source: JpegFrameBinding,
    limits: DecodeLimits,
    decode_budget: &mut DecodeBudget<'_>,
    geometry_budget: &mut WorkBudget<'_>,
) -> Result<JpegRectified, JpegPipelineError> {
    let (decoded, receipt) = decode_source(
        plan,
        bytes,
        mask,
        source,
        limits,
        decode_budget,
        geometry_budget,
    )?;
    let raw = RawGrayFrame::new(receipt.raw, decoded.pixels(), mask, geometry_budget)?;
    let frame = plan.apply(&raw, geometry_budget)?;
    geometry_budget.charge(0)?;
    Ok(JpegRectified { frame, receipt })
}

/// One selected decoded JPEG reference with owner-supplied camera/capture timing.
#[derive(Clone, Copy)]
pub struct JpegReference<'a> {
    /// Unforgeable decoded/rectified output produced above.
    pub image: &'a JpegRectified,
    /// Original external capture interval and camera/clock handles.
    pub capture: FrameCapture,
}

/// Frozen numerical background AND every compressed-source decode receipt.
pub struct JpegBackground {
    background: RectifiedBackground,
    references: Vec<JpegReceipt>,
}
impl JpegBackground {
    /// Use 3..=31 explicitly selected JPEG reference exposures, with no auto-baseline.
    pub fn build(
        plan: &RectificationPlan,
        references: &[JpegReference<'_>],
        policy: BackgroundPolicy,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Self, JpegPipelineError> {
        budget.charge(0)?;
        if !(3..=MAX_BACKGROUND_FRAMES).contains(&references.len()) {
            return Err(JpegPipelineError::Limit);
        }
        let mut frames = Vec::new();
        let mut receipts = Vec::new();
        frames
            .try_reserve_exact(references.len())
            .map_err(|_| JpegPipelineError::Limit)?;
        receipts
            .try_reserve_exact(references.len())
            .map_err(|_| JpegPipelineError::Limit)?;
        for reference in references {
            budget.charge(1)?;
            frames.push(RectifiedReference {
                frame: reference.image.frame(),
                capture: reference.capture,
            });
            receipts.push(reference.image.receipt());
        }
        let background = RectifiedBackground::build(plan, &frames, policy, budget)?;
        budget.charge(0)?;
        Ok(Self {
            background,
            references: receipts,
        })
    }
    /// Full compressed-source receipts for the references, in capture order.
    pub fn reference_receipts(&self) -> &[JpegReceipt] {
        &self.references
    }
    /// Existing frozen rectified background; no replacement detector or model update.
    pub fn background(&self) -> &RectifiedBackground {
        &self.background
    }
    /// Complete compressed-frame to region/crop-ready output, with no supplied boxes.
    #[allow(clippy::too_many_arguments)]
    pub fn detect(
        &self,
        plan: &RectificationPlan,
        bytes: &[u8],
        mask: &[u8],
        source: JpegFrameBinding,
        capture: FrameCapture,
        policy: ForegroundPolicy,
        limits: DecodeLimits,
        decode_budget: &mut DecodeBudget<'_>,
        geometry_budget: &mut WorkBudget<'_>,
    ) -> Result<JpegForeground, JpegPipelineError> {
        let (decoded, receipt) = decode_source(
            plan,
            bytes,
            mask,
            source,
            limits,
            decode_budget,
            geometry_budget,
        )?;
        let raw = RawGrayFrame::new(receipt.raw, decoded.pixels(), mask, geometry_budget)?;
        let analysis = self
            .background
            .detect_luma(plan, &raw, capture, policy, geometry_budget)?;
        geometry_budget.charge(0)?;
        Ok(JpegForeground { analysis, receipt })
    }
}

/// Coupled compressed source and actual image-derived foreground result.
pub struct JpegForeground {
    analysis: RectifiedForeground,
    receipt: JpegReceipt,
}
impl JpegForeground {
    /// Existing exact regions, masks, crops and explicit contact-proposal interface.
    pub fn analysis(&self) -> &RectifiedForeground {
        &self.analysis
    }
    /// Compressed source, interpreted decoder and decoded-plane identity.
    pub fn receipt(&self) -> JpegReceipt {
        self.receipt
    }
}

/// Incrementally framed JPEG sources entering the existing foreground pipeline.
pub mod stream;

/// Multipart entity parts retaining their MIME and compressed-source identities.
pub mod multipart;

/// Source-mapped HTTP frames entering the existing foreground pipeline.
pub mod http;
