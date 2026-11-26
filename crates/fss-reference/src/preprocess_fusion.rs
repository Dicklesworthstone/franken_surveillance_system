#![forbid(unsafe_code)]
//! Model preprocess & postprocess fusion laws and 0-ULP reference certification (`FSS-143`, `fss-x4a.14.14`).
//!
//! Formally verifies that single-pass fused preprocess and postprocess pipelines match explicit
//! multi-stage unfused reference oracles bit-for-bit (`max_ulp_delta == 0`) while eliminating
//! intermediate buffers and redundant work:
//!
//! 1. **Preprocess Fusion Law (`Resize -> ColorConvert -> Scale -> NchwLayout`)**:
//!    Compares an explicit 4-stage unfused reference pipeline (`unfused_reference_preprocess`)
//!    against single-pass [`PreprocessProgram::execute_resized_bytes`] across `Nearest`/`Bilinear`,
//!    `Stretch`/`Letterbox`, `Rgb`/`LumaOnly`, and `scale_to_unit: true/false`, certifying 0-ULP
//!    equivalence and measuring `saved_intermediate_bytes`.
//! 2. **Preprocess Identity-Resize Law**:
//!    Proves `Resize(H, W -> H, W, Stretch)` fused with [`PreprocessProgram`] is bit-identical to
//!    strict-size [`PreprocessProgram::execute_bytes`].
//! 3. **Postprocess Fusion Law (`LogitThreshold/Sigmoid -> Unletterbox -> CanonicalClassNms`)**:
//!    Compares an explicit 4-stage unfused postprocess reference oracle against a single-pass
//!    monotonic-logit pre-filtered fused decoder + deterministic CGSE-ordered class-aware NMS,
//!    certifying bit-exact identical detections (`FusedDetection`), NaN/Inf and padding-only
//!    suppression, and skipped sub-threshold work accounting.
//! 4. **Sealed `FSSMFU01` v1 receipt (`ModelFusionLawReceipt`)**:
//!    Domain-separated under `fss.reference.model_fusion_law_receipt.v1`; carries zero write or
//!    effect authority (`grants_effect_authority() == false`).

use std::error::Error;
use std::fmt;

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, Sha256Hasher};
use fss_tensor::{Shape, Tensor};

use crate::preprocess::{ImageBytes, ResizeAspect, ResizeFilter, ResizeGeometry, ResizeOptions};
use crate::scalar_executor::{
    ChannelTransform, ExecError, PreprocessProgram, ScalarExecCx, deterministic_sigmoid_f32,
};

/// Registered canonical digest domain for [`ModelFusionLawReceipt`] (`FSS-143`).
pub const MODEL_FUSION_LAW_RECEIPT_DOMAIN: &str = "fss.reference.model_fusion_law_receipt.v1";
/// Binary wire magic header for sealed [`ModelFusionLawReceipt`] envelopes.
pub const MODEL_FUSION_WIRE_MAGIC: [u8; 8] = *b"FSSMFU01";
/// Current wire format version for [`ModelFusionLawReceipt`].
pub const MODEL_FUSION_WIRE_VERSION: u32 = 1;
/// Hard ceiling on serialized `FSSMFU01` wire bytes (512 KiB).
pub const MAX_MODEL_FUSION_WIRE_BYTES: usize = 512 * 1024;
/// Hard ceiling on raw box proposals admitted in one postprocess fusion invocation.
pub const MAX_FUSION_PROPOSALS: usize = 65_536;

const WIRE_HEADER_BYTES: usize = 16;
const WIRE_CHECKSUM_BYTES: usize = 32;

/// Registered algebraic fusion law certified by [`ModelFusionLawReceipt`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FusionLawKind {
    /// Single-pass `Resize + ColorConvert + Scale + NCHW` vs 4-stage unfused reference.
    PreprocessResizeColorScaleNchw = 1,
    /// Identity `Stretch(H, W -> H, W)` resize composition vs strict-size `execute_bytes`.
    PreprocessIdentityResize = 2,
    /// Monotonic logit pre-filter + `Sigmoid + Unletterbox + CanonicalClassNms` vs 4-stage unfused reference.
    PostprocessThresholdUnletterboxNms = 3,
}

impl FusionLawKind {
    /// Stable canonical string spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreprocessResizeColorScaleNchw => "preprocess.resize_color_scale_nchw.v1",
            Self::PreprocessIdentityResize => "preprocess.identity_resize.v1",
            Self::PostprocessThresholdUnletterboxNms => "postprocess.threshold_unletterbox_nms.v1",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, FusionLawError> {
        match tag {
            1 => Ok(Self::PreprocessResizeColorScaleNchw),
            2 => Ok(Self::PreprocessIdentityResize),
            3 => Ok(Self::PostprocessThresholdUnletterboxNms),
            other => Err(FusionLawError::MalformedWire(format!(
                "unknown FusionLawKind tag {other}"
            ))),
        }
    }
}

/// Non-collapsed certification verdict emitted by fusion law verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FusionVerificationVerdict {
    /// Fused and unfused reference paths matched bit-for-bit (`max_ulp_delta == 0`).
    CertifiedBitExact = 1,
    /// Semantic or numeric divergence detected between fused and unfused paths.
    DivergenceDetected = 2,
}

impl FusionVerificationVerdict {
    /// Stable canonical string spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CertifiedBitExact => "certified_bit_exact",
            Self::DivergenceDetected => "divergence_detected",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, FusionLawError> {
        match tag {
            1 => Ok(Self::CertifiedBitExact),
            2 => Ok(Self::DivergenceDetected),
            other => Err(FusionLawError::MalformedWire(format!(
                "unknown FusionVerificationVerdict tag {other}"
            ))),
        }
    }
}

/// Safe operator/agent recovery guidance for a refused fusion law operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FusionLawGuidance {
    /// Repair thresholds, image dimensions, or proposal bounds and retry.
    RepairConfigurationOrInput,
    /// Cooperative cancellation observed cleanly; safe to retry deterministically.
    RetryCleanly,
    /// Disable the offending fusion optimization and execute the unfused reference oracle.
    FallbackToUnfusedReferenceOracle,
    /// Reject corrupt `FSSMFU01` wire bytes and re-certify from canonical inputs.
    RecertifyFromCanonicalInputs,
}

/// Typed fail-closed error emitted by preprocess/postprocess fusion certification.
#[derive(Clone, Debug, PartialEq)]
pub enum FusionLawError {
    /// Invalid configuration thresholds, dimensions, or bounds.
    InvalidConfig(String),
    /// Underlying preprocess/executor error.
    Execution(String),
    /// Proposal count or wire size exceeded hard ceiling.
    BoundsExceeded {
        /// Observed count/bytes.
        observed: usize,
        /// Hard limit.
        maximum: usize,
    },
    /// Cooperative cancellation observed cleanly.
    Cancelled,
    /// Fused output diverged from the unfused reference oracle.
    FusionDivergence(String),
    /// Wire envelope lacked [`MODEL_FUSION_WIRE_MAGIC`].
    InvalidMagic,
    /// Wire envelope version unsupported.
    UnsupportedVersion {
        /// Unsupported version tag observed.
        version: u32,
    },
    /// Wire checksum or canonical receipt digest mismatch.
    ChecksumMismatch,
    /// Wire envelope truncated, oversized, or malformed.
    MalformedWire(String),
}

impl FusionLawError {
    /// Stable canonical machine error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfig(_) => "ERR-MODEL-FUSION-CONFIG-001",
            Self::Execution(_) => "ERR-MODEL-FUSION-EXEC-001",
            Self::BoundsExceeded { .. } => "ERR-MODEL-FUSION-BOUNDS-001",
            Self::Cancelled => "ERR-MODEL-FUSION-CANCELLED-001",
            Self::FusionDivergence(_) => "ERR-MODEL-FUSION-DIVERGENCE-001",
            Self::InvalidMagic | Self::UnsupportedVersion { .. } => "ERR-SCHEMA-UNSUPPORTED-001",
            Self::ChecksumMismatch => "ERR-NEG-CHECKSUM-MISMATCH-001",
            Self::MalformedWire(_) => "ERR-MODEL-FUSION-MALFORMED-WIRE-001",
        }
    }

    /// Safe recovery guidance for this refusal.
    #[must_use]
    pub const fn guidance(&self) -> FusionLawGuidance {
        match self {
            Self::InvalidConfig(_) | Self::Execution(_) | Self::BoundsExceeded { .. } => {
                FusionLawGuidance::RepairConfigurationOrInput
            }
            Self::Cancelled => FusionLawGuidance::RetryCleanly,
            Self::FusionDivergence(_) => FusionLawGuidance::FallbackToUnfusedReferenceOracle,
            Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::ChecksumMismatch
            | Self::MalformedWire(_) => FusionLawGuidance::RecertifyFromCanonicalInputs,
        }
    }
}

impl fmt::Display for FusionLawError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.code(), self)
    }
}

impl Error for FusionLawError {}

impl From<ExecError> for FusionLawError {
    fn from(value: ExecError) -> Self {
        match value {
            ExecError::CancellationRequested { .. } => Self::Cancelled,
            other => Self::Execution(other.to_string()),
        }
    }
}

/// Raw uncalibrated detector box proposal in model-input pixel-edge XYXY space.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RawBoxProposal {
    /// Class identifier.
    pub class_id: u32,
    /// Pre-sigmoid raw logit score.
    pub logit: f32,
    /// Model-input pixel-edge box `[x1, y1, x2, y2]`.
    pub model_xyxy: [f64; 4],
}

/// Bounded configuration for postprocess fusion (`Sigmoid + Threshold + Unletterbox + NMS`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PostprocessFusionConfig {
    /// Minimum post-sigmoid score in `(0.0, 1.0)`.
    pub score_threshold: f32,
    /// Class-aware NMS IoU threshold in `[0.0, 1.0]`.
    pub nms_iou_threshold: f64,
    /// Maximum detections retained after deterministic NMS (`>= 1`).
    pub max_detections: usize,
    /// Maximum raw proposals admitted (`<= MAX_FUSION_PROPOSALS`).
    pub max_proposals: usize,
}

impl PostprocessFusionConfig {
    /// Validates finite bounded postprocess thresholds.
    pub fn validate(&self) -> Result<(), FusionLawError> {
        if !self.score_threshold.is_finite()
            || self.score_threshold <= 0.0
            || self.score_threshold >= 1.0
        {
            return Err(FusionLawError::InvalidConfig(
                "score_threshold must be strictly inside (0.0, 1.0)".to_owned(),
            ));
        }
        if !self.nms_iou_threshold.is_finite()
            || self.nms_iou_threshold < 0.0
            || self.nms_iou_threshold > 1.0
        {
            return Err(FusionLawError::InvalidConfig(
                "nms_iou_threshold must be finite inside [0.0, 1.0]".to_owned(),
            ));
        }
        if self.max_detections == 0 || self.max_proposals == 0 {
            return Err(FusionLawError::InvalidConfig(
                "max_detections and max_proposals must be >= 1".to_owned(),
            ));
        }
        if self.max_proposals > MAX_FUSION_PROPOSALS {
            return Err(FusionLawError::BoundsExceeded {
                observed: self.max_proposals,
                maximum: MAX_FUSION_PROPOSALS,
            });
        }
        Ok(())
    }

    /// Canonical SHA-256 identity of this postprocess configuration.
    pub fn digest(&self) -> Result<ContentDigest, FusionLawError> {
        self.validate()?;
        let mut enc = CanonicalEncoder::new();
        enc.text(MODEL_FUSION_LAW_RECEIPT_DOMAIN);
        enc.text("postprocess_config");
        enc.u32(self.score_threshold.to_bits());
        enc.u64(self.nms_iou_threshold.to_bits());
        enc.u64(self.max_detections as u64);
        enc.u64(self.max_proposals as u64);
        let bytes = enc
            .finish_checked()
            .map_err(|e| FusionLawError::MalformedWire(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }
}

/// Deterministic postprocessed detection mapped back to source-image pixel-edge coordinates.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FusedDetection {
    /// Class identifier.
    pub class_id: u32,
    /// Post-sigmoid score (`>= score_threshold`).
    pub score: f32,
    /// Source-image pixel-edge box `[x1, y1, x2, y2]` mapped by [`ResizeGeometry::source_box`].
    pub source_xyxy: [f64; 4],
}

impl FusedDetection {
    /// Bit-exact equality including exact IEEE-754 bit patterns of score and coordinates.
    #[must_use]
    pub fn bit_eq(&self, other: &Self) -> bool {
        self.class_id == other.class_id
            && self.score.to_bits() == other.score.to_bits()
            && self.source_xyxy[0].to_bits() == other.source_xyxy[0].to_bits()
            && self.source_xyxy[1].to_bits() == other.source_xyxy[1].to_bits()
            && self.source_xyxy[2].to_bits() == other.source_xyxy[2].to_bits()
            && self.source_xyxy[3].to_bits() == other.source_xyxy[3].to_bits()
    }
}

/// Sealed, verifiable receipt proving a preprocess/postprocess fusion law (`FSS-143`, `FSSMFU01` v1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelFusionLawReceipt {
    /// Wire format version (`1`).
    pub format_version: u32,
    /// Which algebraic fusion law was certified.
    pub law_kind: FusionLawKind,
    /// Canonical identity of the preprocess or postprocess program + geometry.
    pub program_digest: ContentDigest,
    /// Canonical digest of the raw input image or proposal batch.
    pub input_digest: ContentDigest,
    /// Canonical digest of the unfused multi-stage reference output.
    pub unfused_output_digest: ContentDigest,
    /// Canonical digest of the fused single-pass output.
    pub fused_output_digest: ContentDigest,
    /// Maximum observed ULP distance across all outputs (`0` for `CertifiedBitExact`).
    pub max_ulp_delta: u32,
    /// Intermediate buffer bytes materialized by the unfused multi-stage reference.
    pub unfused_intermediate_bytes: usize,
    /// Intermediate buffer bytes materialized by the fused single-pass implementation.
    pub fused_intermediate_bytes: usize,
    /// Intermediate bytes eliminated by fusion (`unfused - fused`).
    pub saved_intermediate_bytes: usize,
    /// Redundant work units (e.g., skipped sub-threshold proposals) eliminated by fusion.
    pub skipped_work_items: u64,
    /// Non-collapsed certification verdict.
    pub verdict: FusionVerificationVerdict,
    /// Domain-separated SHA-256 commitment under [`MODEL_FUSION_LAW_RECEIPT_DOMAIN`].
    pub receipt_digest: ContentDigest,
}

impl ModelFusionLawReceipt {
    /// Fusion receipts are derived verification metadata and NEVER grant effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Computes canonical SHA-256 receipt digest under [`MODEL_FUSION_LAW_RECEIPT_DOMAIN`].
    pub fn compute_digest(&self) -> Result<ContentDigest, FusionLawError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(MODEL_FUSION_LAW_RECEIPT_DOMAIN);
        self.encode_fields(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| FusionLawError::MalformedWire(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn encode_fields(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.u8(self.law_kind.tag());
        enc.digest(self.program_digest);
        enc.digest(self.input_digest);
        enc.digest(self.unfused_output_digest);
        enc.digest(self.fused_output_digest);
        enc.u32(self.max_ulp_delta);
        enc.u64(self.unfused_intermediate_bytes as u64);
        enc.u64(self.fused_intermediate_bytes as u64);
        enc.u64(self.saved_intermediate_bytes as u64);
        enc.u64(self.skipped_work_items);
        enc.u8(self.verdict.tag());
    }

    /// Validates structural invariants, verdict consistency, and canonical digest integrity.
    pub fn verify_self(&self) -> Result<(), FusionLawError> {
        if self.format_version != MODEL_FUSION_WIRE_VERSION {
            return Err(FusionLawError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        if self
            .unfused_intermediate_bytes
            .saturating_sub(self.fused_intermediate_bytes)
            != self.saved_intermediate_bytes
        {
            return Err(FusionLawError::MalformedWire(
                "saved_intermediate_bytes disagrees with unfused/fused counts".to_owned(),
            ));
        }
        match self.verdict {
            FusionVerificationVerdict::CertifiedBitExact => {
                if self.max_ulp_delta != 0 || self.unfused_output_digest != self.fused_output_digest
                {
                    return Err(FusionLawError::MalformedWire(
                        "CertifiedBitExact requires max_ulp_delta == 0 and equal output digests"
                            .to_owned(),
                    ));
                }
            }
            FusionVerificationVerdict::DivergenceDetected => {
                if self.max_ulp_delta == 0 && self.unfused_output_digest == self.fused_output_digest
                {
                    return Err(FusionLawError::MalformedWire(
                        "DivergenceDetected requires non-zero ULP or distinct output digests"
                            .to_owned(),
                    ));
                }
            }
        }
        if self.compute_digest()? != self.receipt_digest {
            return Err(FusionLawError::ChecksumMismatch);
        }
        Ok(())
    }

    /// Encodes into its versioned, checksummed `FSSMFU01` v1 binary wire envelope.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, FusionLawError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_fields(&mut enc);
        enc.digest(self.receipt_digest);
        let payload = enc
            .finish_checked()
            .map_err(|e| FusionLawError::MalformedWire(e.to_string()))?;
        let total = WIRE_HEADER_BYTES
            .checked_add(payload.len())
            .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
            .ok_or_else(|| FusionLawError::MalformedWire("wire length overflow".to_owned()))?;
        if total > MAX_MODEL_FUSION_WIRE_BYTES {
            return Err(FusionLawError::BoundsExceeded {
                observed: total,
                maximum: MAX_MODEL_FUSION_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&MODEL_FUSION_WIRE_MAGIC);
        out.extend_from_slice(&MODEL_FUSION_WIRE_VERSION.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        let mut hasher = Sha256Hasher::new();
        hasher.update(MODEL_FUSION_LAW_RECEIPT_DOMAIN.as_bytes());
        hasher.update(&out);
        let checksum = hasher
            .finalize()
            .map_err(|e| FusionLawError::MalformedWire(e.to_string()))?;
        out.extend_from_slice(&checksum);
        Ok(out)
    }

    /// Strictly decodes an `FSSMFU01` v1 binary wire envelope, failing closed on tamper or drift.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, FusionLawError> {
        let min_len = WIRE_HEADER_BYTES + WIRE_CHECKSUM_BYTES;
        if bytes.len() < min_len {
            return Err(FusionLawError::MalformedWire(format!(
                "wire length {} below minimum {min_len}",
                bytes.len()
            )));
        }
        if bytes.len() > MAX_MODEL_FUSION_WIRE_BYTES {
            return Err(FusionLawError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_MODEL_FUSION_WIRE_BYTES,
            });
        }
        if bytes[..8] != MODEL_FUSION_WIRE_MAGIC {
            return Err(FusionLawError::InvalidMagic);
        }
        let version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if version != MODEL_FUSION_WIRE_VERSION {
            return Err(FusionLawError::UnsupportedVersion { version });
        }
        let declared_len =
            u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
        let expected_total = WIRE_HEADER_BYTES
            .checked_add(declared_len)
            .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
            .ok_or_else(|| {
                FusionLawError::MalformedWire("declared payload length overflow".to_owned())
            })?;
        if bytes.len() != expected_total {
            return Err(FusionLawError::MalformedWire(format!(
                "wire length {} disagrees with declared payload length {declared_len}",
                bytes.len()
            )));
        }
        let split_at = bytes.len() - WIRE_CHECKSUM_BYTES;
        let (body, trailer) = bytes.split_at(split_at);
        let mut hasher = Sha256Hasher::new();
        hasher.update(MODEL_FUSION_LAW_RECEIPT_DOMAIN.as_bytes());
        hasher.update(body);
        let computed = hasher
            .finalize()
            .map_err(|e| FusionLawError::MalformedWire(e.to_string()))?;
        if computed.as_slice() != trailer {
            return Err(FusionLawError::ChecksumMismatch);
        }

        let mut dec = CanonicalDecoder::new(&body[WIRE_HEADER_BYTES..]);
        let format_version = dec
            .u32()
            .map_err(|e| FusionLawError::MalformedWire(e.to_string()))?;
        let law_kind = FusionLawKind::from_tag(
            dec.u8()
                .map_err(|e| FusionLawError::MalformedWire(e.to_string()))?,
        )?;
        let program_digest = dec
            .digest()
            .map_err(|e| FusionLawError::MalformedWire(e.to_string()))?;
        let input_digest = dec
            .digest()
            .map_err(|e| FusionLawError::MalformedWire(e.to_string()))?;
        let unfused_output_digest = dec
            .digest()
            .map_err(|e| FusionLawError::MalformedWire(e.to_string()))?;
        let fused_output_digest = dec
            .digest()
            .map_err(|e| FusionLawError::MalformedWire(e.to_string()))?;
        let max_ulp_delta = dec
            .u32()
            .map_err(|e| FusionLawError::MalformedWire(e.to_string()))?;
        let unfused_intermediate_bytes = decode_usize(&mut dec)?;
        let fused_intermediate_bytes = decode_usize(&mut dec)?;
        let saved_intermediate_bytes = decode_usize(&mut dec)?;
        let skipped_work_items = dec
            .u64()
            .map_err(|e| FusionLawError::MalformedWire(e.to_string()))?;
        let verdict = FusionVerificationVerdict::from_tag(
            dec.u8()
                .map_err(|e| FusionLawError::MalformedWire(e.to_string()))?,
        )?;
        let receipt_digest = dec
            .digest()
            .map_err(|e| FusionLawError::MalformedWire(e.to_string()))?;
        dec.ensure_finished()
            .map_err(|e| FusionLawError::MalformedWire(e.to_string()))?;

        let receipt = Self {
            format_version,
            law_kind,
            program_digest,
            input_digest,
            unfused_output_digest,
            fused_output_digest,
            max_ulp_delta,
            unfused_intermediate_bytes,
            fused_intermediate_bytes,
            saved_intermediate_bytes,
            skipped_work_items,
            verdict,
            receipt_digest,
        };
        receipt.verify_self()?;
        Ok(receipt)
    }
}

/// Deliberately unfused 4-stage preprocess reference oracle (`Resize -> Color -> Scale -> NCHW`).
///
/// Returns `(output_tensor, geometry, intermediate_stage_bytes)` for differential fusion proofs.
pub fn unfused_reference_preprocess(
    program: &PreprocessProgram,
    image: ImageBytes<'_>,
    options: ResizeOptions,
    cx: &ScalarExecCx,
) -> Result<(Tensor, ResizeGeometry, usize), FusionLawError> {
    cx.checkpoint("fusion-oracle:unfused-preprocess")?;
    let th = program.target_height;
    let tw = program.target_width;
    if image.height == 0 || image.width == 0 || th == 0 || tw == 0 {
        return Err(FusionLawError::InvalidConfig(
            "image and target dimensions must be positive".to_owned(),
        ));
    }
    let out_c = match (program.channel_transform, image.channels) {
        (ChannelTransform::Rgb, 3) => 3,
        (ChannelTransform::LumaOnly, 1 | 3) => 1,
        _ => {
            return Err(FusionLawError::InvalidConfig(
                "incompatible channel transform and source channels".to_owned(),
            ));
        }
    };
    let expected_len = image
        .height
        .checked_mul(image.width)
        .and_then(|v| v.checked_mul(image.channels))
        .ok_or_else(|| FusionLawError::InvalidConfig("input length overflow".to_owned()))?;
    if image.bytes.len() != expected_len {
        return Err(FusionLawError::InvalidConfig(
            "image bytes length disagrees with HWC dimensions".to_owned(),
        ));
    }
    let (ih, iw) = match options.aspect {
        ResizeAspect::Stretch => (th, tw),
        ResizeAspect::Letterbox(_) => {
            if (tw as u128) * (image.height as u128) <= (th as u128) * (image.width as u128) {
                (
                    (((image.height as u128) * (tw as u128) / image.width as u128) as usize).max(1),
                    tw,
                )
            } else {
                (
                    th,
                    (((image.width as u128) * (th as u128) / image.height as u128) as usize).max(1),
                )
            }
        }
    };
    let g = ResizeGeometry {
        source_height: image.height,
        source_width: image.width,
        target_height: th,
        target_width: tw,
        image_height: ih,
        image_width: iw,
        top: (th - ih) / 2,
        left: (tw - iw) / 2,
    };

    // Stage 1: Unfused HWC F32 resized/letterboxed buffer.
    let mut stage1_hwc = vec![0.0_f32; th * tw * image.channels];
    for y in 0..th {
        for x in 0..tw {
            for c in 0..image.channels {
                let val = if y < g.top
                    || y - g.top >= g.image_height
                    || x < g.left
                    || x - g.left >= g.image_width
                {
                    match options.aspect {
                        ResizeAspect::Letterbox(pad) => f32::from(pad),
                        ResizeAspect::Stretch => 0.0_f32,
                    }
                } else {
                    oracle_sample(image, y - g.top, x - g.left, c, g, options.filter)
                };
                stage1_hwc[(y * tw + x) * image.channels + c] = val;
            }
        }
    }

    // Stage 2: Unfused HWC F32 channel conversion buffer.
    let mut stage2_color = vec![0.0_f32; th * tw * out_c];
    for pix in 0..(th * tw) {
        match program.channel_transform {
            ChannelTransform::Rgb => {
                for c in 0..3 {
                    stage2_color[pix * 3 + c] = stage1_hwc[pix * 3 + c];
                }
            }
            ChannelTransform::LumaOnly => {
                stage2_color[pix] = if image.channels == 1 {
                    stage1_hwc[pix]
                } else {
                    0.299_f32 * stage1_hwc[pix * 3]
                        + 0.587_f32 * stage1_hwc[pix * 3 + 1]
                        + 0.114_f32 * stage1_hwc[pix * 3 + 2]
                };
            }
        }
    }

    // Stage 3: Unfused HWC F32 unit normalization buffer.
    let scale = if program.scale_to_unit {
        1.0_f32 / 255.0_f32
    } else {
        1.0_f32
    };
    let stage3_scaled: Vec<f32> = stage2_color.iter().map(|&v| v * scale).collect();

    // Stage 4: Unfused HWC -> NCHW layout transpose buffer.
    let plane = th * tw;
    let mut nchw = vec![0.0_f32; out_c * plane];
    for pix in 0..plane {
        for c in 0..out_c {
            nchw[c * plane + pix] = stage3_scaled[pix * out_c + c];
        }
    }

    let intermediate_bytes = (stage1_hwc.len() + stage2_color.len() + stage3_scaled.len()) * 4;
    let tensor = Tensor::from_values(
        Shape::new(vec![1, out_c, th, tw]).map_err(|e| FusionLawError::Execution(e.to_string()))?,
        &nchw,
        image.generation,
    )
    .map_err(|e| FusionLawError::Execution(e.to_string()))?;
    Ok((tensor, g, intermediate_bytes))
}

/// Certifies 0-ULP equivalence between fused single-pass [`PreprocessProgram::execute_resized_bytes`]
/// and the 4-stage unfused reference oracle [`unfused_reference_preprocess`].
pub fn certify_preprocess_fusion(
    program: &PreprocessProgram,
    image: ImageBytes<'_>,
    options: ResizeOptions,
    cx: &ScalarExecCx,
) -> Result<(Tensor, ResizeGeometry, ModelFusionLawReceipt), FusionLawError> {
    cx.checkpoint("fusion:preprocess-begin")?;
    let fused = program.execute_resized_bytes(image, options, cx)?;
    let (unfused_tensor, unfused_geo, unfused_intermediate_bytes) =
        unfused_reference_preprocess(program, image, options, cx)?;
    if fused.geometry != unfused_geo {
        return Err(FusionLawError::FusionDivergence(
            "fused resize geometry disagrees with unfused reference".to_owned(),
        ));
    }
    let fused_vals = fused
        .tensor
        .to_vec::<f32>()
        .map_err(|e| FusionLawError::Execution(e.to_string()))?;
    let unfused_vals = unfused_tensor
        .to_vec::<f32>()
        .map_err(|e| FusionLawError::Execution(e.to_string()))?;
    let max_ulp = compute_max_ulp(&fused_vals, &unfused_vals)?;
    let verdict = if max_ulp == 0
        && fused_vals
            .iter()
            .zip(&unfused_vals)
            .all(|(a, b)| a.to_bits() == b.to_bits())
    {
        FusionVerificationVerdict::CertifiedBitExact
    } else {
        FusionVerificationVerdict::DivergenceDetected
    };
    let canonical_unfused_digest = hash_f32_slice(&unfused_vals, "preprocess_output");
    let canonical_fused_digest = hash_f32_slice(&fused_vals, "preprocess_output");

    if verdict != FusionVerificationVerdict::CertifiedBitExact {
        return Err(FusionLawError::FusionDivergence(format!(
            "preprocess fusion diverged with max_ulp={max_ulp}"
        )));
    }

    let mut receipt = ModelFusionLawReceipt {
        format_version: MODEL_FUSION_WIRE_VERSION,
        law_kind: FusionLawKind::PreprocessResizeColorScaleNchw,
        program_digest: fused.program_digest,
        input_digest: fused.input_digest,
        unfused_output_digest: canonical_unfused_digest,
        fused_output_digest: canonical_fused_digest,
        max_ulp_delta: max_ulp,
        unfused_intermediate_bytes,
        fused_intermediate_bytes: 0,
        saved_intermediate_bytes: unfused_intermediate_bytes,
        skipped_work_items: 0,
        verdict,
        receipt_digest: ContentDigest::sha256(b"unsealed-fusion-receipt"),
    };
    receipt.receipt_digest = receipt.compute_digest()?;
    receipt.verify_self()?;
    Ok((fused.tensor, fused.geometry, receipt))
}

/// Certifies the identity-resize composition law: `Resize(H, W -> H, W, Stretch)` fused with
/// [`PreprocessProgram`] is 0-ULP bit-identical to strict-size [`PreprocessProgram::execute_bytes`].
pub fn certify_identity_resize_fusion(
    program: &PreprocessProgram,
    image: ImageBytes<'_>,
    filter: ResizeFilter,
    budget: crate::ExecBudget,
    cx: &ScalarExecCx,
) -> Result<ModelFusionLawReceipt, FusionLawError> {
    cx.checkpoint("fusion:identity-resize")?;
    if image.height != program.target_height || image.width != program.target_width {
        return Err(FusionLawError::InvalidConfig(
            "identity resize law requires image dimensions == program target dimensions".to_owned(),
        ));
    }
    let strict = program.execute_bytes(
        image.bytes,
        image.height,
        image.width,
        image.channels,
        image.generation,
    )?;
    let resized = program.execute_resized_bytes(
        image,
        ResizeOptions {
            filter,
            aspect: ResizeAspect::Stretch,
            budget,
        },
        cx,
    )?;
    let strict_vals = strict
        .to_vec::<f32>()
        .map_err(|e| FusionLawError::Execution(e.to_string()))?;
    let resized_vals = resized
        .tensor
        .to_vec::<f32>()
        .map_err(|e| FusionLawError::Execution(e.to_string()))?;
    let max_ulp = compute_max_ulp(&resized_vals, &strict_vals)?;
    if max_ulp != 0 {
        return Err(FusionLawError::FusionDivergence(format!(
            "identity resize diverged from strict execute_bytes by {max_ulp} ULPs"
        )));
    }
    let strict_digest = hash_f32_slice(&strict_vals, "preprocess_output");
    let resized_digest = hash_f32_slice(&resized_vals, "preprocess_output");
    let mut receipt = ModelFusionLawReceipt {
        format_version: MODEL_FUSION_WIRE_VERSION,
        law_kind: FusionLawKind::PreprocessIdentityResize,
        program_digest: resized.program_digest,
        input_digest: resized.input_digest,
        unfused_output_digest: strict_digest,
        fused_output_digest: resized_digest,
        max_ulp_delta: 0,
        unfused_intermediate_bytes: 0,
        fused_intermediate_bytes: 0,
        saved_intermediate_bytes: 0,
        skipped_work_items: 0,
        verdict: FusionVerificationVerdict::CertifiedBitExact,
        receipt_digest: ContentDigest::sha256(b"unsealed-fusion-receipt"),
    };
    receipt.receipt_digest = receipt.compute_digest()?;
    receipt.verify_self()?;
    Ok(receipt)
}

/// Explicit 4-stage unfused postprocess reference oracle:
/// `sigmoid(all) -> threshold filter -> ResizeGeometry::source_box -> deterministic class-aware NMS`.
pub fn unfused_reference_postprocess(
    proposals: &[RawBoxProposal],
    geometry: ResizeGeometry,
    config: PostprocessFusionConfig,
    cx: &ScalarExecCx,
) -> Result<(Vec<FusedDetection>, usize), FusionLawError> {
    cx.checkpoint("fusion-oracle:unfused-postprocess")?;
    config.validate()?;
    if proposals.len() > config.max_proposals {
        return Err(FusionLawError::BoundsExceeded {
            observed: proposals.len(),
            maximum: config.max_proposals,
        });
    }

    // Stage 1: Unfused full score buffer over EVERY proposal.
    let scores: Vec<f32> = proposals
        .iter()
        .map(|p| {
            if p.logit.is_finite() {
                deterministic_sigmoid_f32(p.logit)
            } else {
                f32::NAN
            }
        })
        .collect();

    // Stage 2: Threshold filter buffer.
    let mut passed: Vec<(usize, f32)> = Vec::new();
    for (idx, &score) in scores.iter().enumerate() {
        if score.is_finite() && score >= config.score_threshold {
            passed.push((idx, score));
        }
    }

    // Stage 3: Unletterbox coordinate transform buffer.
    let mut unboxed: Vec<FusedDetection> = Vec::new();
    for &(idx, score) in &passed {
        if let Some(source_xyxy) = geometry.source_box(proposals[idx].model_xyxy) {
            unboxed.push(FusedDetection {
                class_id: proposals[idx].class_id,
                score,
                source_xyxy,
            });
        }
    }

    let intermediate_bytes = scores.len() * 4 + passed.len() * 16 + unboxed.len() * 40;
    let kept = deterministic_class_nms(unboxed, config.nms_iou_threshold, config.max_detections);
    Ok((kept, intermediate_bytes))
}

/// Fused single-pass postprocess (`MonotonicLogitPrefilter + Sigmoid + Unletterbox + NMS`).
///
/// Uses a conservative 2-ULP-lowered inverse-sigmoid bound (`logit_lower_bound`) so sub-threshold
/// proposals skip both sigmoid evaluation and `ResizeGeometry::source_box` without ever risking a
/// boundary false negative. Returns `(detections, skipped_subthreshold_count, intermediate_bytes)`.
pub fn fused_postprocess_decode_nms(
    proposals: &[RawBoxProposal],
    geometry: ResizeGeometry,
    config: PostprocessFusionConfig,
    cx: &ScalarExecCx,
) -> Result<(Vec<FusedDetection>, u64, usize), FusionLawError> {
    cx.checkpoint("fusion:fused-postprocess")?;
    config.validate()?;
    if proposals.len() > config.max_proposals {
        return Err(FusionLawError::BoundsExceeded {
            observed: proposals.len(),
            maximum: config.max_proposals,
        });
    }

    // Conservative monotone lower bound on logit `x` such that `sigmoid(x) >= threshold`.
    let p = f64::from(config.score_threshold);
    let exact_logit = (p / (1.0 - p)).ln() as f32;
    let conservative_logit_lb = exact_logit.next_down().next_down();

    let mut skipped: u64 = 0;
    let mut candidates: Vec<FusedDetection> = Vec::new();
    for (idx, prop) in proposals.iter().enumerate() {
        if idx.is_multiple_of(1024) {
            cx.checkpoint("fusion:postprocess-proposal")?;
        }
        if !prop.logit.is_finite() || prop.logit < conservative_logit_lb {
            skipped = skipped.saturating_add(1);
            continue;
        }
        let score = deterministic_sigmoid_f32(prop.logit);
        if !score.is_finite() || score < config.score_threshold {
            continue;
        }
        if let Some(source_xyxy) = geometry.source_box(prop.model_xyxy) {
            candidates.push(FusedDetection {
                class_id: prop.class_id,
                score,
                source_xyxy,
            });
        }
    }
    let fused_intermediate_bytes = candidates.len() * 40;
    let kept = deterministic_class_nms(candidates, config.nms_iou_threshold, config.max_detections);
    Ok((kept, skipped, fused_intermediate_bytes))
}

/// Certifies bit-exact equivalence between [`fused_postprocess_decode_nms`] and
/// [`unfused_reference_postprocess`], sealing a verifiable `FSSMFU01` v1 receipt.
pub fn certify_postprocess_fusion(
    proposals: &[RawBoxProposal],
    geometry: ResizeGeometry,
    config: PostprocessFusionConfig,
    cx: &ScalarExecCx,
) -> Result<(Vec<FusedDetection>, ModelFusionLawReceipt), FusionLawError> {
    let (unfused, unfused_bytes) = unfused_reference_postprocess(proposals, geometry, config, cx)?;
    let (fused, skipped, fused_bytes) =
        fused_postprocess_decode_nms(proposals, geometry, config, cx)?;

    if unfused.len() != fused.len() || !unfused.iter().zip(&fused).all(|(a, b)| a.bit_eq(b)) {
        return Err(FusionLawError::FusionDivergence(format!(
            "postprocess fusion diverged: unfused_len={} fused_len={}",
            unfused.len(),
            fused.len()
        )));
    }

    let mut prog_enc = CanonicalEncoder::new();
    prog_enc.text(MODEL_FUSION_LAW_RECEIPT_DOMAIN);
    prog_enc.text("postprocess_program");
    prog_enc.digest(config.digest()?);
    prog_enc.u64(geometry.source_height as u64);
    prog_enc.u64(geometry.source_width as u64);
    prog_enc.u64(geometry.target_height as u64);
    prog_enc.u64(geometry.target_width as u64);
    prog_enc.u64(geometry.image_height as u64);
    prog_enc.u64(geometry.image_width as u64);
    prog_enc.u64(geometry.top as u64);
    prog_enc.u64(geometry.left as u64);
    let program_digest = ContentDigest::sha256(
        &prog_enc
            .finish_checked()
            .map_err(|e| FusionLawError::MalformedWire(e.to_string()))?,
    );

    let input_digest = hash_proposals(proposals);
    let unfused_digest = hash_detections(&unfused);
    let fused_digest = hash_detections(&fused);

    let mut receipt = ModelFusionLawReceipt {
        format_version: MODEL_FUSION_WIRE_VERSION,
        law_kind: FusionLawKind::PostprocessThresholdUnletterboxNms,
        program_digest,
        input_digest,
        unfused_output_digest: unfused_digest,
        fused_output_digest: fused_digest,
        max_ulp_delta: 0,
        unfused_intermediate_bytes: unfused_bytes,
        fused_intermediate_bytes: fused_bytes,
        saved_intermediate_bytes: unfused_bytes.saturating_sub(fused_bytes),
        skipped_work_items: skipped,
        verdict: FusionVerificationVerdict::CertifiedBitExact,
        receipt_digest: ContentDigest::sha256(b"unsealed-fusion-receipt"),
    };
    receipt.receipt_digest = receipt.compute_digest()?;
    receipt.verify_self()?;
    Ok((fused, receipt))
}

fn deterministic_class_nms(
    mut candidates: Vec<FusedDetection>,
    iou_threshold: f64,
    max_detections: usize,
) -> Vec<FusedDetection> {
    candidates.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.class_id.cmp(&b.class_id))
            .then_with(|| a.source_xyxy[0].total_cmp(&b.source_xyxy[0]))
            .then_with(|| a.source_xyxy[1].total_cmp(&b.source_xyxy[1]))
            .then_with(|| a.source_xyxy[2].total_cmp(&b.source_xyxy[2]))
            .then_with(|| a.source_xyxy[3].total_cmp(&b.source_xyxy[3]))
    });
    let mut kept: Vec<FusedDetection> = Vec::with_capacity(max_detections.min(candidates.len()));
    for cand in candidates {
        if kept.len() >= max_detections {
            break;
        }
        let suppressed = kept.iter().any(|k| {
            k.class_id == cand.class_id && box_iou(k.source_xyxy, cand.source_xyxy) > iou_threshold
        });
        if !suppressed {
            kept.push(cand);
        }
    }
    kept
}

fn box_iou(a: [f64; 4], b: [f64; 4]) -> f64 {
    let ix1 = a[0].max(b[0]);
    let iy1 = a[1].max(b[1]);
    let ix2 = a[2].min(b[2]);
    let iy2 = a[3].min(b[3]);
    let iw = (ix2 - ix1).max(0.0);
    let ih = (iy2 - iy1).max(0.0);
    let inter = iw * ih;
    let area_a = (a[2] - a[0]).max(0.0) * (a[3] - a[1]).max(0.0);
    let area_b = (b[2] - b[0]).max(0.0) * (b[3] - b[1]).max(0.0);
    let union = area_a + area_b - inter;
    if union <= 0.0 { 0.0 } else { inter / union }
}

fn oracle_sample(
    image: ImageBytes<'_>,
    y: usize,
    x: usize,
    channel: usize,
    g: ResizeGeometry,
    filter: ResizeFilter,
) -> f32 {
    let at = |sy: usize, sx: usize| {
        f64::from(image.bytes[(sy * image.width + sx) * image.channels + channel])
    };
    match filter {
        ResizeFilter::Nearest => {
            let sy = ((y as u128) * (image.height as u128) / g.image_height as u128) as usize;
            let sx = ((x as u128) * (image.width as u128) / g.image_width as u128) as usize;
            at(sy, sx) as f32
        }
        ResizeFilter::Bilinear => {
            let sy = ((y as f64 + 0.5) * image.height as f64 / g.image_height as f64 - 0.5)
                .clamp(0.0, (image.height - 1) as f64);
            let sx = ((x as f64 + 0.5) * image.width as f64 / g.image_width as f64 - 0.5)
                .clamp(0.0, (image.width - 1) as f64);
            let y0 = sy as usize;
            let x0 = sx as usize;
            let y1 = (y0 + 1).min(image.height - 1);
            let x1 = (x0 + 1).min(image.width - 1);
            let fy = sy - y0 as f64;
            let fx = sx - x0 as f64;
            let top = at(y0, x0) * (1.0 - fx) + at(y0, x1) * fx;
            let bottom = at(y1, x0) * (1.0 - fx) + at(y1, x1) * fx;
            (top * (1.0 - fy) + bottom * fy) as f32
        }
    }
}

fn compute_max_ulp(a: &[f32], b: &[f32]) -> Result<u32, FusionLawError> {
    if a.len() != b.len() {
        return Err(FusionLawError::FusionDivergence(format!(
            "tensor length mismatch: {} != {}",
            a.len(),
            b.len()
        )));
    }
    let mut max_ulp = 0_u32;
    for (&x, &y) in a.iter().zip(b.iter()) {
        if !x.is_finite() || !y.is_finite() {
            return Err(FusionLawError::FusionDivergence(
                "non-finite value encountered during fusion certification".to_owned(),
            ));
        }
        if x.to_bits() != y.to_bits() {
            let ord_x = f32_to_ordered_u32(x);
            let ord_y = f32_to_ordered_u32(y);
            max_ulp = max_ulp.max(ord_x.abs_diff(ord_y));
        }
    }
    Ok(max_ulp)
}

fn f32_to_ordered_u32(v: f32) -> u32 {
    let bits = v.to_bits();
    if (bits & 0x8000_0000) != 0 {
        !bits
    } else {
        bits | 0x8000_0000
    }
}

fn hash_f32_slice(values: &[f32], tag: &str) -> ContentDigest {
    let mut h = Sha256Hasher::new();
    h.update(MODEL_FUSION_LAW_RECEIPT_DOMAIN.as_bytes());
    h.update(tag.as_bytes());
    h.update(&(values.len() as u64).to_be_bytes());
    for v in values {
        h.update(&v.to_bits().to_be_bytes());
    }
    ContentDigest::sha256(&h.finalize().unwrap_or([0_u8; 32]))
}

fn hash_proposals(proposals: &[RawBoxProposal]) -> ContentDigest {
    let mut h = Sha256Hasher::new();
    h.update(MODEL_FUSION_LAW_RECEIPT_DOMAIN.as_bytes());
    h.update(b"raw_proposals");
    h.update(&(proposals.len() as u64).to_be_bytes());
    for p in proposals {
        h.update(&p.class_id.to_be_bytes());
        h.update(&p.logit.to_bits().to_be_bytes());
        for coord in p.model_xyxy {
            h.update(&coord.to_bits().to_be_bytes());
        }
    }
    ContentDigest::sha256(&h.finalize().unwrap_or([0_u8; 32]))
}

fn hash_detections(detections: &[FusedDetection]) -> ContentDigest {
    let mut h = Sha256Hasher::new();
    h.update(MODEL_FUSION_LAW_RECEIPT_DOMAIN.as_bytes());
    h.update(b"fused_detections");
    h.update(&(detections.len() as u64).to_be_bytes());
    for d in detections {
        h.update(&d.class_id.to_be_bytes());
        h.update(&d.score.to_bits().to_be_bytes());
        for coord in d.source_xyxy {
            h.update(&coord.to_bits().to_be_bytes());
        }
    }
    ContentDigest::sha256(&h.finalize().unwrap_or([0_u8; 32]))
}

fn decode_usize(dec: &mut CanonicalDecoder<'_>) -> Result<usize, FusionLawError> {
    let raw = dec
        .u64()
        .map_err(|e| FusionLawError::MalformedWire(e.to_string()))?;
    usize::try_from(raw)
        .map_err(|_| FusionLawError::MalformedWire("usize overflow on decode".to_owned()))
}
