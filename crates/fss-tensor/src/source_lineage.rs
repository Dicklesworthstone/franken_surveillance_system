#![forbid(unsafe_code)]
//! Deterministic source-to-tensor span and transform lineage (`FSS-120`, bead `fss-x4a.12.19`).
//!
//! Proves the complete, tamper-evident causal chain from immutable source media byte spans to a
//! decoded frame and through every ordered preprocessing/masking transform to the exact canonical
//! output [`Tensor`] (`INV-003`, `INV-040`, `DOC-041`).
//!
//! Core invariants:
//! - Every lineage record MUST cite at least one valid checked [`SourceByteSpan`] and at least
//!   one [`TransformStep`] starting with [`TransformStep::Decode`].
//! - No derived tensor can ever impersonate raw source custody: `is_source_custody` is strictly
//!   `false` on construction AND enforced fail-closed on canonical decode.
//! - Forbidden `"latest"` mutable aliases are rejected across codec, kernel, and generation IDs.
//! - [`SourceToTensorLineage::verify_against_tensor`] binds exact dtype, shape, generation, and
//!   canonical `fss-tensor::canonical::tensor_digest`.

use core::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, Generation,
};

use crate::buffer_accounting::MAX_OWNER_ID_BYTES;
use crate::canonical::tensor_canonical_digest;
use crate::dtype::DType;
use crate::shape::MAX_TENSOR_RANK;
use crate::tensor::Tensor;

/// Registered digest domain for canonical source-to-tensor lineage receipts
/// (`SCHEMA-DOMAIN-TENSOR-SOURCE-LINEAGE-001`).
pub const SOURCE_TO_TENSOR_LINEAGE_DOMAIN: &str = "fss.tensor.source_to_tensor_lineage.v1";

/// Canonical binary format version for [`SourceToTensorLineage`].
pub const SOURCE_TO_TENSOR_LINEAGE_FORMAT_VERSION: u32 = 1;

/// Maximum source byte spans bound to a single derived tensor lineage.
pub const MAX_SOURCE_SPANS: usize = 1024;

/// Maximum transform steps in one preprocessing/masking pipeline.
pub const MAX_TRANSFORM_STEPS: usize = 64;

/// One exact immutable source media byte span contributing to a decoded frame / tensor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceByteSpan {
    /// Content digest of the retained source object or packet batch.
    pub source_object_digest: ContentDigest,
    /// Inclusive byte offset inside the source object.
    pub byte_offset: u64,
    /// Exact non-zero byte length of the span.
    pub byte_len: u64,
    /// Presentation timestamp in nanoseconds.
    pub pts_ns: i128,
    /// Decode timestamp in nanoseconds.
    pub dts_ns: i128,
    /// Immutable source stream generation fence (`!= 0`).
    pub stream_generation: Generation,
}

impl SourceByteSpan {
    /// Validates span bounds and checked `byte_offset + byte_len` arithmetic.
    pub fn validate(self) -> Result<(), LineageError> {
        if self.byte_len == 0 {
            return Err(LineageError::InvalidSpan("zero_byte_len"));
        }
        if self.stream_generation.0 == 0 {
            return Err(LineageError::InvalidSpan("zero_stream_generation"));
        }
        if self.byte_offset.checked_add(self.byte_len).is_none() {
            return Err(LineageError::ArithmeticOverflow);
        }
        Ok(())
    }
}

impl CanonicalEncode for SourceByteSpan {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.digest(self.source_object_digest);
        encoder.u64(self.byte_offset);
        encoder.u64(self.byte_len);
        encoder.i128(self.pts_ns);
        encoder.i128(self.dts_ns);
        encoder.u64(self.stream_generation.0);
    }
}

impl CanonicalDecode for SourceByteSpan {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let span = Self {
            source_object_digest: decoder.digest()?,
            byte_offset: decoder.u64()?,
            byte_len: decoder.u64()?,
            pts_ns: decoder.i128()?,
            dts_ns: decoder.i128()?,
            stream_generation: Generation(decoder.u64()?),
        };
        if span.validate().is_err() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(span)
    }
}

/// One ordered, deterministic transform applied between source bytes and output tensor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransformStep {
    /// Pure-Rust scalar decode from source spans into decoded pixels.
    Decode {
        /// Codec profile ID (e.g., `fss.codec.h264.scalar.v1`).
        codec_id: String,
        /// Pinned immutable decoder generation (`!= 0`).
        decoder_generation: Generation,
    },
    /// Deterministic spatial crop with checked coordinates and positive extent.
    Crop {
        /// Left pixel coordinate.
        x: u32,
        /// Top pixel coordinate.
        y: u32,
        /// Positive cropped width.
        width: u32,
        /// Positive cropped height.
        height: u32,
    },
    /// Deterministic spatial resize with pinned kernel profile.
    Resize {
        /// Positive target width.
        dst_width: u32,
        /// Positive target height.
        dst_height: u32,
        /// Pinned resize kernel ID (e.g., `bilinear-q16-v1`).
        kernel_id: String,
    },
    /// Deterministic color space conversion.
    ColorConvert {
        /// Input color space label (e.g., `yuv420p-bt709`).
        from_space: String,
        /// Output color space label (e.g., `rgb8-full`).
        to_space: String,
    },
    /// Deterministic affine normalization to target tensor dtype.
    Normalize {
        /// Fixed-point Q16 scale factor (`!= 0`).
        scale_q16: i32,
        /// Fixed-point Q16 offset.
        offset_q16: i32,
        /// Target tensor element dtype.
        output_dtype: DType,
    },
    /// Privacy zone masking applied prior to inference or export.
    PrivacyMask {
        /// Digest of the exact privacy mask policy generation applied.
        mask_policy_digest: ContentDigest,
        /// Number of masked regions applied (`>= 1`).
        masked_region_count: u32,
    },
}

fn validate_clean_id(val: &str, field: &'static str) -> Result<(), LineageError> {
    if val.is_empty()
        || val.len() > MAX_OWNER_ID_BYTES
        || val
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(LineageError::InvalidTransform(field));
    }
    if val
        .split(['-', '_', ':', '/', '@', '.', '+'])
        .any(|tok| tok.eq_ignore_ascii_case("latest"))
    {
        return Err(LineageError::ForbiddenLatestAlias(field));
    }
    Ok(())
}

impl TransformStep {
    /// Validates parameters and generation hygiene of one transform step.
    pub fn validate(&self) -> Result<(), LineageError> {
        match self {
            Self::Decode {
                codec_id,
                decoder_generation,
            } => {
                validate_clean_id(codec_id, "codec_id")?;
                if decoder_generation.0 == 0 {
                    return Err(LineageError::InvalidTransform("decoder_generation_zero"));
                }
            }
            Self::Crop {
                x,
                y,
                width,
                height,
            } => {
                if *width == 0 || *height == 0 {
                    return Err(LineageError::InvalidTransform("crop_zero_dimensions"));
                }
                if x.checked_add(*width).is_none() || y.checked_add(*height).is_none() {
                    return Err(LineageError::ArithmeticOverflow);
                }
            }
            Self::Resize {
                dst_width,
                dst_height,
                kernel_id,
            } => {
                if *dst_width == 0 || *dst_height == 0 {
                    return Err(LineageError::InvalidTransform("resize_zero_dimensions"));
                }
                validate_clean_id(kernel_id, "kernel_id")?;
            }
            Self::ColorConvert {
                from_space,
                to_space,
            } => {
                validate_clean_id(from_space, "from_space")?;
                validate_clean_id(to_space, "to_space")?;
            }
            Self::Normalize { scale_q16, .. } => {
                if *scale_q16 == 0 {
                    return Err(LineageError::InvalidTransform("normalize_zero_scale"));
                }
            }
            Self::PrivacyMask {
                masked_region_count,
                ..
            } => {
                if *masked_region_count == 0 {
                    return Err(LineageError::InvalidTransform("zero_masked_regions"));
                }
            }
        }
        Ok(())
    }
}

fn dtype_tag(dtype: DType) -> u8 {
    match dtype {
        DType::U8 => 1,
        DType::I8 => 2,
        DType::I16 => 3,
        DType::I32 => 4,
        DType::I64 => 5,
        DType::U16 => 6,
        DType::U32 => 7,
        DType::U64 => 8,
        DType::F16 => 9,
        DType::BF16 => 10,
        DType::F32 => 11,
        DType::F64 => 12,
        DType::Bool => 13,
    }
}

fn decode_dtype_tag(tag: u8) -> Result<DType, ContractError> {
    match tag {
        1 => Ok(DType::U8),
        2 => Ok(DType::I8),
        3 => Ok(DType::I16),
        4 => Ok(DType::I32),
        5 => Ok(DType::I64),
        6 => Ok(DType::U16),
        7 => Ok(DType::U32),
        8 => Ok(DType::U64),
        9 => Ok(DType::F16),
        10 => Ok(DType::BF16),
        11 => Ok(DType::F32),
        12 => Ok(DType::F64),
        13 => Ok(DType::Bool),
        _ => Err(ContractError::InvalidIdentifier),
    }
}

impl CanonicalEncode for TransformStep {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::Decode {
                codec_id,
                decoder_generation,
            } => {
                encoder.u8(1);
                encoder.text(codec_id);
                encoder.u64(decoder_generation.0);
            }
            Self::Crop {
                x,
                y,
                width,
                height,
            } => {
                encoder.u8(2);
                encoder.u32(*x);
                encoder.u32(*y);
                encoder.u32(*width);
                encoder.u32(*height);
            }
            Self::Resize {
                dst_width,
                dst_height,
                kernel_id,
            } => {
                encoder.u8(3);
                encoder.u32(*dst_width);
                encoder.u32(*dst_height);
                encoder.text(kernel_id);
            }
            Self::ColorConvert {
                from_space,
                to_space,
            } => {
                encoder.u8(4);
                encoder.text(from_space);
                encoder.text(to_space);
            }
            Self::Normalize {
                scale_q16,
                offset_q16,
                output_dtype,
            } => {
                encoder.u8(5);
                encoder.i128(i128::from(*scale_q16));
                encoder.i128(i128::from(*offset_q16));
                encoder.u8(dtype_tag(*output_dtype));
            }
            Self::PrivacyMask {
                mask_policy_digest,
                masked_region_count,
            } => {
                encoder.u8(6);
                encoder.digest(*mask_policy_digest);
                encoder.u32(*masked_region_count);
            }
        }
    }
}

impl CanonicalDecode for TransformStep {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let step = match decoder.u8()? {
            1 => Self::Decode {
                codec_id: decoder.text()?.to_owned(),
                decoder_generation: Generation(decoder.u64()?),
            },
            2 => Self::Crop {
                x: decoder.u32()?,
                y: decoder.u32()?,
                width: decoder.u32()?,
                height: decoder.u32()?,
            },
            3 => Self::Resize {
                dst_width: decoder.u32()?,
                dst_height: decoder.u32()?,
                kernel_id: decoder.text()?.to_owned(),
            },
            4 => Self::ColorConvert {
                from_space: decoder.text()?.to_owned(),
                to_space: decoder.text()?.to_owned(),
            },
            5 => {
                let scale_q16 =
                    i32::try_from(decoder.i128()?).map_err(|_| ContractError::InvalidIdentifier)?;
                let offset_q16 =
                    i32::try_from(decoder.i128()?).map_err(|_| ContractError::InvalidIdentifier)?;
                let output_dtype = decode_dtype_tag(decoder.u8()?)?;
                Self::Normalize {
                    scale_q16,
                    offset_q16,
                    output_dtype,
                }
            }
            6 => Self::PrivacyMask {
                mask_policy_digest: decoder.digest()?,
                masked_region_count: decoder.u32()?,
            },
            _ => return Err(ContractError::InvalidIdentifier),
        };
        if step.validate().is_err() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(step)
    }
}

/// Typed fail-closed refusal for source-to-tensor lineage construction or verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LineageError {
    /// Invalid lineage identifier or output tensor metadata.
    InvalidLineage(&'static str),
    /// Invalid source byte span.
    InvalidSpan(&'static str),
    /// Invalid transform step or missing initial `Decode` step.
    InvalidTransform(&'static str),
    /// Forbidden `"latest"` alias encountered in a pinned transform identifier.
    ForbiddenLatestAlias(&'static str),
    /// Checked byte or coordinate arithmetic overflowed.
    ArithmeticOverflow,
    /// Hard span or transform step ceiling exceeded.
    LimitExceeded(&'static str),
    /// Supplied tensor disagrees with the sealed lineage digest, shape, dtype, or generation.
    TensorMismatch(&'static str),
    /// Cooperative cancellation observed before sealing lineage.
    Cancelled,
}

impl fmt::Display for LineageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLineage(why) => write!(f, "invalid source-to-tensor lineage: {why}"),
            Self::InvalidSpan(why) => write!(f, "invalid source byte span: {why}"),
            Self::InvalidTransform(why) => write!(f, "invalid transform step: {why}"),
            Self::ForbiddenLatestAlias(field) => {
                write!(f, "forbidden 'latest' alias in transform field '{field}'")
            }
            Self::ArithmeticOverflow => write!(f, "source-to-tensor lineage arithmetic overflow"),
            Self::LimitExceeded(what) => write!(f, "lineage limit exceeded: {what}"),
            Self::TensorMismatch(what) => write!(f, "output tensor disagrees with lineage: {what}"),
            Self::Cancelled => write!(f, "source-to-tensor lineage sealing cancelled"),
        }
    }
}

impl std::error::Error for LineageError {}

/// Canonical, tamper-evident causal lineage record from immutable source spans to a derived tensor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceToTensorLineage {
    /// Format version (`SOURCE_TO_TENSOR_LINEAGE_FORMAT_VERSION`).
    pub format_version: u32,
    /// Stable lineage record identifier.
    pub lineage_id: String,
    /// Non-empty bounded list of source media byte spans contributing to the decoded frame.
    pub source_spans: Vec<SourceByteSpan>,
    /// Content digest of the intermediate decoded frame bytes.
    pub decoded_frame_digest: ContentDigest,
    /// Non-empty ordered transform chain (must begin with `TransformStep::Decode`).
    pub transforms: Vec<TransformStep>,
    /// Canonical `fss-tensor::canonical::tensor_digest` of the derived output tensor.
    pub output_tensor_digest: ContentDigest,
    /// Exact output tensor element dtype.
    pub output_dtype: DType,
    /// Exact output tensor dimensions.
    pub output_shape: Vec<u64>,
    /// Exact output tensor generation fence (`!= 0`).
    pub output_generation: Generation,
    /// Whether at least one `TransformStep::PrivacyMask` was applied.
    pub privacy_masked: bool,
    /// Always `false`: derived tensors NEVER inherit raw source custody status.
    pub is_source_custody: bool,
    /// Domain-separated SHA-256 digest over all fields above.
    pub lineage_digest: ContentDigest,
}

impl SourceToTensorLineage {
    /// Seals a verified source-to-tensor lineage bound directly to `output_tensor`.
    pub fn seal_for_tensor(
        lineage_id: impl Into<String>,
        source_spans: Vec<SourceByteSpan>,
        decoded_frame_digest: ContentDigest,
        transforms: Vec<TransformStep>,
        output_tensor: &Tensor,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<Self, LineageError> {
        if is_cancelled() {
            return Err(LineageError::Cancelled);
        }
        let lineage_id = lineage_id.into();
        validate_clean_id(&lineage_id, "lineage_id")?;
        if source_spans.is_empty() {
            return Err(LineageError::InvalidSpan("empty_source_spans"));
        }
        if source_spans.len() > MAX_SOURCE_SPANS {
            return Err(LineageError::LimitExceeded("source_spans"));
        }
        for span in &source_spans {
            if is_cancelled() {
                return Err(LineageError::Cancelled);
            }
            span.validate()?;
        }

        if transforms.is_empty() {
            return Err(LineageError::InvalidTransform("empty_transforms"));
        }
        if transforms.len() > MAX_TRANSFORM_STEPS {
            return Err(LineageError::LimitExceeded("transforms"));
        }
        if !matches!(transforms.first(), Some(TransformStep::Decode { .. })) {
            return Err(LineageError::InvalidTransform(
                "must_begin_with_decode_step",
            ));
        }
        let mut privacy_masked = false;
        for step in &transforms {
            if is_cancelled() {
                return Err(LineageError::Cancelled);
            }
            step.validate()?;
            if matches!(step, TransformStep::PrivacyMask { .. }) {
                privacy_masked = true;
            }
        }

        let output_generation = output_tensor.generation();
        if output_generation.0 == 0 {
            return Err(LineageError::InvalidLineage("output_generation_zero"));
        }
        let output_shape: Vec<u64> = output_tensor
            .shape()
            .dims()
            .iter()
            .map(|&d| d as u64)
            .collect();
        if output_shape.len() > MAX_TENSOR_RANK {
            return Err(LineageError::LimitExceeded("output_rank"));
        }
        let output_tensor_digest = tensor_canonical_digest(output_tensor)
            .map_err(|_| LineageError::InvalidLineage("canonical_tensor_encoding_failed"))?;

        if is_cancelled() {
            return Err(LineageError::Cancelled);
        }

        let mut lineage = Self {
            format_version: SOURCE_TO_TENSOR_LINEAGE_FORMAT_VERSION,
            lineage_id,
            source_spans,
            decoded_frame_digest,
            transforms,
            output_tensor_digest,
            output_dtype: output_tensor.dtype(),
            output_shape,
            output_generation,
            privacy_masked,
            is_source_custody: false,
            lineage_digest: ContentDigest::sha256(b"pending"),
        };
        lineage.lineage_digest = lineage.computed_digest();
        Ok(lineage)
    }

    /// Verifies that `tensor` matches this lineage's sealed dtype, shape, generation, and digest.
    pub fn verify_against_tensor(&self, tensor: &Tensor) -> Result<(), LineageError> {
        if !self.verify_digest() {
            return Err(LineageError::InvalidLineage("lineage_digest_mismatch"));
        }
        if self.is_source_custody {
            return Err(LineageError::InvalidLineage(
                "derived_tensor_cannot_claim_source_custody",
            ));
        }
        if tensor.dtype() != self.output_dtype {
            return Err(LineageError::TensorMismatch("dtype"));
        }
        if tensor.generation() != self.output_generation {
            return Err(LineageError::TensorMismatch("generation"));
        }
        let dims: Vec<u64> = tensor.shape().dims().iter().map(|&d| d as u64).collect();
        if dims != self.output_shape {
            return Err(LineageError::TensorMismatch("shape"));
        }
        let actual_digest = tensor_canonical_digest(tensor)
            .map_err(|_| LineageError::TensorMismatch("canonical_encoding_failed"))?;
        if actual_digest != self.output_tensor_digest {
            return Err(LineageError::TensorMismatch("canonical_digest"));
        }
        Ok(())
    }

    /// Recomputes the exact domain-separated SHA-256 digest over all canonical fields.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(SOURCE_TO_TENSOR_LINEAGE_DOMAIN);
        encoder.u32(self.format_version);
        encoder.text(&self.lineage_id);
        encoder.u64(self.source_spans.len() as u64);
        for span in &self.source_spans {
            span.encode_canonical(&mut encoder);
        }
        encoder.digest(self.decoded_frame_digest);
        encoder.u64(self.transforms.len() as u64);
        for step in &self.transforms {
            step.encode_canonical(&mut encoder);
        }
        encoder.digest(self.output_tensor_digest);
        encoder.u8(dtype_tag(self.output_dtype));
        encoder.u64(self.output_shape.len() as u64);
        for &dim in &self.output_shape {
            encoder.u64(dim);
        }
        encoder.u64(self.output_generation.0);
        encoder.u8(u8::from(self.privacy_masked));
        encoder.u8(u8::from(self.is_source_custody));
        ContentDigest::sha256(&encoder.finish())
    }

    /// Returns `true` iff `lineage_digest` matches [`Self::computed_digest`].
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.lineage_digest == self.computed_digest()
    }
}

impl CanonicalEncode for SourceToTensorLineage {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.format_version);
        encoder.text(&self.lineage_id);
        encoder.u64(self.source_spans.len() as u64);
        for span in &self.source_spans {
            span.encode_canonical(encoder);
        }
        encoder.digest(self.decoded_frame_digest);
        encoder.u64(self.transforms.len() as u64);
        for step in &self.transforms {
            step.encode_canonical(encoder);
        }
        encoder.digest(self.output_tensor_digest);
        encoder.u8(dtype_tag(self.output_dtype));
        encoder.u64(self.output_shape.len() as u64);
        for &dim in &self.output_shape {
            encoder.u64(dim);
        }
        encoder.u64(self.output_generation.0);
        encoder.u8(u8::from(self.privacy_masked));
        encoder.u8(u8::from(self.is_source_custody));
        encoder.digest(self.lineage_digest);
    }
}

impl CanonicalDecode for SourceToTensorLineage {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let format_version = decoder.u32()?;
        if format_version != SOURCE_TO_TENSOR_LINEAGE_FORMAT_VERSION {
            return Err(ContractError::InvalidIdentifier);
        }
        let lineage_id = decoder.text()?.to_owned();
        if validate_clean_id(&lineage_id, "lineage_id").is_err() {
            return Err(ContractError::InvalidIdentifier);
        }
        let span_count =
            usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidIdentifier)?;
        if span_count == 0 || span_count > MAX_SOURCE_SPANS {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut source_spans = Vec::with_capacity(span_count);
        for _ in 0..span_count {
            source_spans.push(SourceByteSpan::decode_canonical(decoder)?);
        }
        let decoded_frame_digest = decoder.digest()?;
        let step_count =
            usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidIdentifier)?;
        if step_count == 0 || step_count > MAX_TRANSFORM_STEPS {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut transforms = Vec::with_capacity(step_count);
        for _ in 0..step_count {
            transforms.push(TransformStep::decode_canonical(decoder)?);
        }
        if !matches!(transforms.first(), Some(TransformStep::Decode { .. })) {
            return Err(ContractError::InvalidIdentifier);
        }
        let output_tensor_digest = decoder.digest()?;
        let output_dtype = decode_dtype_tag(decoder.u8()?)?;
        let rank = usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidIdentifier)?;
        if rank > MAX_TENSOR_RANK {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut output_shape = Vec::with_capacity(rank);
        for _ in 0..rank {
            output_shape.push(decoder.u64()?);
        }
        let output_generation = Generation(decoder.u64()?);
        if output_generation.0 == 0 {
            return Err(ContractError::InvalidIdentifier);
        }
        let privacy_masked = match decoder.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ContractError::InvalidIdentifier),
        };
        let is_source_custody = match decoder.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ContractError::InvalidIdentifier),
        };
        let lineage_digest = decoder.digest()?;

        // Derived tensors NEVER inherit raw source custody, and privacy_masked must agree with steps.
        let has_mask_step = transforms
            .iter()
            .any(|s| matches!(s, TransformStep::PrivacyMask { .. }));
        if is_source_custody || privacy_masked != has_mask_step {
            return Err(ContractError::InvalidIdentifier);
        }

        let lineage = Self {
            format_version,
            lineage_id,
            source_spans,
            decoded_frame_digest,
            transforms,
            output_tensor_digest,
            output_dtype,
            output_shape,
            output_generation,
            privacy_masked,
            is_source_custody,
            lineage_digest,
        };
        if !lineage.verify_digest() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(lineage)
    }
}
