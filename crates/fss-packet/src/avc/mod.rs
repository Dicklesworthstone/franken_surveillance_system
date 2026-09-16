#![forbid(unsafe_code)]
//! Bounded AVC parameter sets and primary-picture identity (FSS-113).
//!
//! These parsers consume complete NAL bytes, including the one-byte NAL header
//! and excluding Annex-B delimiters. They neither decode macroblocks nor prove
//! picture completeness. Baseline, Main, and High 8-bit 4:2:0 syntax is admitted;
//! data partitioning, slice groups, and extensions fail explicitly. Original
//! NAL bytes and their source custody remain the caller's responsibility.

mod bits;
mod parameters;
mod slice;

pub use parameters::{AvcPps, AvcSps, AvcTimingInfo, PocMode, parse_pps, parse_sps};
pub use slice::{AvcSliceIdentity, AvcSliceType, parse_slice_identity};

/// Independent syntax and allocation ceilings; not H.264 level-conformance claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvcSyntaxLimits {
    /// Maximum complete NAL bytes, including its header; at most 16 MiB.
    pub max_nal_bytes: usize,
    /// Maximum bytes in one SPS or PPS, at most 64 KiB and no larger than a NAL.
    pub max_parameter_set_bytes: usize,
    /// Maximum coded luma width, before cropping; at most 16,384.
    pub max_width: u32,
    /// Maximum coded luma height, before cropping; at most 16,384.
    pub max_height: u32,
    /// Maximum coded luma samples, before cropping; at most 268,435,456.
    pub max_luma_samples: u64,
    /// Maximum reference frames declared by an SPS; at most 16.
    pub max_reference_frames: u32,
    /// Maximum RBSP bits consumed for one slice identity, at most 65,536.
    pub max_slice_identity_bits: usize,
}

impl Default for AvcSyntaxLimits {
    fn default() -> Self {
        Self {
            max_nal_bytes: 8 * 1_024 * 1_024,
            max_parameter_set_bytes: 64 * 1_024,
            max_width: 8_192,
            max_height: 8_192,
            max_luma_samples: 8_192 * 8_192,
            max_reference_frames: 16,
            max_slice_identity_bits: 4_096,
        }
    }
}

impl AvcSyntaxLimits {
    /// Reject invalid policy rather than silently enlarging the requested limits.
    pub fn validate(self) -> Result<(), AvcError> {
        if !(2..=16 * 1_024 * 1_024).contains(&self.max_nal_bytes)
            || !(2..=64 * 1_024).contains(&self.max_parameter_set_bytes)
            || self.max_parameter_set_bytes > self.max_nal_bytes
            || !(1..=16_384).contains(&self.max_width)
            || !(1..=16_384).contains(&self.max_height)
            || !(1..=268_435_456).contains(&self.max_luma_samples)
            || self.max_reference_frames > 16
            || !(1..=65_536).contains(&self.max_slice_identity_bits)
        {
            return Err(AvcError::Configuration);
        }
        Ok(())
    }
}

/// Payload-free parse refusals. None confers source, decoding, or effect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvcError {
    /// Invalid caller-supplied bounds or owner generation.
    Configuration,
    /// A complete NAL or syntax field exceeds a declared bound.
    Limit,
    /// Required bits are not available in the supplied NAL.
    Truncated,
    /// Invalid reserved bits, escape, trailing bits, dimensions, or field value.
    Malformed,
    /// The NAL's forbidden bit reports corruption.
    Corrupt,
    /// The NAL kind is not admitted by this particular operation.
    UnexpectedNal,
    /// Only profile_idc 66, 77, and 100 are admitted by this reference slice.
    UnsupportedProfile,
    /// Only 8-bit 4:2:0 is admitted, including its scaling-matrix syntax.
    UnsupportedSampleFormat,
    /// Flexible macroblock ordering / multiple slice groups is not admitted.
    UnsupportedSliceGroups,
    /// Data partitions, SP/SI slices, or extension-layer pictures are not admitted.
    UnsupportedPicture,
    /// Supplied SPS, PPS, and slice identifiers do not bind to each other.
    ParameterSetMismatch,
    /// A fallible bounded allocation was refused.
    Allocation,
}

impl std::fmt::Display for AvcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AVC syntax refusal: {self:?}")
    }
}

impl std::error::Error for AvcError {}

fn checked_nal(nal: &[u8], limits: AvcSyntaxLimits) -> Result<u8, AvcError> {
    limits.validate()?;
    if nal.len() > limits.max_nal_bytes {
        return Err(AvcError::Limit);
    }
    let header = *nal.first().ok_or(AvcError::Truncated)?;
    if header & 0x80 != 0 {
        return Err(AvcError::Corrupt);
    }
    Ok(header)
}
