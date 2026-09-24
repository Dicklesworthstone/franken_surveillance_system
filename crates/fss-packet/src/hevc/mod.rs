#![forbid(unsafe_code)]
//! Bounded single-layer HEVC picture grouping, not a decoder or completeness proof.
//!
//! Only the parameter-independent slice prefix is interpreted. Parameter-set
//! bodies, entropy data, picture order count and reference availability remain
//! unverified. Source-linked NALs are never replaced by invented SDP packets.

mod assembly;
mod configuration;

pub use configuration::{HevcConfiguration, HevcConfigurationError, HevcConfigurationLimits};

pub use assembly::{
    HevcAssembler, HevcAssemblyError, HevcAssemblyLimits, HevcAssemblyOutput, HevcAssemblyRefusal,
    HevcAssemblyRetirement, HevcAssemblyStep, HevcBoundary, HevcPictureGroup, HevcRetirementReason,
};

/// Parameter-independent part of an admitted single-layer slice segment header.
/// No dependent-segment address, slice type, POC or parameter-set availability is inferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HevcSlicePrefix {
    /// Observed first_slice_segment_in_pic_flag, independent of the RTP marker.
    pub first_slice: bool,
    /// Observed IRAP-only flag. None for a non-IRAP NAL, not an invented false value.
    pub no_output_of_prior_pics: Option<bool>,
    /// Referenced PPS identity, in 0..=63; not proof that a matching PPS is available.
    pub pps_id: u8,
    /// Original admitted VCL NAL type: 0..=9 or 16..=21.
    pub nal_type: u8,
    /// Original nonzero temporal_id_plus1. Layer zero is required by this subset.
    pub temporal_id_plus_one: u8,
}

/// Payload-free syntax refusals for the deliberately small picture-boundary prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HevcPrefixError {
    /// Required header or prefix bits are unavailable.
    Truncated,
    /// NAL length exceeds the explicit caller ceiling, or that ceiling is invalid.
    Limit,
    /// Forbidden-zero bit is set.
    Corrupt,
    /// Zero temporal ID or out-of-range PPS identity.
    Malformed,
    /// Reserved VCL/non-VCL kind, or this operation expected a VCL NAL.
    UnsupportedNal,
    /// Multilayer grouping is not implemented; layer identity is never flattened.
    UnsupportedLayer,
}
impl std::fmt::Display for HevcPrefixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HEVC prefix refusal: {self:?}")
    }
}
impl std::error::Error for HevcPrefixError {}

/// Read at most fifteen RBSP bits: first flag, optional IRAP flag, and PPS ID.
///
/// For PPS IDs 0..=63 the prefix fits in the first two bytes after the NAL header.
/// An emulation-prevention byte cannot occur in these first two bytes. No RBSP
/// suffix is copied or scanned, and no PPS-dependent syntax is guessed. Reserved
/// VCL kinds and nonzero layers fail explicitly. This is NOT a full slice parser.
pub fn parse_slice_prefix(
    nal: &[u8],
    max_nal_bytes: usize,
) -> Result<HevcSlicePrefix, HevcPrefixError> {
    if !(3..=64 * 1_024 * 1_024).contains(&max_nal_bytes) || nal.len() > max_nal_bytes {
        return Err(HevcPrefixError::Limit);
    }
    let (kind, temporal_id_plus_one) = header(nal)?;
    if !matches!(kind, 0..=9 | 16..=21) {
        return Err(HevcPrefixError::UnsupportedNal);
    }
    let mut at = 0;
    let mut bit = || {
        let byte = *nal.get(2 + at / 8).ok_or(HevcPrefixError::Truncated)?;
        let value = (byte >> (7 - at % 8)) & 1;
        at += 1;
        Ok::<u8, HevcPrefixError>(value)
    };
    let first_slice = bit()? != 0;
    let no_output_of_prior_pics = if (16..=21).contains(&kind) {
        Some(bit()? != 0)
    } else {
        None
    };
    let mut zeros = 0;
    while bit()? == 0 {
        zeros += 1;
        if zeros > 6 {
            return Err(HevcPrefixError::Malformed);
        }
    }
    let mut value = 1_u16;
    for _ in 0..zeros {
        value = (value << 1) | u16::from(bit()?);
    }
    let pps_id = value - 1;
    if pps_id > 63 {
        return Err(HevcPrefixError::Malformed);
    }
    Ok(HevcSlicePrefix {
        first_slice,
        no_output_of_prior_pics,
        pps_id: pps_id as u8,
        nal_type: kind,
        temporal_id_plus_one,
    })
}

fn header(nal: &[u8]) -> Result<(u8, u8), HevcPrefixError> {
    if nal.len() < 2 {
        return Err(HevcPrefixError::Truncated);
    }
    if nal[0] & 0x80 != 0 {
        return Err(HevcPrefixError::Corrupt);
    }
    if nal[1] & 7 == 0 {
        return Err(HevcPrefixError::Malformed);
    }
    if nal[0] & 1 != 0 || nal[1] >> 3 != 0 {
        return Err(HevcPrefixError::UnsupportedLayer);
    }
    Ok(((nal[0] >> 1) & 63, nal[1] & 7))
}
