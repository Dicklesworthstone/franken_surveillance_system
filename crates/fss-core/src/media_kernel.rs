#![forbid(unsafe_code)]
//! Cross-kernel media contracts and limits (FSS-052).
//!
//! Each pure-Rust media kernel (H.264, H.265, MJPEG decoders) enforces its
//! own detailed `DecoderLimits`/`DecodeLimits`. This module is the
//! REGISTRY-GRADE contract layer above them: one stable identity per
//! kernel, the documented hard ceilings every implementation of that
//! kernel must respect, a canonical encoding, and a content digest — so
//! kernel limits are comparable, citable, and drift-detectable across the
//! media plane.
//!
//! The contract rows mirror the codecs' documented ceilings exactly; a
//! codec whose validation admits something its contract forbids is a
//! registry disagreement the contract family catches.

use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::{ContentDigest, ContractError};

/// Typed contract violation for a media-kernel contract row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaKernelContractError {
    /// A bound exceeds its documented ceiling.
    BoundsViolation {
        /// Which documented ceiling was exceeded.
        field: &'static str,
    },
    /// The contract version is zero.
    ZeroVersion,
}

impl std::fmt::Display for MediaKernelContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BoundsViolation { field } => {
                write!(f, "media kernel contract: {field} exceeds its documented ceiling")
            }
            Self::ZeroVersion => write!(f, "media kernel contract: version is zero"),
        }
    }
}

impl std::error::Error for MediaKernelContractError {}

/// Documented hard ceiling shared by both ITU codecs: coded luma axis.
pub const MAX_CODED_AXIS: u32 = 16_384;
/// Documented hard ceiling for one NAL unit / encoded frame: 16 MiB.
pub const MAX_ENCODED_BYTES: u64 = 16 * 1024 * 1024;
/// MJPEG documented dimension ceiling.
pub const MAX_MJPEG_DIMENSION: u32 = 4_096;
/// MJPEG documented reconstructed-sample ceiling.
pub const MAX_MJPEG_PIXELS: u64 = 4_194_304;

/// One pure-Rust media kernel identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MediaKernelId {
    /// H.264/AVC Annex-B decoder (`fss-codec-h264`).
    H264,
    /// H.265/HEVC Annex-B decoder (`fss-codec-h265`).
    H265,
    /// Motion-JPEG frame decoder (`fss-codec-mjpeg`).
    Mjpeg,
}

impl MediaKernelId {
    /// Stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::H264 => "h264",
            Self::H265 => "h265",
            Self::Mjpeg => "mjpeg",
        }
    }
}

impl CanonicalEncode for MediaKernelId {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::H264 => 1,
            Self::H265 => 2,
            Self::Mjpeg => 3,
        });
    }
}

impl CanonicalDecode for MediaKernelId {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::H264),
            2 => Ok(Self::H265),
            3 => Ok(Self::Mjpeg),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// The cross-kernel comparable bounds subset of one kernel's contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaKernelBounds {
    /// Maximum coded axis (width or height) admitted.
    pub max_axis: u32,
    /// Maximum one-unit encoded size admitted (NAL or frame).
    pub max_encoded_bytes: u64,
    /// Lifetime work bound in decoded frames (never zero).
    pub max_pictures: u64,
}

/// One kernel's registry contract: identity, contract version, bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaKernelContract {
    /// The kernel.
    pub kernel: MediaKernelId,
    /// Contract version (bumped when documented ceilings change).
    pub version: u32,
    /// Comparable bounds.
    pub bounds: MediaKernelBounds,
}

/// The H.264 contract row (mirrors `fss-codec-h264` documented ceilings).
pub const H264_CONTRACT: MediaKernelContract = MediaKernelContract {
    kernel: MediaKernelId::H264,
    version: 1,
    bounds: MediaKernelBounds {
        max_axis: MAX_CODED_AXIS,
        max_encoded_bytes: MAX_ENCODED_BYTES,
        max_pictures: u64::MAX,
    },
};

/// The H.265 contract row (mirrors `fss-codec-h265` documented ceilings).
pub const H265_CONTRACT: MediaKernelContract = MediaKernelContract {
    kernel: MediaKernelId::H265,
    version: 1,
    bounds: MediaKernelBounds {
        max_axis: MAX_CODED_AXIS,
        max_encoded_bytes: MAX_ENCODED_BYTES,
        max_pictures: u64::MAX,
    },
};

/// The MJPEG contract row (mirrors `fss-codec-mjpeg` documented ceilings).
pub const MJPEG_CONTRACT: MediaKernelContract = MediaKernelContract {
    kernel: MediaKernelId::Mjpeg,
    version: 1,
    bounds: MediaKernelBounds {
        max_axis: MAX_MJPEG_DIMENSION,
        max_encoded_bytes: MAX_ENCODED_BYTES,
        max_pictures: u64::MAX,
    },
};

/// The full registry, in canonical kernel order.
pub const KERNEL_CONTRACTS: [MediaKernelContract; 3] = [H264_CONTRACT, H265_CONTRACT, MJPEG_CONTRACT];

impl MediaKernelContract {
    /// Validates the contract row against the documented ceilings.
    ///
    /// # Errors
    /// Typed refusal when a bound exceeds its documented ceiling, the
    /// picture bound is zero, or the version is zero.
    pub fn validate(&self) -> Result<(), MediaKernelContractError> {
        let axis_ceiling = match self.kernel {
            MediaKernelId::H264 | MediaKernelId::H265 => MAX_CODED_AXIS,
            MediaKernelId::Mjpeg => MAX_MJPEG_DIMENSION,
        };
        if self.bounds.max_axis > axis_ceiling {
            return Err(MediaKernelContractError::BoundsViolation {
                field: "max_axis",
            });
        }
        if self.bounds.max_encoded_bytes > MAX_ENCODED_BYTES {
            return Err(MediaKernelContractError::BoundsViolation {
                field: "max_encoded_bytes",
            });
        }
        if self.bounds.max_pictures == 0 {
            return Err(MediaKernelContractError::BoundsViolation {
                field: "max_pictures",
            });
        }
        if self.version == 0 {
            return Err(MediaKernelContractError::ZeroVersion);
        }
        Ok(())
    }

    /// Canonical byte form: kernel tag, version, bounds — deterministic
    /// and codec-order independent.
    ///
    /// # Errors
    /// Never for in-memory contracts; encoding errors surface the
    /// canonical-layer failure.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut enc = CanonicalEncoder::new();
        self.kernel.encode_canonical(&mut enc);
        enc.u32(self.version);
        enc.u32(self.bounds.max_axis);
        enc.bytes(&self.bounds.max_encoded_bytes.to_be_bytes());
        enc.bytes(&self.bounds.max_pictures.to_be_bytes());
        enc.finish()
    }

    /// Content digest of the canonical form: the citable limits identity.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.canonical_bytes())
    }
}
