#![forbid(unsafe_code)]
//! Native baseline JPEG to packed RGB, sharing the exact luma parser and entropy decoder.
//!
//! All Y/Cb/Cr blocks are reconstructed. Subsampled chroma uses nearest-cell replication;
//! the full-range color matrix is fixed Q16 with half-up rounding and saturation. This is
//! a declared coded-pixel transform, not ICC color management or Exif orientation. Images
//! with those metadata keep them in the original source; no transform is silently applied.

use crate::{ComponentInterpretation, DecodeBudget, DecodeError, DecodeLimits, image};
use fss_core::ContentDigest;

/// Maximum packed RGB result; pixel count still has the shared 4,194,304-pixel ceiling.
pub const MAX_RGB_BYTES: usize = 3 * 4_194_304;

/// Independent frame and reconstructed byte limits, checked before result allocation.
#[derive(Clone, Copy, Debug)]
pub struct RgbDecodeLimits {
    /// Existing bounded JPEG syntax, dimensions, pixel count and metadata contract.
    pub frame: DecodeLimits,
    /// Complete RGB byte ceiling; never permission to downsample or return a partial frame.
    pub maximum_output_bytes: usize,
}
impl Default for RgbDecodeLimits {
    fn default() -> Self {
        Self {
            frame: DecodeLimits::default(),
            maximum_output_bytes: MAX_RGB_BYTES,
        }
    }
}

/// Exact source-to-RGB transform identity. No independent model admission is implied.
#[must_use]
pub fn rgb_decoder_identity() -> [u8; 32] {
    let mut bytes = [0_u8; 192];
    bytes[..32].copy_from_slice(
        &ContentDigest::sha256(b"fss/jpeg-rgb/reference/1;nearest-chroma;q16-half-up;rgb-hwc")
            .bytes(),
    );
    for (i, source) in [
        include_bytes!("color.rs").as_slice(),
        include_bytes!("image.rs").as_slice(),
        include_bytes!("entropy.rs").as_slice(),
        include_bytes!("transform.rs").as_slice(),
        include_bytes!("lib.rs").as_slice(),
    ]
    .iter()
    .enumerate()
    {
        bytes[(i + 1) * 32..(i + 2) * 32].copy_from_slice(&ContentDigest::sha256(source).bytes());
    }
    ContentDigest::sha256(&bytes).bytes()
}

/// Complete decode receipt; metadata stays in the unchanged compressed source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RgbDecodeReceipt {
    /// Whole compressed frame identity, including all metadata and the validated EOI.
    pub encoded_sha256: [u8; 32],
    /// Exactly width*height*3 tightly packed output bytes, channel order R,G,B.
    pub rgb_sha256: [u8; 32],
    /// Immutable source implementation and declared chroma/matrix numeric policy.
    pub decoder: [u8; 32],
    /// Explicit grayscale replication or JPEG YCbCr interpretation supplied by the caller.
    pub interpretation: ComponentInterpretation,
    /// Coded raster dimensions; no rotation, lens correction or implicit crop.
    pub dimensions: [u32; 2],
    /// Complete number of coded MCUs, including boundary padding.
    pub mcus: usize,
    /// All entropy blocks validated and reconstructed, including chroma and edge padding.
    pub entropy_blocks: usize,
    /// Verified restart markers.
    pub restarts: usize,
    /// Structurally consumed APP/COM segments, not applied color/orientation transforms.
    pub metadata_segments: usize,
    /// Metadata payload bytes retained through the original source identity.
    pub metadata_bytes: usize,
}

/// Immutable RGB pixels available only after whole-frame validation succeeds.
pub struct DecodedRgb {
    pixels: Vec<u8>,
    receipt: RgbDecodeReceipt,
}
impl std::fmt::Debug for DecodedRgb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedRgb")
            .field("dimensions", &self.receipt.dimensions)
            .finish_non_exhaustive()
    }
}
impl DecodedRgb {
    /// Coded image width and height.
    pub fn dimensions(&self) -> [u32; 2] {
        self.receipt.dimensions
    }
    /// Tightly packed HWC bytes in R,G,B order, never BGR or a replicated luma substitute.
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }
    /// Exact source and complete transform/accounting record.
    pub fn receipt(&self) -> RgbDecodeReceipt {
        self.receipt
    }
}

/// Decode one complete baseline JPEG with grayscale or YCbCr 4:4:4/4:2:2/4:2:0.
///
/// No FFI, model server or camera I/O is involved. Reordered scan components, odd image
/// dimensions and restart intervals reuse the native parser. Malformed chroma, truncated
/// entropy, progressive scans, absent EOI, incompatible interpretation and trailing bytes
/// refuse the entire result. The existing decode_luma API and its pixels remain unchanged.
pub fn decode_rgb(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    interpretation: ComponentInterpretation,
    limits: RgbDecodeLimits,
    budget: &mut DecodeBudget<'_>,
) -> Result<DecodedRgb, DecodeError> {
    budget.charge(0)?;
    let l = limits.frame;
    if l.maximum_bytes == 0
        || l.maximum_bytes > 16 * 1024 * 1024
        || l.maximum_dimension == 0
        || l.maximum_dimension > 4096
        || l.maximum_pixels == 0
        || l.maximum_pixels > 4_194_304
        || l.maximum_markers == 0
        || l.maximum_markers > 4096
        || bytes.len() > l.maximum_bytes
        || limits.maximum_output_bytes == 0
        || limits.maximum_output_bytes > MAX_RGB_BYTES
    {
        return Err(DecodeError::Limit);
    }
    budget.charge(bytes.len() as u64)?;
    if expected_sha256 == [0; 32] || ContentDigest::sha256(bytes).bytes() != expected_sha256 {
        return Err(DecodeError::SourceMismatch);
    }
    let (dimensions, pixels, stats) = image::decode_with_output(
        bytes,
        interpretation,
        l,
        image::Reconstruction::Rgb {
            maximum_bytes: limits.maximum_output_bytes,
        },
        budget,
    )?;
    // Source-profile hashing is explicit work too, rather than an unpriced post-decode pass.
    let profile_bytes = include_bytes!("color.rs").len()
        + include_bytes!("image.rs").len()
        + include_bytes!("entropy.rs").len()
        + include_bytes!("transform.rs").len()
        + include_bytes!("lib.rs").len();
    budget.charge(pixels.len() as u64 + profile_bytes as u64 + 2048)?;
    let receipt = RgbDecodeReceipt {
        encoded_sha256: expected_sha256,
        rgb_sha256: ContentDigest::sha256(&pixels).bytes(),
        decoder: rgb_decoder_identity(),
        interpretation,
        dimensions,
        mcus: stats.mcus,
        entropy_blocks: stats.blocks,
        restarts: stats.restarts,
        metadata_segments: stats.metadata_segments,
        metadata_bytes: stats.metadata_bytes,
    };
    budget.charge(0)?;
    Ok(DecodedRgb { pixels, receipt })
}

pub(crate) fn ycbcr_to_rgb(y: u8, cb: u8, cr: u8) -> [u8; 3] {
    let y = i32::from(y) * 65_536;
    let cb = i32::from(cb) - 128;
    let cr = i32::from(cr) - 128;
    let channel = |value: i32| ((value + 32_768).div_euclid(65_536)).clamp(0, 255) as u8;
    [
        channel(y + 91_881 * cr),
        channel(y - 22_554 * cb - 46_802 * cr),
        channel(y + 116_130 * cb),
    ]
}
