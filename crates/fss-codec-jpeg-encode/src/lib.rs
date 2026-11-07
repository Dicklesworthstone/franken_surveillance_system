#![forbid(unsafe_code)]
//! Deterministic, bounded baseline JPEG derivatives in first-party Rust.
//!
//! The owner supplies exact tightly packed grayscale or RGB pixels and their independently
//! pinned digest. The RGB profile converts full-range RGB to JPEG Y/Cb/Cr 4:4:4. The encoder
//! uses integer transforms, fixed Huffman tables, and no source metadata or external runtime.
//! Every success is one complete JPEG; failure exposes no partially encoded bytes.
//!
//! A derivative receipt binds supplied pixels, configuration, implementation and encoded
//! bytes. It is not original-source custody, privacy authorization, capture timing or a claim
//! that a lossy reconstruction preserves mask pixels exactly. Source and current privacy
//! checks remain with the caller; a masked frame must be screened before it reaches this API.

mod entropy;
mod tables;
mod transform;

use fss_core::{ContentDigest, Sha256Hasher};
use std::sync::atomic::{AtomicBool, Ordering};

/// Maximum admitted coded dimension on either axis.
pub const MAX_DIMENSION: u32 = 4096;
/// Maximum input pixels, shared by grayscale and RGB profiles.
pub const MAX_PIXELS: usize = 4_194_304;
/// Maximum complete JPEG bytes, compatible with the native FSS JPEG reader.
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
/// Frozen numeric, framing and generation policy, included in [`encoder_identity`].
pub const ENCODER_PROFILE: &str = "fss.jpeg_encoder.profile.v1;baseline-8bit;gray-or-rgb-q16-ycbcr444;exact-dc-q14-ac;quantize-nearest-ties-away;annex-k-huffman;quality-1-100;edge-repeat;no-app-com;no-restarts;source-bound";
/// Deterministic work accounting identity; units are not CPU time or energy.
pub const ENCODE_WORK_MODEL: &str = "fss/jpeg-encode/work/1;hash-byte-1+128;output-byte-1;setup-256;mcu-1+64-per-component;block-4096";

const HASH_CHUNK: usize = 16 * 1024;
const BLOCK_WORK: u64 = 4096;
const SOURCES: [&[u8]; 4] = [
    include_bytes!("lib.rs"),
    include_bytes!("tables.rs"),
    include_bytes!("entropy.rs"),
    include_bytes!("transform.rs"),
];

/// Exact layout and interpretation of the owner's supplied pixels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PixelFormat {
    /// One full-range eight-bit luminance sample per pixel, tightly packed rows.
    Grayscale,
    /// Full-range eight-bit R,G,B channels in that order, tightly packed rows.
    Rgb,
}
impl PixelFormat {
    /// Stable, non-localized format name for receipts and operator projections.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self { Self::Grayscale => "grayscale", Self::Rgb => "rgb" }
    }
    const fn channels(self) -> usize {
        match self { Self::Grayscale => 1, Self::Rgb => 3 }
    }
}

/// Explicit transformation configuration. No interpretation is inferred from pixel values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodeConfig {
    /// Integer quantizer scale in 1..=100. Quality 100 remains a lossy transform.
    pub quality: u8,
    /// Exact supplied channel layout and full-range interpretation.
    pub format: PixelFormat,
}

/// Independent owner-narrowable ceilings, checked before any image-sized allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodeLimits {
    /// Each nonzero input axis must be at most this value and at most 4096.
    pub maximum_dimension: u32,
    /// Complete input pixels, at most 4,194,304.
    pub maximum_pixels: usize,
    /// Whole JPEG including headers, entropy padding and EOI, at most 16 MiB.
    pub maximum_output_bytes: usize,
}
impl Default for EncodeLimits {
    fn default() -> Self {
        Self {
            maximum_dimension: MAX_DIMENSION,
            maximum_pixels: MAX_PIXELS,
            maximum_output_bytes: MAX_OUTPUT_BYTES,
        }
    }
}
impl EncodeLimits {
    /// Reject zero or above-profile bounds rather than silently widening them.
    pub fn validate(&self) -> Result<(), EncodeError> {
        if !(1..=MAX_DIMENSION).contains(&self.maximum_dimension)
            || !(1..=MAX_PIXELS).contains(&self.maximum_pixels)
            || !(1..=MAX_OUTPUT_BYTES).contains(&self.maximum_output_bytes)
        {
            return Err(EncodeError::InvalidConfiguration);
        }
        Ok(())
    }

    /// Conservative work allowance for one image admitted by valid limits and this format.
    ///
    /// Includes one hashing of each fixed source preimage, the pixel hash, complete output
    /// construction and hash, and every padded 8x8 component block. A too-small output ceiling
    /// still refuses; this function cannot promise that a JPEG fits that independent ceiling.
    #[must_use]
    pub fn work_bound(&self, format: PixelFormat) -> u64 {
        let pixels = self.maximum_pixels as u64;
        let channels = format.channels() as u64;
        let mcus = pixels
            .saturating_add(14 * u64::from(self.maximum_dimension))
            .saturating_add(49)
            .div_ceil(64);
        let profile = SOURCES.iter().fold(0_u64, |n, bytes| n.saturating_add(bytes.len() as u64));
        256_u64
            .saturating_add(profile)
            .saturating_add(ENCODER_PROFILE.len() as u64)
            .saturating_add(160 + 6 * 128)
            .saturating_add(pixels.saturating_mul(channels))
            .saturating_add(128)
            .saturating_add(mcus.saturating_mul(1 + channels * (64 + BLOCK_WORK)))
            .saturating_add((self.maximum_output_bytes as u64).saturating_mul(2))
            .saturating_add(128)
    }
}

/// Payload-free refusal. No variant carries partial compressed or raw image bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// Invalid quality or zero/above-profile resource ceilings.
    InvalidConfiguration,
    /// Empty dimensions or a buffer inconsistent with the exact declared shape and layout.
    InvalidPixels,
    /// The independent pixel digest is absent or does not match the supplied bytes.
    SourceMismatch,
    /// Input dimensions, pixels, complete output bytes or checked arithmetic exceed a bound.
    Limit,
    /// A bounded fallible output allocation failed.
    Allocation,
    /// The supplied work allowance is exhausted; unsuccessful prior work remains charged.
    BudgetExhausted,
    /// The borrowed owner cancellation flag or synchronous probe requested a stop.
    Cancelled,
    /// A transform, amplitude or Huffman category exceeds the baseline numerical profile.
    CoefficientRange,
}
impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "invalid bounded JPEG encoder configuration",
            Self::InvalidPixels => "JPEG encoder pixel shape or layout mismatch",
            Self::SourceMismatch => "JPEG encoder pixel digest mismatch",
            Self::Limit => "JPEG encoder resource or arithmetic bound exceeded",
            Self::Allocation => "JPEG encoder bounded allocation failed",
            Self::BudgetExhausted => "JPEG encoder work budget exhausted",
            Self::Cancelled => "JPEG encoding cancelled",
            Self::CoefficientRange => "JPEG coefficient outside the baseline profile",
        })
    }
}
impl std::error::Error for EncodeError {}

/// Request-owned cumulative work, shared across frames without renewal or ambient I/O.
pub struct EncodeBudget<'a> {
    remaining: u64,
    used: u64,
    cancellation: Option<&'a AtomicBool>,
    probe: Option<&'a (dyn Fn() -> bool + Sync)>,
}
impl std::fmt::Debug for EncodeBudget<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncodeBudget")
            .field("remaining", &self.remaining)
            .field("used", &self.used)
            .field("cancellable", &(self.cancellation.is_some() || self.probe.is_some()))
            .finish()
    }
}
impl EncodeBudget<'_> {
    /// Reserve an explicit local allowance; construction starts no clock, worker or I/O.
    #[must_use]
    pub const fn new(limit: u64) -> Self {
        Self { remaining: limit, used: 0, cancellation: None, probe: None }
    }
    /// All work charged across successful and unsuccessful calls using this budget.
    #[must_use]
    pub const fn used(&self) -> u64 { self.used }
    /// Remaining allowance; a codec call never replenishes it.
    #[must_use]
    pub const fn remaining(&self) -> u64 { self.remaining }
    pub(crate) fn charge(&mut self, units: u64) -> Result<(), EncodeError> {
        if self.cancellation.is_some_and(|flag| flag.load(Ordering::Acquire))
            || self.probe.is_some_and(|probe| probe())
        {
            return Err(EncodeError::Cancelled);
        }
        if units > self.remaining {
            return Err(EncodeError::BudgetExhausted);
        }
        self.remaining -= units;
        // used + remaining is the original u64 allowance, so this cannot overflow.
        self.used += units;
        Ok(())
    }
}
impl<'a> EncodeBudget<'a> {
    /// Borrow the existing owner's cancellation flag; no detached task is created.
    #[must_use]
    pub const fn with_cancellation(limit: u64, flag: &'a AtomicBool) -> Self {
        Self { remaining: limit, used: 0, cancellation: Some(flag), probe: None }
    }
    /// Borrow a cheap synchronous cancellation/deadline probe, checked at every work charge.
    #[must_use]
    pub fn with_cancellation_probe(limit: u64, probe: &'a (dyn Fn() -> bool + Sync)) -> Self {
        Self { remaining: limit, used: 0, cancellation: None, probe: Some(probe) }
    }
}

/// Complete transformation accounting; a pixel hash is not evidence of source custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodeReceipt {
    /// Exact owner-supplied tightly packed input bytes, before color conversion or padding.
    pub pixel_sha256: [u8; 32],
    /// Entire complete JPEG, including headers and the final EOI.
    pub encoded_sha256: [u8; 32],
    /// Source-bound implementation and numeric/framing policy returned by [`encoder_identity`].
    pub encoder: [u8; 32],
    /// Original coded width and height; no implicit resize, crop or orientation.
    pub dimensions: [u32; 2],
    /// Declared original layout; RGB becomes Y/Cb/Cr 4:4:4 in the JPEG.
    pub format: PixelFormat,
    /// Explicit quantizer scale, never a claim of lossless output.
    pub quality: u8,
    /// Complete compressed byte count.
    pub output_bytes: usize,
    /// Coded 8x8 MCUs, including repeated edge padding.
    pub mcus: usize,
    /// One block per gray MCU or three blocks per RGB MCU.
    pub entropy_blocks: usize,
    /// Work charged by this call only; the supplied budget retains the cumulative total.
    pub work_units: u64,
}
impl EncodeReceipt {
    /// Fixed canonical receipt identity, distinct from the JPEG bytes and encoder generation.
    ///
    /// SHA-256 preimage: hash of the receipt domain; pixel, JPEG and encoder hashes; two
    /// big-endian u32 dimensions; format tag (gray=0, RGB=1); quality byte; big-endian u64
    /// output bytes, MCUs, blocks and work units. No textual or machine-width encoding occurs.
    #[must_use]
    pub fn digest(self) -> ContentDigest {
        let mut bytes = [0_u8; 170];
        bytes[..32].copy_from_slice(&ContentDigest::sha256(b"fss.jpeg_encoder.receipt.v1").bytes());
        bytes[32..64].copy_from_slice(&self.pixel_sha256);
        bytes[64..96].copy_from_slice(&self.encoded_sha256);
        bytes[96..128].copy_from_slice(&self.encoder);
        bytes[128..132].copy_from_slice(&self.dimensions[0].to_be_bytes());
        bytes[132..136].copy_from_slice(&self.dimensions[1].to_be_bytes());
        bytes[136] = match self.format { PixelFormat::Grayscale => 0, PixelFormat::Rgb => 1 };
        bytes[137] = self.quality;
        for (index, value) in [self.output_bytes as u64, self.mcus as u64, self.entropy_blocks as u64, self.work_units].into_iter().enumerate() {
            bytes[138 + index * 8..146 + index * 8].copy_from_slice(&value.to_be_bytes());
        }
        ContentDigest::sha256(&bytes)
    }
}

/// An entire encoded image, available only after final accounting and cancellation checks.
pub struct EncodedJpeg {
    bytes: Vec<u8>,
    receipt: EncodeReceipt,
}
impl std::fmt::Debug for EncodedJpeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncodedJpeg")
            .field("dimensions", &self.receipt.dimensions)
            .field("format", &self.receipt.format)
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
impl EncodedJpeg {
    /// Exact JPEG bytes. No original metadata or other frame is embedded.
    #[must_use]
    pub fn bytes(&self) -> &[u8] { &self.bytes }
    /// Transfer ownership of the complete compressed image without another allocation.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> { self.bytes }
    /// Exact transform and cost record. This grants no publication or disclosure authority.
    #[must_use]
    pub const fn receipt(&self) -> EncodeReceipt { self.receipt }
}

/// Source-bound encoder identity, with no heap allocation or ambient I/O.
///
/// This hashes a bounded set of compile-time source bytes. The encoding path performs the
/// same construction once per call under its supplied work and cancellation allowance.
#[must_use]
pub fn encoder_identity() -> [u8; 32] {
    let mut hashes = [0_u8; 160];
    hashes[..32].copy_from_slice(&ContentDigest::sha256(ENCODER_PROFILE.as_bytes()).bytes());
    for (index, source) in SOURCES.iter().enumerate() {
        hashes[32 + index * 32..64 + index * 32].copy_from_slice(&ContentDigest::sha256(source).bytes());
    }
    ContentDigest::sha256(&hashes).bytes()
}

fn hash(bytes: &[u8], budget: &mut EncodeBudget<'_>) -> Result<[u8; 32], EncodeError> {
    budget.charge(128)?;
    let mut hasher = Sha256Hasher::new();
    for chunk in bytes.chunks(HASH_CHUNK) {
        budget.charge(chunk.len() as u64)?;
        hasher.update(chunk);
    }
    budget.charge(0)?;
    hasher.finalize().map_err(|_| EncodeError::Limit)
}

fn identity(budget: &mut EncodeBudget<'_>) -> Result<[u8; 32], EncodeError> {
    let mut hashes = [0_u8; 160];
    hashes[..32].copy_from_slice(&hash(ENCODER_PROFILE.as_bytes(), budget)?);
    for (index, source) in SOURCES.iter().enumerate() {
        hashes[32 + index * 32..64 + index * 32].copy_from_slice(&hash(source, budget)?);
    }
    hash(&hashes, budget)
}

/// Encode one complete source-bound frame under explicit shape, output, work and cancellation
/// limits. No filesystem, network, clock, foreign codec, metadata forwarding or shared cache runs.
///
/// Gray pixels remain full-range luminance. RGB pixels use fixed Q16 Y/Cb/Cr conversion with
/// half-up rounding and 4:4:4 sampling. Padding repeats the last pixel/row. The DC coefficient
/// is exact; AC uses a separable fixed Q14 DCT. Quantization rounds to nearest, ties away from
/// zero. Standard Annex K Huffman tables and canonical one-scan SOF0 framing finish with EOI.
///
/// Failures return only [`EncodeError`], never partial bytes. A shared budget retains work
/// already consumed. At quality 100, conversion and transforms still need not reproduce the
/// supplied pixels exactly; this API does not certify a decoded privacy-mask boundary.
pub fn encode_jpeg(
    width: u32,
    height: u32,
    pixels: &[u8],
    expected_pixel_sha256: [u8; 32],
    config: EncodeConfig,
    limits: &EncodeLimits,
    budget: &mut EncodeBudget<'_>,
) -> Result<EncodedJpeg, EncodeError> {
    budget.charge(0)?;
    limits.validate()?;
    if !(1..=100).contains(&config.quality) {
        return Err(EncodeError::InvalidConfiguration);
    }
    if width == 0 || height == 0 {
        return Err(EncodeError::InvalidPixels);
    }
    if width > limits.maximum_dimension || height > limits.maximum_dimension {
        return Err(EncodeError::Limit);
    }
    let width_usize = width as usize;
    let height_usize = height as usize;
    let count = width_usize.checked_mul(height_usize).ok_or(EncodeError::Limit)?;
    if count > limits.maximum_pixels {
        return Err(EncodeError::Limit);
    }
    let channels = config.format.channels();
    let input_bytes = count.checked_mul(channels).ok_or(EncodeError::Limit)?;
    if pixels.len() != input_bytes {
        return Err(EncodeError::InvalidPixels);
    }
    if expected_pixel_sha256 == [0; 32] {
        return Err(EncodeError::SourceMismatch);
    }
    let initial_work = budget.used();
    budget.charge(256)?;
    if hash(pixels, budget)? != expected_pixel_sha256 {
        return Err(EncodeError::SourceMismatch);
    }
    let encoder = identity(budget)?;
    let luma = tables::quantizers(&tables::LUMA_QUANT, config.quality);
    let chroma = tables::quantizers(&tables::CHROMA_QUANT, config.quality);
    let mut output = entropy::Output::new(limits.maximum_output_bytes);
    header(&mut output, [width as u16, height as u16], channels, [&luma, &chroma], budget)?;
    let columns = width_usize.div_ceil(8);
    let rows = height_usize.div_ceil(8);
    let mut previous_dc = [0_i16; 3];
    for row in 0..rows {
        for column in 0..columns {
            budget.charge(1 + 64 * channels as u64)?;
            let mut blocks = [[0_u8; 64]; 3];
            for y in 0..8 {
                let source_y = (row * 8 + y).min(height_usize - 1);
                for x in 0..8 {
                    let source_x = (column * 8 + x).min(width_usize - 1);
                    let at = (source_y * width_usize + source_x) * channels;
                    if config.format == PixelFormat::Grayscale {
                        blocks[0][y * 8 + x] = pixels[at];
                    } else {
                        let values = transform::rgb_to_ycbcr(&pixels[at..at + 3]);
                        for component in 0..3 {
                            blocks[component][y * 8 + x] = values[component];
                        }
                    }
                }
            }
            for component in 0..channels {
                budget.charge(BLOCK_WORK)?;
                let quantizers = if component == 0 { &luma } else { &chroma };
                let coefficients = transform::quantized(&blocks[component], quantizers)?;
                output.block(&coefficients, &mut previous_dc[component], component != 0, budget)?;
            }
        }
    }
    let bytes = output.finish(budget)?;
    let encoded_sha256 = hash(&bytes, budget)?;
    budget.charge(0)?;
    let receipt = EncodeReceipt {
        pixel_sha256: expected_pixel_sha256,
        encoded_sha256,
        encoder,
        dimensions: [width, height],
        format: config.format,
        quality: config.quality,
        output_bytes: bytes.len(),
        mcus: columns * rows,
        entropy_blocks: columns * rows * channels,
        work_units: budget.used() - initial_work,
    };
    Ok(EncodedJpeg { bytes, receipt })
}

fn header(
    output: &mut entropy::Output,
    dimensions: [u16; 2],
    channels: usize,
    quantizers: [&[u8; 64]; 2],
    budget: &mut EncodeBudget<'_>,
) -> Result<(), EncodeError> {
    output.marker(0xd8, budget)?;
    let count = if channels == 1 { 1 } else { 2 };
    let mut quantization = [0_u8; 130];
    for table in 0..count {
        quantization[table * 65] = table as u8;
        for (scan, index) in transform::ZIGZAG.iter().enumerate() {
            quantization[table * 65 + 1 + scan] = quantizers[table][*index];
        }
    }
    output.segment(0xdb, &quantization[..count * 65], budget)?;
    let mut frame = [0_u8; 15];
    frame[0] = 8;
    frame[1..3].copy_from_slice(&dimensions[1].to_be_bytes());
    frame[3..5].copy_from_slice(&dimensions[0].to_be_bytes());
    frame[5] = channels as u8;
    for component in 0..channels {
        frame[6 + component * 3..9 + component * 3].copy_from_slice(&[
            component as u8 + 1, 0x11, u8::from(component != 0),
        ]);
    }
    output.segment(0xc0, &frame[..6 + channels * 3], budget)?;
    let mut huffman = [0_u8; 416];
    let mut at = 0;
    for (id, counts, values) in [
        (0x00, &tables::LUMA_DC_COUNTS, tables::LUMA_DC_VALUES.as_slice()),
        (0x10, &tables::LUMA_AC_COUNTS, tables::LUMA_AC_VALUES.as_slice()),
        (0x01, &tables::CHROMA_DC_COUNTS, tables::CHROMA_DC_VALUES.as_slice()),
        (0x11, &tables::CHROMA_AC_COUNTS, tables::CHROMA_AC_VALUES.as_slice()),
    ].into_iter().take(count * 2) {
        huffman[at] = id;
        huffman[at + 1..at + 17].copy_from_slice(counts);
        huffman[at + 17..at + 17 + values.len()].copy_from_slice(values);
        at += 17 + values.len();
    }
    output.segment(0xc4, &huffman[..at], budget)?;
    let mut scan = [0_u8; 10];
    scan[0] = channels as u8;
    for component in 0..channels {
        scan[1 + component * 2..3 + component * 2].copy_from_slice(&[
            component as u8 + 1, if component == 0 { 0 } else { 0x11 },
        ]);
    }
    scan[1 + channels * 2..4 + channels * 2].copy_from_slice(&[0, 63, 0]);
    output.segment(0xda, &scan[..4 + channels * 2], budget)
}
