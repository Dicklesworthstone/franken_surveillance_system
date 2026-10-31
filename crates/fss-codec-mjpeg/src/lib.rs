#![forbid(unsafe_code)]
//! Stateless baseline and progressive JPEG/MJPEG decoding, with no foreign runtime.
//!
//! Accepts exactly one complete, owner-framed JPEG image, not an HTTP/UVC/AVI stream.
//! The luma API reconstructs Y; `color::decode_rgb` reconstructs all color components.
//! Orientation, timestamp, source custody, and camera calibration are never inferred.

mod entropy;
mod image;
mod progressive;
mod transform;

use fss_core::ContentDigest;
use std::sync::atomic::{AtomicBool, Ordering};

/// Non-disclosing failures. An error never exposes partly reconstructed pixels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// Invalid byte syntax, inconsistent tables, entropy, padding or restart sequence.
    Malformed,
    /// The admitted coding, sampling or component-interpretation subset is exceeded.
    Unsupported,
    /// A required byte is absent; no concealment or partial image is performed.
    Truncated,
    /// Independently supplied source digest is absent or differs from these bytes.
    SourceMismatch,
    /// Input, dimensions, allocation, marker count or coefficient bound is exceeded.
    Limit,
    /// Caller work allowance was exhausted before completion.
    BudgetExhausted,
    /// Owner-requested cancellation observed before publication.
    Cancelled,
}
impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed JPEG frame",
            Self::Unsupported => "unsupported JPEG coding or component interpretation",
            Self::Truncated => "truncated JPEG frame",
            Self::SourceMismatch => "JPEG source digest mismatch",
            Self::Limit => "JPEG resource or numeric bound exceeded",
            Self::BudgetExhausted => "JPEG work budget exhausted",
            Self::Cancelled => "JPEG decode cancelled",
        })
    }
}
impl std::error::Error for DecodeError {}

/// Explicit source-format contract, not a guess based on pixel appearance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentInterpretation {
    /// One full-resolution grayscale component.
    Grayscale,
    /// Components 1/2/3 are full-range JPEG Y/Cb/Cr, not RGB or CMYK.
    YCbCr,
}

/// Owner-narrowable limits. No limit silently changes decoded resolution or precision.
#[derive(Clone, Copy, Debug)]
pub struct DecodeLimits {
    /// At most 16 MiB of one exact encoded frame, including metadata.
    pub maximum_bytes: usize,
    /// Each axis must be at most this value, with a hard ceiling of 4096.
    pub maximum_dimension: u32,
    /// At most 4,194,304 reconstructed luma samples.
    pub maximum_pixels: usize,
    /// At most 4096 non-entropy marker segments; restart markers have a separate MCU bound.
    pub maximum_markers: usize,
}
impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            maximum_bytes: 16 * 1024 * 1024,
            maximum_dimension: 4096,
            maximum_pixels: 4_194_304,
            maximum_markers: 4096,
        }
    }
}
impl DecodeLimits {
    /// Upper bound on the work units [`decode_luma`] charges for any frame these limits admit,
    /// so a caller can size a per-frame [`DecodeBudget`] that never exhausts on an admitted frame.
    ///
    /// Includes the bounded progressive coefficient buffer and at most 256 progressive scans.
    /// Baseline calls keep their original actual charges. The baseline contribution is derived
    /// from the input length once, 32 per marker, every marker
    /// segment's length (together at most the input), the luma buffer, the final
    /// `pixels + 1024`, and per MCU `1 + 4096` per entropy block. Every admitted sampling layout
    /// has at most `ceil(w/8) * ceil(h/8)` MCUs and at most 6 blocks per MCU, and for
    /// `w, h <= maximum_dimension` with `w * h <= maximum_pixels`,
    /// `ceil(w/8) * ceil(h/8) <= (maximum_pixels + 14 * maximum_dimension + 49) / 64`.
    #[must_use]
    pub fn luma_work_bound(&self) -> u64 {
        let bytes = self.maximum_bytes as u64;
        let dimension = u64::from(self.maximum_dimension);
        let pixels = self.maximum_pixels as u64;
        let markers = self.maximum_markers as u64;
        let cells = pixels
            .saturating_add(dimension.saturating_mul(14))
            .saturating_add(49)
            .div_ceil(64);
        let baseline = bytes
            .saturating_mul(2)
            .saturating_add(markers.saturating_mul(32))
            .saturating_add(pixels.saturating_mul(2))
            .saturating_add(1024)
            .saturating_add(cells.saturating_mul(1 + 6 * 4096));
        // Six blocks per cell is conservative for every admitted sampling and edge layout.
        // Each scan visits each allocated block at most once; reconstruction does so once more.
        let progressive =
            baseline
                .saturating_add(cells.saturating_mul(6 * 128))
                .saturating_add(cells.saturating_mul(
                    progressive::MAX_SCANS as u64 * (6 + 6 * 4096) + 6 * (4096 + 64),
                ))
                .saturating_add(progressive::profile_bytes() as u64 + 2048);
        baseline.max(progressive)
    }
}

/// Bounded synchronous work under an optional owner-controlled cancellation flag.
/// Units are deterministic reference operations, not time, energy or throughput.
#[derive(Debug)]
pub struct DecodeBudget<'a> {
    remaining: u64,
    used: u64,
    cancellation: Option<&'a AtomicBool>,
}
impl DecodeBudget<'_> {
    /// Allocate a local allowance, without reading an ambient clock or runtime.
    pub fn new(limit: u64) -> Self {
        Self {
            remaining: limit,
            used: 0,
            cancellation: None,
        }
    }
    /// Reference units actually charged, including unsuccessful work.
    pub fn used(&self) -> u64 {
        self.used
    }
    /// Unspent allowance; can be narrowed by the owning task.
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
    pub(crate) fn charge(&mut self, units: u64) -> Result<(), DecodeError> {
        if self
            .cancellation
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            return Err(DecodeError::Cancelled);
        }
        if units > self.remaining {
            return Err(DecodeError::BudgetExhausted);
        }
        self.remaining -= units;
        self.used += units;
        Ok(())
    }
}
impl<'a> DecodeBudget<'a> {
    /// Share the existing owner's cancellation flag, without creating a worker/runtime.
    pub fn cancellable(limit: u64, flag: &'a AtomicBool) -> Self {
        Self {
            remaining: limit,
            used: 0,
            cancellation: Some(flag),
        }
    }
}

/// Exact codec identity, including the fixed inverse-transform matrix.
pub fn decoder_identity() -> [u8; 32] {
    [
        88, 142, 85, 98, 115, 169, 107, 216, 101, 118, 198, 8, 88, 247, 162, 119, 235, 9, 116, 161,
        239, 86, 22, 94, 145, 108, 119, 51, 80, 134, 132, 97,
    ]
}

/// Source-bound identity of the progressive Huffman coefficient/scan decoder and fixed IDCT.
#[must_use]
pub fn progressive_decoder_identity() -> [u8; 32] {
    progressive::identity(false)
}

/// Deterministically select the decoder generation from the bounded pre-scan marker prefix.
///
/// Only an explicit SOF2 selects progressive decoding. Invalid, absent, or unsupported frame
/// headers retain the baseline generation, whose historical refusals can still be replayed.
/// This performs no entropy work, allocation, metadata interpretation, or source authentication.
#[must_use]
pub fn decoder_identity_for_frame(bytes: &[u8]) -> [u8; 32] {
    if progressive::is_progressive(bytes) {
        progressive_decoder_identity()
    } else {
        decoder_identity()
    }
}

/// Source-linked decoding accounting. A digest is not source custody or authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeReceipt {
    /// Exact complete compressed input bytes, including metadata and EOI.
    pub encoded_sha256: [u8; 32],
    /// Exact reconstructed tightly packed Y samples.
    pub luma_sha256: [u8; 32],
    /// Exact admitted decoder/transform construction.
    pub decoder: [u8; 32],
    /// Explicit caller-supplied component interpretation.
    pub interpretation: ComponentInterpretation,
    /// Coded MCUs consumed, including edge padding; summed over progressive scans.
    pub mcus: usize,
    /// All luma and chroma entropy block visits, including progressive refinements.
    pub entropy_blocks: usize,
    /// Correctly ordered restart markers consumed.
    pub restarts: usize,
    /// APP/COM segments structurally consumed; metadata transformations are not applied.
    pub metadata_segments: usize,
    /// APP/COM payload bytes retained only through the original compressed source.
    pub metadata_bytes: usize,
}

/// Immutable full-range Y image, only constructible after complete frame validation.
/// Exif orientation, ICC colour conversion and lens correction are NOT applied.
pub struct DecodedLuma {
    dimensions: [u32; 2],
    pixels: Vec<u8>,
    receipt: DecodeReceipt,
}
impl std::fmt::Debug for DecodedLuma {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedLuma")
            .field("dimensions", &self.dimensions)
            .finish_non_exhaustive()
    }
}
impl DecodedLuma {
    /// Coded display dimensions, before any explicit orientation/crop transform.
    pub fn dimensions(&self) -> [u32; 2] {
        self.dimensions
    }
    /// Exactly width*height bytes; row stride equals width.
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }
    /// Compressed-to-decoded lineage and interpretation, never an observation timestamp.
    pub fn receipt(&self) -> DecodeReceipt {
        self.receipt
    }
}

/// Decode one complete self-contained baseline or progressive Huffman JPEG into Y.
///
/// SOF2 uses bounded coefficient storage and validates DC/AC spectral and successive-approximation
/// scans, EOB runs, quantizer stability, restart boundaries, and EOI before publishing pixels.
/// Baseline source, output, accounting, and generation remain exactly the v1 contract.
pub fn decode_luma(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    interpretation: ComponentInterpretation,
    limits: DecodeLimits,
    budget: &mut DecodeBudget<'_>,
) -> Result<DecodedLuma, DecodeError> {
    budget.charge(0)?;
    if progressive::is_progressive(bytes) {
        progressive::decode_luma(bytes, expected_sha256, interpretation, limits, budget)
    } else {
        decode_luma_v1(bytes, expected_sha256, interpretation, limits, budget)
    }
}

/// Replay exactly the requested registered generation, including an old progressive refusal.
pub fn decode_luma_for_identity(
    decoder: [u8; 32],
    bytes: &[u8],
    expected_sha256: [u8; 32],
    interpretation: ComponentInterpretation,
    limits: DecodeLimits,
    budget: &mut DecodeBudget<'_>,
) -> Result<DecodedLuma, DecodeError> {
    budget.charge(0)?;
    if decoder == decoder_identity() {
        decode_luma_v1(bytes, expected_sha256, interpretation, limits, budget)
    } else if decoder == progressive_decoder_identity() {
        progressive::decode_luma(bytes, expected_sha256, interpretation, limits, budget)
    } else {
        Err(DecodeError::Unsupported)
    }
}

/// Replay the original complete baseline Huffman JPEG-to-Y generation.
///
/// Supports grayscale and YCbCr 4:4:4/4:2:2/4:2:0, in one sequential scan, with
/// supplied 8-bit quantizers/Huffman tables and optional restart intervals. Chroma
/// entropy is validated even though chroma pixels are not returned. Progressive,
/// arithmetic, abbreviated/table-inheriting frames, multi-scan, RGB/CMYK, missing
/// EOI and trailing bytes are explicit failures. A bad suffix cannot publish Y.
pub fn decode_luma_v1(
    bytes: &[u8],
    expected_sha256: [u8; 32],
    interpretation: ComponentInterpretation,
    limits: DecodeLimits,
    budget: &mut DecodeBudget<'_>,
) -> Result<DecodedLuma, DecodeError> {
    budget.charge(0)?;
    if limits.maximum_bytes == 0
        || limits.maximum_bytes > 16 * 1024 * 1024
        || limits.maximum_dimension == 0
        || limits.maximum_dimension > 4096
        || limits.maximum_pixels == 0
        || limits.maximum_pixels > 4_194_304
        || limits.maximum_markers == 0
        || limits.maximum_markers > 4096
        || bytes.len() > limits.maximum_bytes
    {
        return Err(DecodeError::Limit);
    }
    budget.charge(bytes.len() as u64)?;
    if expected_sha256 == [0; 32] || ContentDigest::sha256(bytes).bytes() != expected_sha256 {
        return Err(DecodeError::SourceMismatch);
    }
    let (dimensions, pixels, stats) = image::decode(bytes, interpretation, limits, budget)?;
    budget.charge(pixels.len() as u64 + 1024)?;
    let receipt = DecodeReceipt {
        encoded_sha256: expected_sha256,
        luma_sha256: ContentDigest::sha256(&pixels).bytes(),
        decoder: decoder_identity(),
        interpretation,
        mcus: stats.mcus,
        entropy_blocks: stats.blocks,
        restarts: stats.restarts,
        metadata_segments: stats.metadata_segments,
        metadata_bytes: stats.metadata_bytes,
    };
    budget.charge(0)?;
    Ok(DecodedLuma {
        dimensions,
        pixels,
        receipt,
    })
}

/// Incremental, source-offset-preserving framing for concatenated JPEG streams.
pub mod stream;

/// Bounded JPEG parts from dechunked multipart/x-mixed-replace entity bytes.
pub mod multipart;

/// HTTP response framing with exact plaintext-to-entity source mappings.
pub mod http;

/// HTTP-to-multipart composition and complete JPEG-to-wire source maps.
pub mod http_mjpeg;

/// Complete native RGB reconstruction with explicit chroma and color-matrix semantics.
pub mod color;
