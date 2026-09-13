#![forbid(unsafe_code)]
//! Safe deterministic baseline JPEG decoder into [`fss_tensor::Tensor`].
//!
//! Provides a bounded, pure-Rust implementation of the ITU-T T.81 / ISO 10918-1
//! baseline sequential discrete cosine transform (DCT) process (SOF0).
//!
//! All memory allocations, dimensions, and symbol counts are strictly bounded
//! and validated with checked arithmetic before allocation to defend against hostile
//! inputs and algorithmic complexity attacks.
//!
//! Cites FSS-117 (reference decoder vertical slice).
//!
//! # Role
//!
//! This module is the fss-reference colour-to-tensor REFERENCE decoder and test oracle. The
//! owner-added crate `fss-codec-mjpeg` is the CANONICAL production JPEG decoder. This module has
//! no production caller outside tests and fss-reference reference paths and must not gain one;
//! porting RGB and tensor output into `fss-codec-mjpeg` is a later bead.
//!
//! # Peak memory
//!
//! Width, height, pixel-count and tensor-byte limits are checked at SOF0, before any plane is
//! allocated. Before the planes are allocated the decoder also requires the entropy-coded
//! segment to be long enough for the declared block count: every 8x8 block costs at least
//! [`MIN_BITS_PER_BLOCK`] bits (one DC code bit and one AC end-of-block code bit), so a header
//! that declares more blocks than the remaining bytes can hold is refused as
//! [`JpegDecodeError::Truncated`] with no plane allocated. Once the planes exist, peak heap is
//! about 2 bytes per pixel for grey (luma plane plus tensor copy) and 7 bytes per pixel for
//! colour (luma plane, RGB plane and tensor copy). Because of the scan-byte bound that is at
//! most about 512 (grey), 597 (4:4:4), 896 (4:2:2) or 1195 (4:2:0) bytes of planes per
//! entropy-coded input byte, and the tensor itself never exceeds `max_tensor_bytes` (at most
//! `MAX_STORAGE_BYTES`, 256 MiB).

use core::fmt;
use std::fmt::Write as _;

use fss_core::{ContentDigest, Generation};
use fss_tensor::{MAX_STORAGE_BYTES, Shape, Tensor, TensorError};

use crate::adapter_replay::ReplayCx;

/// Subsystem decoder generation string without '@'.
pub const JPEG_DECODER_GENERATION: &str = "decoder:fss-reference-jpeg-baseline:v1";

/// Declared numeric [`Generation`] identifying the decoder generation.
pub const JPEG_DECODER_GENERATION_NUMERIC: Generation = Generation(1);

/// Natural to zig-zag mapping: `ZIGZAG[k]` is the row-major raster index in an 8x8 block.
const ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

/// Fixed-point 16-bit scaled orthonormal DCT-II basis constants for 1D IDCT.
/// `IDCT_BASIS[r][c] = round(A^T[r][c] * 65536)`.
const IDCT_BASIS: [[i32; 8]; 8] = [
    [23170, 32138, 30274, 27246, 23170, 18205, 12540, 6393],
    [23170, 27246, 12540, -6393, -23170, -32138, -30274, -18205],
    [23170, 18205, -12540, -32138, -23170, 6393, 30274, 27246],
    [23170, 6393, -30274, -18205, 23170, 27246, -12540, -32138],
    [23170, -6393, -30274, 18205, 23170, -27246, -12540, 32138],
    [23170, -18205, -12540, 32138, -23170, -6393, 30274, -27246],
    [23170, -27246, 12540, 6393, -23170, 32138, -30274, 18205],
    [23170, -32138, 30274, -27246, 23170, -18205, 12540, -6393],
];

/// Extra fractional bits carried from the column pass into the row pass. The column-pass
/// output is scaled by `2^PASS1_BITS` instead of being rounded to an integer (the intermediate
/// precision of the classic islow structure), so the result is rounded once, at the end.
const PASS1_BITS: u32 = 2;
/// Column-pass descale: the basis carries 16 fractional bits, of which `PASS1_BITS` are kept.
const PASS1_SHIFT: u32 = 16 - PASS1_BITS;
/// Round-half-up bias for the column-pass descale.
const PASS1_ROUND: i64 = 1 << (PASS1_SHIFT - 1);
/// Row-pass descale: the 16 basis bits plus the `PASS1_BITS` carried from the column pass.
const PASS2_SHIFT: u32 = 16 + PASS1_BITS;
/// Round-half-up bias for the row-pass descale.
const PASS2_ROUND: i64 = 1 << (PASS2_SHIFT - 1);

/// Minimum entropy-coded bits per 8x8 block: a DC code and an AC end-of-block code, each at
/// least one bit long. Used to bound the declared block count by the scan bytes present.
pub const MIN_BITS_PER_BLOCK: u64 = 2;

/// Chroma subsampling formats supported by baseline sequential JPEG decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum JpegSubsampling {
    /// 1-component grayscale (Y only, 1x1).
    Grayscale,
    /// 3-component full color without subsampling (YCbCr 4:4:4, 1x1).
    Yuv444,
    /// 3-component quarter chroma resolution (YCbCr 4:2:0, 2x2 luma, 1x1 chroma).
    Yuv420,
    /// 3-component horizontal chroma subsampling (YCbCr 4:2:2, 2x1 luma, 1x1 chroma).
    Yuv422,
}

/// Resource and dimension bounds applied during JPEG decoding before allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JpegDecodeLimits {
    /// Maximum allowed image width in pixels (default: 8192).
    pub max_width: u32,
    /// Maximum allowed image height in pixels (default: 8192).
    pub max_height: u32,
    /// Maximum allowed total pixels (width * height) (default: 33_554_432).
    pub max_pixels: u64,
    /// Maximum allowed tensor allocation bytes (default: [`MAX_STORAGE_BYTES`] = 256 MiB).
    pub max_tensor_bytes: usize,
    /// Maximum allowed total Huffman symbols across tables (default: 1024).
    pub max_huffman_symbols: usize,
    /// Maximum allowed restart intervals encountered (default: 65_536).
    pub max_restart_intervals: u32,
}

impl Default for JpegDecodeLimits {
    fn default() -> Self {
        Self {
            max_width: 8192,
            max_height: 8192,
            max_pixels: 33_554_432,
            max_tensor_bytes: MAX_STORAGE_BYTES,
            max_huffman_symbols: 1024,
            max_restart_intervals: 65_536,
        }
    }
}

/// Errors arising during baseline JPEG decoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JpegDecodeError {
    /// Input data is not a valid JPEG stream (e.g. missing SOI marker).
    InvalidHeader(String),
    /// Truncated JPEG stream or truncated entropy data before complete MCU decoding.
    Truncated {
        /// MCU row at which truncation occurred.
        mcu_row: u32,
    },
    /// Unsupported JPEG feature, process, or sampling format.
    Unsupported {
        /// Description of the unsupported process or feature.
        process: String,
    },
    /// A configured decoding limit was exceeded.
    LimitExceeded {
        /// Description of the limit exceeded.
        limit: String,
    },
    /// Corrupt, malformed, or invalid syntax encountered in markers or entropy stream.
    InvalidSyntax(String),
    /// Decoding was cooperatively cancelled via [`ReplayCx`].
    Cancelled,
    /// Tensor construction error.
    Tensor(String),
}

impl fmt::Display for JpegDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHeader(msg) => write!(formatter, "invalid JPEG header: {msg}"),
            Self::Truncated { mcu_row } => {
                write!(
                    formatter,
                    "truncated JPEG entropy stream at MCU row {mcu_row}"
                )
            }
            Self::Unsupported { process } => {
                write!(formatter, "unsupported JPEG feature: {process}")
            }
            Self::LimitExceeded { limit } => {
                write!(formatter, "JPEG decoding limit exceeded: {limit}")
            }
            Self::InvalidSyntax(msg) => write!(formatter, "invalid JPEG syntax: {msg}"),
            Self::Cancelled => write!(formatter, "JPEG decoding cancelled"),
            Self::Tensor(msg) => write!(formatter, "JPEG tensor error: {msg}"),
        }
    }
}

impl std::error::Error for JpegDecodeError {}

impl From<TensorError> for JpegDecodeError {
    fn from(err: TensorError) -> Self {
        Self::Tensor(err.to_string())
    }
}

/// A decoded JPEG image containing the output tensor, dimensions, and cropped luma plane.
#[derive(Clone, Debug)]
pub struct DecodedImage {
    /// Output tensor with [`DType::U8`], shape `[H, W, C]`, and generation [`JPEG_DECODER_GENERATION_NUMERIC`].
    pub tensor: Tensor,
    /// Image width in pixels.
    pub width: u32,
    /// Image height in pixels.
    pub height: u32,
    /// Number of color components (1 for Grayscale, 3 for YCbCr).
    pub components: u8,
    /// Chroma subsampling mode.
    pub sampling: JpegSubsampling,
    /// Subsystem decoder generation string without '@', e.g. `decoder:fss-reference-jpeg-baseline:v1`.
    pub decoder_generation: String,
    /// Pre-conversion cropped Y (luma) plane `[width * height]`.
    pub(crate) luma_plane: Vec<u8>,
    /// SHA-256 hex digest of [`DecodedImage::luma`].
    pub luma_sha256: String,
}

impl DecodedImage {
    /// Returns the cropped, tightly packed pre-conversion Y plane `[width * height]`.
    #[must_use]
    pub fn luma(&self) -> &[u8] {
        &self.luma_plane
    }

    /// Returns the tightly packed decoded pixel bytes from the output tensor.
    #[must_use]
    pub fn pixels(&self) -> &[u8] {
        self.tensor.view().storage().as_slice()
    }
}

#[derive(Clone, Copy, Debug)]
struct ComponentSpec {
    id: u8,
    h_samp: u8,
    v_samp: u8,
    quant_id: usize,
    dc_table_id: usize,
    ac_table_id: usize,
}

#[derive(Clone, Debug)]
struct HuffmanTable {
    mincode: [i32; 17],
    maxcode: [i32; 17],
    valptr: [usize; 17],
    values: Vec<u8>,
}

impl HuffmanTable {
    fn build(bits: &[u8; 16], values: Vec<u8>) -> Result<Self, JpegDecodeError> {
        let total_symbols: usize = bits.iter().map(|&b| b as usize).sum();
        if total_symbols > 256 || values.len() > 256 {
            return Err(JpegDecodeError::InvalidSyntax(format!(
                "Huffman table exceeds 256 symbols: declared {total_symbols}, provided {}",
                values.len()
            )));
        }

        let mut mincode = [0i32; 17];
        let mut maxcode = [-1i32; 17];
        let mut valptr = [0usize; 17];

        let mut code = 0i32;
        let mut val_idx = 0usize;

        for l in 1..=16 {
            let count = bits[l - 1] as usize;
            let max_available = 1usize << l;
            if (code as usize).saturating_add(count) > max_available {
                return Err(JpegDecodeError::InvalidSyntax(format!(
                    "over-subscribed Huffman table at length {l}: code {code} + count {count} > {max_available}"
                )));
            }

            if count == 0 {
                maxcode[l] = -1;
                mincode[l] = 0;
                valptr[l] = 0;
            } else {
                mincode[l] = code;
                valptr[l] = val_idx;
                code = code.checked_add(count as i32 - 1).ok_or_else(|| {
                    JpegDecodeError::InvalidSyntax("Huffman code overflow".into())
                })?;
                maxcode[l] = code;
                val_idx += count;
                code += 1;
            }
            code <<= 1;
        }

        if val_idx != values.len() {
            return Err(JpegDecodeError::InvalidSyntax(format!(
                "Huffman table value count mismatch: declared {val_idx}, provided {}",
                values.len()
            )));
        }

        Ok(Self {
            mincode,
            maxcode,
            valptr,
            values,
        })
    }

    fn decode_symbol(&self, reader: &mut BitReader, mcu_row: u32) -> Result<u8, JpegDecodeError> {
        let mut i = 1usize;
        let mut code = reader.read_bit(mcu_row)? as i32;

        while code > self.maxcode[i] {
            i += 1;
            if i > 16 {
                return Err(JpegDecodeError::InvalidSyntax(
                    "invalid Huffman code exceeds 16 bits".into(),
                ));
            }
            let next_bit = reader.read_bit(mcu_row)? as i32;
            code = (code << 1) | next_bit;
        }

        if code < self.mincode[i] {
            return Err(JpegDecodeError::InvalidSyntax(
                "invalid Huffman code below mincode".into(),
            ));
        }

        let offset = (code - self.mincode[i]) as usize;
        let j = self.valptr[i] + offset;
        if j >= self.values.len() {
            return Err(JpegDecodeError::InvalidSyntax(
                "Huffman symbol index out of bounds".into(),
            ));
        }

        Ok(self.values[j])
    }
}

struct BitReader<'a> {
    bytes: &'a [u8],
    pos: usize,
    bit_buffer: u32,
    bits_in_buffer: u8,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            bit_buffer: 0,
            bits_in_buffer: 0,
        }
    }

    fn read_bit(&mut self, mcu_row: u32) -> Result<u8, JpegDecodeError> {
        if self.bits_in_buffer == 0 {
            let b = self.read_next_byte(mcu_row)?;
            self.bit_buffer = b as u32;
            self.bits_in_buffer = 8;
        }
        self.bits_in_buffer -= 1;
        Ok(((self.bit_buffer >> self.bits_in_buffer) & 1) as u8)
    }

    fn read_bits(&mut self, count: u8, mcu_row: u32) -> Result<u32, JpegDecodeError> {
        let mut val = 0u32;
        for _ in 0..count {
            val = (val << 1) | (self.read_bit(mcu_row)? as u32);
        }
        Ok(val)
    }

    fn read_next_byte(&mut self, mcu_row: u32) -> Result<u8, JpegDecodeError> {
        if self.pos >= self.bytes.len() {
            return Err(JpegDecodeError::Truncated { mcu_row });
        }
        let b = self.bytes[self.pos];
        self.pos += 1;
        if b == 0xFF {
            if self.pos >= self.bytes.len() {
                return Err(JpegDecodeError::Truncated { mcu_row });
            }
            let next = self.bytes[self.pos];
            if next == 0x00 {
                // Byte stuffing: 0xFF 0x00 represents a literal 0xFF
                self.pos += 1;
                Ok(0xFF)
            } else if (0xD0..=0xD7).contains(&next) {
                Err(JpegDecodeError::InvalidSyntax(format!(
                    "unexpected restart marker 0x{next:02X} inside entropy stream"
                )))
            } else if next == 0xD9 {
                // EOI encountered prematurely before all expected MCUs
                Err(JpegDecodeError::Truncated { mcu_row })
            } else {
                Err(JpegDecodeError::InvalidSyntax(format!(
                    "unexpected marker 0xFF{next:02X} inside entropy stream"
                )))
            }
        } else {
            Ok(b)
        }
    }

    fn consume_restart_marker(
        &mut self,
        expected_idx: u8,
        mcu_row: u32,
    ) -> Result<(), JpegDecodeError> {
        self.bit_buffer = 0;
        self.bits_in_buffer = 0;

        if self.pos >= self.bytes.len() {
            return Err(JpegDecodeError::Truncated { mcu_row });
        }

        if self.bytes[self.pos] != 0xFF {
            return Err(JpegDecodeError::InvalidSyntax(format!(
                "missing restart marker RST{} at MCU row {mcu_row}: expected 0xFF, found 0x{:02X}",
                expected_idx & 7,
                self.bytes[self.pos]
            )));
        }

        while self.pos < self.bytes.len() && self.bytes[self.pos] == 0xFF {
            self.pos += 1;
        }

        if self.pos >= self.bytes.len() {
            return Err(JpegDecodeError::Truncated { mcu_row });
        }

        let marker_code = self.bytes[self.pos];
        self.pos += 1;
        let expected_marker = 0xD0 + (expected_idx & 7);
        if marker_code != expected_marker {
            return Err(JpegDecodeError::InvalidSyntax(format!(
                "expected restart marker RST{} (0x{expected_marker:02X}), got 0x{marker_code:02X}",
                expected_idx & 7,
            )));
        }

        Ok(())
    }
}

fn extend_sign(bits: u32, size: u8) -> i32 {
    if size == 0 {
        0
    } else if bits < (1 << (size - 1)) {
        (bits as i32) - ((1 << size) - 1)
    } else {
        bits as i32
    }
}

fn decode_block(
    reader: &mut BitReader,
    prev_dc: &mut i32,
    dc_table: &HuffmanTable,
    ac_table: &HuffmanTable,
    q_table: &[u16; 64],
    mcu_row: u32,
) -> Result<[i32; 64], JpegDecodeError> {
    let mut block = [0i32; 64];

    // 1. Decode DC coefficient
    let dc_size = dc_table.decode_symbol(reader, mcu_row)?;
    if dc_size > 11 {
        return Err(JpegDecodeError::InvalidSyntax(format!(
            "DC magnitude size {dc_size} > 11 in 8-bit baseline"
        )));
    }
    let dc_diff = if dc_size > 0 {
        let bits = reader.read_bits(dc_size, mcu_row)?;
        extend_sign(bits, dc_size)
    } else {
        0
    };
    *prev_dc = prev_dc.checked_add(dc_diff).ok_or_else(|| {
        JpegDecodeError::InvalidSyntax("DC coefficient arithmetic overflow".into())
    })?;
    block[0] = prev_dc
        .checked_mul(q_table[0] as i32)
        .ok_or_else(|| JpegDecodeError::InvalidSyntax("DC dequantization overflow".into()))?;

    // 2. Decode AC coefficients
    let mut k = 1usize;
    while k < 64 {
        let ac_sym = ac_table.decode_symbol(reader, mcu_row)?;
        if ac_sym == 0x00 {
            // EOB: all remaining coefficients in this block are zero
            break;
        }

        let run = (ac_sym >> 4) as usize;
        let size = ac_sym & 0x0F;

        if run > 0 {
            k += run;
            if k >= 64 {
                return Err(JpegDecodeError::InvalidSyntax(format!(
                    "AC zero-run {run} exceeds block capacity at k={k}"
                )));
            }
        }

        if size > 0 {
            if size > 10 {
                return Err(JpegDecodeError::InvalidSyntax(format!(
                    "AC magnitude size {size} > 10 in 8-bit baseline"
                )));
            }
            let bits = reader.read_bits(size, mcu_row)?;
            let coeff = extend_sign(bits, size);
            block[k] = coeff.checked_mul(q_table[k] as i32).ok_or_else(|| {
                JpegDecodeError::InvalidSyntax("AC dequantization overflow".into())
            })?;
            k += 1;
        } else if ac_sym == 0xF0 {
            // ZRL: 16 zeroes total (15 skipped by run, 1 for this symbol)
            k += 1;
        } else {
            return Err(JpegDecodeError::InvalidSyntax(format!(
                "invalid AC symbol 0x{ac_sym:02X} with zero size"
            )));
        }
    }

    Ok(block)
}

fn idct_8x8(dequant: &[[i32; 8]; 8]) -> Result<[[u8; 8]; 8], JpegDecodeError> {
    // Pass 1: Columns, keeping PASS1_BITS extra fractional bits.
    let mut step1 = [[0i32; 8]; 8];
    for c in 0..8 {
        if dequant[1][c] == 0
            && dequant[2][c] == 0
            && dequant[3][c] == 0
            && dequant[4][c] == 0
            && dequant[5][c] == 0
            && dequant[6][c] == 0
            && dequant[7][c] == 0
        {
            let dc_val =
                (IDCT_BASIS[0][0] as i64 * dequant[0][c] as i64 + PASS1_ROUND) >> PASS1_SHIFT;
            let dc_val_i32 = i32::try_from(dc_val)
                .map_err(|_| JpegDecodeError::InvalidSyntax("IDCT dc_val overflow".into()))?;
            for row in &mut step1 {
                row[c] = dc_val_i32;
            }
        } else {
            for r in 0..8 {
                let mut sum = PASS1_ROUND;
                for k in 0..8 {
                    sum += IDCT_BASIS[r][k] as i64 * dequant[k][c] as i64;
                }
                step1[r][c] = i32::try_from(sum >> PASS1_SHIFT)
                    .map_err(|_| JpegDecodeError::InvalidSyntax("IDCT step1 overflow".into()))?;
            }
        }
    }

    // Pass 2: Rows
    let mut out = [[0u8; 8]; 8];
    for r in 0..8 {
        if step1[r][1] == 0
            && step1[r][2] == 0
            && step1[r][3] == 0
            && step1[r][4] == 0
            && step1[r][5] == 0
            && step1[r][6] == 0
            && step1[r][7] == 0
        {
            let dc_val =
                (IDCT_BASIS[0][0] as i64 * step1[r][0] as i64 + PASS2_ROUND) >> PASS2_SHIFT;
            let val = (dc_val + 128).clamp(0, 255) as u8;
            out[r].fill(val);
        } else {
            for c in 0..8 {
                let mut sum = PASS2_ROUND;
                for k in 0..8 {
                    sum += IDCT_BASIS[c][k] as i64 * step1[r][k] as i64;
                }
                let val = (sum >> PASS2_SHIFT) + 128;
                out[r][c] = val.clamp(0, 255) as u8;
            }
        }
    }

    Ok(out)
}

fn block_to_spatial(coeffs: &[i32; 64]) -> Result<[[u8; 8]; 8], JpegDecodeError> {
    let mut matrix = [[0i32; 8]; 8];
    let mut k = 0;
    while k < 64 {
        let natural_idx = ZIGZAG[k];
        let r = natural_idx / 8;
        let c = natural_idx % 8;
        matrix[r][c] = coeffs[k];
        k += 1;
    }
    idct_8x8(&matrix)
}

#[inline]
fn ycbcr_to_rgb(y: u8, cb: u8, cr: u8) -> (u8, u8, u8) {
    let cb_shift = cb as i32 - 128;
    let cr_shift = cr as i32 - 128;
    let y_fp = (y as i32) << 16;

    let r = ((y_fp + 91881 * cr_shift + 32768) >> 16).clamp(0, 255) as u8;
    let g = ((y_fp - 22553 * cb_shift - 46802 * cr_shift + 32768) >> 16).clamp(0, 255) as u8;
    let b = ((y_fp + 116130 * cb_shift + 32768) >> 16).clamp(0, 255) as u8;

    (r, g, b)
}

/// Decodes a deterministic baseline sequential JPEG byte stream into a [`DecodedImage`].
///
/// Refuses non-baseline processes (progressive SOF2, extended 12-bit, lossless, arithmetic coding,
/// 16-bit DQT, multi-scan, CMYK/Adobe transforms) with typed [`JpegDecodeError::Unsupported`].
/// An Adobe APP14 segment is accepted only when it declares transform 1 (YCbCr) on a
/// 3-component image or transform 0 or 1 on a 1-component image; transform 0 (RGB) on a
/// 3-component image and any transform above 1 are refused.
///
/// Every marker must carry its 0xFF prefix (any number of 0xFF fill bytes may precede the marker
/// code); a missing prefix is [`JpegDecodeError::InvalidSyntax`].
///
/// Bounded dimensions and resource limits are validated before allocation.
/// Checks cooperative cancellation with `cx` per MCU row.
///
/// # Errors
/// Returns [`JpegDecodeError`] on invalid syntax, unsupported features, truncation, or limits.
pub fn decode_baseline_jpeg(
    bytes: &[u8],
    limits: JpegDecodeLimits,
    cx: &ReplayCx,
) -> Result<DecodedImage, JpegDecodeError> {
    let mut limits = limits;
    limits.max_tensor_bytes = limits.max_tensor_bytes.min(MAX_STORAGE_BYTES);

    if bytes.len() < 2 || bytes[0] != 0xFF || bytes[1] != 0xD8 {
        return Err(JpegDecodeError::InvalidHeader(
            "missing SOI marker (0xFFD8)".into(),
        ));
    }

    let mut pos = 2usize;
    let mut dqt_tables = [const { None }; 4];
    let mut dc_huff_tables: [Option<HuffmanTable>; 4] = [const { None }; 4];
    let mut ac_huff_tables: [Option<HuffmanTable>; 4] = [const { None }; 4];

    let mut width = 0u32;
    let mut height = 0u32;
    let mut components = 0u8;
    let mut sampling = JpegSubsampling::Grayscale;
    let mut comp_specs: Vec<ComponentSpec> = Vec::new();
    let mut restart_interval = 0u16;
    let mut total_huffman_symbols = 0usize;
    let mut seen_sof = false;
    let mut adobe_transform: Option<u8> = None;

    // Parse marker segments until SOS
    while pos < bytes.len() {
        // T.81 B.1.1.2: a marker is 0xFF followed by a code, and any number of 0xFF fill bytes
        // may precede the code. A marker code without its 0xFF prefix is invalid syntax.
        if bytes[pos] != 0xFF {
            return Err(JpegDecodeError::InvalidSyntax(format!(
                "expected marker prefix 0xFF at offset {pos}, found 0x{:02X}",
                bytes[pos]
            )));
        }
        while pos < bytes.len() && bytes[pos] == 0xFF {
            pos += 1;
        }
        if pos >= bytes.len() {
            return Err(JpegDecodeError::Truncated { mcu_row: 0 });
        }

        let marker = bytes[pos];
        pos += 1;

        match marker {
            0xD8 => {
                return Err(JpegDecodeError::InvalidSyntax(
                    "unexpected duplicate SOI marker".into(),
                ));
            }
            0xD9 => {
                return Err(JpegDecodeError::Truncated { mcu_row: 0 });
            }
            // SOF0: Baseline DCT
            0xC0 => {
                if seen_sof {
                    return Err(JpegDecodeError::InvalidSyntax(
                        "duplicate SOF0 marker".into(),
                    ));
                }
                if pos + 2 > bytes.len() {
                    return Err(JpegDecodeError::Truncated { mcu_row: 0 });
                }
                let len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
                if len < 8 || pos + len > bytes.len() {
                    return Err(JpegDecodeError::Truncated { mcu_row: 0 });
                }
                pos += 2;

                let precision = bytes[pos];
                if precision != 8 {
                    return Err(JpegDecodeError::Unsupported {
                        process: format!("{precision}-bit sample precision"),
                    });
                }
                height = u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]]) as u32;
                width = u16::from_be_bytes([bytes[pos + 3], bytes[pos + 4]]) as u32;
                components = bytes[pos + 5];

                if width == 0 || height == 0 {
                    return Err(JpegDecodeError::InvalidHeader(
                        "image dimensions must be non-zero".into(),
                    ));
                }
                if width > limits.max_width {
                    return Err(JpegDecodeError::LimitExceeded {
                        limit: format!("width {width} exceeds max_width {}", limits.max_width),
                    });
                }
                if height > limits.max_height {
                    return Err(JpegDecodeError::LimitExceeded {
                        limit: format!("height {height} exceeds max_height {}", limits.max_height),
                    });
                }
                let total_pixels = (width as u64).checked_mul(height as u64).ok_or_else(|| {
                    JpegDecodeError::LimitExceeded {
                        limit: "total pixels multiplication overflow".into(),
                    }
                })?;
                if total_pixels > limits.max_pixels {
                    return Err(JpegDecodeError::LimitExceeded {
                        limit: format!(
                            "total pixels {total_pixels} exceeds max_pixels {}",
                            limits.max_pixels
                        ),
                    });
                }

                if components == 4 {
                    return Err(JpegDecodeError::Unsupported {
                        process: "CMYK or 4-component".to_string(),
                    });
                }
                if components != 1 && components != 3 {
                    return Err(JpegDecodeError::Unsupported {
                        process: format!("{components}-component image"),
                    });
                }

                let channels = if components == 1 { 1usize } else { 3usize };
                let tensor_bytes =
                    (total_pixels as usize)
                        .checked_mul(channels)
                        .ok_or_else(|| JpegDecodeError::LimitExceeded {
                            limit: "tensor bytes multiplication overflow".into(),
                        })?;
                if tensor_bytes > limits.max_tensor_bytes {
                    return Err(JpegDecodeError::LimitExceeded {
                        limit: format!(
                            "tensor bytes {tensor_bytes} exceeds max_tensor_bytes {}",
                            limits.max_tensor_bytes
                        ),
                    });
                }

                let expected_len = 8 + 3 * (components as usize);
                if len != expected_len {
                    return Err(JpegDecodeError::InvalidSyntax(format!(
                        "SOF0 length mismatch: declared {len}, expected {expected_len}"
                    )));
                }

                comp_specs.clear();
                let mut c_idx = 0usize;
                while c_idx < components as usize {
                    let c_base = pos + 6 + c_idx * 3;
                    let id = bytes[c_base];
                    let samp = bytes[c_base + 1];
                    let q_id = bytes[c_base + 2] as usize;
                    let h_samp = samp >> 4;
                    let v_samp = samp & 0x0F;
                    if h_samp == 0 || h_samp > 4 || v_samp == 0 || v_samp > 4 {
                        return Err(JpegDecodeError::InvalidSyntax(format!(
                            "sampling factor {h_samp}x{v_samp} outside 1..=4"
                        )));
                    }
                    if q_id > 3 {
                        return Err(JpegDecodeError::InvalidSyntax(format!(
                            "quantization table id {q_id} > 3"
                        )));
                    }
                    comp_specs.push(ComponentSpec {
                        id,
                        h_samp,
                        v_samp,
                        quant_id: q_id,
                        dc_table_id: 0,
                        ac_table_id: 0,
                    });
                    c_idx += 1;
                }

                if components == 1 {
                    sampling = JpegSubsampling::Grayscale;
                } else {
                    let y_spec = comp_specs[0];
                    let cb_spec = comp_specs[1];
                    let cr_spec = comp_specs[2];

                    if cb_spec.h_samp != 1
                        || cb_spec.v_samp != 1
                        || cr_spec.h_samp != 1
                        || cr_spec.v_samp != 1
                    {
                        return Err(JpegDecodeError::Unsupported {
                            process: "chroma sampling factors must be 1x1".to_string(),
                        });
                    }

                    if y_spec.h_samp == 1 && y_spec.v_samp == 1 {
                        sampling = JpegSubsampling::Yuv444;
                    } else if y_spec.h_samp == 2 && y_spec.v_samp == 2 {
                        sampling = JpegSubsampling::Yuv420;
                    } else if y_spec.h_samp == 2 && y_spec.v_samp == 1 {
                        sampling = JpegSubsampling::Yuv422;
                    } else {
                        return Err(JpegDecodeError::Unsupported {
                            process: format!(
                                "sampling factors H={}, V={}",
                                y_spec.h_samp, y_spec.v_samp
                            ),
                        });
                    }
                }

                seen_sof = true;
                pos += len - 2;
            }
            // SOF1: Extended Sequential DCT
            0xC1 => {
                return Err(JpegDecodeError::Unsupported {
                    process: "extended sequential SOF1".to_string(),
                });
            }
            // SOF2: Progressive DCT
            0xC2 => {
                return Err(JpegDecodeError::Unsupported {
                    process: "progressive SOF2".to_string(),
                });
            }
            // SOF3: Lossless
            0xC3 => {
                return Err(JpegDecodeError::Unsupported {
                    process: "lossless SOF3".to_string(),
                });
            }
            // Arithmetic coding processes
            0xC9..=0xCC => {
                return Err(JpegDecodeError::Unsupported {
                    process: "arithmetic coding".to_string(),
                });
            }
            0xC5..=0xC7 | 0xCD..=0xCF => {
                return Err(JpegDecodeError::Unsupported {
                    process: format!("unsupported SOF marker 0x{marker:02X}"),
                });
            }
            // DQT: Define Quantization Table
            0xDB => {
                if pos + 2 > bytes.len() {
                    return Err(JpegDecodeError::Truncated { mcu_row: 0 });
                }
                let len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
                if len < 2 || pos + len > bytes.len() {
                    return Err(JpegDecodeError::Truncated { mcu_row: 0 });
                }
                pos += 2;
                let mut remaining = len - 2;

                while remaining > 0 {
                    if remaining < 65 {
                        return Err(JpegDecodeError::InvalidSyntax(
                            "truncated DQT table segment".into(),
                        ));
                    }
                    let info = bytes[pos];
                    pos += 1;
                    remaining -= 1;
                    let precision = info >> 4;
                    let table_id = (info & 0x0F) as usize;

                    if precision != 0 {
                        return Err(JpegDecodeError::Unsupported {
                            process: "16-bit DQT".to_string(),
                        });
                    }
                    if table_id > 3 {
                        return Err(JpegDecodeError::InvalidSyntax(format!(
                            "quantization table id {table_id} > 3"
                        )));
                    }

                    let mut q = [0u16; 64];
                    let mut k = 0;
                    while k < 64 {
                        let val = bytes[pos + k] as u16;
                        if val == 0 {
                            return Err(JpegDecodeError::InvalidSyntax(
                                "quantization table entry cannot be zero".into(),
                            ));
                        }
                        q[k] = val;
                        k += 1;
                    }
                    dqt_tables[table_id] = Some(q);
                    pos += 64;
                    remaining -= 64;
                }
            }
            // DHT: Define Huffman Table
            0xC4 => {
                if pos + 2 > bytes.len() {
                    return Err(JpegDecodeError::Truncated { mcu_row: 0 });
                }
                let len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
                if len < 2 || pos + len > bytes.len() {
                    return Err(JpegDecodeError::Truncated { mcu_row: 0 });
                }
                pos += 2;
                let mut remaining = len - 2;

                while remaining > 0 {
                    if remaining < 17 {
                        return Err(JpegDecodeError::InvalidSyntax(
                            "truncated DHT table header".into(),
                        ));
                    }
                    let info = bytes[pos];
                    pos += 1;
                    remaining -= 1;
                    let table_class = info >> 4;
                    let table_id = (info & 0x0F) as usize;

                    if table_class > 1 {
                        return Err(JpegDecodeError::InvalidSyntax(format!(
                            "invalid Huffman table class {table_class}"
                        )));
                    }
                    if table_id > 3 {
                        return Err(JpegDecodeError::InvalidSyntax(format!(
                            "Huffman table id {table_id} > 3"
                        )));
                    }

                    let mut bits = [0u8; 16];
                    bits.copy_from_slice(&bytes[pos..pos + 16]);
                    pos += 16;
                    remaining -= 16;

                    let count: usize = bits.iter().map(|&b| b as usize).sum();
                    total_huffman_symbols =
                        total_huffman_symbols.checked_add(count).ok_or_else(|| {
                            JpegDecodeError::LimitExceeded {
                                limit: "total Huffman symbols calculation overflow".into(),
                            }
                        })?;
                    if total_huffman_symbols > limits.max_huffman_symbols {
                        return Err(JpegDecodeError::LimitExceeded {
                            limit: format!(
                                "total Huffman symbols {total_huffman_symbols} exceeds max {}",
                                limits.max_huffman_symbols
                            ),
                        });
                    }

                    if remaining < count {
                        return Err(JpegDecodeError::InvalidSyntax(
                            "truncated DHT table values".into(),
                        ));
                    }
                    let values = bytes[pos..pos + count].to_vec();
                    pos += count;
                    remaining -= count;

                    let table = HuffmanTable::build(&bits, values)?;
                    if table_class == 0 {
                        dc_huff_tables[table_id] = Some(table);
                    } else {
                        ac_huff_tables[table_id] = Some(table);
                    }
                }
            }
            // DRI: Define Restart Interval
            0xDD => {
                if pos + 4 > bytes.len() {
                    return Err(JpegDecodeError::Truncated { mcu_row: 0 });
                }
                let len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
                if len != 4 {
                    return Err(JpegDecodeError::InvalidSyntax(
                        "DRI segment length must be 4".into(),
                    ));
                }
                pos += 2;
                restart_interval = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
                pos += 2;
            }
            // APP14 (Adobe transform detection)
            0xEE => {
                if pos + 2 > bytes.len() {
                    return Err(JpegDecodeError::Truncated { mcu_row: 0 });
                }
                let len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
                if len < 2 || pos + len > bytes.len() {
                    return Err(JpegDecodeError::Truncated { mcu_row: 0 });
                }
                pos += 2;
                if len >= 14 && &bytes[pos..pos + 5] == b"Adobe" {
                    let transform = bytes[pos + 11];
                    if transform > 1 {
                        return Err(JpegDecodeError::Unsupported {
                            process: format!("Adobe APP14 transform {transform}"),
                        });
                    }
                    // Whether transform 0 is acceptable depends on the component count, which
                    // may not be known yet; it is checked once the frame header has been seen.
                    adobe_transform = Some(transform);
                }
                pos += len - 2;
            }
            // APPn and COM markers
            0xE0..=0xED | 0xEF | 0xFE => {
                if pos + 2 > bytes.len() {
                    return Err(JpegDecodeError::Truncated { mcu_row: 0 });
                }
                let len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
                if len < 2 || pos + len > bytes.len() {
                    return Err(JpegDecodeError::Truncated { mcu_row: 0 });
                }
                pos += len;
            }
            // SOS: Start of Scan
            0xDA => {
                if !seen_sof {
                    return Err(JpegDecodeError::InvalidSyntax(
                        "SOS marker encountered before SOF0".into(),
                    ));
                }
                break;
            }
            // DNL: Define Number of Lines
            0xDC => {
                return Err(JpegDecodeError::Unsupported {
                    process: "DNL (Define Number of Lines)".to_string(),
                });
            }
            _ => {
                // Skip unknown marker segments with length field
                if pos + 2 > bytes.len() {
                    return Err(JpegDecodeError::Truncated { mcu_row: 0 });
                }
                let len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
                if len < 2 || pos + len > bytes.len() {
                    return Err(JpegDecodeError::Truncated { mcu_row: 0 });
                }
                pos += len;
            }
        }
    }

    if !seen_sof {
        return Err(JpegDecodeError::InvalidSyntax("missing SOF0 marker".into()));
    }

    // Adobe APP14 transform 0 on a 3-component image means the components are RGB, not YCbCr.
    // Decoding them as YCbCr would give silently wrong colours, so the stream is refused.
    if let Some(transform) = adobe_transform
        && components == 3
        && transform != 1
    {
        return Err(JpegDecodeError::Unsupported {
            process: format!(
                "Adobe APP14 transform {transform} on a 3-component image (only YCbCr transform 1 is supported)"
            ),
        });
    }

    // Parse SOS segment
    if pos + 2 > bytes.len() {
        return Err(JpegDecodeError::Truncated { mcu_row: 0 });
    }
    let sos_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    if sos_len < 6 || pos + sos_len > bytes.len() {
        return Err(JpegDecodeError::Truncated { mcu_row: 0 });
    }
    pos += 2;

    let scan_components = bytes[pos];
    pos += 1;

    if scan_components != components {
        return Err(JpegDecodeError::Unsupported {
            process: "multi-scan".to_string(),
        });
    }

    let expected_sos_len = 6 + 2 * (scan_components as usize);
    if sos_len != expected_sos_len {
        return Err(JpegDecodeError::InvalidSyntax(format!(
            "SOS length mismatch: declared {sos_len}, expected {expected_sos_len}"
        )));
    }

    let mut seen_sos_ids = [false; 256];
    let mut i = 0usize;
    while i < scan_components as usize {
        let comp_id = bytes[pos];
        let huff_ids = bytes[pos + 1];
        pos += 2;

        let dc_id = (huff_ids >> 4) as usize;
        let ac_id = (huff_ids & 0x0F) as usize;

        if dc_id > 3 {
            return Err(JpegDecodeError::InvalidSyntax(format!(
                "DC Huffman table id {dc_id} > 3"
            )));
        }
        if ac_id > 3 {
            return Err(JpegDecodeError::InvalidSyntax(format!(
                "AC Huffman table id {ac_id} > 3"
            )));
        }

        if seen_sos_ids[comp_id as usize] {
            return Err(JpegDecodeError::InvalidSyntax(format!(
                "duplicate component id {comp_id} in SOS"
            )));
        }
        seen_sos_ids[comp_id as usize] = true;

        if comp_specs[i].id != comp_id {
            return Err(JpegDecodeError::InvalidSyntax(format!(
                "SOS component order mismatch: scan component at index {i} has id {comp_id}, expected SOF component id {}",
                comp_specs[i].id
            )));
        }
        let spec = &mut comp_specs[i];
        spec.dc_table_id = dc_id;
        spec.ac_table_id = ac_id;
        i += 1;
    }

    let ss = bytes[pos];
    let se = bytes[pos + 1];
    let a_approx = bytes[pos + 2];
    pos += 3;

    if ss != 0 || se != 63 || a_approx != 0 {
        return Err(JpegDecodeError::Unsupported {
            process: "spectral selection or successive approximation".to_string(),
        });
    }

    // Verify required quantization and Huffman tables exist
    for spec in &comp_specs {
        if spec.quant_id > 3 || dqt_tables[spec.quant_id].is_none() {
            return Err(JpegDecodeError::InvalidSyntax(format!(
                "missing quantization table {}",
                spec.quant_id
            )));
        }
        if spec.dc_table_id > 3 || dc_huff_tables[spec.dc_table_id].is_none() {
            return Err(JpegDecodeError::InvalidSyntax(format!(
                "missing DC Huffman table {}",
                spec.dc_table_id
            )));
        }
        if spec.ac_table_id > 3 || ac_huff_tables[spec.ac_table_id].is_none() {
            return Err(JpegDecodeError::InvalidSyntax(format!(
                "missing AC Huffman table {}",
                spec.ac_table_id
            )));
        }
    }

    let (mcu_w, mcu_h) = match sampling {
        JpegSubsampling::Grayscale | JpegSubsampling::Yuv444 => (8u32, 8u32),
        JpegSubsampling::Yuv420 => (16u32, 16u32),
        JpegSubsampling::Yuv422 => (16u32, 8u32),
    };

    let mcus_x = width.div_ceil(mcu_w);
    let mcus_y = height.div_ceil(mcu_h);

    // Scan-byte bound, checked BEFORE any plane is allocated: every block costs at least
    // MIN_BITS_PER_BLOCK entropy-coded bits, so a header declaring more blocks than the
    // remaining bytes can hold is refused as Truncated without allocating. The planes below are
    // the only allocations proportional to the image size, and they precede the first
    // cancellation checkpoint.
    let scan_bytes = &bytes[pos..];
    let blocks_per_mcu: u64 = match sampling {
        JpegSubsampling::Grayscale => 1,
        JpegSubsampling::Yuv444 => 3,
        JpegSubsampling::Yuv422 => 4,
        JpegSubsampling::Yuv420 => 6,
    };
    let block_overflow = || JpegDecodeError::LimitExceeded {
        limit: "block count multiplication overflow".into(),
    };
    let blocks_per_mcu_row = u64::from(mcus_x)
        .checked_mul(blocks_per_mcu)
        .ok_or_else(block_overflow)?;
    let total_blocks = blocks_per_mcu_row
        .checked_mul(u64::from(mcus_y))
        .ok_or_else(block_overflow)?;
    let available_bits = (scan_bytes.len() as u64)
        .checked_mul(8)
        .ok_or_else(block_overflow)?;
    let max_blocks = available_bits / MIN_BITS_PER_BLOCK;
    if total_blocks > max_blocks {
        let reachable_rows = (max_blocks / blocks_per_mcu_row).min(u64::from(mcus_y));
        let mcu_row = u32::try_from(reachable_rows).map_err(|_| block_overflow())?;
        return Err(JpegDecodeError::Truncated { mcu_row });
    }

    let total_pixels_usize = (width as usize) * (height as usize);
    let mut luma_plane = vec![0u8; total_pixels_usize];
    let mut rgb_plane = if components == 3 {
        vec![0u8; total_pixels_usize * 3]
    } else {
        Vec::new()
    };

    let mut reader = BitReader::new(scan_bytes);

    let mut prev_dc_y = 0i32;
    let mut prev_dc_cb = 0i32;
    let mut prev_dc_cr = 0i32;
    let mut restart_count = 0u32;
    let mut mcu_idx = 0usize;

    // Outer loop: MCU rows
    let mut my = 0u32;
    while my < mcus_y {
        cx.checkpoint("jpeg_mcu_row")
            .map_err(|_| JpegDecodeError::Cancelled)?;

        let mut mx = 0u32;
        while mx < mcus_x {
            if restart_interval > 0
                && mcu_idx > 0
                && mcu_idx.is_multiple_of(restart_interval as usize)
            {
                reader.consume_restart_marker((restart_count & 7) as u8, my)?;
                restart_count =
                    restart_count
                        .checked_add(1)
                        .ok_or_else(|| JpegDecodeError::LimitExceeded {
                            limit: "restart interval count overflow".into(),
                        })?;
                if restart_count > limits.max_restart_intervals {
                    return Err(JpegDecodeError::LimitExceeded {
                        limit: format!(
                            "restart interval count {restart_count} exceeds max {}",
                            limits.max_restart_intervals
                        ),
                    });
                }
                prev_dc_y = 0;
                prev_dc_cb = 0;
                prev_dc_cr = 0;
            }

            let ox = mx * mcu_w;
            let oy = my * mcu_h;

            match sampling {
                JpegSubsampling::Grayscale => {
                    let y_spec = &comp_specs[0];
                    let q_y = dqt_tables[y_spec.quant_id]
                        .as_ref()
                        .ok_or_else(|| JpegDecodeError::InvalidSyntax("missing luma DQT".into()))?;
                    let dc_huff = dc_huff_tables[y_spec.dc_table_id].as_ref().ok_or_else(|| {
                        JpegDecodeError::InvalidSyntax("missing luma DC DHT".into())
                    })?;
                    let ac_huff = ac_huff_tables[y_spec.ac_table_id].as_ref().ok_or_else(|| {
                        JpegDecodeError::InvalidSyntax("missing luma AC DHT".into())
                    })?;

                    let coeffs =
                        decode_block(&mut reader, &mut prev_dc_y, dc_huff, ac_huff, q_y, my)?;
                    let spatial = block_to_spatial(&coeffs)?;

                    let mut r = 0u32;
                    while r < 8 {
                        let py = oy + r;
                        if py < height {
                            let mut c = 0u32;
                            while c < 8 {
                                let px = ox + c;
                                if px < width {
                                    luma_plane[(py * width + px) as usize] =
                                        spatial[r as usize][c as usize];
                                }
                                c += 1;
                            }
                        }
                        r += 1;
                    }
                }
                JpegSubsampling::Yuv444 => {
                    let y_spec = &comp_specs[0];
                    let cb_spec = &comp_specs[1];
                    let cr_spec = &comp_specs[2];

                    let q_y = dqt_tables[y_spec.quant_id]
                        .as_ref()
                        .ok_or_else(|| JpegDecodeError::InvalidSyntax("missing Y DQT".into()))?;
                    let dc_y = dc_huff_tables[y_spec.dc_table_id]
                        .as_ref()
                        .ok_or_else(|| JpegDecodeError::InvalidSyntax("missing Y DC DHT".into()))?;
                    let ac_y = ac_huff_tables[y_spec.ac_table_id]
                        .as_ref()
                        .ok_or_else(|| JpegDecodeError::InvalidSyntax("missing Y AC DHT".into()))?;

                    let q_cb = dqt_tables[cb_spec.quant_id]
                        .as_ref()
                        .ok_or_else(|| JpegDecodeError::InvalidSyntax("missing Cb DQT".into()))?;
                    let dc_cb = dc_huff_tables[cb_spec.dc_table_id]
                        .as_ref()
                        .ok_or_else(|| {
                            JpegDecodeError::InvalidSyntax("missing Cb DC DHT".into())
                        })?;
                    let ac_cb = ac_huff_tables[cb_spec.ac_table_id]
                        .as_ref()
                        .ok_or_else(|| {
                            JpegDecodeError::InvalidSyntax("missing Cb AC DHT".into())
                        })?;

                    let q_cr = dqt_tables[cr_spec.quant_id]
                        .as_ref()
                        .ok_or_else(|| JpegDecodeError::InvalidSyntax("missing Cr DQT".into()))?;
                    let dc_cr = dc_huff_tables[cr_spec.dc_table_id]
                        .as_ref()
                        .ok_or_else(|| {
                            JpegDecodeError::InvalidSyntax("missing Cr DC DHT".into())
                        })?;
                    let ac_cr = ac_huff_tables[cr_spec.ac_table_id]
                        .as_ref()
                        .ok_or_else(|| {
                            JpegDecodeError::InvalidSyntax("missing Cr AC DHT".into())
                        })?;

                    let y_coeffs = decode_block(&mut reader, &mut prev_dc_y, dc_y, ac_y, q_y, my)?;
                    let cb_coeffs =
                        decode_block(&mut reader, &mut prev_dc_cb, dc_cb, ac_cb, q_cb, my)?;
                    let cr_coeffs =
                        decode_block(&mut reader, &mut prev_dc_cr, dc_cr, ac_cr, q_cr, my)?;

                    let y_spatial = block_to_spatial(&y_coeffs)?;
                    let cb_spatial = block_to_spatial(&cb_coeffs)?;
                    let cr_spatial = block_to_spatial(&cr_coeffs)?;

                    let mut r = 0u32;
                    while r < 8 {
                        let py = oy + r;
                        if py < height {
                            let mut c = 0u32;
                            while c < 8 {
                                let px = ox + c;
                                if px < width {
                                    let y_val = y_spatial[r as usize][c as usize];
                                    let cb_val = cb_spatial[r as usize][c as usize];
                                    let cr_val = cr_spatial[r as usize][c as usize];

                                    let idx = (py * width + px) as usize;
                                    luma_plane[idx] = y_val;

                                    let (red, green, blue) = ycbcr_to_rgb(y_val, cb_val, cr_val);
                                    let rgb_idx = idx * 3;
                                    rgb_plane[rgb_idx] = red;
                                    rgb_plane[rgb_idx + 1] = green;
                                    rgb_plane[rgb_idx + 2] = blue;
                                }
                                c += 1;
                            }
                        }
                        r += 1;
                    }
                }
                JpegSubsampling::Yuv420 => {
                    let y_spec = &comp_specs[0];
                    let cb_spec = &comp_specs[1];
                    let cr_spec = &comp_specs[2];

                    let q_y = dqt_tables[y_spec.quant_id]
                        .as_ref()
                        .ok_or_else(|| JpegDecodeError::InvalidSyntax("missing Y DQT".into()))?;
                    let dc_y = dc_huff_tables[y_spec.dc_table_id]
                        .as_ref()
                        .ok_or_else(|| JpegDecodeError::InvalidSyntax("missing Y DC DHT".into()))?;
                    let ac_y = ac_huff_tables[y_spec.ac_table_id]
                        .as_ref()
                        .ok_or_else(|| JpegDecodeError::InvalidSyntax("missing Y AC DHT".into()))?;

                    let q_cb = dqt_tables[cb_spec.quant_id]
                        .as_ref()
                        .ok_or_else(|| JpegDecodeError::InvalidSyntax("missing Cb DQT".into()))?;
                    let dc_cb = dc_huff_tables[cb_spec.dc_table_id]
                        .as_ref()
                        .ok_or_else(|| {
                            JpegDecodeError::InvalidSyntax("missing Cb DC DHT".into())
                        })?;
                    let ac_cb = ac_huff_tables[cb_spec.ac_table_id]
                        .as_ref()
                        .ok_or_else(|| {
                            JpegDecodeError::InvalidSyntax("missing Cb AC DHT".into())
                        })?;

                    let q_cr = dqt_tables[cr_spec.quant_id]
                        .as_ref()
                        .ok_or_else(|| JpegDecodeError::InvalidSyntax("missing Cr DQT".into()))?;
                    let dc_cr = dc_huff_tables[cr_spec.dc_table_id]
                        .as_ref()
                        .ok_or_else(|| {
                            JpegDecodeError::InvalidSyntax("missing Cr DC DHT".into())
                        })?;
                    let ac_cr = ac_huff_tables[cr_spec.ac_table_id]
                        .as_ref()
                        .ok_or_else(|| {
                            JpegDecodeError::InvalidSyntax("missing Cr AC DHT".into())
                        })?;

                    // 4 Y blocks: Y00, Y01, Y10, Y11
                    let y00 = block_to_spatial(&decode_block(
                        &mut reader,
                        &mut prev_dc_y,
                        dc_y,
                        ac_y,
                        q_y,
                        my,
                    )?)?;
                    let y01 = block_to_spatial(&decode_block(
                        &mut reader,
                        &mut prev_dc_y,
                        dc_y,
                        ac_y,
                        q_y,
                        my,
                    )?)?;
                    let y10 = block_to_spatial(&decode_block(
                        &mut reader,
                        &mut prev_dc_y,
                        dc_y,
                        ac_y,
                        q_y,
                        my,
                    )?)?;
                    let y11 = block_to_spatial(&decode_block(
                        &mut reader,
                        &mut prev_dc_y,
                        dc_y,
                        ac_y,
                        q_y,
                        my,
                    )?)?;

                    // Cb and Cr blocks (8x8 each, covering 16x16 luma pixels)
                    let cb_spatial = block_to_spatial(&decode_block(
                        &mut reader,
                        &mut prev_dc_cb,
                        dc_cb,
                        ac_cb,
                        q_cb,
                        my,
                    )?)?;
                    let cr_spatial = block_to_spatial(&decode_block(
                        &mut reader,
                        &mut prev_dc_cr,
                        dc_cr,
                        ac_cr,
                        q_cr,
                        my,
                    )?)?;

                    let mut dy = 0u32;
                    while dy < 16 {
                        let py = oy + dy;
                        if py < height {
                            let mut dx = 0u32;
                            while dx < 16 {
                                let px = ox + dx;
                                if px < width {
                                    let y_val = if dy < 8 {
                                        if dx < 8 {
                                            y00[dy as usize][dx as usize]
                                        } else {
                                            y01[dy as usize][(dx - 8) as usize]
                                        }
                                    } else if dx < 8 {
                                        y10[(dy - 8) as usize][dx as usize]
                                    } else {
                                        y11[(dy - 8) as usize][(dx - 8) as usize]
                                    };

                                    // Chroma replication (2x2)
                                    let cb_val = cb_spatial[(dy / 2) as usize][(dx / 2) as usize];
                                    let cr_val = cr_spatial[(dy / 2) as usize][(dx / 2) as usize];

                                    let idx = (py * width + px) as usize;
                                    luma_plane[idx] = y_val;

                                    let (red, green, blue) = ycbcr_to_rgb(y_val, cb_val, cr_val);
                                    let rgb_idx = idx * 3;
                                    rgb_plane[rgb_idx] = red;
                                    rgb_plane[rgb_idx + 1] = green;
                                    rgb_plane[rgb_idx + 2] = blue;
                                }
                                dx += 1;
                            }
                        }
                        dy += 1;
                    }
                }
                JpegSubsampling::Yuv422 => {
                    let y_spec = &comp_specs[0];
                    let cb_spec = &comp_specs[1];
                    let cr_spec = &comp_specs[2];

                    let q_y = dqt_tables[y_spec.quant_id]
                        .as_ref()
                        .ok_or_else(|| JpegDecodeError::InvalidSyntax("missing Y DQT".into()))?;
                    let dc_y = dc_huff_tables[y_spec.dc_table_id]
                        .as_ref()
                        .ok_or_else(|| JpegDecodeError::InvalidSyntax("missing Y DC DHT".into()))?;
                    let ac_y = ac_huff_tables[y_spec.ac_table_id]
                        .as_ref()
                        .ok_or_else(|| JpegDecodeError::InvalidSyntax("missing Y AC DHT".into()))?;

                    let q_cb = dqt_tables[cb_spec.quant_id]
                        .as_ref()
                        .ok_or_else(|| JpegDecodeError::InvalidSyntax("missing Cb DQT".into()))?;
                    let dc_cb = dc_huff_tables[cb_spec.dc_table_id]
                        .as_ref()
                        .ok_or_else(|| {
                            JpegDecodeError::InvalidSyntax("missing Cb DC DHT".into())
                        })?;
                    let ac_cb = ac_huff_tables[cb_spec.ac_table_id]
                        .as_ref()
                        .ok_or_else(|| {
                            JpegDecodeError::InvalidSyntax("missing Cb AC DHT".into())
                        })?;

                    let q_cr = dqt_tables[cr_spec.quant_id]
                        .as_ref()
                        .ok_or_else(|| JpegDecodeError::InvalidSyntax("missing Cr DQT".into()))?;
                    let dc_cr = dc_huff_tables[cr_spec.dc_table_id]
                        .as_ref()
                        .ok_or_else(|| {
                            JpegDecodeError::InvalidSyntax("missing Cr DC DHT".into())
                        })?;
                    let ac_cr = ac_huff_tables[cr_spec.ac_table_id]
                        .as_ref()
                        .ok_or_else(|| {
                            JpegDecodeError::InvalidSyntax("missing Cr AC DHT".into())
                        })?;

                    // 2 Y blocks: Y0, Y1 (16x8 luma)
                    let y0 = block_to_spatial(&decode_block(
                        &mut reader,
                        &mut prev_dc_y,
                        dc_y,
                        ac_y,
                        q_y,
                        my,
                    )?)?;
                    let y1 = block_to_spatial(&decode_block(
                        &mut reader,
                        &mut prev_dc_y,
                        dc_y,
                        ac_y,
                        q_y,
                        my,
                    )?)?;

                    // Cb and Cr blocks (8x8 each, covering 16x8 luma pixels)
                    let cb_spatial = block_to_spatial(&decode_block(
                        &mut reader,
                        &mut prev_dc_cb,
                        dc_cb,
                        ac_cb,
                        q_cb,
                        my,
                    )?)?;
                    let cr_spatial = block_to_spatial(&decode_block(
                        &mut reader,
                        &mut prev_dc_cr,
                        dc_cr,
                        ac_cr,
                        q_cr,
                        my,
                    )?)?;

                    let mut dy = 0u32;
                    while dy < 8 {
                        let py = oy + dy;
                        if py < height {
                            let mut dx = 0u32;
                            while dx < 16 {
                                let px = ox + dx;
                                if px < width {
                                    let y_val = if dx < 8 {
                                        y0[dy as usize][dx as usize]
                                    } else {
                                        y1[dy as usize][(dx - 8) as usize]
                                    };

                                    // Chroma replication (2x1: horizontal 2x, vertical 1x)
                                    let cb_val = cb_spatial[dy as usize][(dx / 2) as usize];
                                    let cr_val = cr_spatial[dy as usize][(dx / 2) as usize];

                                    let idx = (py * width + px) as usize;
                                    luma_plane[idx] = y_val;

                                    let (red, green, blue) = ycbcr_to_rgb(y_val, cb_val, cr_val);
                                    let rgb_idx = idx * 3;
                                    rgb_plane[rgb_idx] = red;
                                    rgb_plane[rgb_idx + 1] = green;
                                    rgb_plane[rgb_idx + 2] = blue;
                                }
                                dx += 1;
                            }
                        }
                        dy += 1;
                    }
                }
            }

            mcu_idx += 1;
            mx += 1;
        }
        my += 1;
    }

    // Validate post-MCU stream: require valid EOI (0xFFD9), refuse missing EOI,
    // trailing garbage, second SOS/JPEG, or DNL segments.
    let scan_rest = &scan_bytes[reader.pos..];
    if scan_rest.is_empty() {
        return Err(JpegDecodeError::Truncated {
            mcu_row: mcus_y.saturating_sub(1),
        });
    }

    let mut eoi_idx = 0usize;
    loop {
        if eoi_idx >= scan_rest.len() {
            return Err(JpegDecodeError::Truncated {
                mcu_row: mcus_y.saturating_sub(1),
            });
        }

        let prev_idx = eoi_idx;
        while eoi_idx < scan_rest.len() && scan_rest[eoi_idx] == 0xFF {
            eoi_idx += 1;
        }

        if eoi_idx == prev_idx {
            return Err(JpegDecodeError::InvalidSyntax(format!(
                "missing EOI marker: expected 0xFFD9, got 0x{:02X}",
                scan_rest[prev_idx]
            )));
        }

        if eoi_idx >= scan_rest.len() {
            return Err(JpegDecodeError::Truncated {
                mcu_row: mcus_y.saturating_sub(1),
            });
        }

        let post_marker = scan_rest[eoi_idx];
        eoi_idx += 1;

        match post_marker {
            0xD9 => {
                let trailing = &scan_rest[eoi_idx..];
                if !trailing.is_empty() {
                    return Err(JpegDecodeError::InvalidSyntax(format!(
                        "trailing data after EOI marker ({} bytes)",
                        trailing.len()
                    )));
                }
                break;
            }
            0xE0..=0xEF | 0xFE => {
                if eoi_idx + 2 > scan_rest.len() {
                    return Err(JpegDecodeError::Truncated {
                        mcu_row: mcus_y.saturating_sub(1),
                    });
                }
                let seg_len =
                    u16::from_be_bytes([scan_rest[eoi_idx], scan_rest[eoi_idx + 1]]) as usize;
                if seg_len < 2 || eoi_idx + seg_len > scan_rest.len() {
                    return Err(JpegDecodeError::Truncated {
                        mcu_row: mcus_y.saturating_sub(1),
                    });
                }
                eoi_idx += seg_len;
            }
            0xDC => {
                return Err(JpegDecodeError::Unsupported {
                    process: "DNL (Define Number of Lines)".to_string(),
                });
            }
            0xDA => {
                return Err(JpegDecodeError::Unsupported {
                    process: "multi-scan (second SOS)".to_string(),
                });
            }
            0xD8 => {
                return Err(JpegDecodeError::InvalidSyntax(
                    "trailing data: second SOI marker encountered".to_string(),
                ));
            }
            other => {
                return Err(JpegDecodeError::InvalidSyntax(format!(
                    "expected EOI marker (0xFFD9), got 0xFF{other:02X}"
                )));
            }
        }
    }

    let channels = if components == 1 { 1usize } else { 3usize };
    let shape = Shape::new(vec![height as usize, width as usize, channels])?;

    let tensor_values = if components == 1 {
        &luma_plane[..]
    } else {
        &rgb_plane[..]
    };

    let tensor = Tensor::from_values(shape, tensor_values, JPEG_DECODER_GENERATION_NUMERIC)?;

    let luma_digest = ContentDigest::sha256(&luma_plane);
    let mut luma_sha256 = String::with_capacity(64);
    for b in luma_digest.bytes() {
        let _ = write!(&mut luma_sha256, "{b:02x}");
    }

    Ok(DecodedImage {
        tensor,
        width,
        height,
        components,
        sampling,
        decoder_generation: JPEG_DECODER_GENERATION.to_string(),
        luma_plane,
        luma_sha256,
    })
}
