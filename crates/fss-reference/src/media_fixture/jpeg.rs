#![forbid(unsafe_code)]
//! Fixture generation only.
//!
//! First-party deterministic baseline JPEG and MJPEG fixture encoder.
//! Used exclusively to synthesize byte-stable media fixtures and ground-truth
//! source pixel buffers for decoder and ingest qualification.

use std::fmt;

/// Standard Annex K.1 Luminance quantization table in natural order.
pub const BASE_LUMA_QUANT: [u8; 64] = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113,
    92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
];

/// Standard Annex K.1 Chrominance quantization table in natural order.
pub const BASE_CHROMA_QUANT: [u8; 64] = [
    17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99, 24, 26, 56, 99, 99, 99, 99, 99,
    47, 66, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
];

/// Natural to zig-zag mapping: `ZIGZAG[k]` is the row-major index in an 8x8 block.
pub const ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

/// Annex K.3 DC Luminance Huffman bit counts.
pub const LUMA_DC_BITS: [u8; 16] = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0];
/// Annex K.3 DC Luminance Huffman symbol values.
pub const LUMA_DC_VALS: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

/// Annex K.3 DC Chrominance Huffman bit counts.
pub const CHROMA_DC_BITS: [u8; 16] = [0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0];
/// Annex K.3 DC Chrominance Huffman symbol values.
pub const CHROMA_DC_VALS: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

/// Annex K.3 AC Luminance Huffman bit counts.
pub const LUMA_AC_BITS: [u8; 16] = [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 125];
/// Annex K.3 AC Luminance Huffman symbol values.
pub const LUMA_AC_VALS: [u8; 162] = [
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
    0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0,
    0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
    0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5,
    0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
    0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa,
];

/// Annex K.3 AC Chrominance Huffman bit counts.
pub const CHROMA_AC_BITS: [u8; 16] = [0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 119];
/// Annex K.3 AC Chrominance Huffman symbol values.
pub const CHROMA_AC_VALS: [u8; 162] = [
    0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06, 0x12, 0x41, 0x51, 0x07, 0x61, 0x71,
    0x13, 0x22, 0x32, 0x81, 0x08, 0x14, 0x42, 0x91, 0xa1, 0xb1, 0xc1, 0x09, 0x23, 0x33, 0x52, 0xf0,
    0x15, 0x62, 0x72, 0xd1, 0x0a, 0x16, 0x24, 0x34, 0xe1, 0x25, 0xf1, 0x17, 0x18, 0x19, 0x1a, 0x26,
    0x27, 0x28, 0x29, 0x2a, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5,
    0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3,
    0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
    0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa,
];

/// Computes the 8x8 orthonormal DCT-II basis matrix constants in f64.
/// `A[u][x] = C(u) * 0.5 * cos((2x + 1) * u * pi / 16)`.
pub fn compute_dct_basis() -> [[f64; 8]; 8] {
    let mut a = [[0.0f64; 8]; 8];
    let inv_sqrt8 = 1.0f64 / 8.0f64.sqrt();
    let mut x = 0;
    while x < 8 {
        a[0][x] = inv_sqrt8;
        x += 1;
    }
    let mut u = 1;
    while u < 8 {
        let u_f = u as f64;
        let mut x2 = 0;
        while x2 < 8 {
            let x_f = x2 as f64;
            a[u][x2] = 0.5f64 * ((2.0 * x_f + 1.0) * u_f * core::f64::consts::PI / 16.0).cos();
            x2 += 1;
        }
        u += 1;
    }
    a
}

/// Chroma subsampling formats supported by baseline JPEG fixtures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Subsampling {
    /// 1-component grayscale (Y only, 1x1).
    Grayscale,
    /// 3-component full color without subsampling (YCbCr 4:4:4, 1x1).
    Yuv444,
    /// 3-component quarter chroma resolution (YCbCr 4:2:0, 2x2).
    Yuv420,
    /// 3-component horizontal chroma subsampling (YCbCr 4:2:2, 2x1).
    Yuv422,
}

/// A custom marker segment inserted into the JPEG header (e.g. APPn or COM).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomMarker {
    /// Marker code (e.g. 0xE1 for APP1, 0xFE for COM).
    pub marker: u8,
    /// Payload bytes placed between marker length and subsequent segments.
    pub payload: Vec<u8>,
}

/// Configuration options for deterministic baseline JPEG synthesis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JpegConfig {
    /// Quality factor between 1 and 100 inclusive.
    pub quality: u32,
    /// Chroma subsampling mode.
    pub subsampling: Subsampling,
    /// Restart interval in MCUs (0 disables DRI and restart markers).
    pub restart_interval: u16,
    /// Optional custom marker segments emitted after APP0.
    pub custom_markers: Vec<CustomMarker>,
}

impl Default for JpegConfig {
    fn default() -> Self {
        Self {
            quality: 85,
            subsampling: Subsampling::Yuv420,
            restart_interval: 0,
            custom_markers: Vec::new(),
        }
    }
}

/// Errors originating from JPEG and MJPEG fixture synthesis or inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JpegError {
    /// Unknown fixture name.
    UnknownFixture(String),
    /// Dimension values were zero or exceeded JPEG format capacity.
    InvalidDimensions {
        /// Attempted width in pixels.
        width: u32,
        /// Attempted height in pixels.
        height: u32,
    },
    /// Channel or subsampling configuration is inconsistent.
    InvalidSampling(String),
    /// Pixel buffer length does not match specified dimensions and channel count.
    BufferLengthMismatch {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length provided.
        actual: usize,
    },
    /// Inconsistent or malformed payload.
    InvalidData(String),
}

impl fmt::Display for JpegError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFixture(id) => write!(formatter, "unknown fixture identifier: {id}"),
            Self::InvalidDimensions { width, height } => {
                write!(formatter, "invalid image dimensions: {width}x{height}")
            }
            Self::InvalidSampling(msg) => {
                write!(formatter, "invalid sampling configuration: {msg}")
            }
            Self::BufferLengthMismatch { expected, actual } => write!(
                formatter,
                "pixel buffer length mismatch: expected {expected} bytes, got {actual} bytes"
            ),
            Self::InvalidData(msg) => write!(formatter, "invalid data: {msg}"),
        }
    }
}

impl std::error::Error for JpegError {}

#[derive(Clone, Copy, Debug)]
struct HuffmanCode {
    code: u16,
    len: u8,
}

fn scale_quantization_table(base: &[u8; 64], quality: u32) -> [u8; 64] {
    let q = quality.clamp(1, 100);
    let scale = if q < 50 { 5000 / q } else { 200 - 2 * q };
    let mut table = [0u8; 64];
    let mut i = 0;
    while i < 64 {
        let val = (base[i] as u32 * scale + 50) / 100;
        table[i] = val.clamp(1, 255) as u8;
        i += 1;
    }
    table
}

fn build_huffman_codes(bits: &[u8; 16], values: &[u8]) -> [HuffmanCode; 256] {
    let mut table = [HuffmanCode { code: 0, len: 0 }; 256];
    let mut code = 0u16;
    let mut val_idx = 0;
    let mut len_minus_1 = 0;
    while len_minus_1 < 16 {
        let bit_len = (len_minus_1 + 1) as u8;
        let count = bits[len_minus_1] as usize;
        let mut c = 0;
        while c < count {
            if val_idx < values.len() {
                let symbol = values[val_idx] as usize;
                table[symbol] = HuffmanCode { code, len: bit_len };
                code = code.wrapping_add(1);
                val_idx += 1;
            }
            c += 1;
        }
        code = code.wrapping_shl(1);
        len_minus_1 += 1;
    }
    table
}

fn forward_dct(block: &[[f64; 8]; 8], basis: &[[f64; 8]; 8]) -> [[f64; 8]; 8] {
    let mut temp = [[0.0f64; 8]; 8];
    let mut u = 0;
    while u < 8 {
        let mut y = 0;
        while y < 8 {
            let mut sum = 0.0f64;
            let mut x = 0;
            while x < 8 {
                sum += basis[u][x] * block[x][y];
                x += 1;
            }
            temp[u][y] = sum;
            y += 1;
        }
        u += 1;
    }

    let mut out = [[0.0f64; 8]; 8];
    let mut u2 = 0;
    while u2 < 8 {
        let mut v = 0;
        while v < 8 {
            let mut sum = 0.0f64;
            let mut y = 0;
            while y < 8 {
                sum += temp[u2][y] * basis[v][y];
                y += 1;
            }
            out[u2][v] = sum;
            v += 1;
        }
        u2 += 1;
    }
    out
}

fn round_to_i32(val: f64) -> i32 {
    if val >= 0.0 {
        (val + 0.5).floor() as i32
    } else {
        (val - 0.5).ceil() as i32
    }
}

fn quantize_and_zigzag(dct: &[[f64; 8]; 8], q_table: &[u8; 64]) -> [i32; 64] {
    let mut out = [0i32; 64];
    let mut k = 0;
    while k < 64 {
        let natural_idx = ZIGZAG[k];
        let r = natural_idx / 8;
        let c = natural_idx % 8;
        let q = q_table[natural_idx] as f64;
        let val = dct[r][c] / q;
        out[k] = round_to_i32(val);
        k += 1;
    }
    out
}

fn encode_dc_diff(diff: i32) -> (u8, u32) {
    if diff == 0 {
        return (0, 0);
    }
    let abs_val = diff.unsigned_abs();
    let size = (32 - abs_val.leading_zeros()) as u8;
    let bits = if diff > 0 {
        abs_val
    } else {
        (diff + ((1 << size) - 1)) as u32
    };
    (size, bits)
}

struct BitWriter {
    bytes: Vec<u8>,
    bit_buffer: u32,
    bits_in_buffer: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            bit_buffer: 0,
            bits_in_buffer: 0,
        }
    }

    fn write_bits(&mut self, code: u32, len: u8) {
        if len == 0 {
            return;
        }
        self.bit_buffer = (self.bit_buffer << len) | (code & ((1 << len) - 1));
        self.bits_in_buffer += len;

        while self.bits_in_buffer >= 8 {
            let shift = self.bits_in_buffer - 8;
            let byte = ((self.bit_buffer >> shift) & 0xFF) as u8;
            self.bytes.push(byte);
            if byte == 0xFF {
                self.bytes.push(0x00);
            }
            self.bits_in_buffer -= 8;
            self.bit_buffer &= (1 << self.bits_in_buffer) - 1;
        }
    }

    fn pad_and_flush(&mut self) {
        if self.bits_in_buffer > 0 {
            let pad_bits = 8 - self.bits_in_buffer;
            let byte = (((self.bit_buffer << pad_bits) | ((1 << pad_bits) - 1)) & 0xFF) as u8;
            self.bytes.push(byte);
            if byte == 0xFF {
                self.bytes.push(0x00);
            }
            self.bit_buffer = 0;
            self.bits_in_buffer = 0;
        }
    }

    fn emit_restart_marker(&mut self, rst_index: u8) {
        self.pad_and_flush();
        self.bytes.push(0xFF);
        self.bytes.push(0xD0 + (rst_index & 7));
    }
}

fn encode_block(
    coeffs: &[i32; 64],
    prev_dc: &mut i32,
    dc_huff: &[HuffmanCode; 256],
    ac_huff: &[HuffmanCode; 256],
    writer: &mut BitWriter,
) {
    let dc_diff = coeffs[0] - *prev_dc;
    *prev_dc = coeffs[0];
    let (dc_size, dc_bits) = encode_dc_diff(dc_diff);
    let dc_code = dc_huff[dc_size as usize];
    writer.write_bits(dc_code.code as u32, dc_code.len);
    if dc_size > 0 {
        writer.write_bits(dc_bits, dc_size);
    }

    let mut last_non_zero = 0;
    let mut k = 63;
    while k >= 1 {
        if coeffs[k] != 0 {
            last_non_zero = k;
            break;
        }
        k -= 1;
    }

    if last_non_zero == 0 {
        let eob = ac_huff[0x00];
        writer.write_bits(eob.code as u32, eob.len);
        return;
    }

    let mut zero_run = 0u8;
    let mut idx = 1;
    while idx <= last_non_zero {
        let val = coeffs[idx];
        if val == 0 {
            zero_run += 1;
        } else {
            while zero_run >= 16 {
                let zrl = ac_huff[0xF0];
                writer.write_bits(zrl.code as u32, zrl.len);
                zero_run -= 16;
            }
            let (size, bits) = encode_dc_diff(val);
            let symbol = (zero_run << 4) | size;
            let code = ac_huff[symbol as usize];
            writer.write_bits(code.code as u32, code.len);
            writer.write_bits(bits, size);
            zero_run = 0;
        }
        idx += 1;
    }

    if last_non_zero < 63 {
        let eob = ac_huff[0x00];
        writer.write_bits(eob.code as u32, eob.len);
    }
}

fn write_marker_segment(out: &mut Vec<u8>, marker: u8, payload: &[u8]) {
    out.push(0xFF);
    out.push(marker);
    let len = (payload.len() + 2) as u16;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
}

fn sample_rgb_shifted(pixels: &[u8], width: u32, height: u32, x: u32, y: u32) -> (f64, f64, f64) {
    let px = x.min(width.saturating_sub(1));
    let py = y.min(height.saturating_sub(1));
    let idx = ((py * width + px) * 3) as usize;
    let r = pixels[idx] as f64;
    let g = pixels[idx + 1] as f64;
    let b = pixels[idx + 2] as f64;
    (r, g, b)
}

fn rgb_to_y_shifted(r: f64, g: f64, b: f64) -> f64 {
    0.299 * r + 0.587 * g + 0.114 * b - 128.0
}

fn rgb_to_cb_shifted(r: f64, g: f64, b: f64) -> f64 {
    -0.168736 * r - 0.331264 * g + 0.5 * b
}

fn rgb_to_cr_shifted(r: f64, g: f64, b: f64) -> f64 {
    0.5 * r - 0.418688 * g - 0.081312 * b
}

fn extract_gray_block(pixels: &[u8], width: u32, height: u32, ox: u32, oy: u32) -> [[f64; 8]; 8] {
    let mut block = [[0.0f64; 8]; 8];
    let mut r = 0;
    while r < 8 {
        let py = (oy + r as u32).min(height.saturating_sub(1));
        let mut c = 0;
        while c < 8 {
            let px = (ox + c as u32).min(width.saturating_sub(1));
            let idx = (py * width + px) as usize;
            block[r][c] = pixels[idx] as f64 - 128.0;
            c += 1;
        }
        r += 1;
    }
    block
}

fn extract_y_block(pixels: &[u8], width: u32, height: u32, ox: u32, oy: u32) -> [[f64; 8]; 8] {
    let mut block = [[0.0f64; 8]; 8];
    let mut r = 0;
    while r < 8 {
        let mut c = 0;
        while c < 8 {
            let (red, green, blue) =
                sample_rgb_shifted(pixels, width, height, ox + c as u32, oy + r as u32);
            block[r][c] = rgb_to_y_shifted(red, green, blue);
            c += 1;
        }
        r += 1;
    }
    block
}

fn extract_yuv444_chroma_blocks(
    pixels: &[u8],
    width: u32,
    height: u32,
    ox: u32,
    oy: u32,
) -> ([[f64; 8]; 8], [[f64; 8]; 8]) {
    let mut cb_block = [[0.0f64; 8]; 8];
    let mut cr_block = [[0.0f64; 8]; 8];
    let mut r = 0;
    while r < 8 {
        let mut c = 0;
        while c < 8 {
            let (red, green, blue) =
                sample_rgb_shifted(pixels, width, height, ox + c as u32, oy + r as u32);
            cb_block[r][c] = rgb_to_cb_shifted(red, green, blue);
            cr_block[r][c] = rgb_to_cr_shifted(red, green, blue);
            c += 1;
        }
        r += 1;
    }
    (cb_block, cr_block)
}

fn extract_yuv420_chroma_blocks(
    pixels: &[u8],
    width: u32,
    height: u32,
    ox: u32,
    oy: u32,
) -> ([[f64; 8]; 8], [[f64; 8]; 8]) {
    let mut cb_block = [[0.0f64; 8]; 8];
    let mut cr_block = [[0.0f64; 8]; 8];
    let mut r = 0;
    while r < 8 {
        let mut c = 0;
        while c < 8 {
            let x0 = ox + (c as u32 * 2);
            let x1 = x0 + 1;
            let y0 = oy + (r as u32 * 2);
            let y1 = y0 + 1;

            let (r00, g00, b00) = sample_rgb_shifted(pixels, width, height, x0, y0);
            let (r10, g10, b10) = sample_rgb_shifted(pixels, width, height, x1, y0);
            let (r01, g01, b01) = sample_rgb_shifted(pixels, width, height, x0, y1);
            let (r11, g11, b11) = sample_rgb_shifted(pixels, width, height, x1, y1);

            let r_avg = (r00 + r10 + r01 + r11) * 0.25;
            let g_avg = (g00 + g10 + g01 + g11) * 0.25;
            let b_avg = (b00 + b10 + b01 + b11) * 0.25;

            cb_block[r][c] = rgb_to_cb_shifted(r_avg, g_avg, b_avg);
            cr_block[r][c] = rgb_to_cr_shifted(r_avg, g_avg, b_avg);
            c += 1;
        }
        r += 1;
    }
    (cb_block, cr_block)
}

fn extract_yuv422_chroma_blocks(
    pixels: &[u8],
    width: u32,
    height: u32,
    ox: u32,
    oy: u32,
) -> ([[f64; 8]; 8], [[f64; 8]; 8]) {
    let mut cb_block = [[0.0f64; 8]; 8];
    let mut cr_block = [[0.0f64; 8]; 8];
    let mut r = 0;
    while r < 8 {
        let mut c = 0;
        while c < 8 {
            let x0 = ox + (c as u32 * 2);
            let x1 = x0 + 1;
            let y = oy + r as u32;

            let (r0, g0, b0) = sample_rgb_shifted(pixels, width, height, x0, y);
            let (r1, g1, b1) = sample_rgb_shifted(pixels, width, height, x1, y);

            let r_avg = (r0 + r1) * 0.5;
            let g_avg = (g0 + g1) * 0.5;
            let b_avg = (b0 + b1) * 0.5;

            cb_block[r][c] = rgb_to_cb_shifted(r_avg, g_avg, b_avg);
            cr_block[r][c] = rgb_to_cr_shifted(r_avg, g_avg, b_avg);
            c += 1;
        }
        r += 1;
    }
    (cb_block, cr_block)
}

/// Encodes raw image samples into a deterministic baseline JPEG byte stream.
pub fn encode_jpeg(
    width: u32,
    height: u32,
    pixels: &[u8],
    config: &JpegConfig,
) -> Result<Vec<u8>, JpegError> {
    if width == 0 || height == 0 || width > 65_535 || height > 65_535 {
        return Err(JpegError::InvalidDimensions { width, height });
    }

    let is_grayscale = config.subsampling == Subsampling::Grayscale;
    let expected_len = if is_grayscale {
        (width as usize) * (height as usize)
    } else {
        (width as usize) * (height as usize) * 3
    };

    if pixels.len() != expected_len {
        return Err(JpegError::BufferLengthMismatch {
            expected: expected_len,
            actual: pixels.len(),
        });
    }

    let q_luma = scale_quantization_table(&BASE_LUMA_QUANT, config.quality);
    let q_chroma = scale_quantization_table(&BASE_CHROMA_QUANT, config.quality);

    let dc_luma_huff = build_huffman_codes(&LUMA_DC_BITS, &LUMA_DC_VALS);
    let ac_luma_huff = build_huffman_codes(&LUMA_AC_BITS, &LUMA_AC_VALS);
    let dc_chroma_huff = build_huffman_codes(&CHROMA_DC_BITS, &CHROMA_DC_VALS);
    let ac_chroma_huff = build_huffman_codes(&CHROMA_AC_BITS, &CHROMA_AC_VALS);

    let dct_basis = compute_dct_basis();

    let mut out = Vec::with_capacity(1024 + expected_len / 4);

    // 1. SOI
    out.push(0xFF);
    out.push(0xD8);

    // 2. JFIF APP0
    let mut app0 = Vec::with_capacity(14);
    app0.extend_from_slice(b"JFIF\0");
    app0.push(0x01);
    app0.push(0x01);
    app0.push(0x00);
    app0.extend_from_slice(&1u16.to_be_bytes());
    app0.extend_from_slice(&1u16.to_be_bytes());
    app0.push(0x00);
    app0.push(0x00);
    write_marker_segment(&mut out, 0xE0, &app0);

    // 3. Custom markers (e.g. APPn or COM)
    for custom in &config.custom_markers {
        write_marker_segment(&mut out, custom.marker, &custom.payload);
    }

    // 4. DQT
    if is_grayscale {
        let mut dqt_payload = Vec::with_capacity(65);
        dqt_payload.push(0x00); // 8-bit precision, table 0
        let mut k = 0;
        while k < 64 {
            dqt_payload.push(q_luma[ZIGZAG[k]]);
            k += 1;
        }
        write_marker_segment(&mut out, 0xDB, &dqt_payload);
    } else {
        let mut dqt_payload = Vec::with_capacity(130);
        dqt_payload.push(0x00); // Luma: table 0
        let mut k = 0;
        while k < 64 {
            dqt_payload.push(q_luma[ZIGZAG[k]]);
            k += 1;
        }
        dqt_payload.push(0x01); // Chroma: table 1
        let mut j = 0;
        while j < 64 {
            dqt_payload.push(q_chroma[ZIGZAG[j]]);
            j += 1;
        }
        write_marker_segment(&mut out, 0xDB, &dqt_payload);
    }

    // 5. SOF0 (Baseline Sequential DCT)
    let num_components: u8 = if is_grayscale { 1 } else { 3 };
    let mut sof_payload = Vec::with_capacity(8 + 3 * num_components as usize);
    sof_payload.push(0x08); // 8-bit sample precision
    sof_payload.extend_from_slice(&(height as u16).to_be_bytes());
    sof_payload.extend_from_slice(&(width as u16).to_be_bytes());
    sof_payload.push(num_components);

    if is_grayscale {
        sof_payload.push(0x01); // component 1
        sof_payload.push(0x11); // H=1, V=1
        sof_payload.push(0x00); // quant table 0
    } else {
        let sampling_y = match config.subsampling {
            Subsampling::Yuv444 => 0x11,
            Subsampling::Yuv420 => 0x22,
            Subsampling::Yuv422 => 0x21,
            Subsampling::Grayscale => 0x11,
        };
        // Y
        sof_payload.push(0x01);
        sof_payload.push(sampling_y);
        sof_payload.push(0x00);
        // Cb
        sof_payload.push(0x02);
        sof_payload.push(0x11);
        sof_payload.push(0x01);
        // Cr
        sof_payload.push(0x03);
        sof_payload.push(0x11);
        sof_payload.push(0x01);
    }
    write_marker_segment(&mut out, 0xC0, &sof_payload);

    // 6. Optional DRI
    if config.restart_interval > 0 {
        write_marker_segment(&mut out, 0xDD, &config.restart_interval.to_be_bytes());
    }

    // 7. DHT
    let mut dht_payload = Vec::with_capacity(420);
    // Table 0: DC Luma
    dht_payload.push(0x00);
    dht_payload.extend_from_slice(&LUMA_DC_BITS);
    dht_payload.extend_from_slice(&LUMA_DC_VALS);
    // Table 1: AC Luma
    dht_payload.push(0x10);
    dht_payload.extend_from_slice(&LUMA_AC_BITS);
    dht_payload.extend_from_slice(&LUMA_AC_VALS);

    if !is_grayscale {
        // Table 2: DC Chroma
        dht_payload.push(0x01);
        dht_payload.extend_from_slice(&CHROMA_DC_BITS);
        dht_payload.extend_from_slice(&CHROMA_DC_VALS);
        // Table 3: AC Chroma
        dht_payload.push(0x11);
        dht_payload.extend_from_slice(&CHROMA_AC_BITS);
        dht_payload.extend_from_slice(&CHROMA_AC_VALS);
    }
    write_marker_segment(&mut out, 0xC4, &dht_payload);

    // 8. SOS
    let mut sos_payload = Vec::with_capacity(6 + 2 * num_components as usize);
    sos_payload.push(num_components);
    if is_grayscale {
        sos_payload.push(0x01);
        sos_payload.push(0x00); // DC 0, AC 0
    } else {
        sos_payload.push(0x01);
        sos_payload.push(0x00); // Y: DC 0, AC 0
        sos_payload.push(0x02);
        sos_payload.push(0x11); // Cb: DC 1, AC 1
        sos_payload.push(0x03);
        sos_payload.push(0x11); // Cr: DC 1, AC 1
    }
    sos_payload.push(0x00); // Spectral selection start = 0
    sos_payload.push(0x3F); // Spectral selection end = 63
    sos_payload.push(0x00); // Successive approx = 0
    write_marker_segment(&mut out, 0xDA, &sos_payload);

    // 9. Scan data encoding
    let (mcu_w, mcu_h) = match config.subsampling {
        Subsampling::Grayscale | Subsampling::Yuv444 => (8, 8),
        Subsampling::Yuv420 => (16, 16),
        Subsampling::Yuv422 => (16, 8),
    };

    let mcus_x = width.div_ceil(mcu_w);
    let mcus_y = height.div_ceil(mcu_h);

    let mut writer = BitWriter::new();
    let mut prev_dc_y = 0i32;
    let mut prev_dc_cb = 0i32;
    let mut prev_dc_cr = 0i32;
    let mut restart_idx = 0u8;
    let mut mcu_idx = 0usize;

    let mut my = 0;
    while my < mcus_y {
        let mut mx = 0;
        while mx < mcus_x {
            if config.restart_interval > 0
                && mcu_idx > 0
                && mcu_idx.is_multiple_of(config.restart_interval as usize)
            {
                writer.emit_restart_marker(restart_idx);
                restart_idx = (restart_idx + 1) & 7;
                prev_dc_y = 0;
                prev_dc_cb = 0;
                prev_dc_cr = 0;
            }

            let ox = mx * mcu_w;
            let oy = my * mcu_h;

            match config.subsampling {
                Subsampling::Grayscale => {
                    let block = extract_gray_block(pixels, width, height, ox, oy);
                    let dct = forward_dct(&block, &dct_basis);
                    let quantized = quantize_and_zigzag(&dct, &q_luma);
                    encode_block(
                        &quantized,
                        &mut prev_dc_y,
                        &dc_luma_huff,
                        &ac_luma_huff,
                        &mut writer,
                    );
                }
                Subsampling::Yuv444 => {
                    let y_block = extract_y_block(pixels, width, height, ox, oy);
                    let dct_y = forward_dct(&y_block, &dct_basis);
                    let q_y = quantize_and_zigzag(&dct_y, &q_luma);
                    encode_block(
                        &q_y,
                        &mut prev_dc_y,
                        &dc_luma_huff,
                        &ac_luma_huff,
                        &mut writer,
                    );

                    let (cb_block, cr_block) =
                        extract_yuv444_chroma_blocks(pixels, width, height, ox, oy);
                    let dct_cb = forward_dct(&cb_block, &dct_basis);
                    let q_cb = quantize_and_zigzag(&dct_cb, &q_chroma);
                    encode_block(
                        &q_cb,
                        &mut prev_dc_cb,
                        &dc_chroma_huff,
                        &ac_chroma_huff,
                        &mut writer,
                    );

                    let dct_cr = forward_dct(&cr_block, &dct_basis);
                    let q_cr = quantize_and_zigzag(&dct_cr, &q_chroma);
                    encode_block(
                        &q_cr,
                        &mut prev_dc_cr,
                        &dc_chroma_huff,
                        &ac_chroma_huff,
                        &mut writer,
                    );
                }
                Subsampling::Yuv420 => {
                    // Y: 4 blocks
                    let y00 = extract_y_block(pixels, width, height, ox, oy);
                    let q00 = quantize_and_zigzag(&forward_dct(&y00, &dct_basis), &q_luma);
                    encode_block(
                        &q00,
                        &mut prev_dc_y,
                        &dc_luma_huff,
                        &ac_luma_huff,
                        &mut writer,
                    );

                    let y01 = extract_y_block(pixels, width, height, ox + 8, oy);
                    let q01 = quantize_and_zigzag(&forward_dct(&y01, &dct_basis), &q_luma);
                    encode_block(
                        &q01,
                        &mut prev_dc_y,
                        &dc_luma_huff,
                        &ac_luma_huff,
                        &mut writer,
                    );

                    let y10 = extract_y_block(pixels, width, height, ox, oy + 8);
                    let q10 = quantize_and_zigzag(&forward_dct(&y10, &dct_basis), &q_luma);
                    encode_block(
                        &q10,
                        &mut prev_dc_y,
                        &dc_luma_huff,
                        &ac_luma_huff,
                        &mut writer,
                    );

                    let y11 = extract_y_block(pixels, width, height, ox + 8, oy + 8);
                    let q11 = quantize_and_zigzag(&forward_dct(&y11, &dct_basis), &q_luma);
                    encode_block(
                        &q11,
                        &mut prev_dc_y,
                        &dc_luma_huff,
                        &ac_luma_huff,
                        &mut writer,
                    );

                    // Cb and Cr
                    let (cb_block, cr_block) =
                        extract_yuv420_chroma_blocks(pixels, width, height, ox, oy);
                    let q_cb = quantize_and_zigzag(&forward_dct(&cb_block, &dct_basis), &q_chroma);
                    encode_block(
                        &q_cb,
                        &mut prev_dc_cb,
                        &dc_chroma_huff,
                        &ac_chroma_huff,
                        &mut writer,
                    );

                    let q_cr = quantize_and_zigzag(&forward_dct(&cr_block, &dct_basis), &q_chroma);
                    encode_block(
                        &q_cr,
                        &mut prev_dc_cr,
                        &dc_chroma_huff,
                        &ac_chroma_huff,
                        &mut writer,
                    );
                }
                Subsampling::Yuv422 => {
                    // Y: 2 blocks horizontally
                    let y0 = extract_y_block(pixels, width, height, ox, oy);
                    let q0 = quantize_and_zigzag(&forward_dct(&y0, &dct_basis), &q_luma);
                    encode_block(
                        &q0,
                        &mut prev_dc_y,
                        &dc_luma_huff,
                        &ac_luma_huff,
                        &mut writer,
                    );

                    let y1 = extract_y_block(pixels, width, height, ox + 8, oy);
                    let q1 = quantize_and_zigzag(&forward_dct(&y1, &dct_basis), &q_luma);
                    encode_block(
                        &q1,
                        &mut prev_dc_y,
                        &dc_luma_huff,
                        &ac_luma_huff,
                        &mut writer,
                    );

                    let (cb_block, cr_block) =
                        extract_yuv422_chroma_blocks(pixels, width, height, ox, oy);
                    let q_cb = quantize_and_zigzag(&forward_dct(&cb_block, &dct_basis), &q_chroma);
                    encode_block(
                        &q_cb,
                        &mut prev_dc_cb,
                        &dc_chroma_huff,
                        &ac_chroma_huff,
                        &mut writer,
                    );

                    let q_cr = quantize_and_zigzag(&forward_dct(&cr_block, &dct_basis), &q_chroma);
                    encode_block(
                        &q_cr,
                        &mut prev_dc_cr,
                        &dc_chroma_huff,
                        &ac_chroma_huff,
                        &mut writer,
                    );
                }
            }

            mcu_idx += 1;
            mx += 1;
        }
        my += 1;
    }

    writer.pad_and_flush();
    out.extend_from_slice(&writer.bytes);

    // 10. EOI
    out.push(0xFF);
    out.push(0xD9);

    Ok(out)
}

/// Encodes an MJPEG sequence by concatenating valid JPEG frame buffers.
pub fn encode_mjpeg(frames: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for frame in frames {
        out.extend_from_slice(frame);
    }
    out
}

/// Computes the Peak Signal-to-Noise Ratio (PSNR) between source and reconstructed pixels.
pub fn compute_psnr(source: &[u8], reconstructed: &[u8]) -> Result<f64, JpegError> {
    if source.len() != reconstructed.len() {
        return Err(JpegError::BufferLengthMismatch {
            expected: source.len(),
            actual: reconstructed.len(),
        });
    }
    if source.is_empty() {
        return Ok(999.0);
    }
    let mut sum_sq = 0.0f64;
    let mut i = 0;
    while i < source.len() {
        let diff = (source[i] as f64) - (reconstructed[i] as f64);
        sum_sq += diff * diff;
        i += 1;
    }
    let mse = sum_sq / (source.len() as f64);
    if mse <= 1e-10 {
        return Ok(999.0);
    }
    let psnr = 10.0f64 * (255.0f64 * 255.0f64 / mse).log10();
    Ok(psnr)
}

/// Simulates float IDCT reconstruction of an 8-bit grayscale image.
///
/// Divides the image into 8x8 blocks with right/bottom edge clamping (matching encoder),
/// performs forward DCT with the orthonormal basis, quantizes with the quality-scaled
/// luma table, dequantizes, performs inverse DCT, adds 128.0, rounds, and clamps to [0, 255].
///
/// This is NOT the fidelity measurement. It is an encoder-side pre-computation that only
/// fills the `encoder_psnr` / `encoder_max_error` manifest metadata, and it reuses the
/// encoder's own tables and DCT basis. The measurement of record is the test-side
/// independent baseline decoder in `tests/media_fixture_jpeg_contract.rs`, which decodes
/// the emitted file bytes and must agree with this metadata.
///
/// Returns `(reconstructed_pixels, psnr_db, max_absolute_error)`.
fn simulate_float_idct_gray(
    width: u32,
    height: u32,
    pixels: &[u8],
    quality: u32,
) -> Result<(Vec<u8>, f64, u32), JpegError> {
    if width == 0 || height == 0 || width > 65535 || height > 65535 {
        return Err(JpegError::InvalidDimensions { width, height });
    }
    let expected_len = (width as usize) * (height as usize);
    if pixels.len() != expected_len {
        return Err(JpegError::BufferLengthMismatch {
            expected: expected_len,
            actual: pixels.len(),
        });
    }

    let q_luma = scale_quantization_table(&BASE_LUMA_QUANT, quality);
    let basis = compute_dct_basis();

    let mcus_x = width.div_ceil(8);
    let mcus_y = height.div_ceil(8);

    let mut reconstructed = vec![0u8; expected_len];
    let mut max_err = 0u32;
    let mut sum_sq_err = 0.0f64;

    let mut my = 0;
    while my < mcus_y {
        let mut mx = 0;
        while mx < mcus_x {
            let ox = mx * 8;
            let oy = my * 8;

            let block = extract_gray_block(pixels, width, height, ox, oy);
            let dct = forward_dct(&block, &basis);
            let quantized = quantize_and_zigzag(&dct, &q_luma);

            // Dequantize and inverse DCT
            let mut dequant = [[0.0f64; 8]; 8];
            let mut k = 0;
            while k < 64 {
                let natural_idx = ZIGZAG[k];
                let r = natural_idx / 8;
                let c = natural_idx % 8;
                dequant[r][c] = (quantized[k] as f64) * (q_luma[natural_idx] as f64);
                k += 1;
            }

            // Inverse DCT: block = basis^T * dequant * basis
            let mut temp = [[0.0f64; 8]; 8];
            let mut x = 0;
            while x < 8 {
                let mut v = 0;
                while v < 8 {
                    let mut sum = 0.0f64;
                    let mut u = 0;
                    while u < 8 {
                        sum += basis[u][x] * dequant[u][v];
                        u += 1;
                    }
                    temp[x][v] = sum;
                    v += 1;
                }
                x += 1;
            }

            let mut r = 0;
            while r < 8 {
                let py = oy + r as u32;
                if py < height {
                    let mut c = 0;
                    while c < 8 {
                        let px = ox + c as u32;
                        if px < width {
                            let mut sum = 0.0f64;
                            let mut v = 0;
                            while v < 8 {
                                sum += temp[r][v] * basis[v][c];
                                v += 1;
                            }
                            let recon_val = (sum + 128.0).round().clamp(0.0, 255.0) as u8;
                            let idx = (py * width + px) as usize;
                            reconstructed[idx] = recon_val;

                            let orig_val = pixels[idx];
                            let diff = (recon_val as i32 - orig_val as i32).unsigned_abs();
                            if diff > max_err {
                                max_err = diff;
                            }
                            let diff_f = diff as f64;
                            sum_sq_err += diff_f * diff_f;
                        }
                        c += 1;
                    }
                }
                r += 1;
            }
            mx += 1;
        }
        my += 1;
    }

    let mse = sum_sq_err / (expected_len as f64);
    let psnr = if mse <= 1e-10 {
        999.0
    } else {
        10.0f64 * (255.0f64 * 255.0f64 / mse).log10()
    };

    Ok((reconstructed, psnr, max_err))
}

// ---------------------------------------------------------------------------
// Pattern Generators
// ---------------------------------------------------------------------------

/// Generates a flat field 1-channel grayscale buffer.
pub fn generate_flat_gray(width: u32, height: u32, val: u8) -> Vec<u8> {
    vec![val; (width * height) as usize]
}

/// Generates a flat field 3-channel RGB buffer.
pub fn generate_flat_rgb(width: u32, height: u32, r: u8, g: u8, b: u8) -> Vec<u8> {
    let count = (width * height) as usize;
    let mut buf = Vec::with_capacity(count * 3);
    let mut i = 0;
    while i < count {
        buf.push(r);
        buf.push(g);
        buf.push(b);
        i += 1;
    }
    buf
}

/// Generates a 2D smooth gradient grayscale buffer.
pub fn generate_gradient_gray(width: u32, height: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity((width * height) as usize);
    let mut y = 0;
    while y < height {
        let gy = if height > 1 {
            (y * 255) / (height - 1)
        } else {
            128
        };
        let mut x = 0;
        while x < width {
            let gx = if width > 1 {
                (x * 255) / (width - 1)
            } else {
                128
            };
            buf.push(((gx + gy) / 2) as u8);
            x += 1;
        }
        y += 1;
    }
    buf
}

/// Generates a 2D smooth gradient RGB buffer.
pub fn generate_gradient_rgb(width: u32, height: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity((width * height * 3) as usize);
    let mut y = 0;
    while y < height {
        let gy = if height > 1 {
            (y * 255) / (height - 1)
        } else {
            128
        };
        let mut x = 0;
        while x < width {
            let gx = if width > 1 {
                (x * 255) / (width - 1)
            } else {
                128
            };
            let r = gx as u8;
            let g = gy as u8;
            let b = (255 - ((gx + gy) / 2)) as u8;
            buf.push(r);
            buf.push(g);
            buf.push(b);
            x += 1;
        }
        y += 1;
    }
    buf
}

/// Generates a deterministic checkerboard grayscale buffer.
pub fn generate_checkerboard_gray(width: u32, height: u32, square_size: u32) -> Vec<u8> {
    let sq = square_size.max(1);
    let mut buf = Vec::with_capacity((width * height) as usize);
    let mut y = 0;
    while y < height {
        let mut x = 0;
        while x < width {
            let val = if ((x / sq) + (y / sq)).is_multiple_of(2) {
                220
            } else {
                35
            };
            buf.push(val);
            x += 1;
        }
        y += 1;
    }
    buf
}

/// Generates a deterministic checkerboard RGB buffer.
pub fn generate_checkerboard_rgb(width: u32, height: u32, square_size: u32) -> Vec<u8> {
    let sq = square_size.max(1);
    let mut buf = Vec::with_capacity((width * height * 3) as usize);
    let mut y = 0;
    while y < height {
        let mut x = 0;
        while x < width {
            let is_even = ((x / sq) + (y / sq)).is_multiple_of(2);
            if is_even {
                buf.push(240);
                buf.push(20);
                buf.push(20);
            } else {
                buf.push(20);
                buf.push(220);
                buf.push(40);
            }
            x += 1;
        }
        y += 1;
    }
    buf
}

/// Generates an 8-bar SMPTE-style RGB colorbars pattern buffer.
pub fn generate_colorbars_rgb(width: u32, height: u32) -> Vec<u8> {
    const BARS: [[u8; 3]; 8] = [
        [255, 255, 255], // White
        [255, 255, 0],   // Yellow
        [0, 255, 255],   // Cyan
        [0, 255, 0],     // Green
        [255, 0, 255],   // Magenta
        [255, 0, 0],     // Red
        [0, 0, 255],     // Blue
        [0, 0, 0],       // Black
    ];

    let mut buf = Vec::with_capacity((width * height * 3) as usize);
    let mut y = 0;
    while y < height {
        let mut x = 0;
        while x < width {
            let bar_idx = (((x * 8) / width) as usize).min(7);
            let color = BARS[bar_idx];
            buf.push(color[0]);
            buf.push(color[1]);
            buf.push(color[2]);
            x += 1;
        }
        y += 1;
    }
    buf
}

const BROWN_LUMA_96X96_BYTES: &[u8] =
    include_bytes!("../../../../crates/fss-twin/tests/fixtures/brown_luma_96x96.gray");

/// Returns the embedded ground-truth 96x96 grayscale buffer from brown_luma.
pub fn brown_luma_96x96() -> &'static [u8] {
    BROWN_LUMA_96X96_BYTES
}

// ---------------------------------------------------------------------------
// Source Pixels Retrieval
// ---------------------------------------------------------------------------

/// Regenerates the exact uncompressed source pixel buffer for a named fixture.
///
/// Accepts standard fixture names (with or without extension). Returns 8-bit
/// grayscale bytes for 1-channel fixtures and 8-bit interleaved RGB bytes
/// for 3-channel fixtures.
pub fn source_pixels(fixture: &str) -> Result<Vec<u8>, JpegError> {
    let name = fixture
        .strip_suffix(".jpg")
        .or_else(|| fixture.strip_suffix(".mjpeg"))
        .unwrap_or(fixture);

    match name {
        "gray_16x16_flat" => Ok(generate_flat_gray(16, 16, 128)),
        "gray_16x16_gradient" => Ok(generate_gradient_gray(16, 16)),
        "gray_33x17_checkerboard" => Ok(generate_checkerboard_gray(33, 17, 4)),
        "brown_luma_q100" | "brown_luma_qfix" | "gray_96x96_brown_luma" => {
            Ok(brown_luma_96x96().to_vec())
        }
        "rgb_16x16_flat_444" | "rgb_16x16_flat_420" => Ok(generate_flat_rgb(16, 16, 128, 64, 192)),
        "rgb_16x16_gradient_420" => Ok(generate_gradient_rgb(16, 16)),
        "rgb_33x17_checkerboard_420" => Ok(generate_checkerboard_rgb(33, 17, 4)),
        "rgb_64x48_colorbars_420"
        | "rgb_64x48_colorbars_444"
        | "rgb_64x48_colorbars_422"
        | "rgb_64x48_restart_ri5"
        | "rgb_64x48_restart_ri3"
        | "rgb_64x48_app_com_ffd9" => Ok(generate_colorbars_rgb(64, 48)),
        "rgb_64x48_gradient_420" => Ok(generate_gradient_rgb(64, 48)),
        "rgb_64x48_flat_420" | "rgb_64x48_flat_420_truncated" => {
            Ok(generate_flat_rgb(64, 48, 128, 64, 192))
        }
        "mjpeg_clean_3frames"
        | "mjpeg_clean_3frames_frame0"
        | "mjpeg_truncated_last"
        | "mjpeg_garbage_between_frames" => Ok(generate_colorbars_rgb(64, 48)),
        "mjpeg_clean_3frames_frame1" => Ok(generate_gradient_rgb(64, 48)),
        "mjpeg_clean_3frames_frame2" => Ok(generate_flat_rgb(64, 48, 128, 64, 192)),
        "mjpeg_zero_length" => Ok(Vec::new()),
        "mjpeg_dimension_change" | "mjpeg_dimension_change_frame0" => {
            Ok(generate_flat_rgb(16, 16, 128, 64, 192))
        }
        "mjpeg_dimension_change_frame1" => Ok(generate_colorbars_rgb(64, 48)),
        _ => Err(JpegError::UnknownFixture(fixture.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Manifest & Suite Generation
// ---------------------------------------------------------------------------

use fss_core::ContentDigest;

/// Computes a lowercase hex SHA-256 digest string.
pub fn compute_sha256_hex(bytes: &[u8]) -> String {
    let digest = ContentDigest::sha256(bytes);
    let mut s = String::with_capacity(64);
    for b in digest.bytes() {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Metadata and serialized bytes for a generated JPEG fixture.
#[derive(Clone, Debug, PartialEq)]
pub struct GeneratedJpegFixture {
    /// File name with .jpg extension.
    pub name: String,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Number of color channels (1 for gray, 3 for RGB).
    pub channels: u8,
    /// Pixel format description ("gray" or "rgb24").
    pub pixel_format: String,
    /// Subsampling mode ("gray", "4:4:4", "4:2:0", "4:2:2").
    pub subsampling: String,
    /// Encoding quality factor (1..100).
    pub quality: u32,
    /// Restart interval in MCUs (0 if disabled).
    pub restart_interval: u16,
    /// Serialized JPEG byte stream.
    pub file_bytes: Vec<u8>,
    /// SHA-256 hex digest of file_bytes.
    pub file_sha256: String,
    /// Ground-truth uncompressed source pixel buffer.
    pub source_bytes: Vec<u8>,
    /// SHA-256 hex digest of source_bytes.
    pub source_pixel_sha256: String,
    /// Encoder-side PSNR from float IDCT simulation (if evaluated).
    pub encoder_psnr: Option<f64>,
    /// Encoder-side maximum absolute error from float IDCT simulation (if evaluated).
    pub encoder_max_error: Option<u32>,
    /// Minimum required reconstruction PSNR threshold.
    pub psnr_threshold: Option<f64>,
}

/// Frame metadata record for an MJPEG sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedMjpegFrame {
    /// Zero-based frame index.
    pub index: usize,
    /// Description or source fixture identifier.
    pub source_fixture: String,
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// Byte offset within the MJPEG stream.
    pub offset: usize,
    /// Length in bytes of this JPEG frame.
    pub length: usize,
    /// SHA-256 hex digest of the encoded JPEG frame bytes.
    pub frame_sha256: String,
    /// SHA-256 hex digest of uncompressed source pixels.
    pub source_pixel_sha256: String,
}

/// Metadata and serialized bytes for a generated MJPEG stream fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedMjpegFixture {
    /// File name with .mjpeg extension.
    pub name: String,
    /// Variant name ("clean", "truncated_last", "garbage_between_frames", "zero_length", "dimension_change").
    pub variant: String,
    /// Total number of frames in stream.
    pub frame_count: usize,
    /// Serialized MJPEG stream bytes.
    pub file_bytes: Vec<u8>,
    /// SHA-256 hex digest of file_bytes.
    pub file_sha256: String,
    /// Primary or frame-0 source pixel SHA-256 hex digest.
    pub source_pixel_sha256: String,
    /// Per-frame metadata entries.
    pub frames: Vec<GeneratedMjpegFrame>,
}

/// Generates all 13 normative JPEG test fixtures.
pub fn generate_all_jpeg_fixtures() -> Result<Vec<GeneratedJpegFixture>, JpegError> {
    let mut list = Vec::new();

    // 1. gray_16x16_flat.jpg
    let src_1 = generate_flat_gray(16, 16, 128);
    let cfg_1 = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let bytes_1 = encode_jpeg(16, 16, &src_1, &cfg_1)?;
    let (_, psnr_1, max_err_1) = simulate_float_idct_gray(16, 16, &src_1, 90)?;
    list.push(GeneratedJpegFixture {
        name: "gray_16x16_flat.jpg".to_string(),
        width: 16,
        height: 16,
        channels: 1,
        pixel_format: "gray".to_string(),
        subsampling: "gray".to_string(),
        quality: 90,
        restart_interval: 0,
        file_sha256: compute_sha256_hex(&bytes_1),
        file_bytes: bytes_1,
        source_pixel_sha256: compute_sha256_hex(&src_1),
        source_bytes: src_1,
        encoder_psnr: Some(psnr_1),
        encoder_max_error: Some(max_err_1),
        psnr_threshold: Some(30.0),
    });

    // 2. gray_16x16_gradient.jpg
    let src_2 = generate_gradient_gray(16, 16);
    let cfg_2 = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let bytes_2 = encode_jpeg(16, 16, &src_2, &cfg_2)?;
    let (_, psnr_2, max_err_2) = simulate_float_idct_gray(16, 16, &src_2, 90)?;
    list.push(GeneratedJpegFixture {
        name: "gray_16x16_gradient.jpg".to_string(),
        width: 16,
        height: 16,
        channels: 1,
        pixel_format: "gray".to_string(),
        subsampling: "gray".to_string(),
        quality: 90,
        restart_interval: 0,
        file_sha256: compute_sha256_hex(&bytes_2),
        file_bytes: bytes_2,
        source_pixel_sha256: compute_sha256_hex(&src_2),
        source_bytes: src_2,
        encoder_psnr: Some(psnr_2),
        encoder_max_error: Some(max_err_2),
        psnr_threshold: Some(30.0),
    });

    // 3. gray_33x17_checkerboard.jpg
    let src_3 = generate_checkerboard_gray(33, 17, 4);
    let cfg_3 = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let bytes_3 = encode_jpeg(33, 17, &src_3, &cfg_3)?;
    let (_, psnr_3, max_err_3) = simulate_float_idct_gray(33, 17, &src_3, 90)?;
    list.push(GeneratedJpegFixture {
        name: "gray_33x17_checkerboard.jpg".to_string(),
        width: 33,
        height: 17,
        channels: 1,
        pixel_format: "gray".to_string(),
        subsampling: "gray".to_string(),
        quality: 90,
        restart_interval: 0,
        file_sha256: compute_sha256_hex(&bytes_3),
        file_bytes: bytes_3,
        source_pixel_sha256: compute_sha256_hex(&src_3),
        source_bytes: src_3,
        encoder_psnr: Some(psnr_3),
        encoder_max_error: Some(max_err_3),
        psnr_threshold: Some(30.0),
    });

    // 4a. brown_luma_q100.jpg
    let src_luma_q100 = brown_luma_96x96().to_vec();
    let cfg_luma_q100 = JpegConfig {
        quality: 100,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let bytes_luma_q100 = encode_jpeg(96, 96, &src_luma_q100, &cfg_luma_q100)?;
    let (_, psnr_q100, max_err_q100) = simulate_float_idct_gray(96, 96, &src_luma_q100, 100)?;
    list.push(GeneratedJpegFixture {
        name: "brown_luma_q100.jpg".to_string(),
        width: 96,
        height: 96,
        channels: 1,
        pixel_format: "gray".to_string(),
        subsampling: "gray".to_string(),
        quality: 100,
        restart_interval: 0,
        file_sha256: compute_sha256_hex(&bytes_luma_q100),
        file_bytes: bytes_luma_q100,
        source_pixel_sha256: compute_sha256_hex(&src_luma_q100),
        source_bytes: src_luma_q100,
        encoder_psnr: Some(psnr_q100),
        encoder_max_error: Some(max_err_q100),
        psnr_threshold: Some(30.0),
    });

    // 4b. brown_luma_qfix.jpg
    let src_luma_qfix = brown_luma_96x96().to_vec();
    let cfg_luma_qfix = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let bytes_luma_qfix = encode_jpeg(96, 96, &src_luma_qfix, &cfg_luma_qfix)?;
    let (_, psnr_qfix, max_err_qfix) = simulate_float_idct_gray(96, 96, &src_luma_qfix, 90)?;
    list.push(GeneratedJpegFixture {
        name: "brown_luma_qfix.jpg".to_string(),
        width: 96,
        height: 96,
        channels: 1,
        pixel_format: "gray".to_string(),
        subsampling: "gray".to_string(),
        quality: 90,
        restart_interval: 0,
        file_sha256: compute_sha256_hex(&bytes_luma_qfix),
        file_bytes: bytes_luma_qfix,
        source_pixel_sha256: compute_sha256_hex(&src_luma_qfix),
        source_bytes: src_luma_qfix,
        encoder_psnr: Some(psnr_qfix),
        encoder_max_error: Some(max_err_qfix),
        psnr_threshold: Some(30.0),
    });

    // 5. rgb_16x16_flat_444.jpg
    let src_5 = generate_flat_rgb(16, 16, 128, 64, 192);
    let cfg_5 = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Yuv444,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let bytes_5 = encode_jpeg(16, 16, &src_5, &cfg_5)?;
    list.push(GeneratedJpegFixture {
        name: "rgb_16x16_flat_444.jpg".to_string(),
        width: 16,
        height: 16,
        channels: 3,
        pixel_format: "rgb24".to_string(),
        subsampling: "4:4:4".to_string(),
        quality: 90,
        restart_interval: 0,
        file_sha256: compute_sha256_hex(&bytes_5),
        file_bytes: bytes_5,
        source_pixel_sha256: compute_sha256_hex(&src_5),
        source_bytes: src_5,
        encoder_psnr: None,
        encoder_max_error: None,
        psnr_threshold: None,
    });

    // 6. rgb_16x16_gradient_420.jpg
    let src_6 = generate_gradient_rgb(16, 16);
    let cfg_6 = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Yuv420,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let bytes_6 = encode_jpeg(16, 16, &src_6, &cfg_6)?;
    list.push(GeneratedJpegFixture {
        name: "rgb_16x16_gradient_420.jpg".to_string(),
        width: 16,
        height: 16,
        channels: 3,
        pixel_format: "rgb24".to_string(),
        subsampling: "4:2:0".to_string(),
        quality: 90,
        restart_interval: 0,
        file_sha256: compute_sha256_hex(&bytes_6),
        file_bytes: bytes_6,
        source_pixel_sha256: compute_sha256_hex(&src_6),
        source_bytes: src_6,
        encoder_psnr: None,
        encoder_max_error: None,
        psnr_threshold: None,
    });

    // 7. rgb_33x17_checkerboard_420.jpg
    let src_7 = generate_checkerboard_rgb(33, 17, 4);
    let cfg_7 = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Yuv420,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let bytes_7 = encode_jpeg(33, 17, &src_7, &cfg_7)?;
    list.push(GeneratedJpegFixture {
        name: "rgb_33x17_checkerboard_420.jpg".to_string(),
        width: 33,
        height: 17,
        channels: 3,
        pixel_format: "rgb24".to_string(),
        subsampling: "4:2:0".to_string(),
        quality: 90,
        restart_interval: 0,
        file_sha256: compute_sha256_hex(&bytes_7),
        file_bytes: bytes_7,
        source_pixel_sha256: compute_sha256_hex(&src_7),
        source_bytes: src_7,
        encoder_psnr: None,
        encoder_max_error: None,
        psnr_threshold: None,
    });

    // 8. rgb_64x48_colorbars_420.jpg
    let src_8 = generate_colorbars_rgb(64, 48);
    let cfg_8 = JpegConfig {
        quality: 85,
        subsampling: Subsampling::Yuv420,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let bytes_8 = encode_jpeg(64, 48, &src_8, &cfg_8)?;
    list.push(GeneratedJpegFixture {
        name: "rgb_64x48_colorbars_420.jpg".to_string(),
        width: 64,
        height: 48,
        channels: 3,
        pixel_format: "rgb24".to_string(),
        subsampling: "4:2:0".to_string(),
        quality: 85,
        restart_interval: 0,
        file_sha256: compute_sha256_hex(&bytes_8),
        file_bytes: bytes_8,
        source_pixel_sha256: compute_sha256_hex(&src_8),
        source_bytes: src_8,
        encoder_psnr: None,
        encoder_max_error: None,
        psnr_threshold: None,
    });

    // 9. rgb_64x48_colorbars_444.jpg
    let src_9 = generate_colorbars_rgb(64, 48);
    let cfg_9 = JpegConfig {
        quality: 85,
        subsampling: Subsampling::Yuv444,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let bytes_9 = encode_jpeg(64, 48, &src_9, &cfg_9)?;
    list.push(GeneratedJpegFixture {
        name: "rgb_64x48_colorbars_444.jpg".to_string(),
        width: 64,
        height: 48,
        channels: 3,
        pixel_format: "rgb24".to_string(),
        subsampling: "4:4:4".to_string(),
        quality: 85,
        restart_interval: 0,
        file_sha256: compute_sha256_hex(&bytes_9),
        file_bytes: bytes_9,
        source_pixel_sha256: compute_sha256_hex(&src_9),
        source_bytes: src_9,
        encoder_psnr: None,
        encoder_max_error: None,
        psnr_threshold: None,
    });

    // 10. rgb_64x48_colorbars_422.jpg
    let src_10 = generate_colorbars_rgb(64, 48);
    let cfg_10 = JpegConfig {
        quality: 85,
        subsampling: Subsampling::Yuv422,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let bytes_10 = encode_jpeg(64, 48, &src_10, &cfg_10)?;
    list.push(GeneratedJpegFixture {
        name: "rgb_64x48_colorbars_422.jpg".to_string(),
        width: 64,
        height: 48,
        channels: 3,
        pixel_format: "rgb24".to_string(),
        subsampling: "4:2:2".to_string(),
        quality: 85,
        restart_interval: 0,
        file_sha256: compute_sha256_hex(&bytes_10),
        file_bytes: bytes_10,
        source_pixel_sha256: compute_sha256_hex(&src_10),
        source_bytes: src_10,
        encoder_psnr: None,
        encoder_max_error: None,
        psnr_threshold: None,
    });

    // 11. rgb_64x48_restart_ri5.jpg
    let src_11 = generate_colorbars_rgb(64, 48);
    let cfg_11 = JpegConfig {
        quality: 85,
        subsampling: Subsampling::Yuv420,
        restart_interval: 5,
        custom_markers: Vec::new(),
    };
    let bytes_11 = encode_jpeg(64, 48, &src_11, &cfg_11)?;
    list.push(GeneratedJpegFixture {
        name: "rgb_64x48_restart_ri5.jpg".to_string(),
        width: 64,
        height: 48,
        channels: 3,
        pixel_format: "rgb24".to_string(),
        subsampling: "4:2:0".to_string(),
        quality: 85,
        restart_interval: 5,
        file_sha256: compute_sha256_hex(&bytes_11),
        file_bytes: bytes_11,
        source_pixel_sha256: compute_sha256_hex(&src_11),
        source_bytes: src_11,
        encoder_psnr: None,
        encoder_max_error: None,
        psnr_threshold: None,
    });

    // 12. rgb_64x48_app_com_ffd9.jpg
    let src_12 = generate_colorbars_rgb(64, 48);
    let mut app1_payload = Vec::new();
    app1_payload.extend_from_slice(b"FSS_APP1");
    app1_payload.push(0x00);
    app1_payload.push(0xFF);
    app1_payload.push(0xD9); // Embedded EOI marker sequence inside APP1
    app1_payload.extend_from_slice(b"_NOT_EOI");

    let mut com_payload = Vec::new();
    com_payload.extend_from_slice(b"FSS_COMMENT");
    com_payload.push(0xFF);
    com_payload.push(0xD9); // Embedded EOI marker sequence inside COM
    com_payload.extend_from_slice(b"_STILL_NOT_EOI");

    let cfg_12 = JpegConfig {
        quality: 85,
        subsampling: Subsampling::Yuv420,
        restart_interval: 0,
        custom_markers: vec![
            CustomMarker {
                marker: 0xE1, // APP1
                payload: app1_payload,
            },
            CustomMarker {
                marker: 0xFE, // COM
                payload: com_payload,
            },
        ],
    };
    let bytes_12 = encode_jpeg(64, 48, &src_12, &cfg_12)?;
    list.push(GeneratedJpegFixture {
        name: "rgb_64x48_app_com_ffd9.jpg".to_string(),
        width: 64,
        height: 48,
        channels: 3,
        pixel_format: "rgb24".to_string(),
        subsampling: "4:2:0".to_string(),
        quality: 85,
        restart_interval: 0,
        file_sha256: compute_sha256_hex(&bytes_12),
        file_bytes: bytes_12,
        source_pixel_sha256: compute_sha256_hex(&src_12),
        source_bytes: src_12,
        encoder_psnr: None,
        encoder_max_error: None,
        psnr_threshold: None,
    });

    Ok(list)
}

/// Generates all 5 normative MJPEG stream test fixtures.
pub fn generate_all_mjpeg_fixtures() -> Result<Vec<GeneratedMjpegFixture>, JpegError> {
    let mut list = Vec::new();

    // Source frames for 64x48 sequences
    let frame_cb = generate_colorbars_rgb(64, 48);
    let frame_grad = generate_gradient_rgb(64, 48);
    let frame_flat = generate_flat_rgb(64, 48, 128, 64, 192);

    let cfg = JpegConfig {
        quality: 85,
        subsampling: Subsampling::Yuv420,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };

    let f0_bytes = encode_jpeg(64, 48, &frame_cb, &cfg)?;
    let f1_bytes = encode_jpeg(64, 48, &frame_grad, &cfg)?;
    let f2_bytes = encode_jpeg(64, 48, &frame_flat, &cfg)?;

    let sha_cb = compute_sha256_hex(&frame_cb);
    let sha_grad = compute_sha256_hex(&frame_grad);
    let sha_flat = compute_sha256_hex(&frame_flat);

    let sha_f0 = compute_sha256_hex(&f0_bytes);
    let sha_f1 = compute_sha256_hex(&f1_bytes);
    let sha_f2 = compute_sha256_hex(&f2_bytes);
    let f0_len = f0_bytes.len();
    let f1_len = f1_bytes.len();
    let f2_len = f2_bytes.len();

    // 1. mjpeg_clean_3frames.mjpeg
    let clean_bytes = encode_mjpeg(&[&f0_bytes, &f1_bytes, &f2_bytes]);
    list.push(GeneratedMjpegFixture {
        name: "mjpeg_clean_3frames.mjpeg".to_string(),
        variant: "clean".to_string(),
        frame_count: 3,
        file_sha256: compute_sha256_hex(&clean_bytes),
        file_bytes: clean_bytes,
        source_pixel_sha256: sha_cb.clone(),
        frames: vec![
            GeneratedMjpegFrame {
                index: 0,
                source_fixture: "rgb_64x48_colorbars_420".to_string(),
                width: 64,
                height: 48,
                offset: 0,
                length: f0_len,
                frame_sha256: sha_f0.clone(),
                source_pixel_sha256: sha_cb.clone(),
            },
            GeneratedMjpegFrame {
                index: 1,
                source_fixture: "rgb_64x48_gradient_420".to_string(),
                width: 64,
                height: 48,
                offset: f0_len,
                length: f1_len,
                frame_sha256: sha_f1.clone(),
                source_pixel_sha256: sha_grad.clone(),
            },
            GeneratedMjpegFrame {
                index: 2,
                source_fixture: "rgb_64x48_flat_420".to_string(),
                width: 64,
                height: 48,
                offset: f0_len + f1_len,
                length: f2_len,
                frame_sha256: sha_f2.clone(),
                source_pixel_sha256: sha_flat.clone(),
            },
        ],
    });

    // 2. mjpeg_truncated_last.mjpeg
    let mut trunc_bytes = Vec::new();
    trunc_bytes.extend_from_slice(&f0_bytes);
    trunc_bytes.extend_from_slice(&f1_bytes);
    // Find SOS in frame 2 and cut inside the entropy scan data (drops EOI, inside scan)
    let mut sos_data_start = None;
    for i in 0..f2_bytes.len().saturating_sub(4) {
        if f2_bytes[i] == 0xFF && f2_bytes[i + 1] == 0xDA {
            let sos_len = ((f2_bytes[i + 2] as usize) << 8) | (f2_bytes[i + 3] as usize);
            sos_data_start = Some(i + 2 + sos_len);
            break;
        }
    }
    let cut_offset = match sos_data_start {
        Some(sos_start) => {
            let scan_len = (f2_bytes.len().saturating_sub(2)).saturating_sub(sos_start);
            sos_start + scan_len / 2
        }
        None => f2_bytes.len() / 2,
    };
    trunc_bytes.extend_from_slice(&f2_bytes[..cut_offset]);
    let trunc_f2_sha = compute_sha256_hex(&f2_bytes[..cut_offset]);
    list.push(GeneratedMjpegFixture {
        name: "mjpeg_truncated_last.mjpeg".to_string(),
        variant: "truncated_last".to_string(),
        frame_count: 3,
        file_sha256: compute_sha256_hex(&trunc_bytes),
        file_bytes: trunc_bytes,
        source_pixel_sha256: sha_cb.clone(),
        frames: vec![
            GeneratedMjpegFrame {
                index: 0,
                source_fixture: "rgb_64x48_colorbars_420".to_string(),
                width: 64,
                height: 48,
                offset: 0,
                length: f0_len,
                frame_sha256: sha_f0.clone(),
                source_pixel_sha256: sha_cb.clone(),
            },
            GeneratedMjpegFrame {
                index: 1,
                source_fixture: "rgb_64x48_gradient_420".to_string(),
                width: 64,
                height: 48,
                offset: f0_len,
                length: f1_len,
                frame_sha256: sha_f1.clone(),
                source_pixel_sha256: sha_grad,
            },
            GeneratedMjpegFrame {
                index: 2,
                source_fixture: "rgb_64x48_flat_420_truncated".to_string(),
                width: 64,
                height: 48,
                offset: f0_len + f1_len,
                length: cut_offset,
                frame_sha256: trunc_f2_sha,
                source_pixel_sha256: sha_flat,
            },
        ],
    });

    // 3. mjpeg_garbage_between_frames.mjpeg
    let garbage_0 = b"\xFF\xFFGARBAGE_BETWEEN_FRAMES_SPAN_0\x00\xFF";
    let garbage_1 = b"GARBAGE_SPAN_1_BYTES";
    let mut garbage_bytes = Vec::new();
    garbage_bytes.extend_from_slice(&f0_bytes);
    garbage_bytes.extend_from_slice(garbage_0);
    garbage_bytes.extend_from_slice(&f1_bytes);
    garbage_bytes.extend_from_slice(garbage_1);
    garbage_bytes.extend_from_slice(&f2_bytes);
    list.push(GeneratedMjpegFixture {
        name: "mjpeg_garbage_between_frames.mjpeg".to_string(),
        variant: "garbage_between_frames".to_string(),
        frame_count: 3,
        file_sha256: compute_sha256_hex(&garbage_bytes),
        file_bytes: garbage_bytes,
        source_pixel_sha256: sha_cb.clone(),
        frames: vec![
            GeneratedMjpegFrame {
                index: 0,
                source_fixture: "rgb_64x48_colorbars_420".to_string(),
                width: 64,
                height: 48,
                offset: 0,
                length: f0_len,
                frame_sha256: sha_f0.clone(),
                source_pixel_sha256: sha_cb.clone(),
            },
            GeneratedMjpegFrame {
                index: 1,
                source_fixture: "rgb_64x48_gradient_420".to_string(),
                width: 64,
                height: 48,
                offset: f0_len + garbage_0.len(),
                length: f1_len,
                frame_sha256: sha_f1,
                source_pixel_sha256: compute_sha256_hex(&frame_grad),
            },
            GeneratedMjpegFrame {
                index: 2,
                source_fixture: "rgb_64x48_flat_420".to_string(),
                width: 64,
                height: 48,
                offset: f0_len + garbage_0.len() + f1_len + garbage_1.len(),
                length: f2_len,
                frame_sha256: sha_f2,
                source_pixel_sha256: compute_sha256_hex(&frame_flat),
            },
        ],
    });

    // 4. mjpeg_zero_length.mjpeg
    let zero_bytes = Vec::new();
    list.push(GeneratedMjpegFixture {
        name: "mjpeg_zero_length.mjpeg".to_string(),
        variant: "zero_length".to_string(),
        frame_count: 0,
        file_sha256: compute_sha256_hex(&zero_bytes),
        file_bytes: zero_bytes,
        source_pixel_sha256: compute_sha256_hex(&[]),
        frames: Vec::new(),
    });

    // 5. mjpeg_dimension_change.mjpeg
    let src_flat16 = generate_flat_rgb(16, 16, 128, 64, 192);
    let cfg_16 = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Yuv444,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let f16_bytes = encode_jpeg(16, 16, &src_flat16, &cfg_16)?;
    let dim_change_bytes = encode_mjpeg(&[&f16_bytes, &f0_bytes]);
    let sha_flat16 = compute_sha256_hex(&src_flat16);
    let f16_len = f16_bytes.len();
    let sha_f16 = compute_sha256_hex(&f16_bytes);

    list.push(GeneratedMjpegFixture {
        name: "mjpeg_dimension_change.mjpeg".to_string(),
        variant: "dimension_change".to_string(),
        frame_count: 2,
        file_sha256: compute_sha256_hex(&dim_change_bytes),
        file_bytes: dim_change_bytes,
        source_pixel_sha256: sha_flat16.clone(),
        frames: vec![
            GeneratedMjpegFrame {
                index: 0,
                source_fixture: "rgb_16x16_flat_444".to_string(),
                width: 16,
                height: 16,
                offset: 0,
                length: f16_len,
                frame_sha256: sha_f16,
                source_pixel_sha256: sha_flat16,
            },
            GeneratedMjpegFrame {
                index: 1,
                source_fixture: "rgb_64x48_colorbars_420".to_string(),
                width: 64,
                height: 48,
                offset: f16_len,
                length: f0_len,
                frame_sha256: sha_f0,
                source_pixel_sha256: sha_cb,
            },
        ],
    });

    Ok(list)
}

/// Formats the JSON manifest string for JPEG fixtures.
pub fn build_jpeg_manifest_json(fixtures: &[GeneratedJpegFixture]) -> String {
    let mut out =
        String::from("{\n  \"schema\": \"fss.jpeg_fixture_manifest.v1\",\n  \"fixtures\": [\n");
    let mut i = 0;
    while i < fixtures.len() {
        let f = &fixtures[i];
        out.push_str("    {\n");
        let mut fields: Vec<String> = Vec::new();
        fields.push(format!("      \"name\": \"{}\"", f.name));
        fields.push(format!("      \"width\": {}", f.width));
        fields.push(format!("      \"height\": {}", f.height));
        fields.push(format!("      \"channels\": {}", f.channels));
        fields.push(format!("      \"pixel_format\": \"{}\"", f.pixel_format));
        fields.push(format!("      \"subsampling\": \"{}\"", f.subsampling));
        fields.push(format!("      \"quality\": {}", f.quality));
        fields.push(format!(
            "      \"restart_interval\": {}",
            f.restart_interval
        ));
        fields.push(format!("      \"file_sha256\": \"{}\"", f.file_sha256));
        fields.push(format!(
            "      \"source_pixel_sha256\": \"{}\"",
            f.source_pixel_sha256
        ));
        fields.push(format!("      \"file_size\": {}", f.file_bytes.len()));
        if let Some(psnr) = f.encoder_psnr {
            fields.push(format!("      \"encoder_psnr\": {psnr:.2}"));
            fields.push(format!("      \"psnr\": {psnr:.2}"));
        }
        if let Some(max_err) = f.encoder_max_error {
            fields.push(format!("      \"encoder_max_error\": {max_err}"));
            fields.push(format!("      \"max_error\": {max_err}"));
        }
        if let Some(th) = f.psnr_threshold {
            fields.push(format!("      \"psnr_threshold\": {th:.1}"));
        }
        out.push_str(&fields.join(",\n"));
        out.push('\n');
        if i + 1 < fixtures.len() {
            out.push_str("    },\n");
        } else {
            out.push_str("    }\n");
        }
        i += 1;
    }
    out.push_str("  ]\n}\n");
    out
}

/// Formats the JSON manifest string for MJPEG fixtures.
pub fn build_mjpeg_manifest_json(fixtures: &[GeneratedMjpegFixture]) -> String {
    let mut out =
        String::from("{\n  \"schema\": \"fss.mjpeg_fixture_manifest.v1\",\n  \"fixtures\": [\n");
    let mut i = 0;
    while i < fixtures.len() {
        let f = &fixtures[i];
        out.push_str("    {\n");
        out.push_str(&format!("      \"name\": \"{}\",\n", f.name));
        out.push_str(&format!("      \"variant\": \"{}\",\n", f.variant));
        out.push_str(&format!("      \"frame_count\": {},\n", f.frame_count));
        out.push_str(&format!("      \"file_sha256\": \"{}\",\n", f.file_sha256));
        out.push_str(&format!(
            "      \"source_pixel_sha256\": \"{}\",\n",
            f.source_pixel_sha256
        ));
        out.push_str(&format!("      \"file_size\": {},\n", f.file_bytes.len()));
        out.push_str("      \"frames\": [\n");
        let mut j = 0;
        while j < f.frames.len() {
            let fr = &f.frames[j];
            out.push_str("        {\n");
            out.push_str(&format!("          \"index\": {},\n", fr.index));
            out.push_str(&format!(
                "          \"source_fixture\": \"{}\",\n",
                fr.source_fixture
            ));
            out.push_str(&format!("          \"width\": {},\n", fr.width));
            out.push_str(&format!("          \"height\": {},\n", fr.height));
            out.push_str(&format!("          \"offset\": {},\n", fr.offset));
            out.push_str(&format!("          \"length\": {},\n", fr.length));
            out.push_str(&format!(
                "          \"frame_sha256\": \"{}\",\n",
                fr.frame_sha256
            ));
            out.push_str(&format!(
                "          \"source_pixel_sha256\": \"{}\"\n",
                fr.source_pixel_sha256
            ));
            if j + 1 < f.frames.len() {
                out.push_str("        },\n");
            } else {
                out.push_str("        }\n");
            }
            j += 1;
        }
        out.push_str("      ]\n");
        if i + 1 < fixtures.len() {
            out.push_str("    },\n");
        } else {
            out.push_str("    }\n");
        }
        i += 1;
    }
    out.push_str("  ]\n}\n");
    out
}

/// Writes all generated JPEG and MJPEG fixtures and manifests to the target fixtures directory.
pub fn write_all_media_fixtures(media_dir: &std::path::Path) -> Result<(), JpegError> {
    let jpeg_dir = media_dir.join("jpeg");
    let mjpeg_dir = media_dir.join("mjpeg");
    std::fs::create_dir_all(&jpeg_dir).map_err(|e| JpegError::InvalidData(e.to_string()))?;
    std::fs::create_dir_all(&mjpeg_dir).map_err(|e| JpegError::InvalidData(e.to_string()))?;

    let jpegs = generate_all_jpeg_fixtures()?;
    for j in &jpegs {
        std::fs::write(jpeg_dir.join(&j.name), &j.file_bytes)
            .map_err(|e| JpegError::InvalidData(e.to_string()))?;
    }
    let jpeg_manifest = build_jpeg_manifest_json(&jpegs);
    std::fs::write(
        jpeg_dir.join("fixture_manifest.json"),
        jpeg_manifest.as_bytes(),
    )
    .map_err(|e| JpegError::InvalidData(e.to_string()))?;

    let mjpegs = generate_all_mjpeg_fixtures()?;
    for m in &mjpegs {
        std::fs::write(mjpeg_dir.join(&m.name), &m.file_bytes)
            .map_err(|e| JpegError::InvalidData(e.to_string()))?;
    }
    let mjpeg_manifest = build_mjpeg_manifest_json(&mjpegs);
    std::fs::write(
        mjpeg_dir.join("fixture_manifest.json"),
        mjpeg_manifest.as_bytes(),
    )
    .map_err(|e| JpegError::InvalidData(e.to_string()))?;

    Ok(())
}
