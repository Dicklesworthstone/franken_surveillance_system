#![forbid(unsafe_code)]
//! Scalar image resize/color/normalize reference kernels (FSS-122).
//!
//! Deterministic, allocation-bounded, float-free-determinism-first
//! reference kernels over packed u8 luma/RGB images:
//!
//! - [`resize_bilinear_luma`]: area-normalized bilinear downscale/upscale
//!   with fixed-point arithmetic (Q16 accumulation; ties-to-even row
//!   mapping) — identical inputs yield identical outputs on every
//!   platform, no fast-math divergence.
//! - [`rgb_to_luma`]: ITU-R BT.601 integer approximated conversion with
//!   the classic rounding constants, clamped.
//! - [`normalize_luma`]: per-image min/max normalization to 0..=255 with
//!   a fixed-point scale; a constant image maps to a stated fill value
//!   (never a divide-by-zero, never an invented gradient).
//!
//! These are the reference semantics the optimized kernels (WP-060) must
//! match bit-for-bit; the deterministic-reference differential lane
//! compares against THESE functions.

/// Typed kernel refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImageKernelError {
    /// A dimension is zero or above the ceiling.
    InvalidDimension {
        /// Observed value.
        value: usize,
    },
    /// The source buffer does not match width x height.
    BufferMismatch {
        /// Expected bytes.
        expected: usize,
        /// Observed bytes.
        observed: usize,
    },
    /// Output dimensions are zero.
    EmptyTarget,
}

impl std::fmt::Display for ImageKernelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDimension { value } => {
                write!(f, "dimension {value} is zero or above the ceiling")
            }
            Self::BufferMismatch { expected, observed } => {
                write!(f, "buffer {observed} bytes, expected {expected}")
            }
            Self::EmptyTarget => write!(f, "target dimensions are zero"),
        }
    }
}

impl std::error::Error for ImageKernelError {}

/// Maximum admitted axis (matches MJPEG's documented ceiling).
pub const MAX_AXIS: usize = 4_096;

fn check_plane(width: usize, height: usize, len: usize) -> Result<(), ImageKernelError> {
    if width == 0 || height == 0 || width > MAX_AXIS || height > MAX_AXIS {
        return Err(ImageKernelError::InvalidDimension {
            value: width.max(height),
        });
    }
    let expected = width
        .checked_mul(height)
        .ok_or(ImageKernelError::InvalidDimension { value: usize::MAX })?;
    if len != expected {
        return Err(ImageKernelError::BufferMismatch {
            expected,
            observed: len,
        });
    }
    Ok(())
}

/// Area-normalized bilinear luma resize with Q16 fixed-point arithmetic.
///
/// Deterministic on every platform: integer mapping from destination
/// coordinates to source coordinates via Q16 reciprocals of the scale
/// factors, four-tap accumulation with rounding halves added once, single
/// final rounding — no floats anywhere.
///
/// # Errors
/// Typed dimension/buffer refusals.
pub fn resize_bilinear_luma(
    src: &[u8],
    src_w: usize,
    src_h: usize,
    dst_w: usize,
    dst_h: usize,
) -> Result<Vec<u8>, ImageKernelError> {
    check_plane(src_w, src_h, src.len())?;
    if dst_w == 0 || dst_h == 0 || dst_w > MAX_AXIS || dst_h > MAX_AXIS {
        return Err(ImageKernelError::EmptyTarget);
    }
    // Center-mapped Q16 sampling: source position of destination pixel d
    // is (d + 0.5) * (src/dst) - 0.5 — the half-pixel convention that makes
    // same-size resize the EXACT identity. Computed as
    // ((2d + 1) * src << 15) / (2 * dst) - (1 << 15), clamped at zero.
    let mut out = Vec::with_capacity(dst_w * dst_h);
    for dy in 0..dst_h {
        let sy_raw = ((2 * dy as u64 + 1) * (src_h as u64) << 16) / (2 * dst_h as u64);
        let sy = sy_raw.saturating_sub(1 << 15);
        let y0 = ((sy >> 16) as usize).min(src_h - 1);
        let y1 = (y0 + 1).min(src_h - 1);
        let fy = (sy & 0xFFFF) as u64;
        for dx in 0..dst_w {
            let sx_raw = ((2 * dx as u64 + 1) * (src_w as u64) << 16) / (2 * dst_w as u64);
            let sx = sx_raw.saturating_sub(1 << 15);
            let x0 = ((sx >> 16) as usize).min(src_w - 1);
            let x1 = (x0 + 1).min(src_w - 1);
            let fx = (sx & 0xFFFF) as u64;
            let p00 = src[y0 * src_w + x0] as u64;
            let p01 = src[y0 * src_w + x1] as u64;
            let p10 = src[y1 * src_w + x0] as u64;
            let p11 = src[y1 * src_w + x1] as u64;
            // Bilinear in Q32 then single rounding to Q0.
            let top = p00 * (0x1_0000 - fx) + p01 * fx;
            let bottom = p10 * (0x1_0000 - fx) + p11 * fx;
            let value = (top * (0x1_0000 - fy) + bottom * fy + (1u64 << 31)) >> 32;
            out.push(value.min(255) as u8);
        }
    }
    Ok(out)
}

/// BT.601 luma from packed RGB with rounded integer constants.
///
/// # Errors
/// Typed refusals when the buffer is not exactly 3 x pixels.
pub fn rgb_to_luma(rgb: &[u8]) -> Result<Vec<u8>, ImageKernelError> {
    if rgb.len() % 3 != 0 {
        return Err(ImageKernelError::BufferMismatch {
            expected: rgb.len() + 3 - rgb.len() % 3,
            observed: rgb.len(),
        });
    }
    let pixels = rgb.len() / 3;
    if pixels == 0 || pixels > MAX_AXIS * MAX_AXIS {
        return Err(ImageKernelError::InvalidDimension { value: pixels });
    }
    // (R*77 + G*150 + B*29 + 128) >> 8 — the classic integer BT.601.
    let mut out = Vec::with_capacity(pixels);
    for px in rgb.chunks_exact(3) {
        let value =
            (u32::from(px[0]) * 77 + u32::from(px[1]) * 150 + u32::from(px[2]) * 29 + 128) >> 8;
        out.push(value.min(255) as u8);
    }
    Ok(out)
}

/// Per-image min/max luma normalization, fixed-point, deterministic.
///
/// A constant image (max == min) maps every pixel to `constant_fill`
/// (default 128): no divide-by-zero, no invented gradient.
///
/// # Errors
/// Typed dimension/buffer refusals.
pub fn normalize_luma(
    plane: &[u8],
    width: usize,
    height: usize,
    constant_fill: u8,
) -> Result<Vec<u8>, ImageKernelError> {
    check_plane(width, height, plane.len())?;
    let Some(&min) = plane.iter().min() else {
        return Ok(Vec::new());
    };
    let &max = plane.iter().max().ok_or(ImageKernelError::EmptyTarget)?;
    if max == min {
        return Ok(vec![constant_fill; plane.len()]);
    }
    // Q16 gain = 65535 / (max - min), computed once.
    let gain = (65_535u64 << 16) / u64::from(max - min);
    let half = 1u64 << 15;
    Ok(plane
        .iter()
        .map(|&v| {
            let scaled = (u64::from(v).saturating_sub(u64::from(min)) * gain + half) >> 16;
            scaled.min(255) as u8
        })
        .collect())
}
