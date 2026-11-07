#![forbid(unsafe_code)]
//! Integer baseline transform. The Q14 basis follows T.81 A.3.3 and matches the
//! established FSS JPEG inverse-transform constants; no runtime trigonometry runs.

use crate::EncodeError;

const MATRIX: [[i32; 8]; 8] = [
    [11585, 11585, 11585, 11585, 11585, 11585, 11585, 11585],
    [16069, 13623, 9102, 3196, -3196, -9102, -13623, -16069],
    [15137, 6270, -6270, -15137, -15137, -6270, 6270, 15137],
    [13623, -3196, -16069, -9102, 9102, 16069, 3196, -13623],
    [11585, -11585, -11585, 11585, 11585, -11585, -11585, 11585],
    [9102, -16069, 3196, 13623, -13623, -3196, 16069, -9102],
    [6270, -15137, 15137, -6270, -6270, 15137, -15137, 6270],
    [3196, -9102, 13623, -16069, 16069, -13623, 9102, -3196],
];

/// Each scan position names its natural row-major coefficient index.
pub(crate) const ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

/// Full-range eight-bit RGB to JPEG Y/Cb/Cr, Q16 with half-up rounding.
pub(crate) fn rgb_to_ycbcr(rgb: &[u8]) -> [u8; 3] {
    let r = i32::from(rgb[0]);
    let g = i32::from(rgb[1]);
    let b = i32::from(rgb[2]);
    let y = (19595 * r + 38470 * g + 7471 * b + 32768) >> 16;
    let cb = (-11059 * r - 21709 * g + 32768 * b + (128 << 16) + 32768) >> 16;
    let cr = (32768 * r - 27439 * g - 5329 * b + (128 << 16) + 32768) >> 16;
    [y.clamp(0, 255) as u8, cb.clamp(0, 255) as u8, cr.clamp(0, 255) as u8]
}

/// Forward Q14 transform followed by one quantization rounding, ties away from zero.
///
/// A first-pass sum is below 2^24; a second-pass sum is below 2^41. The divisor is
/// at most 255*2^30, so every intermediate and the rounding addition fit i64.
pub(crate) fn quantized(
    pixels: &[u8; 64],
    quantizers: &[u8; 64],
) -> Result<[i16; 64], EncodeError> {
    let mut rows = [[0_i64; 8]; 8];
    for y in 0..8 {
        for u in 0..8 {
            for x in 0..8 {
                rows[y][u] +=
                    i64::from(i32::from(pixels[y * 8 + x]) - 128) * i64::from(MATRIX[u][x]);
            }
        }
    }
    let mut result = [0_i16; 64];
    for v in 0..8 {
        for u in 0..8 {
            let mut sum = 0_i64;
            for y in 0..8 {
                sum += rows[y][u] * i64::from(MATRIX[v][y]);
            }
            if u == 0 && v == 0 {
                // DC is exactly sum(level-shifted pixels)/8. Do not let the
                // approximate Q14 sqrt(1/2) basis perturb a quantization tie.
                sum = pixels.iter().map(|value| i64::from(*value) - 128).sum::<i64>() << 27;
            }
            let divisor = i64::from(quantizers[v * 8 + u]) << 30;
            if divisor == 0 {
                return Err(EncodeError::CoefficientRange);
            }
            let magnitude = (sum.abs() + divisor / 2) / divisor;
            let value = if sum < 0 { -magnitude } else { magnitude };
            // Baseline eight-bit sequential DCT: DC is 11-bit differential;
            // AC coefficients require categories no larger than ten.
            let allowed = if u == 0 && v == 0 { -1024..=1023 } else { -1023..=1023 };
            if !allowed.contains(&value) {
                return Err(EncodeError::CoefficientRange);
            }
            result[v * 8 + u] = value as i16;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_blocks_have_analytic_dc_and_zero_ac() -> Result<(), EncodeError> {
        for value in [0_u8, 1, 64, 127, 128, 129, 192, 254, 255] {
            let coefficients = quantized(&[value; 64], &[1; 64])?;
            assert_eq!(coefficients[0], 8 * (i16::from(value) - 128));
            assert!(coefficients[1..].iter().all(|coefficient| *coefficient == 0));
        }
        Ok(())
    }

    #[test]
    fn level_shift_quantization_and_sign_are_independent_of_entropy() -> Result<(), EncodeError> {
        // Constant 129 has DC=8. With Q=16 its exact half rounds away from zero.
        assert_eq!(quantized(&[129; 64], &[16; 64])?[0], 1);
        assert_eq!(quantized(&[127; 64], &[16; 64])?[0], -1);
        // A (4,4) checker in the DCT basis has exactly one AC coefficient of
        // magnitude 1020 and DC -4, derived directly from ±127.5 input levels.
        let mut pixels = [0; 64];
        for y in 0..8 {
            for x in 0..8 {
                let sign_x = matches!(x % 4, 0 | 3);
                let sign_y = matches!(y % 4, 0 | 3);
                pixels[y * 8 + x] = if sign_x == sign_y { 255 } else { 0 };
            }
        }
        let coefficients = quantized(&pixels, &[1; 64])?;
        assert_eq!(coefficients[0], -4);
        assert_eq!(coefficients[36], 1020);
        assert!(coefficients.iter().enumerate().all(|(i, value)| i == 0 || i == 36 || *value == 0));
        Ok(())
    }

    #[test]
    fn full_range_primary_colors_have_declared_integer_values() {
        for (rgb, expected) in [
            ([0, 0, 0], [0, 128, 128]),
            ([255, 255, 255], [255, 128, 128]),
            ([255, 0, 0], [76, 85, 255]),
            ([0, 255, 0], [150, 44, 21]),
            ([0, 0, 255], [29, 255, 107]),
            ([128, 128, 128], [128, 128, 128]),
        ] {
            assert_eq!(rgb_to_ycbcr(&rgb), expected);
        }
    }
}
