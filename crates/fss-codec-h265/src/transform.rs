//! Scaling (dequantisation) and inverse transforms (ITU-T H.265 clauses
//! 8.6.2..8.6.4): flat or scaling-list factors, transform skip, the 4x4
//! DST-VII for intra luma, and the 4..32-point inverse DCTs, with the
//! intermediate clipping of clause 8.6.4.2.

use crate::tables::DST_MATRIX;

/// `levelScale[]` (equation 8-309).
const LEVEL_SCALE: [i64; 6] = [40, 45, 51, 57, 64, 72];

/// Scales the parsed levels in place (clause 8.6.3):
/// `d = Clip3(-32768, 32767, (level * m * levelScale[qP % 6] << (qP / 6)
/// + (1 << (bdShift - 1))) >> bdShift)` with `bdShift = 8 + log2 - 5`.
/// `factors` is the row-major `m[x][y]` matrix (all 16 when flat).
pub(crate) fn scale(coeffs: &mut [i32], log2: u32, qp: i32, factors: &[u8]) {
    let size = 1usize << log2;
    let shift = 8 + log2 - 5;
    let add = 1i64 << (shift - 1);
    let scale = LEVEL_SCALE[(qp % 6) as usize] << (qp / 6);
    for (i, coeff) in coeffs.iter_mut().take(size * size).enumerate() {
        if *coeff == 0 {
            continue;
        }
        let m = i64::from(factors[i]);
        let value = (i64::from(*coeff) * m * scale + add) >> shift;
        *coeff = value.clamp(-32768, 32767) as i32;
    }
}

/// Residual of a transform-skipped block (clause 8.6.4.2 with
/// `transform_skip_flag`): `r = d << 7`, then the final `bdShift` of 12.
pub(crate) fn transform_skip(coeffs: &mut [i32], log2: u32) {
    let size = 1usize << log2;
    for coeff in coeffs.iter_mut().take(size * size) {
        *coeff = ((*coeff << 7) + (1 << 11)) >> 12;
    }
}

/// One 1-D inverse transform of `n` inputs spaced `stride` apart.
fn inverse_1d(input: &[i32], output: &mut [i32], n: usize, matrix: &[[i32; 32]; 32], dst: bool) {
    let row_step = 32 / n;
    for (i, out) in output.iter_mut().take(n).enumerate() {
        let mut sum: i64 = 0;
        for (k, &x) in input.iter().take(n).enumerate() {
            if x == 0 {
                continue;
            }
            let coefficient = if dst {
                DST_MATRIX[k][i]
            } else {
                matrix[k * row_step][i]
            };
            sum += i64::from(coefficient) * i64::from(x);
        }
        *out = sum.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32;
    }
}

/// Two-stage inverse transform (clause 8.6.4.2): columns first with the
/// intermediate clip `Clip3(-32768, 32767, (e + 64) >> 7)`, then rows with
/// `bdShift = 20 - BitDepth = 12`. `coeffs` is row-major `d[x][y]` at
/// `y * size + x`; the residual replaces it.
pub(crate) fn inverse_transform(
    coeffs: &mut [i32],
    log2: u32,
    dst: bool,
    matrix: &[[i32; 32]; 32],
) {
    let n = 1usize << log2;
    let mut column = [0i32; 32];
    let mut transformed = [0i32; 32];
    for x in 0..n {
        for y in 0..n {
            column[y] = coeffs[y * n + x];
        }
        if column[..n].iter().all(|&v| v == 0) {
            continue;
        }
        inverse_1d(&column, &mut transformed, n, matrix, dst);
        for y in 0..n {
            coeffs[y * n + x] = ((transformed[y] + 64) >> 7).clamp(-32768, 32767);
        }
    }
    for y in 0..n {
        let row = &mut coeffs[y * n..(y + 1) * n];
        inverse_1d(row, &mut transformed, n, matrix, dst);
        for (x, value) in row.iter_mut().enumerate() {
            *value = (transformed[x] + 2048) >> 12;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::transform_matrix;

    /// A lone DC coefficient c through the n-point DCT: first stage
    /// 64 * c -> (64c + 64) >> 7, second 64 * g -> (64g + 2048) >> 12.
    /// c = 100: g = 50, r = (3200 + 2048) >> 12 = 1 everywhere.
    /// c = 1000: g = 500, r = (32000 + 2048) >> 12 = 8.
    #[test]
    fn dc_only_by_hand() {
        let matrix = transform_matrix();
        for log2 in 2..=5u32 {
            let n = 1usize << log2;
            let mut block = vec![0i32; n * n];
            block[0] = 1000;
            inverse_transform(&mut block, log2, false, &matrix);
            assert!(block.iter().all(|&v| v == 8), "log2 {log2}");
            block.fill(0);
            block[0] = 100;
            inverse_transform(&mut block, log2, false, &matrix);
            assert!(block.iter().all(|&v| v == 1), "log2 {log2}");
        }
    }

    /// DST with a lone first coefficient 64: stage 1 column 0 is
    /// 64 * [29, 55, 74, 84] -> (x + 64) >> 7 = [15, 28, 37, 42]; stage 2
    /// row y is value * [29, 55, 74, 84] -> (v + 2048) >> 12:
    /// row 0: 15 * 29 = 435 -> 0; 15 * 84 = 1260 -> 0;
    /// row 3: 42 * [29, 55, 74, 84] = [1218, 2310, 3108, 3528] ->
    /// [0, 1, 1, 1].
    #[test]
    fn dst_by_hand() {
        let matrix = transform_matrix();
        let mut block = [0i32; 16];
        block[0] = 64;
        inverse_transform(&mut block, 2, true, &matrix);
        assert_eq!(&block[..4], &[0, 0, 0, 0]);
        assert_eq!(&block[12..], &[0, 1, 1, 1]);
    }

    /// Clause 8.6.3 by hand, flat m = 16, 4x4 (bdShift 5): level 1 at QP
    /// 4 -> (16 * 64 + 16) >> 5 = 32; at QP 10 -> 16 * 64 << 1 -> 64;
    /// level -3 at QP 0 -> (-3 * 16 * 40 + 16) >> 5 = -1904 >> 5 = -60;
    /// saturation at 32767.
    #[test]
    fn scaling_by_hand() {
        let flat = [16u8; 1024];
        let mut block = [0i32; 16];
        block[0] = 1;
        scale(&mut block, 2, 4, &flat);
        assert_eq!(block[0], 32);
        block[0] = 1;
        scale(&mut block, 2, 10, &flat);
        assert_eq!(block[0], 64);
        block[0] = -3;
        scale(&mut block, 2, 0, &flat);
        assert_eq!(block[0], -60);
        block[0] = 30_000;
        scale(&mut block, 2, 51, &flat);
        assert_eq!(block[0], 32767);
        // 32x32 at QP 22 (bdShift 8): 5 * 16 * 64 << 3 = 40960 -> +128 >>
        // 8 = 160.
        let mut big = vec![0i32; 1024];
        big[33] = 5;
        scale(&mut big, 5, 22, &flat);
        assert_eq!(big[33], 160);
    }

    /// Transform skip: (d << 7 + 2048) >> 12, i.e. (d + 16) >> 5.
    #[test]
    fn transform_skip_by_hand() {
        let mut block = [0i32; 16];
        block[0] = 64;
        block[1] = -48;
        block[2] = 15;
        transform_skip(&mut block, 2);
        assert_eq!(&block[..3], &[2, -1, 0]);
    }
}
