//! Scaling (flat matrices) and inverse transforms (clause 8.5).
//!
//! Blocks are raster 4x4 arrays `block[row * 4 + col]`. Coefficients arrive
//! in zig-zag scan order from CAVLC and are placed with [`ZIGZAG_4X4`].

/// Frame zig-zag scan: scan index -> raster position (Table 8-13).
pub const ZIGZAG_4X4: [usize; 16] = [0, 1, 4, 8, 5, 2, 3, 6, 9, 12, 13, 10, 7, 11, 14, 15];

/// `normAdjust4x4` values `v[m][0..3]` (clause 8.5.9, Table 8-15 basis).
const NORM_ADJUST: [[i32; 3]; 6] = [
    [10, 16, 13],
    [11, 18, 14],
    [13, 20, 16],
    [14, 23, 18],
    [16, 25, 20],
    [18, 29, 23],
];

/// `QP_C` as a function of `qPI` (Table 8-15).
const CHROMA_QP_TABLE: [u8; 52] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 29, 30, 31, 32, 32, 33, 34, 34, 35, 35, 36, 36, 37, 37, 37, 38, 38, 38, 39, 39,
    39, 39,
];

/// Chroma quantiser for a luma QP and a chroma offset (clause 8.5.8, 8-bit).
#[must_use]
pub fn chroma_qp(qp_y: i32, offset: i32) -> i32 {
    let index = (qp_y + offset).clamp(0, 51);
    usize::try_from(index).map_or(0, |i| i32::from(CHROMA_QP_TABLE[i]))
}

/// Flat `normAdjust4x4(m, i, j)` for a raster position.
#[must_use]
pub const fn norm_adjust(qp_mod6: usize, raster: usize) -> i32 {
    let row = raster / 4;
    let col = raster % 4;
    let row_q = &NORM_ADJUST[qp_mod6 % 6];
    // Both indices even -> v0; both odd -> v1; mixed -> v2.
    match (row & 1, col & 1) {
        (0, 0) => row_q[0],
        (1, 1) => row_q[1],
        _ => row_q[2],
    }
}

/// Scales a raster 4x4 block in place with flat weights (clause 8.5.12.1).
/// With `weightScale == 16` the spec formula reduces exactly to
/// `c * normAdjust << (qP / 6)` for every qP. When `skip_dc` is set,
/// position 0 is left as-is (it already holds a separately derived DC).
pub fn dequantize_4x4(block: &mut [i32; 16], qp: i32, skip_dc: bool) {
    let qp = qp.clamp(0, 51);
    let (div, rem) = ((qp / 6) as u32, (qp % 6) as usize);
    for (pos, value) in block.iter_mut().enumerate() {
        if skip_dc && pos == 0 {
            continue;
        }
        if *value != 0 {
            *value = (*value * norm_adjust(rem, pos)) << div;
        }
    }
}

/// Intra16x16 luma DC: inverse Hadamard then scaling (clause 8.5.10).
/// Input and output are raster 4x4 arrays whose position `(row, col)` is the
/// DC of the 4x4 luma block at `(4*col, 4*row)`.
#[must_use]
pub fn luma_dc_inverse(c: &[i32; 16], qp: i32) -> [i32; 16] {
    let mut tmp = [0i32; 16];
    // Rows then columns; the Hadamard is exact so order is immaterial.
    for row in 0..4 {
        let [a, b, cc, d] = [c[row * 4], c[row * 4 + 1], c[row * 4 + 2], c[row * 4 + 3]];
        tmp[row * 4] = a + b + cc + d;
        tmp[row * 4 + 1] = a + b - cc - d;
        tmp[row * 4 + 2] = a - b - cc + d;
        tmp[row * 4 + 3] = a - b + cc - d;
    }
    let mut f = [0i32; 16];
    for col in 0..4 {
        let [a, b, cc, d] = [tmp[col], tmp[4 + col], tmp[8 + col], tmp[12 + col]];
        f[col] = a + b + cc + d;
        f[4 + col] = a + b - cc - d;
        f[8 + col] = a - b - cc + d;
        f[12 + col] = a - b + cc - d;
    }
    let qp = qp.clamp(0, 51);
    let scale = 16 * NORM_ADJUST[(qp % 6) as usize][0];
    let div = qp / 6;
    f.map(|value| {
        if qp >= 36 {
            (value * scale) << (div - 6)
        } else {
            (value * scale + (1 << (5 - div))) >> (6 - div)
        }
    })
}

/// 4:2:0 chroma DC: 2x2 inverse transform then scaling (clause 8.5.11).
/// `c` is `[c00, c01, c10, c11]` (raster 2x2 over the chroma 4x4 blocks).
#[must_use]
pub fn chroma_dc_inverse(c: &[i32; 4], qp: i32) -> [i32; 4] {
    let f = [
        c[0] + c[1] + c[2] + c[3],
        c[0] - c[1] + c[2] - c[3],
        c[0] + c[1] - c[2] - c[3],
        c[0] - c[1] - c[2] + c[3],
    ];
    let qp = qp.clamp(0, 51);
    let scale = 16 * NORM_ADJUST[(qp % 6) as usize][0];
    let div = (qp / 6) as u32;
    f.map(|value| ((value * scale) << div) >> 5)
}

/// 4x4 inverse integer transform (clause 8.5.12.2): horizontal (row)
/// transforms first, then vertical, then `(x + 32) >> 6`.
#[must_use]
pub fn inverse_transform_4x4(d: &[i32; 16]) -> [i32; 16] {
    let mut h = [0i32; 16];
    for row in 0..4 {
        let [d0, d1, d2, d3] = [d[row * 4], d[row * 4 + 1], d[row * 4 + 2], d[row * 4 + 3]];
        let e0 = d0 + d2;
        let e1 = d0 - d2;
        let e2 = (d1 >> 1) - d3;
        let e3 = d1 + (d3 >> 1);
        h[row * 4] = e0 + e3;
        h[row * 4 + 1] = e1 + e2;
        h[row * 4 + 2] = e1 - e2;
        h[row * 4 + 3] = e0 - e3;
    }
    let mut r = [0i32; 16];
    for col in 0..4 {
        let [f0, f1, f2, f3] = [h[col], h[4 + col], h[8 + col], h[12 + col]];
        let g0 = f0 + f2;
        let g1 = f0 - f2;
        let g2 = (f1 >> 1) - f3;
        let g3 = f1 + (f3 >> 1);
        r[col] = (g0 + g3 + 32) >> 6;
        r[4 + col] = (g1 + g2 + 32) >> 6;
        r[8 + col] = (g1 - g2 + 32) >> 6;
        r[12 + col] = (g0 - g3 + 32) >> 6;
    }
    r
}

/// Adds a residual block to a 4x4 prediction in a plane, clipping to 8 bits.
pub(crate) fn add_residual(
    plane: &mut [u8],
    stride: usize,
    x: usize,
    y: usize,
    residual: &[i32; 16],
) {
    for row in 0..4 {
        for col in 0..4 {
            let index = (y + row) * stride + x + col;
            if let Some(sample) = plane.get_mut(index) {
                *sample = clip_u8(i32::from(*sample) + residual[row * 4 + col]);
            }
        }
    }
}

/// `Clip1Y` for 8-bit samples.
#[must_use]
pub fn clip_u8(value: i32) -> u8 {
    u8::try_from(value.clamp(0, 255)).unwrap_or(u8::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DC-only input: every row transform yields the DC, every column the
    /// same, so each residual sample is (DC + 32) >> 6.
    #[test]
    fn dc_only_inverse_transform() {
        let mut d = [0i32; 16];
        d[0] = 100;
        assert_eq!(inverse_transform_4x4(&d), [2; 16]);
        d[0] = -33;
        // (-33 + 32) >> 6 = -1 (arithmetic shift floors).
        assert_eq!(inverse_transform_4x4(&d), [-1; 16]);
    }

    /// Hand-computed: d01 = 64 only. Row 0: e = [0, 0, 32, 64] ->
    /// [64, 32, -32, -64]; each column carries a lone top value, so every
    /// row equals row 0; then (x + 32) >> 6 = [1, 1, 0, -1].
    #[test]
    fn single_ac_inverse_transform() {
        let mut d = [0i32; 16];
        d[1] = 64;
        let r = inverse_transform_4x4(&d);
        for row in 0..4 {
            assert_eq!(&r[row * 4..row * 4 + 4], &[1, 1, 0, -1]);
        }
        // Transposed input (d10 = 64): columns now carry [64, 32, -32, -64].
        let mut d = [0i32; 16];
        d[4] = 64;
        let r = inverse_transform_4x4(&d);
        for row in 0..4 {
            let expected = [1, 1, 0, -1][row];
            assert_eq!(&r[row * 4..row * 4 + 4], &[expected; 4]);
        }
    }

    /// Row-before-column order is observable through the `>> 1` rounding:
    /// d = [[0, 1, 0, 0], [1, 0, 0, 0], ...] hand-computed per 8.5.12.2.
    /// Rows: row0 d1=1 -> e2 = 0, e3 = 1 -> [1, 0, 0, -1];
    ///       row1 d0=1 -> [1, 1, 1, 1].
    /// Column 0 = [1, 1, 0, 0]: g0 = 1, g1 = 1, g2 = 0, g3 = 1
    ///   -> [2, 1, 1, 0]; column 1 = [0, 1, 0, 0] -> g2 = 0, g3 = 1
    ///   -> [1, 0, 0, -1]; column 2 = [0, 1, 0, 0] -> [1, 0, 0, -1];
    /// column 3 = [-1, 1, 0, 0]: g0 = -1, g1 = -1, g2 = 0, g3 = 1
    ///   -> [0, -1, -1, -2]. After (x + 32) >> 6 everything rounds to 0.
    #[test]
    fn small_mixed_block_rounds_to_zero() {
        let mut d = [0i32; 16];
        d[1] = 1;
        d[4] = 1;
        assert_eq!(inverse_transform_4x4(&d), [0; 16]);
    }

    /// Flat scaling: position (0,1) uses v[m][2]; qP = 6 -> m = 0, shift 1:
    /// 1 * 13 << 1 = 26. Position (1,1) uses v[m][1]: qP = 28 -> m = 4,
    /// shift 4: -2 * 25 << 4 = -800.
    #[test]
    fn flat_dequantisation_matches_hand_values() {
        let mut block = [0i32; 16];
        block[1] = 1;
        dequantize_4x4(&mut block, 6, false);
        assert_eq!(block[1], 26);
        let mut block = [0i32; 16];
        block[5] = -2;
        block[0] = 7;
        dequantize_4x4(&mut block, 28, true);
        assert_eq!(block[5], -800);
        assert_eq!(block[0], 7, "DC untouched when skip_dc");
    }

    /// Luma DC with c00 = 1: Hadamard spreads 1 everywhere; qP = 24
    /// (qP/6 = 4 < 6, m = 0): (1 * 160 + 2) >> 2 = 40.
    /// qP = 40 (>= 36, m = 4, qP/6 = 6): (1 * 256) << 0 = 256.
    #[test]
    fn luma_dc_hadamard_and_scaling() {
        let mut c = [0i32; 16];
        c[0] = 1;
        assert_eq!(luma_dc_inverse(&c, 24), [40; 16]);
        assert_eq!(luma_dc_inverse(&c, 40), [256; 16]);
        // c01 = 1: columns alternate sign pattern of Hadamard row 1
        // [1, 1, -1, -1] across columns, identical down rows.
        let mut c = [0i32; 16];
        c[1] = 1;
        let out = luma_dc_inverse(&c, 24);
        for row in 0..4 {
            assert_eq!(&out[row * 4..row * 4 + 4], &[40, 40, -40, -40]);
        }
    }

    /// Chroma DC 2x2: c = [4, 0, 0, 0] -> f = [4, 4, 4, 4];
    /// qP = 30 (m = 0, qP/6 = 5): ((4 * 160) << 5) >> 5 = 640.
    /// c = [1, 1, 0, 0] -> f = [2, 0, 2, 0]; qP = 0: (2 * 160) >> 5 = 10.
    #[test]
    fn chroma_dc_transform_and_scaling() {
        assert_eq!(chroma_dc_inverse(&[4, 0, 0, 0], 30), [640; 4]);
        assert_eq!(chroma_dc_inverse(&[1, 1, 0, 0], 0), [10, 0, 10, 0]);
    }

    #[test]
    fn chroma_qp_table_edges() {
        assert_eq!(chroma_qp(29, 0), 29);
        assert_eq!(chroma_qp(30, 0), 29);
        assert_eq!(chroma_qp(51, 0), 39);
        assert_eq!(chroma_qp(51, 12), 39);
        assert_eq!(chroma_qp(0, -12), 0);
        assert_eq!(chroma_qp(40, -2), 35);
    }

    #[test]
    fn zigzag_is_a_permutation() {
        let mut seen = [false; 16];
        for &pos in &ZIGZAG_4X4 {
            assert!(!seen[pos]);
            seen[pos] = true;
        }
    }
}
