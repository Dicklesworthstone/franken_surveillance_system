//! Fixed tables of ITU-T H.265 transcribed from the standard: scan orders
//! (clause 6.5), intra angles (Tables 8-4 and 8-5), the transform matrix
//! coefficients (clause 8.6.4.2), the default scaling lists (Tables 7-5
//! and 7-6) and the 4:2:0 chroma QP mapping (Table 8-10).

/// Up-right diagonal scan of a `size x size` block (clause 6.5.3), as
/// `(x, y)` pairs in scan order.
pub(crate) fn diagonal_scan(size: usize) -> Vec<(u8, u8)> {
    let mut scan = Vec::with_capacity(size * size);
    let (mut x, mut y) = (0usize, 0usize);
    while scan.len() < size * size {
        loop {
            if x < size && y < size {
                scan.push((x as u8, y as u8));
            }
            if y == 0 {
                break;
            }
            y -= 1;
            x += 1;
        }
        y = x + 1;
        x = 0;
        if y >= 2 * size {
            break;
        }
    }
    scan
}

/// Scan order of one 4x4 coefficient group or one sub-block grid:
/// `scan_idx` 0 = up-right diagonal, 1 = horizontal, 2 = vertical
/// (clauses 6.5.3..6.5.5). Returns `(x, y)` pairs.
pub(crate) fn scan_order(scan_idx: u8, size: usize) -> Vec<(u8, u8)> {
    match scan_idx {
        1 => (0..size * size)
            .map(|i| ((i % size) as u8, (i / size) as u8))
            .collect(),
        2 => (0..size * size)
            .map(|i| ((i / size) as u8, (i % size) as u8))
            .collect(),
        _ => diagonal_scan(size),
    }
}

/// `intraPredAngle` for `predModeIntra` 2..=34 (Table 8-4), indexed by
/// `mode - 2`.
pub(crate) const INTRA_PRED_ANGLE: [i32; 33] = [
    32, 26, 21, 17, 13, 9, 5, 2, 0, -2, -5, -9, -13, -17, -21, -26, -32, -26, -21, -17, -13, -9,
    -5, -2, 0, 2, 5, 9, 13, 17, 21, 26, 32,
];

/// `invAngle` for `predModeIntra` 11..=25 (Table 8-5), indexed by
/// `mode - 11`.
pub(crate) const INV_ANGLE: [i32; 15] = [
    -4096, -1638, -910, -630, -482, -390, -315, -256, -315, -390, -482, -630, -910, -1638, -4096,
];

/// The distinct magnitudes of the 32x32 transform matrix (clause
/// 8.6.4.2, equations 8-315..8-318): `COS64[m]` is the coefficient whose
/// angle is `m * pi / 64`, for `m = 1..=32` (index 0 is unused; row 0 of
/// the matrix is the flat 64).
const COS64: [i32; 33] = [
    0, 90, 90, 90, 89, 88, 87, 85, 83, 82, 80, 78, 75, 73, 70, 67, 64, 61, 57, 54, 50, 46, 43, 38,
    36, 31, 25, 22, 18, 13, 9, 4, 0,
];

/// `transMatrix[row][column]` of the 32-point inverse transform. The
/// `n`-point matrix uses rows `k * 32 / n` and columns `0..n`.
pub(crate) fn transform_matrix() -> [[i32; 32]; 32] {
    let mut matrix = [[0i32; 32]; 32];
    for (row, line) in matrix.iter_mut().enumerate() {
        for (column, value) in line.iter_mut().enumerate() {
            if row == 0 {
                *value = 64;
                continue;
            }
            // Angle (2 * column + 1) * row * pi / 64, reduced to [0, 64]
            // with cos(2 pi - a) = cos(a) and cos(pi - a) = -cos(a).
            let mut m = ((2 * column + 1) * row) % 128;
            if m > 64 {
                m = 128 - m;
            }
            *value = if m > 32 { -COS64[64 - m] } else { COS64[m] };
        }
    }
    matrix
}

/// The 4x4 DST-VII matrix for intra 4x4 luma (equation 8-314).
pub(crate) const DST_MATRIX: [[i32; 4]; 4] = [
    [29, 55, 74, 84],
    [74, 74, 0, -74],
    [84, -29, -74, 55],
    [55, -84, 74, -29],
];

/// Default 8x8 intra scaling list in up-right diagonal scan order
/// (Table 7-6, matrixId 0..=2).
pub(crate) const DEFAULT_SCALING_INTRA: [u8; 64] = [
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 17, 16, 17, 16, 17, 18, 17, 18, 18, 17, 18, 21, 19, 20,
    21, 20, 19, 21, 24, 22, 22, 24, 24, 22, 22, 24, 25, 25, 27, 30, 27, 25, 25, 29, 31, 35, 35, 31,
    29, 36, 41, 44, 41, 36, 47, 54, 54, 47, 65, 70, 65, 88, 88, 115,
];

/// Default 8x8 inter scaling list in up-right diagonal scan order
/// (Table 7-6, matrixId 3..=5).
pub(crate) const DEFAULT_SCALING_INTER: [u8; 64] = [
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 18, 20, 20, 20,
    20, 20, 20, 20, 24, 24, 24, 24, 24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 28, 28, 28, 28, 28,
    28, 33, 33, 33, 33, 33, 41, 41, 41, 41, 54, 54, 54, 71, 71, 91,
];

/// `QpC` as a function of `qPi` for 4:2:0 (Table 8-10).
pub(crate) fn chroma_qp(qpi: i32) -> i32 {
    const MID: [i32; 14] = [29, 30, 31, 32, 33, 33, 34, 34, 35, 35, 36, 36, 37, 37];
    if qpi < 30 {
        qpi
    } else if qpi > 43 {
        qpi - 6
    } else {
        MID[(qpi - 30) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Clause 6.5.3 by hand for a 4x4 block: (0,0) (0,1) (1,0) (0,2)
    /// (1,1) (2,0) (0,3) (1,2) (2,1) (3,0) (1,3) (2,2) (3,1) (2,3) (3,2)
    /// (3,3).
    #[test]
    fn diagonal_scan_4x4_by_hand() {
        let expected: [(u8, u8); 16] = [
            (0, 0),
            (0, 1),
            (1, 0),
            (0, 2),
            (1, 1),
            (2, 0),
            (0, 3),
            (1, 2),
            (2, 1),
            (3, 0),
            (1, 3),
            (2, 2),
            (3, 1),
            (2, 3),
            (3, 2),
            (3, 3),
        ];
        assert_eq!(diagonal_scan(4), expected);
        assert_eq!(diagonal_scan(2), vec![(0, 0), (0, 1), (1, 0), (1, 1)]);
        let eight = diagonal_scan(8);
        assert_eq!(eight.len(), 64);
        // Anti-diagonal 7 starts at index 28 with (0,7) and ends at 35
        // with (7,0); the last entry is (7,7).
        assert_eq!(eight[28], (0, 7));
        assert_eq!(eight[35], (7, 0));
        assert_eq!(eight[63], (7, 7));
        assert_eq!(scan_order(1, 4)[5], (1, 1));
        assert_eq!(scan_order(2, 4)[1], (0, 1));
        assert_eq!(scan_order(2, 2), vec![(0, 0), (0, 1), (1, 0), (1, 1)]);
    }

    /// Rows of the n-point matrices typed from clause 8.6.4.2.
    #[test]
    fn transform_matrix_rows_match_spec() {
        let m = transform_matrix();
        // 4-point: rows 0, 8, 16, 24.
        assert_eq!(&m[8][..4], &[83, 36, -36, -83]);
        assert_eq!(&m[16][..4], &[64, -64, -64, 64]);
        assert_eq!(&m[24][..4], &[36, -83, 83, -36]);
        // 8-point row 1 (matrix row 4).
        assert_eq!(&m[4][..8], &[89, 75, 50, 18, -18, -50, -75, -89]);
        // 16-point row 1 (matrix row 2).
        assert_eq!(
            &m[2][..16],
            &[
                90, 87, 80, 70, 57, 43, 25, 9, -9, -25, -43, -57, -70, -80, -87, -90
            ]
        );
        // 32-point row 1.
        assert_eq!(
            &m[1][..16],
            &[
                90, 90, 88, 85, 82, 78, 73, 67, 61, 54, 46, 38, 31, 22, 13, 4
            ]
        );
        assert_eq!(m[1][31], -90);
        // 32-point row 31 starts 4, -13, 22, -31.
        assert_eq!(&m[31][..4], &[4, -13, 22, -31]);
        assert!(m[0].iter().all(|&v| v == 64));
    }

    #[test]
    fn angle_tables_and_chroma_qp() {
        assert_eq!(INTRA_PRED_ANGLE[0], 32); // mode 2
        assert_eq!(INTRA_PRED_ANGLE[8], 0); // mode 10
        assert_eq!(INTRA_PRED_ANGLE[16], -32); // mode 18
        assert_eq!(INTRA_PRED_ANGLE[24], 0); // mode 26
        assert_eq!(INTRA_PRED_ANGLE[32], 32); // mode 34
        assert_eq!(INV_ANGLE[7], -256); // mode 18
        assert_eq!(chroma_qp(29), 29);
        assert_eq!(chroma_qp(30), 29);
        assert_eq!(chroma_qp(34), 33);
        assert_eq!(chroma_qp(43), 37);
        assert_eq!(chroma_qp(44), 38);
        assert_eq!(chroma_qp(51), 45);
    }

    /// Default list raster positions by hand: (7,0) is diagonal index 35
    /// (24 intra, 24 inter); (7,7) is index 63 (115 / 91).
    #[test]
    fn default_scaling_lists_spot_check() {
        assert_eq!(DEFAULT_SCALING_INTRA[35], 24);
        assert_eq!(DEFAULT_SCALING_INTRA[63], 115);
        assert_eq!(DEFAULT_SCALING_INTER[35], 24);
        assert_eq!(DEFAULT_SCALING_INTER[63], 91);
    }
}
