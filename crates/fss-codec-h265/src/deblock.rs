//! In-loop deblocking filter (ITU-T H.265 clause 8.7.2): boundary strength
//! derivation for transform and prediction block edges on the 8x8 luma
//! grid, and the luma (strong / weak) and chroma edge filters. Vertical
//! edges of the whole picture are filtered first, then horizontal edges
//! on the vertically filtered samples.

use crate::ctu::{BlockInfo, PicState};
use crate::inter::MvField;
use crate::tables::chroma_qp;

/// `tC'` as a function of `Q` (Table 8-12).
const TC_TABLE: [i32; 54] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 3,
    3, 3, 3, 4, 4, 4, 5, 5, 6, 6, 7, 8, 9, 10, 11, 13, 14, 16, 18, 20, 22, 24,
];

/// `beta'` as a function of `Q` (Table 8-12).
const BETA_TABLE: [i32; 52] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64,
];

/// Deblocking parameters of one slice (indexed by slice tag - 1).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SliceFilter {
    pub deblocking_disabled: bool,
    pub beta_offset: i32,
    pub tc_offset: i32,
    pub loop_filter_across_slices: bool,
}

/// Picture-level inputs of the filters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FilterParams {
    pub cb_qp_offset: i32,
    pub cr_qp_offset: i32,
}

/// Boundary strength from motion alone (clause 8.7.2.4, the last three
/// conditions): different reference pictures or motion vector counts, or
/// a vector component difference of at least one integer sample.
pub(crate) fn motion_strength(
    q: &MvField,
    q_refs: &[Vec<(i32, bool)>; 2],
    p: &MvField,
    p_refs: &[Vec<(i32, bool)>; 2],
) -> u8 {
    let poc = |field: &MvField, refs: &[Vec<(i32, bool)>; 2], list: usize| {
        refs[list]
            .get(field.ref_idx[list] as usize)
            .map(|entry| entry.0)
    };
    let far = |a: [i16; 2], b: [i16; 2]| {
        (i32::from(a[0]) - i32::from(b[0])).abs() >= 4
            || (i32::from(a[1]) - i32::from(b[1])).abs() >= 4
    };
    match (q.pred, p.pred) {
        (3, 3) => {
            let (q0, q1) = (poc(q, q_refs, 0), poc(q, q_refs, 1));
            let (p0, p1) = (poc(p, p_refs, 0), poc(p, p_refs, 1));
            if q0 == p0 && q0 == q1 && p0 == p1 {
                let direct = far(p.mv[0], q.mv[0]) || far(p.mv[1], q.mv[1]);
                let crossed = far(p.mv[1], q.mv[0]) || far(p.mv[0], q.mv[1]);
                u8::from(direct && crossed)
            } else if p0 == q0 && p1 == q1 {
                u8::from(far(p.mv[0], q.mv[0]) || far(p.mv[1], q.mv[1]))
            } else if p1 == q0 && p0 == q1 {
                u8::from(far(p.mv[1], q.mv[0]) || far(p.mv[0], q.mv[1]))
            } else {
                1
            }
        }
        (3, _) | (_, 3) => 1,
        _ => {
            let ql = usize::from(!q.uses(0));
            let pl = usize::from(!p.uses(0));
            if poc(q, q_refs, ql) == poc(p, p_refs, pl) {
                u8::from(far(q.mv[ql], p.mv[pl]))
            } else {
                1
            }
        }
    }
}

/// Boundary strength of the edge between `p` and `q` when it is a
/// transform block edge (`tu_edge`) or a prediction block edge only.
pub(crate) fn edge_strength(pic: &PicState, q: &BlockInfo, p: &BlockInfo, tu_edge: bool) -> u8 {
    if q.intra || p.intra {
        return 2;
    }
    if tu_edge && (q.nonzero || p.nonzero) {
        return 1;
    }
    let refs = |info: &BlockInfo| pic.slice_refs.get(usize::from(info.slice).wrapping_sub(1));
    match (refs(q), refs(p)) {
        (Some(q_refs), Some(p_refs)) => motion_strength(&q.mv, q_refs, &p.mv, p_refs),
        _ => 1,
    }
}

/// Filters all edges of the picture (clause 8.7.2.1).
pub(crate) fn deblock(pic: &mut PicState, slices: &[SliceFilter], params: FilterParams) {
    for vertical in [true, false] {
        luma_edges(pic, slices, vertical);
        for c in 1..=2 {
            chroma_edges(pic, slices, params, c, vertical);
        }
    }
}

fn luma_edges(pic: &mut PicState, slices: &[SliceFilter], vertical: bool) {
    let (width, height) = (pic.frame.width, pic.frame.height);
    for by in 0..pic.h4 {
        for bx in 0..pic.w4 {
            let (x, y) = (bx * 4, by * 4);
            let q = pic.info[by * pic.w4 + bx];
            let bs = if vertical { q.bs_v } else { q.bs_h };
            if bs == 0 || (vertical && x % 8 != 0) || (!vertical && y % 8 != 0) {
                continue;
            }
            let (px, py) = if vertical { (x - 1, y) } else { (x, y - 1) };
            let p = pic.info[(py >> 2) * pic.w4 + (px >> 2)];
            let slice = slices
                .get(usize::from(q.slice).wrapping_sub(1))
                .copied()
                .unwrap_or_default();
            let qp = (i32::from(p.qp_y) + i32::from(q.qp_y) + 1) >> 1;
            let beta = BETA_TABLE[(qp + slice.beta_offset).clamp(0, 51) as usize];
            let tc =
                TC_TABLE[(qp + 2 * (i32::from(bs) - 1) + slice.tc_offset).clamp(0, 53) as usize];
            let lines = if vertical {
                height.min(y + 4) - y
            } else {
                width.min(x + 4) - x
            };
            filter_luma_segment(
                &mut pic.frame.planes[0],
                width,
                (x, y),
                vertical,
                lines,
                (beta, tc),
                (!p.no_filter, !q.no_filter),
            );
        }
    }
}

/// One four-line luma edge segment (clauses 8.7.2.5.3, 8.7.2.5.6,
/// 8.7.2.5.7). `at(i, k)` addresses sample `k` (p3..p0 = -4..-1, q0..q3 =
/// 0..3) of line `i`.
fn filter_luma_segment(
    plane: &mut [u8],
    stride: usize,
    (x, y): (usize, usize),
    vertical: bool,
    lines: usize,
    (beta, tc): (i32, i32),
    (filter_p, filter_q): (bool, bool),
) {
    if tc == 0 && beta == 0 {
        return;
    }
    let index = |i: usize, k: isize| -> usize {
        if vertical {
            (y + i) * stride + (x as isize + k) as usize
        } else {
            ((y as isize + k) as usize) * stride + x + i
        }
    };
    let s = |plane: &[u8], i: usize, k: isize| i32::from(plane[index(i, k)]);
    if lines < 4 {
        return;
    }
    let dp0 = (s(plane, 0, -3) - 2 * s(plane, 0, -2) + s(plane, 0, -1)).abs();
    let dp3 = (s(plane, 3, -3) - 2 * s(plane, 3, -2) + s(plane, 3, -1)).abs();
    let dq0 = (s(plane, 0, 2) - 2 * s(plane, 0, 1) + s(plane, 0, 0)).abs();
    let dq3 = (s(plane, 3, 2) - 2 * s(plane, 3, 1) + s(plane, 3, 0)).abs();
    let (dpq0, dpq3) = (dp0 + dq0, dp3 + dq3);
    let (dp, dq) = (dp0 + dp3, dq0 + dq3);
    if dpq0 + dpq3 >= beta {
        return;
    }
    let strong_line = |i: usize, dpq: i32| {
        2 * dpq < (beta >> 2)
            && (s(plane, i, -4) - s(plane, i, -1)).abs() + (s(plane, i, 0) - s(plane, i, 3)).abs()
                < (beta >> 3)
            && (s(plane, i, -1) - s(plane, i, 0)).abs() < ((5 * tc + 1) >> 1)
    };
    let strong = strong_line(0, dpq0) && strong_line(3, dpq3);
    let side = (beta + (beta >> 1)) >> 3;
    let (de_p, de_q) = (dp < side, dq < side);
    for i in 0..4 {
        let p = [
            s(plane, i, -1),
            s(plane, i, -2),
            s(plane, i, -3),
            s(plane, i, -4),
        ];
        let q = [
            s(plane, i, 0),
            s(plane, i, 1),
            s(plane, i, 2),
            s(plane, i, 3),
        ];
        if strong {
            let clip = |v: i32, center: i32| v.clamp(center - 2 * tc, center + 2 * tc);
            if filter_p {
                let p0 = clip(
                    (p[2] + 2 * p[1] + 2 * p[0] + 2 * q[0] + q[1] + 4) >> 3,
                    p[0],
                );
                let p1 = clip((p[2] + p[1] + p[0] + q[0] + 2) >> 2, p[1]);
                let p2 = clip((2 * p[3] + 3 * p[2] + p[1] + p[0] + q[0] + 4) >> 3, p[2]);
                plane[index(i, -1)] = p0 as u8;
                plane[index(i, -2)] = p1 as u8;
                plane[index(i, -3)] = p2 as u8;
            }
            if filter_q {
                let q0 = clip(
                    (p[1] + 2 * p[0] + 2 * q[0] + 2 * q[1] + q[2] + 4) >> 3,
                    q[0],
                );
                let q1 = clip((p[0] + q[0] + q[1] + q[2] + 2) >> 2, q[1]);
                let q2 = clip((p[0] + q[0] + q[1] + 3 * q[2] + 2 * q[3] + 4) >> 3, q[2]);
                plane[index(i, 0)] = q0 as u8;
                plane[index(i, 1)] = q1 as u8;
                plane[index(i, 2)] = q2 as u8;
            }
            continue;
        }
        let mut delta = (9 * (q[0] - p[0]) - 3 * (q[1] - p[1]) + 8) >> 4;
        if delta.abs() >= tc * 10 {
            continue;
        }
        delta = delta.clamp(-tc, tc);
        if filter_p {
            plane[index(i, -1)] = (p[0] + delta).clamp(0, 255) as u8;
            if de_p {
                let dp =
                    ((((p[2] + p[0] + 1) >> 1) - p[1] + delta) >> 1).clamp(-(tc >> 1), tc >> 1);
                plane[index(i, -2)] = (p[1] + dp).clamp(0, 255) as u8;
            }
        }
        if filter_q {
            plane[index(i, 0)] = (q[0] - delta).clamp(0, 255) as u8;
            if de_q {
                let dq =
                    ((((q[2] + q[0] + 1) >> 1) - q[1] - delta) >> 1).clamp(-(tc >> 1), tc >> 1);
                plane[index(i, 1)] = (q[1] + dq).clamp(0, 255) as u8;
            }
        }
    }
}

/// Chroma edges (clause 8.7.2.5.5): only bS 2 edges on the 8x8 chroma
/// grid, four chroma lines per luma boundary-strength sample.
fn chroma_edges(
    pic: &mut PicState,
    slices: &[SliceFilter],
    params: FilterParams,
    c: usize,
    vertical: bool,
) {
    let (cw, ch) = (pic.frame.plane_width(c), pic.frame.plane_height(c));
    let offset = if c == 1 {
        params.cb_qp_offset
    } else {
        params.cr_qp_offset
    };
    let (gw, gh) = (cw.div_ceil(4), ch.div_ceil(4));
    for gy in 0..gh {
        for gx in 0..gw {
            // Chroma sample position of this 4-line segment and the luma
            // sample carrying its boundary strength.
            let (x, y) = (gx * 4, gy * 4);
            if (vertical && (x % 8 != 0 || x == 0)) || (!vertical && (y % 8 != 0 || y == 0)) {
                continue;
            }
            let (lx, ly) = (x * 2, y * 2);
            let q = pic.info[(ly >> 2) * pic.w4 + (lx >> 2)];
            let bs = if vertical { q.bs_v } else { q.bs_h };
            if bs != 2 {
                continue;
            }
            let (px, py) = if vertical { (lx - 1, ly) } else { (lx, ly - 1) };
            let p = pic.info[(py >> 2) * pic.w4 + (px >> 2)];
            let slice = slices
                .get(usize::from(q.slice).wrapping_sub(1))
                .copied()
                .unwrap_or_default();
            let qpi = ((i32::from(p.qp_y) + i32::from(q.qp_y) + 1) >> 1) + offset;
            let qpc = chroma_qp(qpi.clamp(0, 57));
            let tc = TC_TABLE[(qpc + 2 + slice.tc_offset).clamp(0, 53) as usize];
            if tc == 0 {
                continue;
            }
            let lines = if vertical {
                ch.min(y + 4) - y
            } else {
                cw.min(x + 4) - x
            };
            let plane = &mut pic.frame.planes[c];
            for i in 0..lines {
                let (ip0, iq0, ip1, iq1) = if vertical {
                    let row = (y + i) * cw;
                    (row + x - 1, row + x, row + x - 2, row + x + 1)
                } else {
                    let col = x + i;
                    (
                        (y - 1) * cw + col,
                        y * cw + col,
                        (y - 2) * cw + col,
                        (y + 1) * cw + col,
                    )
                };
                let (p0, q0) = (i32::from(plane[ip0]), i32::from(plane[iq0]));
                let (p1, q1) = (i32::from(plane[ip1]), i32::from(plane[iq1]));
                let delta = ((((q0 - p0) << 2) + p1 - q1 + 4) >> 3).clamp(-tc, tc);
                if !p.no_filter {
                    plane[ip0] = (p0 + delta).clamp(0, 255) as u8;
                }
                if !q.no_filter {
                    plane[iq0] = (q0 - delta).clamp(0, 255) as u8;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(pred: u8, mv0: [i16; 2], mv1: [i16; 2], refs: [i8; 2]) -> MvField {
        MvField {
            pred,
            mv: [mv0, mv1],
            ref_idx: refs,
        }
    }

    /// Clause 8.7.2.4 by hand. Two lists: L0 = {POC 8, POC 4}, L1 = {POC
    /// 16}.
    #[test]
    fn motion_strength_by_hand() {
        let refs = [vec![(8, false), (4, false)], vec![(16, false)]];
        let uni = |mv: [i16; 2], idx: i8| field(1, mv, [0, 0], [idx, -1]);
        // Same picture, |dx| = 3 -> 0; |dy| = 4 -> 1.
        assert_eq!(
            motion_strength(&uni([3, 0], 0), &refs, &uni([0, 0], 0), &refs),
            0
        );
        assert_eq!(
            motion_strength(&uni([0, 4], 0), &refs, &uni([0, 0], 0), &refs),
            1
        );
        // Different pictures -> 1.
        assert_eq!(
            motion_strength(&uni([0, 0], 0), &refs, &uni([0, 0], 1), &refs),
            1
        );
        // One vs two vectors -> 1.
        let bi = field(3, [0, 0], [0, 0], [0, 0]);
        assert_eq!(motion_strength(&bi, &refs, &uni([0, 0], 0), &refs), 1);
        // Same two pictures, crossed lists: p (L0 = 8, L1 = 16) vs q with
        // the same references in the same lists, vectors within 3 -> 0.
        let q = field(3, [1, 1], [-2, 0], [0, 0]);
        let p = field(3, [0, 0], [0, 0], [0, 0]);
        assert_eq!(motion_strength(&q, &refs, &p, &refs), 0);
        let q_far = field(3, [1, 1], [-4, 0], [0, 0]);
        assert_eq!(motion_strength(&q_far, &refs, &p, &refs), 1);
    }

    /// Table 8-12 spot checks: tC' at Q 18 is 1, at 53 is 24; beta' at Q
    /// 16 is 6 and at 51 is 64.
    #[test]
    fn tables_spot_check() {
        assert_eq!((TC_TABLE[17], TC_TABLE[18], TC_TABLE[53]), (0, 1, 24));
        assert_eq!(TC_TABLE[47], 13);
        assert_eq!((BETA_TABLE[15], BETA_TABLE[16], BETA_TABLE[51]), (0, 6, 64));
        assert_eq!(BETA_TABLE[29], 20);
    }

    /// A flat step edge (p = 60, q = 70) with beta 38, tc 4: d = 0 < beta,
    /// but the strong filter needs |p0 - q0| = 10 < (5 * tc + 1) / 2 = 10,
    /// which fails, so the weak filter runs: delta = (9 * 10 - 3 * 10 + 8)
    /// / 16 = 4 (within tc): p0 = 64, q0 = 66. dp = 0 < (38 + 19) / 8 = 7:
    /// dp = ((60 + 60 + 1) / 2 - 60 + 4) / 2 = 2 -> p1 = 62; dq =
    /// ((70 + 70 + 1) / 2 - 70 - 4) / 2 = -2 -> q1 = 68 (floor division).
    #[test]
    fn weak_luma_filter_by_hand() {
        let stride = 8;
        let mut plane = vec![0u8; 8 * 4];
        for row in 0..4 {
            for col in 0..8 {
                plane[row * stride + col] = if col < 4 { 60 } else { 70 };
            }
        }
        filter_luma_segment(&mut plane, stride, (4, 0), true, 4, (38, 4), (true, true));
        assert_eq!(&plane[..8], &[60, 60, 62, 64, 66, 68, 70, 70]);
        // The q side is protected (PCM / bypass): only p changes.
        let mut plane2 = vec![0u8; 8 * 4];
        for row in 0..4 {
            for col in 0..8 {
                plane2[row * stride + col] = if col < 4 { 60 } else { 70 };
            }
        }
        filter_luma_segment(&mut plane2, stride, (4, 0), true, 4, (38, 4), (true, false));
        assert_eq!(&plane2[..8], &[60, 60, 62, 64, 70, 70, 70, 70]);
    }
}
