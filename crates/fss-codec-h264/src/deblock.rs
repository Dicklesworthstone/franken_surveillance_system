//! In-loop deblocking filter (clause 8.7) for frame pictures, run over the
//! whole picture in macroblock raster order after all slices are decoded,
//! which is exactly the order the specification defines.

use crate::macroblock::{MbInfo, SliceInfo};
use crate::picture::Frame;
use crate::transform::chroma_qp;

/// alpha' (Table 8-16), indexed by indexA.
const ALPHA: [u8; 52] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 5, 6, 7, 8, 9, 10, 12, 13, 15, 17, 20,
    22, 25, 28, 32, 36, 40, 45, 50, 56, 63, 71, 80, 90, 101, 113, 127, 144, 162, 182, 203, 226,
    255, 255,
];

/// beta' (Table 8-16), indexed by indexB.
const BETA: [u8; 52] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 6, 6, 7, 7, 8, 8,
    9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16, 17, 17, 18, 18,
];

/// tC0' (Table 8-17) for bS = 1, 2, 3, indexed by indexA.
const TC0: [[u8; 3]; 52] = [
    [0, 0, 0],
    [0, 0, 0],
    [0, 0, 0],
    [0, 0, 0],
    [0, 0, 0],
    [0, 0, 0],
    [0, 0, 0],
    [0, 0, 0],
    [0, 0, 0],
    [0, 0, 0],
    [0, 0, 0],
    [0, 0, 0],
    [0, 0, 0],
    [0, 0, 0],
    [0, 0, 0],
    [0, 0, 0],
    [0, 0, 0],
    [0, 0, 1],
    [0, 0, 1],
    [0, 0, 1],
    [0, 0, 1],
    [0, 1, 1],
    [0, 1, 1],
    [1, 1, 1],
    [1, 1, 1],
    [1, 1, 1],
    [1, 1, 1],
    [1, 1, 2],
    [1, 1, 2],
    [1, 1, 2],
    [1, 1, 2],
    [1, 2, 3],
    [1, 2, 3],
    [2, 2, 3],
    [2, 2, 4],
    [2, 3, 4],
    [2, 3, 4],
    [3, 3, 5],
    [3, 4, 6],
    [3, 4, 6],
    [4, 5, 7],
    [4, 5, 8],
    [4, 6, 9],
    [5, 7, 10],
    [6, 8, 11],
    [6, 8, 13],
    [7, 10, 14],
    [8, 11, 16],
    [9, 12, 18],
    [10, 13, 20],
    [11, 15, 23],
    [13, 17, 25],
];

/// Boundary strength between two 4x4 luma blocks (clause 8.7.2.1, frame
/// macroblocks, no MBAFF, no SP/SI).
fn boundary_strength(p: &MbInfo, p_blk: usize, q: &MbInfo, q_blk: usize, mb_edge: bool) -> u8 {
    if p.is_intra() || q.is_intra() {
        return if mb_edge { 4 } else { 3 };
    }
    if p.nz[p_blk] != 0 || q.nz[q_blk] != 0 {
        return 2;
    }
    // Different reference pictures (by identity, not index) or a motion
    // vector component difference of at least four quarter samples.
    if p.ref_pic[p_blk] != q.ref_pic[q_blk] {
        return 1;
    }
    let (mp, mq) = (p.mv[p_blk], q.mv[q_blk]);
    if (mp[0] - mq[0]).abs() >= 4 || (mp[1] - mq[1]).abs() >= 4 {
        return 1;
    }
    0
}

/// Edge filter thresholds for one edge.
#[derive(Clone, Copy)]
struct EdgeParams {
    alpha: i32,
    beta: i32,
    index_a: usize,
}

fn edge_params(qp_p: i32, qp_q: i32, slice: &SliceInfo) -> EdgeParams {
    let qp_av = (qp_p + qp_q + 1) >> 1;
    let index_a = (qp_av + slice.filter_offset_a).clamp(0, 51);
    let index_b = (qp_av + slice.filter_offset_b).clamp(0, 51);
    let index_a = usize::try_from(index_a).unwrap_or(0);
    let index_b = usize::try_from(index_b).unwrap_or(0);
    EdgeParams {
        alpha: i32::from(ALPHA[index_a]),
        beta: i32::from(BETA[index_b]),
        index_a,
    }
}

/// Filters one line of samples across an edge. `get(i)` / `set(i, v)`
/// address p3..p0 as i = -4..-1 and q0..q3 as 0..3.
fn filter_line(
    samples: &mut [u8],
    base: usize,
    step: isize,
    bs: u8,
    params: EdgeParams,
    chroma: bool,
) {
    let index = |i: isize| -> Option<usize> { base.checked_add_signed(i * step) };
    let get = |s: &[u8], i: isize| -> i32 {
        index(i).and_then(|k| s.get(k)).map_or(0, |&v| i32::from(v))
    };
    let (p0, p1, q0, q1) = (
        get(samples, -1),
        get(samples, -2),
        get(samples, 0),
        get(samples, 1),
    );
    if bs == 0
        || (p0 - q0).abs() >= params.alpha
        || (p1 - p0).abs() >= params.beta
        || (q1 - q0).abs() >= params.beta
    {
        return;
    }
    let put = |s: &mut [u8], i: isize, v: i32| {
        if let Some(sample) = index(i).and_then(|k| s.get_mut(k)) {
            *sample = u8::try_from(v.clamp(0, 255)).unwrap_or(u8::MAX);
        }
    };
    let (p2, q2) = if chroma {
        (0, 0)
    } else {
        (get(samples, -3), get(samples, 2))
    };
    let ap = (p2 - p0).abs();
    let aq = (q2 - q0).abs();
    if bs < 4 {
        let tc0 = i32::from(TC0[params.index_a][usize::from(bs - 1)]);
        let tc = if chroma {
            tc0 + 1
        } else {
            tc0 + i32::from(ap < params.beta) + i32::from(aq < params.beta)
        };
        let delta = ((((q0 - p0) << 2) + (p1 - q1) + 4) >> 3).clamp(-tc, tc);
        put(samples, -1, p0 + delta);
        put(samples, 0, q0 - delta);
        if !chroma {
            if ap < params.beta {
                put(
                    samples,
                    -2,
                    p1 + ((p2 + ((p0 + q0 + 1) >> 1) - (p1 << 1)) >> 1).clamp(-tc0, tc0),
                );
            }
            if aq < params.beta {
                put(
                    samples,
                    1,
                    q1 + ((q2 + ((p0 + q0 + 1) >> 1) - (q1 << 1)) >> 1).clamp(-tc0, tc0),
                );
            }
        }
        return;
    }
    // bS == 4.
    if chroma {
        put(samples, -1, (2 * p1 + p0 + q1 + 2) >> 2);
        put(samples, 0, (2 * q1 + q0 + p1 + 2) >> 2);
        return;
    }
    let strong = (p0 - q0).abs() < ((params.alpha >> 2) + 2);
    if ap < params.beta && strong {
        let p3 = get(samples, -4);
        put(samples, -1, (p2 + 2 * p1 + 2 * p0 + 2 * q0 + q1 + 4) >> 3);
        put(samples, -2, (p2 + p1 + p0 + q0 + 2) >> 2);
        put(samples, -3, (2 * p3 + 3 * p2 + p1 + p0 + q0 + 4) >> 3);
    } else {
        put(samples, -1, (2 * p1 + p0 + q1 + 2) >> 2);
    }
    if aq < params.beta && strong {
        let q3 = get(samples, 3);
        put(samples, 0, (p1 + 2 * p0 + 2 * q0 + 2 * q1 + q2 + 4) >> 3);
        put(samples, 1, (p0 + q0 + q1 + q2 + 2) >> 2);
        put(samples, 2, (2 * q3 + 3 * q2 + q1 + q0 + p0 + 4) >> 3);
    } else {
        put(samples, 0, (2 * q1 + q0 + p1 + 2) >> 2);
    }
}

/// Deblocks a fully decoded frame in place.
pub(crate) fn deblock_frame(
    frame: &mut Frame,
    infos: &[MbInfo],
    slices: &[SliceInfo],
    width_mbs: usize,
) {
    if width_mbs == 0 {
        return;
    }
    let height_mbs = infos.len() / width_mbs;
    for mby in 0..height_mbs {
        for mbx in 0..width_mbs {
            deblock_mb(frame, infos, slices, width_mbs, mbx, mby);
        }
    }
}

fn deblock_mb(
    frame: &mut Frame,
    infos: &[MbInfo],
    slices: &[SliceInfo],
    width_mbs: usize,
    mbx: usize,
    mby: usize,
) {
    let addr = mby * width_mbs + mbx;
    let Some(cur) = infos.get(addr) else { return };
    let Some(slice) = usize::from(cur.slice)
        .checked_sub(1)
        .and_then(|s| slices.get(s))
    else {
        return;
    };
    if slice.disable_deblocking_filter_idc == 1 {
        return;
    }
    let left = (mbx > 0)
        .then(|| &infos[addr - 1])
        .filter(|mb| slice.disable_deblocking_filter_idc != 2 || mb.slice == cur.slice);
    let top = (mby > 0)
        .then(|| &infos[addr - width_mbs])
        .filter(|mb| slice.disable_deblocking_filter_idc != 2 || mb.slice == cur.slice);

    let luma_stride = frame.width;
    let chroma_stride = frame.chroma_width();
    let chroma_offsets = [slice.chroma_qp_offset[0], slice.chroma_qp_offset[1]];

    // Vertical edges (filter across x), then horizontal edges.
    for vertical in [true, false] {
        let neighbour = if vertical { left } else { top };
        for edge in 0..4usize {
            let p_mb = if edge == 0 {
                match neighbour {
                    Some(mb) => mb,
                    None => continue,
                }
            } else {
                cur
            };
            let mut bs = [0u8; 4];
            for (k, value) in bs.iter_mut().enumerate() {
                let (q_blk, p_blk) = if vertical {
                    (
                        k * 4 + edge,
                        if edge == 0 {
                            k * 4 + 3
                        } else {
                            k * 4 + edge - 1
                        },
                    )
                } else {
                    (
                        edge * 4 + k,
                        if edge == 0 {
                            12 + k
                        } else {
                            (edge - 1) * 4 + k
                        },
                    )
                };
                *value = boundary_strength(p_mb, p_blk, cur, q_blk, edge == 0);
            }
            if bs == [0; 4] {
                continue;
            }
            // Luma.
            let params = edge_params(i32::from(p_mb.qp), i32::from(cur.qp), slice);
            for line in 0..16usize {
                let (x, y) = if vertical {
                    (mbx * 16 + edge * 4, mby * 16 + line)
                } else {
                    (mbx * 16 + line, mby * 16 + edge * 4)
                };
                let step: isize = if vertical {
                    1
                } else {
                    luma_stride.try_into().unwrap_or(0)
                };
                filter_line(
                    &mut frame.y,
                    y * luma_stride + x,
                    step,
                    bs[line / 4],
                    params,
                    false,
                );
            }
            // Chroma: only luma edges 0 and 2 map to chroma 4x4 edges.
            if !edge.is_multiple_of(2) {
                continue;
            }
            for (component, offset) in chroma_offsets.iter().enumerate() {
                let qp_p = chroma_qp(i32::from(p_mb.qp), *offset);
                let qp_q = chroma_qp(i32::from(cur.qp), *offset);
                let params = edge_params(qp_p, qp_q, slice);
                let plane = if component == 0 {
                    &mut frame.cb
                } else {
                    &mut frame.cr
                };
                for line in 0..8usize {
                    let (x, y) = if vertical {
                        (mbx * 8 + edge * 2, mby * 8 + line)
                    } else {
                        (mbx * 8 + line, mby * 8 + edge * 2)
                    };
                    let step: isize = if vertical {
                        1
                    } else {
                        chroma_stride.try_into().unwrap_or(0)
                    };
                    filter_line(
                        plane,
                        y * chroma_stride + x,
                        step,
                        bs[line / 2],
                        params,
                        true,
                    );
                }
            }
        }
    }
}
