//! Inter prediction (ITU-T H.265 clause 8.5.3): merge candidates
//! (spatial, temporal, combined bi-predictive, zero), AMVP with spatial
//! scaling, temporal motion vector prediction from the collocated picture,
//! and the fractional-sample interpolation (8-tap luma, 4-tap chroma) with
//! default and explicit weighted sample prediction.

use std::sync::Arc;

use crate::picture::Frame;
use crate::slice::{PredWeights, SliceType};

/// Motion of one prediction block. Unused lists hold `ref_idx == -1` and a
/// zero vector, so whole-field equality is the standard's "same motion
/// vectors and reference indices" comparison.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MvField {
    /// Bit 0: `predFlagL0`; bit 1: `predFlagL1`.
    pub pred: u8,
    /// `mvL0`, `mvL1` in quarter luma samples.
    pub mv: [[i16; 2]; 2],
    /// `refIdxL0`, `refIdxL1` (-1 when unused).
    pub ref_idx: [i8; 2],
}

impl MvField {
    pub const fn uses(&self, list: usize) -> bool {
        self.pred & (1 << list) != 0
    }

    /// Normalises the unused list(s).
    fn normalized(mut self) -> Self {
        for list in 0..2 {
            if !self.uses(list) {
                self.mv[list] = [0, 0];
                self.ref_idx[list] = -1;
            }
        }
        self
    }
}

/// Motion stored with a decoded picture for temporal prediction: the
/// reference picture order counts and long-term flags travel with the
/// vectors, so the collocated picture's slice lists are not needed.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ColMv {
    pub pred: u8,
    pub mv: [[i16; 2]; 2],
    pub ref_poc: [i32; 2],
    pub ref_lt: [bool; 2],
}

/// One reference picture list of the current slice.
#[derive(Clone, Debug, Default)]
pub(crate) struct RefList {
    pub pocs: Vec<i32>,
    pub long_term: Vec<bool>,
    pub frames: Vec<Arc<Frame>>,
}

/// The collocated picture: its order count and per-4x4 motion.
#[derive(Clone, Debug)]
pub(crate) struct ColPic {
    pub poc: i32,
    pub motion: Arc<Vec<ColMv>>,
}

/// Everything motion vector derivation reads besides the neighbours.
pub(crate) struct MvContext<'a> {
    pub poc: i32,
    pub slice_type: SliceType,
    pub refs: &'a [RefList; 2],
    pub col: Option<&'a ColPic>,
    pub temporal_mvp: bool,
    pub collocated_from_l0: bool,
    pub max_num_merge_cand: u32,
    pub num_ref_idx: [u32; 2],
    pub log2_parallel_merge_level: u32,
    pub width: usize,
    pub height: usize,
    pub ctb_log2: u32,
    /// Width of the 4x4 motion grid.
    pub w4: usize,
}

/// `PartMode` of an inter coding unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PartMode {
    Part2Nx2N,
    Part2NxN,
    PartNx2N,
    PartNxN,
    Part2NxnU,
    Part2NxnD,
    PartnLx2N,
    PartnRx2N,
}

impl PartMode {
    /// Prediction blocks `(x, y, w, h)` relative to the coding block.
    pub fn blocks(self, size: usize) -> Vec<(usize, usize, usize, usize)> {
        let (h, q) = (size / 2, size / 4);
        match self {
            Self::Part2Nx2N => vec![(0, 0, size, size)],
            Self::Part2NxN => vec![(0, 0, size, h), (0, h, size, h)],
            Self::PartNx2N => vec![(0, 0, h, size), (h, 0, h, size)],
            Self::PartNxN => vec![(0, 0, h, h), (h, 0, h, h), (0, h, h, h), (h, h, h, h)],
            Self::Part2NxnU => vec![(0, 0, size, q), (0, q, size, size - q)],
            Self::Part2NxnD => vec![(0, 0, size, size - q), (0, size - q, size, q)],
            Self::PartnLx2N => vec![(0, 0, q, size), (q, 0, size - q, size)],
            Self::PartnRx2N => vec![(0, 0, size - q, size), (size - q, 0, q, size)],
        }
    }

    const fn vertical_split(self) -> bool {
        matches!(self, Self::PartNx2N | Self::PartnLx2N | Self::PartnRx2N)
    }

    const fn horizontal_split(self) -> bool {
        matches!(self, Self::Part2NxN | Self::Part2NxnU | Self::Part2NxnD)
    }
}

/// A prediction block being derived.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PbGeometry {
    pub x: usize,
    pub y: usize,
    pub w: usize,
    pub h: usize,
    pub part_idx: usize,
    pub cu_x: usize,
    pub cu_y: usize,
    pub cu_log2: u32,
    pub part_mode: PartMode,
}

/// Distance-based motion vector scaling (equations 8-179..8-183).
pub(crate) fn scale_mv(mv: [i16; 2], td: i32, tb: i32) -> [i16; 2] {
    let td = td.clamp(-128, 127);
    let tb = tb.clamp(-128, 127);
    let tx = (16_384 + (td / 2).abs()) / td;
    let factor = ((tb * tx + 32) >> 6).clamp(-4096, 4095);
    mv.map(|component| {
        let product = factor * i32::from(component);
        let magnitude = (product.abs() + 127) >> 8;
        (product.signum() * magnitude).clamp(-32768, 32767) as i16
    })
}

impl MvContext<'_> {
    fn same_mer(&self, xn: isize, yn: isize, xp: usize, yp: usize) -> bool {
        let level = self.log2_parallel_merge_level;
        (xn >> level) as usize == xp >> level && (yn >> level) as usize == yp >> level
    }

    /// Temporal motion vector prediction (clauses 8.5.3.2.8, 8.5.3.2.9).
    fn temporal(&self, pb: &PbGeometry, ref_idx: usize, list: usize) -> Option<[i16; 2]> {
        let col = self.col?;
        let (x, y, w, h) = (pb.x, pb.y, pb.w, pb.h);
        let (xb, yb) = (x + w, y + h);
        if y >> self.ctb_log2 == yb >> self.ctb_log2
            && yb < self.height
            && xb < self.width
            && let Some(mv) = self.col_mv(col, (xb >> 4) << 4, (yb >> 4) << 4, ref_idx, list)
        {
            return Some(mv);
        }
        let (xc, yc) = (((x + w / 2) >> 4) << 4, ((y + h / 2) >> 4) << 4);
        self.col_mv(col, xc, yc, ref_idx, list)
    }

    fn col_mv(
        &self,
        col: &ColPic,
        x: usize,
        y: usize,
        ref_idx: usize,
        list: usize,
    ) -> Option<[i16; 2]> {
        let cm = col.motion.get((y >> 2) * self.w4 + (x >> 2))?;
        let list_col = match cm.pred {
            0 => return None,
            1 => 0,
            2 => 1,
            _ => {
                let backward = self
                    .refs
                    .iter()
                    .any(|refs| refs.pocs.iter().any(|&poc| poc > self.poc));
                if backward {
                    usize::from(self.collocated_from_l0)
                } else {
                    list
                }
            }
        };
        let cur_lt = *self.refs[list].long_term.get(ref_idx)?;
        if cur_lt != cm.ref_lt[list_col] {
            return None;
        }
        let col_diff = col.poc - cm.ref_poc[list_col];
        let cur_diff = self.poc - *self.refs[list].pocs.get(ref_idx)?;
        let mv = cm.mv[list_col];
        Some(if cur_lt || col_diff == cur_diff || col_diff == 0 {
            mv
        } else {
            scale_mv(mv, col_diff, cur_diff)
        })
    }

    /// Merge mode (clause 8.5.3.2.2): candidate `merge_idx` of the list.
    pub fn merge(
        &self,
        pb: &PbGeometry,
        merge_idx: usize,
        neighbour: impl Fn(isize, isize) -> Option<MvField>,
    ) -> MvField {
        let single = self.log2_parallel_merge_level > 2 && pb.cu_log2 == 3;
        let geometry = if single {
            PbGeometry {
                x: pb.cu_x,
                y: pb.cu_y,
                w: 8,
                h: 8,
                part_idx: 0,
                ..*pb
            }
        } else {
            *pb
        };
        let (xp, yp) = (geometry.x, geometry.y);
        let (xi, yi, w, h) = (
            xp as isize,
            yp as isize,
            geometry.w as isize,
            geometry.h as isize,
        );
        let second = !single && geometry.part_idx == 1;
        let get = |xn: isize, yn: isize, excluded: bool| {
            if excluded || self.same_mer(xn, yn, xp, yp) {
                None
            } else {
                neighbour(xn, yn)
            }
        };
        let mut list: Vec<MvField> = Vec::with_capacity(5);
        let max = self.max_num_merge_cand as usize;
        let a1 = get(xi - 1, yi + h - 1, second && pb.part_mode.vertical_split());
        if let Some(a1) = a1 {
            list.push(a1);
        }
        let b1 = get(
            xi + w - 1,
            yi - 1,
            second && pb.part_mode.horizontal_split(),
        );
        if let Some(b1) = b1
            && a1 != Some(b1)
        {
            list.push(b1);
        }
        if let Some(b0) = get(xi + w, yi - 1, false)
            && b1 != Some(b0)
        {
            list.push(b0);
        }
        if let Some(a0) = get(xi - 1, yi + h, false)
            && a1 != Some(a0)
        {
            list.push(a0);
        }
        if list.len() != 4
            && let Some(b2) = get(xi - 1, yi - 1, false)
            && a1 != Some(b2)
            && b1 != Some(b2)
        {
            list.push(b2);
        }
        if self.temporal_mvp && list.len() < max {
            let l0 = self.temporal(&geometry, 0, 0);
            let l1 = if self.slice_type == SliceType::B {
                self.temporal(&geometry, 0, 1)
            } else {
                None
            };
            if l0.is_some() || l1.is_some() {
                list.push(
                    MvField {
                        pred: u8::from(l0.is_some()) | (u8::from(l1.is_some()) << 1),
                        mv: [l0.unwrap_or([0, 0]), l1.unwrap_or([0, 0])],
                        ref_idx: [0, 0],
                    }
                    .normalized(),
                );
            }
        }
        let original = list.len();
        if self.slice_type == SliceType::B && original > 1 && original < max {
            const ORDER: [(usize, usize); 12] = [
                (0, 1),
                (1, 0),
                (0, 2),
                (2, 0),
                (1, 2),
                (2, 1),
                (0, 3),
                (3, 0),
                (1, 3),
                (3, 1),
                (2, 3),
                (3, 2),
            ];
            for &(i0, i1) in ORDER.iter().take(original * (original - 1)) {
                if list.len() >= max {
                    break;
                }
                let (c0, c1) = (list[i0], list[i1]);
                if !c0.uses(0) || !c1.uses(1) {
                    continue;
                }
                let poc0 = self.refs[0].pocs.get(c0.ref_idx[0] as usize);
                let poc1 = self.refs[1].pocs.get(c1.ref_idx[1] as usize);
                if poc0 != poc1 || c0.mv[0] != c1.mv[1] {
                    list.push(MvField {
                        pred: 3,
                        mv: [c0.mv[0], c1.mv[1]],
                        ref_idx: [c0.ref_idx[0], c1.ref_idx[1]],
                    });
                }
            }
        }
        let num_ref = if self.slice_type == SliceType::P {
            self.num_ref_idx[0]
        } else {
            self.num_ref_idx[0].min(self.num_ref_idx[1])
        } as usize;
        let mut zero_idx = 0usize;
        while list.len() < max {
            let idx = if zero_idx < num_ref {
                zero_idx as i8
            } else {
                0
            };
            let pred = if self.slice_type == SliceType::B {
                3
            } else {
                1
            };
            list.push(
                MvField {
                    pred,
                    mv: [[0, 0]; 2],
                    ref_idx: [idx, idx],
                }
                .normalized(),
            );
            zero_idx += 1;
        }
        let mut chosen = list.get(merge_idx).copied().unwrap_or_default();
        // 8x4 / 4x8 prediction blocks are never bi-predicted (8.5.3.2.2).
        if chosen.pred == 3 && pb.w + pb.h == 12 {
            chosen.pred = 1;
            chosen = chosen.normalized();
        }
        chosen
    }

    /// Luma motion vector predictor (clause 8.5.3.2.6) for list `x` and
    /// reference `ref_idx`, candidate `mvp_flag`.
    pub fn amvp(
        &self,
        pb: &PbGeometry,
        list: usize,
        ref_idx: usize,
        mvp_flag: usize,
        neighbour: impl Fn(isize, isize) -> Option<MvField>,
    ) -> [i16; 2] {
        let (xi, yi, w, h) = (pb.x as isize, pb.y as isize, pb.w as isize, pb.h as isize);
        let other = 1 - list;
        let target_poc = self.refs[list]
            .pocs
            .get(ref_idx)
            .copied()
            .unwrap_or(i32::MIN);
        let target_lt = self.refs[list]
            .long_term
            .get(ref_idx)
            .copied()
            .unwrap_or(false);
        let poc_of =
            |l: usize, field: &MvField| self.refs[l].pocs.get(field.ref_idx[l] as usize).copied();
        let lt_of = |l: usize, field: &MvField| {
            self.refs[l]
                .long_term
                .get(field.ref_idx[l] as usize)
                .copied()
        };
        // Same reference picture, no scaling.
        let unscaled = |field: &MvField| {
            [list, other]
                .into_iter()
                .find(|&l| field.uses(l) && poc_of(l, field) == Some(target_poc))
                .map(|l| field.mv[l])
        };
        // Same long-term-ness, scaled when both are short-term.
        let scaled = |field: &MvField| {
            [list, other]
                .into_iter()
                .find(|&l| field.uses(l) && lt_of(l, field) == Some(target_lt))
                .map(|l| {
                    let mv = field.mv[l];
                    let ref_poc = poc_of(l, field).unwrap_or(target_poc);
                    if target_lt || ref_poc == target_poc {
                        mv
                    } else {
                        let td = match self.poc - ref_poc {
                            0 => 1,
                            d => d,
                        };
                        scale_mv(mv, td, self.poc - target_poc)
                    }
                })
        };
        let a = [neighbour(xi - 1, yi + h), neighbour(xi - 1, yi + h - 1)];
        let is_scaled = a.iter().any(Option::is_some);
        let mut mv_a = a.iter().flatten().find_map(unscaled);
        if mv_a.is_none() {
            mv_a = a.iter().flatten().find_map(scaled);
        }
        let b = [
            neighbour(xi + w, yi - 1),
            neighbour(xi + w - 1, yi - 1),
            neighbour(xi - 1, yi - 1),
        ];
        let mut mv_b = b.iter().flatten().find_map(unscaled);
        if !is_scaled {
            if mv_b.is_some() {
                mv_a = mv_b;
            }
            mv_b = b.iter().flatten().find_map(scaled);
        }
        let mut candidates: Vec<[i16; 2]> = Vec::with_capacity(3);
        if let Some(mv) = mv_a {
            candidates.push(mv);
        }
        if let Some(mv) = mv_b
            && mv_a != Some(mv)
        {
            candidates.push(mv);
        }
        if candidates.len() < 2
            && self.temporal_mvp
            && let Some(mv) = self.temporal(pb, ref_idx, list)
        {
            candidates.push(mv);
        }
        candidates.resize(2, [0, 0]);
        candidates[mvp_flag.min(1)]
    }
}

/// Luma interpolation filter coefficients `fL[xFrac]` (Table 8-11).
const LUMA_FILTER: [[i32; 8]; 4] = [
    [0, 0, 0, 64, 0, 0, 0, 0],
    [-1, 4, -10, 58, 17, -5, 1, 0],
    [-1, 4, -11, 40, 40, -11, 4, -1],
    [0, 1, -5, 17, 58, -10, 4, -1],
];

/// Chroma interpolation filter coefficients `fC[xFrac]` (Table 8-12).
const CHROMA_FILTER: [[i32; 4]; 8] = [
    [0, 64, 0, 0],
    [-2, 58, 10, -2],
    [-4, 54, 16, -2],
    [-6, 46, 28, -4],
    [-4, 36, 36, -4],
    [-4, 28, 46, -6],
    [-2, 16, 54, -4],
    [-2, 10, 58, -2],
];

/// Fractional sample interpolation of one block of plane `c` (clauses
/// 8.5.3.3.3.1 and 8.5.3.3.3.2) into 14-bit intermediate samples.
fn interpolate(frame: &Frame, c: usize, block: Block, mv: [i16; 2], out: &mut Vec<i32>) {
    let Block { x, y, w, h } = block;
    let plane = &frame.planes[c];
    let (pw, ph) = (
        frame.plane_width(c) as isize,
        frame.plane_height(c) as isize,
    );
    let (frac_bits, taps): (u32, usize) = if c == 0 { (2, 8) } else { (3, 4) };
    let (mvx, mvy) = (i32::from(mv[0]), i32::from(mv[1]));
    let mask = (1 << frac_bits) - 1;
    let (fx, fy) = ((mvx & mask) as usize, (mvy & mask) as usize);
    let x0 = x as isize + (mvx >> frac_bits) as isize;
    let y0 = y as isize + (mvy >> frac_bits) as isize;
    let half = (taps / 2 - 1) as isize;
    let coeff = |frac: usize, i: usize| -> i32 {
        if c == 0 {
            LUMA_FILTER[frac][i]
        } else {
            CHROMA_FILTER[frac][i]
        }
    };
    let sample = |xs: isize, ys: isize| -> i32 {
        let xs = xs.clamp(0, pw - 1) as usize;
        let ys = ys.clamp(0, ph - 1) as usize;
        i32::from(plane[ys * pw as usize + xs])
    };
    out.clear();
    out.resize(w * h, 0);
    if fx == 0 && fy == 0 {
        for j in 0..h {
            for i in 0..w {
                out[j * w + i] = sample(x0 + i as isize, y0 + j as isize) << 6;
            }
        }
        return;
    }
    if fy == 0 {
        for j in 0..h {
            for i in 0..w {
                let mut sum = 0;
                for t in 0..taps {
                    sum +=
                        coeff(fx, t) * sample(x0 + i as isize + t as isize - half, y0 + j as isize);
                }
                out[j * w + i] = sum;
            }
        }
        return;
    }
    if fx == 0 {
        for j in 0..h {
            for i in 0..w {
                let mut sum = 0;
                for t in 0..taps {
                    sum +=
                        coeff(fy, t) * sample(x0 + i as isize, y0 + j as isize + t as isize - half);
                }
                out[j * w + i] = sum;
            }
        }
        return;
    }
    let rows = h + taps - 1;
    let mut temp = vec![0i32; rows * w];
    for r in 0..rows {
        for i in 0..w {
            let mut sum = 0;
            for t in 0..taps {
                sum += coeff(fx, t)
                    * sample(x0 + i as isize + t as isize - half, y0 + r as isize - half);
            }
            temp[r * w + i] = sum;
        }
    }
    for j in 0..h {
        for i in 0..w {
            let mut sum = 0;
            for t in 0..taps {
                sum += coeff(fy, t) * temp[(j + t) * w + i];
            }
            out[j * w + i] = sum >> 6;
        }
    }
}

/// Explicit weighting parameters of one prediction block.
struct Weights {
    log2_denom: u32,
    weight: [i32; 2],
    offset: [i32; 2],
}

/// A luma-sample rectangle.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Block {
    pub x: usize,
    pub y: usize,
    pub w: usize,
    pub h: usize,
}

/// Inter prediction of one prediction block into `dst` (all three
/// planes): interpolation from the reference pictures, then default or
/// explicit weighted sample prediction (clause 8.5.3.3.4). `None` when a
/// reference index names no picture.
pub(crate) fn predict(
    dst: &mut Frame,
    refs: &[RefList; 2],
    field: &MvField,
    block: Block,
    weights: Option<&PredWeights>,
) -> Option<()> {
    let Block { x, y, w, h } = block;
    let mut preds: [Vec<i32>; 2] = [Vec::new(), Vec::new()];
    for c in 0..3 {
        let (cx, cy, cw, ch) = if c == 0 {
            (x, y, w, h)
        } else {
            (x / 2, y / 2, w / 2, h / 2)
        };
        let mut used = [false; 2];
        for list in 0..2 {
            if !field.uses(list) {
                continue;
            }
            let frame = refs[list].frames.get(field.ref_idx[list] as usize)?;
            let rect = Block {
                x: cx,
                y: cy,
                w: cw,
                h: ch,
            };
            interpolate(frame, c, rect, field.mv[list], &mut preds[list]);
            used[list] = true;
        }
        let explicit = weights.map(|table| {
            let mut out = Weights {
                log2_denom: if c == 0 {
                    table.luma_log2_denom
                } else {
                    table.chroma_log2_denom
                },
                weight: [0; 2],
                offset: [0; 2],
            };
            for list in 0..2 {
                if !used[list] {
                    continue;
                }
                let idx = field.ref_idx[list] as usize;
                let (wt, off) = if c == 0 {
                    table.luma[list]
                        .get(idx)
                        .copied()
                        .unwrap_or((1 << out.log2_denom, 0))
                } else {
                    table.chroma[list]
                        .get(idx)
                        .map_or((1 << out.log2_denom, 0), |pair| pair[c - 1])
                };
                out.weight[list] = wt;
                out.offset[list] = off;
            }
            out
        });
        let stride = dst.plane_width(c);
        let plane = &mut dst.planes[c];
        for j in 0..ch {
            for i in 0..cw {
                let k = j * cw + i;
                let value = match (used, &explicit) {
                    ([true, true], None) => (preds[0][k] + preds[1][k] + 64) >> 7,
                    ([true, true], Some(wp)) => {
                        let log2wd = wp.log2_denom + 6;
                        (preds[0][k] * wp.weight[0]
                            + preds[1][k] * wp.weight[1]
                            + ((wp.offset[0] + wp.offset[1] + 1) << log2wd))
                            >> (log2wd + 1)
                    }
                    ([a, _], None) => (preds[usize::from(!a)][k] + 32) >> 6,
                    ([a, _], Some(wp)) => {
                        let l = usize::from(!a);
                        let log2wd = wp.log2_denom + 6;
                        ((preds[l][k] * wp.weight[l] + (1 << (log2wd - 1))) >> log2wd)
                            + wp.offset[l]
                    }
                };
                plane[(cy + j) * stride + cx + i] = value.clamp(0, 255) as u8;
            }
        }
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Equations 8-179..8-183 by hand: td = 2, tb = 1: tx = (16384 + 1) /
    /// 2 = 8192, factor = (8192 + 32) >> 6 = 128, mv 10 -> (1280 + 127) >> 8
    /// = 5, mv -10 -> -5. td = 1, tb = -1: tx = 16384, factor = (-16384 +
    /// 32) >> 6 = -256 (floor of -255.5) -> mv 3 -> -((768 + 127) >> 8) =
    /// -3. td = 3, tb = 4: tx = (16384 + 1) / 3 = 5461, factor = (21844 +
    /// 32) >> 6 = 341, mv 9 -> (3069 + 127) >> 8 = 12.
    #[test]
    fn mv_scaling_by_hand() {
        assert_eq!(scale_mv([10, -10], 2, 1), [5, -5]);
        assert_eq!(scale_mv([3, 0], 1, -1), [-3, 0]);
        assert_eq!(scale_mv([9, 0], 3, 4), [12, 0]);
        // Saturation of the distance terms and the output.
        assert_eq!(scale_mv([32767, -32768], 1, 127)[0], 32767);
    }

    #[test]
    fn partition_geometry() {
        assert_eq!(
            PartMode::Part2NxnU.blocks(16),
            vec![(0, 0, 16, 4), (0, 4, 16, 12)]
        );
        assert_eq!(
            PartMode::PartnRx2N.blocks(32),
            vec![(0, 0, 24, 32), (24, 0, 8, 32)]
        );
        assert_eq!(PartMode::PartNxN.blocks(16).len(), 4);
    }

    /// Filter taps sum to 64 (DC gain), Tables 8-11 and 8-12.
    #[test]
    fn filters_have_unit_gain() {
        assert!(LUMA_FILTER.iter().all(|f| f.iter().sum::<i32>() == 64));
        assert!(CHROMA_FILTER.iter().all(|f| f.iter().sum::<i32>() == 64));
        assert_eq!(LUMA_FILTER[2], [-1, 4, -11, 40, 40, -11, 4, -1]);
        assert_eq!(CHROMA_FILTER[4], [-4, 36, 36, -4]);
    }
}
