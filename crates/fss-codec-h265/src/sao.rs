//! Sample adaptive offset (ITU-T H.265 clause 8.7.3): band offset and the
//! four edge-offset classes, applied per CTB to the deblocked picture,
//! honouring picture and slice boundaries and leaving PCM
//! (loop-filter-disabled) and transquant-bypass samples untouched.

use crate::ctu::PicState;
use crate::deblock::SliceFilter;

/// `SaoTypeIdx` values.
pub(crate) const SAO_NONE: u8 = 0;
/// Band offset.
pub(crate) const SAO_BAND: u8 = 1;
/// Edge offset.
pub(crate) const SAO_EDGE: u8 = 2;

/// SAO parameters of one CTB, per colour component.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SaoParams {
    /// `SaoTypeIdx`.
    pub type_idx: [u8; 3],
    /// `SaoOffsetVal[1..=4]`.
    pub offsets: [[i32; 4]; 3],
    /// `sao_band_position`.
    pub band_position: [u8; 3],
    /// `SaoEoClass`.
    pub eo_class: [u8; 3],
}

/// `hPos` / `vPos` of the two neighbours per edge class (Table 8-13).
const EDGE_NEIGHBOURS: [[(isize, isize); 2]; 4] = [
    [(-1, 0), (1, 0)],
    [(0, -1), (0, 1)],
    [(-1, -1), (1, 1)],
    [(1, -1), (-1, 1)],
];

/// `edgeIdx` from `2 + Sign(p - a) + Sign(p - b)` (equations 8-253 and
/// 8-254): local minimum -> 1, concave edge -> 2, flat or monotonic -> 0,
/// convex edge -> 3, local maximum -> 4.
fn edge_index(raw: i32) -> usize {
    match raw {
        0 => 1,
        1 => 2,
        3 => 3,
        4 => 4,
        _ => 0,
    }
}

/// Applies SAO to the whole picture (clause 8.7.3.1).
///
/// Samples whose four neighbours all lie inside their own CTB take a fast path when the CTB has
/// no PCM or transquant-bypass block: one CTB belongs to one slice and lies inside the picture,
/// so the per-sample picture-boundary, slice-boundary and `no_filter` checks cannot apply. Every
/// other sample takes the full clause 8.7.3 path.
pub(crate) fn apply(
    pic: &mut PicState,
    sao: &[SaoParams],
    ctb_log2: u32,
    ctb_width: usize,
    slices: &[SliceFilter],
) {
    if sao.iter().all(|p| p.type_idx == [SAO_NONE; 3]) {
        return;
    }
    let deblocked = pic.frame.planes.clone();
    for (addr, params) in sao.iter().enumerate() {
        let (rx, ry) = (addr % ctb_width, addr / ctb_width);
        // Whether any 4x4 block of this CTB is left unfiltered (PCM or transquant bypass).
        let luma_size = 1usize << ctb_log2;
        let (bx0, by0) = ((rx * luma_size) >> 2, (ry * luma_size) >> 2);
        let (bx1, by1) = (
            ((rx + 1) * luma_size).div_ceil(4).min(pic.w4),
            ((ry + 1) * luma_size).div_ceil(4).min(pic.h4),
        );
        let protected = (by0..by1).any(|by| {
            (bx0..bx1).any(|bx| pic.info.get(by * pic.w4 + bx).is_some_and(|b| b.no_filter))
        });
        for c in 0..3 {
            if params.type_idx[c] == SAO_NONE {
                continue;
            }
            let shift = usize::from(c > 0);
            let size = (1usize << ctb_log2) >> shift;
            let (pw, ph) = (pic.frame.plane_width(c), pic.frame.plane_height(c));
            let (x0, y0) = (rx * size, ry * size);
            let (x_end, y_end) = ((x0 + size).min(pw), (y0 + size).min(ph));
            let src = &deblocked[c];
            let mut band_table = [0usize; 32];
            for k in 0..4 {
                band_table[(k + usize::from(params.band_position[c])) & 31] = k + 1;
            }
            let band = params.type_idx[c] == SAO_BAND;
            let [(ax, ay), (bx, by)] = EDGE_NEIGHBOURS[usize::from(params.eo_class[c] & 3)];
            for y in y0..y_end {
                for x in x0..x_end {
                    let interior = !protected && x > x0 && y > y0 && x + 1 < x_end && y + 1 < y_end;
                    let index = if interior {
                        let value = i32::from(src[y * pw + x]);
                        if band {
                            band_table[(value >> 3) as usize]
                        } else {
                            let at = |dx: isize, dy: isize| {
                                i32::from(
                                    src[(y as isize + dy) as usize * pw
                                        + (x as isize + dx) as usize],
                                )
                            };
                            edge_index(
                                2 + (value - at(ax, ay)).signum() + (value - at(bx, by)).signum(),
                            )
                        }
                    } else {
                        match full_index(pic, src, params, c, shift, &band_table, slices, x, y) {
                            Some(index) => index,
                            None => continue,
                        }
                    };
                    if index == 0 {
                        continue;
                    }
                    let value = i32::from(src[y * pw + x]);
                    let out = (value + params.offsets[c][index - 1]).clamp(0, 255);
                    pic.frame.planes[c][y * pw + x] = out as u8;
                }
            }
        }
    }
}

/// The clause 8.7.3 offset category of one sample with every boundary check, or `None` when
/// the sample is left unmodified (`no_filter`, or an unusable edge neighbour).
#[allow(clippy::too_many_arguments)]
fn full_index(
    pic: &PicState,
    src: &[u8],
    params: &SaoParams,
    c: usize,
    shift: usize,
    band_table: &[usize; 32],
    slices: &[SliceFilter],
    x: usize,
    y: usize,
) -> Option<usize> {
    let (pw, ph) = (pic.frame.plane_width(c), pic.frame.plane_height(c));
    let (lx, ly) = (x << shift, y << shift);
    let info = pic.info[(ly >> 2) * pic.w4 + (lx >> 2)];
    if info.no_filter {
        return None;
    }
    let value = i32::from(src[y * pw + x]);
    if params.type_idx[c] == SAO_BAND {
        return Some(band_table[(value >> 3) as usize]);
    }
    let mut raw = 2i32;
    for &(dx, dy) in &EDGE_NEIGHBOURS[usize::from(params.eo_class[c] & 3)] {
        let (nx, ny) = (x as isize + dx, y as isize + dy);
        if nx < 0 || ny < 0 || nx >= pw as isize || ny >= ph as isize {
            return None;
        }
        let (nx, ny) = (nx as usize, ny as usize);
        let neighbour = pic.info[((ny << shift) >> 2) * pic.w4 + ((nx << shift) >> 2)];
        if neighbour.slice != info.slice {
            // The slice decoded later owns the boundary.
            let owner = info.slice.max(neighbour.slice);
            let across = slices
                .get(usize::from(owner).wrapping_sub(1))
                .is_some_and(|s| s.loop_filter_across_slices);
            if !across {
                return None;
            }
        }
        raw += (value - i32::from(src[ny * pw + nx])).signum();
    }
    Some(edge_index(raw))
}

/// Per-sample reference of [`apply`], kept as its test oracle.
#[cfg(test)]
fn apply_reference(
    pic: &mut PicState,
    sao: &[SaoParams],
    ctb_log2: u32,
    ctb_width: usize,
    slices: &[SliceFilter],
) {
    if sao.iter().all(|p| p.type_idx == [SAO_NONE; 3]) {
        return;
    }
    let deblocked = pic.frame.planes.clone();
    for (addr, params) in sao.iter().enumerate() {
        let (rx, ry) = (addr % ctb_width, addr / ctb_width);
        for c in 0..3 {
            if params.type_idx[c] == SAO_NONE {
                continue;
            }
            let shift = usize::from(c > 0);
            let size = (1usize << ctb_log2) >> shift;
            let (pw, ph) = (pic.frame.plane_width(c), pic.frame.plane_height(c));
            let (x0, y0) = (rx * size, ry * size);
            let (x_end, y_end) = ((x0 + size).min(pw), (y0 + size).min(ph));
            let src = &deblocked[c];
            let mut band_table = [0usize; 32];
            for k in 0..4 {
                band_table[(k + usize::from(params.band_position[c])) & 31] = k + 1;
            }
            for y in y0..y_end {
                for x in x0..x_end {
                    let (lx, ly) = (x << shift, y << shift);
                    let info = pic.info[(ly >> 2) * pic.w4 + (lx >> 2)];
                    if info.no_filter {
                        continue;
                    }
                    let value = i32::from(src[y * pw + x]);
                    let index = if params.type_idx[c] == SAO_BAND {
                        band_table[(value >> 3) as usize]
                    } else {
                        let mut raw = 2i32;
                        let mut usable = true;
                        for &(dx, dy) in &EDGE_NEIGHBOURS[usize::from(params.eo_class[c] & 3)] {
                            let (nx, ny) = (x as isize + dx, y as isize + dy);
                            if nx < 0 || ny < 0 || nx >= pw as isize || ny >= ph as isize {
                                usable = false;
                                break;
                            }
                            let (nx, ny) = (nx as usize, ny as usize);
                            let neighbour =
                                pic.info[((ny << shift) >> 2) * pic.w4 + ((nx << shift) >> 2)];
                            if neighbour.slice != info.slice {
                                // The slice decoded later owns the boundary.
                                let owner = info.slice.max(neighbour.slice);
                                let across = slices
                                    .get(usize::from(owner).wrapping_sub(1))
                                    .is_some_and(|s| s.loop_filter_across_slices);
                                if !across {
                                    usable = false;
                                    break;
                                }
                            }
                            raw += (value - i32::from(src[ny * pw + nx])).signum();
                        }
                        if !usable {
                            continue;
                        }
                        edge_index(raw)
                    };
                    if index == 0 {
                        continue;
                    }
                    let out = (value + params.offsets[c][index - 1]).clamp(0, 255);
                    pic.frame.planes[c][y * pw + x] = out as u8;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctu::{BlockInfo, PicState};
    use crate::picture::Frame;

    /// The CTB-interior fast path equals the per-sample reference on random pictures, SAO
    /// parameters, slice layouts (with and without cross-slice filtering) and unfiltered blocks.
    #[test]
    fn fast_sao_equals_the_per_sample_reference() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..300 {
            let (width, height, ctb_log2) = [(64, 48, 4), (40, 24, 4), (96, 64, 5)][round % 3];
            let ctb = 1usize << ctb_log2;
            let (ctb_w, ctb_h) = (usize::div_ceil(width, ctb), usize::div_ceil(height, ctb));
            let mut frame = Frame::new(width, height).unwrap_or_else(|_| unreachable!());
            for plane in &mut frame.planes {
                for sample in plane.iter_mut() {
                    *sample = (next() >> 24) as u8;
                }
            }
            let (w4, h4) = (width.div_ceil(4), height.div_ceil(4));
            // Slices are raster runs of CTBs; tags increase.
            let mut ctb_slice = vec![0u16; ctb_w * ctb_h];
            let mut tag = 1u16;
            for (i, slot) in ctb_slice.iter_mut().enumerate() {
                if i > 0 && next() % 5 == 0 {
                    tag += 1;
                }
                *slot = tag;
            }
            let mut info = vec![BlockInfo::default(); w4 * h4];
            for by in 0..h4 {
                for bx in 0..w4 {
                    let ctb_addr = ((by * 4) / ctb) * ctb_w + (bx * 4) / ctb;
                    info[by * w4 + bx].slice = ctb_slice[ctb_addr];
                    info[by * w4 + bx].no_filter = next() % 40 == 0;
                }
            }
            let slices: Vec<SliceFilter> = (0..tag)
                .map(|_| SliceFilter {
                    deblocking_disabled: false,
                    beta_offset: 0,
                    tc_offset: 0,
                    loop_filter_across_slices: next() % 2 == 0,
                })
                .collect();
            let sao: Vec<SaoParams> = (0..ctb_w * ctb_h)
                .map(|_| {
                    let mut p = SaoParams::default();
                    for c in 0..3 {
                        p.type_idx[c] = (next() % 3) as u8;
                        p.band_position[c] = (next() % 32) as u8;
                        p.eo_class[c] = (next() % 4) as u8;
                        for offset in &mut p.offsets[c] {
                            *offset = (next() % 31) as i32 - 15;
                        }
                    }
                    p
                })
                .collect();
            let picture = |frame: Frame| PicState {
                frame,
                w4,
                h4,
                info: info.clone(),
                ctb_slice: ctb_slice.clone(),
                slice_count: tag,
                next_ctb: 0,
                slice_refs: Vec::new(),
                slice_filters: slices.clone(),
                sao: sao.clone(),
            };
            let mut fast = picture(frame.clone());
            let mut slow = picture(frame);
            apply(&mut fast, &sao, ctb_log2, ctb_w, &slices);
            apply_reference(&mut slow, &sao, ctb_log2, ctb_w, &slices);
            assert_eq!(fast.frame.planes, slow.frame.planes, "round {round}");
        }
    }

    /// Equations 8-253/8-254 by hand: a sample below both neighbours
    /// (2 - 1 - 1 = 0) is category 1; equal to one and below the other
    /// (2 + 0 - 1 = 1) category 2; flat (2) category 0; above one, equal
    /// to the other (3) category 3; a peak (4) category 4.
    #[test]
    fn edge_categories_by_hand() {
        assert_eq!(edge_index(0), 1);
        assert_eq!(edge_index(1), 2);
        assert_eq!(edge_index(2), 0);
        assert_eq!(edge_index(3), 3);
        assert_eq!(edge_index(4), 4);
    }

    /// Table 8-13 neighbour positions: class 0 horizontal, 1 vertical,
    /// 2 135-degree diagonal, 3 45-degree diagonal.
    #[test]
    fn edge_classes_match_table_8_13() {
        assert_eq!(EDGE_NEIGHBOURS[0], [(-1, 0), (1, 0)]);
        assert_eq!(EDGE_NEIGHBOURS[1], [(0, -1), (0, 1)]);
        assert_eq!(EDGE_NEIGHBOURS[2], [(-1, -1), (1, 1)]);
        assert_eq!(EDGE_NEIGHBOURS[3], [(1, -1), (-1, 1)]);
    }
}
