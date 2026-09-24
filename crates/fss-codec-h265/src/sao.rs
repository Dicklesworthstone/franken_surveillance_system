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
