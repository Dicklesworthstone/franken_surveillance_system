//! Intra sample prediction (clauses 8.3.1.2, 8.3.3, 8.3.4) as pure
//! functions of the neighbouring samples. Availability (picture edge,
//! slice edge, decode order, constrained intra) is resolved by the caller;
//! `None` means "not available for Intra prediction". A mode whose required
//! neighbours are unavailable is a non-conforming stream (Malformed).

use crate::DecodeError;

/// Neighbours of a 4x4 luma block. `top` holds `p[0..8, -1]`; when the
/// above-right samples are unavailable but the above ones are, the caller
/// substitutes `p[3, -1]` into positions 4..8 (clause 8.3.1.2).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Neighbors4x4 {
    /// `p[x, -1]`, x = 0..7.
    pub top: Option<[u8; 8]>,
    /// `p[-1, y]`, y = 0..3.
    pub left: Option<[u8; 4]>,
    /// `p[-1, -1]`.
    pub top_left: Option<u8>,
}

/// Neighbours of a 16x16 luma macroblock.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Neighbors16x16 {
    /// `p[x, -1]`, x = 0..15.
    pub top: Option<[u8; 16]>,
    /// `p[-1, y]`, y = 0..15.
    pub left: Option<[u8; 16]>,
    /// `p[-1, -1]`.
    pub top_left: Option<u8>,
}

/// Neighbours of one 8x8 4:2:0 chroma block.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NeighborsChroma {
    /// `p[x, -1]`, x = 0..7.
    pub top: Option<[u8; 8]>,
    /// `p[-1, y]`, y = 0..7.
    pub left: Option<[u8; 8]>,
    /// `p[-1, -1]`.
    pub top_left: Option<u8>,
}

fn sum(values: &[u8]) -> u32 {
    values.iter().map(|&v| u32::from(v)).sum()
}

fn narrow(value: u32) -> u8 {
    u8::try_from(value).unwrap_or(u8::MAX)
}

fn clip(value: i32) -> u8 {
    u8::try_from(value.clamp(0, 255)).unwrap_or(u8::MAX)
}

/// Intra 4x4 prediction for `Intra4x4PredMode` 0..=8; output is raster.
///
/// # Errors
/// [`DecodeError::Malformed`] when the mode is > 8 or needs a neighbour
/// that is unavailable.
pub fn predict_4x4(mode: u8, n: &Neighbors4x4) -> Result<[u8; 16], DecodeError> {
    let mut out = [0u8; 16];
    let need_top = || n.top.ok_or(DecodeError::Malformed);
    let need_left = || n.left.ok_or(DecodeError::Malformed);
    let need_corner = || n.top_left.ok_or(DecodeError::Malformed);
    match mode {
        0 => {
            let top = need_top()?;
            for y in 0..4 {
                out[y * 4..y * 4 + 4].copy_from_slice(&top[..4]);
            }
        }
        1 => {
            let left = need_left()?;
            for y in 0..4 {
                out[y * 4..y * 4 + 4].fill(left[y]);
            }
        }
        2 => {
            let dc = match (n.top, n.left) {
                (Some(t), Some(l)) => (sum(&t[..4]) + sum(&l) + 4) >> 3,
                (None, Some(l)) => (sum(&l) + 2) >> 2,
                (Some(t), None) => (sum(&t[..4]) + 2) >> 2,
                (None, None) => 128,
            };
            out.fill(narrow(dc));
        }
        3 => {
            let t = need_top()?.map(u32::from);
            for y in 0..4 {
                for x in 0..4 {
                    out[y * 4 + x] = narrow(if x == 3 && y == 3 {
                        (t[6] + 3 * t[7] + 2) >> 2
                    } else {
                        (t[x + y] + 2 * t[x + y + 1] + t[x + y + 2] + 2) >> 2
                    });
                }
            }
        }
        4..=6 => {
            let t = need_top()?.map(i32::from);
            let l = need_left()?.map(i32::from);
            let q = i32::from(need_corner()?);
            // p(x, y) with x or y = -1 addressing the neighbour arrays.
            let p = |x: i32, y: i32| -> i32 {
                if y < 0 {
                    if x < 0 { q } else { t[x as usize] }
                } else if x < 0 {
                    l[y as usize]
                } else {
                    0
                }
            };
            for y in 0..4i32 {
                for x in 0..4i32 {
                    let value = match mode {
                        4 => {
                            if x > y {
                                (p(x - y - 2, -1) + 2 * p(x - y - 1, -1) + p(x - y, -1) + 2) >> 2
                            } else if x < y {
                                (p(-1, y - x - 2) + 2 * p(-1, y - x - 1) + p(-1, y - x) + 2) >> 2
                            } else {
                                (p(0, -1) + 2 * p(-1, -1) + p(-1, 0) + 2) >> 2
                            }
                        }
                        5 => {
                            let z = 2 * x - y;
                            if z >= 0 && z % 2 == 0 {
                                (p(x - (y >> 1) - 1, -1) + p(x - (y >> 1), -1) + 1) >> 1
                            } else if z >= 0 {
                                (p(x - (y >> 1) - 2, -1)
                                    + 2 * p(x - (y >> 1) - 1, -1)
                                    + p(x - (y >> 1), -1)
                                    + 2)
                                    >> 2
                            } else if z == -1 {
                                (p(-1, 0) + 2 * p(-1, -1) + p(0, -1) + 2) >> 2
                            } else {
                                (p(-1, y - 1) + 2 * p(-1, y - 2) + p(-1, y - 3) + 2) >> 2
                            }
                        }
                        _ => {
                            let z = 2 * y - x;
                            if z >= 0 && z % 2 == 0 {
                                (p(-1, y - (x >> 1) - 1) + p(-1, y - (x >> 1)) + 1) >> 1
                            } else if z >= 0 {
                                (p(-1, y - (x >> 1) - 2)
                                    + 2 * p(-1, y - (x >> 1) - 1)
                                    + p(-1, y - (x >> 1))
                                    + 2)
                                    >> 2
                            } else if z == -1 {
                                (p(-1, 0) + 2 * p(-1, -1) + p(0, -1) + 2) >> 2
                            } else {
                                (p(x - 1, -1) + 2 * p(x - 2, -1) + p(x - 3, -1) + 2) >> 2
                            }
                        }
                    };
                    out[(y * 4 + x) as usize] = clip(value);
                }
            }
        }
        7 => {
            let t = need_top()?.map(u32::from);
            for y in 0..4 {
                for x in 0..4 {
                    let i = x + (y >> 1);
                    out[y * 4 + x] = narrow(if y.is_multiple_of(2) {
                        (t[i] + t[i + 1] + 1) >> 1
                    } else {
                        (t[i] + 2 * t[i + 1] + t[i + 2] + 2) >> 2
                    });
                }
            }
        }
        8 => {
            let l = need_left()?.map(u32::from);
            for y in 0..4 {
                for x in 0..4 {
                    let z = x + 2 * y;
                    let i = y + (x >> 1);
                    out[y * 4 + x] = narrow(match z {
                        0 | 2 | 4 => (l[i] + l[i + 1] + 1) >> 1,
                        1 | 3 => (l[i] + 2 * l[i + 1] + l[i + 2] + 2) >> 2,
                        5 => (l[2] + 3 * l[3] + 2) >> 2,
                        _ => l[3],
                    });
                }
            }
        }
        _ => return Err(DecodeError::Malformed),
    }
    Ok(out)
}

/// Neighbours of an 8x8 luma block. `top` holds `p[0..16, -1]`; when the
/// above-right samples are unavailable but the above ones are, the caller
/// substitutes `p[7, -1]` into positions 8..16 (clause 8.3.2.2).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Neighbors8x8 {
    /// `p[x, -1]`, x = 0..15.
    pub top: Option<[u8; 16]>,
    /// `p[-1, y]`, y = 0..7.
    pub left: Option<[u8; 8]>,
    /// `p[-1, -1]`.
    pub top_left: Option<u8>,
}

/// Reference sample filtering for Intra_8x8 (clause 8.3.2.2.1).
#[must_use]
pub fn filter_8x8_neighbours(n: &Neighbors8x8) -> Neighbors8x8 {
    let top = n.top.map(|t| {
        let t = t.map(u32::from);
        let mut out = [0u8; 16];
        out[0] = narrow(match n.top_left {
            Some(q) => (u32::from(q) + 2 * t[0] + t[1] + 2) >> 2,
            None => (3 * t[0] + t[1] + 2) >> 2,
        });
        for x in 1..15 {
            out[x] = narrow((t[x - 1] + 2 * t[x] + t[x + 1] + 2) >> 2);
        }
        out[15] = narrow((t[14] + 3 * t[15] + 2) >> 2);
        out
    });
    let top_left = n.top_left.map(|q| {
        let q = u32::from(q);
        narrow(match (n.top, n.left) {
            (Some(t), Some(l)) => (u32::from(t[0]) + 2 * q + u32::from(l[0]) + 2) >> 2,
            (Some(t), None) => (3 * q + u32::from(t[0]) + 2) >> 2,
            (None, Some(l)) => (3 * q + u32::from(l[0]) + 2) >> 2,
            (None, None) => q,
        })
    });
    let left = n.left.map(|l| {
        let l = l.map(u32::from);
        let mut out = [0u8; 8];
        out[0] = narrow(match n.top_left {
            Some(q) => (u32::from(q) + 2 * l[0] + l[1] + 2) >> 2,
            None => (3 * l[0] + l[1] + 2) >> 2,
        });
        for y in 1..7 {
            out[y] = narrow((l[y - 1] + 2 * l[y] + l[y + 1] + 2) >> 2);
        }
        out[7] = narrow((l[6] + 3 * l[7] + 2) >> 2);
        out
    });
    Neighbors8x8 {
        top,
        left,
        top_left,
    }
}

/// Intra 8x8 prediction for `Intra8x8PredMode` 0..=8 (clauses
/// 8.3.2.2.2..10) from UNFILTERED neighbours; the reference filtering of
/// 8.3.2.2.1 is applied here. Output is raster 8x8.
///
/// # Errors
/// [`DecodeError::Malformed`] when the mode is > 8 or needs a neighbour
/// that is unavailable.
pub fn predict_8x8(mode: u8, raw: &Neighbors8x8) -> Result<[u8; 64], DecodeError> {
    let n = filter_8x8_neighbours(raw);
    let mut out = [0u8; 64];
    let need_top = || {
        n.top
            .map(|t| t.map(i32::from))
            .ok_or(DecodeError::Malformed)
    };
    let need_left = || {
        n.left
            .map(|l| l.map(i32::from))
            .ok_or(DecodeError::Malformed)
    };
    match mode {
        0 => {
            let t = n.top.ok_or(DecodeError::Malformed)?;
            for y in 0..8 {
                out[y * 8..y * 8 + 8].copy_from_slice(&t[..8]);
            }
        }
        1 => {
            let l = n.left.ok_or(DecodeError::Malformed)?;
            for y in 0..8 {
                out[y * 8..y * 8 + 8].fill(l[y]);
            }
        }
        2 => {
            let dc = match (n.top, n.left) {
                (Some(t), Some(l)) => (sum(&t[..8]) + sum(&l) + 8) >> 4,
                (None, Some(l)) => (sum(&l) + 4) >> 3,
                (Some(t), None) => (sum(&t[..8]) + 4) >> 3,
                (None, None) => 128,
            };
            out.fill(narrow(dc));
        }
        3 => {
            let t = need_top()?;
            for y in 0..8 {
                for x in 0..8 {
                    out[y * 8 + x] = clip(if x == 7 && y == 7 {
                        (t[14] + 3 * t[15] + 2) >> 2
                    } else {
                        (t[x + y] + 2 * t[x + y + 1] + t[x + y + 2] + 2) >> 2
                    });
                }
            }
        }
        4..=6 => {
            let t = need_top()?;
            let l = need_left()?;
            let q = i32::from(n.top_left.ok_or(DecodeError::Malformed)?);
            // p'(x, y) with x or y = -1 addressing the filtered arrays.
            let p = |x: i32, y: i32| -> i32 {
                if y < 0 {
                    if x < 0 {
                        q
                    } else {
                        usize::try_from(x)
                            .ok()
                            .and_then(|i| t.get(i))
                            .copied()
                            .unwrap_or(0)
                    }
                } else {
                    usize::try_from(y)
                        .ok()
                        .and_then(|i| l.get(i))
                        .copied()
                        .unwrap_or(0)
                }
            };
            for y in 0..8i32 {
                for x in 0..8i32 {
                    let value = match mode {
                        4 => {
                            if x > y {
                                (p(x - y - 2, -1) + 2 * p(x - y - 1, -1) + p(x - y, -1) + 2) >> 2
                            } else if x < y {
                                (p(-1, y - x - 2) + 2 * p(-1, y - x - 1) + p(-1, y - x) + 2) >> 2
                            } else {
                                (p(0, -1) + 2 * p(-1, -1) + p(-1, 0) + 2) >> 2
                            }
                        }
                        5 => {
                            let z = 2 * x - y;
                            if z >= 0 && z % 2 == 0 {
                                (p(x - (y >> 1) - 1, -1) + p(x - (y >> 1), -1) + 1) >> 1
                            } else if z >= 0 {
                                (p(x - (y >> 1) - 2, -1)
                                    + 2 * p(x - (y >> 1) - 1, -1)
                                    + p(x - (y >> 1), -1)
                                    + 2)
                                    >> 2
                            } else if z == -1 {
                                (p(-1, 0) + 2 * p(-1, -1) + p(0, -1) + 2) >> 2
                            } else {
                                (p(-1, y - 2 * x - 1)
                                    + 2 * p(-1, y - 2 * x - 2)
                                    + p(-1, y - 2 * x - 3)
                                    + 2)
                                    >> 2
                            }
                        }
                        _ => {
                            let z = 2 * y - x;
                            if z >= 0 && z % 2 == 0 {
                                (p(-1, y - (x >> 1) - 1) + p(-1, y - (x >> 1)) + 1) >> 1
                            } else if z >= 0 {
                                (p(-1, y - (x >> 1) - 2)
                                    + 2 * p(-1, y - (x >> 1) - 1)
                                    + p(-1, y - (x >> 1))
                                    + 2)
                                    >> 2
                            } else if z == -1 {
                                (p(-1, 0) + 2 * p(-1, -1) + p(0, -1) + 2) >> 2
                            } else {
                                (p(x - 2 * y - 1, -1)
                                    + 2 * p(x - 2 * y - 2, -1)
                                    + p(x - 2 * y - 3, -1)
                                    + 2)
                                    >> 2
                            }
                        }
                    };
                    out[usize::try_from(y * 8 + x).unwrap_or(0)] = clip(value);
                }
            }
        }
        7 => {
            let t = need_top()?;
            for y in 0..8 {
                for x in 0..8 {
                    let i = x + (y >> 1);
                    out[y * 8 + x] = clip(if y % 2 == 0 {
                        (t[i] + t[i + 1] + 1) >> 1
                    } else {
                        (t[i] + 2 * t[i + 1] + t[i + 2] + 2) >> 2
                    });
                }
            }
        }
        8 => {
            let l = need_left()?;
            for y in 0..8 {
                for x in 0..8 {
                    let z = x + 2 * y;
                    let i = y + (x >> 1);
                    out[y * 8 + x] = clip(if z > 13 {
                        l[7]
                    } else if z == 13 {
                        (l[6] + 3 * l[7] + 2) >> 2
                    } else if z % 2 == 0 {
                        (l[i] + l[i + 1] + 1) >> 1
                    } else {
                        (l[i] + 2 * l[i + 1] + l[i + 2] + 2) >> 2
                    });
                }
            }
        }
        _ => return Err(DecodeError::Malformed),
    }
    Ok(out)
}

/// Intra 16x16 prediction for `Intra16x16PredMode` 0..=3; output raster.
///
/// # Errors
/// [`DecodeError::Malformed`] for a bad mode or missing neighbours.
pub fn predict_16x16(mode: u8, n: &Neighbors16x16) -> Result<[u8; 256], DecodeError> {
    let mut out = [0u8; 256];
    match mode {
        0 => {
            let top = n.top.ok_or(DecodeError::Malformed)?;
            for y in 0..16 {
                out[y * 16..y * 16 + 16].copy_from_slice(&top);
            }
        }
        1 => {
            let left = n.left.ok_or(DecodeError::Malformed)?;
            for y in 0..16 {
                out[y * 16..y * 16 + 16].fill(left[y]);
            }
        }
        2 => {
            let dc = match (n.top, n.left) {
                (Some(t), Some(l)) => (sum(&t) + sum(&l) + 16) >> 5,
                (None, Some(l)) => (sum(&l) + 8) >> 4,
                (Some(t), None) => (sum(&t) + 8) >> 4,
                (None, None) => 128,
            };
            out.fill(narrow(dc));
        }
        3 => {
            let t = n.top.ok_or(DecodeError::Malformed)?.map(i32::from);
            let l = n.left.ok_or(DecodeError::Malformed)?.map(i32::from);
            let q = i32::from(n.top_left.ok_or(DecodeError::Malformed)?);
            let top_at = |i: i32| if i < 0 { q } else { t[i as usize] };
            let left_at = |i: i32| if i < 0 { q } else { l[i as usize] };
            let mut h = 0;
            let mut v = 0;
            for k in 0..8i32 {
                h += (k + 1) * (top_at(8 + k) - top_at(6 - k));
                v += (k + 1) * (left_at(8 + k) - left_at(6 - k));
            }
            let a = 16 * (l[15] + t[15]);
            let b = (5 * h + 32) >> 6;
            let c = (5 * v + 32) >> 6;
            for y in 0..16i32 {
                for x in 0..16i32 {
                    out[(y * 16 + x) as usize] = clip((a + b * (x - 7) + c * (y - 7) + 16) >> 5);
                }
            }
        }
        _ => return Err(DecodeError::Malformed),
    }
    Ok(out)
}

/// 4:2:0 chroma prediction for `intra_chroma_pred_mode` 0..=3 (DC,
/// horizontal, vertical, plane); output is raster 8x8.
///
/// # Errors
/// [`DecodeError::Malformed`] for a bad mode or missing neighbours.
pub fn predict_chroma(mode: u8, n: &NeighborsChroma) -> Result<[u8; 64], DecodeError> {
    let mut out = [0u8; 64];
    match mode {
        0 => {
            // Per 4x4 chroma block (clause 8.3.4.1-3).
            for block in 0..4usize {
                let (xo, yo) = ((block % 2) * 4, (block / 2) * 4);
                let top = n.top.map(|t| sum(&t[xo..xo + 4]));
                let left = n.left.map(|l| sum(&l[yo..yo + 4]));
                let dc = if (xo == 0 && yo == 0) || (xo > 0 && yo > 0) {
                    match (top, left) {
                        (Some(t), Some(l)) => (t + l + 4) >> 3,
                        (None, Some(l)) => (l + 2) >> 2,
                        (Some(t), None) => (t + 2) >> 2,
                        (None, None) => 128,
                    }
                } else if xo > 0 {
                    match (top, left) {
                        (Some(t), _) => (t + 2) >> 2,
                        (None, Some(l)) => (l + 2) >> 2,
                        (None, None) => 128,
                    }
                } else {
                    match (top, left) {
                        (_, Some(l)) => (l + 2) >> 2,
                        (Some(t), None) => (t + 2) >> 2,
                        (None, None) => 128,
                    }
                };
                for y in 0..4 {
                    for x in 0..4 {
                        out[(yo + y) * 8 + xo + x] = narrow(dc);
                    }
                }
            }
        }
        1 => {
            let left = n.left.ok_or(DecodeError::Malformed)?;
            for y in 0..8 {
                out[y * 8..y * 8 + 8].fill(left[y]);
            }
        }
        2 => {
            let top = n.top.ok_or(DecodeError::Malformed)?;
            for y in 0..8 {
                out[y * 8..y * 8 + 8].copy_from_slice(&top);
            }
        }
        3 => {
            let t = n.top.ok_or(DecodeError::Malformed)?.map(i32::from);
            let l = n.left.ok_or(DecodeError::Malformed)?.map(i32::from);
            let q = i32::from(n.top_left.ok_or(DecodeError::Malformed)?);
            let top_at = |i: i32| if i < 0 { q } else { t[i as usize] };
            let left_at = |i: i32| if i < 0 { q } else { l[i as usize] };
            let mut h = 0;
            let mut v = 0;
            for k in 0..4i32 {
                h += (k + 1) * (top_at(4 + k) - top_at(2 - k));
                v += (k + 1) * (left_at(4 + k) - left_at(2 - k));
            }
            let a = 16 * (l[7] + t[7]);
            let b = (34 * h + 32) >> 6;
            let c = (34 * v + 32) >> 6;
            for y in 0..8i32 {
                for x in 0..8i32 {
                    out[(y * 8 + x) as usize] = clip((a + b * (x - 3) + c * (y - 3) + 16) >> 5);
                }
            }
        }
        _ => return Err(DecodeError::Malformed),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// Neighbourhood used by every hand-computed 4x4 case:
    /// Q = p[-1,-1] = 50; top = 10, 20, ..., 80; left = 100, 110, 120, 130.
    fn n4() -> Neighbors4x4 {
        Neighbors4x4 {
            top: Some([10, 20, 30, 40, 50, 60, 70, 80]),
            left: Some([100, 110, 120, 130]),
            top_left: Some(50),
        }
    }

    fn rows(block: &[u8; 16]) -> [[u8; 4]; 4] {
        let mut out = [[0u8; 4]; 4];
        for (y, row) in out.iter_mut().enumerate() {
            row.copy_from_slice(&block[y * 4..y * 4 + 4]);
        }
        out
    }

    #[test]
    fn intra4x4_vertical_horizontal_dc() {
        let n = n4();
        assert_eq!(rows(&predict_4x4(0, &n).unwrap()), [[10, 20, 30, 40]; 4]);
        assert_eq!(
            rows(&predict_4x4(1, &n).unwrap()),
            [[100; 4], [110; 4], [120; 4], [130; 4]]
        );
        // (100 + 460 + 4) >> 3 = 70.
        assert_eq!(predict_4x4(2, &n).unwrap(), [70; 16]);
        // Left only: (460 + 2) >> 2 = 115; top only: (100 + 2) >> 2 = 25.
        let left_only = Neighbors4x4 { top: None, ..n };
        assert_eq!(predict_4x4(2, &left_only).unwrap(), [115; 16]);
        let top_only = Neighbors4x4 { left: None, ..n };
        assert_eq!(predict_4x4(2, &top_only).unwrap(), [25; 16]);
        assert_eq!(predict_4x4(2, &Neighbors4x4::default()).unwrap(), [128; 16]);
    }

    /// Diagonal down-left on a linear ramp t[i] = 10(i+1): the 3-tap filter
    /// of a ramp is the centre sample, so pred[x,y] = t[x+y+1], except
    /// (3,3) = (70 + 240 + 2) >> 2 = 78.
    #[test]
    fn intra4x4_diagonal_down_left() {
        let out = rows(&predict_4x4(3, &n4()).unwrap());
        assert_eq!(out[0], [20, 30, 40, 50]);
        assert_eq!(out[1], [30, 40, 50, 60]);
        assert_eq!(out[2], [40, 50, 60, 70]);
        assert_eq!(out[3], [50, 60, 70, 78]);
    }

    /// Diagonal down-right, hand-computed from the 8.3.1.2.5 equations:
    /// diagonal (x == y): (t0 + 2Q + l0 + 2) >> 2 = (10+100+100+2)>>2 = 53.
    /// (1,0): (Q + 2 t0 + t1 + 2) >> 2 = (50+20+20+2)>>2 = 23.
    /// (2,0): (t0 + 2 t1 + t2 + 2) >> 2 = 20; (3,0): 30.
    /// (0,1): (Q + 2 l0 + l1 + 2) >> 2 = (50+200+110+2)>>2 = 90.
    /// (0,2): (l0 + 2 l1 + l2 + 2) >> 2 = 110; (0,3): 120.
    #[test]
    fn intra4x4_diagonal_down_right() {
        let out = rows(&predict_4x4(4, &n4()).unwrap());
        assert_eq!(out[0], [53, 23, 20, 30]);
        assert_eq!(out[1], [90, 53, 23, 20]);
        assert_eq!(out[2], [110, 90, 53, 23]);
        assert_eq!(out[3], [120, 110, 90, 53]);
    }

    /// Vertical-right (8.3.1.2.6), zVR = 2x - y:
    /// row 0: zVR 0,2,4,6 -> 2-tap: (Q+t0+1)>>1 = 30, (t0+t1+1)>>1 = 15,
    ///   (t1+t2+1)>>1 = 25, (t2+t3+1)>>1 = 35.
    /// row 1: (0,1) zVR=-1 -> (l0 + 2Q + t0 + 2)>>2 = (100+100+10+2)>>2 = 53;
    ///   zVR 1,3,5 -> 3-tap: (Q+2t0+t1+2)>>2 = 23, (t0+2t1+t2+2)>>2 = 20,
    ///   (t1+2t2+t3+2)>>2 = 30.
    /// row 2: (0,2) zVR=-2 -> (l1 + 2 l0 + Q + 2)>>2 = (110+200+50+2)>>2 = 90;
    ///   (1,2) zVR=0 -> (Q+t0+1)>>1 = 30; (2,2) -> 15; (3,2) -> 25.
    /// row 3: (0,3) zVR=-3 -> (l2 + 2 l1 + l0 + 2)>>2 = (120+220+100+2)>>2 = 110;
    ///   (1,3) zVR=-1 -> 53; (2,3) zVR=1 -> 23; (3,3) zVR=3 -> 20.
    #[test]
    fn intra4x4_vertical_right() {
        let out = rows(&predict_4x4(5, &n4()).unwrap());
        assert_eq!(out[0], [30, 15, 25, 35]);
        assert_eq!(out[1], [53, 23, 20, 30]);
        assert_eq!(out[2], [90, 30, 15, 25]);
        assert_eq!(out[3], [110, 53, 23, 20]);
    }

    /// Horizontal-down (8.3.1.2.7), zHD = 2y - x:
    /// row 0: (0,0) zHD 0 -> (Q + l0 + 1)>>1 = 75; (1,0) zHD -1 ->
    ///   (l0 + 2Q + t0 + 2)>>2 = 53; (2,0) zHD -2 -> (t1 + 2 t0 + Q + 2)>>2
    ///   = (20+20+50+2)>>2 = 23; (3,0) -> (t2 + 2 t1 + t0 + 2)>>2 = 20.
    /// row 1: (0,1) zHD 2 -> (l0 + l1 + 1)>>1 = 105; (1,1) zHD 1 ->
    ///   (Q + 2 l0 + l1 + 2)>>2 = 90; (2,1) zHD 0 -> 75; (3,1) zHD -1 -> 53.
    /// row 2: (0,2) zHD 4 -> (l1+l2+1)>>1 = 115; (1,2) zHD 3 ->
    ///   (l0 + 2 l1 + l2 + 2)>>2 = 110; (2,2) -> 105; (3,2) -> 90.
    /// row 3: (0,3) -> (l2+l3+1)>>1 = 125; (1,3) zHD 5 -> 120; (2,3) -> 115;
    ///   (3,3) zHD 3 -> 110.
    #[test]
    fn intra4x4_horizontal_down() {
        let out = rows(&predict_4x4(6, &n4()).unwrap());
        assert_eq!(out[0], [75, 53, 23, 20]);
        assert_eq!(out[1], [105, 90, 75, 53]);
        assert_eq!(out[2], [115, 110, 105, 90]);
        assert_eq!(out[3], [125, 120, 115, 110]);
    }

    /// Vertical-left (8.3.1.2.8): even rows 2-tap, odd rows 3-tap, shifted
    /// by y >> 1. Row 0: (t0+t1+1)>>1 = 15, 25, 35, 45. Row 1: ramp centre
    /// t1..t4 = 20, 30, 40, 50. Row 2: 25, 35, 45, 55. Row 3: 30..60.
    #[test]
    fn intra4x4_vertical_left() {
        let out = rows(&predict_4x4(7, &n4()).unwrap());
        assert_eq!(out[0], [15, 25, 35, 45]);
        assert_eq!(out[1], [20, 30, 40, 50]);
        assert_eq!(out[2], [25, 35, 45, 55]);
        assert_eq!(out[3], [30, 40, 50, 60]);
    }

    /// Horizontal-up (8.3.1.2.9), zHU = x + 2y:
    /// (0,0) zHU 0 -> (l0+l1+1)>>1 = 105; (1,0) zHU 1 -> (l0+2l1+l2+2)>>2
    /// = 110; (2,0) zHU 2 -> (l1+l2+1)>>1 = 115; (3,0) zHU 3 -> 120.
    /// (0,1) = 115, (1,1) = 120, (2,1) zHU 4 -> (l2+l3+1)>>1 = 125,
    /// (3,1) zHU 5 -> (l2 + 3 l3 + 2)>>2 = (120+390+2)>>2 = 128.
    /// Rows 2 and 3: zHU >= 4 -> 125, 128, then 130 (l3) beyond 5.
    #[test]
    fn intra4x4_horizontal_up() {
        let out = rows(&predict_4x4(8, &n4()).unwrap());
        assert_eq!(out[0], [105, 110, 115, 120]);
        assert_eq!(out[1], [115, 120, 125, 128]);
        assert_eq!(out[2], [125, 128, 130, 130]);
        assert_eq!(out[3], [130, 130, 130, 130]);
    }

    #[test]
    fn intra4x4_missing_neighbours_are_malformed() {
        let n = Neighbors4x4 {
            top_left: None,
            ..n4()
        };
        for mode in [4u8, 5, 6] {
            assert_eq!(predict_4x4(mode, &n).unwrap_err(), DecodeError::Malformed);
        }
        let n = Neighbors4x4 { top: None, ..n4() };
        for mode in [0u8, 3, 7] {
            assert_eq!(predict_4x4(mode, &n).unwrap_err(), DecodeError::Malformed);
        }
        assert_eq!(predict_4x4(9, &n4()).unwrap_err(), DecodeError::Malformed);
    }

    /// 16x16 plane on a linear ramp top[x] = 2x + 10, left[y] = 3y + 20,
    /// Q = 7. H = sum (k+1)(t[8+k] - t[6-k]) with t[-1] = Q:
    /// k=0..6: (k+1)*(4k+4) = 4(k+1)^2 -> 4*(1+4+9+16+25+36+49) = 560;
    /// k=7: 8*(t15 - Q) = 8*(40 - 7) = 264 -> H = 824.
    /// V: k=0..6: (k+1)*(6k+6) = 6(k+1)^2 -> 840; k=7: 8*(65 - 7) = 464
    /// -> V = 1304. a = 16*(65 + 40) = 1680; b = (5*824+32)>>6 = 64;
    /// c = (5*1304+32)>>6 = 102. pred(0,0) = (1680 - 448 - 714 + 16)>>5
    /// = 16; pred(15,15) = (1680 + 512 + 816 + 16)>>5 = 94;
    /// pred(7,7) = (1680 + 16) >> 5 = 53.
    #[test]
    fn intra16x16_plane_and_dc() {
        let mut top = [0u8; 16];
        let mut left = [0u8; 16];
        for i in 0..16u8 {
            top[usize::from(i)] = 2 * i + 10;
            left[usize::from(i)] = 3 * i + 20;
        }
        let n = Neighbors16x16 {
            top: Some(top),
            left: Some(left),
            top_left: Some(7),
        };
        let out = predict_16x16(3, &n).unwrap();
        assert_eq!(out[0], 16);
        assert_eq!(out[7 * 16 + 7], 53);
        assert_eq!(out[255], 94);
        // DC: sum(top) = 2*120 + 160 = 400; sum(left) = 3*120 + 320 = 680;
        // (1080 + 16) >> 5 = 34.
        assert_eq!(predict_16x16(2, &n).unwrap(), [34; 256]);
        assert_eq!(predict_16x16(0, &n).unwrap()[16 * 5 + 3], 16);
        assert_eq!(predict_16x16(1, &n).unwrap()[16 * 5 + 3], 35);
        let none = Neighbors16x16::default();
        assert_eq!(predict_16x16(2, &none).unwrap(), [128; 256]);
        assert_eq!(predict_16x16(3, &none).unwrap_err(), DecodeError::Malformed);
    }

    /// Chroma DC per 4x4 quadrant (8.3.4.1-3) with top = 8 x 40 then
    /// 4 x 80, left = 4 x 100 then 4 x 20:
    /// block 0 (both): (160 + 400 + 4) >> 3 = 70; block 1 (top-right,
    /// prefers top): (320 + 2) >> 2 = 80; block 2 (bottom-left, prefers
    /// left): (80 + 2) >> 2 = 20; block 3 (both): (320 + 80 + 4) >> 3 = 50.
    #[test]
    fn chroma_dc_quadrant_rules() {
        let n = NeighborsChroma {
            top: Some([40, 40, 40, 40, 80, 80, 80, 80]),
            left: Some([100, 100, 100, 100, 20, 20, 20, 20]),
            top_left: None,
        };
        let out = predict_chroma(0, &n).unwrap();
        assert_eq!(out[0], 70);
        assert_eq!(out[4], 80);
        assert_eq!(out[4 * 8], 20);
        assert_eq!(out[4 * 8 + 4], 50);
        // Top only: bottom-left falls back to top (40), bottom-right uses
        // top over its own columns (80).
        let top_only = NeighborsChroma { left: None, ..n };
        let out = predict_chroma(0, &top_only).unwrap();
        assert_eq!([out[0], out[4], out[32], out[36]], [40, 80, 40, 80]);
    }

    /// Intra 8x8 reference filtering (8.3.2.2.1) and prediction, by hand.
    /// Neighbours: top t[x] = 10(x+1), x = 0..15; left l[y] = 100 + 10y;
    /// Q = 50. Filtered: p'[0,-1] = (Q + 2 t0 + t1 + 2) >> 2 = 92 >> 2 = 23;
    /// interior of a ramp is unchanged (t[x]); p'[15,-1] = (t14 + 3 t15 +
    /// 2) >> 2 = 632 >> 2 = 158; p'[-1,0] = (Q + 2 l0 + l1 + 2) >> 2 = 90;
    /// p'[-1,7] = (l6 + 3 l7 + 2) >> 2 = 168; p'[-1,-1] = (t0 + 2Q + l0 +
    /// 2) >> 2 = 53.
    #[test]
    fn intra8x8_filtering_and_modes_by_hand() {
        let n = Neighbors8x8 {
            top: Some(std::array::from_fn(|x| u8::try_from(10 * (x + 1)).unwrap())),
            left: Some(std::array::from_fn(|y| u8::try_from(100 + 10 * y).unwrap())),
            top_left: Some(50),
        };
        let f = filter_8x8_neighbours(&n);
        let top = f.top.unwrap();
        assert_eq!(top[0], 23);
        assert_eq!(
            &top[1..15],
            &[20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150]
        );
        assert_eq!(top[15], 158);
        assert_eq!(f.left.unwrap(), [90, 110, 120, 130, 140, 150, 160, 168]);
        assert_eq!(f.top_left, Some(53));
        // Vertical: every row is p'[0..8, -1].
        let vertical = predict_8x8(0, &n).unwrap();
        for y in 0..8 {
            assert_eq!(
                &vertical[y * 8..y * 8 + 8],
                &[23, 20, 30, 40, 50, 60, 70, 80]
            );
        }
        // Horizontal: row y is p'[-1, y].
        let horizontal = predict_8x8(1, &n).unwrap();
        assert_eq!(horizontal[7 * 8], 168);
        assert_eq!(horizontal[8], 110);
        // DC: (373 + 1068 + 8) >> 4 = 90.
        assert_eq!(predict_8x8(2, &n).unwrap(), [90; 64]);
        // Diagonal down-left: (0,0) = (23 + 40 + 30 + 2) >> 2 = 23;
        // (7,7) = (p'14 + 3 p'15 + 2) >> 2 = (150 + 474 + 2) >> 2 = 156.
        let ddl = predict_8x8(3, &n).unwrap();
        assert_eq!((ddl[0], ddl[63]), (23, 156));
        // Top-right unavailable: the caller substitutes p[7,-1] = 80, so
        // p'[7,-1] = (70 + 160 + 80 + 2) >> 2 = 78 and p'[15,-1] = 80.
        let mut substituted = n;
        if let Some(t) = substituted.top.as_mut() {
            for value in &mut t[8..] {
                *value = 80;
            }
        }
        let f = filter_8x8_neighbours(&substituted);
        let top = f.top.unwrap();
        assert_eq!((top[7], top[8], top[15]), (78, 80, 80));
        // Missing neighbours for a directional mode are Malformed.
        let no_top = Neighbors8x8 { top: None, ..n };
        assert_eq!(predict_8x8(0, &no_top).unwrap_err(), DecodeError::Malformed);
        assert_eq!(predict_8x8(9, &n).unwrap_err(), DecodeError::Malformed);
    }

    /// Chroma plane with flat neighbours 60 and Q = 60 yields 60 everywhere
    /// (H = V = 0, a = 1920, (1920 + 16) >> 5 = 60).
    #[test]
    fn chroma_plane_flat() {
        let n = NeighborsChroma {
            top: Some([60; 8]),
            left: Some([60; 8]),
            top_left: Some(60),
        };
        assert_eq!(predict_chroma(3, &n).unwrap(), [60; 64]);
        assert_eq!(predict_chroma(1, &n).unwrap(), [60; 64]);
        assert_eq!(predict_chroma(4, &n).unwrap_err(), DecodeError::Malformed);
    }
}
