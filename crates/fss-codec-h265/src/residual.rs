//! `residual_coding()` (ITU-T H.265 clause 7.3.8.11) with the context
//! selection of clauses 9.3.4.2.4..9.3.4.2.7 and the binarisations of
//! clause 9.3.3: last significant position, coded sub-block flags,
//! significance, greater-1/greater-2 flags, Rice/exp-Golomb remainders
//! and sign data hiding.

use crate::DecodeError;
use crate::cabac::SliceCabac;
use crate::cabac_tables::{
    COEFF_ABS_LEVEL_GREATER1_FLAG, COEFF_ABS_LEVEL_GREATER2_FLAG, LAST_SIGNIFICANT_COEFF_X_PREFIX,
    LAST_SIGNIFICANT_COEFF_Y_PREFIX, SIGNIFICANT_COEFF_FLAG, SIGNIFICANT_COEFF_GROUP_FLAG,
    TRANSFORM_SKIP_FLAG,
};
use crate::tables::scan_order;

/// `ctxIdxMap` for 4x4 blocks (equation 9-55).
const CTX_IDX_MAP: [u8; 16] = [0, 1, 4, 5, 2, 3, 4, 5, 6, 6, 8, 8, 7, 7, 8, 8];

/// Precomputed scan orders: `[scan_idx][log2 size of the grid]`.
pub(crate) struct Scans {
    orders: [[Vec<(u8, u8)>; 4]; 3],
}

impl Scans {
    pub fn new() -> Self {
        Self {
            orders: std::array::from_fn(|scan| {
                std::array::from_fn(|log2| scan_order(scan as u8, 1 << log2))
            }),
        }
    }

    fn get(&self, scan_idx: u8, log2: u32) -> &[(u8, u8)] {
        &self.orders[usize::from(scan_idx.min(2))][(log2 as usize).min(3)]
    }
}

/// Syntax-level inputs of one residual block.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ResidualParams {
    /// `log2TrafoSize` of this (luma or chroma) block.
    pub log2: u32,
    /// Colour component.
    pub c_idx: usize,
    /// `scanIdx` (0 diagonal, 1 horizontal, 2 vertical).
    pub scan_idx: u8,
    /// `sign_data_hiding_enabled_flag && !cu_transquant_bypass_flag`.
    pub sign_hiding: bool,
    /// `transform_skip_flag` may be present.
    pub transform_skip_allowed: bool,
}

/// Parses one residual block into `levels` (row-major, `y * size + x`,
/// which must be zeroed by the caller) and returns `transform_skip_flag`.
pub(crate) fn residual_coding(
    cabac: &mut SliceCabac<'_>,
    scans: &Scans,
    params: ResidualParams,
    levels: &mut [i32],
) -> Result<bool, DecodeError> {
    let ResidualParams {
        log2,
        c_idx,
        scan_idx,
        sign_hiding,
        transform_skip_allowed,
    } = params;
    let chroma = c_idx > 0;
    let size = 1usize << log2;
    let transform_skip =
        transform_skip_allowed && cabac.flag(TRANSFORM_SKIP_FLAG + usize::from(chroma))?;

    // last_sig_coeff_{x,y}_prefix (clause 9.3.4.2.3).
    let (offset, shift) = if chroma {
        (15usize, log2 - 2)
    } else {
        (
            3 * (log2 as usize - 2) + ((log2 as usize - 1) >> 2),
            (log2 + 1) >> 2,
        )
    };
    let max_prefix = 2 * log2 - 1;
    let mut prefix = [0u32; 2];
    for (axis, base) in [
        LAST_SIGNIFICANT_COEFF_X_PREFIX,
        LAST_SIGNIFICANT_COEFF_Y_PREFIX,
    ]
    .into_iter()
    .enumerate()
    {
        while prefix[axis] < max_prefix
            && cabac.flag(base + offset + (prefix[axis] >> shift) as usize)?
        {
            prefix[axis] += 1;
        }
    }
    let mut last = [0u32; 2];
    for axis in 0..2 {
        let p = prefix[axis];
        last[axis] = if p > 3 {
            let bits = (p >> 1) - 1;
            let suffix = cabac.bypass_bits(bits)?;
            (1 << bits) * (2 + (p & 1)) + suffix
        } else {
            p
        };
    }
    let (mut last_x, mut last_y) = (last[0] as usize, last[1] as usize);
    if scan_idx == 2 {
        std::mem::swap(&mut last_x, &mut last_y);
    }
    if last_x >= size || last_y >= size {
        return Err(DecodeError::Malformed);
    }

    let sub_log2 = log2 - 2;
    let sub_size = 1usize << sub_log2;
    let sub_scan = scans.get(scan_idx, sub_log2);
    let scan = scans.get(scan_idx, 2);
    let last_sub = sub_scan
        .iter()
        .position(|&(x, y)| usize::from(x) == last_x >> 2 && usize::from(y) == last_y >> 2)
        .ok_or(DecodeError::Malformed)?;
    let last_pos = scan
        .iter()
        .position(|&(x, y)| usize::from(x) == last_x & 3 && usize::from(y) == last_y & 3)
        .ok_or(DecodeError::Malformed)?;

    let mut coded = [[false; 8]; 8];
    let mut greater1_state = 1u8;
    for i in (0..=last_sub).rev() {
        let (xs, ys) = (usize::from(sub_scan[i].0), usize::from(sub_scan[i].1));
        let right = xs + 1 < sub_size && coded[xs + 1][ys];
        let below = ys + 1 < sub_size && coded[xs][ys + 1];
        let mut infer_dc = false;
        if i < last_sub && i > 0 {
            let ctx = usize::from(right || below) + if chroma { 2 } else { 0 };
            coded[xs][ys] = cabac.flag(SIGNIFICANT_COEFF_GROUP_FLAG + ctx)?;
            infer_dc = true;
        } else {
            coded[xs][ys] = true;
        }
        let prev_csbf = usize::from(right) + 2 * usize::from(below);

        // Significant positions (scan index n), highest n first.
        let mut sig = [0u8; 16];
        let mut count = 0usize;
        let start = if i == last_sub {
            sig[0] = last_pos as u8;
            count = 1;
            last_pos as isize - 1
        } else {
            15
        };
        if coded[xs][ys] {
            let mut n = start;
            while n >= 0 {
                let (xp, yp) = (
                    usize::from(scan[n as usize].0),
                    usize::from(scan[n as usize].1),
                );
                if n > 0 || !infer_dc {
                    let ctx = sig_ctx(log2, chroma, (xs, ys), (xp, yp), prev_csbf, scan_idx);
                    if cabac.flag(SIGNIFICANT_COEFF_FLAG + ctx)? {
                        sig[count] = n as u8;
                        count += 1;
                        infer_dc = false;
                    }
                } else {
                    // n == 0 with every other flag of the group zero.
                    sig[count] = 0;
                    count += 1;
                }
                n -= 1;
            }
        }
        if count == 0 {
            continue;
        }

        // Greater-1 / greater-2 flags (clauses 9.3.4.2.6, 9.3.4.2.7).
        let mut ctx_set = if i == 0 || chroma { 0 } else { 2 };
        if i != last_sub && greater1_state == 0 {
            ctx_set += 1;
        }
        let mut greater1_ctx = 1u8;
        let mut g1 = [0u8; 8];
        let mut first_g1: Option<usize> = None;
        for (m, flag) in g1.iter_mut().enumerate().take(count.min(8)) {
            let ctx = ctx_set * 4 + usize::from(greater1_ctx) + if chroma { 16 } else { 0 };
            *flag = cabac.bin(COEFF_ABS_LEVEL_GREATER1_FLAG + ctx)?;
            if *flag == 1 {
                greater1_ctx = 0;
                first_g1.get_or_insert(m);
            } else if greater1_ctx > 0 && greater1_ctx < 3 {
                greater1_ctx += 1;
            }
        }
        greater1_state = greater1_ctx;
        if let Some(m) = first_g1 {
            let ctx = ctx_set + if chroma { 4 } else { 0 };
            g1[m] += cabac.bin(COEFF_ABS_LEVEL_GREATER2_FLAG + ctx)?;
        }
        let hidden = sign_hiding && i32::from(sig[0]) - i32::from(sig[count - 1]) > 3;
        let sign_count = if hidden { count - 1 } else { count };
        // Sign bits left-aligned in a u32 (at most 16 of them).
        let signs = cabac.bypass_bits(sign_count as u32)? << (32 - sign_count as u32).min(31);
        let mut rice = 0u32;
        let mut sum_abs = 0i64;
        for m in 0..count {
            let base = if m < 8 { 1 + i64::from(g1[m]) } else { 1 };
            let threshold = if m < 8 {
                if Some(m) == first_g1 { 3 } else { 2 }
            } else {
                1
            };
            let mut level = base;
            if base == threshold {
                let remaining = abs_level_remaining(cabac, rice)?;
                level += i64::from(remaining);
                if level > 3 * (1i64 << rice) {
                    rice = (rice + 1).min(4);
                }
            }
            sum_abs += level;
            let n = usize::from(sig[m]);
            let negative = if m < sign_count {
                (signs >> (31 - m)) & 1 == 1
            } else {
                // Hidden sign of the last (lowest-frequency) coefficient.
                sum_abs & 1 == 1
            };
            let x = (xs << 2) + usize::from(scan[n].0);
            let y = (ys << 2) + usize::from(scan[n].1);
            let value = if negative { -level } else { level };
            levels[y * size + x] = value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32;
        }
    }
    Ok(transform_skip)
}

/// `sigCtx` / ctxInc of `sig_coeff_flag` (clause 9.3.4.2.5).
fn sig_ctx(
    log2: u32,
    chroma: bool,
    (xs, ys): (usize, usize),
    (xp, yp): (usize, usize),
    prev_csbf: usize,
    scan_idx: u8,
) -> usize {
    let (xc, yc) = ((xs << 2) + xp, (ys << 2) + yp);
    let sig = if log2 == 2 {
        usize::from(CTX_IDX_MAP[(yc << 2) + xc])
    } else if xc + yc == 0 {
        0
    } else {
        let mut sig = match prev_csbf {
            0 => {
                if xp + yp == 0 {
                    2
                } else if xp + yp < 3 {
                    1
                } else {
                    0
                }
            }
            1 => match yp {
                0 => 2,
                1 => 1,
                _ => 0,
            },
            2 => match xp {
                0 => 2,
                1 => 1,
                _ => 0,
            },
            _ => 2,
        };
        if chroma {
            sig += if log2 == 3 { 9 } else { 12 };
        } else {
            if xs + ys > 0 {
                sig += 3;
            }
            sig += if log2 == 3 {
                if scan_idx == 0 { 9 } else { 15 }
            } else {
                21
            };
        }
        sig
    };
    if chroma { 27 + sig } else { sig }
}

/// `coeff_abs_level_remaining` (clause 9.3.3.11): a Rice prefix of up to
/// three ones with `rice` suffix bits, else an exp-Golomb escape of order
/// `rice + 1`.
fn abs_level_remaining(cabac: &mut SliceCabac<'_>, rice: u32) -> Result<u32, DecodeError> {
    let mut prefix = 0u32;
    while cabac.bypass()? == 1 {
        prefix += 1;
        if prefix >= 32 {
            return Err(DecodeError::Malformed);
        }
    }
    if prefix < 3 {
        let suffix = cabac.bypass_bits(rice)?;
        return Ok((prefix << rice) + suffix);
    }
    let extra = prefix - 3;
    if extra + rice > 22 {
        return Err(DecodeError::Malformed);
    }
    let suffix = cabac.bypass_bits(extra + rice)?;
    Ok((((1u32 << extra) + 3 - 1) << rice) + suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Clause 9.3.4.2.5 by hand. 4x4 luma: ctxIdxMap. 8x8 luma DC: 0.
    /// 8x8 luma at (1, 0) of sub-block (0, 0), prevCsbf 0: xP + yP = 1 < 3
    /// -> 1, + 9 (diagonal 8x8) = 10. 16x16 luma sub-block (1, 0) at
    /// (0, 0), prevCsbf 3: 2 + 3 + 21 = 26. Chroma 8x8 (0, 1) prevCsbf 1:
    /// yP 1 -> 1 + 9 + 27 = 37.
    #[test]
    fn significance_context_by_hand() {
        assert_eq!(sig_ctx(2, false, (0, 0), (3, 3), 0, 0), 8);
        assert_eq!(sig_ctx(2, false, (0, 0), (1, 2), 0, 0), 6);
        assert_eq!(sig_ctx(2, true, (0, 0), (2, 0), 0, 0), 27 + 4);
        assert_eq!(sig_ctx(3, false, (0, 0), (0, 0), 0, 0), 0);
        assert_eq!(sig_ctx(3, false, (0, 0), (1, 0), 0, 0), 10);
        assert_eq!(sig_ctx(3, false, (0, 0), (1, 0), 0, 1), 16);
        assert_eq!(sig_ctx(4, false, (1, 0), (0, 0), 3, 0), 26);
        assert_eq!(sig_ctx(3, true, (0, 0), (0, 1), 1, 0), 37);
    }
}
