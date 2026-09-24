//! Intra sample prediction (ITU-T H.265 clause 8.4.4.2): reference sample
//! substitution, filtering (including strong intra smoothing), and the
//! planar, DC and 33 angular predictors.
//!
//! Reference samples are held in one linear array of `4 * n + 1` entries in
//! the order of the substitution process (clause 8.4.4.2.2): index 0 is
//! `p[-1][2n-1]`, index `2n - 1` is `p[-1][0]`, index `2n` is the corner
//! `p[-1][-1]`, and index `2n + 1 + x` is `p[x][-1]`.

use crate::tables::{INTRA_PRED_ANGLE, INV_ANGLE};

/// `INTRA_PLANAR`.
pub(crate) const PLANAR: u8 = 0;
/// `INTRA_DC`.
pub(crate) const DC: u8 = 1;

/// Substitutes unavailable reference samples (clause 8.4.4.2.2) in place.
pub(crate) fn substitute(samples: &mut [u8], available: &[bool]) {
    let Some(first) = available.iter().position(|&a| a) else {
        samples.fill(128);
        return;
    };
    if first != 0 {
        samples[0] = samples[first];
    }
    for i in 1..samples.len() {
        if !available[i] {
            samples[i] = samples[i - 1];
        }
    }
}

/// Filters the reference samples when clause 8.4.4.2.3 asks for it and
/// returns the (possibly filtered) array.
pub(crate) fn filter(
    samples: &[u8],
    n: usize,
    mode: u8,
    luma: bool,
    strong_enabled: bool,
) -> Vec<u8> {
    let mut out = samples.to_vec();
    if !luma || mode == DC || n == 4 {
        return out;
    }
    let dist = (i32::from(mode) - 26)
        .abs()
        .min((i32::from(mode) - 10).abs());
    let threshold = match n {
        8 => 7,
        16 => 1,
        _ => 0,
    };
    if dist <= threshold {
        return out;
    }
    let len = 4 * n + 1;
    let corner = i32::from(samples[2 * n]);
    let bottom = i32::from(samples[0]); // p[-1][2n-1]
    let right = i32::from(samples[len - 1]); // p[2n-1][-1]
    let mid_left = i32::from(samples[n]); // p[-1][n-1]
    let mid_top = i32::from(samples[3 * n]); // p[n-1][-1]
    if strong_enabled
        && n == 32
        && (corner + right - 2 * mid_top).abs() < 8
        && (corner + bottom - 2 * mid_left).abs() < 8
    {
        // Equations 8-35..8-39 (bi-linear interpolation, 64 = 2n).
        for y in 0..63usize {
            let value = ((63 - y as i32) * corner + (y as i32 + 1) * bottom + 32) >> 6;
            out[2 * n - 1 - y] = value as u8;
        }
        for x in 0..63usize {
            let value = ((63 - x as i32) * corner + (x as i32 + 1) * right + 32) >> 6;
            out[2 * n + 1 + x] = value as u8;
        }
        return out;
    }
    for i in 1..len - 1 {
        let sum =
            i32::from(samples[i - 1]) + 2 * i32::from(samples[i]) + i32::from(samples[i + 1]) + 2;
        out[i] = (sum >> 2) as u8;
    }
    out
}

/// Predicts an `n x n` block into `out` (row-major, stride `n`) from the
/// substituted and filtered reference array.
pub(crate) fn predict(refs: &[u8], n: usize, mode: u8, luma: bool, out: &mut [u8]) {
    let left = |y: isize| i32::from(refs[(2 * n as isize - 1 - y) as usize]);
    let top = |x: isize| i32::from(refs[(2 * n as isize + 1 + x) as usize]);
    let log2 = n.trailing_zeros();
    match mode {
        PLANAR => {
            let ni = n as i32;
            for y in 0..n {
                for x in 0..n {
                    let (xi, yi) = (x as i32, y as i32);
                    let value = (ni - 1 - xi) * left(y as isize)
                        + (xi + 1) * top(n as isize)
                        + (ni - 1 - yi) * top(x as isize)
                        + (yi + 1) * left(n as isize)
                        + ni;
                    out[y * n + x] = (value >> (log2 + 1)) as u8;
                }
            }
        }
        DC => {
            let mut sum = n as i32;
            for i in 0..n as isize {
                sum += left(i) + top(i);
            }
            let dc = sum >> (log2 + 1);
            out[..n * n].fill(dc as u8);
            if luma && n < 32 {
                out[0] = ((left(0) + 2 * dc + top(0) + 2) >> 2) as u8;
                for (x, sample) in out.iter_mut().enumerate().take(n).skip(1) {
                    *sample = ((top(x as isize) + 3 * dc + 2) >> 2) as u8;
                }
                for y in 1..n {
                    out[y * n] = ((left(y as isize) + 3 * dc + 2) >> 2) as u8;
                }
            }
        }
        _ => angular(refs, n, mode, luma, out),
    }
}

fn angular(refs: &[u8], n: usize, mode: u8, luma: bool, out: &mut [u8]) {
    let angle = INTRA_PRED_ANGLE[usize::from(mode) - 2];
    let left = |y: isize| i32::from(refs[(2 * n as isize - 1 - y) as usize]);
    let top = |x: isize| i32::from(refs[(2 * n as isize + 1 + x) as usize]);
    let ni = n as isize;
    // ref[] indexed from -n..=2n, stored at offset n.
    let mut reference = [0i32; 3 * 32 + 1];
    let at = |i: isize| (i + ni) as usize;
    let vertical = mode >= 18;
    // main(x) runs along the prediction direction's reference edge,
    // side(y) along the other edge.
    let main = |i: isize| if vertical { top(i) } else { left(i) };
    let side = |i: isize| if vertical { left(i) } else { top(i) };
    for x in 0..=ni {
        reference[at(x)] = main(x - 1);
    }
    let last = (ni * angle as isize) >> 5;
    if angle < 0 {
        if last < -1 {
            let inv = INV_ANGLE[usize::from(mode) - 11] as isize;
            for x in last..=-1 {
                reference[at(x)] = side(-1 + ((x * inv + 128) >> 8));
            }
        }
    } else {
        for x in ni + 1..=2 * ni {
            reference[at(x)] = main(x - 1);
        }
    }
    for y in 0..ni {
        let idx = ((y + 1) * angle as isize) >> 5;
        let fact = (((y + 1) * angle as isize) & 31) as i32;
        for x in 0..ni {
            let a = reference[at(x + idx + 1)];
            let value = if fact == 0 {
                a
            } else {
                let b = reference[at(x + idx + 2)];
                ((32 - fact) * a + fact * b + 16) >> 5
            };
            let (row, col) = if vertical { (y, x) } else { (x, y) };
            out[row as usize * n + col as usize] = value as u8;
        }
    }
    if luma && n < 32 {
        if mode == 26 {
            for y in 0..ni {
                let value = top(0) + ((left(y) - left(-1)) >> 1);
                out[y as usize * n] = value.clamp(0, 255) as u8;
            }
        } else if mode == 10 {
            for x in 0..ni {
                let value = left(0) + ((top(x) - top(-1)) >> 1);
                out[x as usize] = value.clamp(0, 255) as u8;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds the linear array from left (y = 0..2n-1), corner and top
    /// (x = 0..2n-1).
    fn linear(left: &[u8], corner: u8, top: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = left.iter().rev().copied().collect();
        out.push(corner);
        out.extend_from_slice(top);
        out
    }

    /// Clause 8.4.4.2.2 by hand: nothing available -> 128; only the top
    /// row available -> everything below takes top[0] (the search reaches
    /// index 2n + 1 first), then left propagates upward.
    #[test]
    fn substitution_by_hand() {
        let mut samples = vec![7u8; 17];
        substitute(&mut samples, &[false; 17]);
        assert!(samples.iter().all(|&v| v == 128));
        let mut samples: Vec<u8> = (0..17).collect();
        let mut available = vec![false; 17];
        for flag in available.iter_mut().skip(9) {
            *flag = true;
        }
        substitute(&mut samples, &available);
        assert_eq!(&samples[..10], &[9; 10]);
        assert_eq!(&samples[10..], &[10, 11, 12, 13, 14, 15, 16]);
        // Only the bottom-left available: it propagates to every later
        // unavailable entry.
        let mut samples: Vec<u8> = (0..17).map(|v| v + 50).collect();
        let mut available = vec![false; 17];
        available[0] = true;
        available[1] = true;
        substitute(&mut samples, &available);
        assert_eq!(&samples[..2], &[50, 51]);
        assert!(samples[2..].iter().all(|&v| v == 51));
    }

    /// 4x4 DC by hand: left all 10, top all 30 -> dc = (4 + 40 + 120) >> 3
    /// = 20; luma edge: (10 + 40 + 30 + 2) >> 2 = 20, top row
    /// (30 + 60 + 2) >> 2 = 23, left column (10 + 60 + 2) >> 2 = 18.
    #[test]
    fn dc_by_hand() {
        let refs = linear(&[10; 8], 99, &[30; 8]);
        let mut out = [0u8; 16];
        predict(&refs, 4, DC, true, &mut out);
        assert_eq!(out[0], 20);
        assert_eq!(&out[1..4], &[23, 23, 23]);
        assert_eq!(out[4], 18);
        assert_eq!(out[5], 20);
        predict(&refs, 4, DC, false, &mut out);
        assert!(out.iter().all(|&v| v == 20));
    }

    /// 4x4 planar by hand with left = 0.., top = 100: at (0, 0):
    /// (3 * left[0] + 1 * top[4] + 3 * top[0] + 1 * left[4] + 4) >> 3.
    #[test]
    fn planar_by_hand() {
        let left = [0u8, 8, 16, 24, 32, 40, 48, 56];
        let refs = linear(&left, 0, &[100; 8]);
        let mut out = [0u8; 16];
        predict(&refs, 4, PLANAR, true, &mut out);
        // (3 * 0 + 1 * 100 + 3 * 100 + 1 * 32 + 4) >> 3 = 436 >> 3 = 54.
        assert_eq!(out[0], 54);
        // (3, 3): (0 * 24 + 4 * 100 + 0 * 100 + 4 * 32 + 4) >> 3 = 66.
        assert_eq!(out[15], 66);
    }

    /// Pure vertical (mode 26) and horizontal (mode 10) copy with the
    /// luma edge filters; mode 34 (angle 32) copies top[x + y + 1] and
    /// mode 2 copies left[x + y + 1].
    #[test]
    fn angular_by_hand() {
        let left = [10u8, 20, 30, 40, 50, 60, 70, 80];
        let top = [100u8, 110, 120, 130, 140, 150, 160, 170];
        let refs = linear(&left, 5, &top);
        let mut out = [0u8; 16];
        predict(&refs, 4, 26, false, &mut out);
        assert_eq!(&out[..4], &[100, 110, 120, 130]);
        assert_eq!(&out[12..], &[100, 110, 120, 130]);
        predict(&refs, 4, 26, true, &mut out);
        // p[0][y] = top[0] + ((left[y] - corner) >> 1).
        assert_eq!(out[0], 100 + ((10 - 5) >> 1));
        assert_eq!(out[12], 100 + ((40 - 5) >> 1));
        predict(&refs, 4, 10, true, &mut out);
        assert_eq!(
            &out[1..4],
            &[
                10 + ((110 - 5) >> 1),
                10 + ((120 - 5) >> 1),
                10 + ((130 - 5) >> 1)
            ]
        );
        assert_eq!(out[4], 20);
        predict(&refs, 4, 34, true, &mut out);
        assert_eq!(out[0], 110);
        assert_eq!(out[15], 170);
        predict(&refs, 4, 2, true, &mut out);
        assert_eq!(out[0], 20);
        assert_eq!(out[15], 80);
        // Mode 18 (angle -32): p[x][y] = ref[x - y], the diagonal from
        // the corner: (0,0) corner, (1,0) top[0], (0,1) left[0].
        predict(&refs, 4, 18, true, &mut out);
        assert_eq!((out[0], out[1], out[4]), (5, 100, 10));
    }

    /// Filter decision: 8x8 needs a distance above 7 (mode 2: min(24, 8)
    /// = 8 -> filtered; mode 9: 1 -> not), 16x16 above 1, chroma never.
    #[test]
    fn filtering_rules_by_hand() {
        let samples: Vec<u8> = (0..33).map(|v| (v * 3) as u8).collect();
        assert_eq!(filter(&samples, 8, 9, true, false), samples);
        let filtered = filter(&samples, 8, 2, true, false);
        // A linear ramp is a fixed point of the [1 2 1] / 4 filter.
        assert_eq!(filtered, samples);
        let mut bumpy = samples.clone();
        bumpy[5] = 200;
        let filtered = filter(&bumpy, 8, 2, true, false);
        assert_eq!(filtered[5], ((12 + 400 + 18 + 2) >> 2) as u8);
        assert_eq!(filter(&bumpy, 8, 2, false, false), bumpy);
        assert_eq!(filter(&bumpy, 4, 2, true, false), bumpy);
    }
}
