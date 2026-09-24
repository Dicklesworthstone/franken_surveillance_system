//! Inter prediction sample interpolation (clause 8.4.2.2): quarter-sample
//! luma with the 6-tap filter and eighth-sample 4:2:0 chroma bilinear
//! interpolation, both with reference-edge clamping.

use crate::picture::Frame;

/// Reference plane view with coordinate clamping (8-228/8-229).
struct Plane<'a> {
    samples: &'a [u8],
    width: i32,
    height: i32,
}

impl Plane<'_> {
    fn at(&self, x: i32, y: i32) -> i32 {
        let cx = x.clamp(0, self.width - 1);
        let cy = y.clamp(0, self.height - 1);
        // Clamped coordinates are in range by construction; a malformed
        // plane (never produced by Frame::new) reads as 0 instead of panicking.
        usize::try_from(cy * self.width + cx)
            .ok()
            .and_then(|i| self.samples.get(i))
            .map_or(0, |&v| i32::from(v))
    }
}

const fn tap6(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) -> i32 {
    a - 5 * b + 20 * c + 20 * d - 5 * e + f
}

fn clip(value: i32) -> i32 {
    value.clamp(0, 255)
}

/// Unscaled horizontal half-sample intermediate between (x,y) and (x+1,y).
fn b1(p: &Plane<'_>, x: i32, y: i32) -> i32 {
    tap6(
        p.at(x - 2, y),
        p.at(x - 1, y),
        p.at(x, y),
        p.at(x + 1, y),
        p.at(x + 2, y),
        p.at(x + 3, y),
    )
}

/// Unscaled vertical half-sample intermediate between (x,y) and (x,y+1).
fn h1(p: &Plane<'_>, x: i32, y: i32) -> i32 {
    tap6(
        p.at(x, y - 2),
        p.at(x, y - 1),
        p.at(x, y),
        p.at(x, y + 1),
        p.at(x, y + 2),
        p.at(x, y + 3),
    )
}

fn half_h(p: &Plane<'_>, x: i32, y: i32) -> i32 {
    clip((b1(p, x, y) + 16) >> 5)
}

fn half_v(p: &Plane<'_>, x: i32, y: i32) -> i32 {
    clip((h1(p, x, y) + 16) >> 5)
}

fn centre(p: &Plane<'_>, x: i32, y: i32) -> i32 {
    let j1 = tap6(
        b1(p, x, y - 2),
        b1(p, x, y - 1),
        b1(p, x, y),
        b1(p, x, y + 1),
        b1(p, x, y + 2),
        b1(p, x, y + 3),
    );
    clip((j1 + 512) >> 10)
}

/// One luma prediction sample at integer position (x, y) plus fraction.
fn luma_sample(p: &Plane<'_>, x: i32, y: i32, fx: i32, fy: i32) -> i32 {
    let avg = |a: i32, b: i32| (a + b + 1) >> 1;
    match (fx, fy) {
        (0, 0) => p.at(x, y),
        (1, 0) => avg(p.at(x, y), half_h(p, x, y)),
        (2, 0) => half_h(p, x, y),
        (3, 0) => avg(half_h(p, x, y), p.at(x + 1, y)),
        (0, 1) => avg(p.at(x, y), half_v(p, x, y)),
        (0, 2) => half_v(p, x, y),
        (0, 3) => avg(half_v(p, x, y), p.at(x, y + 1)),
        (1, 1) => avg(half_h(p, x, y), half_v(p, x, y)),
        (3, 1) => avg(half_h(p, x, y), half_v(p, x + 1, y)),
        (1, 3) => avg(half_v(p, x, y), half_h(p, x, y + 1)),
        (3, 3) => avg(half_v(p, x + 1, y), half_h(p, x, y + 1)),
        (2, 1) => avg(half_h(p, x, y), centre(p, x, y)),
        (2, 3) => avg(centre(p, x, y), half_h(p, x, y + 1)),
        (1, 2) => avg(half_v(p, x, y), centre(p, x, y)),
        (3, 2) => avg(centre(p, x, y), half_v(p, x + 1, y)),
        _ => centre(p, x, y),
    }
}

/// A rectangular inter partition in luma sample units within the picture.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Block {
    pub x: usize,
    pub y: usize,
    pub width: usize,
    pub height: usize,
}

fn to_i32(value: usize) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

/// Writes the luma and chroma prediction of `block` from `reference` with
/// motion vector `mv` (quarter luma samples) into `target`.
pub(crate) fn predict_block(reference: &Frame, target: &mut Frame, block: Block, mv: [i32; 2]) {
    let luma = Plane {
        samples: &reference.y,
        width: to_i32(reference.width),
        height: to_i32(reference.height),
    };
    let (fx, fy) = (mv[0] & 3, mv[1] & 3);
    let (ox, oy) = (
        to_i32(block.x) + (mv[0] >> 2),
        to_i32(block.y) + (mv[1] >> 2),
    );
    for j in 0..block.height {
        for i in 0..block.width {
            let value = luma_sample(&luma, ox + to_i32(i), oy + to_i32(j), fx, fy);
            let index = (block.y + j) * target.width + block.x + i;
            if let Some(sample) = target.y.get_mut(index) {
                *sample = u8::try_from(value).unwrap_or(u8::MAX);
            }
        }
    }

    // 4:2:0 chroma: same vector in eighth-sample chroma units.
    let (cw, ch) = (reference.chroma_width(), reference.chroma_height());
    let (fx, fy) = (mv[0] & 7, mv[1] & 7);
    let (ox, oy) = (
        to_i32(block.x / 2) + (mv[0] >> 3),
        to_i32(block.y / 2) + (mv[1] >> 3),
    );
    let target_stride = target.chroma_width();
    for (source, destination) in [
        (&reference.cb, &mut target.cb),
        (&reference.cr, &mut target.cr),
    ] {
        let plane = Plane {
            samples: source,
            width: to_i32(cw),
            height: to_i32(ch),
        };
        for j in 0..block.height / 2 {
            for i in 0..block.width / 2 {
                let (x, y) = (ox + to_i32(i), oy + to_i32(j));
                let value = ((8 - fx) * (8 - fy) * plane.at(x, y)
                    + fx * (8 - fy) * plane.at(x + 1, y)
                    + (8 - fx) * fy * plane.at(x, y + 1)
                    + fx * fy * plane.at(x + 1, y + 1)
                    + 32)
                    >> 6;
                let index = (block.y / 2 + j) * target_stride + block.x / 2 + i;
                if let Some(sample) = destination.get_mut(index) {
                    *sample = u8::try_from(value.clamp(0, 255)).unwrap_or(u8::MAX);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn ramp_frame() -> Frame {
        // 16x16 luma, value = 4 * x (constant down columns), chroma = 8 * x.
        let mut frame = Frame::new(16, 16).unwrap();
        for y in 0..16 {
            for x in 0..16 {
                frame.y[y * 16 + x] = u8::try_from(4 * x).unwrap();
            }
        }
        for y in 0..8 {
            for x in 0..8 {
                frame.cb[y * 8 + x] = u8::try_from(8 * x).unwrap();
                frame.cr[y * 8 + x] = 100;
            }
        }
        frame
    }

    /// On a horizontal ramp v = 4x the 6-tap half-sample filter is exact
    /// away from edges: taps sum to 32 and are symmetric, so the half pel
    /// between x and x+1 is 4x + 2. Quarter pels average with the integer
    /// neighbour: (4x + 4x + 2 + 1) >> 1 = 4x + 1. Vertical fractions on a
    /// column-constant image change nothing.
    #[test]
    fn luma_fractions_on_a_ramp() {
        let reference = ramp_frame();
        let mut target = Frame::new(16, 16).unwrap();
        let block = Block {
            x: 4,
            y: 4,
            width: 4,
            height: 4,
        };
        predict_block(&reference, &mut target, block, [2, 0]);
        assert_eq!(target.y[4 * 16 + 4], 18); // 4*4 + 2
        predict_block(&reference, &mut target, block, [1, 0]);
        assert_eq!(target.y[4 * 16 + 4], 17);
        predict_block(&reference, &mut target, block, [3, 0]);
        // c = (b + H + 1) >> 1 = (18 + 20 + 1) >> 1 = 19.
        assert_eq!(target.y[4 * 16 + 4], 19);
        predict_block(&reference, &mut target, block, [0, 2]);
        assert_eq!(target.y[4 * 16 + 4], 16);
        // Centre j: vertical filtering of constant b1 columns gives
        // b1 * 32; (32 * 32 * 18 + 512) >> 10 = 18.
        predict_block(&reference, &mut target, block, [2, 2]);
        assert_eq!(target.y[4 * 16 + 4], 18);
        // Whole-sample move of +1 (mv 4): reads 4 * 5 = 20.
        predict_block(&reference, &mut target, block, [4, 0]);
        assert_eq!(target.y[4 * 16 + 4], 20);
    }

    /// Clamping: a vector pointing far left reads the column-0 value (0).
    #[test]
    fn luma_edge_clamping() {
        let reference = ramp_frame();
        let mut target = Frame::new(16, 16).unwrap();
        let block = Block {
            x: 0,
            y: 0,
            width: 4,
            height: 4,
        };
        predict_block(&reference, &mut target, block, [-400, -400]);
        assert!(target.y[..4].iter().all(|&v| v == 0));
        predict_block(&reference, &mut target, block, [400, 0]);
        assert!(target.y[..4].iter().all(|&v| v == 60));
    }

    /// Chroma eighth-sample: fx = 4 halfway between 8x and 8(x+1):
    /// (4*8*8x + 4*8*8(x+1) + 32) >> 6 = 8x + 4 (+32 rounds down exactly).
    /// fx = 1: (7*8*8x + 1*8*(8x+8) + 32) >> 6 = 8x + 1.
    #[test]
    fn chroma_eighth_sample() {
        let reference = ramp_frame();
        let mut target = Frame::new(16, 16).unwrap();
        let block = Block {
            x: 4,
            y: 4,
            width: 4,
            height: 4,
        };
        predict_block(&reference, &mut target, block, [4, 0]);
        assert_eq!(target.cb[2 * 8 + 2], 20);
        predict_block(&reference, &mut target, block, [1, 3]);
        assert_eq!(target.cb[2 * 8 + 2], 17);
        assert_eq!(target.cr[2 * 8 + 2], 100);
    }
}
