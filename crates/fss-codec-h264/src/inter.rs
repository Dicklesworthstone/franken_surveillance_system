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
#[cfg(test)]
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
#[cfg(test)]
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

#[cfg(test)]
fn half_h(p: &Plane<'_>, x: i32, y: i32) -> i32 {
    clip((b1(p, x, y) + 16) >> 5)
}

#[cfg(test)]
fn half_v(p: &Plane<'_>, x: i32, y: i32) -> i32 {
    clip((h1(p, x, y) + 16) >> 5)
}

#[cfg(test)]
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
#[cfg(test)]
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

/// Prediction samples of one 4x4 luma block and its two 2x2 chroma blocks
/// (4:2:0), raster order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlockPrediction {
    pub luma: [u8; 16],
    pub cb: [u8; 4],
    pub cr: [u8; 4],
}

/// Reference samples around one 4x4 luma block: rows and columns -2..=6 relative to the
/// block's integer origin, clamped to the picture (8-228/8-229) once per block instead of per
/// tap. Window position `p + 2` holds relative coordinate `p`.
struct LumaWindow([[i32; 9]; 9]);

impl LumaWindow {
    fn load(plane: &Plane<'_>, ox: i32, oy: i32) -> Self {
        let inside = ox >= 2 && oy >= 2 && ox + 6 < plane.width && oy + 6 < plane.height;
        Self(std::array::from_fn(|r| {
            let y = oy - 2 + to_i32(r);
            if inside {
                let start = usize::try_from(y * plane.width + ox - 2).unwrap_or(0);
                if let Some(row) = plane
                    .samples
                    .get(start..start + 9)
                    .and_then(|row| <&[u8; 9]>::try_from(row).ok())
                {
                    return row.map(i32::from);
                }
            }
            std::array::from_fn(|c| plane.at(ox - 2 + to_i32(c), y))
        }))
    }

    /// Unscaled horizontal half-sample intermediate at window position (x, y).
    fn b1(&self, x: usize, y: usize) -> i32 {
        let row = &self.0[y];
        tap6(
            row[x - 2],
            row[x - 1],
            row[x],
            row[x + 1],
            row[x + 2],
            row[x + 3],
        )
    }

    /// Unscaled vertical half-sample intermediate at window position (x, y).
    fn h1(&self, x: usize, y: usize) -> i32 {
        let w = &self.0;
        tap6(
            w[y - 2][x],
            w[y - 1][x],
            w[y][x],
            w[y + 1][x],
            w[y + 2][x],
            w[y + 3][x],
        )
    }

    fn half_h(&self, x: usize, y: usize) -> i32 {
        clip((self.b1(x, y) + 16) >> 5)
    }

    fn half_v(&self, x: usize, y: usize) -> i32 {
        clip((self.h1(x, y) + 16) >> 5)
    }
}

/// Luma prediction of one 4x4 block from its window: exactly the per-sample formulas of
/// `luma_sample`, with the centre (j) positions sharing one grid of horizontal intermediates.
fn predict_luma(window: &LumaWindow, fx: i32, fy: i32) -> [u8; 16] {
    let avg = |a: i32, b: i32| (a + b + 1) >> 1;
    // b1 at window rows 0..=8 for the block's four columns; only the j cases read it.
    let centre_grid = (fx == 2 || fy == 2) && (fx, fy) != (2, 0) && (fx, fy) != (0, 2);
    let mut b = [[0_i32; 4]; 9];
    if centre_grid {
        for (y, row) in b.iter_mut().enumerate() {
            for (i, value) in row.iter_mut().enumerate() {
                *value = window.b1(i + 2, y);
            }
        }
    }
    let centre = |i: usize, j: usize| {
        let column = |r: usize| b[j + r][i];
        clip(
            (tap6(
                column(0),
                column(1),
                column(2),
                column(3),
                column(4),
                column(5),
            ) + 512)
                >> 10,
        )
    };
    let w = &window.0;
    let mut out = [0_u8; 16];
    for j in 0..4 {
        for i in 0..4 {
            let (x, y) = (i + 2, j + 2);
            let value = match (fx, fy) {
                (0, 0) => w[y][x],
                (1, 0) => avg(w[y][x], window.half_h(x, y)),
                (2, 0) => window.half_h(x, y),
                (3, 0) => avg(window.half_h(x, y), w[y][x + 1]),
                (0, 1) => avg(w[y][x], window.half_v(x, y)),
                (0, 2) => window.half_v(x, y),
                (0, 3) => avg(window.half_v(x, y), w[y + 1][x]),
                (1, 1) => avg(window.half_h(x, y), window.half_v(x, y)),
                (3, 1) => avg(window.half_h(x, y), window.half_v(x + 1, y)),
                (1, 3) => avg(window.half_v(x, y), window.half_h(x, y + 1)),
                (3, 3) => avg(window.half_v(x + 1, y), window.half_h(x, y + 1)),
                (2, 1) => avg(window.half_h(x, y), centre(i, j)),
                (2, 3) => avg(centre(i, j), window.half_h(x, y + 1)),
                (1, 2) => avg(window.half_v(x, y), centre(i, j)),
                (3, 2) => avg(centre(i, j), window.half_v(x + 1, y)),
                _ => centre(i, j),
            };
            out[j * 4 + i] = u8::try_from(value).unwrap_or(u8::MAX);
        }
    }
    out
}

/// Full-sample luma prediction (both fractions zero): a direct 4x4 copy when the block lies
/// inside the picture, otherwise the clamped reads.
fn copy_luma(plane: &Plane<'_>, ox: i32, oy: i32) -> [u8; 16] {
    let inside = ox >= 0 && oy >= 0 && ox + 3 < plane.width && oy + 3 < plane.height;
    let mut out = [0_u8; 16];
    for (j, row) in out.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let y = oy + to_i32(j);
        if inside {
            let start = usize::try_from(y * plane.width + ox).unwrap_or(0);
            if let Some(source) = plane.samples.get(start..start + 4) {
                row.copy_from_slice(source);
                continue;
            }
        }
        for (i, sample) in row.iter_mut().enumerate() {
            *sample = u8::try_from(plane.at(ox + to_i32(i), y)).unwrap_or(u8::MAX);
        }
    }
    out
}

/// Chroma prediction of one 2x2 block: the 3x3 clamped window at (ox, oy), bilinear eighths.
fn predict_chroma(plane: &Plane<'_>, ox: i32, oy: i32, fx: i32, fy: i32) -> [u8; 4] {
    let inside = ox >= 0 && oy >= 0 && ox + 2 < plane.width && oy + 2 < plane.height;
    let window: [[i32; 3]; 3] = std::array::from_fn(|r| {
        let y = oy + to_i32(r);
        if inside {
            let start = usize::try_from(y * plane.width + ox).unwrap_or(0);
            if let Some(row) = plane
                .samples
                .get(start..start + 3)
                .and_then(|row| <&[u8; 3]>::try_from(row).ok())
            {
                return row.map(i32::from);
            }
        }
        std::array::from_fn(|c| plane.at(ox + to_i32(c), y))
    });
    if fx == 0 && fy == 0 {
        return [window[0][0], window[0][1], window[1][0], window[1][1]]
            .map(|value| u8::try_from(value).unwrap_or(u8::MAX));
    }
    let mut out = [0_u8; 4];
    for j in 0..2 {
        for i in 0..2 {
            let value = ((8 - fx) * (8 - fy) * window[j][i]
                + fx * (8 - fy) * window[j][i + 1]
                + (8 - fx) * fy * window[j + 1][i]
                + fx * fy * window[j + 1][i + 1]
                + 32)
                >> 6;
            out[j * 2 + i] = u8::try_from(value.clamp(0, 255)).unwrap_or(u8::MAX);
        }
    }
    out
}

/// Fractional sample interpolation (clause 8.4.2.2) of the 4x4 luma block
/// at picture position (x, y) and its co-sited 2x2 chroma blocks, from
/// `reference` displaced by `mv` (quarter luma samples).
pub(crate) fn predict_4x4(reference: &Frame, x: usize, y: usize, mv: [i32; 2]) -> BlockPrediction {
    let luma = Plane {
        samples: &reference.y,
        width: to_i32(reference.width),
        height: to_i32(reference.height),
    };
    let (fx, fy) = (mv[0] & 3, mv[1] & 3);
    let (ox, oy) = (to_i32(x) + (mv[0] >> 2), to_i32(y) + (mv[1] >> 2));
    let luma = if fx == 0 && fy == 0 {
        copy_luma(&luma, ox, oy)
    } else {
        predict_luma(&LumaWindow::load(&luma, ox, oy), fx, fy)
    };
    let (cw, ch) = (
        to_i32(reference.chroma_width()),
        to_i32(reference.chroma_height()),
    );
    let (fx, fy) = (mv[0] & 7, mv[1] & 7);
    let (ox, oy) = (to_i32(x / 2) + (mv[0] >> 3), to_i32(y / 2) + (mv[1] >> 3));
    let chroma = |samples: &[u8]| {
        let plane = Plane {
            samples,
            width: cw,
            height: ch,
        };
        predict_chroma(&plane, ox, oy, fx, fy)
    };
    BlockPrediction {
        luma,
        cb: chroma(&reference.cb),
        cr: chroma(&reference.cr),
    }
}

/// Whole-macroblock prediction for one reference and one vector that is a whole sample in
/// both luma and 4:2:0 chroma (both components multiples of 8 quarter-samples): the 16x16 luma
/// and two 8x8 chroma blocks are plain copies, exactly the samples [`predict_4x4`] yields for
/// each of the sixteen 4x4 blocks. Returns `false`, writing nothing, when the vector is
/// fractional or the source block reaches outside the reference picture (clamping applies).
pub(crate) fn copy_macroblock(
    reference: &Frame,
    target: &mut Frame,
    x: usize,
    y: usize,
    mv: [i32; 2],
) -> bool {
    if mv[0] & 7 != 0
        || mv[1] & 7 != 0
        || reference.width != target.width
        || reference.height != target.height
    {
        return false;
    }
    let (sx, sy) = (to_i32(x) + (mv[0] >> 2), to_i32(y) + (mv[1] >> 2));
    if sx < 0
        || sy < 0
        || sx + 16 > to_i32(reference.width)
        || sy + 16 > to_i32(reference.height)
        || x + 16 > target.width
        || y + 16 > target.height
    {
        return false;
    }
    let (sx, sy) = (sx as usize, sy as usize);
    let copy = |source: &[u8], destination: &mut [u8], stride: usize, size: usize, from, to| {
        let ((fx, fy), (tx, ty)): ((usize, usize), (usize, usize)) = (from, to);
        for row in 0..size {
            let (s, d) = ((fy + row) * stride + fx, (ty + row) * stride + tx);
            if let (Some(source), Some(destination)) =
                (source.get(s..s + size), destination.get_mut(d..d + size))
            {
                destination.copy_from_slice(source);
            }
        }
    };
    copy(
        &reference.y,
        &mut target.y,
        target.width,
        16,
        (sx, sy),
        (x, y),
    );
    let stride = target.chroma_width();
    let (from, to) = ((sx / 2, sy / 2), (x / 2, y / 2));
    copy(&reference.cb, &mut target.cb, stride, 8, from, to);
    copy(&reference.cr, &mut target.cr, stride, 8, from, to);
    true
}

/// The sixteen 4x4 block predictions of the macroblock at luma (x, y) for one vector that is a
/// whole sample in luma and 4:2:0 chroma (both components multiples of 8 quarter-samples), read
/// directly from `reference`: exactly what [`predict_4x4`] yields for each block. `None` when the
/// vector is fractional or the source reaches outside the picture (clamping applies).
pub(crate) fn gather_macroblock(
    reference: &Frame,
    x: usize,
    y: usize,
    mv: [i32; 2],
) -> Option<[BlockPrediction; 16]> {
    if mv[0] & 7 != 0 || mv[1] & 7 != 0 {
        return None;
    }
    let (sx, sy) = (to_i32(x) + (mv[0] >> 2), to_i32(y) + (mv[1] >> 2));
    if sx < 0 || sy < 0 || sx + 16 > to_i32(reference.width) || sy + 16 > to_i32(reference.height) {
        return None;
    }
    let (sx, sy) = (usize::try_from(sx).ok()?, usize::try_from(sy).ok()?);
    let (stride, chroma_stride) = (reference.width, reference.chroma_width());
    let mut out = [BlockPrediction {
        luma: [0; 16],
        cb: [0; 4],
        cr: [0; 4],
    }; 16];
    for (raster, block) in out.iter_mut().enumerate() {
        let (ox, oy) = ((raster % 4) * 4, (raster / 4) * 4);
        for j in 0..4 {
            let start = (sy + oy + j) * stride + sx + ox;
            block.luma[j * 4..j * 4 + 4].copy_from_slice(reference.y.get(start..start + 4)?);
        }
        let (cx, cy) = ((sx + ox) / 2, (sy + oy) / 2);
        for j in 0..2 {
            let start = (cy + j) * chroma_stride + cx;
            block.cb[j * 2..j * 2 + 2].copy_from_slice(reference.cb.get(start..start + 2)?);
            block.cr[j * 2..j * 2 + 2].copy_from_slice(reference.cr.get(start..start + 2)?);
        }
    }
    Some(out)
}

/// Stores a block prediction into the picture at luma position (x, y).
pub(crate) fn write_prediction(target: &mut Frame, x: usize, y: usize, p: &BlockPrediction) {
    let stride = target.width;
    for j in 0..4 {
        let start = (y + j) * stride + x;
        if let Some(row) = target.y.get_mut(start..start + 4) {
            row.copy_from_slice(&p.luma[j * 4..j * 4 + 4]);
        }
    }
    let cstride = target.chroma_width();
    let (cx, cy) = (x / 2, y / 2);
    for (plane, samples) in [(&mut target.cb, &p.cb), (&mut target.cr, &p.cr)] {
        for j in 0..2 {
            let start = (cy + j) * cstride + cx;
            if let Some(row) = plane.get_mut(start..start + 2) {
                row.copy_from_slice(&samples[j * 2..j * 2 + 2]);
            }
        }
    }
}

fn map3(
    p0: &BlockPrediction,
    p1: &BlockPrediction,
    mut f: impl FnMut(usize, u8, u8) -> u8,
) -> BlockPrediction {
    BlockPrediction {
        luma: std::array::from_fn(|i| f(0, p0.luma[i], p1.luma[i])),
        cb: std::array::from_fn(|i| f(1, p0.cb[i], p1.cb[i])),
        cr: std::array::from_fn(|i| f(2, p0.cr[i], p1.cr[i])),
    }
}

fn clip_sample(value: i32) -> u8 {
    u8::try_from(value.clamp(0, 255)).unwrap_or(u8::MAX)
}

/// Default bi-prediction average (equation 8-273).
pub(crate) fn average(p0: &BlockPrediction, p1: &BlockPrediction) -> BlockPrediction {
    map3(p0, p1, |_, a, b| {
        clip_sample((i32::from(a) + i32::from(b) + 1) >> 1)
    })
}

/// Explicit weighted single-list prediction (equations 8-270/8-271).
/// `params` holds (weight, offset) for Y, Cb, Cr; `denoms` the luma and
/// chroma `log2_weight_denom`.
pub(crate) fn weight_single(
    p: &BlockPrediction,
    params: [(i32, i32); 3],
    denoms: [u32; 2],
) -> BlockPrediction {
    map3(p, p, |component, a, _| {
        let (w, o) = params[component];
        let log_wd = denoms[usize::from(component > 0)];
        let x = i32::from(a);
        clip_sample(if log_wd >= 1 {
            ((x * w + (1 << (log_wd - 1))) >> log_wd) + o
        } else {
            x * w + o
        })
    })
}

/// Weighted bi-prediction (equation 8-272): explicit or implicit (offsets
/// 0, `logWD` 5). `params` holds ((w0, o0), (w1, o1)) for Y, Cb, Cr.
pub(crate) fn weight_bi(
    p0: &BlockPrediction,
    p1: &BlockPrediction,
    params: [((i32, i32), (i32, i32)); 3],
    denoms: [u32; 2],
) -> BlockPrediction {
    map3(p0, p1, |component, a, b| {
        let ((w0, o0), (w1, o1)) = params[component];
        let log_wd = denoms[usize::from(component > 0)];
        clip_sample(
            ((i32::from(a) * w0 + i32::from(b) * w1 + (1 << log_wd)) >> (log_wd + 1))
                + ((o0 + o1 + 1) >> 1),
        )
    })
}

/// A rectangular inter partition in luma sample units within the picture.
#[cfg(test)]
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
#[cfg(test)]
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

    fn flat(luma: u8, chroma: u8) -> BlockPrediction {
        BlockPrediction {
            luma: [luma; 16],
            cb: [chroma; 4],
            cr: [chroma; 4],
        }
    }

    /// Weighted sample prediction by hand (8-270..8-273).
    /// Single list, logWD 5, w 40, o -3: ((100 * 40 + 16) >> 5) - 3 =
    /// 125 - 3 = 122. logWD 0: x * w + o, clipped: 255 * 127 + 127 -> 255.
    /// Explicit bi, logWD 5, (w0, o0) = (20, 2), (w1, o1) = (44, 5):
    /// ((100 * 20 + 200 * 44 + 32) >> 6) + ((2 + 5 + 1) >> 1) = 169 + 4 =
    /// 173. Implicit 32/32 equals the default average (100 + 200 + 1) >> 1
    /// = 150.
    #[test]
    fn weighted_prediction_by_hand() {
        let a = flat(100, 100);
        let b = flat(200, 200);
        let single = weight_single(&a, [(40, -3); 3], [5, 5]);
        assert_eq!(single, flat(122, 122));
        let clipped = weight_single(&flat(255, 0), [(127, 127); 3], [0, 0]);
        assert_eq!(clipped, flat(255, 127));
        let bi = weight_bi(&a, &b, [((20, 2), (44, 5)); 3], [5, 5]);
        assert_eq!(bi, flat(173, 173));
        let implicit = weight_bi(&a, &b, [((32, 0), (32, 0)); 3], [5, 5]);
        assert_eq!(implicit, average(&a, &b));
        assert_eq!(implicit, flat(150, 150));
        // Luma and chroma use their own denominators: luma logWD 1 with
        // w 2 is the identity ((x * 2 + 1) >> 1 = x), chroma logWD 0 with
        // w 2 doubles.
        let split = weight_single(&flat(60, 60), [(2, 0), (2, 0), (2, 0)], [1, 0]);
        assert_eq!(split, flat(60, 120));
    }

    /// The windowed predictor equals the per-sample clamped reference predictor on random
    /// pictures, positions and vectors, including blocks far outside the picture.
    #[test]
    fn windowed_prediction_equals_the_per_sample_reference() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for (width, height) in [(16, 16), (48, 32), (32, 64)] {
            let mut reference = Frame::new(width, height).unwrap();
            for sample in reference
                .y
                .iter_mut()
                .chain(reference.cb.iter_mut())
                .chain(reference.cr.iter_mut())
            {
                *sample = (next() >> 24) as u8;
            }
            for _ in 0..4000 {
                let x = (next() as usize % (width / 4)) * 4;
                let y = (next() as usize % (height / 4)) * 4;
                let spread = if next() % 4 == 0 { 400 } else { 40 };
                let mv = [
                    (next() % (2 * spread + 1)) as i32 - spread as i32,
                    (next() % (2 * spread + 1)) as i32 - spread as i32,
                ];
                let mut target = Frame::new(width, height).unwrap();
                let block = Block {
                    x,
                    y,
                    width: 4,
                    height: 4,
                };
                predict_block(&reference, &mut target, block, mv);
                let p = predict_4x4(&reference, x, y, mv);
                for j in 0..4 {
                    let row = (y + j) * width + x;
                    assert_eq!(&target.y[row..row + 4], &p.luma[j * 4..j * 4 + 4], "{mv:?}");
                }
                let cw = width / 2;
                for j in 0..2 {
                    let row = (y / 2 + j) * cw + x / 2;
                    assert_eq!(&target.cb[row..row + 2], &p.cb[j * 2..j * 2 + 2], "{mv:?}");
                    assert_eq!(&target.cr[row..row + 2], &p.cr[j * 2..j * 2 + 2], "{mv:?}");
                }
            }
        }
    }

    /// The whole-macroblock copy equals sixteen 4x4 predictions wherever it applies, and
    /// declines fractional vectors and sources reaching outside the picture.
    #[test]
    fn macroblock_copy_equals_sixteen_block_predictions() {
        let mut state = 0x1234_5678_9abc_def1_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut reference = Frame::new(64, 48).unwrap();
        for sample in reference
            .y
            .iter_mut()
            .chain(reference.cb.iter_mut())
            .chain(reference.cr.iter_mut())
        {
            *sample = (next() >> 24) as u8;
        }
        let mut copied = 0;
        for _ in 0..3000 {
            let (x, y) = ((next() as usize % 4) * 16, (next() as usize % 3) * 16);
            let mut mv = [(next() % 161) as i32 - 80, (next() % 161) as i32 - 80];
            if next() % 2 == 0 {
                // Half the vectors are whole chroma samples, the copyable case.
                mv = [mv[0] & !7, mv[1] & !7];
            }
            let mut fast = Frame::new(64, 48).unwrap();
            let mut slow = Frame::new(64, 48).unwrap();
            if !copy_macroblock(&reference, &mut fast, x, y, mv) {
                assert!(
                    mv[0] & 7 != 0
                        || mv[1] & 7 != 0
                        || x as i32 + (mv[0] >> 2) < 0
                        || y as i32 + (mv[1] >> 2) < 0
                        || x as i32 + (mv[0] >> 2) + 16 > 64
                        || y as i32 + (mv[1] >> 2) + 16 > 48
                );
                continue;
            }
            copied += 1;
            for raster in 0..16 {
                let (bx, by) = (x + (raster % 4) * 4, y + (raster / 4) * 4);
                let p = predict_4x4(&reference, bx, by, mv);
                write_prediction(&mut slow, bx, by, &p);
            }
            assert_eq!((&fast.y, &fast.cb, &fast.cr), (&slow.y, &slow.cb, &slow.cr));
            let gathered = gather_macroblock(&reference, x, y, mv).unwrap();
            for (raster, block) in gathered.iter().enumerate() {
                let (bx, by) = (x + (raster % 4) * 4, y + (raster / 4) * 4);
                assert_eq!(*block, predict_4x4(&reference, bx, by, mv));
            }
        }
        assert!(copied > 50);
    }

    /// predict_4x4 agrees with the rectangle predictor it replaced.
    #[test]
    fn block_prediction_matches_rectangle_prediction() {
        let reference = ramp_frame();
        for mv in [[0, 0], [5, -3], [-7, 9], [13, 2]] {
            let mut target = Frame::new(16, 16).unwrap();
            let block = Block {
                x: 4,
                y: 8,
                width: 4,
                height: 4,
            };
            predict_block(&reference, &mut target, block, mv);
            let p = predict_4x4(&reference, 4, 8, mv);
            for j in 0..4 {
                assert_eq!(
                    &target.y[(8 + j) * 16 + 4..(8 + j) * 16 + 8],
                    &p.luma[j * 4..j * 4 + 4]
                );
            }
            for j in 0..2 {
                assert_eq!(
                    &target.cb[(4 + j) * 8 + 2..(4 + j) * 8 + 4],
                    &p.cb[j * 2..j * 2 + 2]
                );
            }
        }
    }
}
