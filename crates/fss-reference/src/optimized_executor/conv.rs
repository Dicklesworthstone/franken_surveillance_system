#![forbid(unsafe_code)]
//! Register-blocked Conv2d kernels that reproduce the scalar reference bit for bit.
//!
//! The scalar reference computes every output element as
//! `acc = 0; for cin_g { for kh { for kw { if tap valid { acc += x * w } } } }; out = acc + bias`.
//! These kernels keep that exact per-element sequence of IEEE-754 binary32 operations: the
//! reduction runs over the same valid taps in the same `(cin_g, kh, kw)` order, starting from
//! `+0.0`, and bias is added last. Speed comes only from computing many independent output
//! elements at once (a `MR x NR` accumulator tile for dense/grouped convolution, a whole output
//! row for depthwise convolution) and from weights packed once at preparation. Nothing is
//! reassociated, no multiply-add is fused (Rust never contracts `a * b + c`), and padded taps are
//! skipped exactly like the reference (never multiplied by an explicit zero), so signed zeros and
//! non-finite values follow the same arithmetic.

use fss_model_ir::{GraphNode, TensorPort};

use super::pointwise::silu_in_place;
use crate::scalar_executor::activation_silu;
use crate::{ExecError, ScalarExecCx};

/// Output channels per register tile.
pub(super) const MR: usize = 4;
/// Output columns per register tile.
pub(super) const NR: usize = 8;

/// Contiguous `[lo, hi)` range of valid kernel taps for one output coordinate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Taps {
    lo: usize,
    hi: usize,
}

/// Immutable prepared convolution: geometry, per-coordinate valid taps and packed weights.
#[derive(Clone, Debug)]
pub(super) struct PreparedConv {
    batch: usize,
    c_in: usize,
    h_in: usize,
    w_in: usize,
    c_out: usize,
    h_out: usize,
    w_out: usize,
    k_h: usize,
    k_w: usize,
    stride_w: usize,
    dilation_h: usize,
    dilation_w: usize,
    stride_h: usize,
    pad_top: usize,
    pad_left: usize,
    groups: usize,
    cpg_in: usize,
    cpg_out: usize,
    depthwise: bool,
    pointwise: bool,
    /// Dense/grouped: `[group][co_block][tap][MR]`; depthwise: `[channel][kh][kw]`.
    packed: Vec<f32>,
    /// One value per output channel; `+0.0` when the node has no bias, exactly like the reference.
    bias: Vec<f32>,
    rows: Vec<Taps>,
    cols: Vec<Taps>,
    interior: Taps,
    co_blocks: usize,
    taps: usize,
    /// Apply the reference SiLU to every biased output (fused `Conv2d -> Silu`).
    pub(super) silu: bool,
}

fn attr_list(node: &GraphNode, name: &str, default: &[usize]) -> Result<Vec<usize>, ExecError> {
    match node.attributes().get(name) {
        Some(a) => a.as_usize_list(node.id(), name).map_err(ExecError::Ir),
        None => Ok(default.to_vec()),
    }
}

/// Valid-tap range of output coordinate `o`, using the reference's checked position arithmetic.
/// `None` when the valid taps are not one contiguous run (never for positive dilation).
fn taps(o: usize, stride: usize, dilation: usize, pad: usize, k: usize, n: usize) -> Option<Taps> {
    let mut first = None;
    let mut last = 0;
    for t in 0..k {
        let valid = o
            .checked_mul(stride)
            .and_then(|s| s.checked_add(t.checked_mul(dilation)?))
            .is_some_and(|p| p >= pad && p - pad < n);
        if valid {
            if first.is_some() && last + 1 != t {
                return None;
            }
            first.get_or_insert(t);
            last = t;
        }
    }
    Some(match first {
        Some(lo) => Taps { lo, hi: last + 1 },
        None => Taps { lo: 0, hi: 0 },
    })
}

impl PreparedConv {
    /// Prepare a convolution with constant weights (and optional constant bias). Returns
    /// `Ok(None)` when the geometry is outside what these kernels reproduce exactly; the caller
    /// then records the scalar reference kernel for that node instead.
    pub(super) fn prepare(
        node: &GraphNode,
        x: &TensorPort,
        weights: (&TensorPort, &[f32]),
        bias: Option<&[f32]>,
        out: &TensorPort,
    ) -> Result<Option<Self>, ExecError> {
        let strides = attr_list(node, "strides", &[1, 1])?;
        let padding = attr_list(node, "padding", &[0, 0, 0, 0])?;
        let dilations = attr_list(node, "dilations", &[1, 1])?;
        let groups = match node.attributes().get("groups") {
            Some(a) => a.as_usize(node.id(), "groups").map_err(ExecError::Ir)?,
            None => 1,
        }
        .max(1);
        let stride_h = strides.first().copied().unwrap_or(1);
        let stride_w = strides.get(1).copied().unwrap_or(1);
        let pad_top = padding.first().copied().unwrap_or(0);
        let pad_left = padding.get(1).copied().unwrap_or(0);
        let dilation_h = dilations.first().copied().unwrap_or(1);
        let dilation_w = dilations.get(1).copied().unwrap_or(1);
        let (x_dims, w_dims, o_dims) = (
            x.shape().dims(),
            weights.0.shape().dims(),
            out.shape().dims(),
        );
        if x_dims.len() != 4 || w_dims.len() != 4 || o_dims.len() != 4 {
            return Ok(None);
        }
        let [batch, c_in, h_in, w_in] = [x_dims[0], x_dims[1], x_dims[2], x_dims[3]];
        let [c_out, h_out, w_out] = [o_dims[1], o_dims[2], o_dims[3]];
        let [k_h, k_w] = [w_dims[2], w_dims[3]];
        // Exactly the index arithmetic of the reference, without its `.max(1)` escape hatches.
        if groups == 0
            || o_dims[0] != batch
            || c_in % groups != 0
            || c_out % groups != 0
            || w_dims[0] != c_out
            || w_dims[1] != c_in / groups
            || c_in == 0
            || c_out == 0
            || stride_h == 0
            || stride_w == 0
            || dilation_h == 0
            || dilation_w == 0
            || bias.is_some_and(|b| b.len() != c_out)
        {
            return Ok(None);
        }
        let (cpg_in, cpg_out) = (c_in / groups, c_out / groups);
        let taps_per_group = cpg_in
            .checked_mul(k_h)
            .and_then(|v| v.checked_mul(k_w))
            .ok_or(ExecError::ArithmeticOverflow {
                operation: "optimized conv taps",
            })?;
        if c_out.checked_mul(taps_per_group) != Some(weights.1.len()) {
            return Ok(None);
        }
        let mut rows = Vec::with_capacity(h_out);
        for oh in 0..h_out {
            match taps(oh, stride_h, dilation_h, pad_top, k_h, h_in) {
                Some(t) => rows.push(t),
                None => return Ok(None),
            }
        }
        let mut cols = Vec::with_capacity(w_out);
        for ow in 0..w_out {
            match taps(ow, stride_w, dilation_w, pad_left, k_w, w_in) {
                Some(t) => cols.push(t),
                None => return Ok(None),
            }
        }
        // Interior columns (every kw valid) form one run because positions are monotone.
        let full: Vec<usize> = (0..w_out)
            .filter(|&ow| cols[ow] == Taps { lo: 0, hi: k_w })
            .collect();
        let interior = match (full.first(), full.last()) {
            (Some(&lo), Some(&hi)) if hi + 1 - lo == full.len() && k_w > 0 => {
                Taps { lo, hi: hi + 1 }
            }
            _ => Taps { lo: 0, hi: 0 },
        };
        let depthwise = cpg_in == 1 && cpg_out == 1;
        let pointwise = k_h == 1
            && k_w == 1
            && stride_h == 1
            && stride_w == 1
            && pad_top == 0
            && pad_left == 0
            && h_out == h_in
            && w_out == w_in
            && !depthwise;
        let bias = bias.map_or_else(|| vec![0.0_f32; c_out], <[f32]>::to_vec);
        let co_blocks = cpg_out.div_ceil(MR);
        let packed = if depthwise {
            weights.1.to_vec()
        } else {
            let mut packed = vec![0.0_f32; groups * co_blocks * taps_per_group * MR];
            for g in 0..groups {
                for block in 0..co_blocks {
                    for i in 0..MR {
                        let co_g = block * MR + i;
                        if co_g >= cpg_out {
                            continue;
                        }
                        let co = g * cpg_out + co_g;
                        let base = ((g * co_blocks + block) * taps_per_group) * MR;
                        for tap in 0..taps_per_group {
                            packed[base + tap * MR + i] = weights.1[co * taps_per_group + tap];
                        }
                    }
                }
            }
            packed
        };
        let mut conv = Self {
            batch,
            c_in,
            h_in,
            w_in,
            c_out,
            h_out,
            w_out,
            k_h,
            k_w,
            stride_w,
            dilation_h,
            dilation_w,
            stride_h,
            pad_top,
            pad_left,
            groups,
            cpg_in,
            cpg_out,
            depthwise,
            pointwise,
            packed,
            bias,
            rows,
            cols,
            interior,
            co_blocks,
            taps: taps_per_group,
            silu: false,
        };
        if pointwise {
            // A 1x1/stride-1/unpadded convolution over [C, H, W] is the same computation over
            // [C, 1, H*W]; flattening only lengthens rows so tiles are rarely partial.
            let plane = h_in * w_in;
            conv.h_in = 1;
            conv.w_in = plane;
            conv.h_out = 1;
            conv.w_out = plane;
            conv.rows = vec![Taps { lo: 0, hi: 1 }];
            conv.cols = vec![Taps { lo: 0, hi: 1 }; plane];
            conv.interior = Taps { lo: 0, hi: plane };
        }
        Ok(Some(conv))
    }

    /// Stable kernel label bound into the prepared plan identity.
    pub(super) fn label(&self) -> &'static str {
        match (self.depthwise, self.pointwise, self.silu) {
            (true, _, false) => "conv2d.depthwise-row.v1",
            (true, _, true) => "conv2d.depthwise-row+silu.v1",
            (false, true, false) => "conv2d.pointwise-gemm-mr4-nr8.v1",
            (false, true, true) => "conv2d.pointwise-gemm-mr4-nr8+silu.v1",
            (false, false, false) => "conv2d.row-gemm-mr4-nr8.v1",
            (false, false, true) => "conv2d.row-gemm-mr4-nr8+silu.v1",
        }
    }

    /// Bytes of packed weights and bias resident in the prepared plan.
    pub(super) fn resident_bytes(&self) -> usize {
        (self.packed.len() + self.bias.len()) * 4
    }

    /// Scratch floats used while running (packed input panel or one accumulator row).
    pub(super) fn scratch_floats(&self) -> usize {
        if self.depthwise {
            self.w_out
        } else {
            self.taps * NR
        }
    }

    /// Output element count.
    pub(super) fn output_len(&self) -> usize {
        self.batch * self.c_out * self.h_out * self.w_out
    }

    /// Execute into `out` (length `output_len`). `x` is the NCHW input.
    pub(super) fn run(
        &self,
        x: &[f32],
        out: &mut [f32],
        scratch: &mut Vec<f32>,
        cx: &ScalarExecCx,
    ) -> Result<(), ExecError> {
        if x.len() != self.batch * self.c_in * self.h_in * self.w_in
            || out.len() != self.output_len()
        {
            return Err(ExecError::ShapeMismatch {
                node_id: "optimized-conv".to_owned(),
                op_id: "OP-CONV2D-001",
                reason: "prepared convolution buffer size mismatch".to_owned(),
            });
        }
        scratch.clear();
        scratch.resize(self.scratch_floats(), 0.0);
        if self.depthwise {
            self.run_depthwise(x, out, scratch, cx)
        } else {
            self.run_gemm(x, out, scratch, cx)
        }
    }

    fn input_row<'a>(&self, x: &'a [f32], n: usize, cin: usize, ih: usize) -> &'a [f32] {
        let start = ((n * self.c_in + cin) * self.h_in + ih) * self.w_in;
        &x[start..start + self.w_in]
    }

    /// Input row index of output row `oh` and tap `kh` (valid by construction of `rows`).
    fn ih(&self, oh: usize, kh: usize) -> usize {
        oh * self.stride_h + kh * self.dilation_h - self.pad_top
    }

    /// Input column of output column `ow` and tap `kw` (valid by construction).
    fn iw(&self, ow: usize, kw: usize) -> usize {
        ow * self.stride_w + kw * self.dilation_w - self.pad_left
    }

    fn finish(&self, values: &mut [f32]) {
        if self.silu {
            silu_in_place(values);
        }
    }

    fn run_gemm(
        &self,
        x: &[f32],
        out: &mut [f32],
        panel: &mut [f32],
        cx: &ScalarExecCx,
    ) -> Result<(), ExecError> {
        let kk = self.k_h * self.k_w;
        for n in 0..self.batch {
            for g in 0..self.groups {
                let weights_g = &self.packed[g * self.co_blocks * self.taps * MR..]
                    [..self.co_blocks * self.taps * MR];
                for oh in 0..self.h_out {
                    cx.checkpoint("optimized-conv:row")?;
                    let rows = self.rows[oh];
                    // Valid taps per input channel for this output row: contiguous in `kh`.
                    let seg = (rows.hi - rows.lo) * self.k_w;
                    let mut ow0 = self.interior.lo;
                    while ow0 < self.interior.hi {
                        let width = NR.min(self.interior.hi - ow0);
                        // Pack [valid tap][NR] in the reference (cin_g, kh, kw) order.
                        let mut r = 0;
                        for c in 0..self.cpg_in {
                            let cin = g * self.cpg_in + c;
                            for kh in rows.lo..rows.hi {
                                let row = self.input_row(x, n, cin, self.ih(oh, kh));
                                for kw in 0..self.k_w {
                                    let dst = &mut panel[r * NR..(r + 1) * NR];
                                    let start = self.iw(ow0, kw);
                                    if self.stride_w == 1 && width == NR {
                                        // Constant-length copy: inlined moves, no memcpy call.
                                        dst.copy_from_slice(&row[start..start + NR]);
                                    } else if self.stride_w == 1 {
                                        dst[..width].copy_from_slice(&row[start..start + width]);
                                    } else {
                                        for (d, s) in dst[..width]
                                            .iter_mut()
                                            .zip(row[start..].iter().step_by(self.stride_w))
                                        {
                                            *d = *s;
                                        }
                                    }
                                    dst[width..].fill(0.0);
                                    r += 1;
                                }
                            }
                        }
                        for block in 0..self.co_blocks {
                            let w = &weights_g[block * self.taps * MR..][..self.taps * MR];
                            let mut acc = [[0.0_f32; NR]; MR];
                            if seg == kk {
                                // Every tap of this row is valid: one contiguous reduction.
                                tile(&mut acc, w, &panel[..self.taps * NR]);
                            } else {
                                for c in 0..self.cpg_in {
                                    let k0 = c * kk + rows.lo * self.k_w;
                                    let a = &w[k0 * MR..(k0 + seg) * MR];
                                    let b = &panel[c * seg * NR..(c + 1) * seg * NR];
                                    tile(&mut acc, a, b);
                                }
                            }
                            for (i, lane) in acc.iter().enumerate() {
                                let co_g = block * MR + i;
                                if co_g >= self.cpg_out {
                                    break;
                                }
                                let co = g * self.cpg_out + co_g;
                                let bias = self.bias[co];
                                let start =
                                    ((n * self.c_out + co) * self.h_out + oh) * self.w_out + ow0;
                                let dst = &mut out[start..start + width];
                                for (d, v) in dst.iter_mut().zip(lane) {
                                    *d = *v + bias;
                                }
                                self.finish(dst);
                            }
                        }
                        ow0 += width;
                    }
                    // Border columns: some kw taps fall into padding and are skipped exactly.
                    for ow in (0..self.interior.lo).chain(self.interior.hi..self.w_out) {
                        let cols = self.cols[ow];
                        for block in 0..self.co_blocks {
                            let w = &weights_g[block * self.taps * MR..][..self.taps * MR];
                            let mut acc = [0.0_f32; MR];
                            for c in 0..self.cpg_in {
                                let cin = g * self.cpg_in + c;
                                for kh in rows.lo..rows.hi {
                                    let row = self.input_row(x, n, cin, self.ih(oh, kh));
                                    for kw in cols.lo..cols.hi {
                                        let xv = row[self.iw(ow, kw)];
                                        let k = c * kk + kh * self.k_w + kw;
                                        let a = &w[k * MR..(k + 1) * MR];
                                        for (s, wv) in acc.iter_mut().zip(a) {
                                            *s += xv * *wv;
                                        }
                                    }
                                }
                            }
                            for (i, s) in acc.iter().enumerate() {
                                let co_g = block * MR + i;
                                if co_g >= self.cpg_out {
                                    break;
                                }
                                let co = g * self.cpg_out + co_g;
                                let index =
                                    ((n * self.c_out + co) * self.h_out + oh) * self.w_out + ow;
                                let v = *s + self.bias[co];
                                out[index] = if self.silu { activation_silu(v) } else { v };
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn run_depthwise(
        &self,
        x: &[f32],
        out: &mut [f32],
        acc: &mut [f32],
        cx: &ScalarExecCx,
    ) -> Result<(), ExecError> {
        let kk = self.k_h * self.k_w;
        let Taps { lo, hi } = self.interior;
        for n in 0..self.batch {
            for c in 0..self.c_out {
                let w = &self.packed[c * kk..(c + 1) * kk];
                let bias = self.bias[c];
                for oh in 0..self.h_out {
                    cx.checkpoint("optimized-conv:depthwise-row")?;
                    let rows = self.rows[oh];
                    let run = &mut acc[lo..hi];
                    let width = hi - lo;
                    run.fill(0.0);
                    for kh in rows.lo..rows.hi {
                        let row = self.input_row(x, n, c, self.ih(oh, kh));
                        for kw in 0..self.k_w {
                            let wv = w[kh * self.k_w + kw];
                            if run.is_empty() {
                                continue;
                            }
                            let start = self.iw(lo, kw);
                            if self.stride_w == 1 {
                                for (a, xv) in run.iter_mut().zip(&row[start..start + width]) {
                                    *a += *xv * wv;
                                }
                            } else {
                                for (a, xv) in run
                                    .iter_mut()
                                    .zip(row[start..].iter().step_by(self.stride_w))
                                {
                                    *a += *xv * wv;
                                }
                            }
                        }
                    }
                    let base = ((n * self.c_out + c) * self.h_out + oh) * self.w_out;
                    let dst = &mut out[base + lo..base + hi];
                    for (d, a) in dst.iter_mut().zip(run.iter()) {
                        *d = *a + bias;
                    }
                    self.finish(dst);
                    for ow in (0..lo).chain(hi..self.w_out) {
                        let cols = self.cols[ow];
                        let mut s = 0.0_f32;
                        for kh in rows.lo..rows.hi {
                            let row = self.input_row(x, n, c, self.ih(oh, kh));
                            for kw in cols.lo..cols.hi {
                                s += row[self.iw(ow, kw)] * w[kh * self.k_w + kw];
                            }
                        }
                        let v = s + bias;
                        out[base + ow] = if self.silu { activation_silu(v) } else { v };
                    }
                }
            }
        }
        Ok(())
    }
}

/// `acc[i][j] += b[t][j] * a[t][i]` for every tap `t` in order: one independent accumulator per
/// output element, updated with exactly the reference's product-then-sum per tap.
/// The four accumulator rows live in locals so they stay in vector registers for the whole
/// reduction (an `MR x NR = 4 x 8` tile is eight 4-lane registers).
#[inline(always)]
fn tile(acc: &mut [[f32; NR]; MR], a: &[f32], b: &[f32]) {
    let [mut c0, mut c1, mut c2, mut c3] = *acc;
    let (a, _) = a.as_chunks::<MR>();
    let (b, _) = b.as_chunks::<NR>();
    for (&[a0, a1, a2, a3], b) in a.iter().zip(b) {
        axpy(&mut c0, b, a0);
        axpy(&mut c1, b, a1);
        axpy(&mut c2, b, a2);
        axpy(&mut c3, b, a3);
    }
    *acc = [c0, c1, c2, c3];
}

/// `acc[j] += b[j] * a`: independent lanes, one product then one sum each.
#[inline(always)]
fn axpy(acc: &mut [f32; NR], b: &[f32; NR], a: f32) {
    for (s, bj) in acc.iter_mut().zip(b) {
        *s += *bj * a;
    }
}
