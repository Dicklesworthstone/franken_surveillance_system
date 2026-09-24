#![forbid(unsafe_code)]
//! Elementwise, broadcast and pooling kernels with the scalar reference's exact arithmetic.
//!
//! SiLU evaluates the reference's binary64 series (16 dependent divisions per element) for
//! `SILU_LANES` independent elements at once, so the divisions pipeline instead of serializing.
//! Every lane performs the identical sequence of IEEE-754 operations as
//! `scalar_executor::activation_silu`; out-of-range lanes compute a discarded value and are
//! selected away exactly where the reference branches.

use fss_model_ir::{GraphNode, OpCode};

use crate::ExecError;
use crate::scalar_executor::activation_silu;

/// Independent SiLU elements evaluated together.
pub(super) const SILU_LANES: usize = 8;

/// Reference SiLU over a slice, several elements at a time; bit-identical to the scalar kernel.
pub(super) fn silu_in_place(values: &mut [f32]) {
    let (lanes, rest) = values.as_chunks_mut::<SILU_LANES>();
    for chunk in lanes {
        silu_lanes(chunk);
    }
    for v in rest {
        *v = activation_silu(*v);
    }
}

#[inline(always)]
fn silu_lanes(chunk: &mut [f32; SILU_LANES]) {
    const L: usize = SILU_LANES;
    let mut value = [0.0_f64; L];
    let mut arg = [0.0_f64; L];
    let mut r = [0.0_f64; L];
    let mut scale = [0.0_f64; L];
    for l in 0..L {
        value[l] = f64::from(chunk[l]);
        // activation_exp_negative(-|value|): range reduction.
        arg[l] = -value[l].abs();
        let k = (arg[l] * std::f64::consts::LOG2_E - 0.5) as i32;
        r[l] = arg[l] - f64::from(k) * std::f64::consts::LN_2;
        // Saturated k for discarded lanes stays representable: i32::MIN + 1023 does not overflow.
        scale[l] = f64::from_bits((k.wrapping_add(1023) as u64) << 52);
    }
    let mut term = [1.0_f64; L];
    let mut sum = [1.0_f64; L];
    for n in 1_u32..=16 {
        let divisor = f64::from(n);
        // For n = 1, 2, 4, 8, 16 the reciprocal is an exact power of two, so `t / n` and
        // `t * (1 / n)` are correctly rounded values of the same real number: identical bits
        // (including subnormal results, zeros, infinities and NaN). Other n keep the division.
        if n.is_power_of_two() {
            let reciprocal = 1.0 / divisor;
            for l in 0..L {
                term[l] = term[l] * r[l] * reciprocal;
                sum[l] += term[l];
            }
        } else {
            for l in 0..L {
                term[l] = term[l] * r[l] / divisor;
                sum[l] += term[l];
            }
        }
    }
    // The reference branches `v >= 0 ? v / (1 + t) : v * t / (1 + t)`. Since `v * 1.0 == v`
    // exactly (also for zeros, infinities and NaN), both arms are `(v * m) / (1 + t)` with
    // `m = 1` or `m = t`: a data-independent select instead of an unpredictable branch, and
    // one vectorizable division per element.
    let mut result = [0.0_f32; L];
    for l in 0..L {
        let tail = if arg[l] < -700.0 {
            0.0
        } else {
            sum[l] * scale[l]
        };
        let v = value[l];
        let m = if v >= 0.0 { 1.0 } else { tail };
        result[l] = (v * m / (1.0 + tail)) as f32;
    }
    for l in 0..L {
        let x = chunk[l];
        chunk[l] = if x.is_nan() || x == f32::NEG_INFINITY {
            f32::from_bits(0x7fc0_0000)
        } else if x == f32::INFINITY {
            x
        } else {
            result[l]
        };
    }
}

/// Binary elementwise operator of the frozen IR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
}

impl BinaryOp {
    pub(super) fn of(op: OpCode) -> Option<Self> {
        match op {
            OpCode::Add => Some(Self::Add),
            OpCode::Sub => Some(Self::Sub),
            OpCode::Mul => Some(Self::Mul),
            OpCode::Div => Some(Self::Div),
            OpCode::Relu
            | OpCode::Gelu
            | OpCode::Silu
            | OpCode::Sigmoid
            | OpCode::Tanh
            | OpCode::MatMul
            | OpCode::Reshape
            | OpCode::Transpose
            | OpCode::Squeeze
            | OpCode::Unsqueeze
            | OpCode::Concat
            | OpCode::Slice
            | OpCode::LayerNorm
            | OpCode::RMSNorm
            | OpCode::Softmax
            | OpCode::Conv2d
            | OpCode::MaxPool2d
            | OpCode::Embedding => None,
        }
    }
    #[inline(always)]
    fn apply(self, a: f32, b: f32) -> f32 {
        match self {
            Self::Add => a + b,
            Self::Sub => a - b,
            Self::Mul => a * b,
            Self::Div => a / b,
        }
    }
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Add => "add.broadcast.v1",
            Self::Sub => "sub.broadcast.v1",
            Self::Mul => "mul.broadcast.v1",
            Self::Div => "div.broadcast.v1",
        }
    }
}

/// Broadcast plan identical to the reference's effective-stride walk.
#[derive(Clone, Debug)]
pub(super) struct Broadcast {
    out_dims: Vec<usize>,
    stride_a: Vec<usize>,
    stride_b: Vec<usize>,
    same: bool,
}

fn row_major(dims: &[usize]) -> Vec<usize> {
    let mut s = vec![1_usize; dims.len()];
    for i in (0..dims.len().saturating_sub(1)).rev() {
        s[i] = s[i + 1].saturating_mul(dims[i + 1]);
    }
    s
}

impl Broadcast {
    pub(super) fn new(a: &[usize], b: &[usize], out: &[usize]) -> Self {
        let r = out.len();
        let (sa, sb) = (row_major(a), row_major(b));
        let mut stride_a = vec![0; r];
        let mut stride_b = vec![0; r];
        for i in 0..r {
            let j = r - 1 - i;
            if j < a.len() && a[a.len() - 1 - j] > 1 {
                stride_a[i] = sa[a.len() - 1 - j];
            }
            if j < b.len() && b[b.len() - 1 - j] > 1 {
                stride_b[i] = sb[b.len() - 1 - j];
            }
        }
        Self {
            out_dims: out.to_vec(),
            stride_a,
            stride_b,
            same: a == out && b == out,
        }
    }

    pub(super) fn run(&self, op: BinaryOp, a: &[f32], b: &[f32], out: &mut Vec<f32>) {
        out.clear();
        if self.same && a.len() == b.len() {
            out.extend(a.iter().zip(b).map(|(x, y)| op.apply(*x, *y)));
            return;
        }
        let total: usize = self.out_dims.iter().product();
        let r = self.out_dims.len();
        let mut coords = vec![0_usize; r];
        out.reserve(total);
        for _ in 0..total {
            let mut oa = 0;
            let mut ob = 0;
            for k in 0..r {
                oa += coords[k] * self.stride_a[k];
                ob += coords[k] * self.stride_b[k];
            }
            // Same out-of-range substitution as the reference (unreachable for valid shapes).
            let va = a.get(oa).copied().unwrap_or(0.0);
            let vb = b.get(ob).copied().unwrap_or(0.0);
            out.push(op.apply(va, vb));
            for k in (0..r).rev() {
                coords[k] += 1;
                if coords[k] < self.out_dims[k] {
                    break;
                }
                coords[k] = 0;
            }
        }
    }
}

/// MaxPool2d geometry with the reference's attribute defaults and window order.
#[derive(Clone, Debug)]
pub(super) struct Pool {
    batch_channels: usize,
    h_in: usize,
    w_in: usize,
    h_out: usize,
    w_out: usize,
    k_h: usize,
    k_w: usize,
    stride_h: usize,
    stride_w: usize,
    pad_top: usize,
    pad_left: usize,
}

impl Pool {
    pub(super) fn new(
        node: &GraphNode,
        x: &[usize],
        out: &[usize],
    ) -> Result<Option<Self>, ExecError> {
        let list = |name: &str, default: &[usize]| -> Result<Vec<usize>, ExecError> {
            match node.attributes().get(name) {
                Some(a) => a.as_usize_list(node.id(), name).map_err(ExecError::Ir),
                None => Ok(default.to_vec()),
            }
        };
        if node.attributes().get("kernel_size").is_none() || x.len() != 4 || out.len() != 4 {
            return Ok(None);
        }
        let k = list("kernel_size", &[1, 1])?;
        let s = list("strides", &[1, 1])?;
        let p = list("padding", &[0, 0, 0, 0])?;
        if x[0] != out[0] || x[1] != out[1] {
            return Ok(None);
        }
        let pool = Self {
            batch_channels: x[0] * x[1],
            h_in: x[2],
            w_in: x[3],
            h_out: out[2],
            w_out: out[3],
            k_h: k.first().copied().unwrap_or(1),
            k_w: k.get(1).copied().unwrap_or(1),
            stride_h: s.first().copied().unwrap_or(1),
            stride_w: s.get(1).copied().unwrap_or(1),
            pad_top: p.first().copied().unwrap_or(0),
            pad_left: p.get(1).copied().unwrap_or(0),
        };
        // Reject geometry whose positions could overflow; the reference path handles it.
        let reach =
            |o: usize, st: usize, k: usize| o.checked_mul(st).and_then(|v| v.checked_add(k));
        if reach(pool.h_out, pool.stride_h, pool.k_h).is_none()
            || reach(pool.w_out, pool.stride_w, pool.k_w).is_none()
        {
            return Ok(None);
        }
        Ok(Some(pool))
    }

    pub(super) fn run(&self, x: &[f32], out: &mut Vec<f32>) {
        out.clear();
        out.reserve(self.batch_channels * self.h_out * self.w_out);
        for plane in 0..self.batch_channels {
            let src = &x[plane * self.h_in * self.w_in..(plane + 1) * self.h_in * self.w_in];
            for oh in 0..self.h_out {
                for ow in 0..self.w_out {
                    let mut max_val = f32::NEG_INFINITY;
                    let mut found = false;
                    for kh in 0..self.k_h {
                        let ph = oh * self.stride_h + kh;
                        if ph < self.pad_top || ph - self.pad_top >= self.h_in {
                            continue;
                        }
                        let row = &src[(ph - self.pad_top) * self.w_in..][..self.w_in];
                        for kw in 0..self.k_w {
                            let pw = ow * self.stride_w + kw;
                            if pw < self.pad_left || pw - self.pad_left >= self.w_in {
                                continue;
                            }
                            let v = row[pw - self.pad_left];
                            if !found || v > max_val {
                                max_val = v;
                                found = true;
                            }
                        }
                    }
                    out.push(if found { max_val } else { 0.0 });
                }
            }
        }
    }
}
