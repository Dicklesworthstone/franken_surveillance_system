#![forbid(unsafe_code)]
//! Pure data-movement kernels (Slice, Transpose, Concat). They copy the exact values the
//! reference gathers, in the same output order, using precomputed strides and contiguous runs
//! instead of a per-element division walk. Copies are bit-exact by construction.

use fss_model_ir::{GraphNode, OpCode};

use crate::ExecError;

/// Strided gather: `out[coord] = in[base + sum(coord[a] * stride[a])]`.
#[derive(Clone, Debug)]
pub(super) struct Gather {
    out_dims: Vec<usize>,
    strides: Vec<usize>,
    base: usize,
}

fn usize_list(node: &GraphNode, name: &str) -> Result<Option<Vec<usize>>, ExecError> {
    node.attributes()
        .get(name)
        .map(|a| a.as_usize_list(node.id(), name).map_err(ExecError::Ir))
        .transpose()
}

impl Gather {
    /// Plan with the reference's attribute defaults. `Ok(None)` when an index could leave the
    /// input or overflow; the reference kernel then runs and reports it identically.
    pub(super) fn new(
        node: &GraphNode,
        in_dims: &[usize],
        out_dims: &[usize],
    ) -> Result<Option<Self>, ExecError> {
        let rank = in_dims.len();
        if out_dims.len() != rank {
            return Ok(None);
        }
        let mut source_strides = vec![1_usize; rank];
        for i in (0..rank.saturating_sub(1)).rev() {
            match source_strides[i + 1].checked_mul(in_dims[i + 1]) {
                Some(s) => source_strides[i] = s,
                None => return Ok(None),
            }
        }
        let mut axes: Vec<usize> = (0..rank).collect();
        let mut starts = vec![0_usize; rank];
        let mut steps = vec![1_usize; rank];
        match node.op() {
            OpCode::Transpose => {
                axes =
                    usize_list(node, "permutation")?.unwrap_or_else(|| (0..rank).rev().collect());
            }
            OpCode::Slice => {
                let Some(selected_starts) = usize_list(node, "starts")? else {
                    return Ok(None);
                };
                let selected_axes = usize_list(node, "axes")?
                    .unwrap_or_else(|| (0..selected_starts.len()).collect());
                let selected_steps =
                    usize_list(node, "steps")?.unwrap_or_else(|| vec![1; selected_starts.len()]);
                for (index, &axis) in selected_axes.iter().enumerate() {
                    let (Some(start), Some(step)) =
                        (selected_starts.get(index), selected_steps.get(index))
                    else {
                        return Ok(None);
                    };
                    if axis >= rank {
                        return Ok(None);
                    }
                    starts[axis] = *start;
                    steps[axis] = *step;
                }
            }
            OpCode::Add
            | OpCode::Sub
            | OpCode::Mul
            | OpCode::Div
            | OpCode::Relu
            | OpCode::Gelu
            | OpCode::Silu
            | OpCode::Sigmoid
            | OpCode::Tanh
            | OpCode::MatMul
            | OpCode::Reshape
            | OpCode::Squeeze
            | OpCode::Unsqueeze
            | OpCode::Concat
            | OpCode::LayerNorm
            | OpCode::RMSNorm
            | OpCode::Softmax
            | OpCode::Conv2d
            | OpCode::MaxPool2d
            | OpCode::Embedding => return Ok(None),
        }
        if axes.len() != rank || axes.iter().any(|&a| a >= rank) {
            return Ok(None);
        }
        let in_len: usize = in_dims.iter().product();
        let mut strides = Vec::with_capacity(rank);
        let mut base = 0_usize;
        let mut reach = 0_usize;
        for (axis, &dim) in out_dims.iter().enumerate() {
            let source = axes[axis];
            let Some(stride) = steps[source].checked_mul(source_strides[source]) else {
                return Ok(None);
            };
            let Some(offset) = starts[source].checked_mul(source_strides[source]) else {
                return Ok(None);
            };
            let Some(extent) = dim.saturating_sub(1).checked_mul(stride) else {
                return Ok(None);
            };
            let (Some(b), Some(r)) = (base.checked_add(offset), reach.checked_add(extent)) else {
                return Ok(None);
            };
            base = b;
            reach = r;
            strides.push(stride);
        }
        let count: usize = out_dims.iter().product();
        if count > 0 && base.checked_add(reach).is_none_or(|last| last >= in_len) {
            return Ok(None);
        }
        Ok(Some(Self {
            out_dims: out_dims.to_vec(),
            strides,
            base,
        }))
    }

    pub(super) fn run(&self, input: &[f32], out: &mut Vec<f32>) {
        out.clear();
        let count: usize = self.out_dims.iter().product();
        let rank = self.out_dims.len();
        if count == 0 {
            return;
        }
        out.reserve(count);
        if rank == 0 {
            out.push(input[self.base]);
            return;
        }
        let inner = self.out_dims[rank - 1];
        let inner_stride = self.strides[rank - 1];
        let mut coords = vec![0_usize; rank - 1];
        let rows = count / inner;
        for _ in 0..rows {
            let mut offset = self.base;
            for (c, s) in coords.iter().zip(&self.strides) {
                offset += c * s;
            }
            if inner_stride == 1 {
                out.extend_from_slice(&input[offset..offset + inner]);
            } else if inner_stride == 0 {
                out.extend(std::iter::repeat_n(input[offset], inner));
            } else {
                out.extend(input[offset..].iter().step_by(inner_stride).take(inner));
            }
            for axis in (0..rank - 1).rev() {
                coords[axis] += 1;
                if coords[axis] < self.out_dims[axis] {
                    break;
                }
                coords[axis] = 0;
            }
        }
    }
}

/// Concatenation along one axis: `outer` rows of per-input `block` copies.
#[derive(Clone, Debug)]
pub(super) struct Concat {
    outer: usize,
    blocks: Vec<usize>,
}

impl Concat {
    pub(super) fn new(
        node: &GraphNode,
        inputs: &[&[usize]],
        out_dims: &[usize],
    ) -> Result<Option<Self>, ExecError> {
        let rank = out_dims.len();
        let raw = match node.attributes().get("axis") {
            Some(value) => value.as_int(node.id(), "axis").map_err(ExecError::Ir)?,
            None => 0,
        };
        let Ok(axis) = usize::try_from(if raw < 0 { rank as i64 + raw } else { raw }) else {
            return Ok(None);
        };
        if axis >= rank {
            return Ok(None);
        }
        let outer: usize = out_dims[..axis].iter().product();
        let inner: usize = out_dims[axis + 1..].iter().product();
        let mut blocks = Vec::with_capacity(inputs.len());
        for dims in inputs {
            if dims.len() != rank {
                return Ok(None);
            }
            blocks.push(dims[axis] * inner);
        }
        Ok(Some(Self { outer, blocks }))
    }

    pub(super) fn run(&self, inputs: &[&[f32]], out: &mut Vec<f32>) {
        out.clear();
        out.reserve(self.outer * self.blocks.iter().sum::<usize>());
        for row in 0..self.outer {
            for (source, block) in inputs.iter().zip(&self.blocks) {
                out.extend_from_slice(&source[row * block..(row + 1) * block]);
            }
        }
    }
}
