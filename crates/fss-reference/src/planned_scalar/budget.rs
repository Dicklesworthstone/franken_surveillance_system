#![forbid(unsafe_code)]
//! Audited payload/work model for the unchanged scalar backend. Actual per-node
//! work is checked against this plan after execution, so policy drift fails closed.

use super::{ExecError, PlannedExecError, add, bytes};
use fss_model_ir::{AttrValue, GraphNode, OpCode, TensorPort};

pub(super) fn node_resources(
    node: &GraphNode,
    inputs: &[TensorPort],
    outputs: &[TensorPort],
) -> Result<(u64, usize), PlannedExecError> {
    if outputs.len() != 1 || inputs.is_empty() {
        return Err(PlannedExecError::BackendMismatch);
    }
    let output = &outputs[0];
    let count = output.shape().num_elements().map_err(ExecError::Tensor)? as u64;
    let mut copied_inputs = 0;
    for input in inputs {
        copied_inputs = add(copied_inputs, bytes(input)?)?;
    }
    // Most kernels materialize each logical input and an output Vec; from_values
    // copies that Vec into the result Tensor already counted by the live schedule.
    // Count repeated references separately because binary/Concat kernels copy them.
    // This is conservative for in-place Vec iteration and empty-kernel fast paths.
    let mut scratch = add(copied_inputs, bytes(output)?)?;
    let work = match node.op() {
        OpCode::Conv2d => {
            let weights = inputs.get(1).ok_or(PlannedExecError::BackendMismatch)?;
            let dims = weights.shape().dims();
            let width = product(&dims[1..])?;
            mul(count, width as u64)?
        }
        OpCode::MatMul => {
            let width = inputs[0]
                .shape()
                .dims()
                .last()
                .copied()
                .ok_or(PlannedExecError::BackendMismatch)?;
            mul(count, width as u64)?
        }
        OpCode::MaxPool2d => {
            let kernel = match node.attributes().get("kernel_size") {
                Some(value) => value
                    .as_usize_list(node.id(), "kernel_size")
                    .map_err(ExecError::Ir)?,
                None => vec![1, 1],
            };
            let height = kernel.first().copied().unwrap_or(1) as u64;
            let width = kernel.get(1).copied().unwrap_or(1) as u64;
            mul(count, mul(height, width)?)?
        }
        OpCode::Add | OpCode::Sub | OpCode::Mul | OpCode::Div | OpCode::Relu | OpCode::Sigmoid => {
            count
        }
        OpCode::Softmax => {
            // Softmax allocates its axis buffer even for a zero-sized outer axis.
            // Bounding only output elements would miss that allocation entirely.
            let rank = output.rank();
            let raw = match node.attributes().get("axis") {
                Some(value) => value.as_int(node.id(), "axis").map_err(ExecError::Ir)?,
                None => -1,
            };
            let axis = usize::try_from(if raw < 0 { rank as i64 + raw } else { raw })
                .map_err(|_| PlannedExecError::BackendMismatch)?;
            let length = *output
                .shape()
                .dims()
                .get(axis)
                .ok_or(PlannedExecError::BackendMismatch)?;
            let axis_bytes = length.checked_mul(4).ok_or(PlannedExecError::Overflow)?;
            if axis_bytes > fss_tensor::MAX_STORAGE_BYTES {
                return Err(PlannedExecError::Planning(
                    fss_model_ir::MemoryPlanError::Limit("softmax scratch"),
                ));
            }
            scratch = add(scratch, axis_bytes)?;
            count
        }
        OpCode::Reshape => 0,
        OpCode::Transpose | OpCode::Slice => mul(count, output.rank() as u64 + 1)?,
        OpCode::Squeeze | OpCode::Unsqueeze | OpCode::Concat => count,
        OpCode::LayerNorm | OpCode::RMSNorm => {
            if count == 0 {
                0
            } else {
                let dims = match node.attributes().get("normalized_shape") {
                    Some(AttrValue::Shape(shape)) => shape.dims().to_vec(),
                    Some(value) => value
                        .as_usize_list(node.id(), "normalized_shape")
                        .map_err(ExecError::Ir)?,
                    None => match inputs.get(1) {
                        Some(weight) => weight.shape().dims().to_vec(),
                        None => inputs[0]
                            .shape()
                            .dims()
                            .last()
                            .copied()
                            .into_iter()
                            .collect(),
                    },
                };
                let width = product(&dims)? as u64;
                if width == 0 {
                    return Err(PlannedExecError::BackendMismatch);
                }
                mul(count, 8)?
                    .checked_add(mul(count / width, 4)?)
                    .ok_or(PlannedExecError::Overflow)?
            }
        }
        OpCode::Gelu => {
            let tanh = match node.attributes().get("approximate") {
                Some(value) => {
                    value
                        .as_str(node.id(), "approximate")
                        .map_err(ExecError::Ir)?
                        == "tanh"
                }
                None => false,
            };
            mul(count, if tanh { 96 } else { 896 })?
        }
        OpCode::Silu | OpCode::Tanh => mul(count, 80)?,
        OpCode::Embedding => {
            // The embedding kernel reads strided indices/weights directly and transfers
            // its output byte Vec into TensorStorage; it makes no payload scratch copy.
            scratch = 0;
            let indices = inputs[0]
                .shape()
                .num_elements()
                .map_err(ExecError::Tensor)? as u64;
            mul(indices, 2 * inputs[0].rank() as u64 + 2)?
                .checked_add(mul(count, 4)?)
                .ok_or(PlannedExecError::Overflow)?
        }
    };
    Ok((work, scratch))
}
fn mul(a: u64, b: u64) -> Result<u64, PlannedExecError> {
    a.checked_mul(b).ok_or(PlannedExecError::Overflow)
}
fn product(dims: &[usize]) -> Result<usize, PlannedExecError> {
    dims.iter().try_fold(1_usize, |value, &dim| {
        value.checked_mul(dim).ok_or(PlannedExecError::Overflow)
    })
}
