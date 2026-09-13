//! Deterministic dtype and shape inference over `fss-tensor` types with checked arithmetic.

use core::cmp::max;

use fss_core::Generation;
use fss_tensor::{DType, MAX_TENSOR_RANK, Shape};

use crate::attribute::AttributeMap;
use crate::error::ModelIrError;
use crate::op::OpCode;
use crate::port::TensorPort;

/// Broadcasts two tensor shapes according to standard multi-dimensional broadcasting rules.
///
/// # Errors
/// Returns [`ModelIrError::ShapeMismatch`] if dimensions cannot be broadcast or if broadcast rank exceeds [`MAX_TENSOR_RANK`].
pub fn broadcast_shapes(
    node_id: &str,
    op_id: &'static str,
    s1: &Shape,
    s2: &Shape,
) -> Result<Shape, ModelIrError> {
    let r1 = s1.rank();
    let r2 = s2.rank();
    let max_rank = max(r1, r2);

    if max_rank > MAX_TENSOR_RANK {
        return Err(ModelIrError::ShapeMismatch {
            node_id: node_id.to_string(),
            op_id,
            reason: format!("broadcast rank {max_rank} exceeds maximum rank {MAX_TENSOR_RANK}"),
        });
    }

    let mut out_dims = vec![0; max_rank];

    for i in 0..max_rank {
        let d1 = if i < r1 { s1.dims()[r1 - 1 - i] } else { 1 };
        let d2 = if i < r2 { s2.dims()[r2 - 1 - i] } else { 1 };

        let out_d = if d1 == d2 {
            d1
        } else if d1 == 1 {
            d2
        } else if d2 == 1 {
            d1
        } else {
            return Err(ModelIrError::ShapeMismatch {
                node_id: node_id.to_string(),
                op_id,
                reason: format!(
                    "cannot broadcast dimension {d1} with {d2} at index {i} from right"
                ),
            });
        };

        out_dims[max_rank - 1 - i] = out_d;
    }

    Shape::new(out_dims).map_err(ModelIrError::from)
}

/// Infers output tensor specifications for a node based on its operator, inputs, and attributes.
///
/// # Errors
/// Returns typed [`ModelIrError`] on any mismatch, missing attribute, or arithmetic overflow.
pub fn infer_operator_outputs(
    node_id: &str,
    op: OpCode,
    inputs: &[&TensorPort],
    output_names: &[String],
    attrs: &AttributeMap,
    generation: Generation,
) -> Result<Vec<TensorPort>, ModelIrError> {
    match op {
        OpCode::Add | OpCode::Sub | OpCode::Mul | OpCode::Div => {
            if inputs.len() != 2 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "2 inputs",
                    actual: inputs.len(),
                });
            }
            if output_names.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 output",
                    actual: output_names.len(),
                });
            }
            let in0 = inputs[0];
            let in1 = inputs[1];

            if in0.dtype() != in1.dtype() {
                return Err(ModelIrError::DTypeMismatch {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: in0.dtype(),
                    actual: in1.dtype(),
                    tensor_name: in1.name().to_string(),
                });
            }

            let out_shape = broadcast_shapes(node_id, op.stable_id(), in0.shape(), in1.shape())?;
            let port = TensorPort::new(&output_names[0], in0.dtype(), out_shape, generation)?;
            Ok(vec![port])
        }

        OpCode::Relu | OpCode::Gelu | OpCode::Silu | OpCode::Sigmoid | OpCode::Tanh => {
            if inputs.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 input",
                    actual: inputs.len(),
                });
            }
            if output_names.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 output",
                    actual: output_names.len(),
                });
            }
            let in0 = inputs[0];
            if !in0.dtype().is_floating_point() {
                return Err(ModelIrError::DTypeMismatch {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: DType::F32,
                    actual: in0.dtype(),
                    tensor_name: in0.name().to_string(),
                });
            }

            let port = TensorPort::new(
                &output_names[0],
                in0.dtype(),
                in0.shape().clone(),
                generation,
            )?;
            Ok(vec![port])
        }

        OpCode::MatMul => {
            if inputs.len() != 2 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "2 inputs",
                    actual: inputs.len(),
                });
            }
            if output_names.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 output",
                    actual: output_names.len(),
                });
            }
            let in0 = inputs[0];
            let in1 = inputs[1];

            if in0.dtype() != in1.dtype() {
                return Err(ModelIrError::DTypeMismatch {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: in0.dtype(),
                    actual: in1.dtype(),
                    tensor_name: in1.name().to_string(),
                });
            }

            let r0 = in0.rank();
            let r1 = in1.rank();
            if r0 < 2 {
                return Err(ModelIrError::RankMismatch {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected_rank: 2,
                    actual_rank: r0,
                    tensor_name: in0.name().to_string(),
                });
            }
            if r1 < 2 {
                return Err(ModelIrError::RankMismatch {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected_rank: 2,
                    actual_rank: r1,
                    tensor_name: in1.name().to_string(),
                });
            }

            let dims0 = in0.shape().dims();
            let dims1 = in1.shape().dims();

            let k0 = dims0[r0 - 1];
            let k1 = dims1[r1 - 2];
            if k0 != k1 {
                return Err(ModelIrError::ShapeMismatch {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    reason: format!("inner matrix dimension mismatch: {k0} != {k1}"),
                });
            }

            let batch_shape0 = Shape::new(&dims0[..r0 - 2])?;
            let batch_shape1 = Shape::new(&dims1[..r1 - 2])?;
            let broadcast_batch =
                broadcast_shapes(node_id, op.stable_id(), &batch_shape0, &batch_shape1)?;

            let m = dims0[r0 - 2];
            let n = dims1[r1 - 1];

            let mut out_dims = broadcast_batch.dims().to_vec();
            out_dims.push(m);
            out_dims.push(n);

            let out_shape = Shape::new(out_dims)?;
            let port = TensorPort::new(&output_names[0], in0.dtype(), out_shape, generation)?;
            Ok(vec![port])
        }

        OpCode::Reshape => {
            if inputs.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 input",
                    actual: inputs.len(),
                });
            }
            if output_names.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 output",
                    actual: output_names.len(),
                });
            }
            let in0 = inputs[0];

            let target_shape_attr =
                attrs
                    .get("shape")
                    .ok_or_else(|| ModelIrError::MissingAttribute {
                        node_id: node_id.to_string(),
                        attr_name: "shape".to_string(),
                    })?;

            let requested_dims = target_shape_attr.as_int_list(node_id, "shape")?;
            let total_in_elements = in0.shape().num_elements()?;

            let mut minus_one_idx = None;
            let mut known_product: usize = 1;
            let mut resolved_dims = Vec::with_capacity(requested_dims.len());

            for (idx, &d) in requested_dims.iter().enumerate() {
                if d == -1 {
                    if minus_one_idx.is_some() {
                        return Err(ModelIrError::InvalidAttribute {
                            node_id: node_id.to_string(),
                            attr_name: "shape".to_string(),
                            reason: "at most one dimension in reshape can be -1".to_string(),
                        });
                    }
                    minus_one_idx = Some(idx);
                    resolved_dims.push(0); // placeholder
                } else if d < 0 {
                    return Err(ModelIrError::InvalidAttribute {
                        node_id: node_id.to_string(),
                        attr_name: "shape".to_string(),
                        reason: format!("negative dimension {d} not permitted in reshape"),
                    });
                } else {
                    let dim_u =
                        usize::try_from(d).map_err(|_| ModelIrError::ArithmeticOverflow {
                            operation: "reshape dimension conversion",
                        })?;
                    known_product = known_product.checked_mul(dim_u).ok_or(
                        ModelIrError::ArithmeticOverflow {
                            operation: "reshape known dimensions product",
                        },
                    )?;
                    resolved_dims.push(dim_u);
                }
            }

            if let Some(idx) = minus_one_idx {
                if known_product == 0 {
                    return Err(ModelIrError::ShapeMismatch {
                        node_id: node_id.to_string(),
                        op_id: op.stable_id(),
                        reason: "cannot infer -1 dimension when known product is 0".to_string(),
                    });
                }
                if total_in_elements % known_product != 0 {
                    return Err(ModelIrError::ShapeMismatch {
                        node_id: node_id.to_string(),
                        op_id: op.stable_id(),
                        reason: format!(
                            "total input elements ({total_in_elements}) not divisible by known dimensions product ({known_product})"
                        ),
                    });
                }
                let inferred_dim = total_in_elements / known_product;
                resolved_dims[idx] = inferred_dim;
            } else {
                if known_product != total_in_elements {
                    return Err(ModelIrError::ShapeMismatch {
                        node_id: node_id.to_string(),
                        op_id: op.stable_id(),
                        reason: format!(
                            "element count mismatch in reshape: input has {total_in_elements}, requested shape has {known_product}"
                        ),
                    });
                }
            }

            let out_shape = Shape::new(resolved_dims)?;
            let port = TensorPort::new(&output_names[0], in0.dtype(), out_shape, generation)?;
            Ok(vec![port])
        }

        OpCode::Transpose => {
            if inputs.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 input",
                    actual: inputs.len(),
                });
            }
            if output_names.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 output",
                    actual: output_names.len(),
                });
            }
            let in0 = inputs[0];
            let rank = in0.rank();

            let perm = if let Some(p_attr) = attrs.get("permutation") {
                p_attr.as_usize_list(node_id, "permutation")?
            } else {
                (0..rank).rev().collect()
            };

            if perm.len() != rank {
                return Err(ModelIrError::InvalidAttribute {
                    node_id: node_id.to_string(),
                    attr_name: "permutation".to_string(),
                    reason: format!(
                        "permutation length {} must match input rank {rank}",
                        perm.len()
                    ),
                });
            }

            let mut seen = vec![false; rank];
            for &p in &perm {
                if p >= rank {
                    return Err(ModelIrError::InvalidAttribute {
                        node_id: node_id.to_string(),
                        attr_name: "permutation".to_string(),
                        reason: format!("permutation index {p} out of bounds for rank {rank}"),
                    });
                }
                if seen[p] {
                    return Err(ModelIrError::InvalidAttribute {
                        node_id: node_id.to_string(),
                        attr_name: "permutation".to_string(),
                        reason: format!("duplicate axis {p} in permutation"),
                    });
                }
                seen[p] = true;
            }

            let in_dims = in0.shape().dims();
            let mut out_dims = Vec::with_capacity(rank);
            for &p in &perm {
                out_dims.push(in_dims[p]);
            }

            let out_shape = Shape::new(out_dims)?;
            let port = TensorPort::new(&output_names[0], in0.dtype(), out_shape, generation)?;
            Ok(vec![port])
        }

        OpCode::Squeeze => {
            if inputs.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 input",
                    actual: inputs.len(),
                });
            }
            if output_names.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 output",
                    actual: output_names.len(),
                });
            }
            let in0 = inputs[0];
            let in_dims = in0.shape().dims();

            let axes_to_squeeze: Vec<usize> = if let Some(a_attr) = attrs.get("axes") {
                a_attr.as_usize_list(node_id, "axes")?
            } else {
                in_dims
                    .iter()
                    .enumerate()
                    .filter(|(_, d)| **d == 1)
                    .map(|(idx, _)| idx)
                    .collect()
            };

            for &axis in &axes_to_squeeze {
                if axis >= in_dims.len() {
                    return Err(ModelIrError::InvalidAttribute {
                        node_id: node_id.to_string(),
                        attr_name: "axes".to_string(),
                        reason: format!(
                            "squeeze axis {axis} out of bounds for rank {}",
                            in_dims.len()
                        ),
                    });
                }
                if in_dims[axis] != 1 {
                    return Err(ModelIrError::ShapeMismatch {
                        node_id: node_id.to_string(),
                        op_id: op.stable_id(),
                        reason: format!(
                            "cannot squeeze axis {axis} with dimension size {}",
                            in_dims[axis]
                        ),
                    });
                }
            }

            let mut out_dims = Vec::new();
            for (idx, &d) in in_dims.iter().enumerate() {
                if !axes_to_squeeze.contains(&idx) {
                    out_dims.push(d);
                }
            }

            let out_shape = Shape::new(out_dims)?;
            let port = TensorPort::new(&output_names[0], in0.dtype(), out_shape, generation)?;
            Ok(vec![port])
        }

        OpCode::Unsqueeze => {
            if inputs.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 input",
                    actual: inputs.len(),
                });
            }
            if output_names.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 output",
                    actual: output_names.len(),
                });
            }
            let in0 = inputs[0];
            let in_dims = in0.shape().dims();

            let axes = attrs
                .get("axes")
                .ok_or_else(|| ModelIrError::MissingAttribute {
                    node_id: node_id.to_string(),
                    attr_name: "axes".to_string(),
                })?
                .as_usize_list(node_id, "axes")?;

            let new_rank =
                in_dims
                    .len()
                    .checked_add(axes.len())
                    .ok_or(ModelIrError::ArithmeticOverflow {
                        operation: "unsqueeze rank calculation",
                    })?;

            if new_rank > MAX_TENSOR_RANK {
                return Err(ModelIrError::RankMismatch {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected_rank: MAX_TENSOR_RANK,
                    actual_rank: new_rank,
                    tensor_name: output_names[0].clone(),
                });
            }

            let mut seen_axes = vec![false; new_rank];
            for &axis in &axes {
                if axis >= new_rank {
                    return Err(ModelIrError::InvalidAttribute {
                        node_id: node_id.to_string(),
                        attr_name: "axes".to_string(),
                        reason: format!(
                            "unsqueeze axis {axis} out of bounds for output rank {new_rank}"
                        ),
                    });
                }
                if seen_axes[axis] {
                    return Err(ModelIrError::InvalidAttribute {
                        node_id: node_id.to_string(),
                        attr_name: "axes".to_string(),
                        reason: format!("duplicate axis {axis} in unsqueeze axes"),
                    });
                }
                seen_axes[axis] = true;
            }

            let mut out_dims = Vec::with_capacity(new_rank);
            let mut in_idx = 0;
            for i in 0..new_rank {
                if axes.contains(&i) {
                    out_dims.push(1);
                } else if in_idx < in_dims.len() {
                    out_dims.push(in_dims[in_idx]);
                    in_idx += 1;
                }
            }

            let out_shape = Shape::new(out_dims)?;
            let port = TensorPort::new(&output_names[0], in0.dtype(), out_shape, generation)?;
            Ok(vec![port])
        }

        OpCode::Concat => {
            if inputs.is_empty() {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "at least 1 input",
                    actual: 0,
                });
            }
            if output_names.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 output",
                    actual: output_names.len(),
                });
            }
            let base = inputs[0];
            let rank = base.rank();
            let base_dims = base.shape().dims();

            let axis = attrs
                .get("axis")
                .ok_or_else(|| ModelIrError::MissingAttribute {
                    node_id: node_id.to_string(),
                    attr_name: "axis".to_string(),
                })?
                .as_usize(node_id, "axis")?;

            if axis >= rank {
                return Err(ModelIrError::InvalidAttribute {
                    node_id: node_id.to_string(),
                    attr_name: "axis".to_string(),
                    reason: format!("concat axis {axis} out of bounds for rank {rank}"),
                });
            }

            let mut total_concat_dim: usize = 0;

            for (idx, in_port) in inputs.iter().enumerate() {
                if in_port.dtype() != base.dtype() {
                    return Err(ModelIrError::DTypeMismatch {
                        node_id: node_id.to_string(),
                        op_id: op.stable_id(),
                        expected: base.dtype(),
                        actual: in_port.dtype(),
                        tensor_name: in_port.name().to_string(),
                    });
                }
                if in_port.rank() != rank {
                    return Err(ModelIrError::RankMismatch {
                        node_id: node_id.to_string(),
                        op_id: op.stable_id(),
                        expected_rank: rank,
                        actual_rank: in_port.rank(),
                        tensor_name: in_port.name().to_string(),
                    });
                }

                let in_dims = in_port.shape().dims();
                for r in 0..rank {
                    if r != axis && in_dims[r] != base_dims[r] {
                        return Err(ModelIrError::ShapeMismatch {
                            node_id: node_id.to_string(),
                            op_id: op.stable_id(),
                            reason: format!(
                                "dimension mismatch at non-concat axis {r}: expected {}, got {} in input {idx}",
                                base_dims[r], in_dims[r]
                            ),
                        });
                    }
                }

                total_concat_dim = total_concat_dim.checked_add(in_dims[axis]).ok_or(
                    ModelIrError::ArithmeticOverflow {
                        operation: "concat dimension summation",
                    },
                )?;
            }

            let mut out_dims = base_dims.to_vec();
            out_dims[axis] = total_concat_dim;

            let out_shape = Shape::new(out_dims)?;
            let port = TensorPort::new(&output_names[0], base.dtype(), out_shape, generation)?;
            Ok(vec![port])
        }

        OpCode::Slice => {
            if inputs.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 input",
                    actual: inputs.len(),
                });
            }
            if output_names.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 output",
                    actual: output_names.len(),
                });
            }
            let in0 = inputs[0];
            let in_dims = in0.shape().dims();
            let rank = in0.rank();

            let starts = attrs
                .get("starts")
                .ok_or_else(|| ModelIrError::MissingAttribute {
                    node_id: node_id.to_string(),
                    attr_name: "starts".to_string(),
                })?
                .as_usize_list(node_id, "starts")?;

            let ends = attrs
                .get("ends")
                .ok_or_else(|| ModelIrError::MissingAttribute {
                    node_id: node_id.to_string(),
                    attr_name: "ends".to_string(),
                })?
                .as_usize_list(node_id, "ends")?;

            let axes = if let Some(a_attr) = attrs.get("axes") {
                a_attr.as_usize_list(node_id, "axes")?
            } else {
                (0..starts.len()).collect()
            };

            if starts.len() != ends.len() || starts.len() != axes.len() {
                return Err(ModelIrError::InvalidAttribute {
                    node_id: node_id.to_string(),
                    attr_name: "starts/ends/axes".to_string(),
                    reason: "starts, ends, and axes must have identical length".to_string(),
                });
            }

            let mut out_dims = in_dims.to_vec();
            let mut seen_axes = vec![false; rank];

            for i in 0..axes.len() {
                let axis = axes[i];
                if axis >= rank {
                    return Err(ModelIrError::InvalidAttribute {
                        node_id: node_id.to_string(),
                        attr_name: "axes".to_string(),
                        reason: format!("slice axis {axis} out of bounds for rank {rank}"),
                    });
                }
                if seen_axes[axis] {
                    return Err(ModelIrError::InvalidAttribute {
                        node_id: node_id.to_string(),
                        attr_name: "axes".to_string(),
                        reason: format!("duplicate axis {axis} in slice axes"),
                    });
                }
                seen_axes[axis] = true;
                let start = starts[i];
                let end = ends[i];
                let dim_len = in_dims[axis];

                if start > dim_len || end > dim_len || start > end {
                    return Err(ModelIrError::ShapeMismatch {
                        node_id: node_id.to_string(),
                        op_id: op.stable_id(),
                        reason: format!(
                            "invalid slice range [{start}..{end}] for dimension size {dim_len} on axis {axis}"
                        ),
                    });
                }

                out_dims[axis] = end - start;
            }

            let out_shape = Shape::new(out_dims)?;
            let port = TensorPort::new(&output_names[0], in0.dtype(), out_shape, generation)?;
            Ok(vec![port])
        }

        OpCode::LayerNorm | OpCode::RMSNorm => {
            if inputs.is_empty() {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "at least 1 input",
                    actual: 0,
                });
            }
            if output_names.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 output",
                    actual: output_names.len(),
                });
            }
            let in0 = inputs[0];
            if !in0.dtype().is_floating_point() {
                return Err(ModelIrError::DTypeMismatch {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: DType::F32,
                    actual: in0.dtype(),
                    tensor_name: in0.name().to_string(),
                });
            }

            let port = TensorPort::new(
                &output_names[0],
                in0.dtype(),
                in0.shape().clone(),
                generation,
            )?;
            Ok(vec![port])
        }

        OpCode::Softmax => {
            if inputs.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 input",
                    actual: inputs.len(),
                });
            }
            if output_names.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 output",
                    actual: output_names.len(),
                });
            }
            let in0 = inputs[0];
            if !in0.dtype().is_floating_point() {
                return Err(ModelIrError::DTypeMismatch {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: DType::F32,
                    actual: in0.dtype(),
                    tensor_name: in0.name().to_string(),
                });
            }

            let axis = attrs
                .get("axis")
                .map(|a| a.as_usize(node_id, "axis"))
                .transpose()?
                .unwrap_or_else(|| in0.rank().saturating_sub(1));

            if in0.rank() > 0 && axis >= in0.rank() {
                return Err(ModelIrError::InvalidAttribute {
                    node_id: node_id.to_string(),
                    attr_name: "axis".to_string(),
                    reason: format!("softmax axis {axis} out of bounds for rank {}", in0.rank()),
                });
            }

            let port = TensorPort::new(
                &output_names[0],
                in0.dtype(),
                in0.shape().clone(),
                generation,
            )?;
            Ok(vec![port])
        }

        OpCode::Conv2d => {
            if inputs.len() < 2 || inputs.len() > 3 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "2 or 3 inputs (x, weight, [bias])",
                    actual: inputs.len(),
                });
            }
            if output_names.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 output",
                    actual: output_names.len(),
                });
            }
            let in0 = inputs[0]; // [N, C_in, H, W]
            let in1 = inputs[1]; // [C_out, C_in / groups, K_h, K_w]

            if in0.rank() != 4 {
                return Err(ModelIrError::RankMismatch {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected_rank: 4,
                    actual_rank: in0.rank(),
                    tensor_name: in0.name().to_string(),
                });
            }
            if in1.rank() != 4 {
                return Err(ModelIrError::RankMismatch {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected_rank: 4,
                    actual_rank: in1.rank(),
                    tensor_name: in1.name().to_string(),
                });
            }

            let in_dims = in0.shape().dims();
            let wt_dims = in1.shape().dims();

            let n = in_dims[0];
            let c_in = in_dims[1];
            let h = in_dims[2];
            let w = in_dims[3];

            let c_out = wt_dims[0];
            let wt_c = wt_dims[1];
            let k_h = wt_dims[2];
            let k_w = wt_dims[3];

            let groups = if let Some(g_attr) = attrs.get("groups") {
                g_attr.as_usize(node_id, "groups")?
            } else {
                1
            };

            if groups == 0 || !c_in.is_multiple_of(groups) || wt_c != c_in / groups {
                return Err(ModelIrError::ShapeMismatch {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    reason: format!(
                        "incompatible groups ({groups}) with C_in ({c_in}) and weight C ({wt_c})"
                    ),
                });
            }

            let strides = if let Some(s_attr) = attrs.get("strides") {
                s_attr.as_usize_list(node_id, "strides")?
            } else {
                vec![1, 1]
            };
            if strides.len() != 2 || strides[0] == 0 || strides[1] == 0 {
                return Err(ModelIrError::InvalidAttribute {
                    node_id: node_id.to_string(),
                    attr_name: "strides".to_string(),
                    reason: "strides must be 2 non-zero positive integers [stride_h, stride_w]"
                        .to_string(),
                });
            }

            let pads = if let Some(p_attr) = attrs.get("padding") {
                p_attr.as_usize_list(node_id, "padding")?
            } else {
                vec![0, 0, 0, 0]
            };
            if pads.len() != 4 {
                return Err(ModelIrError::InvalidAttribute {
                    node_id: node_id.to_string(),
                    attr_name: "padding".to_string(),
                    reason: "padding must be 4 integers [top, left, bottom, right]".to_string(),
                });
            }

            let dilations = if let Some(d_attr) = attrs.get("dilation").or_else(|| attrs.get("dilations")) {
                d_attr.as_usize_list(node_id, "dilation")?
            } else {
                vec![1, 1]
            };
            if dilations.len() != 2 || dilations[0] == 0 || dilations[1] == 0 {
                return Err(ModelIrError::InvalidAttribute {
                    node_id: node_id.to_string(),
                    attr_name: "dilation".to_string(),
                    reason:
                        "dilation must be 2 non-zero positive integers [dilation_h, dilation_w]"
                            .to_string(),
                });
            }

            // Effective kernel sizes with dilation
            let eff_kh = (k_h.saturating_sub(1))
                .checked_mul(dilations[0])
                .and_then(|v| v.checked_add(1))
                .ok_or(ModelIrError::ArithmeticOverflow {
                    operation: "effective kernel height calculation",
                })?;

            let eff_kw = (k_w.saturating_sub(1))
                .checked_mul(dilations[1])
                .and_then(|v| v.checked_add(1))
                .ok_or(ModelIrError::ArithmeticOverflow {
                    operation: "effective kernel width calculation",
                })?;

            let total_h = h
                .checked_add(pads[0])
                .and_then(|v| v.checked_add(pads[2]))
                .ok_or(ModelIrError::ArithmeticOverflow {
                    operation: "padded height calculation",
                })?;

            let total_w = w
                .checked_add(pads[1])
                .and_then(|v| v.checked_add(pads[3]))
                .ok_or(ModelIrError::ArithmeticOverflow {
                    operation: "padded width calculation",
                })?;

            if total_h < eff_kh || total_w < eff_kw {
                return Err(ModelIrError::ShapeMismatch {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    reason: format!(
                        "padded spatial size ({total_h}x{total_w}) smaller than effective kernel size ({eff_kh}x{eff_kw})"
                    ),
                });
            }

            let out_h = (total_h - eff_kh) / strides[0] + 1;
            let out_w = (total_w - eff_kw) / strides[1] + 1;

            let out_shape = Shape::new(vec![n, c_out, out_h, out_w])?;
            let port = TensorPort::new(&output_names[0], in0.dtype(), out_shape, generation)?;
            Ok(vec![port])
        }

        OpCode::MaxPool2d => {
            if inputs.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 input",
                    actual: inputs.len(),
                });
            }
            if output_names.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 output",
                    actual: output_names.len(),
                });
            }
            let in0 = inputs[0];
            if in0.rank() != 4 {
                return Err(ModelIrError::RankMismatch {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected_rank: 4,
                    actual_rank: in0.rank(),
                    tensor_name: in0.name().to_string(),
                });
            }
            let in_dims = in0.shape().dims();
            let n = in_dims[0];
            let c = in_dims[1];
            let h = in_dims[2];
            let w = in_dims[3];

            let kernel_size = attrs
                .get("kernel_size")
                .ok_or_else(|| ModelIrError::MissingAttribute {
                    node_id: node_id.to_string(),
                    attr_name: "kernel_size".to_string(),
                })?
                .as_usize_list(node_id, "kernel_size")?;

            if kernel_size.len() != 2 || kernel_size[0] == 0 || kernel_size[1] == 0 {
                return Err(ModelIrError::InvalidAttribute {
                    node_id: node_id.to_string(),
                    attr_name: "kernel_size".to_string(),
                    reason: "kernel_size must be 2 non-zero positive integers".to_string(),
                });
            }

            let strides = if let Some(s_attr) = attrs.get("strides") {
                s_attr.as_usize_list(node_id, "strides")?
            } else {
                vec![1, 1]
            };
            if strides.len() != 2 || strides[0] == 0 || strides[1] == 0 {
                return Err(ModelIrError::InvalidAttribute {
                    node_id: node_id.to_string(),
                    attr_name: "strides".to_string(),
                    reason: "strides must be 2 non-zero positive integers".to_string(),
                });
            }

            let pads = if let Some(p_attr) = attrs.get("padding") {
                p_attr.as_usize_list(node_id, "padding")?
            } else {
                vec![0, 0, 0, 0]
            };
            if pads.len() != 4 {
                return Err(ModelIrError::InvalidAttribute {
                    node_id: node_id.to_string(),
                    attr_name: "padding".to_string(),
                    reason: "padding must be 4 integers [top, left, bottom, right]".to_string(),
                });
            }

            let total_h = h
                .checked_add(pads[0])
                .and_then(|v| v.checked_add(pads[2]))
                .ok_or(ModelIrError::ArithmeticOverflow {
                    operation: "maxpool padded height calculation",
                })?;

            let total_w = w
                .checked_add(pads[1])
                .and_then(|v| v.checked_add(pads[3]))
                .ok_or(ModelIrError::ArithmeticOverflow {
                    operation: "maxpool padded width calculation",
                })?;

            if total_h < kernel_size[0] || total_w < kernel_size[1] {
                return Err(ModelIrError::ShapeMismatch {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    reason: "padded spatial size smaller than pooling kernel size".to_string(),
                });
            }

            let out_h = (total_h - kernel_size[0]) / strides[0] + 1;
            let out_w = (total_w - kernel_size[1]) / strides[1] + 1;

            let out_shape = Shape::new(vec![n, c, out_h, out_w])?;
            let port = TensorPort::new(&output_names[0], in0.dtype(), out_shape, generation)?;
            Ok(vec![port])
        }

        OpCode::Embedding => {
            if inputs.len() != 2 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "2 inputs (indices, weights)",
                    actual: inputs.len(),
                });
            }
            if output_names.len() != 1 {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: "1 output",
                    actual: output_names.len(),
                });
            }
            let indices = inputs[0];
            let weights = inputs[1];

            if !indices.dtype().is_integer() {
                return Err(ModelIrError::DTypeMismatch {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected: DType::I64,
                    actual: indices.dtype(),
                    tensor_name: indices.name().to_string(),
                });
            }
            if weights.rank() != 2 {
                return Err(ModelIrError::RankMismatch {
                    node_id: node_id.to_string(),
                    op_id: op.stable_id(),
                    expected_rank: 2,
                    actual_rank: weights.rank(),
                    tensor_name: weights.name().to_string(),
                });
            }

            let embedding_dim = weights.shape().dims()[1];
            let mut out_dims = indices.shape().dims().to_vec();
            out_dims.push(embedding_dim);

            let out_shape = Shape::new(out_dims)?;
            let port = TensorPort::new(&output_names[0], weights.dtype(), out_shape, generation)?;
            Ok(vec![port])
        }
    }
}
