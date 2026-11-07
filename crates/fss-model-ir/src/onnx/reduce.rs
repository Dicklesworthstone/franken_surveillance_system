#![forbid(unsafe_code)]
//! ReduceMean-13 with static axes and the existing ordered F32 arithmetic.
//!
//! https://onnx.ai/onnx/operators/onnx__ReduceMean.html#reducemean-13
//! Kept dimensions precede sorted reduced dimensions in a temporary permutation.
//! A MatMul against exact ones sums each row from +0 in ascending F32 order;
//! a separate Div uses the exactly represented positive element count. This is
//! not a higher-precision or overflow-repair mean, nor a bitwise external-oracle
//! equivalence claim. No frozen operator semantics or IDs change.

use fss_tensor::{DType, Tensor};

use super::{Lowering, OnnxError, Result, SourceNode, port};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

struct Plan {
    output: Vec<usize>,
    permutation: Vec<usize>,
    rows: usize,
    width: usize,
    transpose: bool,
    reshape: bool,
    restore: bool,
    nodes: usize,
}

fn product(mut dims: impl Iterator<Item = usize>) -> Result<usize> {
    dims.try_fold(1_usize, |n, dim| n.checked_mul(dim).ok_or(OnnxError::Limit))
}

fn plan(source: &mut SourceNode<'_>, dims: &[usize]) -> Result<Plan> {
    let rank = dims.len() as i64;
    let raw_axes = match source.attrs.remove("axes") {
        None => Vec::new(),
        Some(AttrValue::IntList(axes)) => axes,
        Some(_) => return Err(OnnxError::Graph),
    };
    let keepdims = match source.attrs.remove("keepdims") {
        None | Some(AttrValue::Int(1)) => true,
        Some(AttrValue::Int(0)) => false,
        Some(AttrValue::Int(_)) => return Err(OnnxError::Unsupported),
        Some(_) => return Err(OnnxError::Graph),
    };
    if !source.attrs.is_empty() {
        return Err(OnnxError::Unsupported);
    }
    // Opset 13's absent OR empty axes attribute reduces all dimensions. Its
    // later input-axes and noop_with_empty_axes forms are not admitted here.
    let mut reduced = vec![raw_axes.is_empty(); dims.len()];
    for axis in raw_axes {
        if !(-rank..rank).contains(&axis) {
            return Err(OnnxError::Graph);
        }
        let axis = if axis < 0 { axis + rank } else { axis } as usize;
        if reduced[axis] {
            return Err(OnnxError::Graph);
        }
        reduced[axis] = true;
    }
    let kept = (0..dims.len()).filter(|&axis| !reduced[axis]);
    let axes = (0..dims.len()).filter(|&axis| reduced[axis]);
    let rows = product(kept.clone().map(|axis| dims[axis]))?;
    let width = product(axes.clone().map(|axis| dims[axis]))?;
    // A positive F32 tensor under the existing 64 MiB ceiling implies this
    // exact integer divisor; retain an explicit check before the F32 cast.
    if width == 0 || width > 1 << 24 {
        return Err(OnnxError::Limit);
    }
    let permutation = kept.chain(axes).collect::<Vec<_>>();
    let transpose = permutation.iter().enumerate().any(|(axis, &actual)| axis != actual);
    let permuted_dims = permutation.iter().map(|&axis| dims[axis]).collect::<Vec<_>>();
    let reshape = permuted_dims != [rows, width];
    let output = dims.iter().enumerate().filter_map(|(axis, &dim)| {
        if reduced[axis] { keepdims.then_some(1) } else { Some(dim) }
    }).collect::<Vec<_>>();
    let restore = output != [rows, 1];
    let nodes = 2 + usize::from(transpose) + usize::from(reshape) + usize::from(restore);
    Ok(Plan { output, permutation, rows, width, transpose, reshape, restore, nodes })
}

fn ints(dims: &[usize]) -> Result<AttrValue> {
    Ok(AttrValue::IntList(dims.iter().map(|&dim| i64::try_from(dim).map_err(|_| OnnxError::Limit)).collect::<Result<Vec<_>>>()?))
}

fn append(
    source: &SourceNode<'_>,
    lowering: &mut Lowering<'_, '_>,
    remaining: &mut usize,
    op: OpCode,
    inputs: Vec<String>,
    attrs: AttributeMap,
) -> Result<String> {
    let ordinal = *remaining;
    *remaining = remaining.checked_sub(1).ok_or(OnnxError::Graph)?;
    let id = if *remaining == 0 { source.id.clone() } else { format!("{}-mean-{ordinal}", source.id) };
    let output = if *remaining == 0 { source.outputs[0].clone() } else { lowering.fresh_name(&id)? };
    lowering.append(GraphNode::new(id, op, source.label.clone(), inputs, vec![output.clone()], attrs).map_err(|_| OnnxError::Graph)?)?;
    Ok(output)
}

pub(super) fn lower(mut source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if source.inputs.len() != 1 || source.outputs.len() != 1 || source.inputs[0].is_empty() {
        return Err(OnnxError::Graph);
    }
    let input = lowering.known.get(&source.inputs[0]).ok_or(OnnxError::Graph)?;
    if input.dtype() != DType::F32 || input.shape().dims().contains(&0) {
        return Err(OnnxError::Unsupported);
    }
    let dims = input.shape().dims().to_vec();
    lowering.admission.charge(1 + dims.len())?;
    let plan = plan(&mut source, &dims)?;
    port(source.outputs[0].clone(), plan.output.clone(), lowering.generation, lowering.admission)?;
    let ones_bytes = plan.width.checked_mul(4).ok_or(OnnxError::Limit)?;
    let added_bytes = ones_bytes.checked_add(4).ok_or(OnnxError::Limit)?;
    let limits = lowering.admission.limits;
    // Reserve both parameters and the complete lowering before allocating any
    // vector or helper. Transpose/reshape preserve input size; the sum contracts it.
    if lowering.nodes.len().checked_add(plan.nodes).ok_or(OnnxError::Limit)? > limits.nodes
        || lowering.known.len().checked_add(plan.nodes + 2).ok_or(OnnxError::Limit)? > limits.tensors
        || lowering.reserved.len().checked_add(plan.nodes + 1).ok_or(OnnxError::Limit)? > limits.tensors
        || lowering.parameter_bytes.checked_add(added_bytes).ok_or(OnnxError::Limit)? > limits.parameter_bytes
        || ones_bytes > limits.tensor_bytes
    {
        return Err(OnnxError::Limit);
    }
    let ones_name = lowering.fresh_name(&format!("{}-mean-ones", source.id))?;
    let ones = port(ones_name.clone(), vec![plan.width, 1], lowering.generation, lowering.admission)?;
    lowering.admission.charge(ones_bytes)?;
    let mut values = Vec::new();
    values.try_reserve_exact(plan.width).map_err(|_| OnnxError::Limit)?;
    for _ in 0..plan.width {
        lowering.admission.charge(1)?;
        values.push(1.0_f32);
    }
    lowering.admission.charge(ones_bytes)?;
    let tensor = Tensor::from_values(ones.shape().clone(), &values, lowering.generation).map_err(|_| OnnxError::Limit)?;
    lowering.add_constant(ones, tensor)?;
    let divisor_name = lowering.fresh_name(&format!("{}-mean-divisor", source.id))?;
    let divisor = port(divisor_name.clone(), Vec::new(), lowering.generation, lowering.admission)?;
    lowering.admission.charge(4)?;
    let tensor = Tensor::from_values(divisor.shape().clone(), &[plan.width as f32], lowering.generation).map_err(|_| OnnxError::Limit)?;
    lowering.add_constant(divisor, tensor)?;

    let mut remaining = plan.nodes;
    let mut value = source.inputs[0].clone();
    if plan.transpose {
        value = append(&source, lowering, &mut remaining, OpCode::Transpose, vec![value], AttributeMap::from([("permutation".into(), ints(&plan.permutation)?)]))?;
    }
    if plan.reshape {
        value = append(&source, lowering, &mut remaining, OpCode::Reshape, vec![value], AttributeMap::from([("shape".into(), ints(&[plan.rows, plan.width])?)]))?;
    }
    value = append(&source, lowering, &mut remaining, OpCode::MatMul, vec![value, ones_name], AttributeMap::new())?;
    value = append(&source, lowering, &mut remaining, OpCode::Div, vec![value, divisor_name], AttributeMap::new())?;
    if plan.restore {
        append(&source, lowering, &mut remaining, OpCode::Reshape, vec![value], AttributeMap::from([("shape".into(), ints(&plan.output)?)]))?;
    }
    if remaining != 0 {
        return Err(OnnxError::Graph);
    }
    Ok(())
}
