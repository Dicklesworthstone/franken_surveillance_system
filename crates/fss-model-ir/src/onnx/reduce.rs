#![forbid(unsafe_code)]
//! Opset-13 reductions with static axes and existing ordered F32 arithmetic.
//!
//! https://onnx.ai/onnx/operators/onnx__ReduceMean.html#reducemean-13
//! https://onnx.ai/onnx/operators/onnx__ReduceSum.html#reducesum-13
//! https://onnx.ai/onnx/operators/onnx__ReduceL2.html#reducel2-13
//! Kept dimensions precede sorted reduced dimensions in a temporary permutation.
//! A MatMul against exact ones sums each row from +0 in ascending F32 order.
//! Mean divides by the exactly represented positive element count; L2 squares
//! before summing and takes Sqrt afterward. These are not higher-precision or
//! overflow-repair reductions, nor bitwise external-oracle equivalence claims.
//! No frozen operator semantics or IDs change.

use fss_tensor::{DType, Tensor};

use super::{Lowering, OnnxError, Result, SourceNode, port};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Mean,
    Sum,
    L2,
}

impl Kind {
    fn tag(self) -> &'static str {
        match self {
            Self::Mean => "mean",
            Self::Sum => "sum",
            Self::L2 => "l2",
        }
    }

    fn arithmetic_nodes(self) -> usize {
        match self {
            Self::Mean => 2,
            Self::Sum => 1,
            Self::L2 => 3,
        }
    }
}

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

fn boolean_attribute(source: &mut SourceNode<'_>, name: &str, default: bool) -> Result<bool> {
    match source.attrs.remove(name) {
        None => Ok(default),
        Some(AttrValue::Int(1)) => Ok(true),
        Some(AttrValue::Int(0)) => Ok(false),
        Some(AttrValue::Int(_)) => Err(OnnxError::Unsupported),
        Some(_) => Err(OnnxError::Graph),
    }
}

fn plan(kind: Kind, dims: &[usize], raw_axes: &[i64], keepdims: bool) -> Result<Plan> {
    let rank = dims.len() as i64;
    // Missing/empty axes reduce all dimensions. ReduceSum's explicit no-op
    // case is handled before planning and has no reduction parameters.
    let mut reduced = vec![raw_axes.is_empty(); dims.len()];
    for &axis in raw_axes {
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
    let transpose = permutation
        .iter()
        .enumerate()
        .any(|(axis, &actual)| axis != actual);
    let permuted_dims = permutation
        .iter()
        .map(|&axis| dims[axis])
        .collect::<Vec<_>>();
    let reshape = permuted_dims != [rows, width];
    let output = dims
        .iter()
        .enumerate()
        .filter_map(|(axis, &dim)| {
            if reduced[axis] {
                keepdims.then_some(1)
            } else {
                Some(dim)
            }
        })
        .collect::<Vec<_>>();
    let restore = output != [rows, 1];
    let nodes = kind.arithmetic_nodes()
        + usize::from(transpose)
        + usize::from(reshape)
        + usize::from(restore);
    Ok(Plan {
        output,
        permutation,
        rows,
        width,
        transpose,
        reshape,
        restore,
        nodes,
    })
}

fn ints(dims: &[usize]) -> Result<AttrValue> {
    Ok(AttrValue::IntList(
        dims.iter()
            .map(|&dim| i64::try_from(dim).map_err(|_| OnnxError::Limit))
            .collect::<Result<Vec<_>>>()?,
    ))
}

fn append(
    source: &SourceNode<'_>,
    kind: Kind,
    lowering: &mut Lowering<'_, '_>,
    remaining: &mut usize,
    op: OpCode,
    inputs: Vec<String>,
    attrs: AttributeMap,
) -> Result<String> {
    let ordinal = *remaining;
    *remaining = remaining.checked_sub(1).ok_or(OnnxError::Graph)?;
    let id = if *remaining == 0 {
        source.id.clone()
    } else {
        format!("{}-{}-{ordinal}", source.id, kind.tag())
    };
    let output = if *remaining == 0 {
        source.outputs[0].clone()
    } else {
        lowering.fresh_name(&id)?
    };
    lowering.append(
        GraphNode::new(
            id,
            op,
            source.label.clone(),
            inputs,
            vec![output.clone()],
            attrs,
        )
        .map_err(|_| OnnxError::Graph)?,
    )?;
    Ok(output)
}

pub(super) fn lower(mut source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    let kind = match source.op.as_str() {
        "ReduceMean" => Kind::Mean,
        "ReduceSum" => Kind::Sum,
        "ReduceL2" => Kind::L2,
        _ => return Err(OnnxError::Unsupported),
    };
    let maximum_inputs = if kind == Kind::Sum { 2 } else { 1 };
    if source.inputs.is_empty()
        || source.inputs.len() > maximum_inputs
        || source.outputs.len() != 1
        || source.inputs[0].is_empty()
    {
        return Err(OnnxError::Graph);
    }
    let input = lowering
        .known
        .get(&source.inputs[0])
        .ok_or(OnnxError::Graph)?;
    if input.dtype() != DType::F32 || input.shape().dims().contains(&0) {
        return Err(OnnxError::Unsupported);
    }
    let dims = input.shape().dims().to_vec();
    lowering.admission.charge(1 + dims.len())?;
    // Sum moved axes to an optional INT64 input in opset 13. Mean and L2
    // still use the INTS attribute in this opset; never silently accept their
    // later input-axes/noop forms or Sum's earlier attribute-axes form.
    let raw_axes = if kind == Kind::Sum {
        match source.inputs.get(1).filter(|name| !name.is_empty()) {
            Some(name) => lowering.constant_i64_vector(name)?,
            None => Vec::new(),
        }
    } else {
        match source.attrs.remove("axes") {
            None => Vec::new(),
            Some(AttrValue::IntList(axes)) => axes,
            Some(_) => return Err(OnnxError::Graph),
        }
    };
    let keepdims = boolean_attribute(&mut source, "keepdims", true)?;
    let noop = kind == Kind::Sum && boolean_attribute(&mut source, "noop_with_empty_axes", false)?;
    if !source.attrs.is_empty() {
        return Err(OnnxError::Unsupported);
    }
    if noop && raw_axes.is_empty() {
        // Identity must preserve signed zeros and subnormals bit-for-bit.
        // Summing a width-one row would change -0 to +0, so use Reshape.
        append(
            &source,
            kind,
            lowering,
            &mut 1,
            OpCode::Reshape,
            vec![source.inputs[0].clone()],
            AttributeMap::from([("shape".into(), ints(&dims)?)]),
        )?;
        return Ok(());
    }
    let plan = plan(kind, &dims, &raw_axes, keepdims)?;
    port(
        source.outputs[0].clone(),
        plan.output.clone(),
        lowering.generation,
        lowering.admission,
    )?;
    let ones_bytes = plan.width.checked_mul(4).ok_or(OnnxError::Limit)?;
    let parameter_count = if kind == Kind::Mean { 2 } else { 1 };
    let added_bytes = ones_bytes
        .checked_add(if kind == Kind::Mean { 4 } else { 0 })
        .ok_or(OnnxError::Limit)?;
    let limits = lowering.admission.limits;
    // Reserve parameters and the complete lowering before allocating any
    // vector or helper. Transpose/reshape preserve input size; the sum contracts it.
    if lowering
        .nodes
        .len()
        .checked_add(plan.nodes)
        .ok_or(OnnxError::Limit)?
        > limits.nodes
        || lowering
            .known
            .len()
            .checked_add(plan.nodes + parameter_count)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
        || lowering
            .reserved
            .len()
            .checked_add(plan.nodes + parameter_count - 1)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
        || lowering
            .parameter_bytes
            .checked_add(added_bytes)
            .ok_or(OnnxError::Limit)?
            > limits.parameter_bytes
        || ones_bytes > limits.tensor_bytes
    {
        return Err(OnnxError::Limit);
    }
    let ones_name = lowering.fresh_name(&format!("{}-{}-ones", source.id, kind.tag()))?;
    let ones = port(
        ones_name.clone(),
        vec![plan.width, 1],
        lowering.generation,
        lowering.admission,
    )?;
    lowering.admission.charge(ones_bytes)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(plan.width)
        .map_err(|_| OnnxError::Limit)?;
    for _ in 0..plan.width {
        lowering.admission.charge(1)?;
        values.push(1.0_f32);
    }
    lowering.admission.charge(ones_bytes)?;
    let tensor = Tensor::from_values(ones.shape().clone(), &values, lowering.generation)
        .map_err(|_| OnnxError::Limit)?;
    lowering.add_constant(ones, tensor)?;
    let divisor_name = if kind == Kind::Mean {
        let name = lowering.fresh_name(&format!("{}-mean-divisor", source.id))?;
        let divisor = port(
            name.clone(),
            Vec::new(),
            lowering.generation,
            lowering.admission,
        )?;
        lowering.admission.charge(4)?;
        let tensor = Tensor::from_values(
            divisor.shape().clone(),
            &[plan.width as f32],
            lowering.generation,
        )
        .map_err(|_| OnnxError::Limit)?;
        lowering.add_constant(divisor, tensor)?;
        Some(name)
    } else {
        None
    };

    let mut remaining = plan.nodes;
    let mut value = source.inputs[0].clone();
    if plan.transpose {
        value = append(
            &source,
            kind,
            lowering,
            &mut remaining,
            OpCode::Transpose,
            vec![value],
            AttributeMap::from([("permutation".into(), ints(&plan.permutation)?)]),
        )?;
    }
    if plan.reshape {
        value = append(
            &source,
            kind,
            lowering,
            &mut remaining,
            OpCode::Reshape,
            vec![value],
            AttributeMap::from([("shape".into(), ints(&[plan.rows, plan.width])?)]),
        )?;
    }
    if kind == Kind::L2 {
        value = append(
            &source,
            kind,
            lowering,
            &mut remaining,
            OpCode::Mul,
            vec![value.clone(), value],
            AttributeMap::new(),
        )?;
    }
    value = append(
        &source,
        kind,
        lowering,
        &mut remaining,
        OpCode::MatMul,
        vec![value, ones_name],
        AttributeMap::new(),
    )?;
    if let Some(divisor_name) = divisor_name {
        value = append(
            &source,
            kind,
            lowering,
            &mut remaining,
            OpCode::Div,
            vec![value, divisor_name],
            AttributeMap::new(),
        )?;
    } else if kind == Kind::L2 {
        value = append(
            &source,
            kind,
            lowering,
            &mut remaining,
            OpCode::Sqrt,
            vec![value],
            AttributeMap::new(),
        )?;
    }
    if plan.restore {
        append(
            &source,
            kind,
            lowering,
            &mut remaining,
            OpCode::Reshape,
            vec![value],
            AttributeMap::from([("shape".into(), ints(&plan.output)?)]),
        )?;
    }
    if remaining != 0 {
        return Err(OnnxError::Graph);
    }
    Ok(())
}
