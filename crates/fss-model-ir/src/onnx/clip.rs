#![forbid(unsafe_code)]
//! Finite F32 Clip-13 through the frozen native operator set.
//!
//! https://onnx.ai/onnx/operators/onnx__Clip.html#clip-13
//! Bounds are optional scalar tensors. Comparing with MaxPool avoids arithmetic
//! such as x - bound that could overflow before the result is clipped. A bound
//! occupies the first pool row, preserving its bits on ties, including +/-0.

use fss_tensor::{DType, Tensor};

use super::{Lowering, OnnxError, Result, SourceNode, port};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

/// Reserve a complete clamp, including any affine prefix, before expansion.
/// Every emitted node has one output; the final source output is already reserved.
pub(super) fn reserve(
    lowering: &Lowering<'_, '_>,
    elements: usize,
    lower: bool,
    upper: bool,
    prefix_nodes: usize,
    prefix_scalars: usize,
) -> Result<()> {
    let bounded = lower || upper;
    let clamp_nodes = if bounded {
        4 + usize::from(lower) * 3 + usize::from(upper) * 6
    } else {
        1
    };
    let nodes = prefix_nodes
        .checked_add(clamp_nodes)
        .ok_or(OnnxError::Limit)?;
    let scalars = prefix_scalars
        .checked_add(usize::from(bounded))
        .ok_or(OnnxError::Limit)?;
    let values = nodes.checked_add(scalars).ok_or(OnnxError::Limit)?;
    let names = values.checked_sub(1).ok_or(OnnxError::Limit)?;
    let bytes = scalars.checked_mul(4).ok_or(OnnxError::Limit)?;
    let limits = lowering.admission.limits;
    if elements
        .checked_mul(if bounded { 8 } else { 4 })
        .ok_or(OnnxError::Limit)?
        > limits.tensor_bytes
        || lowering
            .nodes
            .len()
            .checked_add(nodes)
            .ok_or(OnnxError::Limit)?
            > limits.nodes
        || lowering
            .known
            .len()
            .checked_add(values)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
        || lowering
            .reserved
            .len()
            .checked_add(names)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
        || lowering
            .parameter_bytes
            .checked_add(bytes)
            .ok_or(OnnxError::Limit)?
            > limits.parameter_bytes
    {
        return Err(OnnxError::Limit);
    }
    Ok(())
}

pub(super) fn scalar(
    lowering: &mut Lowering<'_, '_>,
    base: &str,
    value: f32,
) -> Result<String> {
    if !value.is_finite() {
        return Err(OnnxError::NonFinite);
    }
    let name = lowering.fresh_name(base)?;
    let value_port = port(
        name.clone(),
        Vec::new(),
        lowering.generation,
        lowering.admission,
    )?;
    lowering.admission.charge(4)?;
    let tensor = Tensor::from_values(value_port.shape().clone(), &[value], lowering.generation)
        .map_err(|_| OnnxError::Limit)?;
    lowering.add_constant(value_port, tensor)?;
    Ok(name)
}

fn shape(dims: &[usize]) -> Result<AttributeMap> {
    let values = dims
        .iter()
        .map(|&value| i64::try_from(value).map_err(|_| OnnxError::Limit))
        .collect::<Result<Vec<_>>>()?;
    Ok(AttributeMap::from([(
        "shape".into(),
        AttrValue::IntList(values),
    )]))
}

fn emit(
    lowering: &mut Lowering<'_, '_>,
    source: &SourceNode<'_>,
    suffix: &str,
    op: OpCode,
    inputs: Vec<String>,
    attrs: AttributeMap,
) -> Result<String> {
    let id = format!("{}-clip-{suffix}", source.id);
    let output = lowering.fresh_name(&id)?;
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

fn maximum(
    lowering: &mut Lowering<'_, '_>,
    source: &SourceNode<'_>,
    suffix: &str,
    bound: String,
    value: String,
) -> Result<String> {
    let stacked = emit(
        lowering,
        source,
        &format!("{suffix}-stack"),
        OpCode::Concat,
        vec![bound, value],
        AttributeMap::from([("axis".into(), AttrValue::Int(2))]),
    )?;
    emit(
        lowering,
        source,
        &format!("{suffix}-select"),
        OpCode::MaxPool2d,
        vec![stacked],
        AttributeMap::from([("kernel_size".into(), AttrValue::IntList(vec![2, 1]))]),
    )
}

/// Append the pre-reserved clamp after checking F32 shapes and scalar bounds.
/// Finite runtime operands are part of the numerical profile; execution remains
/// subject to the caller's own admission policy and work budget.
pub(super) fn append(
    source: &SourceNode<'_>,
    lowering: &mut Lowering<'_, '_>,
    input: String,
    dims: &[usize],
    lower: Option<String>,
    upper: Option<String>,
) -> Result<()> {
    let mut value = input;
    if lower.is_some() || upper.is_some() {
        let elements = dims
            .iter()
            .try_fold(1_usize, |n, &dim| n.checked_mul(dim))
            .ok_or(OnnxError::Limit)?;
        let negative_one = scalar(
            lowering,
            &format!("{}-clip-negative-one", source.id),
            -1.0,
        )?;
        value = emit(
            lowering,
            source,
            "flat",
            OpCode::Reshape,
            vec![value],
            shape(&[1, 1, 1, elements])?,
        )?;
        let zero = emit(
            lowering,
            source,
            "zero",
            OpCode::Sub,
            vec![value.clone(), value.clone()],
            AttributeMap::new(),
        )?;
        let negative_zero = emit(
            lowering,
            source,
            "negative-zero",
            OpCode::Mul,
            vec![zero, negative_one.clone()],
            AttributeMap::new(),
        )?;
        // (-0) + bound reproduces every finite bound, including either zero.
        // x - x is exact and cannot overflow for any admitted finite x.
        if let Some(bound) = lower {
            let expanded = emit(
                lowering,
                source,
                "lower-bound",
                OpCode::Add,
                vec![negative_zero.clone(), bound],
                AttributeMap::new(),
            )?;
            value = maximum(lowering, source, "lower", expanded, value)?;
        }
        if let Some(bound) = upper {
            let negated = emit(
                lowering,
                source,
                "upper-value",
                OpCode::Mul,
                vec![value, negative_one.clone()],
                AttributeMap::new(),
            )?;
            let negated_bound = emit(
                lowering,
                source,
                "upper-bound-negated",
                OpCode::Mul,
                vec![bound, negative_one.clone()],
                AttributeMap::new(),
            )?;
            let expanded = emit(
                lowering,
                source,
                "upper-bound",
                OpCode::Add,
                vec![negative_zero, negated_bound],
                AttributeMap::new(),
            )?;
            let selected = maximum(lowering, source, "upper", expanded, negated)?;
            value = emit(
                lowering,
                source,
                "upper-restored",
                OpCode::Mul,
                vec![selected, negative_one],
                AttributeMap::new(),
            )?;
        }
    }
    lowering.append(
        GraphNode::new(
            source.id.clone(),
            OpCode::Reshape,
            source.label.clone(),
            vec![value],
            source.outputs.clone(),
            shape(dims)?,
        )
        .map_err(|_| OnnxError::Graph)?,
    )
}

pub(super) fn lower(source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if !(1..=3).contains(&source.inputs.len())
        || source.outputs.len() != 1
        || source.inputs[0].is_empty()
    {
        return Err(OnnxError::Graph);
    }
    if !source.attrs.is_empty() {
        return Err(OnnxError::Unsupported);
    }
    let input = lowering
        .known
        .get(&source.inputs[0])
        .ok_or(OnnxError::Graph)?;
    if input.dtype() != DType::F32 || input.shape().dims().contains(&0) {
        return Err(OnnxError::Unsupported);
    }
    let dims = input.shape().dims().to_vec();
    let elements = input.shape().num_elements().map_err(|_| OnnxError::Limit)?;
    lowering.admission.charge(8 + dims.len())?;
    let bounds = source
        .inputs
        .iter()
        .skip(1)
        .map(|name| {
            if name.is_empty() {
                return Ok(None);
            }
            let bound = lowering.known.get(name).ok_or(OnnxError::Graph)?;
            if bound.dtype() != DType::F32 || bound.rank() != 0 {
                return Err(OnnxError::Unsupported);
            }
            Ok(Some(name.clone()))
        })
        .collect::<Result<Vec<_>>>()?;
    let lower = bounds.first().cloned().flatten();
    let upper = bounds.get(1).cloned().flatten();
    reserve(lowering, elements, lower.is_some(), upper.is_some(), 0, 0)?;
    append(
        &source,
        lowering,
        source.inputs[0].clone(),
        &dims,
        lower,
        upper,
    )
}
