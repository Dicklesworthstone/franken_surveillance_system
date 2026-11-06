#![forbid(unsafe_code)]
//! Static constant-mode Pad-13 using existing Slice, Concat and Reshape operators.
//!
//! https://onnx.ai/onnx/operators/onnx__Pad.html#pad-13
//! Crop every negative side before adding constant borders. Data movement and
//! generated fill tensors preserve source F32 bits, including negative zero.
//! The shared eight-element INT64 control bound admits ranks one through four.

use fss_tensor::{DType, Tensor};

use super::{Lowering, OnnxError, Result, SourceNode, port};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

struct Plan {
    starts: Vec<i64>,
    ends: Vec<i64>,
    cropped: Vec<usize>,
    output: Vec<usize>,
    before: Vec<usize>,
    after: Vec<usize>,
    crop: bool,
    axes: usize,
    parameters: usize,
    bytes: usize,
}

fn split(value: i64) -> Result<(usize, usize)> {
    if value < 0 {
        let crop = value.checked_neg().ok_or(OnnxError::Limit)?;
        Ok((usize::try_from(crop).map_err(|_| OnnxError::Limit)?, 0))
    } else {
        Ok((0, usize::try_from(value).map_err(|_| OnnxError::Limit)?))
    }
}

fn byte_count(dims: &[usize]) -> Result<usize> {
    dims.iter().try_fold(4_usize, |bytes, &dim| {
        bytes.checked_mul(dim).ok_or(OnnxError::Limit)
    })
}

fn plan(dims: &[usize], pads: &[i64]) -> Result<Plan> {
    if !(1..=4).contains(&dims.len()) {
        return Err(OnnxError::Unsupported);
    }
    if pads.len() != 2 * dims.len() {
        return Err(OnnxError::Graph);
    }
    let mut plan = Plan {
        starts: Vec::new(),
        ends: Vec::new(),
        cropped: Vec::new(),
        output: Vec::new(),
        before: Vec::new(),
        after: Vec::new(),
        crop: false,
        axes: 0,
        parameters: 0,
        bytes: 0,
    };
    for (axis, &input) in dims.iter().enumerate() {
        let (crop_before, before) = split(pads[axis])?;
        let (crop_after, after) = split(pads[axis + dims.len()])?;
        let end = input
            .checked_sub(crop_after)
            .ok_or(OnnxError::Unsupported)?;
        // A positive final shape does not make an empty cropped tensor a
        // supported runtime value, even when the opposite side adds padding.
        if crop_before >= end {
            return Err(OnnxError::Unsupported);
        }
        let cropped = end - crop_before;
        let output = cropped
            .checked_add(before)
            .and_then(|n| n.checked_add(after))
            .ok_or(OnnxError::Limit)?;
        plan.starts
            .push(i64::try_from(crop_before).map_err(|_| OnnxError::Limit)?);
        plan.ends
            .push(i64::try_from(end).map_err(|_| OnnxError::Limit)?);
        plan.cropped.push(cropped);
        plan.output.push(output);
        plan.before.push(before);
        plan.after.push(after);
        plan.crop |= crop_before != 0 || crop_after != 0;
        plan.axes += usize::from(before != 0 || after != 0);
        plan.parameters += usize::from(before != 0) + usize::from(after != 0);
    }
    // With cropping first, each subsequent shape grows monotonically to the
    // final output. Border sizes telescope to precisely this byte difference.
    plan.bytes = byte_count(&plan.output)?
        .checked_sub(byte_count(&plan.cropped)?)
        .ok_or(OnnxError::Limit)?;
    Ok(plan)
}

fn fill(source: &SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<f32> {
    let Some(name) = source.inputs.get(2).filter(|name| !name.is_empty()) else {
        return Ok(0.0);
    };
    let tensor = lowering.constants.get(name).ok_or(OnnxError::Unsupported)?;
    if tensor.dtype() != DType::F32 || tensor.shape().rank() != 0 {
        return Err(OnnxError::Graph);
    }
    lowering.admission.charge(4)?;
    let values = tensor.to_vec::<f32>().map_err(|_| OnnxError::Graph)?;
    let value = *values.first().ok_or(OnnxError::Graph)?;
    if !value.is_finite() {
        return Err(OnnxError::NonFinite);
    }
    lowering.control_uses.insert(name.clone());
    Ok(value)
}

fn parameter(
    lowering: &mut Lowering<'_, '_>,
    base: &str,
    dims: Vec<usize>,
    value: f32,
) -> Result<String> {
    let name = lowering.fresh_name(base)?;
    let port = port(name.clone(), dims, lowering.generation, lowering.admission)?;
    let shape = port.shape().clone();
    let count = shape.num_elements().map_err(|_| OnnxError::Limit)?;
    let bytes = shape.size_bytes(DType::F32).map_err(|_| OnnxError::Limit)?;
    lowering.admission.charge(bytes)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| OnnxError::Limit)?;
    for _ in 0..count {
        lowering.admission.charge(1)?;
        values.push(value);
    }
    lowering.admission.charge(bytes)?;
    let tensor =
        Tensor::from_values(shape, &values, lowering.generation).map_err(|_| OnnxError::Limit)?;
    lowering.add_constant(port, tensor)?;
    Ok(name)
}

pub(super) fn lower(mut source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if !(2..=3).contains(&source.inputs.len())
        || source.outputs.len() != 1
        || source.inputs[..2].iter().any(String::is_empty)
    {
        return Err(OnnxError::Graph);
    }
    match source.attrs.remove("mode") {
        None => {}
        Some(AttrValue::String(mode)) if mode == "constant" => {}
        Some(AttrValue::String(_)) => return Err(OnnxError::Unsupported),
        Some(_) => return Err(OnnxError::Graph),
    }
    if !source.attrs.is_empty() {
        return Err(OnnxError::Unsupported);
    }
    let input = lowering
        .known
        .get(&source.inputs[0])
        .ok_or(OnnxError::Graph)?;
    if input.dtype() != DType::F32 {
        return Err(OnnxError::Unsupported);
    }
    let dims = input.shape().dims().to_vec();
    if !(1..=4).contains(&dims.len()) {
        return Err(OnnxError::Unsupported);
    }
    let pads = lowering.constant_i64_vector(&source.inputs[1])?;
    let plan = plan(&dims, &pads)?;
    let value = fill(&source, lowering)?;
    let nodes = (usize::from(plan.crop) + plan.axes).max(1);
    let values = nodes.checked_add(plan.parameters).ok_or(OnnxError::Limit)?;
    let helpers = values - 1; // The source output name is already reserved.
    let limits = lowering.admission.limits;
    if byte_count(&plan.output)? > limits.tensor_bytes
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
            .checked_add(helpers)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
        || lowering
            .parameter_bytes
            .checked_add(plan.bytes)
            .ok_or(OnnxError::Limit)?
            > limits.parameter_bytes
    {
        return Err(OnnxError::Limit);
    }
    lowering.admission.charge(values + dims.len())?;
    let mut input = source.inputs[0].clone();
    if !plan.crop && plan.axes == 0 {
        return lowering.append(
            GraphNode::new(
                source.id,
                OpCode::Reshape,
                source.label,
                vec![input],
                source.outputs,
                AttributeMap::from([(
                    "shape".into(),
                    AttrValue::IntList(
                        dims.iter()
                            .map(|&n| i64::try_from(n).map_err(|_| OnnxError::Limit))
                            .collect::<Result<Vec<_>>>()?,
                    ),
                )]),
            )
            .map_err(|_| OnnxError::Graph)?,
        );
    }
    if plan.crop {
        let output = if plan.axes == 0 {
            source.outputs[0].clone()
        } else {
            lowering.fresh_name(&format!("{}-pad-crop", source.id))?
        };
        let attrs = AttributeMap::from([
            ("starts".into(), AttrValue::IntList(plan.starts)),
            ("ends".into(), AttrValue::IntList(plan.ends)),
            (
                "axes".into(),
                AttrValue::IntList((0..dims.len()).map(|axis| axis as i64).collect()),
            ),
            ("steps".into(), AttrValue::IntList(vec![1; dims.len()])),
        ]);
        lowering.append(
            GraphNode::new(
                format!("{}-pad-crop", source.id),
                OpCode::Slice,
                source.label.clone(),
                vec![input],
                vec![output.clone()],
                attrs,
            )
            .map_err(|_| OnnxError::Graph)?,
        )?;
        input = output;
    }
    let mut shape = plan.cropped;
    let mut remaining = plan.axes;
    for axis in 0..dims.len() {
        let (before, after) = (plan.before[axis], plan.after[axis]);
        if before == 0 && after == 0 {
            continue;
        }
        let base = format!("{}-pad-axis-{axis}", source.id);
        let mut parts = Vec::new();
        if before > 0 {
            let mut fill_shape = shape.clone();
            fill_shape[axis] = before;
            parts.push(parameter(
                lowering,
                &format!("{base}-before"),
                fill_shape,
                value,
            )?);
        }
        parts.push(input);
        if after > 0 {
            let mut fill_shape = shape.clone();
            fill_shape[axis] = after;
            parts.push(parameter(
                lowering,
                &format!("{base}-after"),
                fill_shape,
                value,
            )?);
        }
        remaining -= 1;
        let output = if remaining == 0 {
            source.outputs[0].clone()
        } else {
            lowering.fresh_name(&format!("{base}-value"))?
        };
        lowering.append(
            GraphNode::new(
                base,
                OpCode::Concat,
                source.label.clone(),
                parts,
                vec![output.clone()],
                AttributeMap::from([("axis".into(), AttrValue::Int(axis as i64))]),
            )
            .map_err(|_| OnnxError::Graph)?,
        )?;
        shape[axis] = plan.output[axis];
        input = output;
    }
    Ok(())
}
