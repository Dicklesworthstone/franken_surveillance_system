#![forbid(unsafe_code)]
//! Static NCHW ConvTranspose-11 through the frozen native Conv2d and layout kernels.
//!
//! https://onnx.ai/onnx/operators/onnx__ConvTranspose.html#convtranspose-11
//! Constant filters are channel-transposed within each group and spatially reversed.
//! Strided inputs are interleaved with exact positive zeros, never input-dependent
//! arithmetic (Inf - Inf would corrupt padding). One scalar zero and logarithmic
//! Concat helpers avoid image-sized parameter tensors. Native ordered F32 convolution
//! defines rounding/overflow; this is not a cross-framework bitwise equivalence claim.

use fss_tensor::{DType, Tensor};

use super::{Lowering, OnnxError, Result, SourceNode, port};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(OnnxError::Limit)
}

fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or(OnnxError::Limit)
}

fn count(dims: &[usize]) -> Result<usize> {
    dims.iter().try_fold(1_usize, |n, &dim| mul(n, dim))
}

fn shape_admission(dims: &[usize], lowering: &mut Lowering<'_, '_>) -> Result<()> {
    lowering.admission.charge(dims.len())?;
    if dims.contains(&0) || mul(count(dims)?, 4)? > lowering.admission.limits.tensor_bytes {
        return Err(OnnxError::Limit);
    }
    Ok(())
}

fn integers<const N: usize>(value: AttrValue, positive: bool) -> Result<[usize; N]> {
    let AttrValue::IntList(values) = value else {
        return Err(OnnxError::Graph);
    };
    if values.len() != N {
        return Err(OnnxError::Graph);
    }
    let mut out = [0; N];
    for (target, value) in out.iter_mut().zip(values) {
        *target = usize::try_from(value).map_err(|_| OnnxError::Graph)?;
        if positive && *target == 0 {
            return Err(OnnxError::Graph);
        }
    }
    Ok(out)
}

fn pair(attrs: &mut AttributeMap, key: &str, default: usize) -> Result<[usize; 2]> {
    attrs
        .remove(key)
        .map(|value| integers(value, default != 0))
        .transpose()
        .map(|value| value.unwrap_or([default; 2]))
}

fn dims_attr(dims: &[usize]) -> Result<AttrValue> {
    Ok(AttrValue::IntList(
        dims.iter()
            .map(|&dim| i64::try_from(dim).map_err(|_| OnnxError::Limit))
            .collect::<Result<Vec<_>>>()?,
    ))
}

// One existing singleton plus doubles and optional unit appends. The bound is
// logarithmic even for large spatial/batch/channel dimensions.
fn repeat_nodes(count: usize) -> usize {
    (usize::BITS - 1 - count.leading_zeros() + count.count_ones() - 1) as usize
}

struct Stretch {
    axis: usize,
    unit: Vec<usize>,
    zeros: Vec<usize>,
    flat: [usize; 4],
    output: [usize; 4],
    zero_count: usize,
}

struct Plan {
    weights: [usize; 4],
    groups: usize,
    dilations: [usize; 2],
    padding: [usize; 4],
    crop_start: [usize; 2],
    output: [usize; 4],
    stretches: Vec<Stretch>,
    crop: bool,
    nodes: usize,
    parameter_bytes: usize,
}

fn plan(
    source: &mut SourceNode<'_>,
    input: [usize; 4],
    weights: [usize; 4],
    lowering: &mut Lowering<'_, '_>,
) -> Result<Plan> {
    let strides = pair(&mut source.attrs, "strides", 1)?;
    let dilations = pair(&mut source.attrs, "dilations", 1)?;
    let adjustment = pair(&mut source.attrs, "output_padding", 0)?;
    let groups = match source.attrs.remove("group") {
        None => 1,
        Some(AttrValue::Int(value)) if value > 0 => {
            usize::try_from(value).map_err(|_| OnnxError::Limit)?
        }
        Some(_) => return Err(OnnxError::Graph),
    };
    if input[1] != weights[0] || !input[1].is_multiple_of(groups) {
        return Err(OnnxError::Graph);
    }
    let channels = mul(weights[1], groups)?;
    if let Some(value) = source.attrs.remove("kernel_shape") {
        if integers::<2>(value, true)? != weights[2..] {
            return Err(OnnxError::Graph);
        }
    }
    let mode = match source.attrs.remove("auto_pad") {
        None => "NOTSET".to_owned(),
        Some(AttrValue::String(mode))
            if matches!(
                mode.as_str(),
                "NOTSET" | "VALID" | "SAME_UPPER" | "SAME_LOWER"
            ) =>
        {
            mode
        }
        Some(AttrValue::String(_)) => return Err(OnnxError::Unsupported),
        Some(_) => return Err(OnnxError::Graph),
    };
    let explicit_pads = source
        .attrs
        .remove("pads")
        .map(|value| integers::<4>(value, false))
        .transpose()?;
    if mode != "NOTSET" && explicit_pads.is_some() {
        return Err(OnnxError::Graph);
    }
    let target = source
        .attrs
        .remove("output_shape")
        .map(|value| integers::<2>(value, true))
        .transpose()?;
    if !source.attrs.is_empty() {
        return Err(OnnxError::Unsupported);
    }

    let mut padding = [0; 4];
    let mut crop_start = [0; 2];
    let mut output = [input[0], channels, 0, 0];
    let mut convolution = output;
    for axis in 0..2 {
        if adjustment[axis] >= strides[axis].max(dilations[axis]) {
            return Err(OnnxError::Graph);
        }
        let extent = add(mul(input[axis + 2] - 1, strides[axis])?, 1)?;
        let margin = mul(weights[axis + 2] - 1, dilations[axis])?;
        let after_margin = add(margin, adjustment[axis])?;
        let full = add(extent, after_margin)?;
        let desired = match target {
            Some(target) => Some(target[axis]),
            None if mode.starts_with("SAME_") => Some(mul(input[axis + 2], strides[axis])?),
            None => None,
        };
        let (before, after) = if let Some(desired) = desired {
            // output_shape overrides explicit pads by the ONNX contract. Negative
            // inferred padding is outside this profile, never clamped to zero.
            let total = full.checked_sub(desired).ok_or(OnnxError::Unsupported)?;
            let before = total / 2 + usize::from(mode != "SAME_UPPER") * (total % 2);
            (before, total - before)
        } else {
            let pads = explicit_pads.unwrap_or([0; 4]);
            (pads[axis], pads[axis + 2])
        };
        output[axis + 2] = full
            .checked_sub(add(before, after)?)
            .filter(|&size| size != 0)
            .ok_or(OnnxError::Graph)?;
        // Most crops are expressed directly as native Conv2d padding. Crops
        // exceeding the kernel margin use one final Slice, not negative pads.
        padding[axis] = margin.saturating_sub(before);
        padding[axis + 2] = after_margin.saturating_sub(after);
        crop_start[axis] = before.saturating_sub(margin);
        let crop_end = after.saturating_sub(after_margin);
        convolution[axis + 2] = add(add(output[axis + 2], crop_start[axis])?, crop_end)?;
    }
    shape_admission(&output, lowering)?;
    shape_admission(&convolution, lowering)?;

    let crop = output != convolution;
    let mut nodes = 1 + usize::from(crop);
    let mut dims = input;
    let mut stretches = Vec::with_capacity(2);
    for axis in 2..4 {
        let stride = strides[axis - 2];
        // There is no inter-sample gap when an axis contains only one sample.
        if stride == 1 || dims[axis] == 1 {
            continue;
        }
        let mut unit = dims.to_vec();
        unit.insert(axis + 1, 1);
        let mut zeros = unit.clone();
        zeros[axis + 1] = stride - 1;
        let zero_count = count(&zeros)?;
        let mut flat = dims;
        flat[axis] = mul(dims[axis], stride)?;
        let mut stretched = flat;
        stretched[axis] = add(mul(dims[axis] - 1, stride)?, 1)?;
        shape_admission(&flat, lowering)?;
        shape_admission(&zeros, lowering)?;
        nodes = add(nodes, add(5, repeat_nodes(zero_count))?)?;
        stretches.push(Stretch {
            axis,
            unit,
            zeros,
            flat,
            output: stretched,
            zero_count,
        });
        dims = stretched;
    }
    let parameter_bytes = add(
        mul(count(&weights)?, 4)?,
        usize::from(!stretches.is_empty()) * 4,
    )?;
    let parameters = 1 + usize::from(!stretches.is_empty());
    let values = add(nodes, parameters)?;
    let limits = lowering.admission.limits;
    if add(lowering.nodes.len(), nodes)? > limits.nodes
        || add(lowering.known.len(), values)? > limits.tensors
        || add(lowering.reserved.len(), values - 1)? > limits.tensors
        || add(lowering.parameter_bytes, parameter_bytes)? > limits.parameter_bytes
    {
        return Err(OnnxError::Limit);
    }
    lowering.admission.charge(values)?;
    Ok(Plan {
        weights: [channels, input[1] / groups, weights[2], weights[3]],
        groups,
        dilations,
        padding,
        crop_start,
        output,
        stretches,
        crop,
        nodes,
        parameter_bytes,
    })
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
    let id = if *remaining == 0 {
        source.id.clone()
    } else {
        format!("{}-transposeconv-{ordinal}", source.id)
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

fn transform_weights(
    source: &SourceNode<'_>,
    weights: &Tensor,
    plan: &Plan,
    lowering: &mut Lowering<'_, '_>,
) -> Result<String> {
    let shape = plan.weights;
    let bytes = mul(count(&shape)?, 4)?;
    lowering.admission.charge(bytes)?;
    let original = weights.to_vec::<f32>().map_err(|_| OnnxError::Graph)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(original.len())
        .map_err(|_| OnnxError::Limit)?;
    let out_per_group = shape[0] / plan.groups;
    // All products below are bounded by the already admitted original tensor.
    for group in 0..plan.groups {
        for output in 0..out_per_group {
            for input in 0..shape[1] {
                for row in (0..shape[2]).rev() {
                    for column in (0..shape[3]).rev() {
                        lowering.admission.charge(1)?;
                        let index = (((group * shape[1] + input) * out_per_group + output)
                            * shape[2]
                            + row)
                            * shape[3]
                            + column;
                        values.push(original[index]);
                    }
                }
            }
        }
    }
    let name = lowering.fresh_name(&format!("{}-transposeconv-weights", source.id))?;
    let port = port(
        name.clone(),
        shape.to_vec(),
        lowering.generation,
        lowering.admission,
    )?;
    lowering.admission.charge(bytes)?;
    let tensor = Tensor::from_values(port.shape().clone(), &values, lowering.generation)
        .map_err(|_| OnnxError::Limit)?;
    lowering.add_constant(port, tensor)?;
    lowering.control_uses.insert(source.inputs[1].clone());
    Ok(name)
}

fn repeat_zero(
    source: &SourceNode<'_>,
    lowering: &mut Lowering<'_, '_>,
    remaining: &mut usize,
    zero: &str,
    count: usize,
) -> Result<String> {
    let mut block = zero.to_owned();
    let highest = usize::BITS - 1 - count.leading_zeros();
    for bit in (0..highest).rev() {
        block = append(
            source,
            lowering,
            remaining,
            OpCode::Concat,
            vec![block.clone(), block],
            AttributeMap::from([("axis".into(), AttrValue::Int(0))]),
        )?;
        if count & (1_usize << bit) != 0 {
            block = append(
                source,
                lowering,
                remaining,
                OpCode::Concat,
                vec![block, zero.to_owned()],
                AttributeMap::from([("axis".into(), AttrValue::Int(0))]),
            )?;
        }
    }
    Ok(block)
}

pub(super) fn lower(mut source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if !(2..=3).contains(&source.inputs.len())
        || source.outputs.len() != 1
        || source.inputs[..2].iter().any(String::is_empty)
    {
        return Err(OnnxError::Graph);
    }
    let mut shapes = [[0_usize; 4]; 2];
    for (shape, name) in shapes.iter_mut().zip(&source.inputs) {
        let input = lowering.known.get(name).ok_or(OnnxError::Graph)?;
        if input.dtype() != DType::F32 || input.shape().dims().contains(&0) {
            return Err(OnnxError::Unsupported);
        }
        *shape = input
            .shape()
            .dims()
            .try_into()
            .map_err(|_| OnnxError::Unsupported)?;
    }
    let weights = lowering
        .constants
        .get(&source.inputs[1])
        .cloned()
        .ok_or(OnnxError::Unsupported)?;
    let plan = plan(&mut source, shapes[0], shapes[1], lowering)?;
    if let Some(name) = source.inputs.get(2).filter(|name| !name.is_empty()) {
        let bias = lowering.known.get(name).ok_or(OnnxError::Graph)?;
        if bias.dtype() != DType::F32 || bias.shape().dims() != [plan.output[1]] {
            return Err(OnnxError::Graph);
        }
    }
    let before = lowering.parameter_bytes;
    let weight = transform_weights(&source, &weights, &plan, lowering)?;
    let zero = if !plan.stretches.is_empty() {
        let name = lowering.fresh_name(&format!("{}-transposeconv-zero", source.id))?;
        let port = port(
            name.clone(),
            vec![1],
            lowering.generation,
            lowering.admission,
        )?;
        lowering.admission.charge(4)?;
        let tensor = Tensor::from_values(port.shape().clone(), &[0.0_f32], lowering.generation)
            .map_err(|_| OnnxError::Limit)?;
        lowering.add_constant(port, tensor)?;
        Some(name)
    } else {
        None
    };
    if lowering.parameter_bytes != add(before, plan.parameter_bytes)? {
        return Err(OnnxError::Graph);
    }
    let mut remaining = plan.nodes;
    let mut input = source.inputs[0].clone();
    for stretch in &plan.stretches {
        let zero = zero.as_deref().ok_or(OnnxError::Graph)?;
        let zeros = repeat_zero(&source, lowering, &mut remaining, zero, stretch.zero_count)?;
        let zeros = append(
            &source,
            lowering,
            &mut remaining,
            OpCode::Reshape,
            vec![zeros],
            AttributeMap::from([("shape".into(), dims_attr(&stretch.zeros)?)]),
        )?;
        let unit = append(
            &source,
            lowering,
            &mut remaining,
            OpCode::Reshape,
            vec![input],
            AttributeMap::from([("shape".into(), dims_attr(&stretch.unit)?)]),
        )?;
        let wide = append(
            &source,
            lowering,
            &mut remaining,
            OpCode::Concat,
            vec![unit, zeros],
            AttributeMap::from([("axis".into(), AttrValue::Int((stretch.axis + 1) as i64))]),
        )?;
        let flat = append(
            &source,
            lowering,
            &mut remaining,
            OpCode::Reshape,
            vec![wide],
            AttributeMap::from([("shape".into(), dims_attr(&stretch.flat)?)]),
        )?;
        input = append(
            &source,
            lowering,
            &mut remaining,
            OpCode::Slice,
            vec![flat],
            AttributeMap::from([
                ("axes".into(), AttrValue::IntList(vec![stretch.axis as i64])),
                ("starts".into(), AttrValue::IntList(vec![0])),
                ("ends".into(), dims_attr(&[stretch.output[stretch.axis]])?),
                ("steps".into(), AttrValue::IntList(vec![1])),
            ]),
        )?;
    }
    let mut inputs = vec![input, weight];
    if let Some(name) = source.inputs.get(2).filter(|name| !name.is_empty()) {
        inputs.push(name.clone());
    }
    let output = append(
        &source,
        lowering,
        &mut remaining,
        OpCode::Conv2d,
        inputs,
        AttributeMap::from([
            ("strides".into(), AttrValue::IntList(vec![1, 1])),
            ("dilations".into(), dims_attr(&plan.dilations)?),
            ("padding".into(), dims_attr(&plan.padding)?),
            ("groups".into(), AttrValue::Int(plan.groups as i64)),
        ]),
    )?;
    if plan.crop {
        append(
            &source,
            lowering,
            &mut remaining,
            OpCode::Slice,
            vec![output],
            AttributeMap::from([
                ("axes".into(), AttrValue::IntList(vec![2, 3])),
                ("starts".into(), dims_attr(&plan.crop_start)?),
                (
                    "ends".into(),
                    dims_attr(&[
                        add(plan.crop_start[0], plan.output[2])?,
                        add(plan.crop_start[1], plan.output[3])?,
                    ])?,
                ),
                ("steps".into(), AttrValue::IntList(vec![1, 1])),
            ]),
        )?;
    }
    if remaining != 0 {
        return Err(OnnxError::Graph);
    }
    Ok(())
}
