#![forbid(unsafe_code)]
//! Static AveragePool-11 and GlobalAveragePool-1, selected by ONNX opset 13.
//!
//! Contracts: https://onnx.ai/onnx/operators/onnx__AveragePool.html#averagepool-11
//! and https://onnx.ai/onnx/operators/onnx__GlobalAveragePool.html#globalaveragepool-1
//! A depthwise convolution with exact one weights accumulates each spatial window
//! in the native scalar executor's row-major F32 order. A separate Div performs
//! the mean; reciprocal weights would change rounding and intermediate overflow.

use fss_tensor::{DType, Tensor};

use super::{Lowering, OnnxError, Result, SourceNode, padding, port};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

fn dimensions<const N: usize>(
    attrs: &mut AttributeMap,
    name: &str,
    default: Option<[usize; N]>,
) -> Result<[usize; N]> {
    let values = match attrs.remove(name) {
        None => return default.ok_or(OnnxError::Graph),
        Some(AttrValue::IntList(values)) if values.len() == N => values,
        Some(_) => return Err(OnnxError::Graph),
    };
    let mut output = [0; N];
    for (target, value) in output.iter_mut().zip(values) {
        *target = usize::try_from(value).map_err(|_| OnnxError::Graph)?;
    }
    Ok(output)
}

struct Pool {
    input: [usize; 4],
    kernel: [usize; 2],
    strides: [usize; 2],
    pads: [usize; 4],
    output: [usize; 4],
    divisor_grid: bool,
    // Non-2-D global pooling temporarily flattens only spatial dimensions.
    restore: Option<Vec<usize>>,
}

fn plan(source: &mut SourceNode<'_>, dims: &[usize]) -> Result<Pool> {
    if source.op == "GlobalAveragePool" {
        if !source.attrs.is_empty() || !(3..=8).contains(&dims.len()) {
            return Err(OnnxError::Unsupported);
        }
        let (input, restore) = if dims.len() == 4 {
            ([dims[0], dims[1], dims[2], dims[3]], None)
        } else {
            let spatial = dims[2..].iter().try_fold(1_usize, |product, &n| {
                product.checked_mul(n).ok_or(OnnxError::Limit)
            })?;
            let mut output = dims.to_vec();
            output[2..].fill(1);
            ([dims[0], dims[1], spatial, 1], Some(output))
        };
        return Ok(Pool {
            input,
            kernel: [input[2], input[3]],
            strides: [1, 1],
            pads: [0; 4],
            output: [input[0], input[1], 1, 1],
            divisor_grid: false,
            restore,
        });
    }
    let input: [usize; 4] = dims.try_into().map_err(|_| OnnxError::Unsupported)?;
    let kernel = dimensions(&mut source.attrs, "kernel_shape", None::<[usize; 2]>)?;
    let strides = dimensions(&mut source.attrs, "strides", Some([1, 1]))?;
    padding::resolve(
        &mut source.attrs,
        [input[2], input[3]],
        kernel,
        strides,
        [1, 1],
    )?;
    let pads = dimensions(&mut source.attrs, "pads", Some([0; 4]))?;
    let include_padding = match source.attrs.remove("count_include_pad") {
        None | Some(AttrValue::Int(0)) => false,
        Some(AttrValue::Int(1)) => true,
        Some(_) => return Err(OnnxError::Graph),
    };
    match source.attrs.remove("ceil_mode") {
        None | Some(AttrValue::Int(0)) => {}
        Some(AttrValue::Int(_)) => return Err(OnnxError::Unsupported),
        Some(_) => return Err(OnnxError::Graph),
    }
    // In particular, dilations belongs to a later AveragePool schema.
    if !source.attrs.is_empty() {
        return Err(OnnxError::Unsupported);
    }
    if kernel.contains(&0) || strides.contains(&0) {
        return Err(OnnxError::Graph);
    }
    // Together with floor output sizing, this proves every admitted window has
    // a real input sample. There is no empty-window mean or zero divisor.
    if (0..4).any(|index| pads[index] >= kernel[index % 2]) {
        return Err(OnnxError::Unsupported);
    }
    let mut output = input;
    for axis in 0..2 {
        let padded = input[axis + 2]
            .checked_add(pads[axis])
            .and_then(|n| n.checked_add(pads[axis + 2]))
            .ok_or(OnnxError::Limit)?;
        output[axis + 2] =
            padded.checked_sub(kernel[axis]).ok_or(OnnxError::Graph)? / strides[axis] + 1;
    }
    Ok(Pool {
        input,
        kernel,
        strides,
        pads,
        output,
        divisor_grid: !include_padding && pads != [0; 4],
        restore: None,
    })
}

fn parameter(
    lowering: &mut Lowering<'_, '_>,
    base: &str,
    dimensions: Vec<usize>,
    mut value: impl FnMut(usize) -> Result<f32>,
) -> Result<String> {
    let name = lowering.fresh_name(base)?;
    let port = port(
        name.clone(),
        dimensions,
        lowering.generation,
        lowering.admission,
    )?;
    let shape = port.shape().clone();
    let count = shape.num_elements().map_err(|_| OnnxError::Limit)?;
    let bytes = shape.size_bytes(DType::F32).map_err(|_| OnnxError::Limit)?;
    lowering.admission.charge(bytes)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| OnnxError::Limit)?;
    for index in 0..count {
        lowering.admission.charge(1)?;
        values.push(value(index)?);
    }
    lowering.admission.charge(bytes)?;
    let tensor =
        Tensor::from_values(shape, &values, lowering.generation).map_err(|_| OnnxError::Limit)?;
    lowering.add_constant(port, tensor)?;
    Ok(name)
}

fn reshape(
    lowering: &mut Lowering<'_, '_>,
    id: &str,
    label: &str,
    input: String,
    output: String,
    shape: &[usize],
) -> Result<()> {
    let shape = shape
        .iter()
        .map(|&n| i64::try_from(n).map_err(|_| OnnxError::Limit))
        .collect::<Result<Vec<_>>>()?;
    lowering.append(
        GraphNode::new(
            id,
            OpCode::Reshape,
            label,
            vec![input],
            vec![output],
            AttributeMap::from([("shape".into(), AttrValue::IntList(shape))]),
        )
        .map_err(|_| OnnxError::Graph)?,
    )
}

fn attribute(values: &[usize]) -> Result<AttrValue> {
    Ok(AttrValue::IntList(
        values
            .iter()
            .map(|&n| i64::try_from(n).map_err(|_| OnnxError::Limit))
            .collect::<Result<Vec<_>>>()?,
    ))
}

/// Count an axis's intersection with the unpadded input, in padded coordinates.
fn valid_samples(index: usize, axis: usize, pool: &Pool) -> Result<usize> {
    let start = index
        .checked_mul(pool.strides[axis])
        .ok_or(OnnxError::Limit)?;
    let end = start
        .checked_add(pool.kernel[axis])
        .ok_or(OnnxError::Limit)?;
    let input_end = pool.pads[axis]
        .checked_add(pool.input[axis + 2])
        .ok_or(OnnxError::Limit)?;
    Ok(end
        .min(input_end)
        .saturating_sub(start.max(pool.pads[axis])))
}

pub(super) fn lower(mut source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if source.inputs.len() != 1 || source.outputs.len() != 1 {
        return Err(OnnxError::Graph);
    }
    let input = lowering
        .known
        .get(&source.inputs[0])
        .ok_or(OnnxError::Graph)?;
    if input.dtype() != DType::F32 || input.shape().dims().contains(&0) {
        return Err(OnnxError::Unsupported);
    }
    let pool = plan(&mut source, input.shape().dims())?;
    // Validate inferred data size before constructing any generated parameter.
    port(
        source.outputs[0].clone(),
        pool.output.to_vec(),
        lowering.generation,
        lowering.admission,
    )?;
    let area = pool.kernel[0]
        .checked_mul(pool.kernel[1])
        .ok_or(OnnxError::Limit)?;
    let weight_bytes = pool.input[1]
        .checked_mul(area)
        .and_then(|n| n.checked_mul(4))
        .ok_or(OnnxError::Limit)?;
    let divisor_count = if pool.divisor_grid {
        pool.output[2]
            .checked_mul(pool.output[3])
            .ok_or(OnnxError::Limit)?
    } else {
        1
    };
    let divisor_bytes = divisor_count.checked_mul(4).ok_or(OnnxError::Limit)?;
    let generated_bytes = weight_bytes
        .checked_add(divisor_bytes)
        .ok_or(OnnxError::Limit)?;
    let nodes = if pool.restore.is_some() { 4 } else { 2 };
    let limits = lowering.admission.limits;
    if lowering.nodes.len().checked_add(nodes).ok_or(OnnxError::Limit)? > limits.nodes
        || lowering.known.len().checked_add(nodes + 2).ok_or(OnnxError::Limit)? > limits.tensors
        || lowering.reserved.len().checked_add(nodes + 1).ok_or(OnnxError::Limit)? > limits.tensors
        || lowering.parameter_bytes.checked_add(generated_bytes).ok_or(OnnxError::Limit)?
            > limits.parameter_bytes
        || weight_bytes > limits.tensor_bytes
        || divisor_bytes > limits.tensor_bytes
        // Every integer divisor must remain exact when represented as F32.
        || area > (1 << 24)
    {
        return Err(OnnxError::Limit);
    }
    let weights = parameter(
        lowering,
        &format!("{}-pool-ones", source.id),
        vec![pool.input[1], 1, pool.kernel[0], pool.kernel[1]],
        |_| Ok(1.0),
    )?;
    let divisor_shape = if pool.divisor_grid {
        vec![1, 1, pool.output[2], pool.output[3]]
    } else {
        Vec::new()
    };
    let denominator = parameter(
        lowering,
        &format!("{}-pool-divisors", source.id),
        divisor_shape,
        |index| {
            let count = if pool.divisor_grid {
                valid_samples(index / pool.output[3], 0, &pool)?
                    .checked_mul(valid_samples(index % pool.output[3], 1, &pool)?)
                    .ok_or(OnnxError::Limit)?
            } else {
                area
            };
            if count == 0 || count > area {
                return Err(OnnxError::Graph);
            }
            Ok(count as f32)
        },
    )?;
    let mut input = source.inputs[0].clone();
    if pool.restore.is_some() {
        let id = format!("{}-pool-flatten", source.id);
        let flattened = lowering.fresh_name(&id)?;
        reshape(
            lowering,
            &id,
            &source.label,
            input,
            flattened.clone(),
            &pool.input,
        )?;
        input = flattened;
    }
    let sum_id = format!("{}-pool-sum", source.id);
    let sum = lowering.fresh_name(&sum_id)?;
    let attrs = AttributeMap::from([
        (
            "groups".into(),
            AttrValue::Int(i64::try_from(pool.input[1]).map_err(|_| OnnxError::Limit)?),
        ),
        ("padding".into(), attribute(&pool.pads)?),
        ("strides".into(), attribute(&pool.strides)?),
    ]);
    lowering.append(
        GraphNode::new(
            sum_id,
            OpCode::Conv2d,
            &source.label,
            vec![input, weights],
            vec![sum.clone()],
            attrs,
        )
        .map_err(|_| OnnxError::Graph)?,
    )?;
    let divide_id = if pool.restore.is_some() {
        format!("{}-pool-mean", source.id)
    } else {
        source.id.clone()
    };
    let output = if pool.restore.is_some() {
        lowering.fresh_name(&divide_id)?
    } else {
        source.outputs[0].clone()
    };
    lowering.append(
        GraphNode::new(
            &divide_id,
            OpCode::Div,
            &source.label,
            vec![sum, denominator],
            vec![output.clone()],
            AttributeMap::new(),
        )
        .map_err(|_| OnnxError::Graph)?,
    )?;
    if let Some(shape) = pool.restore {
        reshape(
            lowering,
            &source.id,
            &source.label,
            output,
            source.outputs[0].clone(),
            &shape,
        )?;
    }
    Ok(())
}
