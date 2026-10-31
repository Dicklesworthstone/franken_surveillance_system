#![forbid(unsafe_code)]
//! BatchNormalization-9 inference, the schema selected by default-domain opset 13.
//!
//! Contract: https://onnx.ai/onnx/operators/onnx__BatchNormalization.html#batchnormalization-9
//! One output selects inference; training_mode is a later-schema attribute. The
//! admitted F32 evaluation order is (X - mean) / sqrt(var + epsilon) * scale + B.
//! Only the constant denominator is evaluated at import. Folding scale/divisor,
//! bias/mean or a preceding convolution changes rounding and intermediate overflow.

use fss_tensor::{DType, Shape, Tensor};

use super::{Lowering, OnnxError, Result, SourceNode, port};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

fn float_attribute(attrs: &mut AttributeMap, name: &str, default: f32) -> Result<f32> {
    match attrs.remove(name) {
        None => Ok(default),
        Some(AttrValue::Float(value)) if value.is_finite() => Ok(value as f32),
        Some(_) => Err(OnnxError::Graph),
    }
}

fn channel_parameter(
    name: &str,
    channels: usize,
    lowering: &mut Lowering<'_, '_>,
) -> Result<Tensor> {
    lowering.admission.charge(1)?;
    let known = lowering.known.get(name).ok_or(OnnxError::Graph)?;
    if known.dtype() != DType::F32 || known.shape().dims() != [channels] {
        return Err(OnnxError::Graph);
    }
    // Runtime parameters and data-derived statistics are outside this profile.
    // Unlike shape/Resize controls, channel vectors are not limited to eight values.
    lowering
        .constants
        .get(name)
        .cloned()
        .ok_or(OnnxError::Unsupported)
}

fn broadcast_parameter(
    source: &str,
    tensor: &Tensor,
    shape: &Shape,
    base: &str,
    lowering: &mut Lowering<'_, '_>,
) -> Result<String> {
    if tensor.shape() == shape {
        return Ok(source.to_owned());
    }
    // This immutable view shares source storage; no runtime reshape or channel
    // replication is needed. Its full logical size is still cumulatively charged.
    let bytes = shape.size_bytes(DType::F32).map_err(|_| OnnxError::Limit)?;
    lowering.admission.charge(bytes)?;
    let name = lowering.fresh_name(base)?;
    let value = tensor
        .reshape(shape.clone())
        .map_err(|_| OnnxError::Graph)?;
    let port = port(
        name.clone(),
        shape.dims().to_vec(),
        lowering.generation,
        lowering.admission,
    )?;
    lowering.add_constant(port, value)?;
    lowering.control_uses.insert(source.to_owned());
    Ok(name)
}

pub(super) fn lower(mut source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if source.inputs.len() != 5
        || source.outputs.len() != 1
        || source.inputs.iter().any(String::is_empty)
    {
        return Err(OnnxError::Graph);
    }
    let epsilon = float_attribute(&mut source.attrs, "epsilon", 1e-5_f32)?;
    // Momentum only affects training's running statistics. Validate its FLOAT
    // representation, but do not narrow or apply it to one-output inference.
    float_attribute(&mut source.attrs, "momentum", 0.9_f32)?;
    if !source.attrs.is_empty() {
        return Err(OnnxError::Unsupported);
    }
    if epsilon < 0.0 {
        return Err(OnnxError::Graph);
    }
    let input = lowering
        .known
        .get(&source.inputs[0])
        .ok_or(OnnxError::Graph)?;
    if input.dtype() != DType::F32
        || !(1..=8).contains(&input.rank())
        || input.shape().dims().contains(&0)
    {
        return Err(OnnxError::Unsupported);
    }
    let rank = input.rank();
    let channels = if rank == 1 {
        1
    } else {
        input.shape().dims()[1]
    };
    let parameters = [
        channel_parameter(&source.inputs[1], channels, lowering)?,
        channel_parameter(&source.inputs[2], channels, lowering)?,
        channel_parameter(&source.inputs[3], channels, lowering)?,
        channel_parameter(&source.inputs[4], channels, lowering)?,
    ];
    // Right-aligned broadcasting needs [C, 1, ...] for N,C,D1,...; rank-one
    // inputs have the schema's implicit single channel and use [1].
    let mut dimensions = vec![1; rank.saturating_sub(1).max(1)];
    dimensions[0] = channels;
    let shape = Shape::new(dimensions).map_err(|_| OnnxError::Limit)?;
    let bytes = shape.size_bytes(DType::F32).map_err(|_| OnnxError::Limit)?;
    let generated_parameters = if rank > 2 { 4 } else { 1 };
    let generated_bytes = bytes
        .checked_mul(generated_parameters)
        .ok_or(OnnxError::Limit)?;
    let limits = lowering.admission.limits;
    if lowering
        .nodes
        .len()
        .checked_add(4)
        .ok_or(OnnxError::Limit)?
        > limits.nodes
        || lowering
            .reserved
            .len()
            .checked_add(generated_parameters + 3)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
        || lowering
            .known
            .len()
            .checked_add(generated_parameters + 4)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
        || lowering
            .parameter_bytes
            .checked_add(generated_bytes)
            .ok_or(OnnxError::Limit)?
            > limits.parameter_bytes
        || bytes > limits.tensor_bytes
    {
        return Err(OnnxError::Limit);
    }

    // Both primitive operations round to F32 before export. sqrt is the IEEE-754
    // correctly rounded primitive, not a host transcendental approximation.
    // Charge each channel/checkpoint as well as the bounded tensor materialization.
    lowering.admission.charge(bytes)?;
    let variance = &parameters[3];
    let mut divisors = Vec::new();
    divisors
        .try_reserve_exact(channels)
        .map_err(|_| OnnxError::Limit)?;
    for channel in 0..channels {
        lowering.admission.charge(3)?;
        let value = variance
            .read_element::<f32>(&[channel])
            .map_err(|_| OnnxError::Graph)?;
        if value < 0.0 {
            return Err(OnnxError::Graph);
        }
        let shifted = value + epsilon;
        if !shifted.is_finite() {
            return Err(OnnxError::NonFinite);
        }
        if shifted <= 0.0 {
            return Err(OnnxError::Graph);
        }
        divisors.push(shifted.sqrt());
    }
    lowering.admission.charge(bytes)?;
    let denominator = lowering.fresh_name(&format!("{}-batchnorm-denominator", source.id))?;
    let denominator_port = port(
        denominator.clone(),
        shape.dims().to_vec(),
        lowering.generation,
        lowering.admission,
    )?;
    let denominator_tensor = Tensor::from_values(shape.clone(), &divisors, lowering.generation)
        .map_err(|_| OnnxError::Limit)?;
    lowering.add_constant(denominator_port, denominator_tensor)?;
    lowering.control_uses.insert(source.inputs[4].clone());

    let mut channels = Vec::new();
    for (index, suffix) in ["scale", "bias", "mean"].into_iter().enumerate() {
        channels.push(broadcast_parameter(
            &source.inputs[index + 1],
            &parameters[index],
            &shape,
            &format!("{}-batchnorm-{suffix}", source.id),
            lowering,
        )?);
    }
    let mut current = source.inputs[0].clone();
    for (ordinal, (op, right, suffix)) in [
        (OpCode::Sub, channels[2].clone(), "center"),
        (OpCode::Div, denominator, "normalize"),
        (OpCode::Mul, channels[0].clone(), "scale"),
        (OpCode::Add, channels[1].clone(), "bias"),
    ]
    .into_iter()
    .enumerate()
    {
        let id = if ordinal == 3 {
            source.id.clone()
        } else {
            format!("{}-batchnorm-{suffix}", source.id)
        };
        let output = if ordinal == 3 {
            source.outputs[0].clone()
        } else {
            lowering.fresh_name(&id)?
        };
        lowering.append(
            GraphNode::new(
                id,
                op,
                &source.label,
                vec![current, right],
                vec![output.clone()],
                AttributeMap::new(),
            )
            .map_err(|_| OnnxError::Graph)?,
        )?;
        current = output;
    }
    Ok(())
}
