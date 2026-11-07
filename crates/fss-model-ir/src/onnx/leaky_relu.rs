#![forbid(unsafe_code)]
//! Exact bounded LeakyRelu-6 lowering for the admitted default-domain opset 13.
//!
//! https://onnx.ai/onnx/operators/onnx__LeakyRelu.html#leakyrelu-6
//! For finite F32 inputs and 0 <= alpha <= 1, max(x, alpha*x) implements
//! alpha*x for x < 0 and x otherwise without overflowing an unselected branch.
//! The original input is first in the MaxPool window: strict first-value ties
//! preserve signed zeros and subnormal rounding. No new frozen operator is added.

use fss_tensor::{DType, Tensor};

use super::{Lowering, OnnxError, Result, SourceNode, port};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

fn reshape(
    lowering: &mut Lowering<'_, '_>,
    id: &str,
    label: &str,
    input: String,
    output: String,
    dims: &[usize],
) -> Result<()> {
    let dims = dims
        .iter()
        .map(|&value| i64::try_from(value).map_err(|_| OnnxError::Limit))
        .collect::<Result<Vec<_>>>()?;
    lowering.append(
        GraphNode::new(
            id,
            OpCode::Reshape,
            label,
            vec![input],
            vec![output],
            AttributeMap::from([("shape".into(), AttrValue::IntList(dims))]),
        )
        .map_err(|_| OnnxError::Graph)?,
    )
}

pub(super) fn lower(mut source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if source.inputs.len() != 1 || source.outputs.len() != 1 || source.inputs[0].is_empty() {
        return Err(OnnxError::Graph);
    }
    let alpha = match source.attrs.remove("alpha") {
        None => 0.01_f32,
        Some(AttrValue::Float(value)) if value.is_finite() => value as f32,
        Some(AttrValue::Float(_)) => return Err(OnnxError::NonFinite),
        Some(_) => return Err(OnnxError::Graph),
    };
    if !alpha.is_finite() {
        return Err(OnnxError::NonFinite);
    }
    if !(0.0..=1.0).contains(&alpha) || !source.attrs.is_empty() {
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
    lowering.admission.charge(6 + dims.len())?;
    if alpha == 1.0 {
        return reshape(
            lowering,
            &source.id,
            &source.label,
            source.inputs[0].clone(),
            source.outputs[0].clone(),
            &dims,
        );
    }

    // Reserve the whole lowering before allocating its parameter or any helpers.
    // Five nodes add one scalar and five outputs; the source output is reserved.
    let limits = lowering.admission.limits;
    if elements.checked_mul(8).ok_or(OnnxError::Limit)? > limits.tensor_bytes
        || lowering
            .nodes
            .len()
            .checked_add(5)
            .ok_or(OnnxError::Limit)?
            > limits.nodes
        || lowering
            .known
            .len()
            .checked_add(6)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
        || lowering
            .reserved
            .len()
            .checked_add(5)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
        || lowering
            .parameter_bytes
            .checked_add(4)
            .ok_or(OnnxError::Limit)?
            > limits.parameter_bytes
    {
        return Err(OnnxError::Limit);
    }
    let alpha_name = lowering.fresh_name(&format!("{}-leaky-alpha", source.id))?;
    let scalar = port(
        alpha_name.clone(),
        Vec::new(),
        lowering.generation,
        lowering.admission,
    )?;
    lowering.admission.charge(4)?;
    let tensor = Tensor::from_values(scalar.shape().clone(), &[alpha], lowering.generation)
        .map_err(|_| OnnxError::Limit)?;
    lowering.add_constant(scalar, tensor)?;

    let flat = lowering.fresh_name(&format!("{}-leaky-flat", source.id))?;
    reshape(
        lowering,
        &format!("{}-leaky-flatten", source.id),
        &source.label,
        source.inputs[0].clone(),
        flat.clone(),
        &[1, 1, 1, elements],
    )?;
    let scaled = lowering.fresh_name(&format!("{}-leaky-scaled", source.id))?;
    lowering.append(
        GraphNode::new(
            format!("{}-leaky-scale", source.id),
            OpCode::Mul,
            source.label.clone(),
            vec![alpha_name, flat.clone()],
            vec![scaled.clone()],
            AttributeMap::new(),
        )
        .map_err(|_| OnnxError::Graph)?,
    )?;
    let stacked = lowering.fresh_name(&format!("{}-leaky-stacked", source.id))?;
    lowering.append(
        GraphNode::new(
            format!("{}-leaky-stack", source.id),
            OpCode::Concat,
            source.label.clone(),
            vec![flat, scaled],
            vec![stacked.clone()],
            AttributeMap::from([("axis".into(), AttrValue::Int(2))]),
        )
        .map_err(|_| OnnxError::Graph)?,
    )?;
    let selected = lowering.fresh_name(&format!("{}-leaky-selected", source.id))?;
    lowering.append(
        GraphNode::new(
            format!("{}-leaky-select", source.id),
            OpCode::MaxPool2d,
            source.label.clone(),
            vec![stacked],
            vec![selected.clone()],
            AttributeMap::from([("kernel_size".into(), AttrValue::IntList(vec![2, 1]))]),
        )
        .map_err(|_| OnnxError::Graph)?,
    )?;
    reshape(
        lowering,
        &source.id,
        &source.label,
        selected,
        source.outputs[0].clone(),
        &dims,
    )
}
