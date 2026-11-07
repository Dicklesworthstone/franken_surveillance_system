#![forbid(unsafe_code)]
//! Bounded HardSigmoid-6, the version selected by default-domain opset 13.
//!
//! https://onnx.ai/onnx/operators/onnx__HardSigmoid.html#hardsigmoid-6
//! Separate native F32 multiply/add followed by Clip implements the source
//! affine order without FMA. Admission proves that the entire finite F32 input
//! domain has finite affine intermediates before generating any parameter.

use fss_tensor::DType;

use super::{Lowering, OnnxError, Result, SourceNode, clip};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

fn coefficient(attrs: &mut AttributeMap, name: &str, default: f32) -> Result<f32> {
    let value = match attrs.remove(name) {
        None => default,
        Some(AttrValue::Float(value)) if value.is_finite() => value as f32,
        Some(AttrValue::Float(_)) => return Err(OnnxError::NonFinite),
        Some(_) => return Err(OnnxError::Graph),
    };
    if !value.is_finite() {
        return Err(OnnxError::NonFinite);
    }
    Ok(value)
}

fn affine(
    source: &SourceNode<'_>,
    lowering: &mut Lowering<'_, '_>,
    input: String,
    parameter: String,
    op: OpCode,
    suffix: &str,
) -> Result<String> {
    let id = format!("{}-hard-sigmoid-{suffix}", source.id);
    let output = lowering.fresh_name(&id)?;
    lowering.append(
        GraphNode::new(
            id,
            op,
            source.label.clone(),
            vec![input, parameter],
            vec![output.clone()],
            AttributeMap::new(),
        )
        .map_err(|_| OnnxError::Graph)?,
    )?;
    Ok(output)
}

pub(super) fn lower(mut source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if source.inputs.len() != 1 || source.outputs.len() != 1 || source.inputs[0].is_empty() {
        return Err(OnnxError::Graph);
    }
    let alpha = coefficient(&mut source.attrs, "alpha", 0.2_f32)?;
    let beta = coefficient(&mut source.attrs, "beta", 0.5_f32)?;
    if !source.attrs.is_empty() {
        return Err(OnnxError::Unsupported);
    }

    // Round each bound in the same F32 order as execution. Monotonic rounding
    // makes these upper bounds for |alpha*x| and |round(alpha*x) + beta|.
    // Reject overflowing intermediates, even when a later clamp would hide them.
    let largest_product = f32::MAX * alpha.abs();
    let largest_affine = largest_product + beta.abs();
    if !largest_product.is_finite() || !largest_affine.is_finite() {
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
    lowering.admission.charge(12 + dims.len())?;
    // Two affine nodes, four affine/bound scalars, and the shared two-sided clamp:
    // fifteen nodes, five four-byte scalars, at most 2 * input elements per tensor.
    clip::reserve(lowering, elements, true, true, 2, 4)?;
    let alpha_name = clip::scalar(
        lowering,
        &format!("{}-hard-sigmoid-alpha", source.id),
        alpha,
    )?;
    let beta_name = clip::scalar(
        lowering,
        &format!("{}-hard-sigmoid-beta", source.id),
        beta,
    )?;
    let lower = clip::scalar(
        lowering,
        &format!("{}-hard-sigmoid-min", source.id),
        0.0,
    )?;
    let upper = clip::scalar(
        lowering,
        &format!("{}-hard-sigmoid-max", source.id),
        1.0,
    )?;
    let scaled = affine(
        &source,
        lowering,
        source.inputs[0].clone(),
        alpha_name,
        OpCode::Mul,
        "scaled",
    )?;
    let shifted = affine(
        &source,
        lowering,
        scaled,
        beta_name,
        OpCode::Add,
        "shifted",
    )?;
    clip::append(
        &source,
        lowering,
        shifted,
        &dims,
        Some(lower),
        Some(upper),
    )
}
