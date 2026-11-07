#![forbid(unsafe_code)]
//! InstanceNormalization-6, the schema selected by default-domain opset 13.
//!
//! https://onnx.ai/onnx/operators/onnx__InstanceNormalization.html#instancenormalization-6
//! Statistics are independent for every batch/channel pair. The frozen native
//! LayerNorm computes ordered binary64 population statistics over spatial axes
//! and rounds the normalized values to F32. Channel scaling and bias then use
//! separate native F32 Mul/Add. No running statistics or generated weights exist.

use fss_tensor::DType;

use super::{Lowering, OnnxError, Result, SourceNode};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

fn append(
    source: &SourceNode<'_>,
    lowering: &mut Lowering<'_, '_>,
    suffix: Option<&str>,
    op: OpCode,
    inputs: Vec<String>,
    attrs: AttributeMap,
) -> Result<String> {
    let (id, output) = if let Some(suffix) = suffix {
        let id = format!("{}-instancenorm-{suffix}", source.id);
        let output = lowering.fresh_name(&id)?;
        (id, output)
    } else {
        (source.id.clone(), source.outputs[0].clone())
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
    if source.inputs.len() != 3
        || source.outputs.len() != 1
        || source.inputs.iter().any(String::is_empty)
    {
        return Err(OnnxError::Graph);
    }
    let epsilon = match source.attrs.remove("epsilon") {
        // ONNX's FLOAT default is binary32. Do not substitute the native
        // LayerNorm default, which is the different binary64 value 1e-5.
        None => f64::from(1e-5_f32),
        Some(AttrValue::Float(value)) if value.is_finite() && value > 0.0 => value,
        Some(AttrValue::Float(_)) => return Err(OnnxError::Unsupported),
        Some(_) => return Err(OnnxError::Graph),
    };
    if !source.attrs.is_empty() {
        return Err(OnnxError::Unsupported);
    }
    let input = lowering
        .known
        .get(&source.inputs[0])
        .ok_or(OnnxError::Graph)?;
    if input.dtype() != DType::F32
        || !(3..=8).contains(&input.rank())
        || input.shape().dims().contains(&0)
    {
        return Err(OnnxError::Unsupported);
    }
    let dimensions = input.shape().dims().to_vec();
    lowering.admission.charge(dimensions.len())?;
    for name in &source.inputs[1..] {
        lowering.admission.charge(1)?;
        let parameter = lowering.known.get(name).ok_or(OnnxError::Graph)?;
        if parameter.dtype() != DType::F32 || parameter.shape().dims() != [dimensions[1]] {
            return Err(OnnxError::Graph);
        }
    }

    // Three tensor-sized operations and two C-element reshapes. These shapes
    // never exceed the admitted input tensor, and no constants are replicated.
    // Admit every helper/value before allocating any generated name.
    let limits = lowering.admission.limits;
    if lowering.nodes.len().checked_add(5).ok_or(OnnxError::Limit)? > limits.nodes
        || lowering.known.len().checked_add(5).ok_or(OnnxError::Limit)? > limits.tensors
        || lowering.reserved.len().checked_add(4).ok_or(OnnxError::Limit)? > limits.tensors
    {
        return Err(OnnxError::Limit);
    }
    lowering.admission.charge(5)?;
    let spatial = dimensions[2..]
        .iter()
        .map(|&dim| i64::try_from(dim).map_err(|_| OnnxError::Limit))
        .collect::<Result<Vec<_>>>()?;
    let normalized = append(
        &source,
        lowering,
        Some("normalize"),
        OpCode::LayerNorm,
        vec![source.inputs[0].clone()],
        AttributeMap::from([
            ("normalized_shape".into(), AttrValue::IntList(spatial)),
            ("epsilon".into(), AttrValue::Float(epsilon)),
            ("elementwise_affine".into(), AttrValue::Bool(false)),
        ]),
    )?;
    let mut shape = vec![1_i64; dimensions.len()];
    shape[1] = i64::try_from(dimensions[1]).map_err(|_| OnnxError::Limit)?;
    let mut affine = Vec::with_capacity(2);
    for (index, suffix) in ["scale", "bias"].into_iter().enumerate() {
        affine.push(append(
            &source,
            lowering,
            Some(suffix),
            OpCode::Reshape,
            vec![source.inputs[index + 1].clone()],
            AttributeMap::from([("shape".into(), AttrValue::IntList(shape.clone()))]),
        )?);
    }
    let scaled = append(
        &source,
        lowering,
        Some("affine"),
        OpCode::Mul,
        vec![normalized, affine[0].clone()],
        AttributeMap::new(),
    )?;
    append(
        &source,
        lowering,
        None,
        OpCode::Add,
        vec![scaled, affine[1].clone()],
        AttributeMap::new(),
    )?;
    Ok(())
}
