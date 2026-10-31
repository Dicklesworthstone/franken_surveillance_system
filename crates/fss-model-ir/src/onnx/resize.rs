#![forbid(unsafe_code)]
//! Static ONNX Resize-13 nearest-neighbor spatial upsampling.
//!
//! https://onnx.ai/onnx/operators/onnx__Resize.html#resize-13
//! For positive integer scale s, asymmetric/floor selects floor(x / s).
//! Half-pixel followed by nearest rounding selects the same sample: writing
//! x = q*s+r, 0 <= r < s, its source coordinate lies strictly between q-1/2
//! and q+1/2. Both admitted profiles therefore repeat samples exactly, without
//! floating-point arithmetic on the image values or a new frozen IR operator.

use super::{Lowering, OnnxError, Result, SourceNode};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

const MAX_FACTOR: usize = 64;

fn text_attribute(attrs: &mut AttributeMap, name: &str, default: &str) -> Result<String> {
    match attrs.remove(name) {
        None => Ok(default.to_owned()),
        Some(AttrValue::String(value)) => Ok(value),
        Some(_) => Err(OnnxError::Graph),
    }
}

fn attributes(attrs: &mut AttributeMap) -> Result<()> {
    let mode = text_attribute(attrs, "mode", "nearest")?;
    let coordinates = text_attribute(attrs, "coordinate_transformation_mode", "half_pixel")?;
    let nearest = text_attribute(attrs, "nearest_mode", "round_prefer_floor")?;
    if mode != "nearest"
        || !matches!(
            (coordinates.as_str(), nearest.as_str()),
            ("asymmetric", "floor") | ("half_pixel", "round_prefer_floor")
        )
    {
        return Err(OnnxError::Unsupported);
    }
    match attrs.remove("exclude_outside") {
        None | Some(AttrValue::Int(0)) => {}
        Some(AttrValue::Int(_)) => return Err(OnnxError::Unsupported),
        Some(_) => return Err(OnnxError::Graph),
    }
    // These attributes do not affect either admitted nearest profile. Validate
    // their source types, rather than letting exporter-emitted defaults fail.
    for name in ["cubic_coeff_a", "extrapolation_value"] {
        match attrs.remove(name) {
            None => {}
            Some(AttrValue::Float(value)) if value.is_finite() => {}
            Some(_) => return Err(OnnxError::Graph),
        }
    }
    if !attrs.is_empty() {
        return Err(OnnxError::Unsupported);
    }
    Ok(())
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

fn repeat(
    lowering: &mut Lowering<'_, '_>,
    id: &str,
    label: &str,
    input: String,
    output: String,
    axis: i64,
    factor: usize,
) -> Result<()> {
    lowering.admission.charge(factor)?;
    lowering.append(
        GraphNode::new(
            id,
            OpCode::Concat,
            label,
            vec![input; factor],
            vec![output],
            AttributeMap::from([("axis".into(), AttrValue::Int(axis))]),
        )
        .map_err(|_| OnnxError::Graph)?,
    )
}

pub(super) fn lower(mut source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if !(3..=4).contains(&source.inputs.len())
        || source.outputs.len() != 1
        || source.inputs[0].is_empty()
    {
        return Err(OnnxError::Graph);
    }
    attributes(&mut source.attrs)?;
    let input = lowering
        .known
        .get(&source.inputs[0])
        .ok_or(OnnxError::Graph)?;
    let dims: [usize; 4] = input
        .shape()
        .dims()
        .try_into()
        .map_err(|_| OnnxError::Unsupported)?;
    if !source.inputs[1].is_empty() && !lowering.constant_f32_vector(&source.inputs[1])?.is_empty()
    {
        return Err(OnnxError::Unsupported);
    }
    let scales = if source.inputs[2].is_empty() {
        Vec::new()
    } else {
        lowering.constant_f32_vector(&source.inputs[2])?
    };
    let sizes = if let Some(name) = source.inputs.get(3).filter(|name| !name.is_empty()) {
        lowering.constant_i64_vector(name)?
    } else {
        Vec::new()
    };
    // Empty optional constant tensors, emitted by several ONNX exporters, are
    // control values only. They must never become zero-sized runtime tensors.
    if scales.is_empty() == sizes.is_empty() {
        return Err(OnnxError::Graph);
    }
    let factors = if !scales.is_empty() {
        if scales.len() != 4 || scales[0] != 1.0 || scales[1] != 1.0 {
            return Err(OnnxError::Unsupported);
        }
        let factor = |value: f32| {
            if value.is_finite()
                && (1.0..=MAX_FACTOR as f32).contains(&value)
                && value.fract() == 0.0
            {
                Ok(value as usize)
            } else {
                Err(OnnxError::Unsupported)
            }
        };
        [factor(scales[2])?, factor(scales[3])?]
    } else {
        if sizes.len() != 4 {
            return Err(OnnxError::Graph);
        }
        let mut requested = [0_usize; 4];
        for (target, value) in requested.iter_mut().zip(sizes) {
            *target = usize::try_from(value).map_err(|_| OnnxError::Unsupported)?;
        }
        if requested[..2] != dims[..2]
            || requested[2..].contains(&0)
            || !requested[2].is_multiple_of(dims[2])
            || !requested[3].is_multiple_of(dims[3])
        {
            return Err(OnnxError::Unsupported);
        }
        [requested[2] / dims[2], requested[3] / dims[3]]
    };
    if factors
        .iter()
        .any(|factor| !(1..=MAX_FACTOR).contains(factor))
    {
        return Err(OnnxError::Unsupported);
    }
    let height = dims[2].checked_mul(factors[0]).ok_or(OnnxError::Limit)?;
    let width = dims[3].checked_mul(factors[1]).ok_or(OnnxError::Limit)?;
    let output_shape = [dims[0], dims[1], height, width];
    let bytes = output_shape.iter().try_fold(4_usize, |bytes, &dim| {
        bytes.checked_mul(dim).ok_or(OnnxError::Limit)
    })?;
    if bytes > lowering.admission.limits.tensor_bytes {
        return Err(OnnxError::Limit);
    }
    // Every generated name is reserved against all source names, including
    // future source values. Every emitted node uses the same quota admission.
    let base = format!("{}-resize", source.id);
    let unit = lowering.fresh_name(&format!("{base}-unit"))?;
    let wide = lowering.fresh_name(&format!("{base}-wide"))?;
    let tall = lowering.fresh_name(&format!("{base}-tall"))?;
    reshape(
        lowering,
        &format!("{}-unit", source.id),
        &source.label,
        source.inputs[0].clone(),
        unit.clone(),
        &[dims[0], dims[1], dims[2], 1, dims[3], 1],
    )?;
    repeat(
        lowering,
        &format!("{}-width", source.id),
        &source.label,
        unit,
        wide.clone(),
        5,
        factors[1],
    )?;
    repeat(
        lowering,
        &format!("{}-height", source.id),
        &source.label,
        wide,
        tall.clone(),
        3,
        factors[0],
    )?;
    reshape(
        lowering,
        &source.id,
        &source.label,
        tall,
        source.outputs[0].clone(),
        &output_shape,
    )
}
