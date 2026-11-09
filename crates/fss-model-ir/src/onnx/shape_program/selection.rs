#![forbid(unsafe_code)]
//! Compile-time selectors for static detector shape programs. The closed profile
//! remains scalar/vector controls of at most eight elements. No runtime input
//! values, F32 comparisons, or runtime Boolean operators are introduced.
//!
//! ONNX opset 13 selects ConstantOfShape-9, Equal-13, Where-9 and Slice-13:
//! https://onnx.ai/onnx/operators/onnx__ConstantOfShape.html#constantofshape-9
//! https://onnx.ai/onnx/operators/onnx__Equal.html#equal-13
//! https://onnx.ai/onnx/operators/onnx__Where.html#where-9
//! https://onnx.ai/onnx/operators/onnx__Slice.html#slice-13

use super::super::{Wire, constants, singular, text};
use super::{
    Control, Lowering, OnnxError, Result, Shape, SourceNode, arity, axis, control, no_attributes,
    store, typed_control, vector,
};
use fss_tensor::DType;

fn broadcast(source: &SourceNode<'_>, left: &Shape, right: &Shape) -> Result<Shape> {
    let shape = crate::broadcast_shapes(&source.id, "ONNX-SHAPE-SELECT", left, right)
        .map_err(|_| OnnxError::Graph)?;
    if shape.rank() > 1 || shape.num_elements().map_err(|_| OnnxError::Limit)? > 8 {
        return Err(OnnxError::Limit);
    }
    Ok(shape)
}

fn at<T: Copy>(values: &[T], index: usize) -> Result<T> {
    values
        .get(if values.len() == 1 { 0 } else { index })
        .copied()
        .ok_or(OnnxError::Graph)
}

pub(super) fn equal(source: &SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    arity(source, 2)?;
    no_attributes(source)?;
    let a = control(&source.inputs[0], lowering)?;
    let b = control(&source.inputs[1], lowering)?;
    let shape = broadcast(source, &a.shape, &b.shape)?;
    let count = shape.num_elements().map_err(|_| OnnxError::Limit)?;
    let mut values = Vec::with_capacity(count);
    for index in 0..count {
        lowering.admission.charge(1)?;
        // Preserve all 64 bits. Integers never pass through F32 or F64.
        values.push(at(&a.values, index)? == at(&b.values, index)?);
    }
    store(source, lowering, shape, &values)
}

pub(super) fn select(source: &SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<Control> {
    arity(source, 3)?;
    no_attributes(source)?;
    let (condition_shape, conditions) = typed_control::<bool>(&source.inputs[0], lowering)?;
    let a = control(&source.inputs[1], lowering)?;
    let b = control(&source.inputs[2], lowering)?;
    // All three operands are admitted even when every condition selects one
    // branch. This is tensor selection, not permission to ignore an invalid use.
    let data_shape = broadcast(source, &a.shape, &b.shape)?;
    let shape = broadcast(source, &condition_shape, &data_shape)?;
    let count = shape.num_elements().map_err(|_| OnnxError::Limit)?;
    let mut values = Vec::with_capacity(count);
    for index in 0..count {
        lowering.admission.charge(1)?;
        values.push(if at(&conditions, index)? {
            at(&a.values, index)?
        } else {
            at(&b.values, index)?
        });
    }
    Ok(Control { shape, values })
}

fn fill_value(source: &SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<i64> {
    // An omitted value means F32 zero in ONNX. It cannot be silently coerced to
    // INT64 to fit this shape-only profile.
    let mut wire = Wire(source.constant.ok_or(OnnxError::Unsupported)?);
    let (mut seen, mut name, mut kind, mut embedded) = (0, None, None, None);
    while let Some((tag, value)) = wire.next(lowering.admission)? {
        singular(&mut seen, tag)?;
        match tag {
            1 => name = Some(text(value.bytes()?)?),
            5 => embedded = Some(value.bytes()?),
            13 => {
                text(value.bytes()?)?;
            }
            20 => kind = Some(value.integer()?),
            _ => return Err(OnnxError::Unsupported),
        }
    }
    if name != Some("value") || kind != Some(4) {
        return Err(OnnxError::Unsupported);
    }
    let maximum = lowering.admission.limits.parameter_bytes;
    // A fill can contain exactly one admitted INT64 value. Bound temporary
    // parsing too, before an adversarial tensor attribute can allocate a payload.
    lowering.admission.limits.parameter_bytes =
        maximum.saturating_sub(lowering.parameter_bytes).min(8);
    let parsed = constants::tensor(
        embedded.ok_or(OnnxError::Malformed)?,
        Some(&source.outputs[0]),
        lowering.generation,
        lowering.admission,
    );
    lowering.admission.limits.parameter_bytes = maximum;
    let (port, tensor) = parsed?;
    if port.dtype() != DType::I64
        || tensor
            .shape()
            .num_elements()
            .map_err(|_| OnnxError::Limit)?
            != 1
    {
        return Err(OnnxError::Unsupported);
    }
    // The embedded fill and the generated vector both consume the cumulative
    // byte allowance, although the fill is never an extra runtime parameter.
    lowering.parameter_bytes = lowering
        .parameter_bytes
        .checked_add(8)
        .ok_or(OnnxError::Limit)?;
    if lowering.parameter_bytes > maximum {
        return Err(OnnxError::Limit);
    }
    tensor
        .to_vec::<i64>()
        .map_err(|_| OnnxError::Graph)?
        .first()
        .copied()
        .ok_or(OnnxError::Graph)
}

pub(super) fn fill(source: &SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<Control> {
    arity(source, 1)?;
    no_attributes(source)?;
    let dimensions = lowering.constant_i64_vector(&source.inputs[0])?;
    if dimensions.len() > 1 {
        return Err(OnnxError::Unsupported);
    }
    let dimensions = dimensions
        .into_iter()
        .map(|value| usize::try_from(value).map_err(|_| OnnxError::Graph))
        .collect::<Result<Vec<_>>>()?;
    let shape = Shape::new(dimensions).map_err(|_| OnnxError::Limit)?;
    let count = shape.num_elements().map_err(|_| OnnxError::Limit)?;
    if count > 8 {
        return Err(OnnxError::Limit);
    }
    let value = fill_value(source, lowering)?;
    lowering.admission.charge(count)?;
    Ok(Control {
        shape,
        values: vec![value; count],
    })
}

pub(super) fn slice(source: &SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<Control> {
    no_attributes(source)?;
    if !(3..=5).contains(&source.inputs.len()) || source.inputs[..3].iter().any(String::is_empty) {
        return Err(OnnxError::Graph);
    }
    let data = control(&source.inputs[0], lowering)?;
    if data.shape.rank() != 1 {
        return Err(OnnxError::Graph);
    }
    let starts = lowering.constant_i64_vector(&source.inputs[1])?;
    let ends = lowering.constant_i64_vector(&source.inputs[2])?;
    let optional = |index: usize| source.inputs.get(index).filter(|name| !name.is_empty());
    let axes = match optional(3) {
        Some(name) => lowering.constant_i64_vector(name)?,
        None => vec![0],
    };
    let steps = match optional(4) {
        Some(name) => lowering.constant_i64_vector(name)?,
        None => vec![1; starts.len()],
    };
    if starts.len() != ends.len()
        || starts.len() != axes.len()
        || starts.len() != steps.len()
        || axes.len() > 1
    {
        return Err(OnnxError::Graph);
    }
    if axes.is_empty() {
        return Ok(data);
    }
    axis(axes[0], 1)?;
    if steps[0] == 0 {
        return Err(OnnxError::Graph);
    }
    let length = data.values.len() as i128;
    if length == 0 {
        return vector(Vec::new());
    }
    let step = i128::from(steps[0]);
    let adjusted = |value: i64| {
        let value = i128::from(value);
        if value < 0 { value + length } else { value }
    };
    let (mut index, end) = if step > 0 {
        (
            adjusted(starts[0]).clamp(0, length),
            adjusted(ends[0]).clamp(0, length),
        )
    } else {
        (
            adjusted(starts[0]).clamp(0, length - 1),
            adjusted(ends[0]).clamp(-1, length - 1),
        )
    };
    let mut values = Vec::with_capacity(data.values.len());
    while if step > 0 { index < end } else { index > end } {
        lowering.admission.charge(1)?;
        let position = usize::try_from(index).map_err(|_| OnnxError::Graph)?;
        values.push(*data.values.get(position).ok_or(OnnxError::Graph)?);
        // i128 prevents an extreme positive/negative i64 step or end sentinel
        // from wrapping. At most eight input positions can ever be visited.
        index += step;
    }
    vector(values)
}
