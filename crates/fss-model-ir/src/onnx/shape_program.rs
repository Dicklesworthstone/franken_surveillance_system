#![forbid(unsafe_code)]
//! Bounded evaluation of opset-13 shape programs from already-validated static
//! dimensions and embedded INT64 values. No input data or runtime integer graph
//! is evaluated. Every produced control joins ordinary constant admission.
//!
//! Semantics: https://onnx.ai/onnx/operators/onnx__Shape.html#shape-13,
//! Gather-13, Squeeze-13, Unsqueeze-13, Concat-13 and Add/Sub/Mul/Div-13.

use fss_tensor::{DType, Shape, Tensor};

use super::{Lowering, OnnxError, Result, SourceNode};
use crate::{AttrValue, TensorPort};

/// A rank-zero scalar or a rank-one vector; both may contain one value, but they
/// have different ONNX broadcasting, Gather, and concatenation semantics.
struct Control {
    shape: Shape,
    values: Vec<i64>,
}

pub(super) fn handles(source: &SourceNode<'_>, lowering: &Lowering<'_, '_>) -> bool {
    matches!(source.op.as_str(), "Shape" | "Gather")
        || (matches!(
            source.op.as_str(),
            "Identity" | "Squeeze" | "Unsqueeze" | "Concat" | "Add" | "Sub" | "Mul" | "Div"
        ) && source
            .inputs
            .first()
            .and_then(|name| lowering.known.get(name))
            .is_some_and(|port| port.dtype() == DType::I64))
}

fn control(name: &str, lowering: &mut Lowering<'_, '_>) -> Result<Control> {
    let port = lowering.known.get(name).ok_or(OnnxError::Graph)?;
    if port.dtype() != DType::I64 || port.rank() > 1 {
        return Err(OnnxError::Unsupported);
    }
    let tensor = lowering.constants.get(name).ok_or(OnnxError::Unsupported)?;
    let count = tensor
        .shape()
        .num_elements()
        .map_err(|_| OnnxError::Limit)?;
    if count > 8 {
        return Err(OnnxError::Limit);
    }
    lowering.admission.charge(count * 8)?;
    let shape = tensor.shape().clone();
    let values = tensor.to_vec::<i64>().map_err(|_| OnnxError::Graph)?;
    lowering.control_uses.insert(name.to_owned());
    Ok(Control { shape, values })
}

fn no_attributes(source: &SourceNode<'_>) -> Result<()> {
    if source.attrs.is_empty() {
        Ok(())
    } else {
        Err(OnnxError::Unsupported)
    }
}

fn arity(source: &SourceNode<'_>, count: usize) -> Result<()> {
    if source.inputs.len() != count || source.inputs.iter().any(String::is_empty) {
        Err(OnnxError::Graph)
    } else {
        Ok(())
    }
}

fn axis(value: i64, rank: usize) -> Result<usize> {
    let rank = rank as i64;
    if value < -rank || value >= rank {
        return Err(OnnxError::Graph);
    }
    Ok(if value < 0 { value + rank } else { value } as usize)
}

fn selected_axis(source: &SourceNode<'_>, default: Option<i64>) -> Result<usize> {
    if source.attrs.keys().any(|key| key != "axis") {
        return Err(OnnxError::Unsupported);
    }
    let value = match source.attrs.get("axis") {
        Some(AttrValue::Int(value)) => *value,
        Some(_) => return Err(OnnxError::Graph),
        None => default.ok_or(OnnxError::Malformed)?,
    };
    axis(value, 1)
}

fn vector(values: Vec<i64>) -> Result<Control> {
    Ok(Control {
        shape: Shape::new(vec![values.len()]).map_err(|_| OnnxError::Limit)?,
        values,
    })
}

fn shape(source: &SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<Control> {
    arity(source, 1)?;
    // start/end attributes belong to later Shape schemas, not opset 13.
    no_attributes(source)?;
    let name = &source.inputs[0];
    let input = lowering.known.get(name).ok_or(OnnxError::Graph)?;
    let values = input
        .shape()
        .dims()
        .iter()
        .map(|&dimension| i64::try_from(dimension).map_err(|_| OnnxError::Limit))
        .collect::<Result<Vec<_>>>()?;
    // Reading an initializer's shape is a real compile-time use. Its payload is
    // still charged, but need not be exported unless another node uses its data.
    // Runtime input bindings stay present and retain their exact shape checks.
    if lowering.constants.contains_key(name) {
        lowering.control_uses.insert(name.clone());
    }
    vector(values)
}

fn gather(source: &SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<Control> {
    arity(source, 2)?;
    selected_axis(source, Some(0))?;
    let data = control(&source.inputs[0], lowering)?;
    let indices = control(&source.inputs[1], lowering)?;
    if data.shape.rank() != 1 {
        return Err(OnnxError::Graph);
    }
    let length = data.values.len() as i64;
    let mut values = Vec::with_capacity(indices.values.len());
    for index in indices.values {
        lowering.admission.charge(1)?;
        let index = if index < 0 { index + length } else { index };
        let index = usize::try_from(index).map_err(|_| OnnxError::Graph)?;
        values.push(*data.values.get(index).ok_or(OnnxError::Graph)?);
    }
    Ok(Control {
        shape: indices.shape,
        values,
    })
}

fn layout(source: &SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<Control> {
    no_attributes(source)?;
    let squeeze = source.op == "Squeeze";
    if !(1..=2).contains(&source.inputs.len())
        || source.inputs[0].is_empty()
        || (!squeeze && (source.inputs.len() != 2 || source.inputs[1].is_empty()))
    {
        return Err(OnnxError::Graph);
    }
    let data = control(&source.inputs[0], lowering)?;
    let selected = match source.inputs.get(1).filter(|name| !name.is_empty()) {
        Some(name) => lowering.constant_i64_vector(name)?,
        None => data
            .shape
            .dims()
            .iter()
            .enumerate()
            .filter_map(|(i, &n)| (n == 1).then_some(i as i64))
            .collect(),
    };
    let rank = if squeeze {
        data.shape.rank()
    } else {
        data.shape.rank() + selected.len()
    };
    let mut axes = std::collections::BTreeSet::new();
    for value in selected {
        if !axes.insert(axis(value, rank)?) {
            return Err(OnnxError::Graph);
        }
    }
    let dimensions = if squeeze {
        for &selected in &axes {
            if data.shape.dims()[selected] != 1 {
                return Err(OnnxError::Graph);
            }
        }
        data.shape
            .dims()
            .iter()
            .enumerate()
            .filter_map(|(i, &n)| (!axes.contains(&i)).then_some(n))
            .collect()
    } else {
        if rank > 1 {
            return Err(OnnxError::Unsupported);
        }
        let mut original = data.shape.dims().iter();
        (0..rank)
            .map(|i| {
                if axes.contains(&i) {
                    Ok(1)
                } else {
                    original.next().copied().ok_or(OnnxError::Graph)
                }
            })
            .collect::<Result<Vec<_>>>()?
    };
    Ok(Control {
        shape: Shape::new(dimensions).map_err(|_| OnnxError::Limit)?,
        values: data.values,
    })
}

fn concat(source: &SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<Control> {
    if source.inputs.is_empty() {
        return Err(OnnxError::Graph);
    }
    selected_axis(source, None)?;
    let mut values = Vec::new();
    for name in &source.inputs {
        let data = control(name, lowering)?;
        if data.shape.rank() != 1 {
            return Err(OnnxError::Graph);
        }
        if values.len() + data.values.len() > 8 {
            return Err(OnnxError::Limit);
        }
        values.extend(data.values);
    }
    vector(values)
}

fn arithmetic(source: &SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<Control> {
    arity(source, 2)?;
    no_attributes(source)?;
    let a = control(&source.inputs[0], lowering)?;
    let b = control(&source.inputs[1], lowering)?;
    let shape = crate::broadcast_shapes(&source.id, "ONNX-INT64-CONTROL", &a.shape, &b.shape)
        .map_err(|_| OnnxError::Graph)?;
    let count = shape.num_elements().map_err(|_| OnnxError::Limit)?;
    if shape.rank() > 1 || count > 8 {
        return Err(OnnxError::Limit);
    }
    let mut values = Vec::with_capacity(count);
    for i in 0..count {
        lowering.admission.charge(1)?;
        let at = |data: &Control| {
            data.values
                .get(if data.values.len() == 1 { 0 } else { i })
                .copied()
                .ok_or(OnnxError::Graph)
        };
        let (a, b) = (at(&a)?, at(&b)?);
        let value = match source.op.as_str() {
            "Add" => a.checked_add(b),
            "Sub" => a.checked_sub(b),
            "Mul" => a.checked_mul(b),
            "Div" => {
                if b == 0 {
                    return Err(OnnxError::Graph);
                }
                // ONNX integer Div truncates toward zero. No floating conversion
                // loses dimensions above 2^53; MIN/-1 and other overflow refuse.
                a.checked_div(b)
            }
            _ => return Err(OnnxError::Unsupported),
        }
        .ok_or(OnnxError::Limit)?;
        values.push(value);
    }
    Ok(Control { shape, values })
}

pub(super) fn lower(source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if source.outputs.len() != 1 {
        return Err(OnnxError::Graph);
    }
    lowering
        .admission
        .charge(1 + lowering.known.len() + source.inputs.len())?;
    let data = match source.op.as_str() {
        "Shape" => shape(&source, lowering)?,
        "Gather" => gather(&source, lowering)?,
        "Squeeze" | "Unsqueeze" => layout(&source, lowering)?,
        "Concat" => concat(&source, lowering)?,
        "Add" | "Sub" | "Mul" | "Div" => arithmetic(&source, lowering)?,
        "Identity" => {
            arity(&source, 1)?;
            no_attributes(&source)?;
            control(&source.inputs[0], lowering)?
        }
        _ => return Err(OnnxError::Unsupported),
    };
    let bytes = data
        .shape
        .size_bytes(DType::I64)
        .map_err(|_| OnnxError::Limit)?;
    if data.shape.rank() > 1
        || data.values.len() > 8
        || bytes > lowering.admission.limits.tensor_bytes
        || lowering
            .parameter_bytes
            .checked_add(bytes)
            .is_none_or(|total| total > lowering.admission.limits.parameter_bytes)
    {
        return Err(OnnxError::Limit);
    }
    lowering.admission.charge(bytes)?;
    let port = TensorPort::new(
        source.outputs[0].clone(),
        DType::I64,
        data.shape.clone(),
        lowering.generation,
    )
    .map_err(|_| OnnxError::Graph)?;
    let tensor = Tensor::from_values(data.shape, &data.values, lowering.generation)
        .map_err(|_| OnnxError::Graph)?;
    lowering.add_constant(port, tensor)
}
