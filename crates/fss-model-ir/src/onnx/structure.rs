#![forbid(unsafe_code)]
//! Opset-13 layout operators with constant integer controls. Runtime integer
//! tensors and data-dependent shape computation are outside this static F32 profile.

use super::{Lowering, OnnxError, Result, SourceNode};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

fn axis(value: i64, rank: usize) -> Result<i64> {
    let rank = rank as i64;
    if value < -rank || value >= rank {
        return Err(OnnxError::Graph);
    }
    Ok(if value < 0 { value + rank } else { value })
}

fn axes(values: Vec<i64>, rank: usize) -> Result<Vec<i64>> {
    let mut seen = std::collections::BTreeSet::new();
    values
        .into_iter()
        .map(|value| {
            let value = axis(value, rank)?;
            if !seen.insert(value) {
                return Err(OnnxError::Graph);
            }
            Ok(value)
        })
        .collect()
}

fn optional<'a>(source: &'a SourceNode<'_>, index: usize) -> Option<&'a str> {
    source
        .inputs
        .get(index)
        .map(String::as_str)
        .filter(|name| !name.is_empty())
}

pub(super) fn lower(source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if source.outputs.len() != 1 || source.inputs.is_empty() || source.inputs[0].is_empty() {
        return Err(OnnxError::Graph);
    }
    if !source.attrs.is_empty() {
        return Err(OnnxError::Unsupported);
    }
    let input = lowering
        .known
        .get(&source.inputs[0])
        .ok_or(OnnxError::Graph)?;
    if input.dtype() != fss_tensor::DType::F32 || input.shape().dims().contains(&0) {
        return Err(OnnxError::Unsupported);
    }
    let dims = input.shape().dims().to_vec();
    let mut attrs = AttributeMap::new();
    let op = match source.op.as_str() {
        "Reshape" => {
            if source.inputs.len() != 2 || source.inputs[1].is_empty() {
                return Err(OnnxError::Graph);
            }
            let shape = lowering.constant_i64_vector(&source.inputs[1])?;
            attrs.insert("shape".into(), AttrValue::IntList(shape));
            OpCode::Reshape
        }
        "Squeeze" => {
            if source.inputs.len() > 2 {
                return Err(OnnxError::Graph);
            }
            if let Some(name) = optional(&source, 1) {
                let values = lowering.constant_i64_vector(name)?;
                attrs.insert("axes".into(), AttrValue::IntList(axes(values, dims.len())?));
            }
            OpCode::Squeeze
        }
        "Unsqueeze" => {
            if source.inputs.len() != 2 || source.inputs[1].is_empty() {
                return Err(OnnxError::Graph);
            }
            let values = lowering.constant_i64_vector(&source.inputs[1])?;
            let rank = dims
                .len()
                .checked_add(values.len())
                .ok_or(OnnxError::Limit)?;
            if rank > 8 {
                return Err(OnnxError::Limit);
            }
            attrs.insert("axes".into(), AttrValue::IntList(axes(values, rank)?));
            OpCode::Unsqueeze
        }
        "Slice" => {
            if !(3..=5).contains(&source.inputs.len())
                || source.inputs[1..3].iter().any(String::is_empty)
            {
                return Err(OnnxError::Graph);
            }
            let mut starts = lowering.constant_i64_vector(&source.inputs[1])?;
            let mut ends = lowering.constant_i64_vector(&source.inputs[2])?;
            let selected_axes = match optional(&source, 3) {
                Some(name) => lowering.constant_i64_vector(name)?,
                None => (0..starts.len()).map(|n| n as i64).collect(),
            };
            let steps = match optional(&source, 4) {
                Some(name) => lowering.constant_i64_vector(name)?,
                None => vec![1; starts.len()],
            };
            if starts.len() != ends.len()
                || starts.len() != selected_axes.len()
                || starts.len() != steps.len()
            {
                return Err(OnnxError::Graph);
            }
            let selected_axes = axes(selected_axes, dims.len())?;
            for (index, &selected) in selected_axes.iter().enumerate() {
                if steps[index] == 0 {
                    return Err(OnnxError::Graph);
                }
                if steps[index] < 0 {
                    return Err(OnnxError::Unsupported);
                }
                let length = dims[selected as usize] as i64;
                let normalize = |value: i64| {
                    if value < 0 {
                        value.saturating_add(length)
                    } else {
                        value
                    }
                    .clamp(0, length)
                };
                starts[index] = normalize(starts[index]);
                ends[index] = normalize(ends[index]);
                // ONNX permits empty results; the admitted runtime tensor profile does not.
                if starts[index] >= ends[index] {
                    return Err(OnnxError::Unsupported);
                }
            }
            attrs.insert("starts".into(), AttrValue::IntList(starts));
            attrs.insert("ends".into(), AttrValue::IntList(ends));
            attrs.insert("axes".into(), AttrValue::IntList(selected_axes));
            attrs.insert("steps".into(), AttrValue::IntList(steps));
            OpCode::Slice
        }
        _ => return Err(OnnxError::Unsupported),
    };
    lowering.append(
        GraphNode::new(
            source.id,
            op,
            source.label,
            vec![source.inputs[0].clone()],
            source.outputs,
            attrs,
        )
        .map_err(|_| OnnxError::Graph)?,
    )
}
