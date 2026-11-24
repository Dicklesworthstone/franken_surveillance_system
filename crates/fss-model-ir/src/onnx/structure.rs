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

fn append_slice_node(
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
        format!("{}-slice-{ordinal}", source.id)
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

// Native Slice has forward strides. First select the same samples in ascending
// order on every axis, then reverse only the selected negative-stride axes with
// unit Slices and Concat. Every intermediate is no larger than the source.
fn reverse_slice(
    source: SourceNode<'_>,
    lowering: &mut Lowering<'_, '_>,
    dims: &[usize],
    mut starts: Vec<i64>,
    mut ends: Vec<i64>,
    selected_axes: Vec<i64>,
    mut steps: Vec<i64>,
) -> Result<()> {
    let mut reverse = Vec::new();
    let mut nodes = 1_usize;
    for (index, &selected) in selected_axes.iter().enumerate() {
        if steps[index] == 0 {
            return Err(OnnxError::Graph);
        }
        let length = i64::try_from(dims[selected as usize]).map_err(|_| OnnxError::Limit)?;
        let adjust = |value: i64| {
            if value < 0 {
                value.saturating_add(length)
            } else {
                value
            }
        };
        if steps[index] > 0 {
            starts[index] = adjust(starts[index]).clamp(0, length);
            ends[index] = adjust(ends[index]).clamp(0, length);
            if starts[index] >= ends[index] {
                return Err(OnnxError::Unsupported);
            }
            continue;
        }
        // ONNX clamps reverse starts and ends differently. In particular,
        // INT64_MIN ends select through index zero; a literal -1 does not.
        let start = adjust(starts[index]).clamp(0, length - 1);
        let end = adjust(ends[index]).clamp(-1, length - 1);
        if start <= end {
            return Err(OnnxError::Unsupported);
        }
        // Widen before negation so an INT64_MIN step is a valid singleton
        // selection instead of an overflow or a lossy stride approximation.
        let stride = -i128::from(steps[index]);
        let count = 1 + (i128::from(start) - i128::from(end) - 1) / stride;
        starts[index] = i64::try_from(i128::from(start) - (count - 1) * stride)
            .map_err(|_| OnnxError::Limit)?;
        ends[index] = start.checked_add(1).ok_or(OnnxError::Limit)?;
        steps[index] = if count == 1 {
            1
        } else {
            i64::try_from(stride).map_err(|_| OnnxError::Limit)?
        };
        if count > 1 {
            let count = usize::try_from(count).map_err(|_| OnnxError::Limit)?;
            nodes = nodes
                .checked_add(count)
                .and_then(|n| n.checked_add(1))
                .ok_or(OnnxError::Limit)?;
            reverse.push((selected, count));
        }
    }
    // Check the complete expansion before allocating any per-sample helpers.
    // All source names are already reserved, including the final output.
    let limits = lowering.admission.limits;
    if lowering
        .nodes
        .len()
        .checked_add(nodes)
        .ok_or(OnnxError::Limit)?
        > limits.nodes
        || lowering
            .known
            .len()
            .checked_add(nodes)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
        || lowering
            .reserved
            .len()
            .checked_add(nodes - 1)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
    {
        return Err(OnnxError::Limit);
    }
    lowering.admission.charge(nodes + selected_axes.len())?;
    let mut remaining = nodes;
    let mut input = append_slice_node(
        &source,
        lowering,
        &mut remaining,
        OpCode::Slice,
        vec![source.inputs[0].clone()],
        AttributeMap::from([
            ("starts".into(), AttrValue::IntList(starts)),
            ("ends".into(), AttrValue::IntList(ends)),
            ("axes".into(), AttrValue::IntList(selected_axes)),
            ("steps".into(), AttrValue::IntList(steps)),
        ]),
    )?;
    for (axis, count) in reverse {
        let mut parts = Vec::new();
        for index in (0..count).rev() {
            let start = i64::try_from(index).map_err(|_| OnnxError::Limit)?;
            parts.push(append_slice_node(
                &source,
                lowering,
                &mut remaining,
                OpCode::Slice,
                vec![input.clone()],
                AttributeMap::from([
                    ("starts".into(), AttrValue::IntList(vec![start])),
                    ("ends".into(), AttrValue::IntList(vec![start + 1])),
                    ("axes".into(), AttrValue::IntList(vec![axis])),
                    ("steps".into(), AttrValue::IntList(vec![1])),
                ]),
            )?);
        }
        input = append_slice_node(
            &source,
            lowering,
            &mut remaining,
            OpCode::Concat,
            parts,
            AttributeMap::from([("axis".into(), AttrValue::Int(axis))]),
        )?;
    }
    Ok(())
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
            if steps.iter().any(|&step| step < 0) {
                return reverse_slice(source, lowering, &dims, starts, ends, selected_axes, steps);
            }
            for (index, &selected) in selected_axes.iter().enumerate() {
                if steps[index] == 0 {
                    return Err(OnnxError::Graph);
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
