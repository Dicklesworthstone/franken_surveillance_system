#![forbid(unsafe_code)]
//! Gather-13 over F32 data with bounded static INT64 scalar/vector indices.
//!
//! https://onnx.ai/onnx/operators/onnx__Gather.html#gather-13
//! Existing Slice, Concat and Reshape move the selected samples without numerical
//! changes. Adjacent ascending indices share one slice; repeats and permutations
//! retain source order. The independent INT64 shape-program Gather stays unchanged.

use fss_tensor::DType;

use super::{Lowering, OnnxError, Result, SourceNode, port};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

pub(super) fn handles(source: &SourceNode<'_>, lowering: &Lowering<'_, '_>) -> bool {
    source.op == "Gather"
        && source
            .inputs
            .first()
            .and_then(|name| lowering.known.get(name))
            .is_some_and(|value| value.dtype() == DType::F32)
}

fn append(
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
        format!("{}-gather-{ordinal}", source.id)
    };
    let output = if *remaining == 0 {
        source.outputs[0].clone()
    } else {
        lowering.fresh_name(&id)?
    };
    lowering.append(
        GraphNode::new(id, op, source.label.clone(), inputs, vec![output.clone()], attrs)
            .map_err(|_| OnnxError::Graph)?,
    )?;
    Ok(output)
}

pub(super) fn lower(mut source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if source.inputs.len() != 2
        || source.outputs.len() != 1
        || source.inputs.iter().any(String::is_empty)
    {
        return Err(OnnxError::Graph);
    }
    let input = lowering.known.get(&source.inputs[0]).ok_or(OnnxError::Graph)?;
    let dims = input.shape().dims().to_vec();
    if input.dtype() != DType::F32 || dims.is_empty() || dims.contains(&0) {
        return Err(OnnxError::Unsupported);
    }
    let rank = dims.len() as i64;
    let axis = match source.attrs.remove("axis") {
        None => 0,
        Some(AttrValue::Int(axis)) if (-rank..rank).contains(&axis) => {
            (if axis < 0 { axis + rank } else { axis }) as usize
        }
        Some(_) => return Err(OnnxError::Graph),
    };
    if !source.attrs.is_empty() {
        return Err(OnnxError::Unsupported);
    }
    let control = lowering.constants.get(&source.inputs[1]).ok_or(OnnxError::Unsupported)?;
    if control.dtype() != DType::I64 || control.shape().rank() > 1 {
        return Err(OnnxError::Graph);
    }
    let count = control.shape().num_elements().map_err(|_| OnnxError::Limit)?;
    if count == 0 {
        return Err(OnnxError::Unsupported);
    }
    if count > 8 {
        return Err(OnnxError::Limit);
    }
    lowering.admission.charge(count * 8 + dims.len())?;
    let scalar = control.shape().rank() == 0;
    let indices = control.to_vec::<i64>().map_err(|_| OnnxError::Graph)?;
    lowering.control_uses.insert(source.inputs[1].clone());
    let extent = i64::try_from(dims[axis]).map_err(|_| OnnxError::Limit)?;
    let mut runs: Vec<(i64, i64)> = Vec::new();
    for index in indices {
        if index < -extent || index >= extent {
            return Err(OnnxError::Graph);
        }
        let index = if index < 0 { index + extent } else { index };
        match runs.last_mut() {
            Some((_, end)) if *end == index => *end += 1,
            _ => runs.push((index, index + 1)),
        }
    }
    let mut output_dims = dims;
    if scalar {
        output_dims.remove(axis);
    } else {
        output_dims[axis] = count;
    }
    port(source.outputs[0].clone(), output_dims.clone(), lowering.generation, lowering.admission)?;
    let nodes = runs.len() + usize::from(runs.len() > 1) + usize::from(scalar);
    let limits = lowering.admission.limits;
    if lowering.nodes.len().checked_add(nodes).ok_or(OnnxError::Limit)? > limits.nodes
        || lowering.known.len().checked_add(nodes).ok_or(OnnxError::Limit)? > limits.tensors
        || lowering.reserved.len().checked_add(nodes - 1).ok_or(OnnxError::Limit)? > limits.tensors
    {
        return Err(OnnxError::Limit);
    }
    let mut remaining = nodes;
    let mut selected = Vec::with_capacity(runs.len());
    for (start, end) in runs {
        selected.push(append(
            &source,
            lowering,
            &mut remaining,
            OpCode::Slice,
            vec![source.inputs[0].clone()],
            AttributeMap::from([
                ("axes".into(), AttrValue::IntList(vec![axis as i64])),
                ("starts".into(), AttrValue::IntList(vec![start])),
                ("ends".into(), AttrValue::IntList(vec![end])),
                ("steps".into(), AttrValue::IntList(vec![1])),
            ]),
        )?);
    }
    if selected.len() > 1 {
        append(
            &source,
            lowering,
            &mut remaining,
            OpCode::Concat,
            selected,
            AttributeMap::from([("axis".into(), AttrValue::Int(axis as i64))]),
        )?;
    } else if scalar {
        let shape = output_dims.iter().map(|&dim| i64::try_from(dim).map_err(|_| OnnxError::Limit)).collect::<Result<Vec<_>>>()?;
        append(
            &source,
            lowering,
            &mut remaining,
            OpCode::Reshape,
            selected,
            AttributeMap::from([("shape".into(), AttrValue::IntList(shape))]),
        )?;
    }
    if remaining != 0 {
        return Err(OnnxError::Graph);
    }
    Ok(())
}
