#![forbid(unsafe_code)]
//! Static Split-13 partitions expressed as existing native Slice operators.
//!
//! https://onnx.ai/onnx/operators/onnx__Split.html#split-13
//! Partitioning preserves the exact source F32 bits and output order. No new
//! runtime operator, integer execution, parameter tensor or framework is needed.

use super::{Lowering, OnnxError, Result, SourceNode};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

/// Matches the existing compile-time INT64 control-vector bound.
pub(super) const MAX_OUTPUTS: usize = 8;

pub(super) fn lower(mut source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    let count = source.outputs.len();
    if !(1..=2).contains(&source.inputs.len())
        || source.inputs[0].is_empty()
        || !(1..=MAX_OUTPUTS).contains(&count)
    {
        return Err(OnnxError::Graph);
    }
    let axis = match source.attrs.remove("axis") {
        None => 0,
        Some(AttrValue::Int(value)) => value,
        Some(_) => return Err(OnnxError::Graph),
    };
    if !source.attrs.is_empty() {
        return Err(OnnxError::Unsupported);
    }
    let input = lowering
        .known
        .get(&source.inputs[0])
        .ok_or(OnnxError::Graph)?;
    if input.dtype() != fss_tensor::DType::F32 || input.rank() == 0 {
        return Err(OnnxError::Unsupported);
    }
    let rank = i64::try_from(input.rank()).map_err(|_| OnnxError::Limit)?;
    if axis < -rank || axis >= rank {
        return Err(OnnxError::Graph);
    }
    let axis = if axis < 0 { axis + rank } else { axis };
    let length =
        i64::try_from(input.shape().dims()[axis as usize]).map_err(|_| OnnxError::Limit)?;
    let parts = match source.inputs.get(1).filter(|name| !name.is_empty()) {
        Some(name) => lowering.constant_i64_vector(name)?,
        None => {
            if length % count as i64 != 0 {
                return Err(OnnxError::Graph);
            }
            vec![length / count as i64; count]
        }
    };
    if parts.len() != count || parts.iter().any(|&part| part < 0) {
        return Err(OnnxError::Graph);
    }
    // ONNX permits empty parts, but this importer keeps positive runtime shapes.
    if parts.contains(&0) {
        return Err(OnnxError::Unsupported);
    }
    let total = parts.iter().try_fold(0_i64, |sum, &part| {
        sum.checked_add(part).ok_or(OnnxError::Limit)
    })?;
    if total != length {
        return Err(OnnxError::Graph);
    }
    let limits = lowering.admission.limits;
    if lowering
        .nodes
        .len()
        .checked_add(count)
        .ok_or(OnnxError::Limit)?
        > limits.nodes
        || lowering
            .known
            .len()
            .checked_add(count)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
    {
        return Err(OnnxError::Limit);
    }
    lowering.admission.charge(count)?;
    let mut start = 0_i64;
    for (index, (output, part)) in source.outputs.into_iter().zip(parts).enumerate() {
        let end = start.checked_add(part).ok_or(OnnxError::Limit)?;
        // Source node IDs are generated from their ordinals. A suffixed ID
        // cannot collide with another source node or this node's other slices;
        // output tensor names are the already reserved original source names.
        let id = format!("{}-split-{index}", source.id);
        let attrs = AttributeMap::from([
            ("starts".into(), AttrValue::IntList(vec![start])),
            ("ends".into(), AttrValue::IntList(vec![end])),
            ("axes".into(), AttrValue::IntList(vec![axis])),
            ("steps".into(), AttrValue::IntList(vec![1])),
        ]);
        lowering.append(
            GraphNode::new(
                id,
                OpCode::Slice,
                source.label.clone(),
                vec![source.inputs[0].clone()],
                vec![output],
                attrs,
            )
            .map_err(|_| OnnxError::Graph)?,
        )?;
        start = end;
    }
    Ok(())
}
