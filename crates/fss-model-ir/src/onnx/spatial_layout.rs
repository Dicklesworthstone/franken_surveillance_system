#![forbid(unsafe_code)]
//! Exact opset-13 spatial/channel rearrangement using frozen native layout ops.
//!
//! https://onnx.ai/onnx/operators/onnx__DepthToSpace.html#depthtospace-13
//! https://onnx.ai/onnx/operators/onnx__SpaceToDepth.html#spacetodepth-13
//! SpaceToDepth-13 has no mode attribute: its ordering is the inverse of DCR.
//! The three-node lowering neither changes sample bits nor creates parameters.

use fss_tensor::DType;

use super::{Lowering, OnnxError, Result, SourceNode, port};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

fn dimensions(values: &[usize]) -> Result<Vec<i64>> {
    values
        .iter()
        .map(|&value| i64::try_from(value).map_err(|_| OnnxError::Limit))
        .collect()
}

pub(super) fn lower(mut source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if source.inputs.len() != 1 || source.outputs.len() != 1 || source.inputs[0].is_empty() {
        return Err(OnnxError::Graph);
    }
    let block = match source.attrs.remove("blocksize") {
        Some(AttrValue::Int(value)) if value > 0 => {
            usize::try_from(value).map_err(|_| OnnxError::Limit)?
        }
        Some(_) => return Err(OnnxError::Graph),
        None => return Err(OnnxError::Malformed),
    };
    let depth_to_space = source.op == "DepthToSpace";
    let channel_first = if depth_to_space {
        match source.attrs.remove("mode") {
            None => false,
            Some(AttrValue::String(mode)) if mode == "DCR" => false,
            Some(AttrValue::String(mode)) if mode == "CRD" => true,
            Some(AttrValue::String(_)) => return Err(OnnxError::Unsupported),
            Some(_) => return Err(OnnxError::Graph),
        }
    } else {
        false
    };
    if !source.attrs.is_empty() {
        return Err(OnnxError::Unsupported);
    }
    let input = lowering
        .known
        .get(&source.inputs[0])
        .ok_or(OnnxError::Graph)?;
    if input.dtype() != DType::F32 || input.shape().dims().contains(&0) {
        return Err(OnnxError::Unsupported);
    }
    let [n, c, h, w]: [usize; 4] = input
        .shape()
        .dims()
        .try_into()
        .map_err(|_| OnnxError::Unsupported)?;
    let square = block.checked_mul(block).ok_or(OnnxError::Limit)?;
    let (expanded, permutation, output) = if depth_to_space {
        if c % square != 0 {
            return Err(OnnxError::Graph);
        }
        let channels = c / square;
        let expanded = if channel_first {
            [n, channels, block, block, h, w]
        } else {
            [n, block, block, channels, h, w]
        };
        let permutation = if channel_first {
            [0, 1, 4, 2, 5, 3]
        } else {
            [0, 3, 4, 1, 5, 2]
        };
        (
            expanded,
            permutation,
            [
                n,
                channels,
                h.checked_mul(block).ok_or(OnnxError::Limit)?,
                w.checked_mul(block).ok_or(OnnxError::Limit)?,
            ],
        )
    } else {
        if h % block != 0 || w % block != 0 {
            return Err(OnnxError::Graph);
        }
        (
            [n, c, h / block, block, w / block, block],
            [0, 3, 5, 1, 2, 4],
            [
                n,
                c.checked_mul(square).ok_or(OnnxError::Limit)?,
                h / block,
                w / block,
            ],
        )
    };
    // All shapes preserve the input element count. Validate bounds and reserve
    // the entire expansion before adding any intermediate or helper name.
    port(
        source.outputs[0].clone(),
        output.to_vec(),
        lowering.generation,
        lowering.admission,
    )?;
    let expanded = dimensions(&expanded)?;
    let output = dimensions(&output)?;
    let limits = lowering.admission.limits;
    if lowering
        .nodes
        .len()
        .checked_add(3)
        .ok_or(OnnxError::Limit)?
        > limits.nodes
        || lowering
            .known
            .len()
            .checked_add(3)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
        || lowering
            .reserved
            .len()
            .checked_add(2)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
    {
        return Err(OnnxError::Limit);
    }
    lowering.admission.charge(16)?;
    let reshape_id = format!("{}-spatial-reshape", source.id);
    let transpose_id = format!("{}-spatial-transpose", source.id);
    let reshaped = lowering.fresh_name(&reshape_id)?;
    let transposed = lowering.fresh_name(&transpose_id)?;
    for (id, op, input, output, attrs) in [
        (
            reshape_id,
            OpCode::Reshape,
            source.inputs[0].clone(),
            reshaped.clone(),
            AttributeMap::from([("shape".into(), AttrValue::IntList(expanded))]),
        ),
        (
            transpose_id,
            OpCode::Transpose,
            reshaped,
            transposed.clone(),
            AttributeMap::from([(
                "permutation".into(),
                AttrValue::IntList(permutation.to_vec()),
            )]),
        ),
        (
            source.id.clone(),
            OpCode::Reshape,
            transposed,
            source.outputs[0].clone(),
            AttributeMap::from([("shape".into(), AttrValue::IntList(output))]),
        ),
    ] {
        lowering.append(
            GraphNode::new(
                id,
                op,
                source.label.clone(),
                vec![input],
                vec![output],
                attrs,
            )
            .map_err(|_| OnnxError::Graph)?,
        )?;
    }
    Ok(())
}
