#![forbid(unsafe_code)]
//! Static Expand-13 and Tile-13 through bit-preserving Reshape/Concat only.
//!
//! https://onnx.ai/onnx/operators/onnx__Expand.html#expand-13
//! https://onnx.ai/onnx/operators/onnx__Tile.html#tile-13
//! Expand uses multidirectional broadcasting, not broadcast_to's target-only
//! rule. Tile repeats complete axis blocks and never broadcasts its control.
//! Binary prefix construction bounds helper count logarithmically in each
//! repeat factor; every intermediate is no larger than the admitted output.

use fss_tensor::DType;

use super::{Lowering, OnnxError, Result, SourceNode, port};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

struct Plan {
    aligned: Vec<usize>,
    output: Vec<usize>,
    repeats: Vec<usize>,
    reshape: bool,
    nodes: usize,
}

fn positive(value: i64) -> Result<usize> {
    if value <= 0 {
        // Zero-sized runtime tensors and negative dimensions remain outside
        // the importer's profile, even when the source operator admits zero.
        return Err(OnnxError::Unsupported);
    }
    usize::try_from(value).map_err(|_| OnnxError::Limit)
}

fn plan(op: &str, dims: &[usize], control: &[i64]) -> Result<Plan> {
    let rank = match op {
        "Expand" => dims.len().max(control.len()),
        "Tile" if dims.len() == control.len() => dims.len(),
        "Tile" => return Err(OnnxError::Graph),
        _ => return Err(OnnxError::Unsupported),
    };
    if rank > 8 {
        return Err(OnnxError::Limit);
    }
    let mut aligned = vec![1; rank];
    aligned[rank - dims.len()..].copy_from_slice(dims);
    let mut output = aligned.clone();
    let mut repeats = vec![1; rank];
    for (index, &value) in control.iter().enumerate() {
        let axis = rank - control.len() + index;
        let value = positive(value)?;
        if op == "Expand" {
            let input = aligned[axis];
            if input != value && input != 1 && value != 1 {
                return Err(OnnxError::Graph);
            }
            output[axis] = input.max(value);
            if input == 1 {
                repeats[axis] = output[axis];
            }
        } else {
            repeats[axis] = value;
            output[axis] = aligned[axis].checked_mul(value).ok_or(OnnxError::Limit)?;
        }
    }
    let reshape = rank != dims.len();
    let mut nodes = usize::from(reshape);
    for &factor in &repeats {
        // A factor is strictly positive. For its binary digits after the
        // leading one, double the current block and append one original
        // block for each set bit. Each Concat has exactly two inputs.
        let count = factor.ilog2() as usize + factor.count_ones() as usize - 1;
        nodes = nodes.checked_add(count).ok_or(OnnxError::Limit)?;
    }
    Ok(Plan {
        aligned,
        output,
        repeats,
        reshape,
        nodes: nodes.max(1),
    })
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
        format!("{}-repeat-{ordinal}", source.id)
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

pub(super) fn lower(source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if source.inputs.len() != 2
        || source.outputs.len() != 1
        || source.inputs.iter().any(String::is_empty)
    {
        return Err(OnnxError::Graph);
    }
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
    let dims = input.shape().dims().to_vec();
    let control = lowering.constant_i64_vector(&source.inputs[1])?;
    lowering.admission.charge(1 + dims.len() + control.len())?;
    let plan = plan(&source.op, &dims, &control)?;
    // The final shape bounds every monotone prefix. Reject aggregate node and
    // value expansion costs before generating any intermediate name or node.
    port(
        source.outputs[0].clone(),
        plan.output,
        lowering.generation,
        lowering.admission,
    )?;
    let limits = lowering.admission.limits;
    if lowering
        .nodes
        .len()
        .checked_add(plan.nodes)
        .ok_or(OnnxError::Limit)?
        > limits.nodes
        || lowering
            .known
            .len()
            .checked_add(plan.nodes)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
        || lowering
            .reserved
            .len()
            .checked_add(plan.nodes - 1)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
    {
        return Err(OnnxError::Limit);
    }
    let mut remaining = plan.nodes;
    let mut value = source.inputs[0].clone();
    if plan.reshape || plan.repeats.iter().all(|&factor| factor == 1) {
        let shape = plan
            .aligned
            .iter()
            .map(|&dim| i64::try_from(dim).map_err(|_| OnnxError::Limit))
            .collect::<Result<Vec<_>>>()?;
        value = append(
            &source,
            lowering,
            &mut remaining,
            OpCode::Reshape,
            vec![value],
            AttributeMap::from([("shape".into(), AttrValue::IntList(shape))]),
        )?;
    }
    for (axis, &factor) in plan.repeats.iter().enumerate() {
        if factor == 1 {
            continue;
        }
        let base = value.clone();
        let attrs = AttributeMap::from([("axis".into(), AttrValue::Int(axis as i64))]);
        for bit in (0..factor.ilog2()).rev() {
            value = append(
                &source,
                lowering,
                &mut remaining,
                OpCode::Concat,
                vec![value.clone(), value],
                attrs.clone(),
            )?;
            if factor & (1_usize << bit) != 0 {
                value = append(
                    &source,
                    lowering,
                    &mut remaining,
                    OpCode::Concat,
                    vec![value, base.clone()],
                    attrs.clone(),
                )?;
            }
        }
    }
    if remaining != 0 {
        return Err(OnnxError::Graph);
    }
    Ok(())
}
