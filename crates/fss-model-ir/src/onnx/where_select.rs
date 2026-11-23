#![forbid(unsafe_code)]
//! Static BOOL masks select runtime F32 values without arithmetic blending.
//!
//! Where-9/16: https://onnx.ai/onnx/operators/onnx__Where.html
//! All three inputs participate in multidirectional broadcasting. Only the mask
//! is evaluated at import time; both F32 branches remain ordinary graph inputs.
//! Existing Reshape/Concat expansion and contiguous Slice runs preserve selected
//! bits, including signed zeros and subnormals. No Boolean runtime operator,
//! frozen IR revision, generated parameter or numerical approximation is added.

use fss_tensor::DType;

use super::{Lowering, OnnxError, Result, SourceNode, broadcast, port, push};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode, broadcast_shapes};

pub(super) fn handles(source: &SourceNode<'_>, lowering: &Lowering<'_, '_>) -> bool {
    source.op == "Where"
        && source.inputs.iter().skip(1).any(|name| {
            lowering
                .known
                .get(name)
                .is_some_and(|port| port.dtype() == DType::F32)
        })
}

#[derive(Clone, Copy)]
struct Run {
    branch: usize,
    start: usize,
    end: usize,
}

fn reserve(lowering: &Lowering<'_, '_>, nodes: usize) -> Result<()> {
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
    Ok(())
}

fn node_count(base: usize, runs: usize) -> Result<usize> {
    base.checked_add(runs)
        .and_then(|nodes| nodes.checked_add(usize::from(runs > 1)))
        .ok_or(OnnxError::Limit)
}

fn append(
    source: &SourceNode<'_>,
    lowering: &mut Lowering<'_, '_>,
    suffix: &str,
    op: OpCode,
    inputs: Vec<String>,
    attrs: AttributeMap,
    final_output: bool,
) -> Result<String> {
    let id = if final_output {
        source.id.clone()
    } else {
        format!("{}-where-{suffix}", source.id)
    };
    let output = if final_output {
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

fn reshape(
    source: &SourceNode<'_>,
    lowering: &mut Lowering<'_, '_>,
    suffix: &str,
    input: String,
    dims: &[usize],
    final_output: bool,
) -> Result<String> {
    let shape = dims
        .iter()
        .map(|&n| i64::try_from(n).map_err(|_| OnnxError::Limit))
        .collect::<Result<Vec<_>>>()?;
    append(
        source,
        lowering,
        suffix,
        OpCode::Reshape,
        vec![input],
        AttributeMap::from([("shape".into(), AttrValue::IntList(shape))]),
        final_output,
    )
}

pub(super) fn lower(source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if source.inputs.len() != 3
        || source.outputs.len() != 1
        || source.inputs.iter().any(String::is_empty)
    {
        return Err(OnnxError::Graph);
    }
    if !source.attrs.is_empty() {
        return Err(OnnxError::Unsupported);
    }
    let condition = lowering
        .constants
        .get(&source.inputs[0])
        .ok_or(OnnxError::Unsupported)?
        .clone();
    let x = lowering
        .known
        .get(&source.inputs[1])
        .ok_or(OnnxError::Graph)?;
    let y = lowering
        .known
        .get(&source.inputs[2])
        .ok_or(OnnxError::Graph)?;
    if condition.dtype() != DType::Bool
        || x.dtype() != DType::F32
        || y.dtype() != DType::F32
        || [condition.shape(), x.shape(), y.shape()]
            .iter()
            .any(|s| s.dims().contains(&0))
    {
        return Err(OnnxError::Unsupported);
    }
    let data_shape = broadcast_shapes(&source.id, "ONNX-WHERE", x.shape(), y.shape())
        .map_err(|_| OnnxError::Graph)?;
    let shape = broadcast_shapes(&source.id, "ONNX-WHERE", &data_shape, condition.shape())
        .map_err(|_| OnnxError::Graph)?;
    let dims = shape.dims().to_vec();
    port(
        source.outputs[0].clone(),
        dims.clone(),
        lowering.generation,
        lowering.admission,
    )?;
    let count = shape.num_elements().map_err(|_| OnnxError::Limit)?;
    let x_plan = broadcast::expansion(x.shape().dims(), &dims)?;
    let y_plan = broadcast::expansion(y.shape().dims(), &dims)?;
    // Two flattened branches and the final rank restoration accompany expansion.
    let base = x_plan
        .nodes
        .checked_add(y_plan.nodes)
        .and_then(|n| n.checked_add(3))
        .ok_or(OnnxError::Limit)?;
    reserve(lowering, node_count(base, 1)?)?;
    lowering.admission.charge(1 + dims.len() * 3)?;

    // All importer constants own contiguous typed storage. Read that immutable
    // storage directly: neither a second mask nor the broadcasted mask is allocated.
    if !condition.is_c_contiguous() {
        return Err(OnnxError::Graph);
    }
    let mask_count = condition.num_elements().map_err(|_| OnnxError::Limit)?;
    let mask = condition
        .view()
        .storage()
        .slice_range(condition.view().offset_bytes(), mask_count)
        .map_err(|_| OnnxError::Graph)?;
    let mut mask_strides = [0_usize; 8];
    let mut stride = 1_usize;
    for (axis, &dim) in condition.shape().dims().iter().enumerate().rev() {
        let output_axis = dims.len() - condition.rank() + axis;
        if dim != 1 {
            mask_strides[output_axis] = stride;
        }
        stride = stride.checked_mul(dim).ok_or(OnnxError::Limit)?;
    }
    let mut runs: Vec<Run> = Vec::new();
    if mask_count == 1 {
        let branch = match mask[0] {
            0 => 1,
            1 => 0,
            _ => return Err(OnnxError::Graph),
        };
        push(
            &mut runs,
            Run {
                branch,
                start: 0,
                end: count,
            },
            lowering.admission.limits.nodes,
        )?;
    } else {
        for start in (0..count).step_by(256) {
            let end = (start + 256).min(count);
            lowering.admission.charge(
                (end - start)
                    .checked_mul(dims.len() + 1)
                    .ok_or(OnnxError::Limit)?,
            )?;
            for index in start..end {
                let (mut coordinate, mut mask_index) = (index, 0_usize);
                for axis in (0..dims.len()).rev() {
                    mask_index += (coordinate % dims[axis]) * mask_strides[axis];
                    coordinate /= dims[axis];
                }
                let branch = match mask.get(mask_index) {
                    Some(0) => 1,
                    Some(1) => 0,
                    _ => return Err(OnnxError::Graph),
                };
                if let Some(last) = runs.last_mut().filter(|last| last.branch == branch) {
                    last.end = index + 1;
                } else {
                    // Bound the complete future graph before even growing its
                    // run metadata. Alternating masks stop at the first excess.
                    reserve(lowering, node_count(base, runs.len() + 1)?)?;
                    push(
                        &mut runs,
                        Run {
                            branch,
                            start: index,
                            end: index + 1,
                        },
                        lowering.admission.limits.nodes,
                    )?;
                }
            }
        }
    }
    let nodes = node_count(base, runs.len())?;
    reserve(lowering, nodes)?;
    lowering.admission.charge(nodes)?;
    lowering.control_uses.insert(source.inputs[0].clone());
    let before = lowering.nodes.len();
    let mut flat = Vec::with_capacity(2);
    for (branch, plan) in [x_plan, y_plan].into_iter().enumerate() {
        let id = format!("{}-where-branch-{branch}", source.id);
        let output = lowering.fresh_name(&id)?;
        let expanded = SourceNode {
            id,
            label: source.label.clone(),
            op: "Expand".into(),
            inputs: vec![source.inputs[branch + 1].clone()],
            outputs: vec![output.clone()],
            attrs: AttributeMap::new(),
            constant: None,
        };
        broadcast::apply(expanded, lowering, plan)?;
        flat.push(reshape(
            &source,
            lowering,
            &format!("flatten-{branch}"),
            output,
            &[count],
            false,
        )?);
    }
    let mut selected = Vec::with_capacity(runs.len());
    for (ordinal, run) in runs.into_iter().enumerate() {
        selected.push(append(
            &source,
            lowering,
            &format!("slice-{ordinal}"),
            OpCode::Slice,
            vec![flat[run.branch].clone()],
            AttributeMap::from([
                ("starts".into(), AttrValue::IntList(vec![run.start as i64])),
                ("ends".into(), AttrValue::IntList(vec![run.end as i64])),
                ("axes".into(), AttrValue::IntList(vec![0])),
                ("steps".into(), AttrValue::IntList(vec![1])),
            ]),
            false,
        )?);
    }
    let selected = if selected.len() > 1 {
        append(
            &source,
            lowering,
            "join",
            OpCode::Concat,
            selected,
            AttributeMap::from([("axis".into(), AttrValue::Int(0))]),
            false,
        )?
    } else {
        selected.pop().ok_or(OnnxError::Graph)?
    };
    reshape(&source, lowering, "restore", selected, &dims, true)?;
    if lowering.nodes.len() - before != nodes {
        return Err(OnnxError::Graph);
    }
    Ok(())
}
