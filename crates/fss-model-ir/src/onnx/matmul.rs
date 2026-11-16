#![forbid(unsafe_code)]
//! ONNX MatMul-13 vector promotion using the existing frozen matrix operator.
//!
//! https://onnx.ai/onnx/operators/onnx__MatMul.html#matmul-13
//! A left vector gains a leading singleton dimension; a right vector gains a
//! trailing singleton dimension. Only these implicit dimensions are removed from
//! the result. Matrix/matrix graphs retain their existing lowering and bytes.

use fss_tensor::DType;

use super::{Lowering, OnnxError, Result, SourceNode, port};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

pub(super) fn handles(source: &SourceNode<'_>, lowering: &Lowering<'_, '_>) -> bool {
    source.op == "MatMul"
        && source
            .inputs
            .iter()
            .filter_map(|name| lowering.known.get(name))
            .any(|value| value.rank() == 1)
}

fn append(
    source: &SourceNode<'_>,
    lowering: &mut Lowering<'_, '_>,
    remaining: &mut usize,
    op: OpCode,
    inputs: Vec<String>,
    shape: Option<&[usize]>,
) -> Result<String> {
    let ordinal = *remaining;
    *remaining = remaining.checked_sub(1).ok_or(OnnxError::Graph)?;
    let id = if *remaining == 0 {
        source.id.clone()
    } else {
        format!("{}-matmul-{ordinal}", source.id)
    };
    let output = if *remaining == 0 {
        source.outputs[0].clone()
    } else {
        lowering.fresh_name(&id)?
    };
    let mut attrs = AttributeMap::new();
    if let Some(shape) = shape {
        attrs.insert(
            "shape".into(),
            AttrValue::IntList(
                shape
                    .iter()
                    .map(|&dim| i64::try_from(dim).map_err(|_| OnnxError::Limit))
                    .collect::<Result<Vec<_>>>()?,
            ),
        );
    }
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
    let a = lowering
        .known
        .get(&source.inputs[0])
        .ok_or(OnnxError::Graph)?;
    let b = lowering
        .known
        .get(&source.inputs[1])
        .ok_or(OnnxError::Graph)?;
    if a.dtype() != DType::F32
        || b.dtype() != DType::F32
        || a.rank() == 0
        || b.rank() == 0
    {
        return Err(OnnxError::Unsupported);
    }
    let mut a_dims = a.shape().dims().to_vec();
    let mut b_dims = b.shape().dims().to_vec();
    let left_vector = a_dims.len() == 1;
    let right_vector = b_dims.len() == 1;
    if !left_vector && !right_vector {
        return Err(OnnxError::Graph);
    }
    lowering.admission.charge(1 + a_dims.len() + b_dims.len())?;
    if left_vector {
        a_dims.insert(0, 1);
    }
    if right_vector {
        b_dims.push(1);
    }
    if a_dims[a_dims.len() - 1] != b_dims[b_dims.len() - 2] {
        return Err(OnnxError::Graph);
    }
    let output_dims = if left_vector && right_vector {
        Vec::new()
    } else if left_vector {
        let mut dims = b_dims[..b_dims.len() - 2].to_vec();
        dims.push(b_dims[b_dims.len() - 1]);
        dims
    } else {
        a_dims[..a_dims.len() - 1].to_vec()
    };
    port(
        source.outputs[0].clone(),
        output_dims.clone(),
        lowering.generation,
        lowering.admission,
    )?;
    let nodes = 2 + usize::from(left_vector) + usize::from(right_vector);
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
    let mut remaining = nodes;
    let mut a = source.inputs[0].clone();
    let mut b = source.inputs[1].clone();
    if left_vector {
        a = append(
            &source,
            lowering,
            &mut remaining,
            OpCode::Reshape,
            vec![a],
            Some(&a_dims),
        )?;
    }
    if right_vector {
        b = append(
            &source,
            lowering,
            &mut remaining,
            OpCode::Reshape,
            vec![b],
            Some(&b_dims),
        )?;
    }
    let product = append(
        &source,
        lowering,
        &mut remaining,
        OpCode::MatMul,
        vec![a, b],
        None,
    )?;
    append(
        &source,
        lowering,
        &mut remaining,
        OpCode::Reshape,
        vec![product],
        Some(&output_dims),
    )?;
    if remaining != 0 {
        return Err(OnnxError::Graph);
    }
    Ok(())
}
