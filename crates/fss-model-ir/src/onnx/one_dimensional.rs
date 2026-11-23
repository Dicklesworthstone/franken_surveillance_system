#![forbid(unsafe_code)]
//! Static NCW convolution and pooling through the existing frozen NCHW kernels.
//!
//! Conv-11, MaxPool-12 and AveragePool-11 use the same channel and spatial rules
//! in one and two dimensions. A trailing unit axis preserves source storage and
//! arithmetic order. Only the source-declared spatial attributes are promoted;
//! the existing lowerers still own padding, grouping, bias and schema admission.
//! No new operator, duplicated parameter, numeric policy or durable format is
//! introduced. Runtime reshapes use the ordinary accounted copy kernels.

use fss_tensor::DType;

use super::{Lowering, OnnxError, Result, SourceNode, node, pooling};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

pub(super) fn handles(source: &SourceNode<'_>, lowering: &Lowering<'_, '_>) -> bool {
    matches!(source.op.as_str(), "Conv" | "MaxPool" | "AveragePool")
        && source
            .inputs
            .first()
            .and_then(|name| lowering.known.get(name))
            .is_some_and(|port| port.rank() == 3)
}

fn promote_attributes(attrs: &mut AttributeMap) -> Result<()> {
    for key in ["kernel_shape", "strides", "dilations"] {
        if let Some(value) = attrs.get_mut(key) {
            let AttrValue::IntList(values) = value else {
                return Err(OnnxError::Graph);
            };
            if values.len() != 1 {
                return Err(OnnxError::Graph);
            }
            values.push(1);
        }
    }
    if let Some(value) = attrs.get_mut("pads") {
        let AttrValue::IntList(values) = value else {
            return Err(OnnxError::Graph);
        };
        let [before, after] = values.as_slice() else {
            return Err(OnnxError::Graph);
        };
        *values = vec![*before, 0, *after, 0];
    }
    Ok(())
}

fn reshape(
    lowering: &mut Lowering<'_, '_>,
    id: &str,
    label: &str,
    input: String,
    output: String,
    dims: &[usize],
) -> Result<()> {
    let shape = dims
        .iter()
        .map(|&dim| i64::try_from(dim).map_err(|_| OnnxError::Limit))
        .collect::<Result<Vec<_>>>()?;
    lowering.append(
        GraphNode::new(
            id,
            OpCode::Reshape,
            label,
            vec![input],
            vec![output],
            AttributeMap::from([("shape".into(), AttrValue::IntList(shape))]),
        )
        .map_err(|_| OnnxError::Graph)?,
    )
}

pub(super) fn lower(mut source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    let convolution = source.op == "Conv";
    let input_count = if convolution { 2..=3 } else { 1..=1 };
    if !input_count.contains(&source.inputs.len()) || source.outputs.len() != 1 {
        return Err(OnnxError::Graph);
    }
    let mut promoted_shapes = Vec::new();
    for name in source.inputs.iter().take(if convolution { 2 } else { 1 }) {
        let port = lowering.known.get(name).ok_or(OnnxError::Graph)?;
        if port.dtype() != DType::F32 || port.rank() != 3 || port.shape().dims().contains(&0) {
            return Err(OnnxError::Unsupported);
        }
        let mut dims = port.shape().dims().to_vec();
        dims.push(1);
        promoted_shapes.push(dims);
    }
    lowering
        .admission
        .charge(1 + source.attrs.len() + promoted_shapes.len())?;
    promote_attributes(&mut source.attrs)?;
    // Preflight every generated graph value. The rank-4 AveragePool lowerer
    // always adds two parameters and two nodes; its own admission also checks
    // the exact parameter bytes before allocating either tensor.
    let (nodes, parameters, helpers) = match source.op.as_str() {
        "Conv" => (4, 0, 3),
        "AveragePool" => (4, 2, 5),
        _ => (3, 0, 2),
    };
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
            .checked_add(nodes + parameters)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
        || lowering
            .reserved
            .len()
            .checked_add(helpers)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
    {
        return Err(OnnxError::Limit);
    }
    let original_id = source.id.clone();
    let original_output = source.outputs[0].clone();
    let label = source.label.clone();
    for (index, dims) in promoted_shapes.iter().enumerate() {
        let id = format!("{original_id}-oned-input-{index}");
        let output = lowering.fresh_name(&id)?;
        reshape(
            lowering,
            &id,
            &label,
            source.inputs[index].clone(),
            output.clone(),
            dims,
        )?;
        source.inputs[index] = output;
    }
    source.id = format!("{original_id}-oned-spatial");
    let output = lowering.fresh_name(&source.id)?;
    source.outputs[0] = output.clone();
    if source.op == "AveragePool" {
        pooling::lower(source, lowering)?;
    } else {
        let spatial = node(source, &lowering.known)?;
        lowering.append(spatial)?;
    }
    let dims = lowering
        .known
        .get(&output)
        .ok_or(OnnxError::Graph)?
        .shape()
        .dims();
    let [batch, channels, width, 1] = dims else {
        return Err(OnnxError::Graph);
    };
    let restored = [*batch, *channels, *width];
    reshape(
        lowering,
        &original_id,
        &label,
        output,
        original_output,
        &restored,
    )
}
