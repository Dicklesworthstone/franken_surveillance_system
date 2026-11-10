#![forbid(unsafe_code)]
//! Explicit class-axis Softmax before selecting named split-head class slots.
//!
//! The complete source class axis participates in normalization, including every
//! omitted background or unselected class. The existing split-head assembler then
//! preserves box bits and the caller's exact selected-class order.

use std::collections::{BTreeMap, BTreeSet};

use fss_tensor::DType;

use super::head_assembly::{OnnxSplitHeadAssembly, assemble_onnx_split_head};
use super::{
    Admission, ImportedOnnx, Lowering, OnnxError, OnnxHeadLayout, OnnxLimits, Result, port,
};
use crate::{AttrValue, AttributeMap, GraphNode, ModelIrGraph, OpCode, TensorPort};

fn valid_name(name: &str) -> bool {
    name.len() <= 512 && !name.trim().is_empty() && !name.chars().any(char::is_control)
}

fn dimensions(tensor: &TensorPort, layout: OnnxHeadLayout) -> Result<(usize, usize)> {
    let [batch, first, second] = tensor.shape().dims() else {
        return Err(OnnxError::Graph);
    };
    if tensor.dtype() != DType::F32 || *batch != 1 || *first == 0 || *second == 0 {
        return Err(OnnxError::Graph);
    }
    let (rows, fields) = match layout {
        OnnxHeadLayout::Rows => (*first, *second),
        OnnxHeadLayout::Channels => (*second, *first),
    };
    if rows > 32_768 {
        return Err(OnnxError::Limit);
    }
    Ok((rows, fields))
}

fn validation_work(nodes: usize, inputs: usize) -> Result<usize> {
    nodes
        .checked_mul(
            nodes
                .checked_add(inputs)
                .and_then(|value| value.checked_add(1))
                .ok_or(OnnxError::Limit)?,
        )
        .ok_or(OnnxError::Limit)
}

/// Assemble separate boxes and mutually exclusive class logits into probability rows.
///
/// Both source roles must be distinct declared static F32 outputs with batch one
/// and rank three, and equal row counts. Boxes have four fields; logits have one
/// through 257 fields. Source layouts are explicit and may differ. The existing
/// native Softmax normalizes across the COMPLETE original class axis (axis two for
/// Rows, one for Channels), before selecting class_indices in their declared order.
/// Omitted classes therefore retain their probability mass; selected probabilities
/// are never renormalized. This is an explicit model contract, not model detection.
///
/// The resulting output has shape [1, rows, 4 + class_indices.len()]. Original
/// box values and raw logits remain available bit-for-bit. Original source bytes,
/// parameters, runtime inputs, generation and IR version are preserved. Only the
/// requested assembled output is added publicly; normalized logits remain private.
///
/// Full normalization plus assembly node/name counts and logical tensor sizes are
/// admitted before helper construction. All original parameter/control bytes and
/// conversion work remain charged, and cancellation is checked through final graph
/// validation. Refusal returns no partially converted graph.
pub fn assemble_onnx_softmax_split_head<'a>(
    imported: ImportedOnnx<'a>,
    assembly: &OnnxSplitHeadAssembly,
    assembled_output: &str,
    limits: OnnxLimits,
    cancelled: &dyn Fn() -> bool,
) -> Result<ImportedOnnx<'a>> {
    if imported.source.len() > limits.source_bytes
        || limits.source_bytes > 16 * 1024 * 1024
        || limits.nodes == 0
        || limits.nodes > 512
        || limits.tensors == 0
        || limits.tensors > 4096
        || limits.parameter_bytes > 16 * 1024 * 1024
        || imported.parameter_bytes > limits.parameter_bytes
        || limits.tensor_bytes == 0
        || limits.tensor_bytes > 64 * 1024 * 1024
    {
        return Err(OnnxError::Limit);
    }
    let mut admission = Admission {
        limits,
        used: imported.work,
        cancelled,
    };
    admission.charge(0)?;
    assembly.validate()?;
    admission.charge(
        assembly.boxes_output.len() + assembly.scores_output.len() + assembly.class_indices.len(),
    )?;
    if !valid_name(assembled_output) || imported.reserved.contains(assembled_output) {
        return Err(OnnxError::Graph);
    }
    let graph = &imported.graph;
    let boxes = graph
        .find_output(&assembly.boxes_output)
        .ok_or(OnnxError::Graph)?;
    let scores = graph
        .find_output(&assembly.scores_output)
        .ok_or(OnnxError::Graph)?;
    let (rows, box_fields) = dimensions(boxes, assembly.boxes_layout)?;
    let (score_rows, score_fields) = dimensions(scores, assembly.scores_layout)?;
    if box_fields != 4
        || rows != score_rows
        || assembly
            .class_indices
            .iter()
            .any(|&index| index >= score_fields)
    {
        return Err(OnnxError::Graph);
    }
    if score_fields > 257 {
        return Err(OnnxError::Unsupported);
    }
    let complete = assembly.class_indices.iter().copied().eq(0..score_fields);
    // Match the unchanged assembler's coalescing of adjacent selected slots.
    let selections = if complete {
        0
    } else {
        1 + assembly
            .class_indices
            .windows(2)
            .filter(|pair| pair[1] != pair[0] + 1)
            .count()
    };
    let added_nodes = 2
        + selections
        + usize::from(assembly.boxes_layout == OnnxHeadLayout::Channels)
        + usize::from(assembly.scores_layout == OnnxHeadLayout::Channels);
    if graph
        .nodes()
        .len()
        .checked_add(added_nodes)
        .ok_or(OnnxError::Limit)?
        > limits.nodes
        || imported
            .reserved
            .len()
            .checked_add(added_nodes)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
    {
        return Err(OnnxError::Limit);
    }
    port(
        assembled_output.to_owned(),
        vec![1, rows, 4 + assembly.class_indices.len()],
        graph.generation(),
        &mut admission,
    )?;
    for tensor in graph.inputs().iter().chain(graph.outputs()) {
        admission.charge(tensor.name().len() + tensor.rank())?;
        if tensor
            .shape()
            .size_bytes(tensor.dtype())
            .map_err(|_| OnnxError::Limit)?
            > limits.tensor_bytes
        {
            return Err(OnnxError::Limit);
        }
    }
    admission.charge(assembled_output.len())?;
    let mut reserved = imported.reserved;
    // Prevent the requested final name from being consumed by the Softmax helper.
    reserved.insert(assembled_output.to_owned());
    let mut lowering = Lowering {
        generation: graph.generation(),
        inputs: graph.inputs().to_vec(),
        known: graph
            .inputs()
            .iter()
            .map(|p| (p.name().to_owned(), p.clone()))
            .collect(),
        parameters: imported.parameters,
        constants: BTreeMap::new(),
        parameter_bytes: imported.parameter_bytes,
        used_parameters: BTreeSet::new(),
        control_uses: BTreeSet::new(),
        nodes: Vec::new(),
        reserved,
        admission: &mut admission,
    };
    for node in graph.nodes() {
        lowering
            .admission
            .charge(node.inputs().len() + node.outputs().len())?;
        lowering.append(node.clone())?;
    }
    let normalized = lowering.fresh_name("fss:split-head-softmax:scores")?;
    let axis = match assembly.scores_layout {
        OnnxHeadLayout::Rows => 2,
        OnnxHeadLayout::Channels => 1,
    };
    lowering.append(
        GraphNode::new(
            &normalized,
            OpCode::Softmax,
            &normalized,
            vec![assembly.scores_output.clone()],
            vec![normalized.clone()],
            AttributeMap::from([("axis".into(), AttrValue::Int(axis))]),
        )
        .map_err(|_| OnnxError::Graph)?,
    )?;
    let mut outputs = graph.outputs().to_vec();
    outputs.push(
        lowering
            .known
            .get(&normalized)
            .ok_or(OnnxError::Graph)?
            .clone(),
    );
    let Lowering {
        inputs,
        parameters,
        nodes,
        parameter_bytes,
        mut reserved,
        ..
    } = lowering;
    if !reserved.remove(assembled_output) {
        return Err(OnnxError::Graph);
    }
    admission.charge(validation_work(nodes.len(), inputs.len())?)?;
    let graph = ModelIrGraph::new_validated(
        graph.id(),
        graph.version(),
        graph.generation(),
        inputs,
        outputs,
        nodes,
    )
    .map_err(|_| OnnxError::Graph)?;
    admission.charge(0)?;
    let imported = ImportedOnnx {
        source: imported.source,
        source_digest: imported.source_digest,
        graph,
        parameters,
        runtime_inputs: imported.runtime_inputs,
        work: admission.used,
        parameter_bytes,
        reserved,
    };
    let profile = OnnxSplitHeadAssembly {
        scores_output: normalized.clone(),
        ..assembly.clone()
    };
    let mut assembled =
        assemble_onnx_split_head(imported, &profile, assembled_output, limits, cancelled)?;
    // The temporary declaration is solely the existing assembler's role boundary.
    // Keep its computed tensor internal while preserving every original output.
    let graph = &assembled.graph;
    let mut admission = Admission {
        limits,
        used: assembled.work,
        cancelled,
    };
    admission.charge(graph.outputs().len())?;
    let outputs: Vec<_> = graph
        .outputs()
        .iter()
        .filter(|output| output.name() != normalized.as_str())
        .cloned()
        .collect();
    if outputs.len().checked_add(1) != Some(graph.outputs().len()) {
        return Err(OnnxError::Graph);
    }
    admission.charge(validation_work(graph.nodes().len(), graph.inputs().len())?)?;
    let final_graph = ModelIrGraph::new_validated(
        graph.id(),
        graph.version(),
        graph.generation(),
        graph.inputs().to_vec(),
        outputs,
        graph.nodes().to_vec(),
    )
    .map_err(|_| OnnxError::Graph)?;
    admission.charge(0)?;
    assembled.graph = final_graph;
    assembled.work = admission.used;
    Ok(assembled)
}
