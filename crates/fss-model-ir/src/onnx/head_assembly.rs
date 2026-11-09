#![forbid(unsafe_code)]
//! Explicit named box/score assembly for detector exports with separate outputs.
//!
//! Roles, layouts and class slots are supplied by the caller, never inferred from
//! shapes or values. Existing Transpose/Slice/Concat operators preserve every
//! selected F32 bit. Box units and score activation belong to the downstream head
//! contract; this conversion never guesses a background slot or applies sigmoid.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use fss_tensor::DType;

use super::{
    Admission, ImportedOnnx, Lowering, OnnxError, OnnxHeadLayout, OnnxLimits, Result, port,
};
use crate::{AttrValue, AttributeMap, GraphNode, ModelIrGraph, OpCode, TensorPort};

/// Explicit assembly of separate batch-one boxes and class-score outputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnnxSplitHeadAssembly {
    /// Exact declared graph output containing four box fields.
    pub boxes_output: String,
    /// Exact source box layout; fields retain their original declared order.
    pub boxes_layout: OnnxHeadLayout,
    /// Distinct exact declared graph output containing class scores or logits.
    pub scores_output: String,
    /// Exact source score layout, independent of the box layout.
    pub scores_layout: OnnxHeadLayout,
    /// One through 256 unique zero-based source score slots, in output-label order.
    /// Omitted slots are excluded explicitly; none is inferred to be background.
    pub class_indices: Vec<usize>,
}

fn valid_name(name: &str) -> bool {
    name.len() <= 512 && !name.trim().is_empty() && !name.chars().any(char::is_control)
}

impl OnnxSplitHeadAssembly {
    /// Validate bounded explicit roles and mapping without reading model tensors.
    pub fn validate(&self) -> Result<()> {
        if !valid_name(&self.boxes_output)
            || !valid_name(&self.scores_output)
            || self.boxes_output == self.scores_output
        {
            return Err(OnnxError::Graph);
        }
        if !(1..=256).contains(&self.class_indices.len()) {
            return Err(OnnxError::Unsupported);
        }
        // At most 256 foreground classes plus one explicitly excluded source
        // slot fit this profile. Graph admission checks the actual score width.
        if self.class_indices.iter().any(|&index| index > 256)
            || self.class_indices.iter().collect::<BTreeSet<_>>().len()
                != self.class_indices.len()
        {
            return Err(OnnxError::Graph);
        }
        Ok(())
    }
}

fn head_dimensions(tensor: &TensorPort, layout: OnnxHeadLayout) -> Result<(usize, usize)> {
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

fn runs(indices: &[usize]) -> Vec<Range<usize>> {
    let mut result: Vec<Range<usize>> = Vec::new();
    for &index in indices {
        if let Some(last) = result.last_mut()
            && last.end == index
        {
            last.end += 1;
        } else {
            result.push(index..index + 1);
        }
    }
    result
}

fn append(
    lowering: &mut Lowering<'_, '_>,
    suffix: &str,
    op: OpCode,
    inputs: Vec<String>,
    attrs: AttributeMap,
) -> Result<String> {
    let output = lowering.fresh_name(&format!("fss:split-head:{suffix}"))?;
    lowering.append(
        GraphNode::new(&output, op, &output, inputs, vec![output.clone()], attrs)
            .map_err(|_| OnnxError::Graph)?,
    )?;
    Ok(output)
}

fn row_order(
    lowering: &mut Lowering<'_, '_>,
    source: &str,
    layout: OnnxHeadLayout,
    role: &str,
) -> Result<String> {
    match layout {
        OnnxHeadLayout::Rows => Ok(source.to_owned()),
        OnnxHeadLayout::Channels => append(
            lowering,
            role,
            OpCode::Transpose,
            vec![source.to_owned()],
            AttributeMap::from([("permutation".into(), AttrValue::IntList(vec![0, 2, 1]))]),
        ),
    }
}

/// Append a rows-layout output shaped [1, rows, 4 + selected_classes].
///
/// Both roles must name distinct declared F32 graph outputs with equal row counts,
/// batch one, and rank three. Boxes have exactly four fields; scores have one
/// through 257 fields. The explicit class mapping preserves its caller-supplied
/// order and may exclude any unselected slots. No slot, box convention, sigmoid,
/// objectness, confidence threshold or NMS rule is inferred.
///
/// The original ONNX bytes, every original graph output and parameter remain
/// available. Only existing data-movement operators are appended; no parameter,
/// arithmetic approximation, IR version or frozen operator semantics are added.
/// The output name must be new. Complete expansion and original allocations stay
/// under the same cumulative import quotas, with no reset of work or cancellation.
pub fn assemble_onnx_split_head<'a>(
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
        assembly.boxes_output.len()
            + assembly.scores_output.len()
            + assembly.class_indices.len(),
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
    let (rows, box_fields) = head_dimensions(boxes, assembly.boxes_layout)?;
    let (score_rows, score_fields) = head_dimensions(scores, assembly.scores_layout)?;
    if box_fields != 4
        || rows != score_rows
        || assembly.class_indices.iter().any(|&index| index >= score_fields)
    {
        return Err(OnnxError::Graph);
    }
    if score_fields > 257 {
        return Err(OnnxError::Unsupported);
    }
    let complete_scores = assembly.class_indices.iter().copied().eq(0..score_fields);
    let selections = if complete_scores {
        Vec::new()
    } else {
        runs(&assembly.class_indices)
    };
    let added_nodes = 1
        + selections.len()
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
    // The final packed head can be larger than either source output. Admit its
    // full size before cloning nodes or constructing any generated helper.
    port(
        assembled_output.to_owned(),
        vec![1, rows, 4 + assembly.class_indices.len()],
        graph.generation(),
        &mut admission,
    )?;
    for tensor in graph.inputs().iter().chain([boxes, scores]) {
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
    let boxes = row_order(
        &mut lowering,
        &assembly.boxes_output,
        assembly.boxes_layout,
        "boxes",
    )?;
    let scores = row_order(
        &mut lowering,
        &assembly.scores_output,
        assembly.scores_layout,
        "scores",
    )?;
    let mut parts = vec![boxes];
    if complete_scores {
        parts.push(scores);
    } else {
        for (index, range) in selections.iter().enumerate() {
            let selected = append(
                &mut lowering,
                &format!("classes-{index}"),
                OpCode::Slice,
                vec![scores.clone()],
                AttributeMap::from([
                    ("axes".into(), AttrValue::IntList(vec![2])),
                    ("starts".into(), AttrValue::IntList(vec![range.start as i64])),
                    ("ends".into(), AttrValue::IntList(vec![range.end as i64])),
                    ("steps".into(), AttrValue::IntList(vec![1])),
                ]),
            )?;
            parts.push(selected);
        }
    }
    // Imported source IDs use onnx-node-*, and generated helper IDs use fss:*
    // or onnx-node-* derivatives. Other adapters have their own onnx-dfl-* and
    // fss:* prefixes. Only this final node uses onnx-split-head-*, with the
    // monotonically increasing graph ordinal making repeated calls distinct.
    // Tensor names belong to a separate namespace and cannot shadow node IDs.
    let id = format!("onnx-split-head-{:04}", lowering.nodes.len());
    lowering.append(
        GraphNode::new(
            &id,
            OpCode::Concat,
            &id,
            parts,
            vec![assembled_output.to_owned()],
            AttributeMap::from([("axis".into(), AttrValue::Int(2))]),
        )
        .map_err(|_| OnnxError::Graph)?,
    )?;
    let mut outputs = graph.outputs().to_vec();
    outputs.push(
        lowering
            .known
            .get(assembled_output)
            .ok_or(OnnxError::Graph)?
            .clone(),
    );
    let Lowering {
        inputs,
        parameters,
        nodes,
        parameter_bytes,
        reserved,
        ..
    } = lowering;
    admission.charge(
        nodes
            .len()
            .checked_mul(nodes.len() + inputs.len() + 1)
            .ok_or(OnnxError::Limit)?,
    )?;
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
    Ok(ImportedOnnx {
        source: imported.source,
        source_digest: imported.source_digest,
        graph,
        parameters,
        runtime_inputs: imported.runtime_inputs,
        work: admission.used,
        parameter_bytes,
        reserved,
    })
}
