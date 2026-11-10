#![forbid(unsafe_code)]
//! Explicit feature-pyramid assembly into the existing static DFL decoder.
//!
//! Level names, strides and layouts are caller declarations. The complete pyramid
//! is admitted before helper construction; only frozen native layout operations
//! pack the fields. Existing DFL arithmetic, score meaning and source identities
//! are preserved, and the temporary packed tensor is not a public graph output.

use std::collections::{BTreeMap, BTreeSet};

use fss_tensor::DType;

use super::dfl::{OnnxDflHeadDecode, OnnxHeadLayout, decode_onnx_dfl_head};
use super::{Admission, ImportedOnnx, Lowering, OnnxError, OnnxLimits, Result, port};
use crate::{AttrValue, AttributeMap, GraphNode, ModelIrGraph, OpCode};

/// Explicit rank-four layout of one raw DFL feature level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnnxDflPyramidLayout {
    /// Batch, contiguous field planes, grid height, grid width.
    Nchw,
    /// Batch, grid height, grid width, contiguous fields.
    Nhwc,
}

/// One exact declared raw output and its model-input-grid interpretation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnnxDflPyramidLevel {
    /// Exact declared graph output, distinct from every other selected level.
    pub output: String,
    /// Positive pixel stride on both target axes, at most 4096.
    pub stride: usize,
    /// Exact source axis order; it is never inferred from matching dimensions.
    pub layout: OnnxDflPyramidLayout,
}

/// Static multi-scale DFL profile; score, class and NMS interpretation stay separate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnnxDflPyramidDecode {
    /// Two through 32 uniformly spaced distance bins per side.
    pub bins: usize,
    /// One through eight distinct outputs with unique strides. Order is semantic:
    /// rows follow this level order, then y, then x; the list is never sorted.
    pub levels: Vec<OnnxDflPyramidLevel>,
}

fn valid_name(name: &str) -> bool {
    name.len() <= 512 && !name.trim().is_empty() && !name.chars().any(char::is_control)
}

impl OnnxDflPyramidDecode {
    /// Validate the finite declared profile without accessing model tensors.
    ///
    /// Invalid names or duplicate output roles refuse as Graph; unsupported bin,
    /// level or stride bounds, including repeated strides, refuse as Unsupported.
    pub fn validate(&self) -> Result<()> {
        if !(2..=32).contains(&self.bins) || !(1..=8).contains(&self.levels.len()) {
            return Err(OnnxError::Unsupported);
        }
        let mut outputs = BTreeSet::new();
        let mut strides = BTreeSet::new();
        for level in &self.levels {
            if !valid_name(&level.output) || !outputs.insert(&level.output) {
                return Err(OnnxError::Graph);
            }
            if !(1..=4096).contains(&level.stride) || !strides.insert(level.stride) {
                return Err(OnnxError::Unsupported);
            }
        }
        Ok(())
    }
}

fn append(
    lowering: &mut Lowering<'_, '_>,
    suffix: &str,
    op: OpCode,
    inputs: Vec<String>,
    attrs: AttributeMap,
) -> Result<String> {
    let output = lowering.fresh_name(&format!("fss:dfl-pyramid:{suffix}"))?;
    lowering.append(
        GraphNode::new(&output, op, &output, inputs, vec![output.clone()], attrs)
            .map_err(|_| OnnxError::Graph)?,
    )?;
    Ok(output)
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

/// Decode explicitly named raw feature levels into one pixel-corner rows head.
///
/// Each level is static F32 with batch one. Its fields are four contiguous groups
/// of bins in left/top/right/bottom order, followed by the unchanged score tail.
/// Its spatial shape must equal target height/width divided by its declared stride.
/// NCHW levels are transposed to NHWC, each grid is flattened in y/x order, and
/// those rows are concatenated in the caller's level order. No level, class,
/// objectness, score activation or grid offset is guessed.
///
/// The existing native DFL decoder supplies the numerical profile: Softmax and
/// ascending-bin MatMul, stride multiplication, then separate center Sub/Add.
/// The final graph retains every original output in its original order and adds
/// only decoded_output. The temporary packed tensor remains private.
///
/// Complete packing plus DFL node/name counts and generated parameter/tensor
/// bytes are admitted before payload construction. Original source and cumulative
/// work/cancellation limits remain in force throughout. Missing/mismatched output
/// roles refuse as Graph; unsupported target,
/// bins or stride geometry as Unsupported; resource overflow as Limit.
/// Cancellation/refusal returns no partial converted graph.
pub fn decode_onnx_dfl_pyramid<'a>(
    imported: ImportedOnnx<'a>,
    decode: &OnnxDflPyramidDecode,
    decoded_output: &str,
    target: [usize; 2],
    score_fields: usize,
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
    decode.validate()?;
    if !valid_name(decoded_output) || imported.reserved.contains(decoded_output) {
        return Err(OnnxError::Graph);
    }
    if !(1..=257).contains(&score_fields)
        || target.iter().any(|n| !(1..=4096).contains(n))
        || target[0].checked_mul(target[1]).ok_or(OnnxError::Limit)? > 4_194_304
    {
        return Err(OnnxError::Unsupported);
    }
    admission.charge(decoded_output.len())?;
    let fields = decode
        .bins
        .checked_mul(4)
        .and_then(|value| value.checked_add(score_fields))
        .ok_or(OnnxError::Limit)?;
    let graph = &imported.graph;
    let mut level_rows = Vec::with_capacity(decode.levels.len());
    let mut rows = 0_usize;
    for level in &decode.levels {
        admission.charge(level.output.len() + 4)?;
        if !target[0].is_multiple_of(level.stride) || !target[1].is_multiple_of(level.stride) {
            return Err(OnnxError::Unsupported);
        }
        let height = target[0] / level.stride;
        let width = target[1] / level.stride;
        let count = height.checked_mul(width).ok_or(OnnxError::Limit)?;
        rows = rows.checked_add(count).ok_or(OnnxError::Limit)?;
        if rows > 32_768 {
            return Err(OnnxError::Limit);
        }
        let raw = graph.find_output(&level.output).ok_or(OnnxError::Graph)?;
        let expected = match level.layout {
            OnnxDflPyramidLayout::Nchw => [1, fields, height, width],
            OnnxDflPyramidLayout::Nhwc => [1, height, width, fields],
        };
        if raw.dtype() != DType::F32 || raw.shape().dims() != expected {
            return Err(OnnxError::Graph);
        }
        level_rows.push(count);
    }
    // One reshape per level, an explicit transpose for NCHW, and one row concat.
    // The unchanged rows-layout DFL decoder adds 13 nodes and three parameters.
    let packing_nodes = 1
        + decode.levels.len()
        + decode
            .levels
            .iter()
            .filter(|level| level.layout == OnnxDflPyramidLayout::Nchw)
            .count();
    let added_nodes = packing_nodes.checked_add(13).ok_or(OnnxError::Limit)?;
    let added_names = added_nodes.checked_add(3).ok_or(OnnxError::Limit)?;
    let parameter_bytes = rows
        .checked_mul(3)
        .and_then(|value| value.checked_add(decode.bins))
        .and_then(|value| value.checked_mul(4))
        .ok_or(OnnxError::Limit)?;
    if graph
        .nodes()
        .len()
        .checked_add(added_nodes)
        .ok_or(OnnxError::Limit)?
        > limits.nodes
        || imported
            .reserved
            .len()
            .checked_add(added_names)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
        || imported
            .parameter_bytes
            .checked_add(parameter_bytes)
            .ok_or(OnnxError::Limit)?
            > limits.parameter_bytes
    {
        return Err(OnnxError::Limit);
    }
    // The packed head is at least as large as every generated DFL tensor.
    // In particular, its size can exceed every individual source feature map.
    port(
        decoded_output.to_owned(),
        vec![1, rows, fields],
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
    let mut reserved = imported.reserved;
    // Prevent a valid caller-selected final name from being consumed by a packing
    // helper. It is removed again before the unchanged DFL owner reserves it.
    reserved.insert(decoded_output.to_owned());
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
    let mut parts = Vec::with_capacity(decode.levels.len());
    for (index, (level, &count)) in decode.levels.iter().zip(&level_rows).enumerate() {
        let mut output = level.output.clone();
        if level.layout == OnnxDflPyramidLayout::Nchw {
            output = append(
                &mut lowering,
                &format!("level-{index}-nhwc"),
                OpCode::Transpose,
                vec![output],
                AttributeMap::from([("permutation".into(), AttrValue::IntList(vec![0, 2, 3, 1]))]),
            )?;
        }
        let shape = [1, count, fields]
            .into_iter()
            .map(|value| i64::try_from(value).map_err(|_| OnnxError::Limit))
            .collect::<Result<Vec<_>>>()?;
        parts.push(append(
            &mut lowering,
            &format!("level-{index}-rows"),
            OpCode::Reshape,
            vec![output],
            AttributeMap::from([("shape".into(), AttrValue::IntList(shape))]),
        )?);
    }
    let packed = append(
        &mut lowering,
        "packed",
        OpCode::Concat,
        parts,
        AttributeMap::from([("axis".into(), AttrValue::Int(1))]),
    )?;
    let mut outputs = graph.outputs().to_vec();
    outputs.push(lowering.known.get(&packed).ok_or(OnnxError::Graph)?.clone());
    let Lowering {
        inputs,
        parameters,
        nodes,
        parameter_bytes,
        mut reserved,
        ..
    } = lowering;
    if !reserved.remove(decoded_output) {
        return Err(OnnxError::Graph);
    }
    admission.charge(validation_work(nodes.len(), inputs.len())?)?;
    let packed_graph = ModelIrGraph::new_validated(
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
        graph: packed_graph,
        parameters,
        runtime_inputs: imported.runtime_inputs,
        work: admission.used,
        parameter_bytes,
        reserved,
    };
    let profile = OnnxDflHeadDecode {
        raw_output: packed.clone(),
        raw_layout: OnnxHeadLayout::Rows,
        bins: decode.bins,
        strides: decode.levels.iter().map(|level| level.stride).collect(),
    };
    let mut decoded = decode_onnx_dfl_head(
        imported,
        &profile,
        decoded_output,
        target,
        score_fields,
        limits,
        cancelled,
    )?;
    // The packed output exists only to cross the existing DFL owner's explicit
    // declared-output boundary. Do not retain it as an extra public package head.
    let graph = &decoded.graph;
    let mut admission = Admission {
        limits,
        used: decoded.work,
        cancelled,
    };
    admission.charge(graph.outputs().len())?;
    let outputs: Vec<_> = graph
        .outputs()
        .iter()
        .filter(|output| output.name() != packed.as_str())
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
    decoded.graph = final_graph;
    decoded.work = admission.used;
    Ok(decoded)
}
