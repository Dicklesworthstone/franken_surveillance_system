#![forbid(unsafe_code)]
//! Explicit static anchor-free distribution-distance head conversion.
//!
//! Each row stores left/top/right/bottom bin logits, then unchanged score fields.
//! Native Softmax and ascending-bin MatMul compute expected distances. Distances
//! are multiplied by stride before subtracting/adding exact half-cell pixel centers.
//! This declares one numerical profile, not automatic recognition of a model family.

use std::collections::{BTreeMap, BTreeSet};

use fss_tensor::{DType, Tensor};

use super::{Admission, ImportedOnnx, Lowering, OnnxError, OnnxLimits, Result, port};
use crate::{AttrValue, AttributeMap, GraphNode, ModelIrGraph, OpCode};

/// Explicit layout of a batch-one dense output; no layout is inferred from values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnnxHeadLayout {
    /// `[1, rows, fields]` row records.
    Rows,
    /// `[1, fields, rows]` field planes.
    Channels,
}

/// Static anchor-free DFL profile, separate from class/score/NMS interpretation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnnxDflHeadDecode {
    /// Existing declared graph output; its original name and values remain available.
    pub raw_output: String,
    /// Exact source tensor layout.
    pub raw_layout: OnnxHeadLayout,
    /// Bins per side, in increasing integer-distance order, from 2 through 32.
    pub bins: usize,
    /// One through eight unique positive strides, each at most 4096. Rows follow
    /// this declared order, then y, then x; this list is never sorted.
    pub strides: Vec<usize>,
}

fn valid_name(name: &str) -> bool {
    name.len() <= 512 && !name.trim().is_empty() && !name.chars().any(char::is_control)
}

impl OnnxDflHeadDecode {
    /// Validate the finite profile without reading or allocating model tensors.
    pub fn validate(&self) -> Result<()> {
        if !valid_name(&self.raw_output) {
            return Err(OnnxError::Graph);
        }
        if !(2..=32).contains(&self.bins)
            || self.strides.is_empty()
            || self.strides.len() > 8
            || self.strides.iter().any(|s| !(1..=4096).contains(s))
            || self.strides.iter().collect::<BTreeSet<_>>().len() != self.strides.len()
        {
            return Err(OnnxError::Unsupported);
        }
        Ok(())
    }
}

fn grid_rows(decode: &OnnxDflHeadDecode, target: [usize; 2]) -> Result<usize> {
    if target.iter().any(|n| !(1..=4096).contains(n)) || target[0] * target[1] > 4_194_304 {
        return Err(OnnxError::Unsupported);
    }
    let mut rows = 0_usize;
    for &stride in &decode.strides {
        if !target[0].is_multiple_of(stride) || !target[1].is_multiple_of(stride) {
            return Err(OnnxError::Unsupported);
        }
        rows = rows
            .checked_add((target[0] / stride) * (target[1] / stride))
            .ok_or(OnnxError::Limit)?;
    }
    if rows == 0 || rows > 32_768 {
        return Err(OnnxError::Limit);
    }
    Ok(rows)
}

fn cell(mut row: usize, target: [usize; 2], strides: &[usize]) -> Result<[usize; 3]> {
    for &stride in strides {
        let width = target[1] / stride;
        let count = (target[0] / stride) * width;
        if row < count {
            return Ok([stride, row % width, row / width]);
        }
        row -= count;
    }
    Err(OnnxError::Graph)
}

fn parameter(
    lowering: &mut Lowering<'_, '_>,
    base: &str,
    dimensions: Vec<usize>,
    mut value: impl FnMut(usize) -> Result<f32>,
) -> Result<String> {
    let name = lowering.fresh_name(base)?;
    let port = port(
        name.clone(),
        dimensions,
        lowering.generation,
        lowering.admission,
    )?;
    let count = port.shape().num_elements().map_err(|_| OnnxError::Limit)?;
    let bytes = port
        .shape()
        .size_bytes(DType::F32)
        .map_err(|_| OnnxError::Limit)?;
    lowering.admission.charge(bytes)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| OnnxError::Limit)?;
    for index in 0..count {
        // Includes a lookup through at most eight declared pyramid levels.
        lowering.admission.charge(9)?;
        values.push(value(index)?);
    }
    lowering.admission.charge(bytes)?;
    let tensor = Tensor::from_values(port.shape().clone(), &values, lowering.generation)
        .map_err(|_| OnnxError::Limit)?;
    lowering.add_constant(port, tensor)?;
    Ok(name)
}

fn append(
    lowering: &mut Lowering<'_, '_>,
    suffix: &str,
    op: OpCode,
    inputs: Vec<String>,
    attrs: AttributeMap,
) -> Result<String> {
    let output = lowering.fresh_name(&format!("fss:dfl:{suffix}"))?;
    lowering.append(
        GraphNode::new(&output, op, &output, inputs, vec![output.clone()], attrs)
            .map_err(|_| OnnxError::Graph)?,
    )?;
    Ok(output)
}
fn reshape(
    lowering: &mut Lowering<'_, '_>,
    suffix: &str,
    input: String,
    shape: &[usize],
) -> Result<String> {
    let shape = shape
        .iter()
        .map(|&n| i64::try_from(n).map_err(|_| OnnxError::Limit))
        .collect::<Result<Vec<_>>>()?;
    append(
        lowering,
        suffix,
        OpCode::Reshape,
        vec![input],
        AttributeMap::from([("shape".into(), AttrValue::IntList(shape))]),
    )
}
fn slice(
    lowering: &mut Lowering<'_, '_>,
    suffix: &str,
    input: String,
    start: usize,
    end: usize,
) -> Result<String> {
    append(
        lowering,
        suffix,
        OpCode::Slice,
        vec![input],
        AttributeMap::from([
            ("axes".into(), AttrValue::IntList(vec![2])),
            ("starts".into(), AttrValue::IntList(vec![start as i64])),
            ("ends".into(), AttrValue::IntList(vec![end as i64])),
            ("steps".into(), AttrValue::IntList(vec![1])),
        ]),
    )
}

/// Append a decoded `[1, rows, 4 + score_fields]` pixel-corner output while retaining
/// every original source output, parameter and ONNX byte.
///
/// Raw rows contain four contiguous groups of `bins` logits in left/top/right/bottom
/// order, then `score_fields` values copied without activation or interpretation.
/// `target` is `[height,width]`; both axes must be divisible by every declared stride.
/// Cell centers are `(x+0.5)*stride,(y+0.5)*stride`. Native F32 Softmax/MatMul computes
/// expected bin distances, then multiplication converts distances to pixels before
/// separate Sub/Add forms corners. No coordinate/score is silently clamped.
///
/// `decoded_output` must be a distinct new name. The same cumulative import quotas
/// apply to original controls, generated constants, helper nodes, validation and work.
/// Cancellation or refusal returns no partially converted graph.
pub fn decode_onnx_dfl_head<'a>(
    imported: ImportedOnnx<'a>,
    decode: &OnnxDflHeadDecode,
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
    if !(1..=257).contains(&score_fields) {
        return Err(OnnxError::Unsupported);
    }
    let rows = grid_rows(decode, target)?;
    let fields = 4 * decode.bins + score_fields;
    let graph = &imported.graph;
    let raw = graph
        .find_output(&decode.raw_output)
        .ok_or(OnnxError::Graph)?;
    let expected = match decode.raw_layout {
        OnnxHeadLayout::Rows => [1, rows, fields],
        OnnxHeadLayout::Channels => [1, fields, rows],
    };
    if raw.dtype() != DType::F32 || raw.shape().dims() != expected {
        return Err(OnnxError::Graph);
    }
    let added_nodes = 13 + usize::from(decode.raw_layout == OnnxHeadLayout::Channels);
    let added_bytes = (3 * rows + decode.bins)
        .checked_mul(4)
        .ok_or(OnnxError::Limit)?;
    if graph.nodes().len() + added_nodes > limits.nodes
        || imported.reserved.len() + added_nodes + 3 > limits.tensors
        || imported
            .parameter_bytes
            .checked_add(added_bytes)
            .ok_or(OnnxError::Limit)?
            > limits.parameter_bytes
    {
        return Err(OnnxError::Limit);
    }
    // Every generated tensor is no larger than the admitted raw head. Check it and
    // all existing input copies before constructing generated parameter buffers.
    for tensor in graph.inputs().iter().chain(std::iter::once(raw)) {
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
    admission.charge(decoded_output.len())?;
    let mut reserved = imported.reserved;
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
    let bins = parameter(&mut lowering, "fss:dfl:bins", vec![decode.bins, 1], |i| {
        Ok(i as f32)
    })?;
    let centers = parameter(&mut lowering, "fss:dfl:centers", vec![1, rows, 2], |i| {
        let [stride, x, y] = cell(i / 2, target, &decode.strides)?;
        Ok(((if i.is_multiple_of(2) { x } else { y }) as f32 + 0.5_f32) * stride as f32)
    })?;
    let stride = parameter(&mut lowering, "fss:dfl:strides", vec![1, rows, 1], |i| {
        Ok(cell(i, target, &decode.strides)?[0] as f32)
    })?;
    let mut raw = decode.raw_output.clone();
    if decode.raw_layout == OnnxHeadLayout::Channels {
        raw = append(
            &mut lowering,
            "rows",
            OpCode::Transpose,
            vec![raw],
            AttributeMap::from([("permutation".into(), AttrValue::IntList(vec![0, 2, 1]))]),
        )?;
    }
    let logits = slice(&mut lowering, "logits", raw.clone(), 0, 4 * decode.bins)?;
    let logits = reshape(
        &mut lowering,
        "side-bins",
        logits,
        &[1, rows, 4, decode.bins],
    )?;
    let probabilities = append(
        &mut lowering,
        "probabilities",
        OpCode::Softmax,
        vec![logits],
        AttributeMap::from([("axis".into(), AttrValue::Int(3))]),
    )?;
    let expected = append(
        &mut lowering,
        "expectation",
        OpCode::MatMul,
        vec![probabilities, bins],
        AttributeMap::new(),
    )?;
    let distances = reshape(&mut lowering, "distances", expected, &[1, rows, 4])?;
    let pixels = append(
        &mut lowering,
        "pixel-distances",
        OpCode::Mul,
        vec![distances, stride],
        AttributeMap::new(),
    )?;
    let left_top = slice(&mut lowering, "left-top", pixels.clone(), 0, 2)?;
    let right_bottom = slice(&mut lowering, "right-bottom", pixels, 2, 4)?;
    let minimum = append(
        &mut lowering,
        "minimum",
        OpCode::Sub,
        vec![centers.clone(), left_top],
        AttributeMap::new(),
    )?;
    let maximum = append(
        &mut lowering,
        "maximum",
        OpCode::Add,
        vec![centers, right_bottom],
        AttributeMap::new(),
    )?;
    let concat = || AttributeMap::from([("axis".into(), AttrValue::Int(2))]);
    let corners = append(
        &mut lowering,
        "corners",
        OpCode::Concat,
        vec![minimum, maximum],
        concat(),
    )?;
    let scores = slice(&mut lowering, "scores", raw, 4 * decode.bins, fields)?;
    // Source IDs use onnx-node-*; helper IDs use their reserved fss:* output names.
    // The final node's monotonically increasing graph ordinal makes repeated explicit
    // decode calls safe even when a caller's output name resembles a source node ID.
    let id = format!("onnx-dfl-{:04}", lowering.nodes.len());
    lowering.append(
        GraphNode::new(
            &id,
            OpCode::Concat,
            &id,
            vec![corners, scores],
            vec![decoded_output.to_owned()],
            concat(),
        )
        .map_err(|_| OnnxError::Graph)?,
    )?;
    let mut outputs = graph.outputs().to_vec();
    outputs.push(
        lowering
            .known
            .get(decoded_output)
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
