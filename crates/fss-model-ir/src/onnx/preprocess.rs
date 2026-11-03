#![forbid(unsafe_code)]
//! Explicit offline image adaptation for an already admitted ONNX graph.
//!
//! The source stays intact. Only frozen native Slice/Concat/Sub/Div operators and exact
//! F32 parameters are added, after the caller's RGB scaling and before the source graph.
//! Subtraction and division remain separate: folding them into weights changes rounding.

use std::collections::{BTreeMap, BTreeSet};

use fss_tensor::Tensor;

use super::{Admission, ImportedOnnx, Lowering, OnnxError, OnnxLimits, Result, port};
use crate::{AttrValue, AttributeMap, GraphNode, ModelIrGraph, OpCode};

/// Model-input channel order, explicitly selected by the operator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnnxChannelOrder {
    /// Preserve the caller's R, G, B channels.
    Rgb,
    /// Present the caller's B, G, R channels to the source model.
    Bgr,
}

/// Explicit F32 image transformation after native RGB resize and optional unit scaling.
/// Means and standard deviations are in the selected **model-input** channel order.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OnnxImageTransform {
    /// Preserve RGB or reverse it to BGR; never inferred from weights or metadata.
    pub channel_order: OnnxChannelOrder,
    /// Three finite F32 values, subtracted after channel ordering.
    pub mean: [f32; 3],
    /// Three strictly positive finite F32 divisors, applied after subtraction.
    pub standard_deviation: [f32; 3],
}

impl OnnxImageTransform {
    /// Validate parameters without reading a model or allocating tensors.
    pub fn validate(self) -> Result<()> {
        if self
            .mean
            .iter()
            .chain(&self.standard_deviation)
            .any(|v| !v.is_finite())
        {
            return Err(OnnxError::NonFinite);
        }
        if self.standard_deviation.iter().any(|&v| v <= 0.0) {
            return Err(OnnxError::Unsupported);
        }
        Ok(())
    }

    /// Check that the complete admitted RGB input interval produces finite normalized values.
    /// Scaling is performed by the existing caller, not by the generated graph.
    pub fn validate_rgb_range(self, scale_to_unit: bool) -> Result<()> {
        self.validate()?;
        let maximum = if scale_to_unit { 1.0_f32 } else { 255.0_f32 };
        for (mean, deviation) in self.mean.into_iter().zip(self.standard_deviation) {
            for value in [0.0_f32, maximum] {
                if !((value - mean) / deviation).is_finite() {
                    return Err(OnnxError::NonFinite);
                }
            }
        }
        Ok(())
    }
}

fn parameter(lowering: &mut Lowering<'_, '_>, base: &str, values: &[f32; 3]) -> Result<String> {
    lowering.admission.charge(12)?;
    let name = lowering.fresh_name(base)?;
    let port = port(
        name.clone(),
        vec![1, 3, 1, 1],
        lowering.generation,
        lowering.admission,
    )?;
    let tensor = Tensor::from_values(port.shape().clone(), values, lowering.generation)
        .map_err(|_| OnnxError::Limit)?;
    lowering.add_constant(port, tensor)?;
    Ok(name)
}

fn append(
    lowering: &mut Lowering<'_, '_>,
    base: &str,
    op: OpCode,
    inputs: Vec<String>,
    attributes: AttributeMap,
) -> Result<String> {
    let output = lowering.fresh_name(base)?;
    // Original source node IDs use onnx-node-*. Transform IDs equal their reserved
    // generated outputs, so repeated explicit transformations cannot collide either.
    let node = GraphNode::new(
        &output,
        op,
        &output,
        inputs,
        vec![output.clone()],
        attributes,
    )
    .map_err(|_| OnnxError::Graph)?;
    lowering.append(node)?;
    Ok(output)
}

/// Prepend explicit channel ordering and `(x - mean) / standard_deviation` to one
/// runtime image input of an imported graph, retaining the exact original ONNX bytes.
///
/// The input remains F32 `[1,3,height,width]` under its original name. All source nodes
/// consuming it are rewired, including branches. A directly exported image input is
/// refused because preserving both its input and output names would alias two values.
/// Other source outputs and parameters retain their names and exact bits.
///
/// Bounds and work are cumulative with the original import, including compile-time
/// controls discarded from execution. Failure returns no partially transformed graph.
/// This is an explicit conversion choice; ordinary `import_onnx` never invokes it.
pub fn transform_onnx_image<'a>(
    imported: ImportedOnnx<'a>,
    image_input: &str,
    transform: OnnxImageTransform,
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
    transform.validate()?;
    if !imported
        .runtime_inputs
        .iter()
        .any(|name| name == image_input)
    {
        return Err(OnnxError::Graph);
    }
    let graph = &imported.graph;
    let input = graph.find_input(image_input).ok_or(OnnxError::Graph)?;
    let dims = input.shape().dims();
    if dims.len() != 4 || dims[0] != 1 || dims[1] != 3 {
        return Err(OnnxError::Unsupported);
    }
    if graph
        .outputs()
        .iter()
        .any(|port| port.name() == image_input)
    {
        return Err(OnnxError::Unsupported);
    }
    let added_nodes = if transform.channel_order == OnnxChannelOrder::Bgr {
        6
    } else {
        2
    };
    if graph.nodes().len() + added_nodes > limits.nodes
        || imported.reserved.len() + added_nodes + 2 > limits.tensors
        || imported
            .parameter_bytes
            .checked_add(24)
            .ok_or(OnnxError::Limit)?
            > limits.parameter_bytes
    {
        return Err(OnnxError::Limit);
    }
    // Validate input/parameter copies and all new broadcast shapes before allocation.
    for input in graph.inputs() {
        admission.charge(input.name().len() + input.rank())?;
        if input
            .shape()
            .size_bytes(input.dtype())
            .map_err(|_| OnnxError::Limit)?
            > limits.tensor_bytes
        {
            return Err(OnnxError::Limit);
        }
    }
    if limits.tensor_bytes < 12 {
        return Err(OnnxError::Limit);
    }
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
        reserved: imported.reserved,
        admission: &mut admission,
    };
    let mut image = image_input.to_owned();
    if transform.channel_order == OnnxChannelOrder::Bgr {
        let mut channels = Vec::new();
        for channel in [2, 1, 0] {
            channels.push(append(
                &mut lowering,
                &format!("fss:image-preprocess:channel-{channel}"),
                OpCode::Slice,
                vec![image.clone()],
                AttributeMap::from([
                    ("axes".into(), AttrValue::IntList(vec![1])),
                    ("starts".into(), AttrValue::IntList(vec![channel])),
                    ("ends".into(), AttrValue::IntList(vec![channel + 1])),
                    ("steps".into(), AttrValue::IntList(vec![1])),
                ]),
            )?);
        }
        image = append(
            &mut lowering,
            "fss:image-preprocess:bgr",
            OpCode::Concat,
            channels,
            AttributeMap::from([("axis".into(), AttrValue::Int(1))]),
        )?;
    }
    let mean = parameter(&mut lowering, "fss:image-preprocess:mean", &transform.mean)?;
    let deviation = parameter(
        &mut lowering,
        "fss:image-preprocess:standard-deviation",
        &transform.standard_deviation,
    )?;
    let centered = append(
        &mut lowering,
        "fss:image-preprocess:centered",
        OpCode::Sub,
        vec![image, mean],
        AttributeMap::new(),
    )?;
    let normalized = append(
        &mut lowering,
        "fss:image-preprocess:normalized",
        OpCode::Div,
        vec![centered, deviation],
        AttributeMap::new(),
    )?;
    for node in graph.nodes() {
        lowering
            .admission
            .charge(node.inputs().len() + node.outputs().len())?;
        let inputs = node
            .inputs()
            .iter()
            .map(|name| {
                if name == image_input {
                    normalized.clone()
                } else {
                    name.clone()
                }
            })
            .collect();
        lowering.append(
            GraphNode::new(
                node.id(),
                node.op(),
                node.name(),
                inputs,
                node.outputs().to_vec(),
                node.attributes().clone(),
            )
            .map_err(|_| OnnxError::Graph)?,
        )?;
    }
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
        graph.outputs().to_vec(),
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
