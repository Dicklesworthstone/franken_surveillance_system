#![forbid(unsafe_code)]
//! Offline ONNX IR 7..=9 / default-domain opset 13 import into the frozen Model IR.
//!
//! This is deliberately a closed profile, not an ONNX interpreter. It supports static,
//! positive F32 shapes, embedded finite F32 initializers, and the operators lowered below.
//! Original bytes remain borrowed for provenance. No downloads, external tensor files,
//! custom functions, training graphs, model activation or inference occur here.
//! Wire/schema reference: onnx/onnx, onnx/onnx.proto; operator semantics: onnx.ai/operators.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{ContentDigest, DigestAlgorithm, Generation, Sha256Hasher};
use fss_tensor::{DType, Shape, Tensor};

use crate::{AttrValue, AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort};

mod gemm;

/// Explicit bounds for parsing, source hashing, graph conversion and parameter allocation.
#[derive(Clone, Copy, Debug)]
pub struct OnnxLimits {
    /// Complete source file ceiling, at most 16 MiB.
    pub source_bytes: usize,
    /// Source and lowered native operator ceiling, at most 512.
    pub nodes: usize,
    /// Total named tensor declarations and intermediate values, at most 4096.
    pub tensors: usize,
    /// Aggregate embedded and generated F32 parameter bytes, at most 16 MiB.
    pub parameter_bytes: usize,
    /// Each declared/inferred logical tensor size, at most 64 MiB.
    pub tensor_bytes: usize,
    /// Cumulative deterministic import work; not a hardware MAC or RSS measurement.
    pub work_units: u64,
}
impl Default for OnnxLimits {
    fn default() -> Self {
        Self {
            source_bytes: 16 * 1024 * 1024,
            nodes: 512,
            tensors: 4096,
            parameter_bytes: 16 * 1024 * 1024,
            tensor_bytes: 64 * 1024 * 1024,
            work_units: 128 * 1024 * 1024,
        }
    }
}

/// Payload-free import refusal; no incomplete graph or partially bound parameters escape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnnxError {
    /// A byte, item, rank, allocation or arithmetic bound failed.
    Limit,
    /// Original source does not match the independently expected SHA-256 digest.
    Digest,
    /// Malformed protobuf, duplicate singular field/name, missing field or invalid UTF-8.
    Malformed,
    /// Version, domain, operator, attribute, dtype or external/dynamic facility is unsupported.
    Unsupported,
    /// Native graph shape, topology, parameter or output declarations disagree.
    Graph,
    /// An embedded parameter or floating-point attribute is nonfinite.
    NonFinite,
    /// The caller's cancellation probe requested stopping.
    Cancelled,
    /// The cumulative import work allowance is exhausted.
    WorkBudget,
}
impl std::fmt::Display for OnnxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Limit => "ONNX import bound exceeded",
            Self::Digest => "ONNX source digest mismatch",
            Self::Malformed => "malformed or ambiguous ONNX source",
            Self::Unsupported => "ONNX feature outside the admitted static profile",
            Self::Graph => "ONNX graph disagrees with native Model IR",
            Self::NonFinite => "nonfinite ONNX initializer or attribute",
            Self::Cancelled => "ONNX import cancelled",
            Self::WorkBudget => "ONNX import work exhausted",
        })
    }
}
impl std::error::Error for OnnxError {}
type Result<T> = std::result::Result<T, OnnxError>;

/// Verified conversion retaining the original source and exact native parameter tensors.
/// This is a conversion result, not a model qualification or publication receipt.
#[derive(Debug)]
pub struct ImportedOnnx<'a> {
    source: &'a [u8],
    source_digest: ContentDigest,
    graph: ModelIrGraph,
    parameters: BTreeMap<String, Tensor>,
    runtime_inputs: Vec<String>,
    work: u64,
}
impl<'a> ImportedOnnx<'a> {
    /// Original bytes, including source metadata that does not participate in execution.
    pub fn source(&self) -> &'a [u8] {
        self.source
    }
    /// Independently checked source identity; no mutable file alias is followed.
    pub fn source_digest(&self) -> ContentDigest {
        self.source_digest
    }
    /// Validated frozen graph. Existing scalar/planned/optimized executors may consume it.
    pub fn graph(&self) -> &ModelIrGraph {
        &self.graph
    }
    /// Exact embedded F32 initializers and generated lowering scalars, generation-bound.
    pub fn parameters(&self) -> &BTreeMap<String, Tensor> {
        &self.parameters
    }
    /// Input names the caller must supply in addition to the embedded parameters.
    pub fn runtime_inputs(&self) -> &[String] {
        &self.runtime_inputs
    }
    /// Charged conversion work, including source hashing; not inference cost.
    pub fn work_units(&self) -> u64 {
        self.work
    }
}

struct Admission<'a> {
    limits: OnnxLimits,
    used: u64,
    cancelled: &'a dyn Fn() -> bool,
}
impl Admission<'_> {
    fn charge(&mut self, units: usize) -> Result<()> {
        if (self.cancelled)() {
            return Err(OnnxError::Cancelled);
        }
        let next = self
            .used
            .checked_add(u64::try_from(units).map_err(|_| OnnxError::Limit)?)
            .ok_or(OnnxError::Limit)?;
        if next > self.limits.work_units {
            return Err(OnnxError::WorkBudget);
        }
        self.used = next;
        Ok(())
    }
}
fn push<T>(values: &mut Vec<T>, value: T, maximum: usize) -> Result<()> {
    if values.len() >= maximum {
        return Err(OnnxError::Limit);
    }
    values.try_reserve(1).map_err(|_| OnnxError::Limit)?;
    values.push(value);
    Ok(())
}
fn singular(seen: &mut u64, tag: u32) -> Result<()> {
    let bit = 1_u64.checked_shl(tag).ok_or(OnnxError::Unsupported)?;
    if *seen & bit != 0 {
        return Err(OnnxError::Malformed);
    }
    *seen |= bit;
    Ok(())
}
fn text(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| OnnxError::Malformed)
}
fn name(bytes: &[u8]) -> Result<String> {
    let value = text(bytes)?;
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(OnnxError::Limit);
    }
    Ok(value.to_owned())
}

#[derive(Clone, Copy)]
enum Value<'a> {
    Integer(u64),
    Bytes(&'a [u8]),
    Fixed32(u32),
    Fixed64,
}
impl<'a> Value<'a> {
    fn bytes(self) -> Result<&'a [u8]> {
        match self {
            Self::Bytes(b) => Ok(b),
            _ => Err(OnnxError::Malformed),
        }
    }
    fn integer(self) -> Result<u64> {
        match self {
            Self::Integer(n) => Ok(n),
            _ => Err(OnnxError::Malformed),
        }
    }
}
struct Wire<'a>(&'a [u8]);
impl<'a> Wire<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let part = self.0.get(..count).ok_or(OnnxError::Malformed)?;
        self.0 = &self.0[count..];
        Ok(part)
    }
    fn varint(&mut self) -> Result<u64> {
        let mut out = 0_u64;
        for index in 0..10 {
            let byte = self.take(1)?[0];
            if index == 9 && byte > 1 {
                return Err(OnnxError::Malformed);
            }
            out |= u64::from(byte & 127) << (index * 7);
            if byte & 128 == 0 {
                return Ok(out);
            }
        }
        Err(OnnxError::Malformed)
    }
    fn next(&mut self, admission: &mut Admission<'_>) -> Result<Option<(u32, Value<'a>)>> {
        if self.0.is_empty() {
            return Ok(None);
        }
        admission.charge(1)?;
        let key = self.varint()?;
        let tag = u32::try_from(key >> 3).map_err(|_| OnnxError::Malformed)?;
        if tag == 0 || tag > 0x1fff_ffff {
            return Err(OnnxError::Malformed);
        }
        let value = match key & 7 {
            0 => Value::Integer(self.varint()?),
            1 => {
                self.take(8)?;
                Value::Fixed64
            }
            2 => {
                let length = usize::try_from(self.varint()?).map_err(|_| OnnxError::Limit)?;
                Value::Bytes(self.take(length)?)
            }
            5 => Value::Fixed32(u32::from_le_bytes(
                self.take(4)?.try_into().map_err(|_| OnnxError::Malformed)?,
            )),
            _ => return Err(OnnxError::Unsupported),
        };
        Ok(Some((tag, value)))
    }
}
fn integers(
    value: Value<'_>,
    output: &mut Vec<i64>,
    maximum: usize,
    a: &mut Admission<'_>,
) -> Result<()> {
    match value {
        Value::Integer(n) => {
            a.charge(1)?;
            push(output, n as i64, maximum)
        }
        Value::Bytes(bytes) => {
            let mut wire = Wire(bytes);
            while !wire.0.is_empty() {
                a.charge(1)?;
                push(output, wire.varint()? as i64, maximum)?;
            }
            Ok(())
        }
        _ => Err(OnnxError::Malformed),
    }
}
fn port(
    name: String,
    dims: Vec<usize>,
    generation: Generation,
    a: &Admission<'_>,
) -> Result<TensorPort> {
    if dims.len() > 8 || dims.contains(&0) {
        return Err(OnnxError::Unsupported);
    }
    let shape = Shape::new(dims).map_err(|_| OnnxError::Limit)?;
    if shape.size_bytes(DType::F32).map_err(|_| OnnxError::Limit)? > a.limits.tensor_bytes {
        return Err(OnnxError::Limit);
    }
    TensorPort::new(name, DType::F32, shape, generation).map_err(|_| OnnxError::Graph)
}
fn dimension(bytes: &[u8], a: &mut Admission<'_>) -> Result<usize> {
    let mut wire = Wire(bytes);
    let (mut seen, mut value) = (0, None);
    while let Some((tag, field)) = wire.next(a)? {
        singular(&mut seen, tag)?;
        match tag {
            1 => value = Some(field.integer()?),
            3 => {
                text(field.bytes()?)?;
            }
            _ => return Err(OnnxError::Unsupported),
        }
    }
    let n = value.ok_or(OnnxError::Unsupported)?;
    if n == 0 || n > i64::MAX as u64 {
        return Err(OnnxError::Unsupported);
    }
    usize::try_from(n).map_err(|_| OnnxError::Limit)
}
fn value_info(bytes: &[u8], generation: Generation, a: &mut Admission<'_>) -> Result<TensorPort> {
    let mut wire = Wire(bytes);
    let (mut seen, mut id, mut ty) = (0, None, None);
    while let Some((tag, value)) = wire.next(a)? {
        singular(&mut seen, tag)?;
        match tag {
            1 => id = Some(name(value.bytes()?)?),
            2 => ty = Some(value.bytes()?),
            3 => {
                text(value.bytes()?)?;
            }
            _ => return Err(OnnxError::Unsupported),
        }
    }
    let mut wire = Wire(ty.ok_or(OnnxError::Malformed)?);
    let (mut seen, mut tensor) = (0, None);
    while let Some((tag, value)) = wire.next(a)? {
        singular(&mut seen, tag)?;
        match tag {
            1 => tensor = Some(value.bytes()?),
            6 => {
                text(value.bytes()?)?;
            }
            _ => return Err(OnnxError::Unsupported),
        }
    }
    let mut wire = Wire(tensor.ok_or(OnnxError::Unsupported)?);
    let (mut seen, mut dtype, mut shape) = (0, None, None);
    while let Some((tag, value)) = wire.next(a)? {
        singular(&mut seen, tag)?;
        match tag {
            1 => dtype = Some(value.integer()?),
            2 => shape = Some(value.bytes()?),
            _ => return Err(OnnxError::Unsupported),
        }
    }
    if dtype != Some(1) {
        return Err(OnnxError::Unsupported);
    }
    let mut wire = Wire(shape.ok_or(OnnxError::Unsupported)?);
    let mut dims = Vec::new();
    while let Some((tag, value)) = wire.next(a)? {
        if tag != 1 {
            return Err(OnnxError::Unsupported);
        }
        push(&mut dims, dimension(value.bytes()?, a)?, 8)?;
    }
    port(id.ok_or(OnnxError::Malformed)?, dims, generation, a)
}
fn initializer(
    bytes: &[u8],
    generation: Generation,
    a: &mut Admission<'_>,
) -> Result<(TensorPort, Tensor)> {
    let mut wire = Wire(bytes);
    let (mut seen, mut id, mut dtype, mut raw) = (0, None, None, None);
    let (mut dims, mut floats) = (Vec::new(), Vec::new());
    let mut typed_data = false;
    while let Some((tag, value)) = wire.next(a)? {
        match tag {
            1 => integers(value, &mut dims, 8, a)?,
            4 => {
                typed_data = true;
                match value {
                    Value::Fixed32(bits) => {
                        a.charge(4)?;
                        push(
                            &mut floats,
                            f32::from_bits(bits),
                            a.limits.parameter_bytes / 4,
                        )?;
                    }
                    Value::Bytes(data) => {
                        if data.len() % 4 != 0 {
                            return Err(OnnxError::Malformed);
                        }
                        for bytes in data.chunks_exact(4) {
                            a.charge(4)?;
                            let bits = u32::from_le_bytes(
                                bytes.try_into().map_err(|_| OnnxError::Malformed)?,
                            );
                            push(
                                &mut floats,
                                f32::from_bits(bits),
                                a.limits.parameter_bytes / 4,
                            )?;
                        }
                    }
                    _ => return Err(OnnxError::Malformed),
                }
            }
            2 | 8 | 9 | 12 => {
                singular(&mut seen, tag)?;
                match tag {
                    2 => dtype = Some(value.integer()?),
                    8 => id = Some(name(value.bytes()?)?),
                    9 => raw = Some(value.bytes()?),
                    12 => {
                        text(value.bytes()?)?;
                    }
                    _ => return Err(OnnxError::Malformed),
                }
            }
            _ => return Err(OnnxError::Unsupported),
        }
    }
    if dtype != Some(1) {
        return Err(OnnxError::Unsupported);
    }
    let dims = dims
        .into_iter()
        .map(|n| {
            if n <= 0 {
                Err(OnnxError::Unsupported)
            } else {
                usize::try_from(n).map_err(|_| OnnxError::Limit)
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let declared = port(id.ok_or(OnnxError::Malformed)?, dims, generation, a)?;
    let count = declared
        .shape()
        .num_elements()
        .map_err(|_| OnnxError::Limit)?;
    let size = count.checked_mul(4).ok_or(OnnxError::Limit)?;
    if size > a.limits.parameter_bytes {
        return Err(OnnxError::Limit);
    }
    if let Some(raw) = raw {
        if typed_data || raw.len() != size {
            return Err(OnnxError::Malformed);
        }
        for bytes in raw.chunks_exact(4) {
            a.charge(4)?;
            push(
                &mut floats,
                f32::from_le_bytes(bytes.try_into().map_err(|_| OnnxError::Malformed)?),
                count,
            )?;
        }
    }
    if floats.len() != count {
        return Err(OnnxError::Malformed);
    }
    if floats.iter().any(|n| !n.is_finite()) {
        return Err(OnnxError::NonFinite);
    }
    a.charge(size)?;
    let tensor = Tensor::from_values(declared.shape().clone(), &floats, generation)
        .map_err(|_| OnnxError::Limit)?;
    Ok((declared, tensor))
}
fn attribute(bytes: &[u8], a: &mut Admission<'_>) -> Result<(String, AttrValue)> {
    let mut wire = Wire(bytes);
    let (mut seen, mut id, mut ty, mut scalar) = (0, None, None, None);
    let mut list = Vec::new();
    let mut list_present = false;
    while let Some((tag, value)) = wire.next(a)? {
        if tag == 8 {
            list_present = true;
            integers(value, &mut list, 8, a)?;
            continue;
        }
        singular(&mut seen, tag)?;
        match tag {
            1 => id = Some(name(value.bytes()?)?),
            2 => {
                let Value::Fixed32(bits) = value else {
                    return Err(OnnxError::Malformed);
                };
                let value = f32::from_bits(bits);
                if !value.is_finite() {
                    return Err(OnnxError::NonFinite);
                }
                scalar = Some(AttrValue::Float(f64::from(value)));
            }
            3 => scalar = Some(AttrValue::Int(value.integer()? as i64)),
            4 => scalar = Some(AttrValue::String(text(value.bytes()?)?.to_owned())),
            13 => {
                text(value.bytes()?)?;
            }
            20 => ty = Some(value.integer()?),
            _ => return Err(OnnxError::Unsupported),
        }
    }
    if (seen & ((1 << 2) | (1 << 3) | (1 << 4))).count_ones() > 1 {
        return Err(OnnxError::Malformed);
    }
    let value = match (ty, scalar, list_present) {
        (Some(1), Some(v @ AttrValue::Float(_)), false) => v,
        (Some(2), Some(v @ AttrValue::Int(_)), false) => v,
        (Some(3), Some(v @ AttrValue::String(_)), false) => v,
        (Some(7), None, true) => AttrValue::IntList(list),
        _ => return Err(OnnxError::Malformed),
    };
    Ok((id.ok_or(OnnxError::Malformed)?, value))
}
struct SourceNode {
    id: String,
    label: String,
    op: String,
    inputs: Vec<String>,
    outputs: Vec<String>,
    attrs: AttributeMap,
}

fn source_node(bytes: &[u8], ordinal: usize, a: &mut Admission<'_>) -> Result<SourceNode> {
    let mut wire = Wire(bytes);
    let (mut seen, mut op, mut node_name) = (0, None, None);
    let (mut inputs, mut outputs, mut attrs) = (Vec::new(), Vec::new(), AttributeMap::new());
    while let Some((tag, value)) = wire.next(a)? {
        match tag {
            1 => {
                let bytes = value.bytes()?;
                let input = if bytes.is_empty() {
                    String::new()
                } else {
                    name(bytes)?
                };
                push(&mut inputs, input, 256)?;
            }
            2 => push(&mut outputs, name(value.bytes()?)?, 1)?,
            5 => {
                if attrs.len() >= 16 {
                    return Err(OnnxError::Limit);
                }
                let (key, value) = attribute(value.bytes()?, a)?;
                if attrs.insert(key, value).is_some() {
                    return Err(OnnxError::Malformed);
                }
            }
            3 | 4 | 6 | 7 => {
                singular(&mut seen, tag)?;
                match tag {
                    3 => {
                        let bytes = value.bytes()?;
                        if !bytes.is_empty() {
                            node_name = Some(name(bytes)?);
                        }
                    }
                    4 => op = Some(name(value.bytes()?)?),
                    6 => {
                        text(value.bytes()?)?;
                    }
                    7 => {
                        if !value.bytes()?.is_empty() {
                            return Err(OnnxError::Unsupported);
                        }
                    }
                    _ => return Err(OnnxError::Malformed),
                }
            }
            _ => return Err(OnnxError::Unsupported),
        }
    }
    let op = op.ok_or(OnnxError::Malformed)?;
    let id = format!("onnx-node-{ordinal:04}");
    if op != "Gemm" && inputs.iter().any(String::is_empty) {
        return Err(OnnxError::Limit);
    }
    Ok(SourceNode {
        label: node_name.unwrap_or_else(|| id.clone()),
        id,
        op,
        inputs,
        outputs,
        attrs,
    })
}

fn node(source: SourceNode, known: &BTreeMap<String, TensorPort>) -> Result<GraphNode> {
    let SourceNode {
        id,
        label,
        op,
        inputs,
        outputs,
        mut attrs,
    } = source;
    if matches!(op.as_str(), "Identity" | "Flatten") {
        if inputs.len() != 1 || outputs.len() != 1 {
            return Err(OnnxError::Graph);
        }
        let input = known.get(&inputs[0]).ok_or(OnnxError::Graph)?;
        let dims = input.shape().dims();
        let shape = if op == "Identity" {
            if !attrs.is_empty() {
                return Err(OnnxError::Unsupported);
            }
            dims.iter().map(|&n| n as i64).collect()
        } else {
            let axis = match attrs.remove("axis") {
                None => 1,
                Some(AttrValue::Int(axis)) => axis,
                Some(_) => return Err(OnnxError::Graph),
            };
            if !attrs.is_empty() {
                return Err(OnnxError::Unsupported);
            }
            let rank = dims.len() as i64;
            if axis < -rank || axis > rank {
                return Err(OnnxError::Graph);
            }
            let axis = if axis < 0 { axis + rank } else { axis } as usize;
            let product = |dims: &[usize]| -> Result<i64> {
                dims.iter().try_fold(1_i64, |product, &n| {
                    product.checked_mul(n as i64).ok_or(OnnxError::Limit)
                })
            };
            vec![product(&dims[..axis])?, product(&dims[axis..])?]
        };
        let mut lowered = AttributeMap::new();
        lowered.insert("shape".into(), AttrValue::IntList(shape));
        return GraphNode::new(id.clone(), OpCode::Reshape, label, inputs, outputs, lowered)
            .map_err(|_| OnnxError::Graph);
    }
    let opcode = match op.as_str() {
        "Add" => OpCode::Add,
        "Sub" => OpCode::Sub,
        "Mul" => OpCode::Mul,
        "Div" => OpCode::Div,
        "Relu" => OpCode::Relu,
        "Sigmoid" => OpCode::Sigmoid,
        "Tanh" => OpCode::Tanh,
        "MatMul" => OpCode::MatMul,
        "Softmax" => OpCode::Softmax,
        "Conv" => OpCode::Conv2d,
        "MaxPool" => OpCode::MaxPool2d,
        "Transpose" => OpCode::Transpose,
        "Concat" => OpCode::Concat,
        _ => return Err(OnnxError::Unsupported),
    };
    let mut lowered = AttributeMap::new();
    for (key, value) in attrs {
        let target = match (op.as_str(), key.as_str()) {
            ("Conv", "auto_pad") | ("MaxPool", "auto_pad") => {
                if value != AttrValue::String("NOTSET".into()) {
                    return Err(OnnxError::Unsupported);
                }
                continue;
            }
            ("Conv", "kernel_shape") => {
                let shape = value
                    .as_usize_list(&id, "kernel_shape")
                    .map_err(|_| OnnxError::Graph)?;
                let weight = inputs
                    .get(1)
                    .and_then(|name| known.get(name))
                    .ok_or(OnnxError::Graph)?;
                if weight.rank() != 4 || shape != weight.shape().dims()[2..] {
                    return Err(OnnxError::Graph);
                }
                continue;
            }
            ("Conv", "pads") | ("MaxPool", "pads") => "padding",
            ("Conv", "strides") | ("MaxPool", "strides") => "strides",
            ("Conv", "dilations") => "dilations",
            ("Conv", "group") => "groups",
            ("MaxPool", "kernel_shape") => "kernel_size",
            ("MaxPool", "ceil_mode" | "storage_order") => {
                if value != AttrValue::Int(0) {
                    return Err(OnnxError::Unsupported);
                }
                continue;
            }
            ("MaxPool", "dilations") => {
                if value != AttrValue::IntList(vec![1, 1]) {
                    return Err(OnnxError::Unsupported);
                }
                continue;
            }
            ("Transpose", "perm") => "permutation",
            ("Softmax", "axis") | ("Concat", "axis") => "axis",
            _ => return Err(OnnxError::Unsupported),
        };
        if opcode == OpCode::MaxPool2d
            && target == "padding"
            && value != AttrValue::IntList(vec![0, 0, 0, 0])
        {
            return Err(OnnxError::Unsupported);
        }
        lowered.insert(target.to_owned(), value);
    }
    if opcode == OpCode::Concat && !lowered.contains_key("axis") {
        return Err(OnnxError::Malformed);
    }
    GraphNode::new(id.clone(), opcode, label, inputs, outputs, lowered)
        .map_err(|_| OnnxError::Graph)
}

/// One quota/shape admission path for source operators and every generated helper.
struct Lowering<'a, 'c> {
    admission: &'a mut Admission<'c>,
    generation: Generation,
    inputs: Vec<TensorPort>,
    known: BTreeMap<String, TensorPort>,
    parameters: BTreeMap<String, Tensor>,
    parameter_bytes: usize,
    used_parameters: BTreeSet<String>,
    nodes: Vec<GraphNode>,
    reserved: BTreeSet<String>,
}
impl Lowering<'_, '_> {
    fn append(&mut self, node: GraphNode) -> Result<()> {
        let limits = self.admission.limits;
        if self.nodes.len() >= limits.nodes {
            return Err(OnnxError::Limit);
        }
        self.admission
            .charge(1 + self.known.len() + node.inputs().len())?;
        let ports = node
            .inputs()
            .iter()
            .map(|name| {
                if self.parameters.contains_key(name) {
                    self.used_parameters.insert(name.clone());
                }
                self.known.get(name).ok_or(OnnxError::Graph)
            })
            .collect::<Result<Vec<_>>>()?;
        if node.op() == OpCode::MatMul && ports.iter().any(|p| p.rank() < 2) {
            return Err(OnnxError::Unsupported);
        }
        let inferred = crate::infer_operator_outputs(
            node.id(),
            node.op(),
            &ports,
            node.outputs(),
            node.attributes(),
            self.generation,
        )
        .map_err(|_| OnnxError::Graph)?;
        for output in inferred {
            if output
                .shape()
                .size_bytes(DType::F32)
                .map_err(|_| OnnxError::Limit)?
                > limits.tensor_bytes
                || output.shape().dims().contains(&0)
                || self.known.len() >= limits.tensors
            {
                return Err(OnnxError::Limit);
            }
            if self
                .known
                .insert(output.name().to_owned(), output)
                .is_some()
            {
                return Err(OnnxError::Graph);
            }
        }
        push(&mut self.nodes, node, limits.nodes)
    }
}

fn reserve_name(reserved: &mut BTreeSet<String>, name: &str, a: &mut Admission<'_>) -> Result<()> {
    a.charge(1)?;
    if !name.is_empty() && !reserved.contains(name) {
        if reserved.len() >= a.limits.tensors {
            return Err(OnnxError::Limit);
        }
        reserved.insert(name.to_owned());
    }
    Ok(())
}

fn opset(bytes: &[u8], a: &mut Admission<'_>) -> Result<()> {
    let mut wire = Wire(bytes);
    let (mut seen, mut version) = (0, None);
    while let Some((tag, value)) = wire.next(a)? {
        singular(&mut seen, tag)?;
        match tag {
            1 => {
                if !value.bytes()?.is_empty() {
                    return Err(OnnxError::Unsupported);
                }
            }
            2 => version = Some(value.integer()?),
            _ => return Err(OnnxError::Unsupported),
        }
    }
    if version != Some(13) {
        return Err(OnnxError::Unsupported);
    }
    Ok(())
}

/// Import an exact ONNX source into native graph/parameters, without executing it.
///
/// Only default-domain opset 13 is accepted. Runtime inputs and initializers must be
/// disjoint: this API does not silently freeze an overridable ONNX graph input.
/// Every declared output/intermediate is checked against native shape inference.
/// Unused initializers, duplicate outputs, forward references and custom facilities refuse.
/// Gemm expands into bounded native transpose/matmul/multiply/add nodes and scalar parameters.
/// Source names are reserved before expansion; no helper can alias any source tensor.
/// The cancellation probe is checked throughout bounded wire and tensor traversal.
/// Original Model IR v1 encodings and operator freeze IDs remain unchanged.
pub fn import_onnx<'a>(
    source: &'a [u8],
    expected: ContentDigest,
    generation: Generation,
    limits: OnnxLimits,
    cancelled: &dyn Fn() -> bool,
) -> Result<ImportedOnnx<'a>> {
    if source.is_empty()
        || source.len() > limits.source_bytes
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
    let mut a = Admission {
        limits,
        used: 0,
        cancelled,
    };
    a.charge(source.len())?;
    let mut hasher = Sha256Hasher::new();
    for chunk in source.chunks(64 * 1024) {
        a.charge(0)?;
        hasher.update(chunk);
    }
    let observed = ContentDigest::new(
        DigestAlgorithm::Sha256,
        hasher.finalize().map_err(|_| OnnxError::Limit)?,
    );
    if observed != expected {
        return Err(OnnxError::Digest);
    }
    let mut wire = Wire(source);
    let (mut seen, mut ir_version, mut graph_bytes) = (0, None, None);
    while let Some((tag, value)) = wire.next(&mut a)? {
        singular(&mut seen, tag)?;
        match tag {
            1 => ir_version = Some(value.integer()?),
            2 | 3 | 4 | 6 => {
                text(value.bytes()?)?;
            }
            5 => {
                value.integer()?;
            }
            7 => graph_bytes = Some(value.bytes()?),
            8 => opset(value.bytes()?, &mut a)?,
            _ => return Err(OnnxError::Unsupported),
        }
    }
    if !matches!(ir_version, Some(7..=9)) || seen & (1 << 8) == 0 {
        return Err(OnnxError::Unsupported);
    }
    let mut wire = Wire(graph_bytes.ok_or(OnnxError::Malformed)?);
    let (mut seen, mut graph_name) = (0, "onnx-graph".to_owned());
    let (mut node_sources, mut inputs, mut outputs, mut declared) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut initializers = Vec::new();
    let mut parameter_bytes = 0_usize;
    let mut declarations = 0_usize;
    while let Some((tag, value)) = wire.next(&mut a)? {
        match tag {
            1 => {
                push(&mut node_sources, value.bytes()?, limits.nodes)?;
            }
            2 | 10 => {
                singular(&mut seen, tag)?;
                if tag == 2 {
                    graph_name = name(value.bytes()?)?;
                } else {
                    text(value.bytes()?)?;
                }
            }
            5 | 11 | 12 | 13 => {
                declarations = declarations.checked_add(1).ok_or(OnnxError::Limit)?;
                if declarations > limits.tensors {
                    return Err(OnnxError::Limit);
                }
                let bytes = value.bytes()?;
                if tag == 5 {
                    let remaining = limits.parameter_bytes.saturating_sub(parameter_bytes);
                    a.limits.parameter_bytes = remaining;
                    let pair = initializer(bytes, generation, &mut a)?;
                    a.limits.parameter_bytes = limits.parameter_bytes;
                    parameter_bytes = parameter_bytes
                        .checked_add(
                            pair.0
                                .shape()
                                .size_bytes(DType::F32)
                                .map_err(|_| OnnxError::Limit)?,
                        )
                        .ok_or(OnnxError::Limit)?;
                    push(&mut initializers, pair, limits.tensors)?;
                } else {
                    let parsed = value_info(bytes, generation, &mut a)?;
                    let target = match tag {
                        11 => &mut inputs,
                        12 => &mut outputs,
                        _ => &mut declared,
                    };
                    push(target, parsed, limits.tensors)?;
                }
            }
            _ => return Err(OnnxError::Unsupported),
        }
    }
    if outputs.is_empty() {
        return Err(OnnxError::Malformed);
    }
    let runtime_inputs = inputs.iter().map(|p| p.name().to_owned()).collect();
    let mut parameters = BTreeMap::new();
    for (port, tensor) in initializers {
        if parameters.insert(port.name().to_owned(), tensor).is_some() {
            return Err(OnnxError::Malformed);
        }
        push(&mut inputs, port, limits.tensors)?;
    }
    let mut known = BTreeMap::new();
    for input in &inputs {
        if known
            .insert(input.name().to_owned(), input.clone())
            .is_some()
        {
            return Err(OnnxError::Malformed);
        }
    }
    // Reserve all source tensor names, including future uses and type annotations,
    // before generating helpers. A helper must never turn a missing source value
    // into a valid input or accidentally satisfy an output/type declaration.
    let mut reserved = BTreeSet::new();
    for port in inputs.iter().chain(&outputs).chain(&declared) {
        reserve_name(&mut reserved, port.name(), &mut a)?;
    }
    let mut sources = Vec::new();
    for (ordinal, source) in node_sources.into_iter().enumerate() {
        let parsed = source_node(source, ordinal, &mut a)?;
        for name in parsed.inputs.iter().chain(&parsed.outputs) {
            reserve_name(&mut reserved, name, &mut a)?;
        }
        push(&mut sources, parsed, limits.nodes)?;
    }
    let mut lowering = Lowering {
        admission: &mut a,
        generation,
        inputs,
        known,
        parameters,
        parameter_bytes,
        used_parameters: BTreeSet::new(),
        nodes: Vec::new(),
        reserved,
    };
    for source in sources {
        if source.op == "Gemm" {
            gemm::lower(source, &mut lowering)?;
        } else {
            let node = node(source, &lowering.known)?;
            lowering.append(node)?;
        }
    }
    let Lowering {
        inputs,
        known,
        parameters,
        mut used_parameters,
        nodes,
        ..
    } = lowering;
    for output in &outputs {
        if parameters.contains_key(output.name()) {
            used_parameters.insert(output.name().to_owned());
        }
    }
    // Value-info annotations are type witnesses, not uses of an initializer.
    // The same value may occur in both lists, but cannot repeat inside either list.
    for declarations in [&outputs, &declared] {
        let mut output_names = BTreeSet::new();
        for output in declarations {
            a.charge(1)?;
            if !output_names.insert(output.name()) {
                return Err(OnnxError::Malformed);
            }
            if known.get(output.name()) != Some(output) {
                return Err(OnnxError::Graph);
            }
        }
    }
    if used_parameters.len() != parameters.len() {
        return Err(OnnxError::Graph);
    }
    // Reserve bounded native graph validation work before invoking the existing validator.
    a.charge(
        nodes
            .len()
            .checked_mul(nodes.len() + inputs.len() + 1)
            .ok_or(OnnxError::Limit)?,
    )?;
    let graph = ModelIrGraph::new_validated(
        graph_name,
        ModelIrVersion::V1,
        generation,
        inputs,
        outputs,
        nodes,
    )
    .map_err(|_| OnnxError::Graph)?;
    a.charge(0)?;
    Ok(ImportedOnnx {
        source,
        source_digest: expected,
        graph,
        parameters,
        runtime_inputs,
        work: a.used,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    type Test = std::result::Result<(), Box<dyn std::error::Error>>;
    fn vi(mut n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let b = (n & 127) as u8;
            n >>= 7;
            out.push(b | if n != 0 { 128 } else { 0 });
            if n == 0 {
                return out;
            }
        }
    }
    fn bytes(tag: u64, value: &[u8]) -> Vec<u8> {
        let mut out = vi(tag * 8 + 2);
        out.extend(vi(value.len() as u64));
        out.extend(value);
        out
    }
    fn int(tag: u64, value: u64) -> Vec<u8> {
        let mut out = vi(tag * 8);
        out.extend(vi(value));
        out
    }
    fn info(id: &str, dims: &[u64]) -> Vec<u8> {
        let shape: Vec<u8> = dims.iter().flat_map(|&n| bytes(1, &int(1, n))).collect();
        let tensor = [int(1, 1), bytes(2, &shape)].concat();
        [bytes(1, id.as_bytes()), bytes(2, &bytes(1, &tensor))].concat()
    }
    fn source(op: &str, initializer_suffix: &[u8]) -> Vec<u8> {
        let tensor = [
            int(1, 2),
            int(2, 1),
            bytes(8, b"bias"),
            bytes(
                9,
                &[(-0.0_f32).to_le_bytes(), 2.0_f32.to_le_bytes()].concat(),
            ),
            initializer_suffix.to_vec(),
        ]
        .concat();
        let node = [
            bytes(1, b"x"),
            bytes(1, b"bias"),
            bytes(2, b"y"),
            bytes(4, op.as_bytes()),
        ]
        .concat();
        let graph = [
            bytes(1, &node),
            bytes(2, b"test"),
            bytes(5, &tensor),
            bytes(11, &info("x", &[1, 2])),
            bytes(12, &info("y", &[1, 2])),
        ]
        .concat();
        [int(1, 8), bytes(8, &int(2, 13)), bytes(7, &graph)].concat()
    }
    #[test]
    fn source_graph_parameters_and_signed_zero_are_preserved() -> Test {
        let source = source("Add", &[]);
        let imported = import_onnx(
            &source,
            ContentDigest::sha256(&source),
            Generation(1),
            OnnxLimits::default(),
            &|| false,
        )?;
        assert_eq!(imported.source(), source);
        assert_eq!(imported.runtime_inputs(), ["x"]);
        assert_eq!(imported.graph().nodes()[0].op(), OpCode::Add);
        let values = imported
            .parameters()
            .get("bias")
            .ok_or("missing parameter")?
            .to_vec::<f32>()?;
        assert_eq!(values[0].to_bits(), (-0.0_f32).to_bits());
        assert_eq!(values[1], 2.0);
        Ok(())
    }
    #[test]
    fn unsupported_operator_and_external_weights_refuse() {
        for input in [source("Custom", &[]), source("Add", &int(14, 1))] {
            assert!(matches!(
                import_onnx(
                    &input,
                    ContentDigest::sha256(&input),
                    Generation(1),
                    OnnxLimits::default(),
                    &|| false
                ),
                Err(OnnxError::Unsupported)
            ));
        }
    }
    #[test]
    fn wrong_digest_cancellation_and_zero_work_refuse() {
        let input = source("Add", &[]);
        let digest = ContentDigest::sha256(&input);
        assert!(matches!(
            import_onnx(
                &input,
                ContentDigest::sha256(b"wrong"),
                Generation(1),
                OnnxLimits::default(),
                &|| false
            ),
            Err(OnnxError::Digest)
        ));
        assert!(matches!(
            import_onnx(
                &input,
                digest,
                Generation(1),
                OnnxLimits::default(),
                &|| true
            ),
            Err(OnnxError::Cancelled)
        ));
        let limits = OnnxLimits {
            work_units: 0,
            ..OnnxLimits::default()
        };
        assert!(matches!(
            import_onnx(&input, digest, Generation(1), limits, &|| false),
            Err(OnnxError::WorkBudget)
        ));
    }
    #[test]
    fn truncated_and_duplicate_model_fields_never_produce_a_graph() {
        let valid = source("Add", &[]);
        for end in 0..valid.len() {
            let input = &valid[..end];
            assert!(
                import_onnx(
                    input,
                    ContentDigest::sha256(input),
                    Generation(1),
                    OnnxLimits::default(),
                    &|| false
                )
                .is_err()
            );
        }
        let input = [valid, int(1, 8)].concat();
        assert!(matches!(
            import_onnx(
                &input,
                ContentDigest::sha256(&input),
                Generation(1),
                OnnxLimits::default(),
                &|| false
            ),
            Err(OnnxError::Malformed)
        ));
    }
    #[test]
    fn overflowing_varints_and_lengths_are_rejected_without_panicking() {
        for input in [
            vec![0xff; 11],
            vec![0x3a, 0xff, 0xff, 0xff, 0xff, 0x7f],
            vec![0],
        ] {
            assert!(
                import_onnx(
                    &input,
                    ContentDigest::sha256(&input),
                    Generation(1),
                    OnnxLimits::default(),
                    &|| false
                )
                .is_err()
            );
        }
    }

    fn wrap_graph(graph: &[u8]) -> Vec<u8> {
        [int(1, 8), bytes(8, &int(2, 13)), bytes(7, graph)].concat()
    }
    fn tensor(id: &str, dims: &[u64], values: &[f32]) -> Vec<u8> {
        [
            dims.iter().flat_map(|&n| int(1, n)).collect::<Vec<_>>(),
            int(2, 1),
            bytes(8, id.as_bytes()),
            bytes(
                9,
                &values
                    .iter()
                    .flat_map(|n| n.to_le_bytes())
                    .collect::<Vec<_>>(),
            ),
        ]
        .concat()
    }
    #[test]
    fn flatten_and_identity_lower_to_checked_native_reshapes() -> Test {
        for (op, axis, dims) in [
            ("Flatten", 1_i64, vec![2, 12]),
            ("Flatten", -1, vec![6, 4]),
            ("Flatten", 0, vec![1, 24]),
            ("Flatten", 3, vec![24, 1]),
            ("Identity", 0, vec![2, 3, 4]),
        ] {
            let attributes = if op == "Identity" {
                vec![]
            } else {
                bytes(
                    5,
                    &[bytes(1, b"axis"), int(3, axis as u64), int(20, 2)].concat(),
                )
            };
            let node = [
                bytes(1, b"x"),
                bytes(2, b"y"),
                bytes(4, op.as_bytes()),
                attributes,
            ]
            .concat();
            let source = wrap_graph(
                &[
                    bytes(1, &node),
                    bytes(11, &info("x", &[2, 3, 4])),
                    bytes(12, &info("y", &dims)),
                ]
                .concat(),
            );
            let imported = import_onnx(
                &source,
                ContentDigest::sha256(&source),
                Generation(1),
                OnnxLimits::default(),
                &|| false,
            )?;
            assert_eq!(imported.graph().nodes()[0].op(), OpCode::Reshape);
            assert_eq!(
                imported.graph().outputs()[0].shape().dims(),
                dims.iter().map(|&n| n as usize).collect::<Vec<_>>()
            );
        }
        Ok(())
    }
    #[test]
    fn flatten_does_not_clamp_an_out_of_range_axis() {
        for axis in [-4_i64, 4, i64::MIN, i64::MAX] {
            let attr = [bytes(1, b"axis"), int(3, axis as u64), int(20, 2)].concat();
            let node = [
                bytes(1, b"x"),
                bytes(2, b"y"),
                bytes(4, b"Flatten"),
                bytes(5, &attr),
            ]
            .concat();
            let source = wrap_graph(
                &[
                    bytes(1, &node),
                    bytes(11, &info("x", &[2, 3, 4])),
                    bytes(12, &info("y", &[2, 12])),
                ]
                .concat(),
            );
            assert!(matches!(
                import_onnx(
                    &source,
                    ContentDigest::sha256(&source),
                    Generation(1),
                    OnnxLimits::default(),
                    &|| false
                ),
                Err(OnnxError::Graph)
            ));
        }
    }
    #[test]
    fn conv_kernel_shape_is_checked_against_the_actual_initializer() -> Test {
        for size in [1, 2] {
            let attr = [
                bytes(1, b"kernel_shape"),
                bytes(8, &[size, size]),
                int(20, 7),
            ]
            .concat();
            let node = [
                bytes(1, b"x"),
                bytes(1, b"w"),
                bytes(2, b"y"),
                bytes(4, b"Conv"),
                bytes(5, &attr),
            ]
            .concat();
            let source = wrap_graph(
                &[
                    bytes(1, &node),
                    bytes(5, &tensor("w", &[1, 1, 1, 1], &[2.])),
                    bytes(11, &info("x", &[1, 1, 2, 2])),
                    bytes(12, &info("y", &[1, 1, 2, 2])),
                ]
                .concat(),
            );
            let result = import_onnx(
                &source,
                ContentDigest::sha256(&source),
                Generation(1),
                OnnxLimits::default(),
                &|| false,
            );
            if size == 1 {
                result?;
            } else {
                assert!(matches!(result, Err(OnnxError::Graph)));
            }
        }
        Ok(())
    }
    #[test]
    fn value_info_is_not_a_use_of_an_unreferenced_initializer() {
        let node = [bytes(1, b"x"), bytes(2, b"y"), bytes(4, b"Relu")].concat();
        let source = wrap_graph(
            &[
                bytes(1, &node),
                bytes(5, &tensor("unused", &[1], &[1.])),
                bytes(11, &info("x", &[1])),
                bytes(12, &info("y", &[1])),
                bytes(13, &info("unused", &[1])),
            ]
            .concat(),
        );
        assert!(matches!(
            import_onnx(
                &source,
                ContentDigest::sha256(&source),
                Generation(1),
                OnnxLimits::default(),
                &|| false
            ),
            Err(OnnxError::Graph)
        ));
    }
    #[test]
    fn matching_output_value_info_is_permitted_but_duplicate_outputs_are_not() -> Test {
        let node = [bytes(1, b"x"), bytes(2, b"y"), bytes(4, b"Relu")].concat();
        let graph = [
            bytes(1, &node),
            bytes(11, &info("x", &[1])),
            bytes(12, &info("y", &[1])),
        ]
        .concat();
        for tag in [12, 13] {
            let source = wrap_graph(&[graph.clone(), bytes(tag, &info("y", &[1]))].concat());
            let result = import_onnx(
                &source,
                ContentDigest::sha256(&source),
                Generation(1),
                OnnxLimits::default(),
                &|| false,
            );
            if tag == 13 {
                result?;
            } else {
                assert!(matches!(result, Err(OnnxError::Malformed)));
            }
        }
        Ok(())
    }
    #[test]
    fn large_source_hashing_has_cancellation_boundaries() {
        use std::cell::Cell;
        let source = vec![0; 131_072];
        let calls = Cell::new(0);
        let cancelled = || {
            calls.set(calls.get() + 1);
            calls.get() == 3
        };
        assert!(matches!(
            import_onnx(
                &source,
                ContentDigest::sha256(&source),
                Generation(1),
                OnnxLimits::default(),
                &cancelled
            ),
            Err(OnnxError::Cancelled)
        ));
        assert_eq!(calls.get(), 3);
    }
    #[test]
    fn bounded_generated_wire_inputs_refuse_without_panicking() {
        let mut state = 0x853c_49e6_748f_ea9b_u64;
        for length in 0..128 {
            for _ in 0..8 {
                let input: Vec<_> = (0..length)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        state as u8
                    })
                    .collect();
                assert!(
                    import_onnx(
                        &input,
                        ContentDigest::sha256(&input),
                        Generation(1),
                        OnnxLimits::default(),
                        &|| false
                    )
                    .is_err()
                );
            }
        }
    }
}
