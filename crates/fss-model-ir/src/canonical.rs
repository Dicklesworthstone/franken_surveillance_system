//! Canonical encoding and content digest computation for Model IR v1 graphs.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use fss_core::{ContentDigest, DigestAlgorithm, Sha256Hasher};

use crate::attribute::AttrValue;
use crate::error::ModelIrError;
use crate::graph::{ModelIrGraph, ModelIrVersion};
use crate::node::GraphNode;
use crate::op::OpCode;
use crate::port::TensorPort;
use crate::validator::GraphValidator;

/// Registered digest domain tag for Model IR v1 graphs from `registries/DIGEST_DOMAINS.md`.
pub const MODEL_IR_DIGEST_DOMAIN: &[u8] = b"fss.model_ir.v1\0";

/// Encodes a `ModelIrGraph` into a deterministic, canonical byte representation.
///
/// Nodes are ordered in deterministic topological order with stable tie-breaking on `node.id()`.
/// Default operator attributes are normalized so that explicit and implicit defaults encode identically.
/// Floating point values are canonicalized (-0.0 -> +0.0).
/// Encodes a `ModelIrGraph` into a deterministic, canonical byte representation.
///
/// Nodes are ordered in deterministic topological order with stable tie-breaking on `node.id()`.
/// Default operator attributes are normalized so that explicit and implicit defaults encode identically.
/// Floating point values are canonicalized (-0.0 -> +0.0).
///
/// # Errors
/// Returns [`ModelIrError`] if graph validation fails or arithmetic overflow occurs.
pub fn encode_canonical_model_ir(graph: &ModelIrGraph) -> Result<Vec<u8>, ModelIrError> {
    graph.validate()?;

    let mut buf = Vec::new();

    // Domain tag
    buf.extend_from_slice(MODEL_IR_DIGEST_DOMAIN);

    // Version with distinct tags: Tag 1 for V1, Tag 2 for Unsupported(v)
    match graph.version() {
        ModelIrVersion::V1 => {
            buf.push(1);
            buf.extend_from_slice(&1u32.to_be_bytes());
        }
        ModelIrVersion::Unsupported(v) => {
            buf.push(2);
            buf.extend_from_slice(&v.to_be_bytes());
        }
    }

    // Operator table freeze digest binding
    let op_table_digest = crate::op::compute_operator_table_digest()?;
    buf.extend_from_slice(&op_table_digest.bytes());

    // Graph ID
    encode_str(&mut buf, graph.id());

    // Model Generation
    buf.extend_from_slice(&graph.generation().get().to_be_bytes());

    // Inputs count and elements
    buf.extend_from_slice(&(graph.inputs().len() as u32).to_be_bytes());
    for input in graph.inputs() {
        encode_port(&mut buf, input);
    }

    // Outputs count and elements
    buf.extend_from_slice(&(graph.outputs().len() as u32).to_be_bytes());
    for output in graph.outputs() {
        encode_port(&mut buf, output);
    }

    // Canonical topological ordering with stable tie-break
    let mut producer_map = BTreeMap::new();
    for input in graph.inputs() {
        producer_map.insert(input.name(), crate::validator::ProducerId::GraphInput);
    }
    for node in graph.nodes() {
        for out_name in node.outputs() {
            producer_map.insert(
                out_name.as_str(),
                crate::validator::ProducerId::Node(node.id()),
            );
        }
    }

    let sorted_nodes = GraphValidator::topological_sort(graph, &producer_map)?;

    let mut env: BTreeMap<String, TensorPort> = BTreeMap::new();
    for input in graph.inputs() {
        env.insert(input.name().to_string(), input.clone());
    }

    // Nodes count and elements
    buf.extend_from_slice(&(sorted_nodes.len() as u32).to_be_bytes());
    for node in sorted_nodes {
        let mut input_ports = Vec::with_capacity(node.inputs().len());
        for in_name in node.inputs() {
            if let Some(p) = env.get(in_name) {
                input_ports.push(p.clone());
            }
        }
        let input_refs: Vec<&TensorPort> = input_ports.iter().collect();
        let output_ports = crate::shape_inference::infer_operator_outputs(
            node.id(),
            node.op(),
            &input_refs,
            node.outputs(),
            node.attributes(),
            graph.generation(),
        )?;
        encode_node(&mut buf, node, &input_ports);
        for out_port in output_ports {
            env.insert(out_port.name().to_string(), out_port);
        }
    }

    Ok(buf)
}

/// Computes the deterministic SHA-256 content digest for a `ModelIrGraph`.
///
/// # Errors
/// Returns [`ModelIrError`] if the graph fails validation or the SHA-256 hasher encounters message length overflow.
pub fn compute_model_ir_digest(graph: &ModelIrGraph) -> Result<ContentDigest, ModelIrError> {
    let canonical_bytes = encode_canonical_model_ir(graph)?;
    let mut hasher = Sha256Hasher::new();
    hasher.update(&canonical_bytes);
    let digest_bytes = hasher
        .finalize()
        .map_err(|_| ModelIrError::ArithmeticOverflow {
            operation: "SHA-256 digest computation message length",
        })?;
    Ok(ContentDigest::new(DigestAlgorithm::Sha256, digest_bytes))
}

fn encode_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn encode_port(buf: &mut Vec<u8>, port: &TensorPort) {
    encode_str(buf, port.name());
    buf.push(port.dtype().type_tag());
    buf.extend_from_slice(&port.generation().get().to_be_bytes());
    buf.extend_from_slice(&(port.rank() as u32).to_be_bytes());
    for &dim in port.shape().dims() {
        buf.extend_from_slice(&(dim as u64).to_be_bytes());
    }
}

fn normalize_attributes(
    op: OpCode,
    attrs: &crate::attribute::AttributeMap,
    inputs: &[TensorPort],
) -> crate::attribute::AttributeMap {
    let mut norm = attrs.clone();
    match op {
        OpCode::Softmax => {
            if !inputs.is_empty() {
                let rank = inputs[0].rank();
                norm.entry("axis".to_string())
                    .or_insert_with(|| AttrValue::Int(rank.saturating_sub(1) as i64));
            }
        }
        OpCode::Transpose => {
            if !inputs.is_empty() {
                let rank = inputs[0].rank();
                norm.entry("permutation".to_string()).or_insert_with(|| {
                    let rev: Vec<i64> = (0..rank).rev().map(|x| x as i64).collect();
                    AttrValue::IntList(rev)
                });
            }
        }
        OpCode::Slice => {
            let starts_len = match norm.get("starts") {
                Some(AttrValue::IntList(list)) => list.len(),
                _ => 0,
            };
            if starts_len > 0 {
                norm.entry("axes".to_string()).or_insert_with(|| {
                    let axes: Vec<i64> = (0..starts_len).map(|x| x as i64).collect();
                    AttrValue::IntList(axes)
                });
                norm.entry("steps".to_string())
                    .or_insert_with(|| AttrValue::IntList(vec![1; starts_len]));
            }
        }
        OpCode::MaxPool2d => {
            norm.entry("ceil_mode".to_string())
                .or_insert_with(|| AttrValue::Bool(false));
            norm.entry("padding".to_string())
                .or_insert_with(|| AttrValue::IntList(vec![0, 0, 0, 0]));
            norm.entry("strides".to_string())
                .or_insert_with(|| AttrValue::IntList(vec![1, 1]));
        }
        OpCode::Gelu => {
            norm.entry("approximate".to_string())
                .or_insert_with(|| AttrValue::String("none".to_string()));
        }
        OpCode::Reshape => {
            if let Some(AttrValue::Shape(shape)) = norm.get("shape") {
                let int_list: Vec<i64> = shape.dims().iter().map(|&d| d as i64).collect();
                norm.insert("shape".to_string(), AttrValue::IntList(int_list));
            }
            norm.entry("allowzero".to_string())
                .or_insert_with(|| AttrValue::Bool(false));
        }
        OpCode::LayerNorm => {
            norm.entry("epsilon".to_string())
                .or_insert_with(|| AttrValue::Float(1e-5));
            norm.entry("elementwise_affine".to_string())
                .or_insert_with(|| AttrValue::Bool(true));
            norm.entry("scale".to_string())
                .or_insert_with(|| AttrValue::Bool(true));
            norm.entry("bias".to_string())
                .or_insert_with(|| AttrValue::Bool(true));
        }
        OpCode::RMSNorm => {
            norm.entry("epsilon".to_string())
                .or_insert_with(|| AttrValue::Float(1e-5));
            norm.entry("elementwise_affine".to_string())
                .or_insert_with(|| AttrValue::Bool(true));
            norm.entry("scale".to_string())
                .or_insert_with(|| AttrValue::Bool(true));
        }
        OpCode::Conv2d => {
            norm.entry("dilations".to_string())
                .or_insert_with(|| AttrValue::IntList(vec![1, 1]));
            norm.entry("groups".to_string())
                .or_insert_with(|| AttrValue::Int(1));
            norm.entry("padding".to_string())
                .or_insert_with(|| AttrValue::IntList(vec![0, 0, 0, 0]));
            norm.entry("strides".to_string())
                .or_insert_with(|| AttrValue::IntList(vec![1, 1]));
        }
        _ => {}
    }
    norm
}

fn encode_node(buf: &mut Vec<u8>, node: &GraphNode, inputs: &[TensorPort]) {
    encode_str(buf, node.id());
    encode_str(buf, node.op().stable_id());
    encode_str(buf, node.name());

    // Inputs
    buf.extend_from_slice(&(node.inputs().len() as u32).to_be_bytes());
    for input_name in node.inputs() {
        encode_str(buf, input_name);
    }

    // Outputs
    buf.extend_from_slice(&(node.outputs().len() as u32).to_be_bytes());
    for output_name in node.outputs() {
        encode_str(buf, output_name);
    }

    // Attributes (normalized for defaults, ordered by key in BTreeMap)
    let normalized = normalize_attributes(node.op(), node.attributes(), inputs);
    buf.extend_from_slice(&(normalized.len() as u32).to_be_bytes());
    for (k, v) in &normalized {
        encode_str(buf, k);
        encode_attr_value(buf, v);
    }
}

/// Encodes an attribute value into its canonical byte representation.
#[must_use]
pub fn encode_canonical_attr_value(val: &AttrValue) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_attr_value(&mut buf, val);
    buf
}

fn encode_attr_value(buf: &mut Vec<u8>, val: &AttrValue) {
    match val {
        AttrValue::Bool(b) => {
            buf.push(1);
            buf.push(if *b { 1 } else { 0 });
        }
        AttrValue::Int(i) => {
            buf.push(2);
            buf.extend_from_slice(&i.to_be_bytes());
        }
        AttrValue::Float(f) => {
            buf.push(3);
            let canonical_f = if *f == 0.0 { 0.0f64 } else { *f };
            buf.extend_from_slice(&canonical_f.to_bits().to_be_bytes());
        }
        AttrValue::String(s) => {
            buf.push(4);
            encode_str(buf, s);
        }
        AttrValue::IntList(list) => {
            buf.push(5);
            buf.extend_from_slice(&(list.len() as u32).to_be_bytes());
            for &item in list {
                buf.extend_from_slice(&item.to_be_bytes());
            }
        }
        AttrValue::FloatList(list) => {
            buf.push(6);
            buf.extend_from_slice(&(list.len() as u32).to_be_bytes());
            for &item in list {
                let canonical_item = if item == 0.0 { 0.0f64 } else { item };
                buf.extend_from_slice(&canonical_item.to_bits().to_be_bytes());
            }
        }
        AttrValue::DType(dt) => {
            buf.push(7);
            buf.push(dt.type_tag());
        }
        AttrValue::Shape(shape) => {
            buf.push(8);
            buf.extend_from_slice(&(shape.rank() as u32).to_be_bytes());
            for &dim in shape.dims() {
                buf.extend_from_slice(&(dim as u64).to_be_bytes());
            }
        }
    }
}
