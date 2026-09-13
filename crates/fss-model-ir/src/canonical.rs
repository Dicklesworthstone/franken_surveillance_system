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
#[must_use]
pub fn encode_canonical_model_ir(graph: &ModelIrGraph) -> Vec<u8> {
    let mut buf = Vec::new();

    // Domain tag
    buf.extend_from_slice(MODEL_IR_DIGEST_DOMAIN);

    // Version
    let version_code = match graph.version() {
        ModelIrVersion::V1 => 1u32,
        ModelIrVersion::Unsupported(1) => 0u32,
        ModelIrVersion::Unsupported(v) => {
            if v == 0 {
                u32::MAX
            } else {
                0x8000_0000 | v
            }
        }
    };
    buf.extend_from_slice(&version_code.to_be_bytes());

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
        producer_map.insert(input.name(), "graph_input");
    }
    for node in graph.nodes() {
        for out_name in node.outputs() {
            producer_map.insert(out_name.as_str(), node.id());
        }
    }

    let sorted_nodes: Vec<&GraphNode> =
        if let Ok(topo) = GraphValidator::topological_sort(graph, &producer_map) {
            topo
        } else {
            let mut nodes: Vec<&GraphNode> = graph.nodes().iter().collect();
            nodes.sort_by_key(|n| n.id());
            nodes
        };

    // Nodes count and elements
    buf.extend_from_slice(&(sorted_nodes.len() as u32).to_be_bytes());
    for node in sorted_nodes {
        encode_node(&mut buf, node);
    }

    buf
}

/// Computes the deterministic SHA-256 content digest for a `ModelIrGraph`.
///
/// # Errors
/// Returns [`ModelIrError`] if the SHA-256 hasher encounters message length overflow.
pub fn compute_model_ir_digest(graph: &ModelIrGraph) -> Result<ContentDigest, ModelIrError> {
    let canonical_bytes = encode_canonical_model_ir(graph);
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
) -> crate::attribute::AttributeMap {
    let mut norm = attrs.clone();
    match op {
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
        OpCode::MaxPool2d => {
            norm.entry("padding".to_string())
                .or_insert_with(|| AttrValue::IntList(vec![0, 0, 0, 0]));
            norm.entry("strides".to_string())
                .or_insert_with(|| AttrValue::IntList(vec![1, 1]));
        }
        OpCode::LayerNorm | OpCode::RMSNorm => {
            norm.entry("epsilon".to_string())
                .or_insert_with(|| AttrValue::Float(1e-5));
        }
        _ => {}
    }
    norm
}

fn encode_node(buf: &mut Vec<u8>, node: &GraphNode) {
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
    let normalized = normalize_attributes(node.op(), node.attributes());
    buf.extend_from_slice(&(normalized.len() as u32).to_be_bytes());
    for (k, v) in &normalized {
        encode_str(buf, k);
        encode_attr_value(buf, v);
    }
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
