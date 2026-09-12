//! Canonical encoding and content digest computation for Model IR v1 graphs.

use alloc::vec::Vec;

use fss_core::{ContentDigest, DigestAlgorithm, Sha256Hasher};

use crate::attribute::AttrValue;
use crate::error::ModelIrError;
use crate::graph::ModelIrGraph;
use crate::node::GraphNode;
use crate::port::TensorPort;

/// Registered digest domain tag for Model IR v1 graphs from `registries/DIGEST_DOMAINS.md`.
pub const MODEL_IR_DIGEST_DOMAIN: &[u8] = b"fss.model_ir.v1\0";

/// Encodes a `ModelIrGraph` into a deterministic, canonical byte representation.
#[must_use]
pub fn encode_canonical_model_ir(graph: &ModelIrGraph) -> Vec<u8> {
    let mut buf = Vec::new();

    // Domain tag
    buf.extend_from_slice(MODEL_IR_DIGEST_DOMAIN);

    // Version
    buf.extend_from_slice(&graph.version().as_u32().to_be_bytes());

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

    // Nodes count and elements
    buf.extend_from_slice(&(graph.nodes().len() as u32).to_be_bytes());
    for node in graph.nodes() {
        encode_node(&mut buf, node);
    }

    buf
}

/// Computes the deterministic SHA-256 content digest for a `ModelIrGraph`.
///
/// # Errors
/// Returns [`ModelIrError::CoreError`] if the SHA-256 hasher encounters message length overflow.
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

    // Attributes (ordered by key from BTreeMap)
    buf.extend_from_slice(&(node.attributes().len() as u32).to_be_bytes());
    for (k, v) in node.attributes() {
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
            buf.extend_from_slice(&f.to_bits().to_be_bytes());
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
                buf.extend_from_slice(&item.to_bits().to_be_bytes());
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
