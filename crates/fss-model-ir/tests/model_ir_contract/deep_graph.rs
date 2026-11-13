//! Depth and canonical-order regressions for the Model IR graph validator.
//!
//! Ref: fss-x4a.14.8 / FSS-137

#![forbid(unsafe_code)]

use std::error::Error;
use std::mem::size_of;

use fss_core::{ContentDigest, Generation};
use fss_model_ir::{
    AttributeMap, GraphNode, MAX_MODEL_IR_ITEMS, ModelIrDecodeError, ModelIrError, ModelIrGraph,
    ModelIrVersion, OpCode, TensorPort, decode_canonical_model_ir, encode_canonical_model_ir,
};
use fss_tensor::{DType, Shape};

type TestResult = Result<(), Box<dyn Error>>;

fn port(name: &str) -> Result<TensorPort, Box<dyn Error>> {
    Ok(TensorPort::new(
        name,
        DType::F32,
        Shape::new(vec![1])?,
        Generation::from_u64(1),
    )?)
}

fn operator(
    id: &str,
    op: OpCode,
    inputs: &[&str],
    output: &str,
) -> Result<GraphNode, ModelIrError> {
    GraphNode::new(
        id,
        op,
        "operation",
        inputs.iter().map(|name| (*name).to_owned()).collect(),
        vec![output.to_owned()],
        AttributeMap::new(),
    )
}

// Consumer-first storage deliberately forces a traversal through the entire dependency chain.
// Fixed-width names also let the wire test reverse complete node records without altering fields.
fn chain(cycle_entry: Option<usize>) -> Result<ModelIrGraph, Box<dyn Error>> {
    let mut nodes = Vec::with_capacity(MAX_MODEL_IR_ITEMS);
    for index in 0..MAX_MODEL_IR_ITEMS {
        let input = if index + 1 < MAX_MODEL_IR_ITEMS {
            format!("value{:04}", index + 1)
        } else if let Some(entry) = cycle_entry {
            format!("value{entry:04}")
        } else {
            "input0000".to_owned()
        };
        nodes.push(operator(
            &format!("node{index:04}"),
            OpCode::Relu,
            &[&input],
            &format!("value{index:04}"),
        )?);
    }
    Ok(ModelIrGraph::new(
        "deep_graph",
        ModelIrVersion::V1,
        Generation::from_u64(1),
        vec![port("input0000")?],
        vec![port("value0000")?],
        nodes,
    )?)
}

#[test]
fn maximum_depth_dag_preserves_canonical_order_and_digest() -> TestResult {
    let graph = chain(None)?;
    graph.validate()?;
    let bytes = encode_canonical_model_ir(&graph)?;

    let reordered = ModelIrGraph::new(
        graph.id(),
        graph.version(),
        graph.generation(),
        graph.inputs().to_vec(),
        graph.outputs().to_vec(),
        graph.nodes().iter().rev().cloned().collect(),
    )?;
    assert_eq!(encode_canonical_model_ir(&reordered)?, bytes);
    assert_eq!(graph.content_digest()?, reordered.content_digest()?);

    let restored = decode_canonical_model_ir(&bytes, ContentDigest::sha256(&bytes))?;
    assert_eq!(restored.node_count(), MAX_MODEL_IR_ITEMS);
    assert!(
        restored
            .nodes()
            .iter()
            .zip(graph.nodes().iter().rev())
            .all(|(actual, expected)| actual.id() == expected.id())
    );
    Ok(())
}

#[test]
fn maximum_depth_cycle_returns_a_closed_witness() -> TestResult {
    let graph = chain(Some(0))?;
    match graph.validate() {
        Err(ModelIrError::CycleDetected {
            node_id,
            cycle_path,
        }) => {
            assert_eq!(node_id, "node0000");
            assert_eq!(cycle_path.len(), MAX_MODEL_IR_ITEMS + 1);
            for (node, witness) in graph.nodes().iter().zip(&cycle_path) {
                assert_eq!(node.id(), witness.as_str());
            }
            assert_eq!(cycle_path.first(), cycle_path.last());
        }
        other => return Err(format!("expected a deep cycle witness, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn deep_cycle_witness_excludes_the_acyclic_prefix() -> TestResult {
    let entry = MAX_MODEL_IR_ITEMS - 2;
    let graph = chain(Some(entry))?;
    match graph.validate() {
        Err(ModelIrError::CycleDetected {
            node_id,
            cycle_path,
        }) => {
            assert_eq!(node_id, format!("node{entry:04}"));
            assert_eq!(
                cycle_path,
                vec![
                    format!("node{entry:04}"),
                    format!("node{:04}", entry + 1),
                    format!("node{entry:04}"),
                ]
            );
        }
        other => return Err(format!("expected a cycle after a deep prefix, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn loader_refuses_reversed_maximum_depth_node_records() -> TestResult {
    let graph = chain(None)?;
    let bytes = encode_canonical_model_ir(&graph)?;
    let first = graph.nodes().first().ok_or("missing fixture node")?;

    // Each fixture node has five text fields and eight u32 length/count fields:
    // ID, operator ID, name, one input, one output, and zero attributes.
    let record_len = 8 * size_of::<u32>()
        + first.id().len()
        + first.op().stable_id().len()
        + first.name().len()
        + "input0000".len()
        + "value0000".len();
    for node in graph.nodes() {
        assert_eq!(node.id().len(), first.id().len());
        assert_eq!(node.inputs().len(), 1);
        assert_eq!(node.outputs().len(), 1);
        assert_eq!(node.inputs()[0].len(), "input0000".len());
        assert_eq!(node.outputs()[0].len(), "value0000".len());
        assert!(node.attributes().is_empty());
    }
    let node_start = bytes
        .len()
        .checked_sub(record_len * graph.node_count())
        .ok_or("node records exceed fixture size")?;
    let records = bytes[node_start..].chunks_exact(record_len);
    assert!(records.remainder().is_empty());
    let mut reversed = bytes[..node_start].to_vec();
    for record in records.rev() {
        reversed.extend_from_slice(record);
    }
    assert_ne!(reversed, bytes);

    // The loader validates topology before enforcing canonical node order. A digest that
    // matches hostile ordering must produce a typed refusal without exhausting the stack.
    match decode_canonical_model_ir(&reversed, ContentDigest::sha256(&reversed)) {
        Err(ModelIrDecodeError::NonCanonical) => {}
        other => {
            return Err(format!("expected a noncanonical ordering refusal, got {other:?}").into());
        }
    }
    Ok(())
}

#[test]
fn shared_predecessors_and_duplicate_inputs_keep_stable_topological_order() -> TestResult {
    let graph = ModelIrGraph::new(
        "shared_dependencies",
        ModelIrVersion::V1,
        Generation::from_u64(1),
        vec![port("input")?],
        vec![port("output")?],
        vec![
            operator("sink", OpCode::Add, &["left", "right"], "output")?,
            operator("right", OpCode::Add, &["shared", "shared"], "right")?,
            operator("left", OpCode::Relu, &["shared"], "left")?,
            operator("source", OpCode::Relu, &["input"], "shared")?,
        ],
    )?;
    let bytes = encode_canonical_model_ir(&graph)?;
    let restored = decode_canonical_model_ir(&bytes, ContentDigest::sha256(&bytes))?;
    let ids: Vec<_> = restored.nodes().iter().map(GraphNode::id).collect();
    assert_eq!(ids, vec!["source", "left", "right", "sink"]);
    Ok(())
}
