#![forbid(unsafe_code)]
//! FSS-072 property family: model invocation/receipt protocol.
//!
//! Determinism + idempotency, generation binding, quarantine, budget
//! exhaustion, and provenance sensitivity over validated real IR graphs.
//! Each property emits one JSONL verdict line.

use fss_core::{ContentDigest, Generation};
use fss_model_ir::graph::ModelIrGraph;
use fss_model_ir::invocation::{
    InputBinding, InvocationError, InvocationOutcome, ModelInvocationSpec, execute, prepare,
};
use fss_model_ir::node::GraphNode;
use fss_model_ir::op::OpCode;
use fss_model_ir::port::TensorPort;
use fss_tensor::{DType, Shape};

fn emit(property: &str, cases: u64) {
    println!(
        "{{\"family\":\"FSS-072\",\"property\":\"{property}\",\"cases\":{cases},\"verdict\":\"pass\"}}"
    );
}

fn port(name: &str) -> Result<TensorPort, fss_model_ir::error::ModelIrError> {
    TensorPort::new(
        name,
        DType::F32,
        Shape::new(vec![2, 3])?,
        Generation::GENESIS,
    )
}

/// A minimal validated two-node graph: input -> Add -> Relu -> output.
fn two_node_graph() -> Result<ModelIrGraph, fss_model_ir::error::ModelIrError> {
    let add = GraphNode::new(
        "n-add",
        OpCode::Add,
        "add",
        vec!["x".to_string(), "y".to_string()],
        vec!["sum".to_string()],
        Default::default(),
    )?;
    let relu = GraphNode::new(
        "n-relu",
        OpCode::Relu,
        "relu",
        vec!["sum".to_string()],
        vec!["activated".to_string()],
        Default::default(),
    )?;
    ModelIrGraph::builder("graph:invocation-family", Generation::GENESIS)
        .add_input(port("x")?)
        .add_input(port("y")?)
        .add_output(port("activated")?)
        .add_node(add)
        .add_node(relu)
        .build_and_validate()
}

fn spec(inputs: Vec<InputBinding>) -> ModelInvocationSpec {
    ModelInvocationSpec {
        model_root: ContentDigest::sha256(b"manifest-v1-root"),
        preprocess_generation: Generation::GENESIS,
        calibration_generation: None,
        inputs,
        max_nodes: 1000,
    }
}

fn binding(name: &str, salt: &[u8]) -> InputBinding {
    InputBinding {
        name: name.to_string(),
        digest: ContentDigest::sha256(salt),
        generation: Generation::GENESIS,
    }
}

/// P1 DETERMINISM + IDEMPOTENCY: identical (graph, spec) yields identical
/// receipts; a different input digest changes the invocation identity and
/// the outputs.
#[test]
fn p1_determinism_and_idempotency() -> Result<(), Box<dyn std::error::Error>> {
    let graph = two_node_graph()?;
    let s = spec(vec![binding("x", b"tensor-x"), binding("y", b"tensor-y")]);
    let prepared = prepare(&graph, &s)?;
    let r1 = execute(&graph, &prepared)?;
    let r2 = execute(&graph, &prepared)?;
    assert_eq!(r1, r2, "identical spec yields identical receipt");
    let InvocationOutcome::Completed {
        outputs,
        nodes_evaluated,
        ..
    } = &r1.outcome
    else {
        return Err("expected completion".into());
    };
    assert_eq!(*nodes_evaluated, 2);
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].0, "activated");

    let s2 = spec(vec![
        binding("x", b"tensor-x-CHANGED"),
        binding("y", b"tensor-y"),
    ]);
    let p2 = prepare(&graph, &s2)?;
    let r3 = execute(&graph, &p2)?;
    assert_ne!(
        r1.invocation, r3.invocation,
        "spec digest is input-sensitive"
    );
    assert_ne!(r1.outcome, r3.outcome, "outputs are input-sensitive");
    emit("determinism-idempotency", 2);
    Ok(())
}

/// P2 GENERATION BINDING: an input whose generation differs from the port's
/// is refused at prepare with the exact generations named.
#[test]
fn p2_stale_generation_refused_at_prepare() -> Result<(), Box<dyn std::error::Error>> {
    let graph = two_node_graph()?;
    let stale = InputBinding {
        name: "x".to_string(),
        digest: ContentDigest::sha256(b"tensor-x"),
        generation: Generation::from_u64(7),
    };
    let err = prepare(&graph, &spec(vec![stale, binding("y", b"y")])).err();
    assert!(matches!(
        err,
        Some(InvocationError::StaleGeneration {
            name,
            bound,
            required,
        }) if name == "x" && bound.get() == 7 && required.get() == 1
    ));
    // Unbound port refused; unknown name refused.
    assert!(matches!(
        prepare(&graph, &spec(vec![binding("x", b"x")])),
        Err(InvocationError::InputBinding { .. })
    ));
    assert!(matches!(
        prepare(
            &graph,
            &spec(vec![
                binding("x", b"x"),
                binding("y", b"y"),
                binding("ghost", b"g")
            ])
        ),
        Err(InvocationError::InputBinding { .. })
    ));
    emit("generation-binding", 3);
    Ok(())
}

/// P3 BUDGET: node-budget exhaustion is a typed refusal, never a partial
/// receipt.
#[test]
fn p3_budget_exhaustion_is_typed() -> Result<(), Box<dyn std::error::Error>> {
    let graph = two_node_graph()?;
    let mut s = spec(vec![binding("x", b"x"), binding("y", b"y")]);
    s.max_nodes = 1;
    let prepared = prepare(&graph, &s)?;
    assert!(matches!(
        execute(&graph, &prepared),
        Err(InvocationError::BudgetExhausted { max_nodes }) if max_nodes == 1
    ));
    emit("budget-exhaustion", 1);
    Ok(())
}

/// P4 QUARANTINE: an invalid graph (dangling output) still prepares and
/// executes to a receipt whose outcome QUARANTINES with the validator's
/// reason — never a silent success or crash.
#[test]
fn p4_quarantine_is_receipted() -> Result<(), Box<dyn std::error::Error>> {
    let bad = GraphNode::new(
        "n-add",
        OpCode::Add,
        "add",
        vec!["x".to_string(), "y".to_string()],
        vec!["wrong-output".to_string()],
        Default::default(),
    )?;
    let graph = ModelIrGraph::builder("graph:bad", Generation::GENESIS)
        .add_input(port("x")?)
        .add_input(port("y")?)
        .add_output(port("activated")?)
        .add_node(bad)
        .build()?; // intentionally unvalidated
    let prepared = prepare(&graph, &spec(vec![binding("x", b"x"), binding("y", b"y")]))?;
    let receipt = execute(&graph, &prepared)?;
    assert!(matches!(
        receipt.outcome,
        InvocationOutcome::Quarantined { .. }
    ));
    assert_eq!(receipt.mode, "digest-binding");
    emit("quarantine-receipt", 1);
    Ok(())
}

/// P5 PROVENANCE SENSITIVITY: the receipt binds graph identity — the same
/// spec against a DIFFERENT graph yields a different IR digest and
/// different outputs.
#[test]
fn p5_receipt_binds_graph_identity() -> Result<(), Box<dyn std::error::Error>> {
    let g1 = two_node_graph()?;
    // Same topology, different node id: a genuinely different graph.
    let add = GraphNode::new(
        "n-add-v2",
        OpCode::Add,
        "add",
        vec!["x".to_string(), "y".to_string()],
        vec!["sum".to_string()],
        Default::default(),
    )?;
    let relu = GraphNode::new(
        "n-relu",
        OpCode::Relu,
        "relu",
        vec!["sum".to_string()],
        vec!["activated".to_string()],
        Default::default(),
    )?;
    let g2 = ModelIrGraph::builder("graph:invocation-family", Generation::GENESIS)
        .add_input(port("x")?)
        .add_input(port("y")?)
        .add_output(port("activated")?)
        .add_node(add.clone())
        .add_node(relu.clone())
        .build_and_validate()?;
    let s = spec(vec![binding("x", b"x"), binding("y", b"y")]);
    let r1 = execute(&g1, &prepare(&g1, &s)?)?;
    let r2 = execute(&g2, &prepare(&g2, &s)?)?;
    assert_ne!(r1.ir_digest, r2.ir_digest, "IR digest binds the graph");
    assert_ne!(r1.outcome, r2.outcome, "outputs bind the graph");
    // Node-order independence: the same graph with nodes listed in reverse
    // (same node CONTENT as g1) yields IDENTICAL outputs — the evaluator
    // computes its own topological order.
    let add3 = GraphNode::new(
        "n-add",
        OpCode::Add,
        "add",
        vec!["x".to_string(), "y".to_string()],
        vec!["sum".to_string()],
        Default::default(),
    )?;
    let relu3 = GraphNode::new(
        "n-relu",
        OpCode::Relu,
        "relu",
        vec!["sum".to_string()],
        vec!["activated".to_string()],
        Default::default(),
    )?;
    let g3 = ModelIrGraph::builder("graph:invocation-family", Generation::GENESIS)
        .add_input(port("x")?)
        .add_input(port("y")?)
        .add_output(port("activated")?)
        .add_node(relu3)
        .add_node(add3)
        .build_and_validate()?;
    let r3 = execute(&g3, &prepare(&g3, &s)?)?;
    assert_eq!(r1.outcome, r3.outcome, "storage order must not matter");
    emit("graph-identity-binding", 3);
    Ok(())
}
