#![forbid(unsafe_code)]

use std::error::Error;

use fss_core::{ContentDigest, Generation, TimestampNs};
use fss_model_ir::{AttrValue, AttributeMap, GraphNode, ModelIrGraph, OpCode, TensorPort};
use fss_tensor::{DType, Shape, Tensor};

use crate::clock::VirtualClock;
use crate::model_receipt::{
    ReceiptDigest, ReceiptOutcome, ReceiptVerificationError, execute_and_record_receipt,
};
use crate::scalar_executor::{ExecBudget, ScalarExecCx};

fn test_gen() -> Generation {
    Generation::from_u64(1)
}

fn build_simple_relu_graph(g: Generation) -> Result<ModelIrGraph, Box<dyn Error>> {
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![1, 3])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![1, 3])?, g)?;
    let node = GraphNode::new(
        "relu_1",
        OpCode::Relu,
        "relu",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::builder("test_relu_model", g)
        .add_input(in_port)
        .add_output(out_port)
        .add_node(node)
        .build_and_validate()?;
    Ok(graph)
}

#[test]
fn test_receipt_ok_outcome() -> Result<(), Box<dyn Error>> {
    let g = test_gen();
    let graph = build_simple_relu_graph(g)?;

    let x_vals = [-1.5_f32, 0.0, 2.5];
    let x_tensor = Tensor::from_values(Shape::new(vec![1, 3])?, &x_vals, g)?;
    let inputs = vec![("x", x_tensor)];

    let cx = ScalarExecCx::new();
    let clock = VirtualClock::new(0, TimestampNs(50_000));

    let (res, receipt) = execute_and_record_receipt(
        &graph,
        &inputs,
        ExecBudget::unlimited(),
        &cx,
        "job:test-ok-1",
        None,
        None,
        Some(&clock),
    );

    assert!(res.is_ok());
    assert_eq!(receipt.outcome, ReceiptOutcome::Ok);
    assert_eq!(receipt.job_id, "job:test-ok-1");
    assert!(receipt.output_root.is_some());
    assert!(receipt.operator_trace_digest.is_some());
    assert!(receipt.error_id.is_none());
    assert!(receipt.cancel_reason.is_none());
    assert!(receipt.is_reference_only()); // Due to activationGeneration sentinel
    assert_eq!(receipt.usage.wall_ns, 50_000);

    let digest = receipt.compute_canonical_digest();
    receipt.verify(g, &digest)?;

    let json = receipt.to_json_canonical();
    assert!(json.contains(r#""schema":"fss.model_execution_receipt.v1""#));
    assert!(json.contains(r#""outcome":"ok""#));
    assert!(json.contains(r#""errorId":null"#));
    assert!(json.contains(r#""cancelReason":null"#));
    assert!(json.contains(r#""activationGeneration":"fss-na:"#));

    Ok(())
}

#[test]
fn test_receipt_refused_graph_outcome() -> Result<(), Box<dyn Error>> {
    // RMSNorm, the op this test first used as "unsupported", executes since 35b07e0, and every
    // frozen opcode now has a scalar kernel, so no valid graph yields UnsupportedOperator. The
    // still-reachable pre-execution refusal is graph validation: a GELU mode outside none/tanh.
    let g = test_gen();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![1, 4])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![1, 4])?, g)?;
    let mut attrs = AttributeMap::new();
    attrs.insert(
        "approximate".to_string(),
        AttrValue::String("erf".to_string()),
    );
    let node = GraphNode::new(
        "gelu_1",
        OpCode::Gelu,
        "gelu",
        vec!["x".to_string()],
        vec!["y".to_string()],
        attrs,
    )?;

    // Deliberately unvalidated: the executor behind the receipt must refuse it.
    let graph = ModelIrGraph::builder("test_refused_graph", g)
        .add_input(in_port)
        .add_output(out_port)
        .add_node(node)
        .build()?;

    let x_vals = [1.0_f32, 2.0, 3.0, 4.0];
    let x_tensor = Tensor::from_values(Shape::new(vec![1, 4])?, &x_vals, g)?;
    let inputs = vec![("x", x_tensor)];

    let cx = ScalarExecCx::new();
    let (res, receipt) = execute_and_record_receipt(
        &graph,
        &inputs,
        ExecBudget::unlimited(),
        &cx,
        "job:test-refused-graph",
        None,
        None,
        None,
    );

    assert!(res.is_err());
    assert_eq!(receipt.outcome, ReceiptOutcome::Error);
    assert_eq!(
        receipt.error_id.as_deref(),
        Some("ERR-EXEC-IR-VALIDATION-001")
    );
    assert!(receipt.output_root.is_none());
    assert!(receipt.operator_trace_digest.is_none());
    assert!(receipt.cancel_reason.is_none());

    let digest = receipt.compute_canonical_digest();
    receipt.verify(g, &digest)?;

    let json = receipt.to_json_canonical();
    assert!(json.contains(r#""outcome":"error""#));
    assert!(json.contains(r#""errorId":"ERR-EXEC-IR-VALIDATION-001""#));
    assert!(json.contains(r#""outputRoot":null"#));

    Ok(())
}

#[test]
fn test_receipt_unsupported_dtype_outcome() -> Result<(), Box<dyn Error>> {
    let g = test_gen();
    // Declare an F16 graph: it passes IR validation (U8 Relu does not: DTypeMismatch), but the
    // scalar executor only admits F32 arithmetic and refuses it before execution.
    let in_port = TensorPort::new("x", DType::F16, Shape::new(vec![1, 2])?, g)?;
    let out_port = TensorPort::new("y", DType::F16, Shape::new(vec![1, 2])?, g)?;
    let node = GraphNode::new(
        "relu_f16",
        OpCode::Relu,
        "relu",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::builder("test_unsupported_dtype", g)
        .add_input(in_port)
        .add_output(out_port)
        .add_node(node)
        .build_and_validate()?;

    let x_vals = [1.0_f32, 2.0];
    let x_tensor = Tensor::from_values(Shape::new(vec![1, 2])?, &x_vals, g)?;
    let inputs = vec![("x", x_tensor)];

    let cx = ScalarExecCx::new();
    let (res, receipt) = execute_and_record_receipt(
        &graph,
        &inputs,
        ExecBudget::unlimited(),
        &cx,
        "job:test-unsupported-dtype",
        None,
        None,
        None,
    );

    assert!(res.is_err());
    assert_eq!(receipt.outcome, ReceiptOutcome::Error);
    assert_eq!(
        receipt.error_id.as_deref(),
        Some("ERR-EXEC-UNSUPPORTED-DTYPE-001")
    );
    assert!(receipt.output_root.is_none());

    let digest = receipt.compute_canonical_digest();
    receipt.verify(g, &digest)?;

    let json = receipt.to_json_canonical();
    assert!(json.contains(r#""outcome":"error""#));
    assert!(json.contains(r#""errorId":"ERR-EXEC-UNSUPPORTED-DTYPE-001""#));

    Ok(())
}

#[test]
fn test_receipt_shape_mismatch_outcome() -> Result<(), Box<dyn Error>> {
    let g = test_gen();
    let graph = build_simple_relu_graph(g)?;

    // Supply tensor of wrong shape [1, 5] instead of declared [1, 3]
    let x_vals = [1.0_f32, 2.0, 3.0, 4.0, 5.0];
    let x_tensor = Tensor::from_values(Shape::new(vec![1, 5])?, &x_vals, g)?;
    let inputs = vec![("x", x_tensor)];

    let cx = ScalarExecCx::new();
    let (res, receipt) = execute_and_record_receipt(
        &graph,
        &inputs,
        ExecBudget::unlimited(),
        &cx,
        "job:test-shape-mismatch",
        None,
        None,
        None,
    );

    assert!(res.is_err());
    assert_eq!(receipt.outcome, ReceiptOutcome::Error);
    assert_eq!(
        receipt.error_id.as_deref(),
        Some("ERR-EXEC-SHAPE-MISMATCH-001")
    );

    let digest = receipt.compute_canonical_digest();
    receipt.verify(g, &digest)?;

    Ok(())
}

#[test]
fn test_receipt_budget_exhausted_outcome() -> Result<(), Box<dyn Error>> {
    let g = test_gen();
    // Build Add graph which requires 4 MACs/work units
    let a_port = TensorPort::new("a", DType::F32, Shape::new(vec![1, 4])?, g)?;
    let b_port = TensorPort::new("b", DType::F32, Shape::new(vec![1, 4])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![1, 4])?, g)?;
    let node = GraphNode::new(
        "add_1",
        OpCode::Add,
        "add",
        vec!["a".to_string(), "b".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::builder("test_budget", g)
        .add_input(a_port)
        .add_input(b_port)
        .add_output(out_port)
        .add_node(node)
        .build_and_validate()?;

    let a_tensor = Tensor::from_values(Shape::new(vec![1, 4])?, &[1.0_f32, 2.0, 3.0, 4.0], g)?;
    let b_tensor = Tensor::from_values(Shape::new(vec![1, 4])?, &[0.5_f32, 0.5, 0.5, 0.5], g)?;
    let inputs = vec![("a", a_tensor), ("b", b_tensor)];

    let cx = ScalarExecCx::new();
    // Constrain budget to max_macs: 1, below required 4 operations
    let budget = ExecBudget::new(1, 1024 * 1024);

    let (res, receipt) = execute_and_record_receipt(
        &graph,
        &inputs,
        budget,
        &cx,
        "job:test-budget-exceeded",
        None,
        None,
        None,
    );

    assert!(res.is_err());
    assert_eq!(receipt.outcome, ReceiptOutcome::BudgetExhausted);
    assert!(receipt.output_root.is_none());
    assert!(receipt.operator_trace_digest.is_none());

    let digest = receipt.compute_canonical_digest();
    receipt.verify(g, &digest)?;

    let json = receipt.to_json_canonical();
    assert!(json.contains(r#""outcome":"budget_exhausted""#));
    assert!(json.contains(r#""outputRoot":null"#));

    Ok(())
}

#[test]
fn test_receipt_cancelled_outcome() -> Result<(), Box<dyn Error>> {
    let g = test_gen();
    let graph = build_simple_relu_graph(g)?;

    let x_vals = [1.0_f32, 2.0, 3.0];
    let x_tensor = Tensor::from_values(Shape::new(vec![1, 3])?, &x_vals, g)?;
    let inputs = vec![("x", x_tensor)];

    let cx = ScalarExecCx::new();
    cx.request_cancellation(); // Cancel before execution

    let (res, receipt) = execute_and_record_receipt(
        &graph,
        &inputs,
        ExecBudget::unlimited(),
        &cx,
        "job:test-cancelled",
        None,
        None,
        None,
    );

    assert!(res.is_err());
    assert_eq!(receipt.outcome, ReceiptOutcome::Cancelled);
    assert_eq!(receipt.cancel_reason.as_deref(), Some("pre-execution"));
    assert!(receipt.output_root.is_none());
    assert!(receipt.operator_trace_digest.is_none());

    let digest = receipt.compute_canonical_digest();
    receipt.verify(g, &digest)?;

    let json = receipt.to_json_canonical();
    assert!(json.contains(r#""outcome":"cancelled""#));
    assert!(json.contains(r#""cancelReason":"pre-execution""#));

    Ok(())
}

#[test]
fn test_bit_exact_reproducibility() -> Result<(), Box<dyn Error>> {
    let g = test_gen();
    let graph = build_simple_relu_graph(g)?;

    let x_vals = [-2.0_f32, 0.5, 3.0];
    let x_tensor1 = Tensor::from_values(Shape::new(vec![1, 3])?, &x_vals, g)?;
    let x_tensor2 = Tensor::from_values(Shape::new(vec![1, 3])?, &x_vals, g)?;

    let cx1 = ScalarExecCx::new();
    let cx2 = ScalarExecCx::new();
    let clock1 = VirtualClock::new(0, TimestampNs(12345));
    let clock2 = VirtualClock::new(0, TimestampNs(12345));

    let (_, receipt1) = execute_and_record_receipt(
        &graph,
        &[("x", x_tensor1)],
        ExecBudget::unlimited(),
        &cx1,
        "job:reproducible-1",
        None,
        None,
        Some(&clock1),
    );

    let (_, receipt2) = execute_and_record_receipt(
        &graph,
        &[("x", x_tensor2)],
        ExecBudget::unlimited(),
        &cx2,
        "job:reproducible-1",
        None,
        None,
        Some(&clock2),
    );

    assert_eq!(
        receipt1.compute_canonical_digest(),
        receipt2.compute_canonical_digest()
    );
    assert_eq!(receipt1.to_json_canonical(), receipt2.to_json_canonical());

    Ok(())
}

#[test]
fn test_tamper_detection() -> Result<(), Box<dyn Error>> {
    let g = test_gen();
    let graph = build_simple_relu_graph(g)?;

    let x_vals = [1.0_f32, 2.0, 3.0];
    let x_tensor = Tensor::from_values(Shape::new(vec![1, 3])?, &x_vals, g)?;

    let cx = ScalarExecCx::new();
    let (_, receipt) = execute_and_record_receipt(
        &graph,
        &[("x", x_tensor)],
        ExecBudget::unlimited(),
        &cx,
        "job:tamper-test",
        None,
        None,
        None,
    );

    let original_digest = receipt.compute_canonical_digest();
    receipt.verify(g, &original_digest)?;

    // Tamper with job_id
    let mut tampered = receipt.clone();
    tampered.job_id = "job:tampered".to_string();
    assert_ne!(tampered.compute_canonical_digest(), original_digest);
    assert!(matches!(
        tampered.verify(g, &original_digest),
        Err(ReceiptVerificationError::DigestMismatch { .. })
    ));

    // Generation mismatch
    assert!(matches!(
        receipt.verify(Generation::from_u64(999), &original_digest),
        Err(ReceiptVerificationError::GenerationMismatch { .. })
    ));

    Ok(())
}

#[test]
fn test_sentinel_refusal_by_content_digest_parse() -> Result<(), Box<dyn Error>> {
    let sentinel =
        ReceiptDigest::not_applicable("activationGeneration", "unactivated_reference_run");

    let sentinel_text = sentinel.to_text();
    assert!(sentinel_text.starts_with("fss-na:"));
    assert_eq!(sentinel_text.len(), 7 + 64);

    // ContentDigest::parse must strictly REFUSE the sentinel format
    let parsed = ContentDigest::parse(&sentinel_text);
    assert!(parsed.is_err());

    // Authentic sha256 must parse successfully
    let authentic = ContentDigest::sha256(b"authentic payload");
    let parsed_auth = ContentDigest::parse(authentic.to_text());
    assert!(parsed_auth.is_ok());

    Ok(())
}

#[test]
fn test_virtual_clock_determinism() -> Result<(), Box<dyn Error>> {
    let g = test_gen();
    let graph = build_simple_relu_graph(g)?;
    let x_tensor = Tensor::from_values(Shape::new(vec![1, 3])?, &[1.0_f32, 2.0, 3.0], g)?;

    let cx = ScalarExecCx::new();
    let clock = VirtualClock::new(0, TimestampNs(987_654_321));

    let (_, receipt) = execute_and_record_receipt(
        &graph,
        &[("x", x_tensor)],
        ExecBudget::unlimited(),
        &cx,
        "job:clock-test",
        None,
        None,
        Some(&clock),
    );

    assert_eq!(receipt.usage.wall_ns, 987_654_321);

    Ok(())
}
