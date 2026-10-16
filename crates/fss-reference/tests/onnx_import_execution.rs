#![forbid(unsafe_code)]
//! Complete protobuf sources -> native Model IR -> real scalar kernels, without model runtimes.
//! These tiny numerical fixtures test conversion, not detector quality or model admission.

use std::cell::Cell;

use fss_core::ContentDigest;
use fss_model_ir::{OnnxError, OnnxLimits, import_onnx};
use fss_reference::{ExecBudget, ExecError, ScalarExecCx, ScalarExecutor};
use fss_tensor::{Shape, Tensor};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        out.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 {
            return out;
        }
    }
}
fn integer(tag: u64, value: u64) -> Vec<u8> {
    [varint(tag * 8), varint(value)].concat()
}
fn bytes(tag: u64, value: &[u8]) -> Vec<u8> {
    [varint(tag * 8 + 2), varint(value.len() as u64), value.to_vec()].concat()
}
fn info(name: &str, dimensions: &[u64]) -> Vec<u8> {
    let shape: Vec<_> = dimensions
        .iter()
        .flat_map(|&n| bytes(1, &integer(1, n)))
        .collect();
    let tensor = [integer(1, 1), bytes(2, &shape)].concat();
    [bytes(1, name.as_bytes()), bytes(2, &bytes(1, &tensor))].concat()
}
fn weight(name: &str, dimensions: &[u64], values: &[f32], raw: bool) -> Vec<u8> {
    let dims: Vec<_> = dimensions.iter().flat_map(|&n| integer(1, n)).collect();
    let data: Vec<_> = values.iter().flat_map(|n| n.to_le_bytes()).collect();
    bytes(5, &[dims, integer(2, 1), bytes(8, name.as_bytes()), bytes(if raw { 9 } else { 4 }, &data)].concat())
}
fn attribute_list(name: &str, values: &[u64]) -> Vec<u8> {
    let values: Vec<_> = values.iter().flat_map(|&n| varint(n)).collect();
    bytes(5, &[bytes(1, name.as_bytes()), integer(20, 7), bytes(8, &values)].concat())
}
fn node(op: &str, inputs: &[&str], output: &str, attributes: &[u8]) -> Vec<u8> {
    let inputs: Vec<_> = inputs.iter().flat_map(|name| bytes(1, name.as_bytes())).collect();
    bytes(1, &[inputs, bytes(2, output.as_bytes()), bytes(4, op.as_bytes()), attributes.to_vec()].concat())
}
fn model(graph: &[u8]) -> Vec<u8> {
    [integer(1, 8), bytes(8, &integer(2, 13)), bytes(7, graph)].concat()
}
fn dense_graph(raw: bool) -> Vec<u8> {
    [
        bytes(2, b"dense-numerical-fixture"),
        node("MatMul", &["image", "weights"], "product", &[]),
        node("Add", &["product", "bias"], "biased", &[]),
        node("Relu", &["biased"], "output", &[]),
        weight("weights", &[2, 3], &[1., 2., 3., 4., 5., 6.], raw),
        weight("bias", &[3], &[-1., 0., 1.], raw),
        bytes(11, &info("image", &[1, 2])),
        bytes(12, &info("output", &[1, 3])),
        bytes(13, &info("product", &[1, 3])),
    ].concat()
}

#[test]
fn raw_and_packed_initializers_reach_the_real_matmul_bias_and_relu_kernels() -> Test {
    for raw in [false, true] {
        let source = model(&dense_graph(raw));
        let imported = import_onnx(&source, ContentDigest::sha256(&source), 7, OnnxLimits::default(), &|| false)?;
        let image = Tensor::from_values(Shape::new(vec![1, 2])?, &[2_f32, 3.], 7)?;
        let mut inputs: Vec<_> = imported.parameters().iter()
            .map(|(name, tensor)| (name.clone(), tensor.clone())).collect();
        inputs.push(("image".to_owned(), image));
        let first = ScalarExecutor::run(imported.graph(), &inputs, ExecBudget::unlimited(), &ScalarExecCx::new())?;
        let second = ScalarExecutor::run(imported.graph(), &inputs, ExecBudget::unlimited(), &ScalarExecCx::new())?;
        let output = first.get_output("output").ok_or("missing output")?;
        assert_eq!(output.to_vec::<f32>()?, [13., 19., 25.]);
        assert_eq!(first.nodes_executed(), 3);
        assert_eq!(first.node_output_digests(), second.node_output_digests());
        assert_eq!(first.node_output_digests().len(), 3);
        assert_eq!(imported.runtime_inputs(), ["image"]);
        assert_eq!(imported.source(), source);
        assert!(imported.work_units() > source.len() as u64);
    }
    Ok(())
}

#[test]
fn imported_convolution_relu_and_maxpool_use_source_attributes_and_weights() -> Test {
    let graph = [
        node("Conv", &["image", "kernel", "bias"], "convolution", &attribute_list("strides", &[1, 1])),
        node("Relu", &["convolution"], "activated", &[]),
        node("MaxPool", &["activated"], "output", &attribute_list("kernel_shape", &[2, 2])),
        weight("kernel", &[1, 1, 1, 1], &[2.], true),
        weight("bias", &[1], &[-1.], true),
        bytes(11, &info("image", &[1, 1, 2, 2])),
        bytes(12, &info("output", &[1, 1, 1, 1])),
    ].concat();
    let source = model(&graph);
    let imported = import_onnx(&source, ContentDigest::sha256(&source), 1, OnnxLimits::default(), &|| false)?;
    let image = Tensor::from_values(Shape::new(vec![1, 1, 2, 2])?, &[-1_f32, 0., 1., 2.], 1)?;
    let mut inputs: Vec<_> = imported.parameters().iter()
        .map(|(name, tensor)| (name.clone(), tensor.clone())).collect();
    inputs.push(("image".into(), image));
    let outcome = ScalarExecutor::run(imported.graph(), &inputs, ExecBudget::unlimited(), &ScalarExecCx::new())?;
    assert_eq!(outcome.get_output("output").ok_or("missing pooled output")?.to_vec::<f32>()?, [3.]);
    assert_eq!(outcome.nodes_executed(), 3);
    Ok(())
}

#[test]
fn source_declared_intermediate_shape_is_checked_not_ignored() {
    let graph = [dense_graph(true), bytes(13, &info("biased", &[1, 4]))].concat();
    let source = model(&graph);
    assert!(matches!(import_onnx(&source, ContentDigest::sha256(&source), 1,
        OnnxLimits::default(), &|| false), Err(OnnxError::Graph)));
}

#[test]
fn duplicate_parameters_and_overridable_graph_inputs_are_rejected() {
    for extra in [
        weight("bias", &[3], &[0., 0., 0.], true),
        bytes(11, &info("weights", &[2, 3])),
    ] {
        let source = model(&[dense_graph(true), extra].concat());
        assert!(matches!(import_onnx(&source, ContentDigest::sha256(&source), 1,
            OnnxLimits::default(), &|| false), Err(OnnxError::Malformed)));
    }
}

#[test]
fn nonfinite_initializers_and_unreferenced_parameters_are_rejected() {
    for (value, error) in [(f32::NAN, OnnxError::NonFinite), (f32::INFINITY, OnnxError::NonFinite), (1., OnnxError::Graph)] {
        let source = model(&[dense_graph(true), weight("unused", &[1], &[value], true)].concat());
        assert!(matches!(import_onnx(&source, ContentDigest::sha256(&source), 1,
            OnnxLimits::default(), &|| false), Err(found) if found == error));
    }
}

#[test]
fn exact_parameter_and_work_budgets_are_enforced_before_a_model_escapes() -> Test {
    let source = model(&dense_graph(true));
    let digest = ContentDigest::sha256(&source);
    let complete = import_onnx(&source, digest, 1, OnnxLimits::default(), &|| false)?;
    let limits = OnnxLimits { parameter_bytes: 36, work_units: complete.work_units(), ..OnnxLimits::default() };
    assert!(import_onnx(&source, digest, 1, limits, &|| false).is_ok());
    assert!(matches!(import_onnx(&source, digest, 1,
        OnnxLimits { parameter_bytes: 35, ..limits }, &|| false), Err(OnnxError::Limit)));
    assert!(matches!(import_onnx(&source, digest, 1,
        OnnxLimits { work_units: limits.work_units - 1, ..limits }, &|| false), Err(OnnxError::WorkBudget)));
    Ok(())
}

#[test]
fn cancellation_during_wire_traversal_stops_conversion() {
    let source = model(&dense_graph(true));
    let calls = Cell::new(0);
    let cancelled = || { calls.set(calls.get() + 1); calls.get() >= 20 };
    assert!(matches!(import_onnx(&source, ContentDigest::sha256(&source), 1,
        OnnxLimits::default(), &cancelled), Err(OnnxError::Cancelled)));
    assert_eq!(calls.get(), 20);
}

#[test]
fn imported_graph_still_enforces_native_generation_and_execution_budgets() -> Test {
    let source = model(&dense_graph(true));
    let imported = import_onnx(&source, ContentDigest::sha256(&source), 7, OnnxLimits::default(), &|| false)?;
    let mut inputs: Vec<_> = imported.parameters().iter()
        .map(|(name, tensor)| (name.clone(), tensor.clone())).collect();
    inputs.push(("image".into(), Tensor::from_values(Shape::new(vec![1, 2])?, &[2_f32, 3.], 6)?));
    assert!(matches!(ScalarExecutor::run(imported.graph(), &inputs, ExecBudget::unlimited(), &ScalarExecCx::new()),
        Err(ExecError::GenerationMismatch { .. })));
    inputs.pop();
    inputs.push(("image".into(), Tensor::from_values(Shape::new(vec![1, 2])?, &[2_f32, 3.], 7)?));
    assert!(matches!(ScalarExecutor::run(imported.graph(), &inputs, ExecBudget::new(0, 0), &ScalarExecCx::new()),
        Err(ExecError::BudgetExceeded { .. })));
    Ok(())
}
