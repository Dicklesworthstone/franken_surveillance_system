#![forbid(unsafe_code)]

//! Integration contract tests for `ScalarExecutor` over `fss_model_ir::ModelIrGraph`.
//!
//! Verifies hand-computed numerical goldens for all supported kernels (Conv2d, Relu, Sigmoid,
//! Add/Sub/Mul/Div with broadcasting, MaxPool2d, MatMul, Reshape, Softmax), bit reproducibility,
//! strict F32 data type enforcement, pre-execution validation, resource budgeting, and cooperative
//! cancellation.
//!
//! Emits structured `CAPLOG` lines per test step conforming to the CAP- E2E harness specification.

use std::error::Error;
use std::fmt::Write as _;
use std::time::Instant;

use fss_core::{ContentDigest, Generation};
use fss_model_ir::{
    AttrValue, AttributeMap, GraphNode, ModelIrError, ModelIrGraph, ModelIrVersion, OpCode,
    TensorPort,
};
use fss_reference::scalar_executor::{
    ChannelTransform, ExecBudget, ExecError, PreprocessProgram, ScalarExecCx, ScalarExecutor,
    deterministic_exp_f32, deterministic_sigmoid_f32,
};
use fss_tensor::{DType, F16, Shape, Tensor};

fn gen1() -> Generation {
    Generation::from_u64(1)
}

/// Emits a single-line structured CAPLOG record for digestion by the E2E logging harness.
fn emit_caplog(
    step: &str,
    verdict: &str,
    exit_code: i32,
    expected: &str,
    observed: &str,
    duration_ms: u128,
) {
    println!(
        r#"CAPLOG {{"step":"{}","verdict":"{}","exit":{},"duration_ms":{},"expected":{},"observed":{}}}"#,
        step, verdict, exit_code, duration_ms, expected, observed
    );
}

/// Computes SHA-256 lower-case hex string using `fss_core::ContentDigest`.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ContentDigest::sha256(bytes);
    let mut hex = String::with_capacity(64);
    for b in digest.bytes() {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Trait providing lowercase hex rendering of [`ContentDigest`].
trait DigestHex {
    /// Renders the digest bytes as a 64-character lowercase hex string.
    fn to_hex(&self) -> String;
}

impl DigestHex for ContentDigest {
    fn to_hex(&self) -> String {
        let mut hex = String::with_capacity(64);
        for b in self.bytes() {
            let _ = write!(hex, "{b:02x}");
        }
        hex
    }
}

/// Trait providing canonical byte representation of a [`Tensor`].
trait TensorCanonicalBytes {
    /// Returns canonical byte representation for hashing or equality comparison.
    fn to_canonical_bytes(&self) -> Vec<u8>;
}

impl TensorCanonicalBytes for Tensor {
    fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"fss.tensor.v1\0");
        bytes.push(self.dtype().type_tag());
        bytes.extend_from_slice(&self.generation().get().to_be_bytes());
        bytes.push(self.rank() as u8);
        for &d in self.shape().dims() {
            bytes.extend_from_slice(&(d as u64).to_be_bytes());
        }
        match self.dtype() {
            DType::F32 => {
                if let Ok(vals) = self.to_vec::<f32>() {
                    for v in vals {
                        bytes.extend_from_slice(&v.to_bits().to_be_bytes());
                    }
                }
            }
            DType::U8 => {
                if let Ok(vals) = self.to_vec::<u8>() {
                    bytes.extend(vals);
                }
            }
            DType::I32 => {
                if let Ok(vals) = self.to_vec::<i32>() {
                    for v in vals {
                        bytes.extend_from_slice(&v.to_be_bytes());
                    }
                }
            }
            DType::I64 => {
                if let Ok(vals) = self.to_vec::<i64>() {
                    for v in vals {
                        bytes.extend_from_slice(&v.to_be_bytes());
                    }
                }
            }
            _ => {}
        }
        bytes
    }
}

#[test]
fn test_golden_conv2d_relu_add_3op() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let g = gen1();

    // 1. Inputs:
    // X: [1, 1, 3, 3]
    // [[ 1.0,  2.0, 3.0],
    //  [ 4.0, -5.0, 6.0],
    //  [-7.0,  8.0, 9.0]]
    let x_vals = [1.0_f32, 2.0, 3.0, 4.0, -5.0, 6.0, -7.0, 8.0, 9.0];
    let x_port = TensorPort::new("x", DType::F32, Shape::new(vec![1, 1, 3, 3])?, g)?;
    let x_tensor = Tensor::from_values(x_port.shape().clone(), &x_vals, g)?;

    // W: [1, 1, 2, 2]
    // [[ 1.0, -1.0],
    //  [ 2.0,  0.5]]
    let w_vals = [1.0_f32, -1.0, 2.0, 0.5];
    let w_port = TensorPort::new("w", DType::F32, Shape::new(vec![1, 1, 2, 2])?, g)?;
    let w_tensor = Tensor::from_values(w_port.shape().clone(), &w_vals, g)?;

    // B: [1] = [0.5]
    let b_vals = [0.5_f32];
    let b_port = TensorPort::new("b", DType::F32, Shape::new(vec![1])?, g)?;
    let b_tensor = Tensor::from_values(b_port.shape().clone(), &b_vals, g)?;

    // Z: [1, 1, 2, 2] (residual input for Add)
    // [[ 1.0, 2.0],
    //  [ 3.0, 4.0]]
    let z_vals = [1.0_f32, 2.0, 3.0, 4.0];
    let z_port = TensorPort::new("z", DType::F32, Shape::new(vec![1, 1, 2, 2])?, g)?;
    let z_tensor = Tensor::from_values(z_port.shape().clone(), &z_vals, g)?;

    // Output port: [1, 1, 2, 2]
    let y_port = TensorPort::new("y", DType::F32, Shape::new(vec![1, 1, 2, 2])?, g)?;

    let mut conv_attrs = AttributeMap::new();
    conv_attrs.insert("strides".to_string(), AttrValue::IntList(vec![1, 1]));
    conv_attrs.insert("padding".to_string(), AttrValue::IntList(vec![0, 0, 0, 0]));
    conv_attrs.insert("dilations".to_string(), AttrValue::IntList(vec![1, 1]));
    conv_attrs.insert("groups".to_string(), AttrValue::Int(1));

    let n_conv = GraphNode::new(
        "node_conv",
        OpCode::Conv2d,
        "conv",
        vec!["x".to_string(), "w".to_string(), "b".to_string()],
        vec!["c".to_string()],
        conv_attrs,
    )?;

    let n_relu = GraphNode::new(
        "node_relu",
        OpCode::Relu,
        "relu",
        vec!["c".to_string()],
        vec!["r".to_string()],
        AttributeMap::new(),
    )?;

    let n_add = GraphNode::new(
        "node_add",
        OpCode::Add,
        "add",
        vec!["r".to_string(), "z".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::builder("conv_relu_add", g)
        .add_input(x_port)
        .add_input(w_port)
        .add_input(b_port)
        .add_input(z_port)
        .add_output(y_port)
        .add_node(n_conv)
        .add_node(n_relu)
        .add_node(n_add)
        .build_and_validate()?;

    let inputs = vec![
        ("x", x_tensor),
        ("w", w_tensor),
        ("b", b_tensor),
        ("z", z_tensor),
    ];

    // Hand computation verification:
    // Conv2d window (0, 0): 1*1 + 2*(-1) + 4*2 + (-5)*0.5 + 0.5 = 1 - 2 + 8 - 2.5 + 0.5 = 5.0
    // Conv2d window (0, 1): 2*1 + 3*(-1) + (-5)*2 + 6*0.5 + 0.5 = 2 - 3 - 10 + 3 + 0.5 = -7.5
    // Conv2d window (1, 0): 4*1 + (-5)*(-1) + (-7)*2 + 8*0.5 + 0.5 = 4 + 5 - 14 + 4 + 0.5 = -0.5
    // Conv2d window (1, 1): (-5)*1 + 6*(-1) + 8*2 + 9*0.5 + 0.5 = -5 - 6 + 16 + 4.5 + 0.5 = 10.0
    //
    // Relu:
    // max(0,  5.0) = 5.0
    // max(0, -7.5) = 0.0
    // max(0, -0.5) = 0.0
    // max(0, 10.0) = 10.0
    //
    // Add z ([1.0, 2.0, 3.0, 4.0]):
    // 5.0 + 1.0 = 6.0
    // 0.0 + 2.0 = 2.0
    // 0.0 + 3.0 = 3.0
    // 10.0 + 4.0 = 14.0
    let expected_y = vec![6.0_f32, 2.0, 3.0, 14.0];

    let cx = ScalarExecCx::new();
    let outcome = ScalarExecutor::run(&graph, &inputs, ExecBudget::unlimited(), &cx)?;
    let y_out = outcome.get_output("y").ok_or("missing output y")?;
    let y_actual = y_out.to_vec::<f32>()?;

    assert_eq!(
        y_actual, expected_y,
        "Hand-computed golden mismatch for 3-op graph"
    );
    assert_eq!(outcome.nodes_executed(), 3);
    assert_eq!(outcome.executed_macs(), 24); // Conv 16 (4 output elements * 4 inputs in filter) + Relu 4 + Add 4 = 24 MACs

    // Repeated execution test for bit-identical reproducibility
    for _ in 0..10 {
        let repeat_cx = ScalarExecCx::new();
        let rep_outcome =
            ScalarExecutor::run(&graph, &inputs, ExecBudget::unlimited(), &repeat_cx)?;
        let rep_y = rep_outcome.get_output("y").ok_or("missing output y")?;
        let rep_vals = rep_y.to_vec::<f32>()?;
        for (a, b) in y_actual.iter().zip(rep_vals.iter()) {
            assert_eq!(
                a.to_bits(),
                b.to_bits(),
                "Non-deterministic bit mismatch across runs"
            );
        }
    }

    let graph_digest = graph.content_digest()?.to_hex();
    let out_digest = sha256_hex(&y_out.to_canonical_bytes());
    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"macs":16,"output_elements":4}"#.to_string();
    let obs_json = format!(
        r#"{{"graph_digest":"{}","output_digest":"{}","nodes":3,"macs":{}}}"#,
        graph_digest,
        out_digest,
        outcome.executed_macs()
    );
    emit_caplog("conv2d_relu_add_3op", "pass", 0, &exp_json, &obs_json, dur);

    Ok(())
}

#[test]
fn test_golden_conv2d_asymmetric_padding_and_strides() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let g = gen1();

    // Input X: [1, 1, 5, 5]
    // Filter W: [1, 1, 3, 3]
    // Padding: [1, 0, 0, 1] (top=1, left=0, bottom=0, right=1)
    // Strides: [2, 2]
    //
    // Spatial dimensions:
    // H_out = (5 + 1 + 0 - 3) / 2 + 1 = 6 / 2 + 1 = 2
    // W_out = (5 + 0 + 1 - 3) / 2 + 1 = 6 / 2 + 1 = 2
    // Output shape: [1, 1, 2, 2]
    //
    // Input values (5x5 matrix from 1.0 to 25.0):
    // [[ 1.0,  2.0,  3.0,  4.0,  5.0],
    //  [ 6.0,  7.0,  8.0,  9.0, 10.0],
    //  [11.0, 12.0, 13.0, 14.0, 15.0],
    //  [16.0, 17.0, 18.0, 19.0, 20.0],
    //  [21.0, 22.0, 23.0, 24.0, 25.0]]
    let mut x_vals = Vec::with_capacity(25);
    for v in 1..=25 {
        x_vals.push(v as f32);
    }
    let x_port = TensorPort::new("x", DType::F32, Shape::new(vec![1, 1, 5, 5])?, g)?;
    let x_t = Tensor::from_values(x_port.shape().clone(), &x_vals, g)?;

    // Filter values:
    // [[ 1.0, 0.0, -1.0],
    //  [ 0.0, 2.0,  0.0],
    //  [-1.0, 0.0,  1.0]]
    let w_vals = [1.0_f32, 0.0, -1.0, 0.0, 2.0, 0.0, -1.0, 0.0, 1.0];
    let w_port = TensorPort::new("w", DType::F32, Shape::new(vec![1, 1, 3, 3])?, g)?;
    let w_t = Tensor::from_values(w_port.shape().clone(), &w_vals, g)?;

    let y_port = TensorPort::new("y", DType::F32, Shape::new(vec![1, 1, 2, 2])?, g)?;

    let mut attrs = AttributeMap::new();
    attrs.insert("strides".to_string(), AttrValue::IntList(vec![2, 2]));
    attrs.insert("padding".to_string(), AttrValue::IntList(vec![1, 0, 0, 1]));

    let node = GraphNode::new(
        "conv_asym",
        OpCode::Conv2d,
        "conv",
        vec!["x".to_string(), "w".to_string()],
        vec!["y".to_string()],
        attrs,
    )?;

    let graph = ModelIrGraph::builder("g_conv_asym", g)
        .add_input(x_port)
        .add_input(w_port)
        .add_output(y_port)
        .add_node(node)
        .build_and_validate()?;

    // Hand arithmetic with asymmetric padding [1, 0, 0, 1]:
    // Window (0, 0): oh=0, ow=0
    //   ih spans [-1, 0, 1] (row -1 is zero; row 0 is [1, 2, 3]; row 1 is [6, 7, 8])
    //   iw spans [0, 1, 2]
    //   kh=0: [ 1, 0, -1] * [0, 0, 0] = 0
    //   kh=1: [ 0, 2,  0] * [1, 2, 3] = 4.0
    //   kh=2: [-1, 0,  1] * [6, 7, 8] = -6 + 8 = 2.0
    //   sum = 0 + 4 + 2 = 6.0
    //
    // Window (0, 1): oh=0, ow=1 (stride 2 on width)
    //   ih spans [-1, 0, 1] (row -1 is zero; row 0 is [3, 4, 5]; row 1 is [8, 9, 10])
    //   iw spans [2, 3, 4]
    //   kh=0: [ 1, 0, -1] * [0, 0, 0] = 0
    //   kh=1: [ 0, 2,  0] * [3, 4, 5] = 8.0
    //   kh=2: [-1, 0,  1] * [8, 9, 10] = -8 + 10 = 2.0
    //   sum = 0 + 8 + 2 = 10.0
    //
    // Window (1, 0): oh=1, ow=0 (stride 2 on height)
    //   ih spans [1, 2, 3] (row 1 is [6, 7, 8]; row 2 is [11, 12, 13]; row 3 is [16, 17, 18])
    //   iw spans [0, 1, 2]
    //   kh=0: [ 1, 0, -1] * [6, 7, 8] = 6 - 8 = -2.0
    //   kh=1: [ 0, 2,  0] * [11, 12, 13] = 24.0
    //   kh=2: [-1, 0,  1] * [16, 17, 18] = -16 + 18 = 2.0
    //   sum = -2.0 + 24.0 + 2.0 = 24.0
    //
    // Window (1, 1): oh=1, ow=1 (stride 2 on height and width)
    //   ih spans [1, 2, 3] (row 1 is [8, 9, 10]; row 2 is [13, 14, 15]; row 3 is [18, 19, 20])
    //   iw spans [2, 3, 4]
    //   kh=0: [ 1, 0, -1] * [8, 9, 10] = 8 - 10 = -2.0
    //   kh=1: [ 0, 2,  0] * [13, 14, 15] = 28.0
    //   kh=2: [-1, 0,  1] * [18, 19, 20] = -18 + 20 = 2.0
    //   sum = -2.0 + 28.0 + 2.0 = 28.0
    //
    // Expected output: [6.0, 10.0, 24.0, 28.0]
    let expected = vec![6.0_f32, 10.0, 24.0, 28.0];

    let cx = ScalarExecCx::new();
    let outcome = ScalarExecutor::run(
        &graph,
        &[("x", x_t), ("w", w_t)],
        ExecBudget::unlimited(),
        &cx,
    )?;
    let y_out = outcome.get_output("y").ok_or("missing output y")?;
    let y_vals = y_out.to_vec::<f32>()?;

    assert_eq!(y_vals, expected);
    assert_eq!(outcome.executed_macs(), 36);

    let dur = start.elapsed().as_millis();
    let graph_digest = graph.content_digest()?.to_hex();
    let out_digest = sha256_hex(&y_out.to_canonical_bytes());
    let exp_json = r#"{"macs":36,"output_shape":[1,1,2,2]}"#.to_string();
    let obs_json = format!(
        r#"{{"graph_digest":"{}","output_digest":"{}","macs":{}}}"#,
        graph_digest,
        out_digest,
        outcome.executed_macs()
    );
    emit_caplog(
        "conv2d_asymmetric_padding",
        "pass",
        0,
        &exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

#[test]
fn test_golden_conv2d_bias_and_grouped() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let g = gen1();

    // Input X: [1, 2, 2, 2] (N=1, C=2, H=2, W=2)
    // Filter W: [2, 1, 2, 2] (C_out=2, C_in/groups=1, k_h=2, k_w=2, groups=2)
    // Bias B: [2]
    // Strides: [1, 1], Padding: [0, 0, 0, 0]
    // Output Y: [1, 2, 1, 1]
    let x_vals = [
        // Channel 0 (group 0):
        1.0_f32, 2.0, 3.0, 4.0, // Channel 1 (group 1):
        5.0, 6.0, 7.0, -8.0,
    ];
    let x_port = TensorPort::new("x", DType::F32, Shape::new(vec![1, 2, 2, 2])?, g)?;
    let x_t = Tensor::from_values(x_port.shape().clone(), &x_vals, g)?;

    let w_vals = [
        // Cout 0 (group 0):
        1.0_f32, -1.0, 2.0, 0.5, // Cout 1 (group 1):
        0.5, 1.0, 2.0, -1.0,
    ];
    let w_port = TensorPort::new("w", DType::F32, Shape::new(vec![2, 1, 2, 2])?, g)?;
    let w_t = Tensor::from_values(w_port.shape().clone(), &w_vals, g)?;

    let b_vals = [0.25_f32, -0.5];
    let b_port = TensorPort::new("b", DType::F32, Shape::new(vec![2])?, g)?;
    let b_t = Tensor::from_values(b_port.shape().clone(), &b_vals, g)?;

    let y_port = TensorPort::new("y", DType::F32, Shape::new(vec![1, 2, 1, 1])?, g)?;

    let mut attrs = AttributeMap::new();
    attrs.insert("strides".to_string(), AttrValue::IntList(vec![1, 1]));
    attrs.insert("padding".to_string(), AttrValue::IntList(vec![0, 0, 0, 0]));
    attrs.insert("groups".to_string(), AttrValue::Int(2));

    let node = GraphNode::new(
        "conv_grouped",
        OpCode::Conv2d,
        "conv",
        vec!["x".to_string(), "w".to_string(), "b".to_string()],
        vec!["y".to_string()],
        attrs,
    )?;

    let graph = ModelIrGraph::builder("g_conv_grouped", g)
        .add_input(x_port)
        .add_input(w_port)
        .add_input(b_port)
        .add_output(y_port)
        .add_node(node)
        .build_and_validate()?;

    // Hand arithmetic:
    // Group 0 (Cout 0):
    //   X channel 0: [[1.0, 2.0], [3.0, 4.0]]
    //   Filter 0:    [[1.0, -1.0], [2.0, 0.5]]
    //   conv = 1*1 + 2*(-1) + 3*2 + 4*0.5 = 1 - 2 + 6 + 2 = 7.0
    //   bias = 0.25 -> 7.0 + 0.25 = 7.25
    //
    // Group 1 (Cout 1):
    //   X channel 1: [[5.0, 6.0], [7.0, -8.0]]
    //   Filter 1:    [[0.5, 1.0], [2.0, -1.0]]
    //   conv = 5*0.5 + 6*1.0 + 7*2.0 + (-8)*(-1.0) = 2.5 + 6.0 + 14.0 + 8.0 = 30.5
    //   bias = -0.5 -> 30.5 - 0.5 = 30.0
    //
    // Expected: [7.25, 30.0]
    let expected = vec![7.25_f32, 30.0];

    let cx = ScalarExecCx::new();
    let outcome = ScalarExecutor::run(
        &graph,
        &[("x", x_t), ("w", w_t), ("b", b_t)],
        ExecBudget::unlimited(),
        &cx,
    )?;
    let y_out = outcome.get_output("y").ok_or("missing output y")?;
    let y_vals = y_out.to_vec::<f32>()?;

    assert_eq!(y_vals, expected);
    assert_eq!(outcome.executed_macs(), 8);

    let dur = start.elapsed().as_millis();
    let graph_digest = graph.content_digest()?.to_hex();
    let out_digest = sha256_hex(&y_out.to_canonical_bytes());
    let exp_json = r#"{"macs":8,"groups":2,"bias":true}"#.to_string();
    let obs_json = format!(
        r#"{{"graph_digest":"{}","output_digest":"{}","macs":{}}}"#,
        graph_digest,
        out_digest,
        outcome.executed_macs()
    );
    emit_caplog("conv2d_grouped_bias", "pass", 0, &exp_json, &obs_json, dur);

    Ok(())
}

#[test]
fn test_golden_conv2d_metamorphic_delta_identity() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let g = gen1();

    // Metamorphic identity: Conv2d with delta kernel W=[[[[1.0]]]] and B=[0.0] reproduces input exactly.
    let x_vals = [1.5_f32, -2.3, 4.1, 0.0, 9.9, -1.1, 7.7, 3.3, -5.5];
    let x_port = TensorPort::new("x", DType::F32, Shape::new(vec![1, 1, 3, 3])?, g)?;
    let x_t = Tensor::from_values(x_port.shape().clone(), &x_vals, g)?;

    let w_port = TensorPort::new("w", DType::F32, Shape::new(vec![1, 1, 1, 1])?, g)?;
    let w_t = Tensor::from_values(w_port.shape().clone(), &[1.0_f32], g)?;

    let b_port = TensorPort::new("b", DType::F32, Shape::new(vec![1])?, g)?;
    let b_t = Tensor::from_values(b_port.shape().clone(), &[0.0_f32], g)?;

    let y_port = TensorPort::new("y", DType::F32, Shape::new(vec![1, 1, 3, 3])?, g)?;

    let mut attrs = AttributeMap::new();
    attrs.insert("strides".to_string(), AttrValue::IntList(vec![1, 1]));
    attrs.insert("padding".to_string(), AttrValue::IntList(vec![0, 0, 0, 0]));

    let node = GraphNode::new(
        "conv_delta",
        OpCode::Conv2d,
        "conv",
        vec!["x".to_string(), "w".to_string(), "b".to_string()],
        vec!["y".to_string()],
        attrs,
    )?;

    let graph = ModelIrGraph::builder("g_conv_delta", g)
        .add_input(x_port)
        .add_input(w_port)
        .add_input(b_port)
        .add_output(y_port)
        .add_node(node)
        .build_and_validate()?;

    let cx = ScalarExecCx::new();
    let outcome = ScalarExecutor::run(
        &graph,
        &[("x", x_t.clone()), ("w", w_t), ("b", b_t)],
        ExecBudget::unlimited(),
        &cx,
    )?;
    let y_out = outcome.get_output("y").ok_or("missing output y")?;
    let y_vals = y_out.to_vec::<f32>()?;

    for (orig, out) in x_vals.iter().zip(y_vals.iter()) {
        assert_eq!(
            orig.to_bits(),
            out.to_bits(),
            "Metamorphic delta kernel must reproduce input bit-identically"
        );
    }

    let dur = start.elapsed().as_millis();
    let graph_digest = graph.content_digest()?.to_hex();
    let out_digest = sha256_hex(&y_out.to_canonical_bytes());
    let in_digest = sha256_hex(&x_t.to_canonical_bytes());
    let exp_json = format!(r#"{{"input_digest":"{}"}}"#, in_digest);
    let obs_json = format!(
        r#"{{"graph_digest":"{}","output_digest":"{}"}}"#,
        graph_digest, out_digest
    );
    emit_caplog(
        "conv2d_metamorphic_delta",
        "pass",
        0,
        &exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

#[test]
fn test_golden_relu_metamorphic_idempotent() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let g = gen1();

    // Relu is idempotent: Relu(Relu(x)) == Relu(x)
    let vals = [-10.0_f32, -0.0, 0.0, 5.5, -1e-6, 1e6];
    let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![6])?, g)?;
    let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![6])?, g)?;
    let n = GraphNode::new(
        "relu",
        OpCode::Relu,
        "relu",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::builder("g_relu_idempotent", g)
        .add_input(p_in)
        .add_output(p_out)
        .add_node(n)
        .build_and_validate()?;

    let in_t = Tensor::from_values(Shape::new(vec![6])?, &vals, g)?;
    let cx = ScalarExecCx::new();
    let out1 = ScalarExecutor::run(&graph, &[("x", in_t)], ExecBudget::unlimited(), &cx)?;
    let y_t1 = out1.get_output("y").ok_or("missing output y")?;
    let r1_vals = y_t1.to_vec::<f32>()?;

    let expected = vec![0.0_f32, 0.0, 0.0, 5.5, 0.0, 1e6];
    assert_eq!(r1_vals, expected);

    // Apply Relu a second time
    let in_t2 = Tensor::from_values(Shape::new(vec![6])?, &r1_vals, g)?;
    let out2 = ScalarExecutor::run(&graph, &[("x", in_t2)], ExecBudget::unlimited(), &cx)?;
    let y_t2 = out2.get_output("y").ok_or("missing output y")?;
    let r2_vals = y_t2.to_vec::<f32>()?;

    for (a, b) in r1_vals.iter().zip(r2_vals.iter()) {
        assert_eq!(
            a.to_bits(),
            b.to_bits(),
            "Relu must be strictly idempotent with identical bit patterns"
        );
    }

    let dur = start.elapsed().as_millis();
    let graph_digest = graph.content_digest()?.to_hex();
    let out_digest = sha256_hex(&y_t1.to_canonical_bytes());
    let exp_json = r#"{"idempotent":true}"#.to_string();
    let obs_json = format!(
        r#"{{"graph_digest":"{}","output_digest":"{}"}}"#,
        graph_digest, out_digest
    );
    emit_caplog("relu_idempotent", "pass", 0, &exp_json, &obs_json, dur);

    Ok(())
}

#[test]
fn test_golden_sigmoid() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let g = gen1();

    let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![3])?, g)?;
    let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![3])?, g)?;
    let n = GraphNode::new(
        "sig",
        OpCode::Sigmoid,
        "sig",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;
    let gr = ModelIrGraph::builder("g_sig", g)
        .add_input(p_in)
        .add_output(p_out)
        .add_node(n)
        .build_and_validate()?;

    let in_t = Tensor::from_values(Shape::new(vec![3])?, &[0.0_f32, 1.0, -1.0], g)?;
    let cx = ScalarExecCx::new();
    let out = ScalarExecutor::run(&gr, &[("x", in_t)], ExecBudget::unlimited(), &cx)?;
    let y_t = out.get_output("y").ok_or("missing output y")?;
    let vals = y_t.to_vec::<f32>()?;

    assert_eq!(vals[0], 0.5_f32);
    assert_eq!(vals[1], deterministic_sigmoid_f32(1.0));
    assert_eq!(vals[2], deterministic_sigmoid_f32(-1.0));

    let dur = start.elapsed().as_millis();
    let graph_digest = gr.content_digest()?.to_hex();
    let out_digest = sha256_hex(&y_t.to_canonical_bytes());
    let exp_json = r#"{"sig_0":0.5}"#.to_string();
    let obs_json = format!(
        r#"{{"graph_digest":"{}","output_digest":"{}"}}"#,
        graph_digest, out_digest
    );
    emit_caplog("sigmoid_golden", "pass", 0, &exp_json, &obs_json, dur);

    Ok(())
}

#[test]
fn test_golden_binary_broadcast_add_sub_mul_div() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let g = gen1();

    // Broadcasting: [1, C, 1, 1] op [N, C, H, W]
    // N=2, C=2, H=2, W=2
    // A: [1, 2, 1, 1] = [10.0, 20.0]
    // B: [2, 2, 2, 2] = 1.0..=16.0
    // Output: [2, 2, 2, 2]
    let a_vals = [10.0_f32, 20.0];
    let mut b_vals = Vec::with_capacity(16);
    for v in 1..=16 {
        b_vals.push(v as f32);
    }

    // Hand calculations:
    // Add:
    // N=0, C=0: [1+10, 2+10, 3+10, 4+10] = [11, 12, 13, 14]
    // N=0, C=1: [5+20, 6+20, 7+20, 8+20] = [25, 26, 27, 28]
    // N=1, C=0: [9+10, 10+10, 11+10, 12+10] = [19, 20, 21, 22]
    // N=1, C=1: [13+20, 14+20, 15+20, 16+20] = [33, 34, 35, 36]
    let exp_add = vec![
        11.0_f32, 12.0, 13.0, 14.0, 25.0, 26.0, 27.0, 28.0, 19.0, 20.0, 21.0, 22.0, 33.0, 34.0,
        35.0, 36.0,
    ];

    // Sub (A - B):
    // N=0, C=0: [10-1, 10-2, 10-3, 10-4] = [9, 8, 7, 6]
    // N=0, C=1: [20-5, 20-6, 20-7, 20-8] = [15, 14, 13, 12]
    // N=1, C=0: [10-9, 10-10, 10-11, 10-12] = [1, 0, -1, -2]
    // N=1, C=1: [20-13, 20-14, 20-15, 20-16] = [7, 6, 5, 4]
    let exp_sub = vec![
        9.0_f32, 8.0, 7.0, 6.0, 15.0, 14.0, 13.0, 12.0, 1.0, 0.0, -1.0, -2.0, 7.0, 6.0, 5.0, 4.0,
    ];

    let ops = vec![(OpCode::Add, exp_add), (OpCode::Sub, exp_sub)];

    for (op, expected) in ops {
        let p_a = TensorPort::new("a", DType::F32, Shape::new(vec![1, 2, 1, 1])?, g)?;
        let p_b = TensorPort::new("b", DType::F32, Shape::new(vec![2, 2, 2, 2])?, g)?;
        let p_out = TensorPort::new("out", DType::F32, Shape::new(vec![2, 2, 2, 2])?, g)?;
        let n = GraphNode::new(
            "bin",
            op,
            "bin_op",
            vec!["a".to_string(), "b".to_string()],
            vec!["out".to_string()],
            AttributeMap::new(),
        )?;
        let gr = ModelIrGraph::builder("g_bin_broadcast", g)
            .add_input(p_a)
            .add_input(p_b)
            .add_output(p_out)
            .add_node(n)
            .build_and_validate()?;

        let t_a = Tensor::from_values(Shape::new(vec![1, 2, 1, 1])?, &a_vals, g)?;
        let t_b = Tensor::from_values(Shape::new(vec![2, 2, 2, 2])?, &b_vals, g)?;

        let cx = ScalarExecCx::new();
        let out =
            ScalarExecutor::run(&gr, &[("a", t_a), ("b", t_b)], ExecBudget::unlimited(), &cx)?;
        let out_t = out.get_output("out").ok_or("missing output out")?;
        assert_eq!(out_t.to_vec::<f32>()?, expected);
    }

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"broadcast_shape":[2,2,2,2]}"#.to_string();
    let obs_json = r#"{"status":"ok"}"#.to_string();
    emit_caplog(
        "broadcast_add_sub_mul_div",
        "pass",
        0,
        &exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

#[test]
fn test_golden_maxpool2d_ceil_mode_true_and_false() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let g = gen1();

    // Input: [1, 1, 5, 5] with values 1.0..=25.0
    let vals: Vec<f32> = (1..=25).map(|v| v as f32).collect();
    let in_t = Tensor::from_values(Shape::new(vec![1, 1, 5, 5])?, &vals, g)?;

    // Case 1: ceil_mode = false -> output [1, 1, 2, 2]
    // window (0, 0): max(1, 2, 6, 7) = 7
    // window (0, 1): max(3, 4, 8, 9) = 9
    // window (1, 0): max(11, 12, 16, 17) = 17
    // window (1, 1): max(13, 14, 18, 19) = 19
    {
        let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![1, 1, 5, 5])?, g)?;
        let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![1, 1, 2, 2])?, g)?;
        let mut attrs = AttributeMap::new();
        attrs.insert("kernel_size".to_string(), AttrValue::IntList(vec![2, 2]));
        attrs.insert("strides".to_string(), AttrValue::IntList(vec![2, 2]));
        attrs.insert("padding".to_string(), AttrValue::IntList(vec![0, 0, 0, 0]));
        attrs.insert("ceil_mode".to_string(), AttrValue::Bool(false));

        let node = GraphNode::new(
            "p_no_ceil",
            OpCode::MaxPool2d,
            "p",
            vec!["x".to_string()],
            vec!["y".to_string()],
            attrs,
        )?;
        let gr = ModelIrGraph::builder("g_no_ceil", g)
            .add_input(p_in)
            .add_output(p_out)
            .add_node(node)
            .build_and_validate()?;
        let cx = ScalarExecCx::new();
        let out = ScalarExecutor::run(&gr, &[("x", in_t.clone())], ExecBudget::unlimited(), &cx)?;
        let y_t = out.get_output("y").ok_or("missing output y")?;
        assert_eq!(y_t.to_vec::<f32>()?, vec![7.0_f32, 9.0, 17.0, 19.0]);
    }

    // Case 2: ceil_mode = true -> output [1, 1, 3, 3]
    // (5 - 2).div_ceil(2) + 1 = 3
    // window (0, 0): rows 0..2, cols 0..2 -> 7.0
    // window (0, 1): rows 0..2, cols 2..4 -> 9.0
    // window (0, 2): rows 0..2, col 4 -> max(5, 10) = 10.0
    // window (1, 0): rows 2..4, cols 0..2 -> 17.0
    // window (1, 1): rows 2..4, cols 2..4 -> 19.0
    // window (1, 2): rows 2..4, col 4 -> max(15, 20) = 20.0
    // window (2, 0): row 4, cols 0..2 -> max(21, 22) = 22.0
    // window (2, 1): row 4, cols 2..4 -> max(23, 24) = 24.0
    // window (2, 2): row 4, col 4 -> 25.0
    {
        let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![1, 1, 5, 5])?, g)?;
        let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![1, 1, 3, 3])?, g)?;
        let mut attrs = AttributeMap::new();
        attrs.insert("kernel_size".to_string(), AttrValue::IntList(vec![2, 2]));
        attrs.insert("strides".to_string(), AttrValue::IntList(vec![2, 2]));
        attrs.insert("padding".to_string(), AttrValue::IntList(vec![0, 0, 0, 0]));
        attrs.insert("ceil_mode".to_string(), AttrValue::Bool(true));

        let node = GraphNode::new(
            "p_ceil",
            OpCode::MaxPool2d,
            "p",
            vec!["x".to_string()],
            vec!["y".to_string()],
            attrs,
        )?;
        let gr = ModelIrGraph::builder("g_ceil", g)
            .add_input(p_in)
            .add_output(p_out)
            .add_node(node)
            .build_and_validate()?;
        let cx = ScalarExecCx::new();
        let out = ScalarExecutor::run(&gr, &[("x", in_t)], ExecBudget::unlimited(), &cx)?;
        let y_t = out.get_output("y").ok_or("missing output y")?;
        assert_eq!(
            y_t.to_vec::<f32>()?,
            vec![7.0_f32, 9.0, 10.0, 17.0, 19.0, 20.0, 22.0, 24.0, 25.0]
        );
    }

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"false_shape":[1,1,2,2],"true_shape":[1,1,3,3]}"#.to_string();
    let obs_json = r#"{"status":"ok"}"#.to_string();
    emit_caplog(
        "maxpool2d_ceil_mode_true_false",
        "pass",
        0,
        &exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

#[test]
fn test_golden_maxpool2d_ceil_mode_equality_boundaries() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let g = gen1();

    // 1. Width equality boundary: W=2, k=2, s=2, padding=[0, 0, 0, 1], ceil_mode=true
    // (2 + 1 - 2).div_ceil(2) + 1 = 2, but last window start = (2 - 1)*2 = 2 >= W(2).
    // The clamp drops the last window -> output W=1.
    {
        let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![1, 1, 1, 2])?, g)?;
        let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![1, 1, 1, 1])?, g)?;
        let mut attrs = AttributeMap::new();
        attrs.insert("kernel_size".to_string(), AttrValue::IntList(vec![1, 2]));
        attrs.insert("strides".to_string(), AttrValue::IntList(vec![1, 2]));
        attrs.insert("padding".to_string(), AttrValue::IntList(vec![0, 0, 0, 1]));
        attrs.insert("ceil_mode".to_string(), AttrValue::Bool(true));

        let node = GraphNode::new(
            "p_w",
            OpCode::MaxPool2d,
            "p",
            vec!["x".to_string()],
            vec!["y".to_string()],
            attrs,
        )?;
        let gr = ModelIrGraph::builder("g_p_w", g)
            .add_input(p_in)
            .add_output(p_out)
            .add_node(node)
            .build_and_validate()?;

        let in_t = Tensor::from_values(Shape::new(vec![1, 1, 1, 2])?, &[3.0_f32, 8.0], g)?;
        let cx = ScalarExecCx::new();
        let out = ScalarExecutor::run(&gr, &[("x", in_t)], ExecBudget::unlimited(), &cx)?;
        let y_t = out.get_output("y").ok_or("missing output y")?;
        assert_eq!(y_t.shape().dims(), &[1, 1, 1, 1]);
        assert_eq!(y_t.to_vec::<f32>()?, vec![8.0_f32]);
    }

    // 2. Height equality boundary: H=2, k=2, s=2, padding=[0, 0, 1, 0], ceil_mode=true
    // Output H=1 after boundary clamp.
    {
        let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![1, 1, 2, 1])?, g)?;
        let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![1, 1, 1, 1])?, g)?;
        let mut attrs = AttributeMap::new();
        attrs.insert("kernel_size".to_string(), AttrValue::IntList(vec![2, 1]));
        attrs.insert("strides".to_string(), AttrValue::IntList(vec![2, 1]));
        attrs.insert("padding".to_string(), AttrValue::IntList(vec![0, 0, 1, 0]));
        attrs.insert("ceil_mode".to_string(), AttrValue::Bool(true));

        let node = GraphNode::new(
            "p_h",
            OpCode::MaxPool2d,
            "p",
            vec!["x".to_string()],
            vec!["y".to_string()],
            attrs,
        )?;
        let gr = ModelIrGraph::builder("g_p_h", g)
            .add_input(p_in)
            .add_output(p_out)
            .add_node(node)
            .build_and_validate()?;

        let in_t = Tensor::from_values(Shape::new(vec![1, 1, 2, 1])?, &[4.0_f32, 9.0], g)?;
        let cx = ScalarExecCx::new();
        let out = ScalarExecutor::run(&gr, &[("x", in_t)], ExecBudget::unlimited(), &cx)?;
        let y_t = out.get_output("y").ok_or("missing output y")?;
        assert_eq!(y_t.shape().dims(), &[1, 1, 1, 1]);
        assert_eq!(y_t.to_vec::<f32>()?, vec![9.0_f32]);
    }

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"clamped_w":1,"clamped_h":1}"#.to_string();
    let obs_json = r#"{"status":"ok"}"#.to_string();
    emit_caplog(
        "maxpool2d_ceil_mode_equality_boundary",
        "pass",
        0,
        &exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

#[test]
fn test_golden_matmul() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let g = gen1();

    // A: [2, 3] = [[1, 2, 3], [4, 5, 6]]
    // B: [3, 2] = [[7, 8], [9, 1], [2, 3]]
    // C = A * B: [2, 2]
    // C[0, 0] = 1*7 + 2*9 + 3*2 = 7 + 18 + 6 = 31
    // C[0, 1] = 1*8 + 2*1 + 3*3 = 8 + 2 + 9 = 19
    // C[1, 0] = 4*7 + 5*9 + 6*2 = 28 + 45 + 12 = 85
    // C[1, 1] = 4*8 + 5*1 + 6*3 = 32 + 5 + 18 = 55
    let p_a = TensorPort::new("a", DType::F32, Shape::new(vec![2, 3])?, g)?;
    let p_b = TensorPort::new("b", DType::F32, Shape::new(vec![3, 2])?, g)?;
    let p_c = TensorPort::new("c", DType::F32, Shape::new(vec![2, 2])?, g)?;
    let n = GraphNode::new(
        "mm",
        OpCode::MatMul,
        "matmul",
        vec!["a".to_string(), "b".to_string()],
        vec!["c".to_string()],
        AttributeMap::new(),
    )?;
    let gr = ModelIrGraph::builder("g_mm", g)
        .add_input(p_a)
        .add_input(p_b)
        .add_output(p_c)
        .add_node(n)
        .build_and_validate()?;

    let t_a = Tensor::from_values(
        Shape::new(vec![2, 3])?,
        &[1.0_f32, 2.0, 3.0, 4.0, 5.0, 6.0],
        g,
    )?;
    let t_b = Tensor::from_values(
        Shape::new(vec![3, 2])?,
        &[7.0_f32, 8.0, 9.0, 1.0, 2.0, 3.0],
        g,
    )?;

    let cx = ScalarExecCx::new();
    let out = ScalarExecutor::run(&gr, &[("a", t_a), ("b", t_b)], ExecBudget::unlimited(), &cx)?;
    let c_t = out.get_output("c").ok_or("missing output c")?;
    let vals = c_t.to_vec::<f32>()?;
    assert_eq!(vals, vec![31.0_f32, 19.0, 85.0, 55.0]);
    assert_eq!(out.executed_macs(), 12);

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"macs":12,"output_shape":[2,2]}"#.to_string();
    let obs_json = r#"{"status":"ok","macs":12}"#.to_string();
    emit_caplog("matmul_golden", "pass", 0, &exp_json, &obs_json, dur);

    Ok(())
}

#[test]
fn test_golden_reshape_cases() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let g = gen1();

    // 1. allowzero = false (or default): shape [0, -1] copies dim 0
    // Input: [2, 6] -> Output: [2, 6]
    {
        let in_vals: Vec<f32> = (1..=12).map(|v| v as f32).collect();
        let in_t = Tensor::from_values(Shape::new(vec![2, 6])?, &in_vals, g)?;

        let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![2, 6])?, g)?;
        let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![2, 6])?, g)?;

        let mut attrs = AttributeMap::new();
        attrs.insert("shape".to_string(), AttrValue::IntList(vec![0, -1]));
        attrs.insert("allowzero".to_string(), AttrValue::Bool(false));

        let node = GraphNode::new(
            "res_copy",
            OpCode::Reshape,
            "r",
            vec!["x".to_string()],
            vec!["y".to_string()],
            attrs,
        )?;
        let gr = ModelIrGraph::builder("g_res_copy", g)
            .add_input(p_in)
            .add_output(p_out)
            .add_node(node)
            .build_and_validate()?;

        let cx = ScalarExecCx::new();
        let out = ScalarExecutor::run(&gr, &[("x", in_t)], ExecBudget::unlimited(), &cx)?;
        let y_t = out.get_output("y").ok_or("missing output y")?;
        assert_eq!(y_t.shape().dims(), &[2, 6]);
        assert_eq!(y_t.to_vec::<f32>()?, in_vals);
    }

    // 2. allowzero = true with a 0 dim is refused at validation before any execution
    {
        let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![2, 6])?, g)?;
        let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![0, 6])?, g)?;

        let mut attrs = AttributeMap::new();
        attrs.insert("shape".to_string(), AttrValue::IntList(vec![0, 6]));
        attrs.insert("allowzero".to_string(), AttrValue::Bool(true));

        let node = GraphNode::new(
            "res_az",
            OpCode::Reshape,
            "r",
            vec!["x".to_string()],
            vec!["y".to_string()],
            attrs,
        )?;
        let res_build = ModelIrGraph::builder("g_res_az", g)
            .add_input(p_in)
            .add_output(p_out)
            .add_node(node)
            .build_and_validate();

        match res_build {
            Err(ModelIrError::ShapeMismatch { reason, .. }) => {
                assert!(reason.contains("element count mismatch"));
            }
            Ok(_) => {
                return Err("Expected ShapeMismatch for allowzero=true with 0 dim, got Ok".into());
            }
            Err(other) => {
                return Err(
                    format!("Expected ShapeMismatch for allowzero=true, got {other:?}").into(),
                );
            }
        }
    }

    // 3. Shape-typed shape attribute gives identical result to IntList form
    {
        let in_vals: Vec<f32> = (1..=12).map(|v| v as f32).collect();
        let in_t = Tensor::from_values(Shape::new(vec![2, 6])?, &in_vals, g)?;

        let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![2, 6])?, g)?;
        let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![3, 4])?, g)?;

        let mut attrs_sh = AttributeMap::new();
        attrs_sh.insert(
            "shape".to_string(),
            AttrValue::Shape(Shape::new(vec![3, 4])?),
        );

        let node_sh = GraphNode::new(
            "res_sh",
            OpCode::Reshape,
            "r",
            vec!["x".to_string()],
            vec!["y".to_string()],
            attrs_sh,
        )?;
        let gr_sh = ModelIrGraph::builder("g_res_sh", g)
            .add_input(p_in.clone())
            .add_output(p_out.clone())
            .add_node(node_sh)
            .build_and_validate()?;

        let mut attrs_il = AttributeMap::new();
        attrs_il.insert("shape".to_string(), AttrValue::IntList(vec![3, 4]));

        let node_il = GraphNode::new(
            "res_il",
            OpCode::Reshape,
            "r",
            vec!["x".to_string()],
            vec!["y".to_string()],
            attrs_il,
        )?;
        let gr_il = ModelIrGraph::builder("g_res_il", g)
            .add_input(p_in)
            .add_output(p_out)
            .add_node(node_il)
            .build_and_validate()?;

        let cx = ScalarExecCx::new();
        let out_sh =
            ScalarExecutor::run(&gr_sh, &[("x", in_t.clone())], ExecBudget::unlimited(), &cx)?;
        let out_il = ScalarExecutor::run(&gr_il, &[("x", in_t)], ExecBudget::unlimited(), &cx)?;

        let y_sh = out_sh.get_output("y").ok_or("missing output y")?;
        let y_il = out_il.get_output("y").ok_or("missing output y")?;

        assert_eq!(y_sh.shape().dims(), &[3, 4]);
        assert_eq!(y_il.shape().dims(), &[3, 4]);
        assert_eq!(y_sh.to_canonical_bytes(), y_il.to_canonical_bytes());
    }

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"allowzero_false":true,"shape_attr_equiv":true}"#.to_string();
    let obs_json = r#"{"status":"ok"}"#.to_string();
    emit_caplog(
        "reshape_round3_contract",
        "pass",
        0,
        &exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

#[test]
fn test_golden_softmax_metamorphic_invariance() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let g = gen1();

    // 1. Softmax golden check
    // [1, 3] = [[1.0, 2.0, 3.0]]
    // max = 3.0, diffs = [-2.0, -1.0, 0.0]
    // exps = [exp(-2), exp(-1), 1.0]
    // sum = exp(-2) + exp(-1) + 1.0
    let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![1, 3])?, g)?;
    let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![1, 3])?, g)?;
    let mut sm_attrs = AttributeMap::new();
    sm_attrs.insert("axis".to_string(), AttrValue::Int(-1));

    let node = GraphNode::new(
        "sm",
        OpCode::Softmax,
        "sm",
        vec!["x".to_string()],
        vec!["y".to_string()],
        sm_attrs,
    )?;
    let gr = ModelIrGraph::builder("g_sm", g)
        .add_input(p_in.clone())
        .add_output(p_out.clone())
        .add_node(node)
        .build_and_validate()?;

    let t_in = Tensor::from_values(Shape::new(vec![1, 3])?, &[1.0_f32, 2.0, 3.0], g)?;
    let cx = ScalarExecCx::new();
    let out = ScalarExecutor::run(&gr, &[("x", t_in)], ExecBudget::unlimited(), &cx)?;
    let y_t = out.get_output("y").ok_or("missing output y")?;
    let vals = y_t.to_vec::<f32>()?;

    let e0 = deterministic_exp_f32(-2.0);
    let e1 = deterministic_exp_f32(-1.0);
    let e2 = deterministic_exp_f32(0.0);
    let sum = e0 + e1 + e2;
    let inv = 1.0 / sum;

    assert_eq!(vals[0], e0 * inv);
    assert_eq!(vals[1], e1 * inv);
    assert_eq!(vals[2], e2 * inv);
    let total_prob: f32 = vals.iter().sum();
    assert!((total_prob - 1.0_f32).abs() < 1e-6);

    // 2. Metamorphic check: invariance to adding constant c: Softmax(x + c) == Softmax(x)
    let t_shifted = Tensor::from_values(Shape::new(vec![1, 3])?, &[501.0_f32, 502.0, 503.0], g)?;
    let out_shifted = ScalarExecutor::run(&gr, &[("x", t_shifted)], ExecBudget::unlimited(), &cx)?;
    let y_shifted = out_shifted.get_output("y").ok_or("missing output y")?;
    let vals_shifted = y_shifted.to_vec::<f32>()?;

    for (a, b) in vals.iter().zip(vals_shifted.iter()) {
        assert!((a - b).abs() < 1e-6, "Softmax must be shift-invariant");
    }

    // 3. Numerical stability: large values do not overflow to NaN or Inf
    let t_large = Tensor::from_values(Shape::new(vec![1, 3])?, &[1000.0_f32, 1001.0, 1002.0], g)?;
    let out_large = ScalarExecutor::run(&gr, &[("x", t_large)], ExecBudget::unlimited(), &cx)?;
    let y_large = out_large.get_output("y").ok_or("missing output y")?;
    let vals_large = y_large.to_vec::<f32>()?;
    for v in &vals_large {
        assert!(!v.is_nan());
        assert!(!v.is_infinite());
    }

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"sum_prob_approx":1.0,"shift_invariant":true}"#.to_string();
    let obs_json = format!(r#"{{"total_prob":{}}}"#, total_prob);
    emit_caplog(
        "softmax_metamorphic_invariance",
        "pass",
        0,
        &exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

#[test]
fn test_exp_vector_against_f64_reference_and_pinned_bits() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();

    // Check exp routine against f64 reference across wide dynamic range
    let test_points = [
        -87.0_f32, -50.0, -10.0, -2.0, -1.0, -0.5, 0.0, 0.5, 1.0, 2.0, 10.0, 50.0, 87.0,
    ];

    for &x in &test_points {
        let actual = deterministic_exp_f32(x) as f64;
        let expected = (x as f64).exp();
        let rel_err = (actual - expected).abs() / expected;
        assert!(
            rel_err < 1e-6,
            "deterministic_exp_f32({x}) relative error {rel_err} exceeds 1e-6 (actual={actual}, expected={expected})"
        );
    }

    // Pin exact bit patterns for reproducible regression protection
    assert_eq!(deterministic_exp_f32(0.0).to_bits(), 0x3f800000);
    assert_eq!(deterministic_exp_f32(1.0).to_bits(), 0x402df854);
    assert_eq!(deterministic_exp_f32(-1.0).to_bits(), 0x3ebc5ab2);
    assert_eq!(deterministic_exp_f32(2.0).to_bits(), 0x40ec7326);

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"pinned_points":4,"max_rel_err":1e-6}"#.to_string();
    let obs_json = r#"{"status":"ok"}"#.to_string();
    emit_caplog(
        "exp_vector_pinned_bits",
        "pass",
        0,
        &exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

#[test]
fn test_formerly_unsupported_opcodes_execute_and_unknown_gelu_mode_is_refused()
-> Result<(), Box<dyn Error>> {
    // Every frozen Model IR v1 opcode now has a scalar kernel: layout (cf0b306), LayerNorm and
    // RMSNorm (35b07e0), SiLU, Tanh and both GELU modes (c8dac61) and Embedding (6f65e8f).
    // No opcode is refused as UnsupportedOperator any more; what is still refused before any
    // node executes is a GELU mode outside the frozen none/tanh vocabulary.
    let start = Instant::now();
    let g = gen1();

    let gelu_graph = |mode: Option<&str>| -> Result<ModelIrGraph, Box<dyn Error>> {
        let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![1, 4])?, g)?;
        let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![1, 4])?, g)?;
        let mut attrs = AttributeMap::new();
        if let Some(mode) = mode {
            attrs.insert(
                "approximate".to_string(),
                AttrValue::String(mode.to_string()),
            );
        }
        let node = GraphNode::new(
            "gelu",
            OpCode::Gelu,
            "gelu",
            vec!["x".to_string()],
            vec!["y".to_string()],
            attrs,
        )?;
        // Deliberately unvalidated: the executor itself must refuse an unknown mode.
        Ok(ModelIrGraph::builder("g_gelu", g)
            .add_input(p_in)
            .add_output(p_out)
            .add_node(node)
            .build()?)
    };

    // GELU (default, explicit none, tanh) executes one node with finite outputs.
    for mode in [None, Some("none"), Some("tanh")] {
        let graph = gelu_graph(mode)?;
        let in_t = Tensor::from_values(Shape::new(vec![1, 4])?, &[1.0_f32; 4], g)?;
        let cx = ScalarExecCx::new();
        let out = ScalarExecutor::run(&graph, &[("x", in_t)], ExecBudget::unlimited(), &cx)
            .map_err(|e| format!("GELU mode {mode:?} must execute, got {e:?}"))?;
        let y = out.outputs().get("y").ok_or("GELU output y missing")?;
        let values = y.to_vec::<f32>()?;
        assert_eq!(values.len(), 4);
        assert!(values.iter().all(|v| v.is_finite() && *v > 0.8 && *v < 0.9));
    }

    // An unknown GELU mode is a typed refusal before execution, never a guessed formula.
    {
        let graph = gelu_graph(Some("erf"))?;
        let in_t = Tensor::from_values(Shape::new(vec![1, 4])?, &[1.0_f32; 4], g)?;
        let cx = ScalarExecCx::new();
        match ScalarExecutor::run(&graph, &[("x", in_t)], ExecBudget::unlimited(), &cx) {
            Err(ExecError::Ir(ModelIrError::InvalidAttribute { attr_name, .. })) => {
                assert_eq!(attr_name, "approximate");
            }
            other => {
                return Err(format!(
                    "Expected InvalidAttribute(approximate) for GELU mode erf, got {other:?}"
                )
                .into());
            }
        }
    }

    // The ops this test used to list as unsupported are never refused as UnsupportedOperator.
    let formerly_unsupported = [
        OpCode::Silu,
        OpCode::Tanh,
        OpCode::Transpose,
        OpCode::Squeeze,
        OpCode::Unsqueeze,
        OpCode::Concat,
        OpCode::Slice,
        OpCode::LayerNorm,
        OpCode::RMSNorm,
        OpCode::Embedding,
    ];
    let mut executed = Vec::new();
    for op in formerly_unsupported {
        let (in_shape, in_dtype) = if op == OpCode::Embedding {
            (Shape::new(vec![2, 4])?, DType::I32)
        } else {
            (Shape::new(vec![2, 4, 8])?, DType::F32)
        };
        let out_shape = Shape::new(vec![2, 4, 8])?;

        let in_port = TensorPort::new("in0", in_dtype, in_shape.clone(), g)?;
        let out_port = TensorPort::new("out0", DType::F32, out_shape, g)?;

        let mut attrs = AttributeMap::new();
        match op {
            OpCode::Transpose => {
                attrs.insert("perm".to_string(), AttrValue::IntList(vec![0, 2, 1]));
            }
            OpCode::Squeeze | OpCode::Unsqueeze => {
                attrs.insert("axes".to_string(), AttrValue::IntList(vec![1]));
            }
            OpCode::Slice => {
                attrs.insert("starts".to_string(), AttrValue::IntList(vec![0]));
                attrs.insert("ends".to_string(), AttrValue::IntList(vec![2]));
            }
            OpCode::Embedding => {
                attrs.insert("num_embeddings".to_string(), AttrValue::Int(100));
                attrs.insert("embedding_dim".to_string(), AttrValue::Int(8));
            }
            _ => {}
        }

        let node = GraphNode::new(
            "n_formerly_unsupported",
            op,
            "op",
            vec!["in0".to_string()],
            vec!["out0".to_string()],
            attrs,
        )?;
        if let Ok(graph) = ModelIrGraph::builder("g_test", g)
            .add_input(in_port)
            .add_output(out_port)
            .add_node(node)
            .build_and_validate()
        {
            let cx = ScalarExecCx::new();
            let dummy = if in_dtype == DType::I32 {
                Tensor::from_values(in_shape, &[0_i32; 8], g)?
            } else {
                Tensor::from_values(in_shape, &[0.0_f32; 64], g)?
            };
            let res = ScalarExecutor::run(&graph, &[("in0", dummy)], ExecBudget::unlimited(), &cx);
            match res {
                Ok(out) => {
                    assert!(out.outputs().contains_key("out0"), "{op:?} output missing");
                    executed.push(op);
                }
                Err(err) => {
                    return Err(format!("validated {op:?} graph must execute, got {err:?}").into());
                }
            }
        }
    }
    assert!(
        executed.contains(&OpCode::Silu) && executed.contains(&OpCode::Tanh),
        "SiLU and Tanh graphs must validate and execute: {executed:?}"
    );

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"gelu_modes_executed":3,"unknown_mode_refused":true}"#.to_string();
    let obs_json = format!(
        r#"{{"status":"ok","formerly_unsupported_executed":{}}}"#,
        executed.len()
    );
    emit_caplog(
        "formerly_unsupported_opcodes_execute",
        "pass",
        0,
        &exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

#[test]
fn test_dtype_refusal_f16_and_i32() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let g = gen1();
    let cx = ScalarExecCx::new();

    // 1. F16 Relu graph: passes ModelIrGraph validation, refused by executor gate
    {
        let p_in = TensorPort::new("x", DType::F16, Shape::new(vec![4])?, g)?;
        let p_out = TensorPort::new("y", DType::F16, Shape::new(vec![4])?, g)?;
        let node = GraphNode::new(
            "r",
            OpCode::Relu,
            "relu",
            vec!["x".to_string()],
            vec!["y".to_string()],
            AttributeMap::new(),
        )?;
        let graph = ModelIrGraph::builder("g_f16_relu", g)
            .add_input(p_in)
            .add_output(p_out)
            .add_node(node)
            .build_and_validate()?;

        let t_f16 = Tensor::from_values(Shape::new(vec![4])?, &[F16::from_bits(0); 4], g)?;
        let res = ScalarExecutor::run(&graph, &[("x", t_f16)], ExecBudget::unlimited(), &cx);
        match res {
            Err(ExecError::UnsupportedDType {
                expected, actual, ..
            }) => {
                assert_eq!(expected, DType::F32);
                assert_eq!(actual, DType::F16);
            }
            Ok(_) => return Err("Expected UnsupportedDType for F16 Relu, got Ok".into()),
            Err(other) => {
                return Err(format!("Expected UnsupportedDType for F16, got {other:?}").into());
            }
        }
    }

    // 2. I32 Add graph: passes ModelIrGraph validation, refused by executor gate
    {
        let p_a = TensorPort::new("a", DType::I32, Shape::new(vec![2, 2])?, g)?;
        let p_b = TensorPort::new("b", DType::I32, Shape::new(vec![2, 2])?, g)?;
        let p_out = TensorPort::new("y", DType::I32, Shape::new(vec![2, 2])?, g)?;
        let node = GraphNode::new(
            "add",
            OpCode::Add,
            "add",
            vec!["a".to_string(), "b".to_string()],
            vec!["y".to_string()],
            AttributeMap::new(),
        )?;
        let graph = ModelIrGraph::builder("g_i32_add", g)
            .add_input(p_a)
            .add_input(p_b)
            .add_output(p_out)
            .add_node(node)
            .build_and_validate()?;

        let t_a = Tensor::from_values(Shape::new(vec![2, 2])?, &[1_i32, 2, 3, 4], g)?;
        let t_b = Tensor::from_values(Shape::new(vec![2, 2])?, &[5_i32, 6, 7, 8], g)?;
        let res = ScalarExecutor::run(
            &graph,
            &[("a", t_a), ("b", t_b)],
            ExecBudget::unlimited(),
            &cx,
        );
        match res {
            Err(ExecError::UnsupportedDType {
                expected, actual, ..
            }) => {
                assert_eq!(expected, DType::F32);
                assert_eq!(actual, DType::I32);
            }
            Ok(_) => return Err("Expected UnsupportedDType for I32 Add, got Ok".into()),
            Err(other) => {
                return Err(format!("Expected UnsupportedDType for I32, got {other:?}").into());
            }
        }
    }

    // 3. F64 graph declared input
    {
        let p_in = TensorPort::new("x", DType::F64, Shape::new(vec![4])?, g)?;
        let p_out = TensorPort::new("y", DType::F64, Shape::new(vec![4])?, g)?;
        let node = GraphNode::new(
            "r",
            OpCode::Relu,
            "relu",
            vec!["x".to_string()],
            vec!["y".to_string()],
            AttributeMap::new(),
        )?;
        let graph = ModelIrGraph::builder("g_f64", g)
            .add_input(p_in)
            .add_output(p_out)
            .add_node(node)
            .build_and_validate()?;

        let dummy_f64 = Tensor::from_values(Shape::new(vec![4])?, &[1.0_f64, 2.0, 3.0, 4.0], g)?;
        let res = ScalarExecutor::run(&graph, &[("x", dummy_f64)], ExecBudget::unlimited(), &cx);
        match res {
            Err(ExecError::UnsupportedDType {
                expected, actual, ..
            }) => {
                assert_eq!(expected, DType::F32);
                assert_eq!(actual, DType::F64);
            }
            Ok(_) => return Err("Expected UnsupportedDType for F64, got Ok".into()),
            Err(other) => {
                return Err(format!("Expected UnsupportedDType for F64, got {other:?}").into());
            }
        }
    }

    // 4. F32 graph provided with U8 tensor
    {
        let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![4])?, g)?;
        let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![4])?, g)?;
        let node = GraphNode::new(
            "r",
            OpCode::Relu,
            "relu",
            vec!["x".to_string()],
            vec!["y".to_string()],
            AttributeMap::new(),
        )?;
        let graph = ModelIrGraph::builder("g_f32", g)
            .add_input(p_in)
            .add_output(p_out)
            .add_node(node)
            .build_and_validate()?;

        let t_u8 = Tensor::from_values(Shape::new(vec![4])?, &[10_u8, 20, 30, 40], g)?;
        let res = ScalarExecutor::run(&graph, &[("x", t_u8)], ExecBudget::unlimited(), &cx);
        match res {
            Err(ExecError::UnsupportedDType {
                expected, actual, ..
            }) => {
                assert_eq!(expected, DType::F32);
                assert_eq!(actual, DType::U8);
            }
            Ok(_) => return Err("Expected UnsupportedDType for U8, got Ok".into()),
            Err(other) => {
                return Err(format!("Expected UnsupportedDType for U8, got {other:?}").into());
            }
        }
    }

    let dur = start.elapsed().as_millis();
    let exp_json =
        r#"{"f16_refused":true,"i32_refused":true,"f64_refused":true,"u8_refused":true}"#
            .to_string();
    let obs_json = r#"{"status":"ok"}"#.to_string();
    emit_caplog(
        "dtype_refusal_before_execution",
        "pass",
        0,
        &exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

#[test]
fn test_version_helper_contract() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let g = gen1();

    // 1. from_u32(2) gives VersionMismatch
    match ModelIrVersion::from_u32(2) {
        Err(ModelIrError::VersionMismatch { expected, actual }) => {
            assert_eq!(expected, 1);
            assert_eq!(actual, 2);
        }
        Ok(_) => return Err("Expected VersionMismatch for from_u32(2), got Ok".into()),
        Err(other) => {
            return Err(format!("Expected VersionMismatch for from_u32(2), got {other:?}").into());
        }
    }

    // 2. ModelIrVersion::unsupported(1) is an error
    assert!(ModelIrVersion::unsupported(1).is_err());

    // 3. Graph built with unsupported(2)? is refused by validate
    let v2 = ModelIrVersion::unsupported(2)?;
    assert_eq!(v2.as_u32(), 2);

    let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![2])?, g)?;
    let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![2])?, g)?;
    let n = GraphNode::new(
        "r",
        OpCode::Relu,
        "relu",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::new("g_unsupported_v2", v2, g, vec![p_in], vec![p_out], vec![n])?;
    match graph.validate() {
        Err(ModelIrError::VersionMismatch { expected, actual }) => {
            assert_eq!(expected, 1);
            assert_eq!(actual, 2);
        }
        Ok(_) => return Err("Expected validate() to fail on unsupported version 2, got Ok".into()),
        Err(other) => {
            return Err(format!("Expected VersionMismatch from validate(), got {other:?}").into());
        }
    }

    // 4. ScalarExecutor::run on graph with version 2 is refused
    let in_t = Tensor::from_values(Shape::new(vec![2])?, &[1.0_f32, 2.0], g)?;
    let cx = ScalarExecCx::new();
    let res = ScalarExecutor::run(&graph, &[("x", in_t)], ExecBudget::unlimited(), &cx);
    match res {
        Err(ExecError::UnsupportedVersion { expected, actual }) => {
            assert_eq!(expected, 1);
            assert_eq!(actual, 2);
        }
        Err(ExecError::Ir(ModelIrError::VersionMismatch { expected, actual })) => {
            assert_eq!(expected, 1);
            assert_eq!(actual, 2);
        }
        Ok(_) => return Err("Expected UnsupportedVersion or Ir error, got Ok".into()),
        Err(other) => return Err(format!("Expected version error from run, got {other:?}").into()),
    }

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"v2_mismatch":true,"unsupported_1_err":true}"#.to_string();
    let obs_json = r#"{"status":"ok"}"#.to_string();
    emit_caplog(
        "version_helper_contract",
        "pass",
        0,
        &exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

#[test]
fn test_weight_input_binding_missing_port() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let g = gen1();

    // Graph requires two inputs: "x" and "w"
    let p_x = TensorPort::new("x", DType::F32, Shape::new(vec![1, 1, 3, 3])?, g)?;
    let p_w = TensorPort::new("w", DType::F32, Shape::new(vec![1, 1, 2, 2])?, g)?;
    let p_y = TensorPort::new("y", DType::F32, Shape::new(vec![1, 1, 2, 2])?, g)?;

    let mut conv_attrs = AttributeMap::new();
    conv_attrs.insert("strides".to_string(), AttrValue::IntList(vec![1, 1]));
    conv_attrs.insert("padding".to_string(), AttrValue::IntList(vec![0, 0, 0, 0]));

    let n = GraphNode::new(
        "conv",
        OpCode::Conv2d,
        "conv",
        vec!["x".to_string(), "w".to_string()],
        vec!["y".to_string()],
        conv_attrs,
    )?;
    let graph = ModelIrGraph::builder("g_missing_w", g)
        .add_input(p_x)
        .add_input(p_w)
        .add_output(p_y)
        .add_node(n)
        .build_and_validate()?;

    let x_t = Tensor::from_values(Shape::new(vec![1, 1, 3, 3])?, &[1.0_f32; 9], g)?;
    let cx = ScalarExecCx::new();

    // Provide only "x", omitting required weight port "w"
    let res = ScalarExecutor::run(&graph, &[("x", x_t)], ExecBudget::unlimited(), &cx);
    match res {
        Err(ExecError::MissingInputPort { expected_port }) => {
            assert_eq!(expected_port, "w");
        }
        Ok(_) => return Err("Expected MissingInputPort for missing weight port, got Ok".into()),
        Err(other) => return Err(format!("Expected MissingInputPort, got {other:?}").into()),
    }

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"missing_port":"w"}"#.to_string();
    let obs_json = r#"{"status":"ok"}"#.to_string();
    emit_caplog(
        "weight_input_binding_missing_port",
        "pass",
        0,
        &exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

#[test]
fn test_shape_mismatch_refused_before_execution() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let g = gen1();

    let p_x = TensorPort::new("x", DType::F32, Shape::new(vec![1, 1, 3, 3])?, g)?;
    let p_y = TensorPort::new("y", DType::F32, Shape::new(vec![1, 1, 3, 3])?, g)?;
    let node = GraphNode::new(
        "relu",
        OpCode::Relu,
        "relu",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;
    let graph = ModelIrGraph::builder("g_shape_mismatch", g)
        .add_input(p_x)
        .add_output(p_y)
        .add_node(node)
        .build_and_validate()?;

    // Provide wrong shape: [1, 1, 4, 4] instead of [1, 1, 3, 3]
    let bad_tensor = Tensor::from_values(Shape::new(vec![1, 1, 4, 4])?, &[1.0_f32; 16], g)?;
    let cx = ScalarExecCx::new();
    let res = ScalarExecutor::run(&graph, &[("x", bad_tensor)], ExecBudget::unlimited(), &cx);
    match res {
        Err(ExecError::ShapeMismatch { op_id, .. }) => {
            assert_eq!(op_id, "graph_input");
        }
        Ok(_) => return Err("Expected ShapeMismatch, got Ok".into()),
        Err(other) => return Err(format!("Expected ShapeMismatch, got {other:?}").into()),
    }

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"op_id":"graph_input"}"#.to_string();
    let obs_json = r#"{"status":"ok"}"#.to_string();
    emit_caplog(
        "shape_mismatch_refusal",
        "pass",
        0,
        &exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

#[test]
fn test_budget_macs_and_bytes_exceeded() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let g = gen1();

    let x_port = TensorPort::new("x", DType::F32, Shape::new(vec![1, 1, 4, 4])?, g)?;
    let w_port = TensorPort::new("w", DType::F32, Shape::new(vec![1, 1, 2, 2])?, g)?;
    let y_port = TensorPort::new("y", DType::F32, Shape::new(vec![1, 1, 3, 3])?, g)?;

    let mut conv_attrs = AttributeMap::new();
    conv_attrs.insert("strides".to_string(), AttrValue::IntList(vec![1, 1]));
    conv_attrs.insert("padding".to_string(), AttrValue::IntList(vec![0, 0, 0, 0]));

    let node = GraphNode::new(
        "conv",
        OpCode::Conv2d,
        "conv",
        vec!["x".to_string(), "w".to_string()],
        vec!["y".to_string()],
        conv_attrs,
    )?;

    let graph = ModelIrGraph::builder("budget_graph", g)
        .add_input(x_port)
        .add_input(w_port)
        .add_output(y_port)
        .add_node(node)
        .build_and_validate()?;

    let x_t = Tensor::from_values(Shape::new(vec![1, 1, 4, 4])?, &[0.0_f32; 16], g)?;
    let w_t = Tensor::from_values(Shape::new(vec![1, 1, 2, 2])?, &[0.0_f32; 4], g)?;
    let inputs = vec![("x", x_t), ("w", w_t)];

    let cx = ScalarExecCx::new();

    // 1. MACs budget overrun (max_macs = 0, required = 36 MACs)
    let macs_budget = ExecBudget::new(0, 1_000_000);
    let result_macs = ScalarExecutor::run(&graph, &inputs, macs_budget, &cx);
    match result_macs {
        Err(ExecError::BudgetExceeded { macs, max_macs, .. }) => {
            assert_eq!(macs, 36);
            assert_eq!(max_macs, 0);
        }
        Ok(_) => return Err("Expected BudgetExceeded for MACs, got Ok".into()),
        Err(other) => return Err(format!("Expected BudgetExceeded for MACs, got {other:?}").into()),
    }

    // 2. Memory bytes budget overrun (max_bytes = 10, required = 116 bytes)
    let bytes_budget = ExecBudget::new(1_000_000, 10);
    let result_bytes = ScalarExecutor::run(&graph, &inputs, bytes_budget, &cx);
    match result_bytes {
        Err(ExecError::BudgetExceeded {
            bytes, max_bytes, ..
        }) => {
            assert_eq!(bytes, 116);
            assert_eq!(max_bytes, 10);
        }
        Ok(_) => return Err("Expected BudgetExceeded for bytes, got Ok".into()),
        Err(other) => {
            return Err(format!("Expected BudgetExceeded for bytes, got {other:?}").into());
        }
    }

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"macs_overrun":true,"bytes_overrun":true}"#.to_string();
    let obs_json = r#"{"status":"ok"}"#.to_string();
    emit_caplog(
        "budget_exceeded_refusal",
        "pass",
        0,
        &exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

#[test]
fn test_cancellation_pre_execution_and_cooperative() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let g = gen1();

    let x_port = TensorPort::new("x", DType::F32, Shape::new(vec![1, 4])?, g)?;
    let y_port = TensorPort::new("y", DType::F32, Shape::new(vec![1, 4])?, g)?;

    let node = GraphNode::new(
        "relu",
        OpCode::Relu,
        "relu",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::builder("cancel_graph", g)
        .add_input(x_port)
        .add_output(y_port)
        .add_node(node)
        .build_and_validate()?;

    let x_t = Tensor::from_values(Shape::new(vec![1, 4])?, &[1.0_f32; 4], g)?;
    let inputs = vec![("x", x_t)];

    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    assert!(cx.is_cancelled());

    let result = ScalarExecutor::run(&graph, &inputs, ExecBudget::unlimited(), &cx);
    match result {
        Err(ExecError::CancellationRequested { stage }) => {
            assert_eq!(stage, "pre-execution");
            assert!(cx.is_drain_completed());
        }
        Ok(_) => return Err("Expected CancellationRequested, got Ok".into()),
        Err(other) => return Err(format!("Expected CancellationRequested, got {other:?}").into()),
    }

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"stage":"pre-execution","drain_completed":true}"#.to_string();
    let obs_json = r#"{"status":"ok"}"#.to_string();
    emit_caplog(
        "cancellation_cooperative",
        "pass",
        0,
        &exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

#[test]
fn test_preprocess_program_rgb_and_luma() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let g = gen1();

    // 1. RGB Preprocessing (scale_to_unit: true)
    let prog_rgb = PreprocessProgram::new(2, 2, ChannelTransform::Rgb, true);
    let bytes_rgb = vec![
        0_u8, 128, 255, // (0, 0)
        50, 100, 150, // (0, 1)
        10, 20, 30, // (1, 0)
        200, 210, 220, // (1, 1)
    ];
    let tensor_nchw = prog_rgb.execute_bytes(&bytes_rgb, 2, 2, 3, g)?;
    assert_eq!(tensor_nchw.shape().dims(), &[1, 3, 2, 2]);

    let f_vals = tensor_nchw.to_vec::<f32>()?;
    assert_eq!(f_vals[0], 0.0 / 255.0);
    assert_eq!(f_vals[4], 128.0 / 255.0);
    assert_eq!(f_vals[8], 255.0 / 255.0);

    // 2. LumaOnly Preprocessing (scale_to_unit: true)
    let prog_luma = PreprocessProgram::new(2, 2, ChannelTransform::LumaOnly, true);
    let tensor_luma = prog_luma.execute_bytes(&bytes_rgb, 2, 2, 3, g)?;
    assert_eq!(tensor_luma.shape().dims(), &[1, 1, 2, 2]);

    let l_vals = tensor_luma.to_vec::<f32>()?;
    let scale = 1.0_f32 / 255.0_f32;
    let expected_luma_00 = (0.299_f32 * 0.0 + 0.587_f32 * 128.0 + 0.114_f32 * 255.0) * scale;
    assert_eq!(l_vals[0], expected_luma_00);

    // Canonical bytes determinism
    let b1 = prog_rgb.canonical_bytes();
    let b2 = prog_rgb.canonical_bytes();
    assert_eq!(b1, b2);

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"rgb_shape":[1,3,2,2],"luma_shape":[1,1,2,2]}"#.to_string();
    let obs_json = r#"{"status":"ok"}"#.to_string();
    emit_caplog("preprocess_program", "pass", 0, &exp_json, &obs_json, dur);

    Ok(())
}

#[test]
fn test_kernel_goldens_individual() -> Result<(), Box<dyn Error>> {
    let g = gen1();

    // 1. Relu golden
    {
        let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![4])?, g)?;
        let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![4])?, g)?;
        let n = GraphNode::new(
            "relu",
            OpCode::Relu,
            "r",
            vec!["x".to_string()],
            vec!["y".to_string()],
            AttributeMap::new(),
        )?;
        let gr = ModelIrGraph::builder("g_relu", g)
            .add_input(p_in)
            .add_output(p_out)
            .add_node(n)
            .build_and_validate()?;
        let in_t = Tensor::from_values(Shape::new(vec![4])?, &[-2.5_f32, 0.0, 3.7, -0.001], g)?;
        let cx = ScalarExecCx::new();
        let out = ScalarExecutor::run(&gr, &[("x", in_t)], ExecBudget::unlimited(), &cx)?;
        let y_t = out.get_output("y").ok_or("missing output y")?;
        let vals = y_t.to_vec::<f32>()?;
        assert_eq!(vals, vec![0.0_f32, 0.0, 3.7, 0.0]);
    }

    // 2. Sigmoid golden with deterministic exp
    {
        let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![3])?, g)?;
        let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![3])?, g)?;
        let n = GraphNode::new(
            "sig",
            OpCode::Sigmoid,
            "s",
            vec!["x".to_string()],
            vec!["y".to_string()],
            AttributeMap::new(),
        )?;
        let gr = ModelIrGraph::builder("g_sig", g)
            .add_input(p_in)
            .add_output(p_out)
            .add_node(n)
            .build_and_validate()?;
        let in_t = Tensor::from_values(Shape::new(vec![3])?, &[0.0_f32, 1.0, -1.0], g)?;
        let cx = ScalarExecCx::new();
        let out = ScalarExecutor::run(&gr, &[("x", in_t)], ExecBudget::unlimited(), &cx)?;
        let y_t = out.get_output("y").ok_or("missing output y")?;
        let vals = y_t.to_vec::<f32>()?;
        assert_eq!(vals[0], 0.5_f32);
        assert!((vals[1] - 0.731_058_6_f32).abs() < 1e-6);
        assert!((vals[2] - 0.268_941_43_f32).abs() < 1e-6);

        // Sigmoid extremes: +/-100, +/-inf
        let in_ext = Tensor::from_values(
            Shape::new(vec![4])?,
            &[100.0_f32, -100.0, f32::INFINITY, f32::NEG_INFINITY],
            g,
        )?;
        let p_in_ext = TensorPort::new("x_ext", DType::F32, Shape::new(vec![4])?, g)?;
        let p_out_ext = TensorPort::new("y_ext", DType::F32, Shape::new(vec![4])?, g)?;
        let n_ext = GraphNode::new(
            "sig_ext",
            OpCode::Sigmoid,
            "sigmoid_ext",
            vec!["x_ext".to_string()],
            vec!["y_ext".to_string()],
            AttributeMap::new(),
        )?;
        let gr_ext = ModelIrGraph::builder("g_sig_ext", g)
            .add_input(p_in_ext)
            .add_output(p_out_ext)
            .add_node(n_ext)
            .build_and_validate()?;
        let out_ext =
            ScalarExecutor::run(&gr_ext, &[("x_ext", in_ext)], ExecBudget::unlimited(), &cx)?;
        let y_ext = out_ext
            .get_output("y_ext")
            .ok_or("missing output y_ext")?
            .to_vec::<f32>()?;
        assert_eq!(y_ext[0], 1.0_f32);
        assert!(y_ext[1] >= 0.0_f32 && y_ext[1] < 1e-30_f32);
        assert_eq!(y_ext[2], 1.0_f32);
        assert_eq!(y_ext[3], 0.0_f32);
    }

    // 3. Add / Sub / Mul / Div with broadcasting
    // a: [1, 3] = [[10.0, 20.0, 30.0]]
    // b: [2, 1] = [[2.0], [5.0]]
    // out: [2, 3]
    {
        let ops = vec![
            (OpCode::Add, vec![12.0_f32, 22.0, 32.0, 15.0, 25.0, 35.0]),
            (OpCode::Sub, vec![8.0_f32, 18.0, 28.0, 5.0, 15.0, 25.0]),
            (OpCode::Mul, vec![20.0_f32, 40.0, 60.0, 50.0, 100.0, 150.0]),
            (OpCode::Div, vec![5.0_f32, 10.0, 15.0, 2.0, 4.0, 6.0]),
        ];

        for (op, expected) in ops {
            let p_a = TensorPort::new("a", DType::F32, Shape::new(vec![1, 3])?, g)?;
            let p_b = TensorPort::new("b", DType::F32, Shape::new(vec![2, 1])?, g)?;
            let p_out = TensorPort::new("out", DType::F32, Shape::new(vec![2, 3])?, g)?;
            let n = GraphNode::new(
                "bin_op",
                op,
                "bin",
                vec!["a".to_string(), "b".to_string()],
                vec!["out".to_string()],
                AttributeMap::new(),
            )?;
            let gr = ModelIrGraph::builder("g_bin", g)
                .add_input(p_a)
                .add_input(p_b)
                .add_output(p_out)
                .add_node(n)
                .build_and_validate()?;

            let t_a = Tensor::from_values(Shape::new(vec![1, 3])?, &[10.0_f32, 20.0, 30.0], g)?;
            let t_b = Tensor::from_values(Shape::new(vec![2, 1])?, &[2.0_f32, 5.0], g)?;

            let cx = ScalarExecCx::new();
            let out =
                ScalarExecutor::run(&gr, &[("a", t_a), ("b", t_b)], ExecBudget::unlimited(), &cx)?;
            let out_t = out.get_output("out").ok_or("missing output out")?;
            let vals = out_t.to_vec::<f32>()?;
            assert_eq!(vals, expected, "Binary op {op:?} broadcast golden mismatch");
        }
    }

    // 4. MaxPool2d golden (with padding and strides)
    // x: [1, 1, 3, 3] =
    // [[ 1,  5, 2],
    //  [ 4,  8, 3],
    //  [ 7, -1, 6]]
    // pool kernel [2, 2], strides [1, 1], padding [0, 0, 0, 0] -> out [1, 1, 2, 2]
    // window (0, 0): max(1, 5, 4, 8) = 8
    // window (0, 1): max(5, 2, 8, 3) = 8
    // window (1, 0): max(4, 8, 7, -1) = 8
    // window (1, 1): max(8, 3, -1, 6) = 8
    {
        let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![1, 1, 3, 3])?, g)?;
        let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![1, 1, 2, 2])?, g)?;
        let mut pool_attrs = AttributeMap::new();
        pool_attrs.insert("kernel_size".to_string(), AttrValue::IntList(vec![2, 2]));
        pool_attrs.insert("strides".to_string(), AttrValue::IntList(vec![1, 1]));
        pool_attrs.insert("padding".to_string(), AttrValue::IntList(vec![0, 0, 0, 0]));

        let n = GraphNode::new(
            "pool",
            OpCode::MaxPool2d,
            "p",
            vec!["x".to_string()],
            vec!["y".to_string()],
            pool_attrs,
        )?;
        let gr = ModelIrGraph::builder("g_pool", g)
            .add_input(p_in)
            .add_output(p_out)
            .add_node(n)
            .build_and_validate()?;

        // Non-degenerate MaxPool2d: each 2x2 window has a distinct maximum
        // [[1.0, 2.0, 3.0],
        //  [4.0, 5.0, 6.0],
        //  [7.0, 8.0, 9.0]]
        // (0,0): {1,2,4,5} -> 5; (0,1): {2,3,5,6} -> 6
        // (1,0): {4,5,7,8} -> 8; (1,1): {5,6,8,9} -> 9
        let in_t = Tensor::from_values(
            Shape::new(vec![1, 1, 3, 3])?,
            &[1.0_f32, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0],
            g,
        )?;
        let cx = ScalarExecCx::new();
        let out = ScalarExecutor::run(&gr, &[("x", in_t)], ExecBudget::unlimited(), &cx)?;
        let y_t = out.get_output("y").ok_or("missing output y")?;
        let vals = y_t.to_vec::<f32>()?;
        assert_eq!(vals, vec![5.0_f32, 6.0, 8.0, 9.0]);
    }

    // 5. MatMul golden (2D GEMM)
    // A: [2, 3] = [[1, 2, 3], [4, 5, 6]]
    // B: [3, 2] = [[7, 8], [9, 1], [2, 3]]
    // C = A * B: [2, 2]
    // C[0, 0] = 1*7 + 2*9 + 3*2 = 7 + 18 + 6 = 31
    // C[0, 1] = 1*8 + 2*1 + 3*3 = 8 + 2 + 9 = 19
    // C[1, 0] = 4*7 + 5*9 + 6*2 = 28 + 45 + 12 = 85
    // C[1, 1] = 4*8 + 5*1 + 6*3 = 32 + 5 + 18 = 55
    {
        let p_a = TensorPort::new("a", DType::F32, Shape::new(vec![2, 3])?, g)?;
        let p_b = TensorPort::new("b", DType::F32, Shape::new(vec![3, 2])?, g)?;
        let p_c = TensorPort::new("c", DType::F32, Shape::new(vec![2, 2])?, g)?;
        let n = GraphNode::new(
            "mm",
            OpCode::MatMul,
            "matmul",
            vec!["a".to_string(), "b".to_string()],
            vec!["c".to_string()],
            AttributeMap::new(),
        )?;
        let gr = ModelIrGraph::builder("g_mm", g)
            .add_input(p_a)
            .add_input(p_b)
            .add_output(p_c)
            .add_node(n)
            .build_and_validate()?;

        let t_a = Tensor::from_values(
            Shape::new(vec![2, 3])?,
            &[1.0_f32, 2.0, 3.0, 4.0, 5.0, 6.0],
            g,
        )?;
        let t_b = Tensor::from_values(
            Shape::new(vec![3, 2])?,
            &[7.0_f32, 8.0, 9.0, 1.0, 2.0, 3.0],
            g,
        )?;

        let cx = ScalarExecCx::new();
        let out =
            ScalarExecutor::run(&gr, &[("a", t_a), ("b", t_b)], ExecBudget::unlimited(), &cx)?;
        let c_t = out.get_output("c").ok_or("missing output c")?;
        let vals = c_t.to_vec::<f32>()?;
        assert_eq!(vals, vec![31.0_f32, 19.0, 85.0, 55.0]);
        assert_eq!(out.executed_macs(), 12); // 4 output elements * 3 reduction dim = 12 MACs
    }

    // 6. Reshape golden
    // [1, 6] -> [2, 3]
    {
        let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![1, 6])?, g)?;
        let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![2, 3])?, g)?;
        let mut r_attrs = AttributeMap::new();
        r_attrs.insert(
            "shape".to_string(),
            AttrValue::Shape(Shape::new(vec![2, 3])?),
        );
        let n = GraphNode::new(
            "res",
            OpCode::Reshape,
            "r",
            vec!["x".to_string()],
            vec!["y".to_string()],
            r_attrs,
        )?;
        let gr = ModelIrGraph::builder("g_res", g)
            .add_input(p_in)
            .add_output(p_out)
            .add_node(n)
            .build_and_validate()?;

        let t_in = Tensor::from_values(
            Shape::new(vec![1, 6])?,
            &[10.0_f32, 20.0, 30.0, 40.0, 50.0, 60.0],
            g,
        )?;
        let cx = ScalarExecCx::new();
        let out = ScalarExecutor::run(&gr, &[("x", t_in)], ExecBudget::unlimited(), &cx)?;
        let t_y = out.get_output("y").ok_or("missing output y")?;
        assert_eq!(t_y.shape().dims(), &[2, 3]);
        assert_eq!(
            t_y.to_vec::<f32>()?,
            vec![10.0_f32, 20.0, 30.0, 40.0, 50.0, 60.0]
        );
    }

    // 7. Softmax golden (with max-subtraction and axis)
    // [1, 3] = [[1.0, 2.0, 3.0]]
    // max = 3.0
    // diffs = [-2.0, -1.0, 0.0]
    // exps = [exp(-2), exp(-1), 1.0]
    // sum_exp = exp(-2) + exp(-1) + 1.0
    {
        let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![1, 3])?, g)?;
        let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![1, 3])?, g)?;
        let mut sm_attrs = AttributeMap::new();
        sm_attrs.insert("axis".to_string(), AttrValue::Int(-1));
        let n = GraphNode::new(
            "sm",
            OpCode::Softmax,
            "softmax",
            vec!["x".to_string()],
            vec!["y".to_string()],
            sm_attrs,
        )?;
        let gr = ModelIrGraph::builder("g_sm", g)
            .add_input(p_in)
            .add_output(p_out)
            .add_node(n)
            .build_and_validate()?;

        let t_in = Tensor::from_values(Shape::new(vec![1, 3])?, &[1.0_f32, 2.0, 3.0], g)?;
        let cx = ScalarExecCx::new();
        let out = ScalarExecutor::run(&gr, &[("x", t_in)], ExecBudget::unlimited(), &cx)?;
        let y_t = out.get_output("y").ok_or("missing output y")?;
        let vals = y_t.to_vec::<f32>()?;

        // Independent literal constants from python golden
        assert!((vals[0] - 0.090_030_57_f32).abs() < 1e-6);
        assert!((vals[1] - 0.244_728_48_f32).abs() < 1e-6);
        assert!((vals[2] - 0.665_240_94_f32).abs() < 1e-6);
        let total_prob: f32 = vals.iter().sum();
        assert!((total_prob - 1.0_f32).abs() < 1e-6);

        // Softmax extreme stability: [1000.0, 0.0, -1000.0] -> [1.0, 0.0, 0.0]
        let t_ext = Tensor::from_values(Shape::new(vec![1, 3])?, &[1000.0_f32, 0.0, -1000.0], g)?;
        let out_ext = ScalarExecutor::run(&gr, &[("x", t_ext)], ExecBudget::unlimited(), &cx)?;
        let vals_ext = out_ext
            .get_output("y")
            .ok_or("missing output y")?
            .to_vec::<f32>()?;
        assert_eq!(vals_ext, vec![1.0_f32, 0.0, 0.0]);
    }

    Ok(())
}

#[test]
fn test_deterministic_exp_f32_pinned_bit_constants() {
    // Exact bit representations pinning deterministic_exp_f32
    assert_eq!(deterministic_exp_f32(1.0).to_bits(), 0x402DF854);
    assert_eq!(deterministic_exp_f32(0.0).to_bits(), 0x3F800000);
    assert_eq!(deterministic_exp_f32(-1.0).to_bits(), 0x3EBC5AB2);
    assert_eq!(deterministic_exp_f32(10.0).to_bits(), 0x46AC14EE);

    // M4 kill pins: points where deterministic_exp_f32 differs from libm (f32::exp)
    assert_eq!(deterministic_exp_f32(1.75).to_bits(), 0x40B825B4);
    assert_eq!(deterministic_exp_f32(0.33).to_bits(), 0x3FB20B3E);
    assert_eq!(deterministic_exp_f32(-0.98).to_bits(), 0x3EC028C6);
}

#[test]
fn test_m7_kill_no_wildcard_arms_in_scalar_executor_opcode_matches() -> Result<(), Box<dyn Error>> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src = std::fs::read_to_string(root.join("src/scalar_executor.rs"))?;

    // Verify deny attribute is present
    assert!(
        src.contains("#![deny(clippy::wildcard_enum_match_arm)]"),
        "scalar_executor.rs must contain #![deny(clippy::wildcard_enum_match_arm)]"
    );

    // Verify there is no wildcard arm matching on OpCode. The only admitted wildcard arms are
    // the catch-all of a match on a string attribute value (`.as_str(`), which has no finite
    // variant list to enumerate: the GELU `approximate` mode match added by c8dac61. Every
    // wildcard arm is attributed to the closest preceding `match` line.
    let mut last_match_line = "";
    let mut offending = Vec::new();
    for (number, line) in src.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("match ") {
            last_match_line = trimmed;
        }
        let is_wildcard =
            trimmed == "_ =>" || trimmed.starts_with("_ =>") || trimmed.starts_with("_ |");
        if is_wildcard && !last_match_line.contains(".as_str(") {
            offending.push(format!(
                "{}: {trimmed} (match: {last_match_line})",
                number + 1
            ));
        }
    }
    assert!(
        offending.is_empty(),
        "scalar_executor.rs must not contain wildcard arms outside string matches: {offending:?}"
    );

    // Source guard: scalar_executor.rs must never call native f32::exp at any call site,
    // including fully-qualified `f32::exp(` and `::exp(` spellings that bypass `.exp(`.
    for banned in [".exp(", "f32::exp(", "::exp("] {
        assert!(
            !src.contains(banned),
            "scalar_executor.rs must not call native exp ({banned}); must use deterministic_exp_f32"
        );
    }

    // Every opcode now executes (cf0b306, 35b07e0, c8dac61, 6f65e8f), so the former three
    // "unsupported" lists are gone. UnsupportedOperator survives only as the fallback of the two
    // per-family kernels (layout, activation), and each fallback arm must name the opcodes it
    // refuses explicitly rather than bind a catch-all.
    let lines: Vec<&str> = src.lines().map(str::trim).collect();
    let fallback_sites: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.contains("Err(ExecError::UnsupportedOperator {"))
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        fallback_sites.len(),
        2,
        "scalar_executor.rs must have exactly 2 explicit UnsupportedOperator fallbacks"
    );
    for index in fallback_sites {
        let arm = index
            .checked_sub(1)
            .and_then(|previous| lines.get(previous))
            .ok_or("UnsupportedOperator fallback has no arm line")?;
        assert!(
            arm.contains("OpCode::") && arm.ends_with("=> {"),
            "UnsupportedOperator fallback must follow an explicit OpCode list, got {arm:?}"
        );
    }

    Ok(())
}

mod reviewer_probes {
    use std::error::Error;

    use fss_core::Generation;
    use fss_model_ir::{
        AttrValue, AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort,
    };
    use fss_reference::scalar_executor::{
        ExecBudget, ExecError, ExecOutcome, ScalarExecCx, ScalarExecutor, deterministic_exp_f32,
    };
    use fss_tensor::{DType, Shape, Tensor};

    type R = Result<(), Box<dyn Error>>;

    fn g() -> Generation {
        Generation::from_u64(1)
    }

    fn port(name: &str, dt: DType, dims: &[usize]) -> Result<TensorPort, Box<dyn Error>> {
        Ok(TensorPort::new(name, dt, Shape::new(dims.to_vec())?, g())?)
    }

    fn f(name: &str, dims: &[usize]) -> Result<TensorPort, Box<dyn Error>> {
        port(name, DType::F32, dims)
    }

    fn t(dims: &[usize], vals: &[f32]) -> Result<Tensor, Box<dyn Error>> {
        Ok(Tensor::from_values(Shape::new(dims.to_vec())?, vals, g())?)
    }

    fn node(
        id: &str,
        op: OpCode,
        ins: &[&str],
        outs: &[&str],
        attrs: AttributeMap,
    ) -> Result<GraphNode, Box<dyn Error>> {
        Ok(GraphNode::new(
            id,
            op,
            id,
            ins.iter().map(|s| (*s).to_string()).collect(),
            outs.iter().map(|s| (*s).to_string()).collect(),
            attrs,
        )?)
    }

    fn attrs(list: Vec<(&str, AttrValue)>) -> AttributeMap {
        let mut m = AttributeMap::new();
        for (k, v) in list {
            m.insert(k.to_string(), v);
        }
        m
    }

    fn run(graph: &ModelIrGraph, inputs: Vec<(&str, Tensor)>) -> Result<ExecOutcome, ExecError> {
        ScalarExecutor::run(
            graph,
            &inputs,
            ExecBudget::unlimited(),
            &ScalarExecCx::new(),
        )
    }

    fn out(o: &ExecOutcome, name: &str) -> Result<Vec<f32>, Box<dyn Error>> {
        Ok(o.get_output(name)
            .ok_or("missing output")?
            .to_vec::<f32>()?)
    }

    fn close(a: &[f32], e: &[f32], rel: f32) -> bool {
        a.len() == e.len()
            && a.iter()
                .zip(e)
                .all(|(x, y)| (x - y).abs() <= rel * y.abs().max(f32::MIN_POSITIVE))
    }

    fn seq(n: usize) -> Vec<f32> {
        (1..=n).map(|v| v as f32).collect()
    }

    #[test]
    fn p01_conv_asymmetric_padding_is_top_left_bottom_right() -> R {
        // padding [top=1, left=2, bottom=0, right=0], 1x1 weight 2, bias 0.5 -> out 3x4.
        let gr = ModelIrGraph::builder("p01", g())
            .add_input(f("x", &[1, 1, 2, 2])?)
            .add_input(f("w", &[1, 1, 1, 1])?)
            .add_input(f("b", &[1])?)
            .add_output(f("y", &[1, 1, 3, 4])?)
            .add_node(node(
                "c",
                OpCode::Conv2d,
                &["x", "w", "b"],
                &["y"],
                attrs(vec![("padding", AttrValue::IntList(vec![1, 2, 0, 0]))]),
            )?)
            .build_and_validate()?;
        let o = run(
            &gr,
            vec![
                ("x", t(&[1, 1, 2, 2], &[1.0, 2.0, 3.0, 4.0])?),
                ("w", t(&[1, 1, 1, 1], &[2.0])?),
                ("b", t(&[1], &[0.5])?),
            ],
        )?;
        assert_eq!(
            out(&o, "y")?,
            vec![0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 2.5, 4.5, 0.5, 0.5, 6.5, 8.5]
        );
        Ok(())
    }

    #[test]
    fn p02_conv_dilation_and_stride() -> R {
        let gr = ModelIrGraph::builder("p02", g())
            .add_input(f("x", &[1, 1, 5, 5])?)
            .add_input(f("w", &[1, 1, 2, 2])?)
            .add_output(f("y", &[1, 1, 2, 2])?)
            .add_node(node(
                "c",
                OpCode::Conv2d,
                &["x", "w"],
                &["y"],
                attrs(vec![
                    ("strides", AttrValue::IntList(vec![2, 2])),
                    ("dilations", AttrValue::IntList(vec![2, 2])),
                ]),
            )?)
            .build_and_validate()?;
        let o = run(
            &gr,
            vec![
                ("x", t(&[1, 1, 5, 5], &seq(25))?),
                ("w", t(&[1, 1, 2, 2], &[1.0, 2.0, 3.0, 4.0])?),
            ],
        )?;
        assert_eq!(out(&o, "y")?, vec![92.0, 112.0, 192.0, 212.0]);
        Ok(())
    }

    #[test]
    fn p03_conv_kernel_larger_than_input_with_padding() -> R {
        let gr = ModelIrGraph::builder("p03", g())
            .add_input(f("x", &[1, 1, 1, 1])?)
            .add_input(f("w", &[1, 1, 3, 3])?)
            .add_output(f("y", &[1, 1, 1, 1])?)
            .add_node(node(
                "c",
                OpCode::Conv2d,
                &["x", "w"],
                &["y"],
                attrs(vec![("padding", AttrValue::IntList(vec![1, 1, 1, 1]))]),
            )?)
            .build_and_validate()?;
        let o = run(
            &gr,
            vec![
                ("x", t(&[1, 1, 1, 1], &[2.0])?),
                ("w", t(&[1, 1, 3, 3], &seq(9))?),
            ],
        )?;
        assert_eq!(out(&o, "y")?, vec![10.0]);
        Ok(())
    }

    #[test]
    fn p04_conv_groups() -> R {
        let gr = ModelIrGraph::builder("p04", g())
            .add_input(f("x", &[1, 2, 2, 2])?)
            .add_input(f("w", &[2, 1, 1, 1])?)
            .add_output(f("y", &[1, 2, 2, 2])?)
            .add_node(node(
                "c",
                OpCode::Conv2d,
                &["x", "w"],
                &["y"],
                attrs(vec![("groups", AttrValue::Int(2))]),
            )?)
            .build_and_validate()?;
        let o = run(
            &gr,
            vec![
                ("x", t(&[1, 2, 2, 2], &seq(8))?),
                ("w", t(&[2, 1, 1, 1], &[2.0, 3.0])?),
            ],
        )?;
        assert_eq!(
            out(&o, "y")?,
            vec![2.0, 4.0, 6.0, 8.0, 15.0, 18.0, 21.0, 24.0]
        );
        Ok(())
    }

    fn pool_graph(
        id: &str,
        in_dims: &[usize],
        out_dims: &[usize],
        a: AttributeMap,
    ) -> Result<ModelIrGraph, Box<dyn Error>> {
        Ok(ModelIrGraph::builder(id, g())
            .add_input(f("x", in_dims)?)
            .add_output(f("y", out_dims)?)
            .add_node(node("p", OpCode::MaxPool2d, &["x"], &["y"], a)?)
            .build_and_validate()?)
    }

    #[test]
    fn p05_maxpool_ceil_mode_last_window_clamp() -> R {
        // H=W=1, k=2, s=2, pad=[1,1,1,1], ceil: floor=1, ceil without clamp=2, with clamp=1.
        let gr = pool_graph(
            "p05",
            &[1, 1, 1, 1],
            &[1, 1, 1, 1],
            attrs(vec![
                ("kernel_size", AttrValue::IntList(vec![2, 2])),
                ("strides", AttrValue::IntList(vec![2, 2])),
                ("padding", AttrValue::IntList(vec![1, 1, 1, 1])),
                ("ceil_mode", AttrValue::Bool(true)),
            ]),
        )?;
        let o = run(&gr, vec![("x", t(&[1, 1, 1, 1], &[-1.0])?)])?;
        assert_eq!(out(&o, "y")?, vec![-1.0]);
        Ok(())
    }

    #[test]
    fn p06_maxpool_padding_positions_skipped_not_zero() -> R {
        // 5x5 of -1..-25, k=2, s=2, pad=[1,0,0,1], ceil -> 3x3 (python golden).
        let gr = pool_graph(
            "p06",
            &[1, 1, 5, 5],
            &[1, 1, 3, 3],
            attrs(vec![
                ("kernel_size", AttrValue::IntList(vec![2, 2])),
                ("strides", AttrValue::IntList(vec![2, 2])),
                ("padding", AttrValue::IntList(vec![1, 0, 0, 1])),
                ("ceil_mode", AttrValue::Bool(true)),
            ]),
        )?;
        let xs: Vec<f32> = seq(25).iter().map(|v| -v).collect();
        let o = run(&gr, vec![("x", t(&[1, 1, 5, 5], &xs)?)])?;
        assert_eq!(
            out(&o, "y")?,
            vec![-1.0, -3.0, -5.0, -6.0, -8.0, -10.0, -16.0, -18.0, -20.0]
        );
        Ok(())
    }

    #[test]
    fn p06b_maxpool_floor_distinct_windows() -> R {
        let gr = pool_graph(
            "p06b",
            &[1, 1, 4, 4],
            &[1, 1, 2, 2],
            attrs(vec![
                ("kernel_size", AttrValue::IntList(vec![2, 2])),
                ("strides", AttrValue::IntList(vec![2, 2])),
            ]),
        )?;
        let xs = [
            3.0, 1.0, 4.0, 1.0, 5.0, 9.0, 2.0, 6.0, 5.0, 3.0, 5.0, 8.0, 9.0, 7.0, 9.0, 3.0,
        ];
        let o = run(&gr, vec![("x", t(&[1, 1, 4, 4], &xs)?)])?;
        assert_eq!(out(&o, "y")?, vec![9.0, 6.0, 9.0, 9.0]);
        Ok(())
    }

    fn softmax_graph(dims: &[usize], axis: i64) -> Result<ModelIrGraph, Box<dyn Error>> {
        Ok(ModelIrGraph::builder("sm", g())
            .add_input(f("x", dims)?)
            .add_output(f("y", dims)?)
            .add_node(node(
                "s",
                OpCode::Softmax,
                &["x"],
                &["y"],
                attrs(vec![("axis", AttrValue::Int(axis))]),
            )?)
            .build_and_validate()?)
    }

    #[test]
    fn p07_softmax_extremes_are_stable() -> R {
        let o = run(
            &softmax_graph(&[1, 3], -1)?,
            vec![("x", t(&[1, 3], &[1000.0, 0.0, -1000.0])?)],
        )?;
        assert_eq!(out(&o, "y")?, vec![1.0, 0.0, 0.0]);
        Ok(())
    }

    #[test]
    fn p08_softmax_independent_golden() -> R {
        let o = run(
            &softmax_graph(&[1, 3], -1)?,
            vec![("x", t(&[1, 3], &[1.0, 2.0, 3.0])?)],
        )?;
        let y = out(&o, "y")?;
        assert!(
            close(&y, &[0.090_030_57, 0.244_728_48, 0.665_240_94], 3e-7),
            "{y:?}"
        );
        Ok(())
    }

    #[test]
    fn p09_softmax_axis0() -> R {
        let o = run(
            &softmax_graph(&[2, 2], 0)?,
            vec![("x", t(&[2, 2], &[1.0, 2.0, 3.0, 4.0])?)],
        )?;
        let y = out(&o, "y")?;
        assert!(
            close(
                &y,
                &[0.119_202_92, 0.119_202_92, 0.880_797_1, 0.880_797_1],
                3e-7
            ),
            "{y:?}"
        );
        Ok(())
    }

    #[test]
    fn p10_sigmoid_extremes_and_goldens() -> R {
        let gr = ModelIrGraph::builder("p10", g())
            .add_input(f("x", &[7])?)
            .add_output(f("y", &[7])?)
            .add_node(node(
                "s",
                OpCode::Sigmoid,
                &["x"],
                &["y"],
                AttributeMap::new(),
            )?)
            .build_and_validate()?;
        let xs = [
            100.0,
            -100.0,
            1.0,
            -1.0,
            f32::NAN,
            f32::INFINITY,
            f32::NEG_INFINITY,
        ];
        let y = out(&run(&gr, vec![("x", t(&[7], &xs)?)])?, "y")?;
        assert_eq!(y[0], 1.0);
        assert!(y[1] >= 0.0 && y[1] < 1e-30, "{}", y[1]);
        assert_eq!(y[2].to_bits(), 0x3F3B_26A8, "sigmoid(1.0) bits drifted");
        assert_eq!(y[3].to_bits(), 0x3E89_B2B1, "sigmoid(-1.0) bits drifted");
        assert!(y[4].is_nan());
        assert_eq!(y[5], 1.0);
        assert_eq!(y[6], 0.0);
        Ok(())
    }

    #[test]
    fn p10b_sigmoid_bits_pinned_against_native_exp_call_site() -> R {
        // Independent literal golden bits captured from the deterministic executor on the
        // pinned toolchain; a native `f32::exp` swapped into either sigmoid branch (M4g)
        // flips at least one of these final values.
        let gr = ModelIrGraph::builder("p10b", g())
            .add_input(f("x", &[7])?)
            .add_output(f("y", &[7])?)
            .add_node(node(
                "s",
                OpCode::Sigmoid,
                &["x"],
                &["y"],
                AttributeMap::new(),
            )?)
            .build_and_validate()?;
        let xs = [0.98_f32, -0.98, 1.75, -1.75, 0.33, 1.0, -1.0];
        let y = out(&run(&gr, vec![("x", t(&[7], &xs)?)])?, "y")?;
        let expected: [u32; 7] = [
            0x3F3A_23C3, 0x3E8B_B878, 0x3F5A_1993, 0x3E17_99AF, 0x3F14_EE2E, 0x3F3B_26A8,
            0x3E89_B2B1,
        ];
        let actual: Vec<u32> = y.iter().map(|v| v.to_bits()).collect();
        assert_eq!(actual, expected, "sigmoid bits drifted for xs {xs:?}: {actual:?}");
        Ok(())
    }

    #[test]
    fn p11c_exp_upper_clamp_returns_positive_infinity() {
        // M6a: loosening the upper clamp to 1000 must fail here. True exp overflows f32 for
        // arguments above ~88.72, so 711, 1000, and f32::MAX are all +INFINITY.
        for x in [711.0_f32, 1000.0, f32::MAX] {
            let v = deterministic_exp_f32(x);
            assert_eq!(
                v.to_bits(),
                f32::INFINITY.to_bits(),
                "deterministic_exp_f32({x}) must be +INFINITY, got {v:?} (bits 0x{:08X})",
                v.to_bits()
            );
        }
    }

    #[test]
    fn p10c_softmax_large_negative_row_bits_pinned() -> R {
        // M10: a row max starting at 0.0 instead of NEG_INFINITY collapses
        // exp(-1000 - 0) to zero, so the row normalizes to [0, 0, 0] and misses these pins.
        let o = run(
            &softmax_graph(&[1, 3], -1)?,
            vec![("x", t(&[1, 3], &[-1000.0, -1001.0, -1002.0])?)],
        )?;
        let expected: [u32; 3] = [0x3F2A_4D3B, 0x3E7A_9A1A, 0x3DB8_61F3];
        let actual: Vec<u32> = out(&o, "y")?.iter().map(|v| v.to_bits()).collect();
        assert_eq!(
            actual, expected,
            "softmax large-negative row drifted: expected {expected:?}, got {actual:?}"
        );
        Ok(())
    }

    #[test]
    fn p10d_softmax_shifted_row_bits_pinned() -> R {
        // M4s: swapping `deterministic_exp_f32` for `f32::exp` inside the softmax kernel
        // flips at least one final bit of this shifted row (max at 0.0).
        let o = run(
            &softmax_graph(&[1, 3], -1)?,
            vec![("x", t(&[1, 3], &[0.0, -0.98, -1.75])?)],
        )?;
        let expected: [u32; 3] = [0x3F25_4243, 0x3E78_1809, 0x3DE5_BDCF];
        let actual: Vec<u32> = out(&o, "y")?.iter().map(|v| v.to_bits()).collect();
        assert_eq!(
            actual, expected,
            "softmax shifted-row bits drifted: expected {expected:?}, got {actual:?}"
        );
        Ok(())
    }

    #[test]
    fn p11_exp_extremes_in_claimed_range() {
        assert!(deterministic_exp_f32(f32::NAN).is_nan());
        assert_eq!(deterministic_exp_f32(f32::INFINITY), f32::INFINITY);
        assert_eq!(deterministic_exp_f32(f32::NEG_INFINITY), 0.0);
        assert_eq!(deterministic_exp_f32(1e-40), 1.0);
        assert_eq!(deterministic_exp_f32(-1e-40), 1.0);
        assert_eq!(deterministic_exp_f32(0.0), 1.0);
        assert_eq!(deterministic_exp_f32(1.0), 2.718_281_7);
        let pts = [
            (-1.0_f32, 0.367_879_44_f32),
            (10.0, 22_026.465),
            (-50.0, 1.928_749_8e-22),
            (88.0, 1.651_636_3e38),
        ];
        for (x, e) in pts {
            let v = deterministic_exp_f32(x);
            assert!(
                v.is_finite() && (v - e).abs() <= 1.2e-7 * e,
                "exp({x})={v} vs {e}"
            );
        }
    }

    #[test]
    fn p11b_exp_edge_outside_claimed_range_minor() {
        // true exp(88.5)=2.72e38 < f32::MAX; true exp(-87.5)=9.98e-39 (subnormal, representable)
        let hi = deterministic_exp_f32(88.5);
        let lo = deterministic_exp_f32(-87.5);
        assert!(hi.is_finite() && lo > 0.0, "exp(88.5)={hi} exp(-87.5)={lo}");
    }

    #[test]
    fn p12_non_f32_graphs_that_pass_ir_validation_are_refused() -> R {
        let cases = vec![
            (DType::F16, OpCode::Relu),
            (DType::BF16, OpCode::Sigmoid),
            (DType::F64, OpCode::Softmax),
            (DType::I32, OpCode::Add),
            (DType::I64, OpCode::MatMul),
            (DType::U8, OpCode::MaxPool2d),
            (DType::I32, OpCode::Conv2d),
        ];
        for (dt, op) in cases {
            let (ins, shapes, out_shape, a): (
                Vec<&str>,
                Vec<Vec<usize>>,
                Vec<usize>,
                AttributeMap,
            ) = match op {
                OpCode::Relu | OpCode::Sigmoid => {
                    (vec!["x"], vec![vec![4]], vec![4], AttributeMap::new())
                }
                OpCode::Softmax => (vec!["x"], vec![vec![1, 3]], vec![1, 3], AttributeMap::new()),
                OpCode::Add => (
                    vec!["x", "z"],
                    vec![vec![2], vec![2]],
                    vec![2],
                    AttributeMap::new(),
                ),
                OpCode::MatMul => (
                    vec!["x", "z"],
                    vec![vec![2, 2], vec![2, 2]],
                    vec![2, 2],
                    AttributeMap::new(),
                ),
                OpCode::MaxPool2d => (
                    vec!["x"],
                    vec![vec![1, 1, 2, 2]],
                    vec![1, 1, 1, 1],
                    attrs(vec![("kernel_size", AttrValue::IntList(vec![2, 2]))]),
                ),
                _ => (
                    vec!["x", "z"],
                    vec![vec![1, 1, 2, 2], vec![1, 1, 1, 1]],
                    vec![1, 1, 2, 2],
                    AttributeMap::new(),
                ),
            };
            let mut b = ModelIrGraph::builder("p12", g());
            for (n, s) in ins.iter().zip(&shapes) {
                b = b.add_input(port(n, dt, s)?);
            }
            let gr = b
                .add_output(port("y", dt, &out_shape)?)
                .add_node(node("n", op, &ins, &["y"], a)?)
                .build_and_validate()
                .map_err(|e| format!("{dt:?} {op:?} did not pass IR validation: {e}"))?;
            let empty: Vec<(&str, Tensor)> = Vec::new();
            match ScalarExecutor::run(&gr, &empty, ExecBudget::unlimited(), &ScalarExecCx::new()) {
                Err(ExecError::UnsupportedDType { actual, .. }) => assert_eq!(actual, dt),
                other => {
                    return Err(
                        format!("{dt:?} {op:?}: expected UnsupportedDType, got {other:?}").into(),
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn p13_refused_op_after_supported_op_refused_before_execution() -> R {
        // Tanh, the op this probe first used, executes since c8dac61; no opcode is refused as
        // UnsupportedOperator any more. A later node with an unknown GELU mode is still refused,
        // and the refusal must come from whole-graph validation before the leading Relu runs.
        let mut mode = AttributeMap::new();
        mode.insert(
            "approximate".to_string(),
            AttrValue::String("erf".to_string()),
        );
        let gr = ModelIrGraph::builder("p13", g())
            .add_input(f("x", &[4])?)
            .add_output(f("y", &[4])?)
            .add_node(node(
                "a_relu",
                OpCode::Relu,
                &["x"],
                &["m"],
                AttributeMap::new(),
            )?)
            .add_node(node("b_gelu", OpCode::Gelu, &["m"], &["y"], mode)?)
            .build()?;
        match run(&gr, vec![("x", t(&[4], &[1.0; 4])?)]) {
            Err(ExecError::Ir(fss_model_ir::ModelIrError::InvalidAttribute {
                node_id,
                attr_name,
                ..
            })) => {
                assert_eq!(node_id, "b_gelu");
                assert_eq!(attr_name, "approximate");
            }
            other => return Err(format!("expected InvalidAttribute, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn p14_cycle_in_unvalidated_graph_is_typed_error() -> R {
        let gr = ModelIrGraph::builder("p14", g())
            .add_input(f("x", &[4])?)
            .add_output(f("q", &[4])?)
            .add_node(node(
                "n1",
                OpCode::Relu,
                &["q"],
                &["p"],
                AttributeMap::new(),
            )?)
            .add_node(node(
                "n2",
                OpCode::Relu,
                &["p"],
                &["q"],
                AttributeMap::new(),
            )?)
            .build()?;
        let r = run(&gr, vec![("x", t(&[4], &[1.0; 4])?)]);
        println!("PROBE p14 {r:?}");
        assert!(matches!(r, Err(ExecError::Ir(_))), "{r:?}");
        Ok(())
    }

    #[test]
    fn p15_dangling_input_is_typed_error() -> R {
        let gr = ModelIrGraph::builder("p15", g())
            .add_input(f("x", &[4])?)
            .add_output(f("y", &[4])?)
            .add_node(node(
                "n1",
                OpCode::Relu,
                &["ghost"],
                &["y"],
                AttributeMap::new(),
            )?)
            .build()?;
        let r = run(&gr, vec![("x", t(&[4], &[1.0; 4])?)]);
        println!("PROBE p15 {r:?}");
        assert!(
            matches!(r, Err(ExecError::Ir(_))) && format!("{r:?}").contains("Dangling"),
            "{r:?}"
        );
        Ok(())
    }

    #[test]
    fn p16_unsupported_version_is_typed_error() -> R {
        let gr = ModelIrGraph::builder("p16", g())
            .version(ModelIrVersion::unsupported(2)?)
            .add_input(f("x", &[4])?)
            .add_output(f("y", &[4])?)
            .add_node(node(
                "n1",
                OpCode::Relu,
                &["x"],
                &["y"],
                AttributeMap::new(),
            )?)
            .build()?;
        let r = run(&gr, vec![("x", t(&[4], &[1.0; 4])?)]);
        println!("PROBE p16 {r:?}");
        assert!(
            matches!(
                r,
                Err(ExecError::UnsupportedVersion { actual: 2, .. }) | Err(ExecError::Ir(_))
            ),
            "{r:?}"
        );
        Ok(())
    }

    #[test]
    fn p17_determinism_two_runs_bit_identical() -> R {
        let gr = ModelIrGraph::builder("p17", g())
            .add_input(f("x", &[1, 1, 3, 3])?)
            .add_input(f("w", &[1, 1, 2, 2])?)
            .add_output(f("y", &[1, 4])?)
            .add_node(node(
                "a_conv",
                OpCode::Conv2d,
                &["x", "w"],
                &["c"],
                AttributeMap::new(),
            )?)
            .add_node(node(
                "b_sig",
                OpCode::Sigmoid,
                &["c"],
                &["s"],
                AttributeMap::new(),
            )?)
            .add_node(node(
                "c_res",
                OpCode::Reshape,
                &["s"],
                &["r"],
                attrs(vec![("shape", AttrValue::IntList(vec![1, 4]))]),
            )?)
            .add_node(node(
                "d_sm",
                OpCode::Softmax,
                &["r"],
                &["y"],
                AttributeMap::new(),
            )?)
            .build_and_validate()?;
        let xs = [0.1, -0.7, 1.3, 2.9, -3.1, 0.25, 0.333, -1.5, 4.75];
        let ws = [0.3, -0.2, 1.7, 0.01];
        let a = out(
            &run(
                &gr,
                vec![("x", t(&[1, 1, 3, 3], &xs)?), ("w", t(&[1, 1, 2, 2], &ws)?)],
            )?,
            "y",
        )?;
        let b = out(
            &run(
                &gr,
                vec![("x", t(&[1, 1, 3, 3], &xs)?), ("w", t(&[1, 1, 2, 2], &ws)?)],
            )?,
            "y",
        )?;
        let ab: Vec<u32> = a.iter().map(|v| v.to_bits()).collect();
        let bb: Vec<u32> = b.iter().map(|v| v.to_bits()).collect();
        assert_eq!(ab, bb);
        Ok(())
    }

    #[test]
    fn p18_hostile_conv_huge_dilation_and_padding_no_panic() -> R {
        // eff_kh = 1*(2^63-1)+1 = 2^63; total_h = 3+(2^63-1)+2; out_h = 5. Correct math:
        // ih = oh + kh*D - P, only kh=1 lands at ih=oh -> y = [100, 200, 300, 0, 0].
        let a = attrs(vec![
            ("dilations", AttrValue::IntList(vec![i64::MAX, 1])),
            ("padding", AttrValue::IntList(vec![i64::MAX, 0, 2, 0])),
        ]);
        let gr = ModelIrGraph::builder("p18", g())
            .add_input(f("x", &[1, 1, 3, 1])?)
            .add_input(f("w", &[1, 1, 2, 1])?)
            .add_output(f("y", &[1, 1, 5, 1])?)
            .add_node(node("c", OpCode::Conv2d, &["x", "w"], &["y"], a)?)
            .build_and_validate()?;
        let o = run(
            &gr,
            vec![
                ("x", t(&[1, 1, 3, 1], &[1.0, 2.0, 3.0])?),
                ("w", t(&[1, 1, 2, 1], &[10.0, 100.0])?),
            ],
        )?;
        assert_eq!(out(&o, "y")?, vec![100.0, 200.0, 300.0, 0.0, 0.0]);
        Ok(())
    }
    #[test]
    fn p19_maxpool_window_work_is_budgeted() -> R {
        // compute_node_macs charges out_elems * k_h * k_w = 1 * 2^20 * 2^20 = 2^40 "MACs",
        // exceeding the 0-MAC budget and failing closed (the 2^21 inner-loop visits are not
        // the charged quantity).
        let k: i64 = 1 << 20;
        let gr = pool_graph(
            "p19",
            &[1, 1, 1, 1],
            &[1, 1, 1, 1],
            attrs(vec![
                ("kernel_size", AttrValue::IntList(vec![k, k])),
                ("strides", AttrValue::IntList(vec![k, k])),
                (
                    "padding",
                    AttrValue::IntList(vec![k - 1, k - 1, k - 1, k - 1]),
                ),
            ]),
        )?;
        let inputs = vec![("x", t(&[1, 1, 1, 1], &[7.0])?)];
        match ScalarExecutor::run(&gr, &inputs, ExecBudget::new(0, 64), &ScalarExecCx::new()) {
            Err(ExecError::BudgetExceeded { .. }) => Ok(()),
            other => Err(format!(
                "MaxPool with a 2^20 x 2^20 window ran under a 0-MAC budget: {other:?}"
            )
            .into()),
        }
    }

    #[test]
    fn p20_zero_sized_dims_no_panic() -> R {
        let relu = ModelIrGraph::builder("p20a", g())
            .add_input(f("x", &[0, 3])?)
            .add_output(f("y", &[0, 3])?)
            .add_node(node(
                "r",
                OpCode::Relu,
                &["x"],
                &["y"],
                AttributeMap::new(),
            )?)
            .build_and_validate();
        match relu {
            Ok(gr) => {
                let r = run(&gr, vec![("x", t(&[0, 3], &[])?)]);
                println!("PROBE p20 relu {r:?}");
            }
            Err(e) => println!("PROBE p20 relu refused by IR: {e}"),
        }
        let mm = ModelIrGraph::builder("p20b", g())
            .add_input(f("a", &[2, 0])?)
            .add_input(f("b", &[0, 3])?)
            .add_output(f("y", &[2, 3])?)
            .add_node(node(
                "m",
                OpCode::MatMul,
                &["a", "b"],
                &["y"],
                AttributeMap::new(),
            )?)
            .build_and_validate();
        match mm {
            Ok(gr) => {
                let o = run(&gr, vec![("a", t(&[2, 0], &[])?), ("b", t(&[0, 3], &[])?)])?;
                assert_eq!(out(&o, "y")?, vec![0.0; 6]);
            }
            Err(e) => println!("PROBE p20 matmul refused by IR: {e}"),
        }
        Ok(())
    }

    #[test]
    fn p21_stride_zero_unvalidated_is_typed_error() -> R {
        let gr = ModelIrGraph::builder("p21", g())
            .add_input(f("x", &[1, 1, 2, 2])?)
            .add_input(f("w", &[1, 1, 1, 1])?)
            .add_output(f("y", &[1, 1, 2, 2])?)
            .add_node(node(
                "c",
                OpCode::Conv2d,
                &["x", "w"],
                &["y"],
                attrs(vec![("strides", AttrValue::IntList(vec![0, 0]))]),
            )?)
            .build()?;
        let r = run(
            &gr,
            vec![
                ("x", t(&[1, 1, 2, 2], &seq(4))?),
                ("w", t(&[1, 1, 1, 1], &[1.0])?),
            ],
        );
        assert!(matches!(r, Err(ExecError::Ir(_))), "{r:?}");
        Ok(())
    }

    #[test]
    fn p22_broadcast_add_rank_mismatch() -> R {
        let gr = ModelIrGraph::builder("p22", g())
            .add_input(f("a", &[2, 3])?)
            .add_input(f("b", &[3])?)
            .add_output(f("y", &[2, 3])?)
            .add_node(node(
                "n",
                OpCode::Add,
                &["a", "b"],
                &["y"],
                AttributeMap::new(),
            )?)
            .build_and_validate()?;
        let o = run(
            &gr,
            vec![
                ("a", t(&[2, 3], &seq(6))?),
                ("b", t(&[3], &[10.0, 20.0, 30.0])?),
            ],
        )?;
        assert_eq!(out(&o, "y")?, vec![11.0, 22.0, 33.0, 14.0, 25.0, 36.0]);
        Ok(())
    }

    #[test]
    fn p23_matmul_batch_broadcast() -> R {
        let gr = ModelIrGraph::builder("p23", g())
            .add_input(f("a", &[1, 1, 2])?)
            .add_input(f("b", &[3, 2, 1])?)
            .add_output(f("y", &[3, 1, 1])?)
            .add_node(node(
                "n",
                OpCode::MatMul,
                &["a", "b"],
                &["y"],
                AttributeMap::new(),
            )?)
            .build_and_validate()?;
        let o = run(
            &gr,
            vec![
                ("a", t(&[1, 1, 2], &[1.0, 2.0])?),
                ("b", t(&[3, 2, 1], &seq(6))?),
            ],
        )?;
        assert_eq!(out(&o, "y")?, vec![5.0, 11.0, 17.0]);
        Ok(())
    }

    #[test]
    fn p24_reshape_minus_one() -> R {
        let gr = ModelIrGraph::builder("p24", g())
            .add_input(f("x", &[2, 3])?)
            .add_output(f("y", &[3, 2])?)
            .add_node(node(
                "n",
                OpCode::Reshape,
                &["x"],
                &["y"],
                attrs(vec![("shape", AttrValue::IntList(vec![3, -1]))]),
            )?)
            .build_and_validate()?;
        let o = run(&gr, vec![("x", t(&[2, 3], &seq(6))?)])?;
        let y = o.get_output("y").ok_or("missing")?;
        assert_eq!(y.shape().dims(), &[3, 2]);
        assert_eq!(y.to_vec::<f32>()?, seq(6));
        Ok(())
    }
}
