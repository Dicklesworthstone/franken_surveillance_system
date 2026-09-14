#![forbid(unsafe_code)]

//! Integration contract tests for `ScalarExecutor` over `fss_model_ir::ModelIrGraph`.
//!
//! Verifies hand-computed numerical goldens for all supported kernels (Conv2d, Relu, Sigmoid,
//! Add/Sub/Mul/Div with broadcasting, MaxPool2d, MatMul, Reshape, Softmax), bit reproducibility,
//! strict F32 data type enforcement, pre-execution validation, resource budgeting, and cooperative
//! cancellation.

use std::error::Error;

use fss_core::Generation;
use fss_model_ir::{
    AttrValue, AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort,
};
use fss_reference::scalar_executor::{
    ChannelTransform, ExecBudget, ExecError, PreprocessProgram, ScalarExecCx, ScalarExecutor,
    deterministic_exp_f32, deterministic_sigmoid_f32,
};
use fss_tensor::{DType, Shape, Tensor};

fn gen1() -> Generation {
    Generation::from_u64(1)
}

#[test]
fn test_hand_computed_3op_golden_conv2d_relu_add() -> Result<(), Box<dyn Error>> {
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
    assert_eq!(outcome.executed_macs(), 16); // 4 output elements * 4 inputs in filter = 16 MACs

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

    Ok(())
}

#[test]
fn test_unsupported_opcodes_fail_before_execution() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let unsupported_ops = vec![
        OpCode::Gelu,
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

    for op in unsupported_ops {
        let in_shape = if op == OpCode::Embedding {
            Shape::new(vec![2, 4])?
        } else {
            Shape::new(vec![2, 4, 8])?
        };
        let in_dtype = if op == OpCode::Embedding {
            DType::I32
        } else {
            DType::F32
        };

        let in_port = TensorPort::new("in0", in_dtype, in_shape, g)?;
        let out_port = TensorPort::new("out0", DType::F32, Shape::new(vec![2, 4, 8])?, g)?;

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
            "unsupported_node",
            op,
            "test_op",
            vec!["in0".to_string()],
            vec!["out0".to_string()],
            attrs,
        )?;

        // If graph validation passes, execution MUST reject it with UnsupportedOperator or UnsupportedDType
        if let Ok(graph) = ModelIrGraph::builder("test_unsupported", g)
            .add_input(in_port)
            .add_output(out_port)
            .add_node(node)
            .build_and_validate()
        {
            let cx = ScalarExecCx::new();
            let dummy_tensor = if in_dtype == DType::I32 {
                Tensor::from_values(Shape::new(vec![2, 4])?, &[0_i32; 8], g)?
            } else {
                Tensor::from_values(Shape::new(vec![2, 4, 8])?, &[0.0_f32; 64], g)?
            };
            let inputs = vec![("in0", dummy_tensor)];

            let result = ScalarExecutor::run(&graph, &inputs, ExecBudget::unlimited(), &cx);
            match result {
                Err(ExecError::UnsupportedOperator { op: err_op, .. }) => {
                    assert_eq!(err_op, op);
                }
                Err(ExecError::UnsupportedDType { .. }) => {
                    // Embedding input is I32 which is also rejected before execution
                    assert_eq!(op, OpCode::Embedding);
                }
                Ok(_) => {
                    return Err(format!(
                        "Expected failure for unsupported op {op:?}, but execution succeeded"
                    )
                    .into());
                }
                Err(other) => {
                    return Err(format!(
                        "Expected UnsupportedOperator or UnsupportedDType for {op:?}, got {other:?}"
                    )
                    .into());
                }
            }
        }
    }

    Ok(())
}

#[test]
fn test_shape_mismatches_fail_before_execution() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let x_port = TensorPort::new("x", DType::F32, Shape::new(vec![1, 1, 3, 3])?, g)?;
    let y_port = TensorPort::new("y", DType::F32, Shape::new(vec![1, 1, 3, 3])?, g)?;

    let node = GraphNode::new(
        "relu",
        OpCode::Relu,
        "relu",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::builder("relu_graph", g)
        .add_input(x_port)
        .add_output(y_port)
        .add_node(node)
        .build_and_validate()?;

    // Provide tensor with wrong shape: [1, 1, 4, 4] instead of [1, 1, 3, 3]
    let bad_tensor = Tensor::from_values(Shape::new(vec![1, 1, 4, 4])?, &[1.0_f32; 16], g)?;
    let inputs = vec![("x", bad_tensor)];

    let cx = ScalarExecCx::new();
    let result = ScalarExecutor::run(&graph, &inputs, ExecBudget::unlimited(), &cx);
    match result {
        Err(ExecError::ShapeMismatch { op_id, .. }) => {
            assert_eq!(op_id, "graph_input");
        }
        Ok(_) => return Err("Expected ShapeMismatch for wrong input shape, got Ok".into()),
        Err(other) => {
            return Err(
                format!("Expected ShapeMismatch for wrong input shape, got {other:?}").into(),
            );
        }
    }

    Ok(())
}

#[test]
fn test_budget_overruns_fail_before_execution() -> Result<(), Box<dyn Error>> {
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

    // 1. MACs budget overrun (max_macs = 0, required = 36 MACs: 9 elements * 4 inputs in kernel)
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

    // 2. Memory bytes budget overrun (max_bytes = 10, required = (16 + 4 + 9) * 4 = 116 bytes)
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

    Ok(())
}

#[test]
fn test_cancellation_leaves_no_outputs() -> Result<(), Box<dyn Error>> {
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
fn test_f32_only_gate_refuses_non_f32_graphs_and_tensors() -> Result<(), Box<dyn Error>> {
    let g = gen1();

    // 1. Graph with non-F32 declared input (e.g. F64)
    let p_in_f64 = TensorPort::new("x", DType::F64, Shape::new(vec![4])?, g)?;
    let p_out_f64 = TensorPort::new("y", DType::F64, Shape::new(vec![4])?, g)?;
    let n = GraphNode::new(
        "relu",
        OpCode::Relu,
        "r",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let gr_f64 = ModelIrGraph::builder("g_f64", g)
        .add_input(p_in_f64)
        .add_output(p_out_f64)
        .add_node(n)
        .build_and_validate()?;

    let dummy_f64 = Tensor::from_values(Shape::new(vec![4])?, &[1.0_f64, 2.0, 3.0, 4.0], g)?;
    let cx = ScalarExecCx::new();
    let res_f64 = ScalarExecutor::run(&gr_f64, &[("x", dummy_f64)], ExecBudget::unlimited(), &cx);

    match res_f64 {
        Err(ExecError::UnsupportedDType {
            expected, actual, ..
        }) => {
            assert_eq!(expected, DType::F32);
            assert_eq!(actual, DType::F64);
        }
        Ok(_) => return Err("Expected UnsupportedDType for F64 graph, got Ok".into()),
        Err(other) => {
            return Err(format!("Expected UnsupportedDType for F64 graph, got {other:?}").into());
        }
    }

    // 2. F32 graph provided with U8 tensor
    let p_in_f32 = TensorPort::new("x", DType::F32, Shape::new(vec![4])?, g)?;
    let p_out_f32 = TensorPort::new("y", DType::F32, Shape::new(vec![4])?, g)?;
    let n_f32 = GraphNode::new(
        "relu",
        OpCode::Relu,
        "r",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;
    let gr_f32 = ModelIrGraph::builder("g_f32", g)
        .add_input(p_in_f32)
        .add_output(p_out_f32)
        .add_node(n_f32)
        .build_and_validate()?;

    let t_u8 = Tensor::from_values(Shape::new(vec![4])?, &[10_u8, 20, 30, 40], g)?;
    let res_u8 = ScalarExecutor::run(&gr_f32, &[("x", t_u8)], ExecBudget::unlimited(), &cx);

    match res_u8 {
        Err(ExecError::UnsupportedDType {
            expected, actual, ..
        }) => {
            assert_eq!(expected, DType::F32);
            assert_eq!(actual, DType::U8);
        }
        Ok(_) => return Err("Expected UnsupportedDType for U8 tensor, got Ok".into()),
        Err(other) => {
            return Err(format!("Expected UnsupportedDType for U8 tensor, got {other:?}").into());
        }
    }

    Ok(())
}

#[test]
fn test_canonical_topological_sort_execution_order() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    // Chain: x -> n1 (Relu) -> mid -> n2 (Sigmoid) -> y
    // Add nodes in reverse order: n2 first, then n1.
    // Topological sort MUST execute n1 before n2.
    let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![2])?, g)?;
    let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![2])?, g)?;

    let n1 = GraphNode::new(
        "n1_relu",
        OpCode::Relu,
        "relu",
        vec!["x".to_string()],
        vec!["mid".to_string()],
        AttributeMap::new(),
    )?;
    let n2 = GraphNode::new(
        "n2_sig",
        OpCode::Sigmoid,
        "sig",
        vec!["mid".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::builder("toposort_graph", g)
        .add_input(p_in)
        .add_output(p_out)
        .add_node(n2) // Add out-of-order
        .add_node(n1)
        .build_and_validate()?;

    let t_in = Tensor::from_values(Shape::new(vec![2])?, &[-1.0_f32, 2.0], g)?;
    let cx = ScalarExecCx::new();
    let outcome = ScalarExecutor::run(&graph, &[("x", t_in)], ExecBudget::unlimited(), &cx)?;

    // x = [-1.0, 2.0]
    // mid = Relu(x) = [0.0, 2.0]
    // y = Sigmoid(mid) = [sigmoid(0.0) = 0.5, sigmoid(2.0)]
    let y_t = outcome.get_output("y").ok_or("missing output y")?;
    let vals = y_t.to_vec::<f32>()?;
    assert_eq!(vals[0], 0.5_f32);
    assert_eq!(vals[1], deterministic_sigmoid_f32(2.0));

    Ok(())
}

#[test]
fn test_version_gate() -> Result<(), Box<dyn Error>> {
    let version = ModelIrVersion::from_u32(1)?;
    assert_eq!(version.as_u32(), 1);

    // Any other version number is rejected
    assert!(ModelIrVersion::from_u32(0).is_err());
    assert!(ModelIrVersion::from_u32(2).is_err());

    Ok(())
}

#[test]
fn test_maxpool2d_ceil_mode_with_last_window_clamp() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    // Input: [1, 1, 4, 4]
    // kernel_size: [3, 3], strides: [2, 2], ceil_mode: true, padding: [0, 0, 0, 0]
    // With h=4: (4 - 3)/2 + 1 = 1 (floor).
    // With ceil_mode: div_ceil(4 - 3, 2) + 1 = 1 + 1 = 2!
    // Last window starts at (2 - 1)*2 = 2.
    // Boundary is h + pad = 4 + 0 = 4. Since 2 < 4, last window is valid and not clamped!
    let p_in = TensorPort::new("x", DType::F32, Shape::new(vec![1, 1, 4, 4])?, g)?;
    let p_out = TensorPort::new("y", DType::F32, Shape::new(vec![1, 1, 2, 2])?, g)?;

    let mut pool_attrs = AttributeMap::new();
    pool_attrs.insert("kernel_size".to_string(), AttrValue::IntList(vec![3, 3]));
    pool_attrs.insert("strides".to_string(), AttrValue::IntList(vec![2, 2]));
    pool_attrs.insert("padding".to_string(), AttrValue::IntList(vec![0, 0, 0, 0]));
    pool_attrs.insert("ceil_mode".to_string(), AttrValue::Bool(true));

    let n = GraphNode::new(
        "pool_ceil",
        OpCode::MaxPool2d,
        "p",
        vec!["x".to_string()],
        vec!["y".to_string()],
        pool_attrs,
    )?;
    let gr = ModelIrGraph::builder("g_pool_ceil", g)
        .add_input(p_in)
        .add_output(p_out)
        .add_node(n)
        .build_and_validate()?;

    // Values: 4x4 matrix from 1.0 to 16.0
    let vals: Vec<f32> = (1..=16).map(|v| v as f32).collect();
    let in_t = Tensor::from_values(Shape::new(vec![1, 1, 4, 4])?, &vals, g)?;

    let cx = ScalarExecCx::new();
    let out = ScalarExecutor::run(&gr, &[("x", in_t)], ExecBudget::unlimited(), &cx)?;
    let y_t = out.get_output("y").ok_or("missing output y")?;
    let res = y_t.to_vec::<f32>()?;

    // Window (0, 0): rows 0..3, cols 0..3 -> max is at (2, 2) = val 11
    // Window (0, 1): rows 0..3, cols 2..4 (clipped) -> max is at (2, 3) = val 12
    // Window (1, 0): rows 2..4, cols 0..3 -> max is at (3, 2) = val 15
    // Window (1, 1): rows 2..4, cols 2..4 -> max is at (3, 3) = val 16
    assert_eq!(res, vec![11.0_f32, 12.0, 15.0, 16.0]);

    Ok(())
}

#[test]
fn test_preprocess_program_execution() -> Result<(), Box<dyn Error>> {
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
    // R channel at (0, 0)
    assert_eq!(f_vals[0], 0.0 / 255.0);
    // G channel at (0, 0) -> offset 4
    assert_eq!(f_vals[4], 128.0 / 255.0);
    // B channel at (0, 0) -> offset 8
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

    Ok(())
}

#[test]
fn test_deterministic_exp_f32_pinned_bit_constants() {
    // Exact bit representations pinning deterministic_exp_f32
    assert_eq!(deterministic_exp_f32(1.0).to_bits(), 0x402DF854);
    assert_eq!(deterministic_exp_f32(0.0).to_bits(), 0x3F800000);
    assert_eq!(deterministic_exp_f32(-1.0).to_bits(), 0x3EBC5AB2);
    assert_eq!(deterministic_exp_f32(10.0).to_bits(), 0x46AC54EE);
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

    // Verify there is no wildcard arm matching on OpCode
    let has_wildcard = src.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == "_ =>" || trimmed.starts_with("_ =>") || trimmed.starts_with("_ |")
    });
    assert!(
        !has_wildcard,
        "scalar_executor.rs must not contain wildcard arms"
    );

    // Verify all 3 match blocks explicitly name the unsupported variants (Gelu | Silu | ...)
    let unsupported_count = src.matches("OpCode::Gelu").count();
    assert_eq!(
        unsupported_count, 3,
        "scalar_executor.rs must have exactly 3 explicit unsupported OpCode match lists"
    );

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
        assert!(close(&y[2..4], &[0.731_058_6, 0.268_941_43], 2e-7), "{y:?}");
        assert!(y[4].is_nan());
        assert_eq!(y[5], 1.0);
        assert_eq!(y[6], 0.0);
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
    fn p13_unsupported_op_after_supported_op_refused_before_execution() -> R {
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
            .add_node(node(
                "b_tanh",
                OpCode::Tanh,
                &["m"],
                &["y"],
                AttributeMap::new(),
            )?)
            .build_and_validate()?;
        match run(&gr, vec![("x", t(&[4], &[1.0; 4])?)]) {
            Err(ExecError::UnsupportedOperator { op, .. }) => assert_eq!(op, OpCode::Tanh),
            other => return Err(format!("expected UnsupportedOperator, got {other:?}").into()),
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
        println!("CAPLOG p14 {r:?}");
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
        println!("CAPLOG p15 {r:?}");
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
        println!("CAPLOG p16 {r:?}");
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
        // K=2^20 window with stride K: 1 output element, 2^21 window visits, 0 MACs charged.
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
                println!("CAPLOG p20 relu {r:?}");
            }
            Err(e) => println!("CAPLOG p20 relu refused by IR: {e}"),
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
            Err(e) => println!("CAPLOG p20 matmul refused by IR: {e}"),
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
