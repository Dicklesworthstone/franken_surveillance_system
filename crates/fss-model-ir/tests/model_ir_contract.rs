//! Comprehensive contract tests for the pure-Rust Model Operator IR v1.
//!
//! Ref: fss-x4a.14.8 / FSS-137

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::path::Path;

use fss_core::Generation;
use fss_model_ir::{
    AttrValue, AttributeMap, GraphNode, MODEL_IR_DIGEST_DOMAIN, ModelIrError, ModelIrGraph,
    ModelIrVersion, OpCode, TensorPort,
};
use fss_tensor::{DType, Shape};

fn gen1() -> Generation {
    Generation::from_u64(1)
}

fn gen2() -> Generation {
    Generation::from_u64(2)
}

#[test]
fn test_closed_operator_set_admissions() -> Result<(), Box<dyn Error>> {
    let ops = OpCode::all();
    assert_eq!(ops.len(), 22, "Model IR v1 must contain exactly 22 closed operators");

    for &op in ops {
        let stable_id = op.stable_id();
        let name = op.name();

        assert!(stable_id.starts_with("OP-"));
        assert!(stable_id.ends_with("-001"));
        assert!(!name.is_empty());

        let resolved_id = OpCode::from_stable_id(stable_id)?;
        assert_eq!(resolved_id, op);

        let resolved_name = OpCode::from_name(name)?;
        assert_eq!(resolved_name, op);

        assert!(OpCode::is_admitted(stable_id));
        assert!(OpCode::is_admitted(name));
    }

    match OpCode::from_stable_id("OP-UNKNOWN-999") {
        Err(ModelIrError::UnknownOperator { op_id }) => {
            assert_eq!(op_id, "OP-UNKNOWN-999");
        }
        other => return Err(format!("expected UnknownOperator, got {other:?}").into()),
    }

    match OpCode::from_name("unknown_nonexistent_op") {
        Err(ModelIrError::UnknownOperator { op_id }) => {
            assert_eq!(op_id, "unknown_nonexistent_op");
        }
        other => return Err(format!("expected UnknownOperator, got {other:?}").into()),
    }

    assert!(!OpCode::is_admitted("OP-UNKNOWN-999"));
    assert!(!OpCode::is_admitted("unknown_nonexistent_op"));
    Ok(())
}

#[test]
fn test_version_pin_and_mismatch() -> Result<(), Box<dyn Error>> {
    assert_eq!(ModelIrVersion::V1.as_u32(), 1);
    assert_eq!(ModelIrVersion::from_u32(1)?, ModelIrVersion::V1);

    match ModelIrVersion::from_u32(2) {
        Err(ModelIrError::VersionMismatch { expected, actual }) => {
            assert_eq!(expected, 1);
            assert_eq!(actual, 2);
        }
        other => return Err(format!("expected VersionMismatch, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_valid_feedforward_graph() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let x_port = TensorPort::new("x", DType::F32, Shape::new(vec![32, 128])?, g)?;
    let w_port = TensorPort::new("w", DType::F32, Shape::new(vec![128, 64])?, g)?;
    let b_port = TensorPort::new("b", DType::F32, Shape::new(vec![64])?, g)?;
    let out_port = TensorPort::new("out", DType::F32, Shape::new(vec![32, 64])?, g)?;

    let n1 = GraphNode::new(
        "matmul1",
        OpCode::MatMul,
        "first_linear",
        vec!["x".to_string(), "w".to_string()],
        vec!["mm".to_string()],
        AttributeMap::new(),
    )?;

    let n2 = GraphNode::new(
        "add1",
        OpCode::Add,
        "bias_add",
        vec!["mm".to_string(), "b".to_string()],
        vec!["biased".to_string()],
        AttributeMap::new(),
    )?;

    let n3 = GraphNode::new(
        "relu1",
        OpCode::Relu,
        "activation",
        vec!["biased".to_string()],
        vec!["out".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::builder("mlp_layer", g)
        .add_input(x_port)
        .add_input(w_port)
        .add_input(b_port)
        .add_output(out_port)
        .add_node(n1)
        .add_node(n2)
        .add_node(n3)
        .build_and_validate()?;

    assert_eq!(graph.id(), "mlp_layer");
    assert_eq!(graph.node_count(), 3);
    assert_eq!(graph.input_count(), 3);
    assert_eq!(graph.output_count(), 1);

    let digest = graph.content_digest()?;
    assert_ne!(digest.bytes(), [0u8; 32]);
    Ok(())
}

#[test]
fn test_valid_cnn_graph() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let img_port = TensorPort::new("img", DType::F32, Shape::new(vec![4, 3, 32, 32])?, g)?;
    let wt_port = TensorPort::new("wt", DType::F32, Shape::new(vec![16, 3, 3, 3])?, g)?;
    // Conv output: (32 + 2 - 3)/1 + 1 = 32 -> [4, 16, 32, 32]
    // Pool output: (32 - 2)/2 + 1 = 16 -> [4, 16, 16, 16]
    let out_port = TensorPort::new("pooled", DType::F32, Shape::new(vec![4, 16, 16, 16])?, g)?;

    let mut conv_attrs = AttributeMap::new();
    conv_attrs.insert("strides".to_string(), AttrValue::IntList(vec![1, 1]));
    conv_attrs.insert("padding".to_string(), AttrValue::IntList(vec![1, 1, 1, 1]));

    let mut pool_attrs = AttributeMap::new();
    pool_attrs.insert("kernel_size".to_string(), AttrValue::IntList(vec![2, 2]));
    pool_attrs.insert("strides".to_string(), AttrValue::IntList(vec![2, 2]));
    pool_attrs.insert("padding".to_string(), AttrValue::IntList(vec![0, 0, 0, 0]));

    let n_conv = GraphNode::new(
        "conv1",
        OpCode::Conv2d,
        "spatial_conv",
        vec!["img".to_string(), "wt".to_string()],
        vec!["conv_out".to_string()],
        conv_attrs,
    )?;

    let n_relu = GraphNode::new(
        "relu1",
        OpCode::Relu,
        "relu_activation",
        vec!["conv_out".to_string()],
        vec!["relu_out".to_string()],
        AttributeMap::new(),
    )?;

    let n_pool = GraphNode::new(
        "pool1",
        OpCode::MaxPool2d,
        "spatial_maxpool",
        vec!["relu_out".to_string()],
        vec!["pooled".to_string()],
        pool_attrs,
    )?;

    let graph = ModelIrGraph::builder("cnn_block", g)
        .add_input(img_port)
        .add_input(wt_port)
        .add_output(out_port)
        .add_node(n_conv)
        .add_node(n_relu)
        .add_node(n_pool)
        .build_and_validate()?;

    let digest = graph.content_digest()?;
    assert_ne!(digest.bytes(), [0u8; 32]);
    Ok(())
}

#[test]
fn test_valid_transformer_block_graph() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let hidden_port = TensorPort::new("hidden", DType::F32, Shape::new(vec![2, 16, 64])?, g)?;
    let w_port = TensorPort::new("w_proj", DType::F32, Shape::new(vec![64, 64])?, g)?;
    let out_port = TensorPort::new("residual", DType::F32, Shape::new(vec![2, 16, 64])?, g)?;

    let mut norm_attrs = AttributeMap::new();
    norm_attrs.insert("eps".to_string(), AttrValue::Float(1e-5));

    let mut softmax_attrs = AttributeMap::new();
    softmax_attrs.insert("axis".to_string(), AttrValue::Int(2));

    let n1 = GraphNode::new(
        "norm",
        OpCode::RMSNorm,
        "pre_norm",
        vec!["hidden".to_string()],
        vec!["normed".to_string()],
        norm_attrs,
    )?;

    let n2 = GraphNode::new(
        "proj",
        OpCode::MatMul,
        "projection",
        vec!["normed".to_string(), "w_proj".to_string()],
        vec!["projected".to_string()],
        AttributeMap::new(),
    )?;

    let n3 = GraphNode::new(
        "sm",
        OpCode::Softmax,
        "attention_softmax",
        vec!["projected".to_string()],
        vec!["act".to_string()],
        softmax_attrs,
    )?;

    let n4 = GraphNode::new(
        "res",
        OpCode::Add,
        "residual_connection",
        vec!["act".to_string(), "hidden".to_string()],
        vec!["residual".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::builder("transformer_sublayer", g)
        .add_input(hidden_port)
        .add_input(w_port)
        .add_output(out_port)
        .add_node(n1)
        .add_node(n2)
        .add_node(n3)
        .add_node(n4)
        .build_and_validate()?;

    let digest = graph.content_digest()?;
    assert_ne!(digest.bytes(), [0u8; 32]);
    Ok(())
}

#[test]
fn test_valid_embedding_graph() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let indices_port = TensorPort::new("idx", DType::I64, Shape::new(vec![8, 32])?, g)?;
    let table_port = TensorPort::new("tbl", DType::F32, Shape::new(vec![1000, 128])?, g)?;
    let out_port = TensorPort::new("emb", DType::F32, Shape::new(vec![8, 32, 128])?, g)?;

    let n1 = GraphNode::new(
        "emb1",
        OpCode::Embedding,
        "lookup",
        vec!["idx".to_string(), "tbl".to_string()],
        vec!["emb".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::builder("embedding_layer", g)
        .add_input(indices_port)
        .add_input(table_port)
        .add_output(out_port)
        .add_node(n1)
        .build_and_validate()?;

    let digest = graph.content_digest()?;
    assert_ne!(digest.bytes(), [0u8; 32]);
    Ok(())
}

#[test]
fn test_canonical_digest_determinism_and_sensitivity() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![4, 4])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![4, 4])?, g)?;

    let n = GraphNode::new(
        "relu_node",
        OpCode::Relu,
        "relu_op",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let g1 = ModelIrGraph::builder("base_graph", g)
        .add_input(in_port.clone())
        .add_output(out_port.clone())
        .add_node(n.clone())
        .build_and_validate()?;

    let g2 = ModelIrGraph::builder("base_graph", g)
        .add_input(in_port.clone())
        .add_output(out_port.clone())
        .add_node(n.clone())
        .build_and_validate()?;

    assert_eq!(g1.content_digest()?, g2.content_digest()?);

    // 1. Sensitivity to graph ID
    let g_diff_id = ModelIrGraph::builder("different_graph", g)
        .add_input(in_port.clone())
        .add_output(out_port.clone())
        .add_node(n.clone())
        .build_and_validate()?;
    assert_ne!(g1.content_digest()?, g_diff_id.content_digest()?);

    // 2. Sensitivity to generation
    let g2_gen = gen2();
    let in_port2 = TensorPort::new("x", DType::F32, Shape::new(vec![4, 4])?, g2_gen)?;
    let out_port2 = TensorPort::new("y", DType::F32, Shape::new(vec![4, 4])?, g2_gen)?;
    let g_diff_gen = ModelIrGraph::builder("base_graph", g2_gen)
        .add_input(in_port2)
        .add_output(out_port2)
        .add_node(n.clone())
        .build_and_validate()?;
    assert_ne!(g1.content_digest()?, g_diff_gen.content_digest()?);

    // 3. Sensitivity to operator
    let n_gelu = GraphNode::new(
        "relu_node",
        OpCode::Gelu,
        "relu_op",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;
    let g_diff_op = ModelIrGraph::builder("base_graph", g)
        .add_input(in_port.clone())
        .add_output(out_port.clone())
        .add_node(n_gelu)
        .build_and_validate()?;
    assert_ne!(g1.content_digest()?, g_diff_op.content_digest()?);

    // 4. Sensitivity to node name
    let n_diff_name = GraphNode::new(
        "relu_node",
        OpCode::Relu,
        "different_node_name",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;
    let g_diff_node_name = ModelIrGraph::builder("base_graph", g)
        .add_input(in_port)
        .add_output(out_port)
        .add_node(n_diff_name)
        .build_and_validate()?;
    assert_ne!(g1.content_digest()?, g_diff_node_name.content_digest()?);

    Ok(())
}

#[test]
fn test_schema_domain_and_pinned_counts() -> Result<(), Box<dyn Error>> {
    assert_eq!(MODEL_IR_DIGEST_DOMAIN, b"fss.model_ir.v1\0");

    let domains_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .ok_or("missing root ancestor")?
        .join("registries/DIGEST_DOMAINS.md");
    let content = fs::read_to_string(domains_path)?;
    assert!(
        content.contains("fss.model_ir.v1"),
        "DIGEST_DOMAINS.md must register domain 'fss.model_ir.v1'"
    );

    let schemas_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .ok_or("missing root ancestor")?
        .join("registries/SCHEMAS.md");
    let schemas_content = fs::read_to_string(schemas_path)?;
    let schema_count = schemas_content
        .lines()
        .filter(|line| line.starts_with("| `SCHEMA-"))
        .count();
    assert_eq!(
        schema_count, 71,
        "registries/SCHEMAS.md count must remain pinned at 71"
    );
    Ok(())
}

#[test]
fn test_empty_graph_rejected() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let graph = ModelIrGraph::new("empty", ModelIrVersion::V1, g, vec![], vec![], vec![])?;
    match graph.validate() {
        Err(ModelIrError::EmptyGraph) => {}
        other => return Err(format!("expected EmptyGraph, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_cycle_detected_two_nodes() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![4, 4])?, g)?;
    let out_port = TensorPort::new("b_out", DType::F32, Shape::new(vec![4, 4])?, g)?;

    // Node A consumes b_out and produces a_out
    let n_a = GraphNode::new(
        "node_a",
        OpCode::Relu,
        "a",
        vec!["b_out".to_string()],
        vec!["a_out".to_string()],
        AttributeMap::new(),
    )?;

    // Node B consumes a_out and produces b_out (cycle!)
    let n_b = GraphNode::new(
        "node_b",
        OpCode::Relu,
        "b",
        vec!["a_out".to_string()],
        vec!["b_out".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::new(
        "cycle_graph",
        ModelIrVersion::V1,
        g,
        vec![in_port],
        vec![out_port],
        vec![n_a, n_b],
    )?;

    match graph.validate() {
        Err(ModelIrError::CycleDetected { cycle_path, .. }) => {
            assert!(
                cycle_path.len() >= 2,
                "cycle path must contain loop nodes: {cycle_path:?}"
            );
        }
        other => return Err(format!("expected CycleDetected, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_cycle_detected_three_nodes() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![4, 4])?, g)?;
    let out_port = TensorPort::new("c_out", DType::F32, Shape::new(vec![4, 4])?, g)?;

    // A -> B -> C -> A
    let n_a = GraphNode::new(
        "node_a",
        OpCode::Relu,
        "a",
        vec!["c_out".to_string()],
        vec!["a_out".to_string()],
        AttributeMap::new(),
    )?;
    let n_b = GraphNode::new(
        "node_b",
        OpCode::Relu,
        "b",
        vec!["a_out".to_string()],
        vec!["b_out".to_string()],
        AttributeMap::new(),
    )?;
    let n_c = GraphNode::new(
        "node_c",
        OpCode::Relu,
        "c",
        vec!["b_out".to_string()],
        vec!["c_out".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::new(
        "cycle_3",
        ModelIrVersion::V1,
        g,
        vec![in_port],
        vec![out_port],
        vec![n_a, n_b, n_c],
    )?;

    match graph.validate() {
        Err(ModelIrError::CycleDetected { cycle_path, .. }) => {
            assert!(cycle_path.len() >= 3, "cycle path was: {cycle_path:?}");
        }
        other => return Err(format!("expected CycleDetected, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_dangling_input_rejected() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![4, 4])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![4, 4])?, g)?;

    let n = GraphNode::new(
        "node1",
        OpCode::Relu,
        "relu",
        vec!["nonexistent_tensor".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::new(
        "dangling_in",
        ModelIrVersion::V1,
        g,
        vec![in_port],
        vec![out_port],
        vec![n],
    )?;

    match graph.validate() {
        Err(ModelIrError::DanglingInput {
            node_id,
            tensor_name,
        }) => {
            assert_eq!(node_id, "node1");
            assert_eq!(tensor_name, "nonexistent_tensor");
        }
        other => return Err(format!("expected DanglingInput, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_dangling_output_rejected() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![4, 4])?, g)?;
    let out_port = TensorPort::new("unproduced_output", DType::F32, Shape::new(vec![4, 4])?, g)?;

    let n = GraphNode::new(
        "node1",
        OpCode::Relu,
        "relu",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::new(
        "dangling_out",
        ModelIrVersion::V1,
        g,
        vec![in_port],
        vec![out_port],
        vec![n],
    )?;

    match graph.validate() {
        Err(ModelIrError::DanglingOutput { tensor_name }) => {
            assert_eq!(tensor_name, "unproduced_output");
        }
        other => return Err(format!("expected DanglingOutput, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_duplicate_node_id_rejected() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![4, 4])?, g)?;
    let out_port = TensorPort::new("y2", DType::F32, Shape::new(vec![4, 4])?, g)?;

    let n1 = GraphNode::new(
        "dup_id",
        OpCode::Relu,
        "relu1",
        vec!["x".to_string()],
        vec!["y1".to_string()],
        AttributeMap::new(),
    )?;
    let n2 = GraphNode::new(
        "dup_id",
        OpCode::Relu,
        "relu2",
        vec!["y1".to_string()],
        vec!["y2".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::new(
        "dup_node",
        ModelIrVersion::V1,
        g,
        vec![in_port],
        vec![out_port],
        vec![n1, n2],
    )?;

    match graph.validate() {
        Err(ModelIrError::DuplicateNodeId { node_id }) => {
            assert_eq!(node_id, "dup_id");
        }
        other => return Err(format!("expected DuplicateNodeId, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_duplicate_tensor_output_rejected() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![4, 4])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![4, 4])?, g)?;

    let n1 = GraphNode::new(
        "node1",
        OpCode::Relu,
        "relu1",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;
    let n2 = GraphNode::new(
        "node2",
        OpCode::Gelu,
        "gelu2",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::new(
        "dup_tensor",
        ModelIrVersion::V1,
        g,
        vec![in_port],
        vec![out_port],
        vec![n1, n2],
    )?;

    match graph.validate() {
        Err(ModelIrError::DuplicateTensorOutput {
            tensor_name,
            first_node,
            second_node,
        }) => {
            assert_eq!(tensor_name, "y");
            assert_eq!(first_node, "node1");
            assert_eq!(second_node, "node2");
        }
        other => return Err(format!("expected DuplicateTensorOutput, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_dtype_mismatch_rejected() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_f32 = TensorPort::new("a", DType::F32, Shape::new(vec![4, 4])?, g)?;
    let in_i32 = TensorPort::new("b", DType::I32, Shape::new(vec![4, 4])?, g)?;
    let out = TensorPort::new("c", DType::F32, Shape::new(vec![4, 4])?, g)?;

    let n = GraphNode::new(
        "add_node",
        OpCode::Add,
        "mismatched_add",
        vec!["a".to_string(), "b".to_string()],
        vec!["c".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::new(
        "dtype_mismatch",
        ModelIrVersion::V1,
        g,
        vec![in_f32, in_i32],
        vec![out],
        vec![n],
    )?;

    match graph.validate() {
        Err(ModelIrError::DTypeMismatch {
            expected, actual, ..
        }) => {
            assert_eq!(expected, DType::F32);
            assert_eq!(actual, DType::I32);
        }
        other => return Err(format!("expected DTypeMismatch, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_shape_mismatch_rejected() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in1 = TensorPort::new("a", DType::F32, Shape::new(vec![3, 4])?, g)?;
    let in2 = TensorPort::new("b", DType::F32, Shape::new(vec![5, 6])?, g)?;
    let out = TensorPort::new("c", DType::F32, Shape::new(vec![3, 4])?, g)?;

    let n = GraphNode::new(
        "add_node",
        OpCode::Add,
        "unbroadcastable_add",
        vec!["a".to_string(), "b".to_string()],
        vec!["c".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::new(
        "shape_mismatch",
        ModelIrVersion::V1,
        g,
        vec![in1, in2],
        vec![out],
        vec![n],
    )?;

    match graph.validate() {
        Err(ModelIrError::ShapeMismatch { op_id, .. }) => {
            assert_eq!(op_id, "OP-ADD-001");
        }
        other => return Err(format!("expected ShapeMismatch, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_rank_mismatch_rejected() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    // 2D image provided to Conv2d which strictly expects 4D
    let in_img = TensorPort::new("img", DType::F32, Shape::new(vec![32, 32])?, g)?;
    let in_wt = TensorPort::new("wt", DType::F32, Shape::new(vec![16, 3, 3, 3])?, g)?;
    let out = TensorPort::new("conv_out", DType::F32, Shape::new(vec![1, 16, 30, 30])?, g)?;

    let mut attrs = AttributeMap::new();
    attrs.insert("kernel_shape".to_string(), AttrValue::IntList(vec![3, 3]));

    let n = GraphNode::new(
        "conv",
        OpCode::Conv2d,
        "bad_rank_conv",
        vec!["img".to_string(), "wt".to_string()],
        vec!["conv_out".to_string()],
        attrs,
    )?;

    let graph = ModelIrGraph::new(
        "bad_rank",
        ModelIrVersion::V1,
        g,
        vec![in_img, in_wt],
        vec![out],
        vec![n],
    )?;

    match graph.validate() {
        Err(ModelIrError::RankMismatch {
            expected_rank,
            actual_rank,
            ..
        }) => {
            assert_eq!(expected_rank, 4);
            assert_eq!(actual_rank, 2);
        }
        other => return Err(format!("expected RankMismatch, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_generation_mixing_rejected() -> Result<(), Box<dyn Error>> {
    let g_graph = gen1();
    let g_divergent = gen2();

    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![4, 4])?, g_divergent)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![4, 4])?, g_graph)?;

    let n = GraphNode::new(
        "n",
        OpCode::Relu,
        "relu",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::new(
        "mixed_gen",
        ModelIrVersion::V1,
        g_graph,
        vec![in_port],
        vec![out_port],
        vec![n],
    )?;

    match graph.validate() {
        Err(ModelIrError::GenerationMismatch {
            expected,
            actual,
            tensor_name,
        }) => {
            assert_eq!(expected, g_graph);
            assert_eq!(actual, g_divergent);
            assert_eq!(tensor_name, "x");
        }
        other => return Err(format!("expected GenerationMismatch, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_invalid_attribute_rejected() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![2, 3, 4])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![4, 3, 2])?, g)?;

    // Transpose permutation has out-of-bounds axis 5
    let mut attrs = AttributeMap::new();
    attrs.insert("permutation".to_string(), AttrValue::IntList(vec![0, 1, 5]));

    let n = GraphNode::new(
        "transpose_node",
        OpCode::Transpose,
        "bad_perm",
        vec!["x".to_string()],
        vec!["y".to_string()],
        attrs,
    )?;

    let graph = ModelIrGraph::new(
        "bad_attr",
        ModelIrVersion::V1,
        g,
        vec![in_port],
        vec![out_port],
        vec![n],
    )?;

    match graph.validate() {
        Err(ModelIrError::InvalidAttribute { attr_name, .. }) => {
            assert_eq!(attr_name, "permutation");
        }
        other => return Err(format!("expected InvalidAttribute, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_missing_attribute_rejected() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![2, 8])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![4, 4])?, g)?;

    // Missing required "shape" attribute for Reshape
    let n = GraphNode::new(
        "reshape",
        OpCode::Reshape,
        "missing_shape_reshape",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::new(
        "missing_attr",
        ModelIrVersion::V1,
        g,
        vec![in_port],
        vec![out_port],
        vec![n],
    )?;

    match graph.validate() {
        Err(ModelIrError::MissingAttribute { attr_name, .. }) => {
            assert_eq!(attr_name, "shape");
        }
        other => return Err(format!("expected MissingAttribute, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_invalid_port_count_rejected() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in1 = TensorPort::new("a", DType::F32, Shape::new(vec![4, 4])?, g)?;
    let in2 = TensorPort::new("b", DType::F32, Shape::new(vec![4, 4])?, g)?;
    let out = TensorPort::new("y", DType::F32, Shape::new(vec![4, 4])?, g)?;

    // Relu is a unary op, but 2 inputs are passed
    let n = GraphNode::new(
        "relu_node",
        OpCode::Relu,
        "two_input_relu",
        vec!["a".to_string(), "b".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::new(
        "bad_ports",
        ModelIrVersion::V1,
        g,
        vec![in1, in2],
        vec![out],
        vec![n],
    )?;

    match graph.validate() {
        Err(ModelIrError::InvalidPortCount { actual, .. }) => {
            assert_eq!(actual, 2);
        }
        other => return Err(format!("expected InvalidPortCount, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_declared_output_mismatch_rejected() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![4, 4])?, g)?;
    // Declared shape [4, 8] differs from inferred shape [4, 4]
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![4, 8])?, g)?;

    let n = GraphNode::new(
        "relu",
        OpCode::Relu,
        "r",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::new(
        "out_mismatch",
        ModelIrVersion::V1,
        g,
        vec![in_port],
        vec![out_port],
        vec![n],
    )?;

    match graph.validate() {
        Err(ModelIrError::ShapeMismatch { op_id, .. }) => {
            assert_eq!(op_id, "GRAPH-OUTPUT");
        }
        other => return Err(format!("expected ShapeMismatch, got {other:?}").into()),
    }
    Ok(())
}
