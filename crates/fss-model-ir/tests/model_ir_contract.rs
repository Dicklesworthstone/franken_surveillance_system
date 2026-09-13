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
    ModelIrVersion, OPERATOR_BASELINE_IDS, OPERATOR_SPECS, OPERATOR_TABLE_DIGEST_DOMAIN,
    OPERATOR_TABLE_FREEZE_DIGEST, OPERATOR_TOMBSTONES, OpCode, TensorPort,
    compute_operator_table_digest, verify_operator_baseline, verify_operator_table_frozen,
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
    assert_eq!(
        ops.len(),
        22,
        "Model IR v1 must contain exactly 22 closed operators"
    );

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
    assert_eq!(
        digest.to_string(),
        "sha256:c227ec96549593de1744dca380151b816fff44a08a56fe9a429b44ec5b82f9be"
    );
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
    conv_attrs.insert("dilations".to_string(), AttrValue::IntList(vec![1, 1]));
    conv_attrs.insert("groups".to_string(), AttrValue::Int(1));

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
    assert_eq!(
        digest.to_string(),
        "sha256:7dd31b21b1df9216cbe1fe9f3530ea04f8052b11ff2d1fb100dda452de6db3c3"
    );
    Ok(())
}

#[test]
fn test_valid_transformer_block_graph() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let hidden_port = TensorPort::new("hidden", DType::F32, Shape::new(vec![2, 16, 64])?, g)?;
    let w_port = TensorPort::new("w_proj", DType::F32, Shape::new(vec![64, 64])?, g)?;
    let out_port = TensorPort::new("residual", DType::F32, Shape::new(vec![2, 16, 64])?, g)?;

    let mut norm_attrs = AttributeMap::new();
    norm_attrs.insert("epsilon".to_string(), AttrValue::Float(1e-5));

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
    assert_eq!(
        digest.to_string(),
        "sha256:e20aeab0076636d85f7312f198121368c300e453032c01185d04dd4548ed5cb3"
    );
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
    assert_eq!(
        digest.to_string(),
        "sha256:259f0c834b3b5e4abc7f9b29b61517fa3eeb4e06f33ade1e30a6510dd0e3577a"
    );
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

    assert_eq!(
        g1.content_digest()?.to_string(),
        "sha256:f0e7b3d03dd1312d48d08153b883353e857482cb53fd268fa1e05194c41dd520"
    );
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
        content.contains("`SCHEMA-DOMAIN-MODEL-IR-001`"),
        "DIGEST_DOMAINS.md must register stable ID 'SCHEMA-DOMAIN-MODEL-IR-001'"
    );
    assert!(
        content.contains("fss.model_ir.v1"),
        "DIGEST_DOMAINS.md must register domain 'fss.model_ir.v1'"
    );

    let domain_count = content
        .lines()
        .filter(|line| line.starts_with("| `SCHEMA-DOMAIN-"))
        .count();
    assert_eq!(
        domain_count, 43,
        "registries/DIGEST_DOMAINS.md count must remain pinned at 43"
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

    let attrs = AttributeMap::new();

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

#[test]
fn test_unsqueeze_out_of_bounds_axis_rejected() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![2, 3])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![2, 3, 1])?, g)?;

    let mut attrs = AttributeMap::new();
    // Input rank is 2. With 1 axis added, new_rank is 3. Axis 5 is out of bounds (5 >= 3).
    attrs.insert("axes".to_string(), AttrValue::IntList(vec![5]));

    let n = GraphNode::new(
        "unsq",
        OpCode::Unsqueeze,
        "unsq_op",
        vec!["x".to_string()],
        vec!["y".to_string()],
        attrs,
    )?;

    let graph = ModelIrGraph::new(
        "unsq_oob",
        ModelIrVersion::V1,
        g,
        vec![in_port],
        vec![out_port],
        vec![n],
    )?;

    match graph.validate() {
        Err(ModelIrError::InvalidAttribute { attr_name, .. }) => {
            assert_eq!(attr_name, "axes");
        }
        other => return Err(format!("expected InvalidAttribute for axes, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_unsqueeze_duplicate_axes_rejected() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![2, 3])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![2, 1, 3])?, g)?;

    let mut attrs = AttributeMap::new();
    // Duplicate axis [1, 1]
    attrs.insert("axes".to_string(), AttrValue::IntList(vec![1, 1]));

    let n = GraphNode::new(
        "unsq",
        OpCode::Unsqueeze,
        "unsq_op",
        vec!["x".to_string()],
        vec!["y".to_string()],
        attrs,
    )?;

    let graph = ModelIrGraph::new(
        "unsq_dup",
        ModelIrVersion::V1,
        g,
        vec![in_port],
        vec![out_port],
        vec![n],
    )?;

    match graph.validate() {
        Err(ModelIrError::InvalidAttribute { attr_name, .. }) => {
            assert_eq!(attr_name, "axes");
        }
        other => {
            return Err(
                format!("expected InvalidAttribute for duplicate axes, got {other:?}").into(),
            );
        }
    }
    Ok(())
}

#[test]
fn test_slice_duplicate_axes_rejected() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![4, 8, 16])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![4, 4, 16])?, g)?;

    let mut attrs = AttributeMap::new();
    // Duplicate axis [1, 1]
    attrs.insert("axes".to_string(), AttrValue::IntList(vec![1, 1]));
    attrs.insert("starts".to_string(), AttrValue::IntList(vec![0, 0]));
    attrs.insert("ends".to_string(), AttrValue::IntList(vec![4, 4]));

    let n = GraphNode::new(
        "slice",
        OpCode::Slice,
        "slice_op",
        vec!["x".to_string()],
        vec!["y".to_string()],
        attrs,
    )?;

    let graph = ModelIrGraph::new(
        "slice_dup",
        ModelIrVersion::V1,
        g,
        vec![in_port],
        vec![out_port],
        vec![n],
    )?;

    match graph.validate() {
        Err(ModelIrError::InvalidAttribute { attr_name, .. }) => {
            assert_eq!(attr_name, "axes");
        }
        other => {
            return Err(format!(
                "expected InvalidAttribute for duplicate slice axes, got {other:?}"
            )
            .into());
        }
    }
    Ok(())
}

#[test]
fn test_arithmetic_overflow_reshape_product() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![4, 4])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![16])?, g)?;

    let mut attrs = AttributeMap::new();
    // Multiplying i64::MAX and 3 overflows usize
    attrs.insert("shape".to_string(), AttrValue::IntList(vec![i64::MAX, 3]));

    let n = GraphNode::new(
        "reshape_overflow",
        OpCode::Reshape,
        "reshape_op",
        vec!["x".to_string()],
        vec!["y".to_string()],
        attrs,
    )?;

    let graph = ModelIrGraph::new(
        "reshape_of_graph",
        ModelIrVersion::V1,
        g,
        vec![in_port],
        vec![out_port],
        vec![n],
    )?;

    match graph.validate() {
        Err(ModelIrError::ArithmeticOverflow { operation }) => {
            assert_eq!(operation, "reshape known dimensions product");
        }
        other => return Err(format!("expected ArithmeticOverflow, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_arithmetic_overflow_concat_dimension_summation() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let max_dim = i64::MAX as usize;
    let in_port1 = TensorPort::new("x1", DType::F32, Shape::new(vec![max_dim, 1])?, g)?;
    let in_port2 = TensorPort::new("x2", DType::F32, Shape::new(vec![max_dim, 1])?, g)?;
    let in_port3 = TensorPort::new("x3", DType::F32, Shape::new(vec![10, 1])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![16, 1])?, g)?;

    let mut attrs = AttributeMap::new();
    attrs.insert("axis".to_string(), AttrValue::Int(0));

    let n = GraphNode::new(
        "concat_overflow",
        OpCode::Concat,
        "concat_op",
        vec!["x1".to_string(), "x2".to_string(), "x3".to_string()],
        vec!["y".to_string()],
        attrs,
    )?;

    let graph = ModelIrGraph::new(
        "concat_of_graph",
        ModelIrVersion::V1,
        g,
        vec![in_port1, in_port2, in_port3],
        vec![out_port],
        vec![n],
    )?;

    match graph.validate() {
        Err(ModelIrError::ArithmeticOverflow { operation }) => {
            assert_eq!(operation, "concat dimension summation");
        }
        other => return Err(format!("expected ArithmeticOverflow, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_arithmetic_overflow_conv2d_dilation() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let x_port = TensorPort::new("img", DType::F32, Shape::new(vec![1, 1, 10, 10])?, g)?;
    let w_port = TensorPort::new("w_conv", DType::F32, Shape::new(vec![1, 1, 4, 3])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![1, 1, 4, 4])?, g)?;

    let mut conv_attrs = AttributeMap::new();
    conv_attrs.insert("strides".to_string(), AttrValue::IntList(vec![1, 1]));
    conv_attrs.insert("padding".to_string(), AttrValue::IntList(vec![0, 0, 0, 0]));
    // (4 - 1) * i64::MAX overflows usize during effective kernel calculation
    conv_attrs.insert(
        "dilations".to_string(),
        AttrValue::IntList(vec![i64::MAX, 1]),
    );
    conv_attrs.insert("groups".to_string(), AttrValue::Int(1));

    let n_conv = GraphNode::new(
        "conv_overflow",
        OpCode::Conv2d,
        "conv_op",
        vec!["img".to_string(), "w_conv".to_string()],
        vec!["y".to_string()],
        conv_attrs,
    )?;

    let graph = ModelIrGraph::new(
        "conv_of_graph",
        ModelIrVersion::V1,
        g,
        vec![x_port, w_port],
        vec![out_port],
        vec![n_conv],
    )?;

    match graph.validate() {
        Err(ModelIrError::ArithmeticOverflow { operation }) => {
            assert_eq!(operation, "effective kernel height calculation");
        }
        other => return Err(format!("expected ArithmeticOverflow, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_arithmetic_overflow_conv2d_padding() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let x_port = TensorPort::new("img", DType::F32, Shape::new(vec![1, 1, 10, 10])?, g)?;
    let w_port = TensorPort::new("w_conv", DType::F32, Shape::new(vec![1, 1, 3, 3])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![1, 1, 4, 4])?, g)?;

    let mut conv_attrs = AttributeMap::new();
    conv_attrs.insert("strides".to_string(), AttrValue::IntList(vec![1, 1]));
    // i64::MAX top + i64::MAX bottom + h overflows usize padded height calculation
    conv_attrs.insert(
        "padding".to_string(),
        AttrValue::IntList(vec![i64::MAX, 0, i64::MAX, 0]),
    );
    conv_attrs.insert("dilations".to_string(), AttrValue::IntList(vec![1, 1]));
    conv_attrs.insert("groups".to_string(), AttrValue::Int(1));

    let n_conv = GraphNode::new(
        "conv_pad_overflow",
        OpCode::Conv2d,
        "conv_op",
        vec!["img".to_string(), "w_conv".to_string()],
        vec!["y".to_string()],
        conv_attrs,
    )?;

    let graph = ModelIrGraph::new(
        "conv_pad_of_graph",
        ModelIrVersion::V1,
        g,
        vec![x_port, w_port],
        vec![out_port],
        vec![n_conv],
    )?;

    match graph.validate() {
        Err(ModelIrError::ArithmeticOverflow { operation }) => {
            assert_eq!(operation, "padded height calculation");
        }
        other => return Err(format!("expected ArithmeticOverflow, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_arithmetic_overflow_maxpool2d_padding() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let x_port = TensorPort::new("img", DType::F32, Shape::new(vec![1, 1, 10, 10])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![1, 1, 4, 4])?, g)?;

    let mut pool_attrs = AttributeMap::new();
    pool_attrs.insert("kernel_size".to_string(), AttrValue::IntList(vec![2, 2]));
    pool_attrs.insert("strides".to_string(), AttrValue::IntList(vec![2, 2]));
    // i64::MAX top + i64::MAX bottom + h overflows usize maxpool padded height calculation
    pool_attrs.insert(
        "padding".to_string(),
        AttrValue::IntList(vec![i64::MAX, 0, i64::MAX, 0]),
    );

    let n_pool = GraphNode::new(
        "pool_pad_overflow",
        OpCode::MaxPool2d,
        "maxpool_op",
        vec!["img".to_string()],
        vec!["y".to_string()],
        pool_attrs,
    )?;

    let graph = ModelIrGraph::new(
        "pool_pad_of_graph",
        ModelIrVersion::V1,
        g,
        vec![x_port],
        vec![out_port],
        vec![n_pool],
    )?;

    match graph.validate() {
        Err(ModelIrError::ArithmeticOverflow { operation }) => {
            assert_eq!(operation, "maxpool padded height calculation");
        }
        other => return Err(format!("expected ArithmeticOverflow, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_graph_validator_rejects_unsupported_version() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![4, 4])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![4, 4])?, g)?;

    let n = GraphNode::new(
        "relu",
        OpCode::Relu,
        "r",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::new(
        "unsupported_version_graph",
        ModelIrVersion::unsupported(2),
        g,
        vec![in_port],
        vec![out_port],
        vec![n],
    )?;

    match graph.validate() {
        Err(ModelIrError::VersionMismatch { expected, actual }) => {
            assert_eq!(expected, 1);
            assert_eq!(actual, 2);
        }
        other => return Err(format!("expected VersionMismatch, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_finding_1_unknown_attributes_rejected_everywhere() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let x_port = TensorPort::new("x", DType::F32, Shape::new(vec![4, 4])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![4, 4])?, g)?;

    // Case 1: Relu with {"bogus": 1}
    let mut bogus_attrs = AttributeMap::new();
    bogus_attrs.insert("bogus".to_string(), AttrValue::Int(1));
    let n1 = GraphNode::new(
        "relu_bogus",
        OpCode::Relu,
        "relu_op",
        vec!["x".to_string()],
        vec!["y".to_string()],
        bogus_attrs,
    )?;
    let g1 = ModelIrGraph::new(
        "g_relu_bogus",
        ModelIrVersion::V1,
        g,
        vec![x_port.clone()],
        vec![out_port.clone()],
        vec![n1],
    )?;
    match g1.validate() {
        Err(ModelIrError::InvalidAttribute { attr_name, .. }) => {
            assert_eq!(attr_name, "bogus");
        }
        other => return Err(format!("expected InvalidAttribute for bogus, got {other:?}").into()),
    }

    // Case 2: Conv2d with typo "stride" instead of "strides"
    let img_port = TensorPort::new("img", DType::F32, Shape::new(vec![1, 1, 6, 6])?, g)?;
    let wt_port = TensorPort::new("wt", DType::F32, Shape::new(vec![1, 1, 3, 3])?, g)?;
    let c_out = TensorPort::new("out", DType::F32, Shape::new(vec![1, 1, 4, 4])?, g)?;
    let mut typo_attrs = AttributeMap::new();
    typo_attrs.insert("stride".to_string(), AttrValue::IntList(vec![2, 2]));
    let n2 = GraphNode::new(
        "conv_typo",
        OpCode::Conv2d,
        "conv_op",
        vec!["img".to_string(), "wt".to_string()],
        vec!["out".to_string()],
        typo_attrs,
    )?;
    let g2 = ModelIrGraph::new(
        "g_conv_typo",
        ModelIrVersion::V1,
        g,
        vec![img_port, wt_port],
        vec![c_out],
        vec![n2],
    )?;
    match g2.validate() {
        Err(ModelIrError::InvalidAttribute { attr_name, .. }) => {
            assert_eq!(attr_name, "stride");
        }
        other => {
            return Err(format!("expected InvalidAttribute for stride typo, got {other:?}").into());
        }
    }
    Ok(())
}

#[test]
fn test_finding_2_conv2d_rejects_singular_dilation() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in0 = TensorPort::new("img", DType::F32, Shape::new(vec![1, 1, 6, 6])?, g)?;
    let in1 = TensorPort::new("wt", DType::F32, Shape::new(vec![1, 1, 3, 3])?, g)?;
    let mut bad_attrs = AttributeMap::new();
    bad_attrs.insert("dilation".to_string(), AttrValue::IntList(vec![1, 1]));
    match fss_model_ir::infer_operator_outputs(
        "conv_node",
        OpCode::Conv2d,
        &[&in0, &in1],
        &["out".to_string()],
        &bad_attrs,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute { attr_name, .. }) => {
            assert_eq!(attr_name, "dilation");
        }
        other => {
            return Err(format!("expected InvalidAttribute for dilation, got {other:?}").into());
        }
    }
    Ok(())
}

#[test]
fn test_finding_3_conv2d_dtype_and_shape_invariants() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let img_f32 = TensorPort::new("img", DType::F32, Shape::new(vec![1, 1, 6, 6])?, g)?;
    let wt_i8 = TensorPort::new("wt", DType::I8, Shape::new(vec![1, 1, 3, 3])?, g)?;
    let wt_f32 = TensorPort::new("wt", DType::F32, Shape::new(vec![1, 1, 3, 3])?, g)?;

    // 1. DType mismatch (F32 input, I8 weight)
    match fss_model_ir::infer_operator_outputs(
        "c1",
        OpCode::Conv2d,
        &[&img_f32, &wt_i8],
        &["out".to_string()],
        &AttributeMap::new(),
        g,
    ) {
        Err(ModelIrError::DTypeMismatch {
            expected, actual, ..
        }) => {
            assert_eq!(expected, DType::F32);
            assert_eq!(actual, DType::I8);
        }
        other => return Err(format!("expected DTypeMismatch, got {other:?}").into()),
    }

    // 2. Bool dtype rejected
    let img_bool = TensorPort::new("img_b", DType::Bool, Shape::new(vec![1, 1, 6, 6])?, g)?;
    let wt_bool = TensorPort::new("wt_b", DType::Bool, Shape::new(vec![1, 1, 3, 3])?, g)?;
    match fss_model_ir::infer_operator_outputs(
        "c2",
        OpCode::Conv2d,
        &[&img_bool, &wt_bool],
        &["out".to_string()],
        &AttributeMap::new(),
        g,
    ) {
        Err(ModelIrError::DTypeMismatch { actual, .. }) => {
            assert_eq!(actual, DType::Bool);
        }
        other => return Err(format!("expected DTypeMismatch for Bool, got {other:?}").into()),
    }

    // 3. Bias validation: length must match c_out and dtype must match
    let bias_wrong_len = TensorPort::new("bias_w", DType::F32, Shape::new(vec![4])?, g)?;
    match fss_model_ir::infer_operator_outputs(
        "c3",
        OpCode::Conv2d,
        &[&img_f32, &wt_f32, &bias_wrong_len],
        &["out".to_string()],
        &AttributeMap::new(),
        g,
    ) {
        Err(ModelIrError::ShapeMismatch { reason, .. }) => {
            assert!(reason.contains("bias length 4 must match Conv2d output channels 1"));
        }
        other => {
            return Err(format!("expected ShapeMismatch for bias length, got {other:?}").into());
        }
    }

    let bias_wrong_dtype = TensorPort::new("bias_d", DType::I32, Shape::new(vec![1])?, g)?;
    match fss_model_ir::infer_operator_outputs(
        "c4",
        OpCode::Conv2d,
        &[&img_f32, &wt_f32, &bias_wrong_dtype],
        &["out".to_string()],
        &AttributeMap::new(),
        g,
    ) {
        Err(ModelIrError::DTypeMismatch {
            expected, actual, ..
        }) => {
            assert_eq!(expected, DType::F32);
            assert_eq!(actual, DType::I32);
        }
        other => {
            return Err(format!("expected DTypeMismatch for bias dtype, got {other:?}").into());
        }
    }

    // 4. Kernel size cannot be 0
    let wt_zero_k = TensorPort::new("wt_z", DType::F32, Shape::new(vec![1, 1, 0, 3])?, g)?;
    match fss_model_ir::infer_operator_outputs(
        "c5",
        OpCode::Conv2d,
        &[&img_f32, &wt_zero_k],
        &["out".to_string()],
        &AttributeMap::new(),
        g,
    ) {
        Err(ModelIrError::ShapeMismatch { reason, .. }) => {
            assert!(reason.contains("kernel dimensions [0, 3] must be non-zero positive integers"));
        }
        other => {
            return Err(format!("expected ShapeMismatch for zero kernel, got {other:?}").into());
        }
    }

    // 5. out_channels must be divisible by groups
    let img_grouped = TensorPort::new("img_g", DType::F32, Shape::new(vec![1, 4, 6, 6])?, g)?;
    let wt_grouped = TensorPort::new("wt_g", DType::F32, Shape::new(vec![5, 2, 3, 3])?, g)?;
    let mut group_attrs = AttributeMap::new();
    group_attrs.insert("groups".to_string(), AttrValue::Int(2));
    match fss_model_ir::infer_operator_outputs(
        "c6",
        OpCode::Conv2d,
        &[&img_grouped, &wt_grouped],
        &["out".to_string()],
        &group_attrs,
        g,
    ) {
        Err(ModelIrError::ShapeMismatch { reason, .. }) => {
            assert!(reason.contains("incompatible groups (2)"));
        }
        other => {
            return Err(
                format!("expected ShapeMismatch for groups divisibility, got {other:?}").into(),
            );
        }
    }
    Ok(())
}

#[test]
fn test_finding_4_layernorm_and_rmsnorm_strict_invariants() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let x_f32 = TensorPort::new("x", DType::F32, Shape::new(vec![2, 4, 8])?, g)?;
    let wt_f32 = TensorPort::new("wt", DType::F32, Shape::new(vec![8])?, g)?;
    let bias_f32 = TensorPort::new("bias", DType::F32, Shape::new(vec![8])?, g)?;
    let extra = TensorPort::new("extra", DType::F32, Shape::new(vec![8])?, g)?;

    // 1. Input count bounds: LayerNorm max 3, RMSNorm max 2
    match fss_model_ir::infer_operator_outputs(
        "ln1",
        OpCode::LayerNorm,
        &[&x_f32, &wt_f32, &bias_f32, &extra],
        &["out".to_string()],
        &AttributeMap::new(),
        g,
    ) {
        Err(ModelIrError::InvalidPortCount { actual, .. }) => {
            assert_eq!(actual, 4);
        }
        other => {
            return Err(
                format!("expected InvalidPortCount for LayerNorm 4 inputs, got {other:?}").into(),
            );
        }
    }

    match fss_model_ir::infer_operator_outputs(
        "rms1",
        OpCode::RMSNorm,
        &[&x_f32, &wt_f32, &bias_f32],
        &["out".to_string()],
        &AttributeMap::new(),
        g,
    ) {
        Err(ModelIrError::InvalidPortCount { actual, .. }) => {
            assert_eq!(actual, 3);
        }
        other => {
            return Err(
                format!("expected InvalidPortCount for RMSNorm 3 inputs, got {other:?}").into(),
            );
        }
    }

    // 2. Input dtype must be floating point
    let x_i32 = TensorPort::new("x_int", DType::I32, Shape::new(vec![2, 4, 8])?, g)?;
    match fss_model_ir::infer_operator_outputs(
        "ln2",
        OpCode::LayerNorm,
        &[&x_i32],
        &["out".to_string()],
        &AttributeMap::new(),
        g,
    ) {
        Err(ModelIrError::DTypeMismatch { actual, .. }) => {
            assert_eq!(actual, DType::I32);
        }
        other => {
            return Err(format!("expected DTypeMismatch for int LayerNorm, got {other:?}").into());
        }
    }

    // 3. Weight and bias dtypes must match input
    let wt_f64 = TensorPort::new("wt_64", DType::F64, Shape::new(vec![8])?, g)?;
    match fss_model_ir::infer_operator_outputs(
        "ln3",
        OpCode::LayerNorm,
        &[&x_f32, &wt_f64],
        &["out".to_string()],
        &AttributeMap::new(),
        g,
    ) {
        Err(ModelIrError::DTypeMismatch {
            expected, actual, ..
        }) => {
            assert_eq!(expected, DType::F32);
            assert_eq!(actual, DType::F64);
        }
        other => return Err(format!("expected DTypeMismatch for wt dtype, got {other:?}").into()),
    }

    let bias_f64 = TensorPort::new("b_64", DType::F64, Shape::new(vec![8])?, g)?;
    match fss_model_ir::infer_operator_outputs(
        "ln4",
        OpCode::LayerNorm,
        &[&x_f32, &wt_f32, &bias_f64],
        &["out".to_string()],
        &AttributeMap::new(),
        g,
    ) {
        Err(ModelIrError::DTypeMismatch {
            expected, actual, ..
        }) => {
            assert_eq!(expected, DType::F32);
            assert_eq!(actual, DType::F64);
        }
        other => {
            return Err(format!("expected DTypeMismatch for bias dtype, got {other:?}").into());
        }
    }

    // 4. Weight and bias shapes must match normalized_shape
    let wt_wrong_shape = TensorPort::new("wt_bad", DType::F32, Shape::new(vec![4])?, g)?;
    match fss_model_ir::infer_operator_outputs(
        "ln5",
        OpCode::LayerNorm,
        &[&x_f32, &wt_wrong_shape],
        &["out".to_string()],
        &AttributeMap::new(),
        g,
    ) {
        Err(ModelIrError::ShapeMismatch { reason, .. }) => {
            assert!(reason.contains("normalized shape"));
        }
        other => return Err(format!("expected ShapeMismatch for wt shape, got {other:?}").into()),
    }

    // 5. Epsilon validation: negative or NaN must be rejected
    let mut neg_eps_attrs = AttributeMap::new();
    neg_eps_attrs.insert("epsilon".to_string(), AttrValue::Float(-1.0));
    match fss_model_ir::infer_operator_outputs(
        "ln6",
        OpCode::LayerNorm,
        &[&x_f32],
        &["out".to_string()],
        &neg_eps_attrs,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute { attr_name, .. }) => {
            assert_eq!(attr_name, "epsilon");
        }
        other => {
            return Err(
                format!("expected InvalidAttribute for negative epsilon, got {other:?}").into(),
            );
        }
    }

    let mut nan_eps_attrs = AttributeMap::new();
    nan_eps_attrs.insert("epsilon".to_string(), AttrValue::Float(f64::NAN));
    match fss_model_ir::infer_operator_outputs(
        "ln7",
        OpCode::LayerNorm,
        &[&x_f32],
        &["out".to_string()],
        &nan_eps_attrs,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute { attr_name, .. }) => {
            assert_eq!(attr_name, "epsilon");
        }
        other => {
            return Err(format!("expected InvalidAttribute for NaN epsilon, got {other:?}").into());
        }
    }

    let mut str_eps_attrs = AttributeMap::new();
    str_eps_attrs.insert("epsilon".to_string(), AttrValue::String("1e-5".to_string()));
    match fss_model_ir::infer_operator_outputs(
        "ln8",
        OpCode::LayerNorm,
        &[&x_f32],
        &["out".to_string()],
        &str_eps_attrs,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute { attr_name, .. }) => {
            assert_eq!(attr_name, "epsilon");
        }
        other => {
            return Err(
                format!("expected InvalidAttribute for String epsilon, got {other:?}").into(),
            );
        }
    }
    Ok(())
}

#[test]
fn test_finding_5_softmax_rank0_and_axis_bounds() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let scalar_port = TensorPort::new("s", DType::F32, Shape::scalar(), g)?;

    // Rank 0 input to Softmax must fail closed with RankMismatch
    match fss_model_ir::infer_operator_outputs(
        "sm0",
        OpCode::Softmax,
        &[&scalar_port],
        &["out".to_string()],
        &AttributeMap::new(),
        g,
    ) {
        Err(ModelIrError::RankMismatch {
            expected_rank,
            actual_rank,
            ..
        }) => {
            assert_eq!(expected_rank, 1);
            assert_eq!(actual_rank, 0);
        }
        other => {
            return Err(format!("expected RankMismatch on rank-0 Softmax, got {other:?}").into());
        }
    }

    // Axis >= rank must fail with InvalidAttribute
    let tensor2d = TensorPort::new("t2", DType::F32, Shape::new(vec![4, 8])?, g)?;
    let mut bad_axis_attrs = AttributeMap::new();
    bad_axis_attrs.insert("axis".to_string(), AttrValue::Int(2));
    match fss_model_ir::infer_operator_outputs(
        "sm1",
        OpCode::Softmax,
        &[&tensor2d],
        &["out".to_string()],
        &bad_axis_attrs,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute { attr_name, .. }) => {
            assert_eq!(attr_name, "axis");
        }
        other => {
            return Err(format!("expected InvalidAttribute on axis >= rank, got {other:?}").into());
        }
    }
    Ok(())
}

#[test]
fn test_finding_6_squeeze_duplicate_axes_rejected() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![2, 1, 1, 4])?, g)?;
    let mut dup_attrs = AttributeMap::new();
    dup_attrs.insert("axes".to_string(), AttrValue::IntList(vec![1, 1]));

    match fss_model_ir::infer_operator_outputs(
        "sq1",
        OpCode::Squeeze,
        &[&in_port],
        &["out".to_string()],
        &dup_attrs,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute {
            attr_name, reason, ..
        }) => {
            assert_eq!(attr_name, "axes");
            assert!(reason.contains("duplicate axis 1"));
        }
        other => {
            return Err(format!(
                "expected InvalidAttribute for duplicate squeeze axes, got {other:?}"
            )
            .into());
        }
    }
    Ok(())
}

#[test]
fn test_finding_7_maxpool2d_padding_ge_kernel_size_rejected() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let img = TensorPort::new("img", DType::F32, Shape::new(vec![1, 1, 10, 10])?, g)?;

    // Top padding 2 >= kernel_size 2
    let mut attrs = AttributeMap::new();
    attrs.insert("kernel_size".to_string(), AttrValue::IntList(vec![2, 2]));
    attrs.insert("padding".to_string(), AttrValue::IntList(vec![2, 0, 0, 0]));

    match fss_model_ir::infer_operator_outputs(
        "mp1",
        OpCode::MaxPool2d,
        &[&img],
        &["out".to_string()],
        &attrs,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute {
            attr_name, reason, ..
        }) => {
            assert_eq!(attr_name, "padding");
            assert!(reason.contains("strictly less than kernel size"));
        }
        other => {
            return Err(format!(
                "expected InvalidAttribute for padding >= kernel size, got {other:?}"
            )
            .into());
        }
    }

    // Left padding 2 >= kernel_size 2
    let mut attrs2 = AttributeMap::new();
    attrs2.insert("kernel_size".to_string(), AttrValue::IntList(vec![2, 2]));
    attrs2.insert("padding".to_string(), AttrValue::IntList(vec![0, 2, 0, 0]));

    match fss_model_ir::infer_operator_outputs(
        "mp2",
        OpCode::MaxPool2d,
        &[&img],
        &["out".to_string()],
        &attrs2,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute {
            attr_name, reason, ..
        }) => {
            assert_eq!(attr_name, "padding");
            assert!(reason.contains("strictly less than kernel size"));
        }
        other => {
            return Err(format!(
                "expected InvalidAttribute for padding >= kernel size, got {other:?}"
            )
            .into());
        }
    }
    Ok(())
}

#[test]
fn test_finding_8_element_counts_and_reshape_overflow() -> Result<(), Box<dyn Error>> {
    let g = gen1();

    // 1. TensorPort::new rejects element count overflowing i64
    let overflow_shape = Shape::new(vec![i64::MAX as usize, 2])?;
    match TensorPort::new("big", DType::F32, overflow_shape, g) {
        Err(ModelIrError::ArithmeticOverflow { .. }) => {}
        other => {
            return Err(
                format!("expected ArithmeticOverflow for huge shape, got {other:?}").into(),
            );
        }
    }

    // 2. Reshape rejects non-zero product exceeding i64::MAX when 0 is present
    let in_port = TensorPort::new("in", DType::F32, Shape::new(vec![1, 10])?, g)?;
    let mut attrs = AttributeMap::new();
    attrs.insert(
        "shape".to_string(),
        AttrValue::IntList(vec![0, i64::MAX, i64::MAX]),
    );

    match fss_model_ir::infer_operator_outputs(
        "rs1",
        OpCode::Reshape,
        &[&in_port],
        &["out".to_string()],
        &attrs,
        g,
    ) {
        Err(ModelIrError::ArithmeticOverflow { operation }) => {
            assert!(operation.contains("reshape"));
        }
        other => {
            return Err(
                format!("expected ArithmeticOverflow for reshape product, got {other:?}").into(),
            );
        }
    }
    Ok(())
}

#[test]
fn test_finding_9_graph_validator_duplicate_outputs_rejected() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![4, 4])?, g)?;
    let out1 = TensorPort::new("y", DType::F32, Shape::new(vec![4, 4])?, g)?;
    let out2 = TensorPort::new("y", DType::F32, Shape::new(vec![4, 4])?, g)?;

    let n = GraphNode::new(
        "r",
        OpCode::Relu,
        "relu",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::new(
        "dup_out_graph",
        ModelIrVersion::V1,
        g,
        vec![in_port],
        vec![out1, out2],
        vec![n],
    )?;

    match graph.validate() {
        Err(ModelIrError::DuplicateTensorOutput { tensor_name, .. }) => {
            assert_eq!(tensor_name, "y");
        }
        other => return Err(format!("expected DuplicateTensorOutput, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_finding_10_model_ir_version_unsupported_mapping() -> Result<(), Box<dyn Error>> {
    let v_unsupported = ModelIrVersion::unsupported(1);
    assert_eq!(v_unsupported.as_u32(), 0);
    assert!(!v_unsupported.is_supported());

    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![2, 2])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![2, 2])?, g)?;
    let n = GraphNode::new(
        "r",
        OpCode::Relu,
        "relu",
        vec!["x".to_string()],
        vec!["y".to_string()],
        AttributeMap::new(),
    )?;

    let graph = ModelIrGraph::new(
        "unsupported_1_graph",
        v_unsupported,
        g,
        vec![in_port],
        vec![out_port],
        vec![n],
    )?;

    match graph.validate() {
        Err(ModelIrError::VersionMismatch { expected, actual }) => {
            assert_eq!(expected, 1);
            assert_eq!(actual, 0);
        }
        other => return Err(format!("expected VersionMismatch (1 != 0), got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn test_finding_11_content_digest_validates_before_hashing() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![4, 4])?, g)?;
    let out_port = TensorPort::new("b_out", DType::F32, Shape::new(vec![4, 4])?, g)?;

    // Cyclic graph
    let n_a = GraphNode::new(
        "node_a",
        OpCode::Relu,
        "a",
        vec!["b_out".to_string()],
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

    let cyclic_graph = ModelIrGraph::new(
        "cyclic",
        ModelIrVersion::V1,
        g,
        vec![in_port.clone()],
        vec![out_port.clone()],
        vec![n_a, n_b],
    )?;

    match cyclic_graph.content_digest() {
        Err(ModelIrError::CycleDetected { .. }) => {}
        other => {
            return Err(
                format!("expected CycleDetected from content_digest, got {other:?}").into(),
            );
        }
    }

    // Graph with dangling output
    let valid_node = GraphNode::new(
        "r",
        OpCode::Relu,
        "relu",
        vec!["x".to_string()],
        vec!["y_actual".to_string()],
        AttributeMap::new(),
    )?;
    let dangling_out = TensorPort::new("y_missing", DType::F32, Shape::new(vec![4, 4])?, g)?;
    let dangling_graph = ModelIrGraph::new(
        "dangling",
        ModelIrVersion::V1,
        g,
        vec![in_port],
        vec![dangling_out],
        vec![valid_node],
    )?;

    match dangling_graph.content_digest() {
        Err(ModelIrError::DanglingOutput { tensor_name }) => {
            assert_eq!(tensor_name, "y_missing");
        }
        other => {
            return Err(
                format!("expected DanglingOutput from content_digest, got {other:?}").into(),
            );
        }
    }
    Ok(())
}

#[test]
fn test_finding_12_canonical_digest_determinism_and_defaults() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let x1 = TensorPort::new("x1", DType::F32, Shape::new(vec![2, 2])?, g)?;
    let x2 = TensorPort::new("x2", DType::F32, Shape::new(vec![2, 2])?, g)?;
    let y1 = TensorPort::new("y1", DType::F32, Shape::new(vec![2, 2])?, g)?;
    let y2 = TensorPort::new("y2", DType::F32, Shape::new(vec![2, 2])?, g)?;

    let n1 = GraphNode::new(
        "n1",
        OpCode::Relu,
        "r1",
        vec!["x1".to_string()],
        vec!["y1".to_string()],
        AttributeMap::new(),
    )?;
    let n2 = GraphNode::new(
        "n2",
        OpCode::Relu,
        "r2",
        vec!["x2".to_string()],
        vec!["y2".to_string()],
        AttributeMap::new(),
    )?;

    // Insertion order [n1, n2]
    let g_a = ModelIrGraph::builder("order_test", g)
        .add_input(x1.clone())
        .add_input(x2.clone())
        .add_output(y1.clone())
        .add_output(y2.clone())
        .add_node(n1.clone())
        .add_node(n2.clone())
        .build_and_validate()?;

    // Insertion order [n2, n1]
    let g_b = ModelIrGraph::builder("order_test", g)
        .add_input(x1.clone())
        .add_input(x2.clone())
        .add_output(y1.clone())
        .add_output(y2.clone())
        .add_node(n2)
        .add_node(n1)
        .build_and_validate()?;

    assert_eq!(
        g_a.content_digest()?,
        g_b.content_digest()?,
        "Canonical digest must be invariant to insertion order of independent nodes"
    );

    // Float canonicalization: -0.0 vs +0.0 in float attribute
    let mut attrs_pos = AttributeMap::new();
    attrs_pos.insert("epsilon".to_string(), AttrValue::Float(0.0));
    let n_pos = GraphNode::new(
        "ln1",
        OpCode::LayerNorm,
        "ln",
        vec!["x1".to_string()],
        vec!["y1".to_string()],
        attrs_pos,
    )?;

    let mut attrs_neg = AttributeMap::new();
    attrs_neg.insert("epsilon".to_string(), AttrValue::Float(-0.0));
    let n_neg = GraphNode::new(
        "ln1",
        OpCode::LayerNorm,
        "ln",
        vec!["x1".to_string()],
        vec!["y1".to_string()],
        attrs_neg,
    )?;

    let g_pos = ModelIrGraph::builder("ln_pos", g)
        .add_input(x1.clone())
        .add_output(y1.clone())
        .add_node(n_pos)
        .build_and_validate()?;

    let g_neg = ModelIrGraph::builder("ln_pos", g)
        .add_input(x1)
        .add_output(y1)
        .add_node(n_neg)
        .build_and_validate()?;

    assert_eq!(
        g_pos.content_digest()?,
        g_neg.content_digest()?,
        "-0.0 and +0.0 float attributes must encode identically"
    );
    Ok(())
}

#[test]
fn test_finding_13_and_14_operator_table_freeze_and_baseline() -> Result<(), Box<dyn Error>> {
    // Finding 13: Operator table freeze digest matches pinned constant
    let digest = compute_operator_table_digest()?;
    assert_eq!(
        digest.to_string(),
        OPERATOR_TABLE_FREEZE_DIGEST,
        "Live operator table digest must match OPERATOR_TABLE_FREEZE_DIGEST"
    );
    verify_operator_table_frozen()?;

    // Finding 14: Baseline operators and empty tombstones
    assert_eq!(OPERATOR_BASELINE_IDS.len(), 22);
    assert_eq!(OPERATOR_SPECS.len(), 22);
    assert!(OPERATOR_TOMBSTONES.is_empty());
    verify_operator_baseline()?;

    assert_eq!(
        OPERATOR_TABLE_DIGEST_DOMAIN,
        b"fss.model_ir.operator_table.v1\0"
    );
    Ok(())
}

#[test]
fn test_finding_16_width_side_arithmetic_overflow_checks() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let x_port = TensorPort::new("img", DType::F32, Shape::new(vec![1, 1, 10, 10])?, g)?;
    let w_port = TensorPort::new("w_conv", DType::F32, Shape::new(vec![1, 1, 3, 4])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![1, 1, 4, 4])?, g)?;

    // 1. Conv2d width dilation overflow: (k_w - 1) * dilations[1]
    let mut conv_attrs1 = AttributeMap::new();
    conv_attrs1.insert("strides".to_string(), AttrValue::IntList(vec![1, 1]));
    conv_attrs1.insert("padding".to_string(), AttrValue::IntList(vec![0, 0, 0, 0]));
    conv_attrs1.insert(
        "dilations".to_string(),
        AttrValue::IntList(vec![1, i64::MAX]),
    );
    let n1 = GraphNode::new(
        "conv_w_dil_of",
        OpCode::Conv2d,
        "conv_op",
        vec!["img".to_string(), "w_conv".to_string()],
        vec!["y".to_string()],
        conv_attrs1,
    )?;
    let g1 = ModelIrGraph::new(
        "g1",
        ModelIrVersion::V1,
        g,
        vec![x_port.clone(), w_port.clone()],
        vec![out_port.clone()],
        vec![n1],
    )?;
    match g1.validate() {
        Err(ModelIrError::ArithmeticOverflow { operation }) => {
            assert_eq!(operation, "effective kernel width calculation");
        }
        other => {
            return Err(format!("expected ArithmeticOverflow for eff_kw, got {other:?}").into());
        }
    }

    // 2. Conv2d padded width overflow: w + pad_left + pad_right
    let mut conv_attrs2 = AttributeMap::new();
    conv_attrs2.insert("strides".to_string(), AttrValue::IntList(vec![1, 1]));
    conv_attrs2.insert(
        "padding".to_string(),
        AttrValue::IntList(vec![0, i64::MAX, 0, i64::MAX]),
    );
    conv_attrs2.insert("dilations".to_string(), AttrValue::IntList(vec![1, 1]));
    let n2 = GraphNode::new(
        "conv_w_pad_of",
        OpCode::Conv2d,
        "conv_op",
        vec!["img".to_string(), "w_conv".to_string()],
        vec!["y".to_string()],
        conv_attrs2,
    )?;
    let g2 = ModelIrGraph::new(
        "g2",
        ModelIrVersion::V1,
        g,
        vec![x_port.clone(), w_port],
        vec![out_port.clone()],
        vec![n2],
    )?;
    match g2.validate() {
        Err(ModelIrError::ArithmeticOverflow { operation }) => {
            assert_eq!(operation, "padded width calculation");
        }
        other => {
            return Err(
                format!("expected ArithmeticOverflow for conv total_w, got {other:?}").into(),
            );
        }
    }

    // 3. MaxPool2d padded width overflow: w + pad_left + pad_right
    let mut pool_attrs = AttributeMap::new();
    pool_attrs.insert("kernel_size".to_string(), AttrValue::IntList(vec![2, 2]));
    pool_attrs.insert("strides".to_string(), AttrValue::IntList(vec![2, 2]));
    pool_attrs.insert(
        "padding".to_string(),
        AttrValue::IntList(vec![0, i64::MAX, 0, i64::MAX]),
    );
    let n3 = GraphNode::new(
        "pool_w_pad_of",
        OpCode::MaxPool2d,
        "pool_op",
        vec!["img".to_string()],
        vec!["y".to_string()],
        pool_attrs,
    )?;
    let g3 = ModelIrGraph::new(
        "g3",
        ModelIrVersion::V1,
        g,
        vec![x_port],
        vec![out_port],
        vec![n3],
    )?;
    match g3.validate() {
        Err(ModelIrError::ArithmeticOverflow { operation }) => {
            assert_eq!(operation, "maxpool padded width calculation");
        }
        other => {
            return Err(
                format!("expected ArithmeticOverflow for maxpool total_w, got {other:?}").into(),
            );
        }
    }
    Ok(())
}

#[test]
fn test_finding_17_encoder_all_attribute_kinds() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![4, 4])?, g)?;
    let out_port = TensorPort::new("y", DType::F32, Shape::new(vec![4, 4])?, g)?;

    // Construct node exercising Bool, String, FloatList, DType, Shape, Int, Float, IntList
    let mut attrs = AttributeMap::new();
    attrs.insert("scale".to_string(), AttrValue::Bool(true));
    attrs.insert("bias".to_string(), AttrValue::Bool(false));
    attrs.insert("elementwise_affine".to_string(), AttrValue::Bool(true));
    attrs.insert("epsilon".to_string(), AttrValue::Float(1e-4));
    attrs.insert(
        "normalized_shape".to_string(),
        AttrValue::Shape(Shape::new(vec![4])?),
    );

    let n = GraphNode::new(
        "norm_all_kinds",
        OpCode::LayerNorm,
        "norm_node",
        vec!["x".to_string()],
        vec!["y".to_string()],
        attrs,
    )?;

    let graph = ModelIrGraph::builder("all_kinds_graph", g)
        .add_input(in_port)
        .add_output(out_port)
        .add_node(n)
        .build_and_validate()?;

    let bytes = fss_model_ir::canonical::encode_canonical_model_ir(&graph);
    assert!(!bytes.is_empty());
    let digest = graph.content_digest()?;
    assert_ne!(digest.to_string(), "");

    // Also test AttrValue serialization directly for String, FloatList, DType, Int, IntList
    let vals = [
        AttrValue::Bool(true),
        AttrValue::Int(42),
        AttrValue::Float(1.25),
        AttrValue::String("hello_ir".to_string()),
        AttrValue::IntList(vec![1, 2, 3]),
        AttrValue::FloatList(vec![1.0, 2.0, 3.0]),
        AttrValue::DType(DType::F32),
        AttrValue::Shape(Shape::new(vec![2, 4, 8])?),
    ];
    assert_eq!(vals.len(), 8);
    Ok(())
}
