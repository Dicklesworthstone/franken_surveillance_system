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
        "sha256:fd4d54b93c42de573d38395e6ff9a652809c4c61446e7496e5850c3ff27ed54a"
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
        "sha256:e67f69d0b9a3ed95c1a3038364759fe8eb3378333264725a6f69ff8b07950d39"
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
        "sha256:5c56d2e3623573d35150a942653796de50004d342c9bd1fd66c73e8a6fa107cf"
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
        "sha256:ea7f99246f42dc95e1b9931e3ebe2b0b223e115753fc383cb73aca43aa43e56e"
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
        "sha256:1e671e17d51aa24138463ea5400a3debc5f2273523efb6a377e3dfd79385a170"
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
        domain_count, 47,
        "registries/DIGEST_DOMAINS.md count must remain pinned at 47"
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
    // 72 = 71 + SCHEMA-NEGATIVE-EVIDENCE-REPORT-001 (fss.negative_evidence_report.v1, the
    // `fss negative-evidence --json` report added by fss-x4a.6.12).
    assert_eq!(
        schema_count, 72,
        "registries/SCHEMAS.md count must remain pinned at 72"
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
    assert_eq!(v_unsupported.as_u32(), 1);
    assert_eq!(ModelIrVersion::unsupported(99).as_u32(), 99);
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
            assert_eq!(actual, 1);
        }
        other => return Err(format!("expected VersionMismatch (1 != 1), got {other:?}").into()),
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
    let pos_bytes = fss_model_ir::canonical::encode_canonical_attr_value(&AttrValue::Float(0.0));
    let neg_bytes = fss_model_ir::canonical::encode_canonical_attr_value(&AttrValue::Float(-0.0));
    assert_eq!(
        pos_bytes, neg_bytes,
        "-0.0 and +0.0 float attributes must encode identically"
    );

    let pos_list_bytes =
        fss_model_ir::canonical::encode_canonical_attr_value(&AttrValue::FloatList(vec![0.0]));
    let neg_list_bytes =
        fss_model_ir::canonical::encode_canonical_attr_value(&AttrValue::FloatList(vec![-0.0]));
    assert_eq!(
        pos_list_bytes, neg_list_bytes,
        "-0.0 and +0.0 in float list attributes must encode identically"
    );

    // Pairwise tests killing Mutant M7: implicit vs explicit defaults normalize identically

    // 1. Softmax: no axis vs explicit axis = rank - 1
    let sm_implicit = AttributeMap::new();
    let n_sm_imp = GraphNode::new(
        "sm",
        OpCode::Softmax,
        "sm",
        vec!["x1".to_string()],
        vec!["y1".to_string()],
        sm_implicit,
    )?;
    let mut sm_explicit = AttributeMap::new();
    sm_explicit.insert("axis".to_string(), AttrValue::Int(1));
    let n_sm_exp = GraphNode::new(
        "sm",
        OpCode::Softmax,
        "sm",
        vec!["x1".to_string()],
        vec!["y1".to_string()],
        sm_explicit,
    )?;
    let g_sm_imp = ModelIrGraph::builder("sm_graph", g)
        .add_input(x1.clone())
        .add_output(y1.clone())
        .add_node(n_sm_imp)
        .build_and_validate()?;
    let g_sm_exp = ModelIrGraph::builder("sm_graph", g)
        .add_input(x1.clone())
        .add_output(y1.clone())
        .add_node(n_sm_exp)
        .build_and_validate()?;
    assert_eq!(
        g_sm_imp.content_digest()?,
        g_sm_exp.content_digest()?,
        "Softmax implicit vs explicit axis must match"
    );

    // 2. Transpose: no perm vs explicit permutation = reverse
    let tr_implicit = AttributeMap::new();
    let n_tr_imp = GraphNode::new(
        "tr",
        OpCode::Transpose,
        "tr",
        vec!["x1".to_string()],
        vec!["y1".to_string()],
        tr_implicit,
    )?;
    let mut tr_explicit = AttributeMap::new();
    tr_explicit.insert("permutation".to_string(), AttrValue::IntList(vec![1, 0]));
    let n_tr_exp = GraphNode::new(
        "tr",
        OpCode::Transpose,
        "tr",
        vec!["x1".to_string()],
        vec!["y1".to_string()],
        tr_explicit,
    )?;
    let g_tr_imp = ModelIrGraph::builder("tr_graph", g)
        .add_input(x1.clone())
        .add_output(y1.clone())
        .add_node(n_tr_imp)
        .build_and_validate()?;
    let g_tr_exp = ModelIrGraph::builder("tr_graph", g)
        .add_input(x1.clone())
        .add_output(y1.clone())
        .add_node(n_tr_exp)
        .build_and_validate()?;
    assert_eq!(
        g_tr_imp.content_digest()?,
        g_tr_exp.content_digest()?,
        "Transpose implicit vs explicit perm must match"
    );

    // 3. Slice: no axes/steps vs explicit axes 0..N, steps 1..1
    let mut sl_implicit = AttributeMap::new();
    sl_implicit.insert("starts".to_string(), AttrValue::IntList(vec![0, 0]));
    sl_implicit.insert("ends".to_string(), AttrValue::IntList(vec![2, 2]));
    let n_sl_imp = GraphNode::new(
        "sl",
        OpCode::Slice,
        "sl",
        vec!["x1".to_string()],
        vec!["y1".to_string()],
        sl_implicit,
    )?;
    let mut sl_explicit = AttributeMap::new();
    sl_explicit.insert("starts".to_string(), AttrValue::IntList(vec![0, 0]));
    sl_explicit.insert("ends".to_string(), AttrValue::IntList(vec![2, 2]));
    sl_explicit.insert("axes".to_string(), AttrValue::IntList(vec![0, 1]));
    sl_explicit.insert("steps".to_string(), AttrValue::IntList(vec![1, 1]));
    let n_sl_exp = GraphNode::new(
        "sl",
        OpCode::Slice,
        "sl",
        vec!["x1".to_string()],
        vec!["y1".to_string()],
        sl_explicit,
    )?;
    let g_sl_imp = ModelIrGraph::builder("sl_graph", g)
        .add_input(x1.clone())
        .add_output(y1.clone())
        .add_node(n_sl_imp)
        .build_and_validate()?;
    let g_sl_exp = ModelIrGraph::builder("sl_graph", g)
        .add_input(x1.clone())
        .add_output(y1.clone())
        .add_node(n_sl_exp)
        .build_and_validate()?;
    assert_eq!(
        g_sl_imp.content_digest()?,
        g_sl_exp.content_digest()?,
        "Slice implicit vs explicit axes/steps must match"
    );

    // 4. MaxPool2d: no ceil_mode/padding/strides vs explicit
    let img_port = TensorPort::new("img", DType::F32, Shape::new(vec![1, 1, 4, 4])?, g)?;
    let pool_out = TensorPort::new("p_out", DType::F32, Shape::new(vec![1, 1, 3, 3])?, g)?;
    let mut mp_implicit = AttributeMap::new();
    mp_implicit.insert("kernel_size".to_string(), AttrValue::IntList(vec![2, 2]));
    let n_mp_imp = GraphNode::new(
        "mp",
        OpCode::MaxPool2d,
        "mp",
        vec!["img".to_string()],
        vec!["p_out".to_string()],
        mp_implicit,
    )?;
    let mut mp_explicit = AttributeMap::new();
    mp_explicit.insert("kernel_size".to_string(), AttrValue::IntList(vec![2, 2]));
    mp_explicit.insert("ceil_mode".to_string(), AttrValue::Bool(false));
    mp_explicit.insert("padding".to_string(), AttrValue::IntList(vec![0, 0, 0, 0]));
    mp_explicit.insert("strides".to_string(), AttrValue::IntList(vec![1, 1]));
    let n_mp_exp = GraphNode::new(
        "mp",
        OpCode::MaxPool2d,
        "mp",
        vec!["img".to_string()],
        vec!["p_out".to_string()],
        mp_explicit,
    )?;
    let g_mp_imp = ModelIrGraph::builder("mp_graph", g)
        .add_input(img_port.clone())
        .add_output(pool_out.clone())
        .add_node(n_mp_imp)
        .build_and_validate()?;
    let g_mp_exp = ModelIrGraph::builder("mp_graph", g)
        .add_input(img_port.clone())
        .add_output(pool_out)
        .add_node(n_mp_exp)
        .build_and_validate()?;
    assert_eq!(
        g_mp_imp.content_digest()?,
        g_mp_exp.content_digest()?,
        "MaxPool2d implicit vs explicit defaults must match"
    );

    // 5. Gelu: no approximate vs explicit approximate = "none"
    let gelu_implicit = AttributeMap::new();
    let n_g_imp = GraphNode::new(
        "ge",
        OpCode::Gelu,
        "ge",
        vec!["x1".to_string()],
        vec!["y1".to_string()],
        gelu_implicit,
    )?;
    let mut gelu_explicit = AttributeMap::new();
    gelu_explicit.insert(
        "approximate".to_string(),
        AttrValue::String("none".to_string()),
    );
    let n_g_exp = GraphNode::new(
        "ge",
        OpCode::Gelu,
        "ge",
        vec!["x1".to_string()],
        vec!["y1".to_string()],
        gelu_explicit,
    )?;
    let g_ge_imp = ModelIrGraph::builder("ge_graph", g)
        .add_input(x1.clone())
        .add_output(y1.clone())
        .add_node(n_g_imp)
        .build_and_validate()?;
    let g_ge_exp = ModelIrGraph::builder("ge_graph", g)
        .add_input(x1.clone())
        .add_output(y1.clone())
        .add_node(n_g_exp)
        .build_and_validate()?;
    assert_eq!(
        g_ge_imp.content_digest()?,
        g_ge_exp.content_digest()?,
        "Gelu implicit vs explicit approximate must match"
    );

    // 6. Reshape: Shape(sh) vs IntList and allowzero = false
    let flat_port = TensorPort::new("flat", DType::F32, Shape::new(vec![4])?, g)?;
    let mut res_shape = AttributeMap::new();
    res_shape.insert("shape".to_string(), AttrValue::Shape(Shape::new(vec![4])?));
    let n_res_sh = GraphNode::new(
        "rs",
        OpCode::Reshape,
        "rs",
        vec!["x1".to_string()],
        vec!["flat".to_string()],
        res_shape,
    )?;
    let mut res_intlist = AttributeMap::new();
    res_intlist.insert("shape".to_string(), AttrValue::IntList(vec![4]));
    res_intlist.insert("allowzero".to_string(), AttrValue::Bool(false));
    let n_res_il = GraphNode::new(
        "rs",
        OpCode::Reshape,
        "rs",
        vec!["x1".to_string()],
        vec!["flat".to_string()],
        res_intlist,
    )?;
    let g_res_sh = ModelIrGraph::builder("res_graph", g)
        .add_input(x1.clone())
        .add_output(flat_port.clone())
        .add_node(n_res_sh)
        .build_and_validate()?;
    let g_res_il = ModelIrGraph::builder("res_graph", g)
        .add_input(x1.clone())
        .add_output(flat_port)
        .add_node(n_res_il)
        .build_and_validate()?;
    assert_eq!(
        g_res_sh.content_digest()?,
        g_res_il.content_digest()?,
        "Reshape Shape vs IntList and allowzero must match"
    );

    // 7. LayerNorm: no epsilon/affine/scale/bias vs explicit defaults
    let ln_implicit = AttributeMap::new();
    let n_ln_imp = GraphNode::new(
        "ln",
        OpCode::LayerNorm,
        "ln",
        vec!["x1".to_string()],
        vec!["y1".to_string()],
        ln_implicit,
    )?;
    let mut ln_explicit = AttributeMap::new();
    ln_explicit.insert("epsilon".to_string(), AttrValue::Float(1e-5));
    ln_explicit.insert("elementwise_affine".to_string(), AttrValue::Bool(true));
    ln_explicit.insert("scale".to_string(), AttrValue::Bool(true));
    ln_explicit.insert("bias".to_string(), AttrValue::Bool(true));
    let n_ln_exp = GraphNode::new(
        "ln",
        OpCode::LayerNorm,
        "ln",
        vec!["x1".to_string()],
        vec!["y1".to_string()],
        ln_explicit,
    )?;
    let g_ln_imp = ModelIrGraph::builder("ln_graph", g)
        .add_input(x1.clone())
        .add_output(y1.clone())
        .add_node(n_ln_imp)
        .build_and_validate()?;
    let g_ln_exp = ModelIrGraph::builder("ln_graph", g)
        .add_input(x1.clone())
        .add_output(y1.clone())
        .add_node(n_ln_exp)
        .build_and_validate()?;
    assert_eq!(
        g_ln_imp.content_digest()?,
        g_ln_exp.content_digest()?,
        "LayerNorm implicit vs explicit defaults must match"
    );

    // 8. RMSNorm: no epsilon/affine/scale vs explicit defaults
    let rms_implicit = AttributeMap::new();
    let n_rms_imp = GraphNode::new(
        "rms",
        OpCode::RMSNorm,
        "rms",
        vec!["x1".to_string()],
        vec!["y1".to_string()],
        rms_implicit,
    )?;
    let mut rms_explicit = AttributeMap::new();
    rms_explicit.insert("epsilon".to_string(), AttrValue::Float(1e-5));
    rms_explicit.insert("elementwise_affine".to_string(), AttrValue::Bool(true));
    rms_explicit.insert("scale".to_string(), AttrValue::Bool(true));
    let n_rms_exp = GraphNode::new(
        "rms",
        OpCode::RMSNorm,
        "rms",
        vec!["x1".to_string()],
        vec!["y1".to_string()],
        rms_explicit,
    )?;
    let g_rms_imp = ModelIrGraph::builder("rms_graph", g)
        .add_input(x1.clone())
        .add_output(y1.clone())
        .add_node(n_rms_imp)
        .build_and_validate()?;
    let g_rms_exp = ModelIrGraph::builder("rms_graph", g)
        .add_input(x1.clone())
        .add_output(y1.clone())
        .add_node(n_rms_exp)
        .build_and_validate()?;
    assert_eq!(
        g_rms_imp.content_digest()?,
        g_rms_exp.content_digest()?,
        "RMSNorm implicit vs explicit defaults must match"
    );

    // 9. Conv2d: no padding/strides/dilations/groups vs explicit defaults
    let w_conv = TensorPort::new("w_c", DType::F32, Shape::new(vec![1, 1, 2, 2])?, g)?;
    let conv_out = TensorPort::new("c_out", DType::F32, Shape::new(vec![1, 1, 3, 3])?, g)?;
    let conv_implicit = AttributeMap::new();
    let n_cv_imp = GraphNode::new(
        "cv",
        OpCode::Conv2d,
        "cv",
        vec!["img".to_string(), "w_c".to_string()],
        vec!["c_out".to_string()],
        conv_implicit,
    )?;
    let mut conv_explicit = AttributeMap::new();
    conv_explicit.insert("padding".to_string(), AttrValue::IntList(vec![0, 0, 0, 0]));
    conv_explicit.insert("strides".to_string(), AttrValue::IntList(vec![1, 1]));
    conv_explicit.insert("dilations".to_string(), AttrValue::IntList(vec![1, 1]));
    conv_explicit.insert("groups".to_string(), AttrValue::Int(1));
    let n_cv_exp = GraphNode::new(
        "cv",
        OpCode::Conv2d,
        "cv",
        vec!["img".to_string(), "w_c".to_string()],
        vec!["c_out".to_string()],
        conv_explicit,
    )?;
    let g_cv_imp = ModelIrGraph::builder("cv_graph", g)
        .add_input(img_port.clone())
        .add_input(w_conv.clone())
        .add_output(conv_out.clone())
        .add_node(n_cv_imp)
        .build_and_validate()?;
    let g_cv_exp = ModelIrGraph::builder("cv_graph", g)
        .add_input(img_port)
        .add_input(w_conv)
        .add_output(conv_out)
        .add_node(n_cv_exp)
        .build_and_validate()?;
    assert_eq!(
        g_cv_imp.content_digest()?,
        g_cv_exp.content_digest()?,
        "Conv2d implicit vs explicit defaults must match"
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

    let bytes = fss_model_ir::canonical::encode_canonical_model_ir(&graph)?;
    assert!(!bytes.is_empty());
    let digest = graph.content_digest()?;
    assert_ne!(digest.to_string(), "");

    // Direct canonical encoding tag and byte assertions for all 8 attribute types (kills Mutant M6)
    let b_bytes = fss_model_ir::canonical::encode_canonical_attr_value(&AttrValue::Bool(true));
    assert_eq!(b_bytes[0], 1, "Bool tag must be 1");
    assert_eq!(b_bytes, vec![1, 1]);

    let i_bytes = fss_model_ir::canonical::encode_canonical_attr_value(&AttrValue::Int(42));
    assert_eq!(i_bytes[0], 2, "Int tag must be 2");
    assert_eq!(i_bytes, [vec![2], 42i64.to_be_bytes().to_vec()].concat());

    let f_bytes = fss_model_ir::canonical::encode_canonical_attr_value(&AttrValue::Float(1.25));
    assert_eq!(f_bytes[0], 3, "Float tag must be 3");
    assert_eq!(
        f_bytes,
        [vec![3], 1.25f64.to_bits().to_be_bytes().to_vec()].concat()
    );

    let s_bytes = fss_model_ir::canonical::encode_canonical_attr_value(&AttrValue::String(
        "hello_ir".to_string(),
    ));
    assert_eq!(s_bytes[0], 4, "String tag must be 4");
    assert_eq!(
        s_bytes,
        [vec![4], 8u32.to_be_bytes().to_vec(), b"hello_ir".to_vec()].concat()
    );

    let il_bytes =
        fss_model_ir::canonical::encode_canonical_attr_value(&AttrValue::IntList(vec![1, 2, 3]));
    assert_eq!(il_bytes[0], 5, "IntList tag must be 5");
    assert_eq!(
        il_bytes,
        [
            vec![5],
            3u32.to_be_bytes().to_vec(),
            1i64.to_be_bytes().to_vec(),
            2i64.to_be_bytes().to_vec(),
            3i64.to_be_bytes().to_vec()
        ]
        .concat()
    );

    let fl_bytes =
        fss_model_ir::canonical::encode_canonical_attr_value(&AttrValue::FloatList(vec![
            1.0, 2.0, 3.0,
        ]));
    assert_eq!(fl_bytes[0], 6, "FloatList tag must be 6");
    assert_eq!(
        fl_bytes,
        [
            vec![6],
            3u32.to_be_bytes().to_vec(),
            1.0f64.to_bits().to_be_bytes().to_vec(),
            2.0f64.to_bits().to_be_bytes().to_vec(),
            3.0f64.to_bits().to_be_bytes().to_vec()
        ]
        .concat()
    );

    let dt_bytes =
        fss_model_ir::canonical::encode_canonical_attr_value(&AttrValue::DType(DType::F32));
    assert_eq!(dt_bytes[0], 7, "DType tag must be 7");
    assert_eq!(dt_bytes, vec![7, DType::F32.type_tag()]);

    let sh_bytes =
        fss_model_ir::canonical::encode_canonical_attr_value(&AttrValue::Shape(Shape::new(vec![
            2, 4, 8,
        ])?));
    assert_eq!(sh_bytes[0], 8, "Shape tag must be 8");
    assert_eq!(
        sh_bytes,
        [
            vec![8],
            3u32.to_be_bytes().to_vec(),
            2u64.to_be_bytes().to_vec(),
            4u64.to_be_bytes().to_vec(),
            8u64.to_be_bytes().to_vec()
        ]
        .concat()
    );

    Ok(())
}

#[test]
fn test_slice_steps_contract() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![10])?, g)?;

    // 1. Valid steps: input [10], starts [0], ends [10], steps [2] -> [5]
    let mut attrs = AttributeMap::new();
    attrs.insert("starts".to_string(), AttrValue::IntList(vec![0]));
    attrs.insert("ends".to_string(), AttrValue::IntList(vec![10]));
    attrs.insert("steps".to_string(), AttrValue::IntList(vec![2]));
    let out = fss_model_ir::infer_operator_outputs(
        "slice_node",
        OpCode::Slice,
        &[&in_port],
        &["y".to_string()],
        &attrs,
        g,
    )?;
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].shape().dims(), &[5]);

    // 2. Valid steps with non-even division: input [10], starts [0], ends [10], steps [3] -> [4] (0, 3, 6, 9)
    let mut attrs3 = AttributeMap::new();
    attrs3.insert("starts".to_string(), AttrValue::IntList(vec![0]));
    attrs3.insert("ends".to_string(), AttrValue::IntList(vec![10]));
    attrs3.insert("steps".to_string(), AttrValue::IntList(vec![3]));
    let out3 = fss_model_ir::infer_operator_outputs(
        "slice_node",
        OpCode::Slice,
        &[&in_port],
        &["y".to_string()],
        &attrs3,
        g,
    )?;
    assert_eq!(out3[0].shape().dims(), &[4]);

    // 3. steps = 0 is rejected
    let mut attrs_zero = AttributeMap::new();
    attrs_zero.insert("starts".to_string(), AttrValue::IntList(vec![0]));
    attrs_zero.insert("ends".to_string(), AttrValue::IntList(vec![10]));
    attrs_zero.insert("steps".to_string(), AttrValue::IntList(vec![0]));
    match fss_model_ir::infer_operator_outputs(
        "slice_zero",
        OpCode::Slice,
        &[&in_port],
        &["y".to_string()],
        &attrs_zero,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute {
            attr_name, reason, ..
        }) => {
            assert_eq!(attr_name, "steps");
            assert!(reason.contains("zero"));
        }
        other => {
            return Err(format!("expected InvalidAttribute for zero step, got {other:?}").into());
        }
    }

    // 4. steps of wrong type (e.g. String) is rejected by schema validator
    let mut attrs_str = AttributeMap::new();
    attrs_str.insert("starts".to_string(), AttrValue::IntList(vec![0]));
    attrs_str.insert("ends".to_string(), AttrValue::IntList(vec![10]));
    attrs_str.insert(
        "steps".to_string(),
        AttrValue::String("garbage".to_string()),
    );
    match fss_model_ir::infer_operator_outputs(
        "slice_str",
        OpCode::Slice,
        &[&in_port],
        &["y".to_string()],
        &attrs_str,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute {
            attr_name, reason, ..
        }) => {
            assert_eq!(attr_name, "steps");
            assert!(reason.contains("expected IntList"));
        }
        other => {
            return Err(
                format!("expected InvalidAttribute for String steps, got {other:?}").into(),
            );
        }
    }

    // 5. steps length mismatch is rejected
    let mut attrs_len = AttributeMap::new();
    attrs_len.insert("starts".to_string(), AttrValue::IntList(vec![0]));
    attrs_len.insert("ends".to_string(), AttrValue::IntList(vec![10]));
    attrs_len.insert("steps".to_string(), AttrValue::IntList(vec![1, 2]));
    match fss_model_ir::infer_operator_outputs(
        "slice_len",
        OpCode::Slice,
        &[&in_port],
        &["y".to_string()],
        &attrs_len,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute { reason, .. }) => {
            assert!(reason.contains("identical length"));
        }
        other => {
            return Err(format!(
                "expected InvalidAttribute for steps length mismatch, got {other:?}"
            )
            .into());
        }
    }

    Ok(())
}

#[test]
fn test_maxpool2d_ceil_mode_contract() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![1, 1, 5, 5])?, g)?;

    // 1. ceil_mode = true: [1, 1, 5, 5] k=2, s=2 -> [1, 1, 3, 3]
    let mut attrs_ceil = AttributeMap::new();
    attrs_ceil.insert("kernel_size".to_string(), AttrValue::IntList(vec![2, 2]));
    attrs_ceil.insert("strides".to_string(), AttrValue::IntList(vec![2, 2]));
    attrs_ceil.insert("padding".to_string(), AttrValue::IntList(vec![0, 0, 0, 0]));
    attrs_ceil.insert("ceil_mode".to_string(), AttrValue::Bool(true));
    let out_ceil = fss_model_ir::infer_operator_outputs(
        "pool_ceil",
        OpCode::MaxPool2d,
        &[&in_port],
        &["y".to_string()],
        &attrs_ceil,
        g,
    )?;
    assert_eq!(out_ceil[0].shape().dims(), &[1, 1, 3, 3]);

    // 2. ceil_mode = false: [1, 1, 5, 5] k=2, s=2 -> [1, 1, 2, 2]
    let mut attrs_no_ceil = AttributeMap::new();
    attrs_no_ceil.insert("kernel_size".to_string(), AttrValue::IntList(vec![2, 2]));
    attrs_no_ceil.insert("strides".to_string(), AttrValue::IntList(vec![2, 2]));
    attrs_no_ceil.insert("padding".to_string(), AttrValue::IntList(vec![0, 0, 0, 0]));
    attrs_no_ceil.insert("ceil_mode".to_string(), AttrValue::Bool(false));
    let out_no_ceil = fss_model_ir::infer_operator_outputs(
        "pool_no_ceil",
        OpCode::MaxPool2d,
        &[&in_port],
        &["y".to_string()],
        &attrs_no_ceil,
        g,
    )?;
    assert_eq!(out_no_ceil[0].shape().dims(), &[1, 1, 2, 2]);

    // 3. ceil_mode = String("yes") rejected by schema
    let mut attrs_bad = AttributeMap::new();
    attrs_bad.insert("kernel_size".to_string(), AttrValue::IntList(vec![2, 2]));
    attrs_bad.insert(
        "ceil_mode".to_string(),
        AttrValue::String("yes".to_string()),
    );
    match fss_model_ir::infer_operator_outputs(
        "pool_bad",
        OpCode::MaxPool2d,
        &[&in_port],
        &["y".to_string()],
        &attrs_bad,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute {
            attr_name, reason, ..
        }) => {
            assert_eq!(attr_name, "ceil_mode");
            assert!(reason.contains("expected Bool"));
        }
        other => {
            return Err(format!(
                "expected InvalidAttribute for ceil_mode type mismatch, got {other:?}"
            )
            .into());
        }
    }

    Ok(())
}

#[test]
fn test_gelu_approximate_contract() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![2, 4])?, g)?;

    // 1. approximate = "none" accepted
    let mut attrs1 = AttributeMap::new();
    attrs1.insert(
        "approximate".to_string(),
        AttrValue::String("none".to_string()),
    );
    let out1 = fss_model_ir::infer_operator_outputs(
        "gelu1",
        OpCode::Gelu,
        &[&in_port],
        &["y".to_string()],
        &attrs1,
        g,
    )?;
    assert_eq!(out1[0].shape().dims(), &[2, 4]);

    // 2. approximate = "tanh" accepted
    let mut attrs2 = AttributeMap::new();
    attrs2.insert(
        "approximate".to_string(),
        AttrValue::String("tanh".to_string()),
    );
    let out2 = fss_model_ir::infer_operator_outputs(
        "gelu2",
        OpCode::Gelu,
        &[&in_port],
        &["y".to_string()],
        &attrs2,
        g,
    )?;
    assert_eq!(out2[0].shape().dims(), &[2, 4]);

    // 3. approximate = Int(99) rejected by schema validation
    let mut attrs3 = AttributeMap::new();
    attrs3.insert("approximate".to_string(), AttrValue::Int(99));
    match fss_model_ir::infer_operator_outputs(
        "gelu3",
        OpCode::Gelu,
        &[&in_port],
        &["y".to_string()],
        &attrs3,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute {
            attr_name, reason, ..
        }) => {
            assert_eq!(attr_name, "approximate");
            assert!(reason.contains("expected String"));
        }
        other => {
            return Err(
                format!("expected InvalidAttribute for Int approximate, got {other:?}").into(),
            );
        }
    }

    // 4. approximate = "garbage" rejected
    let mut attrs4 = AttributeMap::new();
    attrs4.insert(
        "approximate".to_string(),
        AttrValue::String("garbage".to_string()),
    );
    match fss_model_ir::infer_operator_outputs(
        "gelu4",
        OpCode::Gelu,
        &[&in_port],
        &["y".to_string()],
        &attrs4,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute {
            attr_name, reason, ..
        }) => {
            assert_eq!(attr_name, "approximate");
            assert!(reason.contains("approximate must be 'none' or 'tanh'"));
        }
        other => {
            return Err(format!(
                "expected InvalidAttribute for garbage approximate, got {other:?}"
            )
            .into());
        }
    }

    Ok(())
}

#[test]
fn test_reshape_allowzero_and_dim_bounds_contract() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let in_port = TensorPort::new("x", DType::F32, Shape::new(vec![2, 4])?, g)?;

    // 1. allowzero = false accepted
    let mut attrs1 = AttributeMap::new();
    attrs1.insert("shape".to_string(), AttrValue::IntList(vec![4, 2]));
    attrs1.insert("allowzero".to_string(), AttrValue::Bool(false));
    let out1 = fss_model_ir::infer_operator_outputs(
        "reshape1",
        OpCode::Reshape,
        &[&in_port],
        &["y".to_string()],
        &attrs1,
        g,
    )?;
    assert_eq!(out1[0].shape().dims(), &[4, 2]);

    // 2. allowzero = String("true") rejected by schema
    let mut attrs2 = AttributeMap::new();
    attrs2.insert("shape".to_string(), AttrValue::IntList(vec![4, 2]));
    attrs2.insert(
        "allowzero".to_string(),
        AttrValue::String("true".to_string()),
    );
    match fss_model_ir::infer_operator_outputs(
        "reshape2",
        OpCode::Reshape,
        &[&in_port],
        &["y".to_string()],
        &attrs2,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute {
            attr_name, reason, ..
        }) => {
            assert_eq!(attr_name, "allowzero");
            assert!(reason.contains("expected Bool"));
        }
        other => {
            return Err(
                format!("expected InvalidAttribute for String allowzero, got {other:?}").into(),
            );
        }
    }

    // 3. Shape attribute with dim > i64::MAX rejected with overflow
    let mut attrs3 = AttributeMap::new();
    attrs3.insert(
        "shape".to_string(),
        AttrValue::Shape(Shape::new(vec![u64::MAX as usize])?),
    );
    match fss_model_ir::infer_operator_outputs(
        "reshape3",
        OpCode::Reshape,
        &[&in_port],
        &["y".to_string()],
        &attrs3,
        g,
    ) {
        Err(ModelIrError::ArithmeticOverflow { operation }) => {
            assert_eq!(operation, "reshape shape dimension exceeds i64::MAX");
        }
        other => {
            return Err(
                format!("expected ArithmeticOverflow for dim > i64::MAX, got {other:?}").into(),
            );
        }
    }

    Ok(())
}

#[test]
fn test_layernorm_and_rmsnorm_extended_contract() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let x_port = TensorPort::new("x", DType::F32, Shape::new(vec![2, 4, 8])?, g)?;
    let wt_port = TensorPort::new("wt", DType::F32, Shape::new(vec![8])?, g)?;
    let bias_port = TensorPort::new("b", DType::F32, Shape::new(vec![8])?, g)?;

    // 1. elementwise_affine = false rejects weight input
    let mut attrs_no_affine = AttributeMap::new();
    attrs_no_affine.insert("elementwise_affine".to_string(), AttrValue::Bool(false));
    match fss_model_ir::infer_operator_outputs(
        "ln_no_aff",
        OpCode::LayerNorm,
        &[&x_port, &wt_port],
        &["y".to_string()],
        &attrs_no_affine,
        g,
    ) {
        Err(ModelIrError::InvalidPortCount {
            actual, expected, ..
        }) => {
            assert_eq!(actual, 2);
            assert!(expected.contains("elementwise_affine/scale is disabled"));
        }
        other => {
            return Err(format!(
                "expected InvalidPortCount for affine=false with weight, got {other:?}"
            )
            .into());
        }
    }

    // 2. bias = false rejects bias input (3 inputs)
    let mut attrs_no_bias = AttributeMap::new();
    attrs_no_bias.insert("bias".to_string(), AttrValue::Bool(false));
    match fss_model_ir::infer_operator_outputs(
        "ln_no_bias",
        OpCode::LayerNorm,
        &[&x_port, &wt_port, &bias_port],
        &["y".to_string()],
        &attrs_no_bias,
        g,
    ) {
        Err(ModelIrError::InvalidPortCount {
            actual, expected, ..
        }) => {
            assert_eq!(actual, 3);
            assert!(expected.contains("elementwise_affine/bias is disabled"));
        }
        other => {
            return Err(format!(
                "expected InvalidPortCount for bias=false with bias input, got {other:?}"
            )
            .into());
        }
    }

    // 3. RMSNorm scale = false rejects weight input
    let mut attrs_rms_no_scale = AttributeMap::new();
    attrs_rms_no_scale.insert("scale".to_string(), AttrValue::Bool(false));
    match fss_model_ir::infer_operator_outputs(
        "rms_no_scale",
        OpCode::RMSNorm,
        &[&x_port, &wt_port],
        &["y".to_string()],
        &attrs_rms_no_scale,
        g,
    ) {
        Err(ModelIrError::InvalidPortCount { actual, .. }) => {
            assert_eq!(actual, 2);
        }
        other => {
            return Err(format!(
                "expected InvalidPortCount for RMSNorm scale=false, got {other:?}"
            )
            .into());
        }
    }

    // 4. epsilon <= 0.0 rejected
    let mut attrs_zero_eps = AttributeMap::new();
    attrs_zero_eps.insert("epsilon".to_string(), AttrValue::Float(0.0));
    match fss_model_ir::infer_operator_outputs(
        "ln_zero_eps",
        OpCode::LayerNorm,
        &[&x_port],
        &["y".to_string()],
        &attrs_zero_eps,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute {
            attr_name, reason, ..
        }) => {
            assert_eq!(attr_name, "epsilon");
            assert!(reason.contains("strictly positive finite float"));
        }
        other => {
            return Err(
                format!("expected InvalidAttribute for zero epsilon, got {other:?}").into(),
            );
        }
    }

    // 5. epsilon = infinity rejected
    let mut attrs_inf_eps = AttributeMap::new();
    attrs_inf_eps.insert("epsilon".to_string(), AttrValue::Float(f64::INFINITY));
    match fss_model_ir::infer_operator_outputs(
        "ln_inf_eps",
        OpCode::LayerNorm,
        &[&x_port],
        &["y".to_string()],
        &attrs_inf_eps,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute {
            attr_name, reason, ..
        }) => {
            assert_eq!(attr_name, "epsilon");
            assert!(reason.contains("strictly positive finite float"));
        }
        other => {
            return Err(format!("expected InvalidAttribute for inf epsilon, got {other:?}").into());
        }
    }

    // 6. empty normalized_shape rejected
    let mut attrs_empty_ns = AttributeMap::new();
    attrs_empty_ns.insert("normalized_shape".to_string(), AttrValue::IntList(vec![]));
    match fss_model_ir::infer_operator_outputs(
        "ln_empty_ns",
        OpCode::LayerNorm,
        &[&x_port],
        &["y".to_string()],
        &attrs_empty_ns,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute {
            attr_name, reason, ..
        }) => {
            assert_eq!(attr_name, "normalized_shape");
            assert!(reason.contains("cannot be empty"));
        }
        other => {
            return Err(format!(
                "expected InvalidAttribute for empty normalized_shape, got {other:?}"
            )
            .into());
        }
    }

    // 7. rank-0 input rejected
    let rank0_port = TensorPort::new("rank0", DType::F32, Shape::scalar(), g)?;
    match fss_model_ir::infer_operator_outputs(
        "ln_rank0",
        OpCode::LayerNorm,
        &[&rank0_port],
        &["y".to_string()],
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
            return Err(
                format!("expected RankMismatch for rank-0 LayerNorm, got {other:?}").into(),
            );
        }
    }

    Ok(())
}

#[test]
fn test_bool_dtype_rejected_in_arithmetic_ops() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let bool_port1 = TensorPort::new("b1", DType::Bool, Shape::new(vec![4, 4])?, g)?;
    let bool_port2 = TensorPort::new("b2", DType::Bool, Shape::new(vec![4, 4])?, g)?;

    // 1. Div with DType::Bool rejected
    match fss_model_ir::infer_operator_outputs(
        "div_bool",
        OpCode::Div,
        &[&bool_port1, &bool_port2],
        &["y".to_string()],
        &AttributeMap::new(),
        g,
    ) {
        Err(ModelIrError::DTypeMismatch { actual, .. }) => {
            assert_eq!(actual, DType::Bool);
        }
        other => {
            return Err(format!("expected DTypeMismatch for Div with Bool, got {other:?}").into());
        }
    }

    // 2. MatMul with DType::Bool rejected
    match fss_model_ir::infer_operator_outputs(
        "matmul_bool",
        OpCode::MatMul,
        &[&bool_port1, &bool_port2],
        &["y".to_string()],
        &AttributeMap::new(),
        g,
    ) {
        Err(ModelIrError::DTypeMismatch { actual, .. }) => {
            assert_eq!(actual, DType::Bool);
        }
        other => {
            return Err(
                format!("expected DTypeMismatch for MatMul with Bool, got {other:?}").into(),
            );
        }
    }

    // 3. MaxPool2d with DType::Bool rejected
    let bool_pool = TensorPort::new("bp", DType::Bool, Shape::new(vec![1, 1, 4, 4])?, g)?;
    let mut pool_attrs = AttributeMap::new();
    pool_attrs.insert("kernel_size".to_string(), AttrValue::IntList(vec![2, 2]));
    match fss_model_ir::infer_operator_outputs(
        "pool_bool",
        OpCode::MaxPool2d,
        &[&bool_pool],
        &["y".to_string()],
        &pool_attrs,
        g,
    ) {
        Err(ModelIrError::DTypeMismatch { actual, .. }) => {
            assert_eq!(actual, DType::Bool);
        }
        other => {
            return Err(
                format!("expected DTypeMismatch for MaxPool2d with Bool, got {other:?}").into(),
            );
        }
    }

    // 4. Embedding with DType::Bool table rejected
    let idx_port = TensorPort::new("idx", DType::I64, Shape::new(vec![2, 3])?, g)?;
    let bool_table = TensorPort::new("tbl_b", DType::Bool, Shape::new(vec![10, 4])?, g)?;
    match fss_model_ir::infer_operator_outputs(
        "emb_bool",
        OpCode::Embedding,
        &[&idx_port, &bool_table],
        &["y".to_string()],
        &AttributeMap::new(),
        g,
    ) {
        Err(ModelIrError::DTypeMismatch { actual, .. }) => {
            assert_eq!(actual, DType::Bool);
        }
        other => {
            return Err(format!(
                "expected DTypeMismatch for Embedding with Bool table, got {other:?}"
            )
            .into());
        }
    }

    Ok(())
}

#[test]
fn test_embedding_invariants_contract() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let idx_port = TensorPort::new("idx", DType::I64, Shape::new(vec![2, 3])?, g)?;
    let table = TensorPort::new("tbl", DType::F32, Shape::new(vec![10, 16])?, g)?;

    // 1. Valid embedding succeeds
    let mut valid_attrs = AttributeMap::new();
    valid_attrs.insert("num_embeddings".to_string(), AttrValue::Int(10));
    valid_attrs.insert("embedding_dim".to_string(), AttrValue::Int(16));
    valid_attrs.insert("padding_idx".to_string(), AttrValue::Int(0));
    valid_attrs.insert("dtype".to_string(), AttrValue::DType(DType::F32));
    let out = fss_model_ir::infer_operator_outputs(
        "emb_ok",
        OpCode::Embedding,
        &[&idx_port, &table],
        &["y".to_string()],
        &valid_attrs,
        g,
    )?;
    assert_eq!(out[0].shape().dims(), &[2, 3, 16]);

    // 2. num_embeddings mismatch rejected
    let mut bad_ne = AttributeMap::new();
    bad_ne.insert("num_embeddings".to_string(), AttrValue::Int(20));
    match fss_model_ir::infer_operator_outputs(
        "emb_bad_ne",
        OpCode::Embedding,
        &[&idx_port, &table],
        &["y".to_string()],
        &bad_ne,
        g,
    ) {
        Err(ModelIrError::ShapeMismatch { reason, .. }) => {
            assert!(reason.contains("num_embeddings attribute 20 does not match"));
        }
        other => {
            return Err(format!(
                "expected ShapeMismatch for num_embeddings mismatch, got {other:?}"
            )
            .into());
        }
    }

    // 3. embedding_dim mismatch rejected
    let mut bad_ed = AttributeMap::new();
    bad_ed.insert("embedding_dim".to_string(), AttrValue::Int(32));
    match fss_model_ir::infer_operator_outputs(
        "emb_bad_ed",
        OpCode::Embedding,
        &[&idx_port, &table],
        &["y".to_string()],
        &bad_ed,
        g,
    ) {
        Err(ModelIrError::ShapeMismatch { reason, .. }) => {
            assert!(reason.contains("embedding_dim attribute 32 does not match"));
        }
        other => {
            return Err(format!(
                "expected ShapeMismatch for embedding_dim mismatch, got {other:?}"
            )
            .into());
        }
    }

    // 4. padding_idx >= num_embeddings rejected
    let mut bad_pi = AttributeMap::new();
    bad_pi.insert("padding_idx".to_string(), AttrValue::Int(10));
    match fss_model_ir::infer_operator_outputs(
        "emb_bad_pi",
        OpCode::Embedding,
        &[&idx_port, &table],
        &["y".to_string()],
        &bad_pi,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute {
            attr_name, reason, ..
        }) => {
            assert_eq!(attr_name, "padding_idx");
            assert!(reason.contains("out of bounds"));
        }
        other => {
            return Err(format!(
                "expected InvalidAttribute for padding_idx out of bounds, got {other:?}"
            )
            .into());
        }
    }

    // 5. padding_idx < 0 rejected
    let mut bad_neg_pi = AttributeMap::new();
    bad_neg_pi.insert("padding_idx".to_string(), AttrValue::Int(-1));
    match fss_model_ir::infer_operator_outputs(
        "emb_neg_pi",
        OpCode::Embedding,
        &[&idx_port, &table],
        &["y".to_string()],
        &bad_neg_pi,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute {
            attr_name, reason, ..
        }) => {
            assert_eq!(attr_name, "padding_idx");
            assert!(reason.contains("out of bounds"));
        }
        other => {
            return Err(format!(
                "expected InvalidAttribute for negative padding_idx, got {other:?}"
            )
            .into());
        }
    }

    // 6. dtype = Bool rejected
    let mut bad_dt = AttributeMap::new();
    bad_dt.insert("dtype".to_string(), AttrValue::DType(DType::Bool));
    match fss_model_ir::infer_operator_outputs(
        "emb_bool_dt",
        OpCode::Embedding,
        &[&idx_port, &table],
        &["y".to_string()],
        &bad_dt,
        g,
    ) {
        Err(ModelIrError::InvalidAttribute {
            attr_name, reason, ..
        }) => {
            assert_eq!(attr_name, "dtype");
            assert!(reason.contains("embedding dtype cannot be Bool"));
        }
        other => {
            return Err(format!("expected InvalidAttribute for Bool dtype, got {other:?}").into());
        }
    }

    Ok(())
}

#[test]
fn test_order_independent_element_count_zero_handling() -> Result<(), Box<dyn Error>> {
    let g = gen1();
    let max_dim = i64::MAX as usize;

    // Both [0, max_dim, max_dim] and [max_dim, max_dim, 0] must succeed without overflow
    let port1 = TensorPort::new("p1", DType::F32, Shape::new(vec![0, max_dim, max_dim])?, g)?;
    assert_eq!(port1.shape().dims(), &[0, max_dim, max_dim]);

    let port2 = TensorPort::new("p2", DType::F32, Shape::new(vec![max_dim, max_dim, 0])?, g)?;
    assert_eq!(port2.shape().dims(), &[max_dim, max_dim, 0]);

    // Dimension > i64::MAX is rejected with ArithmeticOverflow
    let overflow_dim = u64::MAX as usize;
    match TensorPort::new("p_of", DType::F32, Shape::new(vec![overflow_dim])?, g) {
        Err(ModelIrError::ArithmeticOverflow { operation }) => {
            assert_eq!(operation, "tensor dimension exceeds i64::MAX");
        }
        other => {
            return Err(
                format!("expected ArithmeticOverflow for dim > i64::MAX, got {other:?}").into(),
            );
        }
    }

    Ok(())
}
