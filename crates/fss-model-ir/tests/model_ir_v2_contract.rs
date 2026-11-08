#![forbid(unsafe_code)]
//! Version-selected operator universes, strict decoding and unchanged v1 custody.

use fss_core::{ContentDigest, Generation};
use fss_model_ir::{
    AttrValue, AttributeMap, GraphNode, MODEL_IR_DIGEST_DOMAIN, MODEL_IR_DIGEST_DOMAIN_V2,
    MemoryPlan, MemoryPlanLimits, ModelIrDecodeError, ModelIrError, ModelIrGraph, ModelIrVersion,
    OPERATOR_SPECS, OPERATOR_SPECS_V2, OPERATOR_TABLE_FREEZE_DIGEST,
    OPERATOR_TABLE_FREEZE_DIGEST_V2, OpCode, TensorPort, compute_model_ir_digest,
    compute_operator_table_digest, compute_operator_table_digest_for_version,
    decode_canonical_model_ir, encode_canonical_model_ir, infer_operator_outputs,
    model_ir_digest_domain, operator_specs_for_version, verify_operator_table_frozen,
    verify_operator_table_frozen_for_version,
};
use fss_tensor::{DType, Shape};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const GENERATION: Generation = Generation(19);

fn port(name: &str, dtype: DType, dims: &[usize]) -> Test<TensorPort> {
    Ok(TensorPort::new(name, dtype, Shape::new(dims)?, GENERATION)?)
}

fn node(op: OpCode, input: &str, output: &str) -> Test<GraphNode> {
    Ok(GraphNode::new(
        output,
        op,
        op.name(),
        vec![input.to_owned()],
        vec![output.to_owned()],
        AttributeMap::new(),
    )?)
}

fn graph(version: ModelIrVersion, op: OpCode) -> Test<ModelIrGraph> {
    Ok(ModelIrGraph::new(
        "graph:version-contract",
        version,
        GENERATION,
        vec![port("input", DType::F32, &[2, 3])?],
        vec![port("output", DType::F32, &[2, 3])?],
        vec![node(op, "input", "output")?],
    )?)
}

#[test]
fn both_operator_tables_are_frozen_and_v1_apis_stay_v1() -> Test {
    assert_eq!(OPERATOR_SPECS.len(), 22);
    assert_eq!(OPERATOR_SPECS_V2.len(), 24);
    assert_eq!(&OPERATOR_SPECS_V2[..22], OPERATOR_SPECS);
    assert_eq!(OpCode::all().len(), 22);
    assert_eq!(OpCode::all_for_version(ModelIrVersion::V1)?, OpCode::all());
    assert_eq!(OpCode::all_for_version(ModelIrVersion::V2)?.len(), 24);
    assert_eq!(
        compute_operator_table_digest()?.to_text(),
        OPERATOR_TABLE_FREEZE_DIGEST
    );
    assert_eq!(
        compute_operator_table_digest_for_version(ModelIrVersion::V2)?.to_text(),
        OPERATOR_TABLE_FREEZE_DIGEST_V2
    );
    assert_ne!(
        OPERATOR_TABLE_FREEZE_DIGEST,
        OPERATOR_TABLE_FREEZE_DIGEST_V2
    );
    verify_operator_table_frozen()?;
    verify_operator_table_frozen_for_version(ModelIrVersion::V2)?;

    for &op in OpCode::all() {
        assert_eq!(op.minimum_ir_version(), ModelIrVersion::V1);
        assert!(op.is_admitted_in(ModelIrVersion::V1));
        assert!(op.is_admitted_in(ModelIrVersion::V2));
    }
    for (op, tag) in [(OpCode::Sqrt, 22), (OpCode::Erf, 23)] {
        assert_eq!(op as usize, tag);
        assert_eq!(op.minimum_ir_version(), ModelIrVersion::V2);
        assert!(!op.is_admitted_in(ModelIrVersion::V1));
        assert!(op.is_admitted_in(ModelIrVersion::V2));
        assert!(OpCode::from_name(op.name()).is_err());
        assert!(OpCode::from_stable_id(op.stable_id()).is_err());
        assert!(!OpCode::is_admitted(op.name()));
        assert_eq!(
            OpCode::from_name_for_version(op.name(), ModelIrVersion::V2)?,
            op
        );
        assert_eq!(
            OpCode::from_stable_id_for_version(op.stable_id(), ModelIrVersion::V2)?,
            op
        );
        assert!(op.allowed_attributes().is_empty());
    }
    Ok(())
}

#[test]
fn historical_v1_graph_fixture_keeps_its_exact_bytes_and_digest() -> Test {
    let hex = include_str!("fixtures/onnx/legacy_add_v1.hex").trim();
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|start| u8::from_str_radix(&hex[start..start + 2], 16))
        .collect::<Result<Vec<_>, _>>()?;
    let expected = ContentDigest::parse(
        "sha256:de1ba6db69e22279ecd4bc351ed26a6ebd3db705d456ac14752d9aceb2c57521",
    )?;
    assert_eq!(ContentDigest::sha256(&bytes), expected);
    let loaded = decode_canonical_model_ir(&bytes, expected)?;
    assert_eq!(loaded.version(), ModelIrVersion::V1);
    assert_eq!(loaded.generation(), Generation(7));
    assert_eq!(encode_canonical_model_ir(&loaded)?, bytes);
    assert_eq!(compute_model_ir_digest(&loaded)?, expected);
    Ok(())
}

#[test]
fn new_operators_require_explicit_v2_and_builder_defaults_remain_v1() -> Test {
    assert_eq!(
        ModelIrGraph::builder("default-version", GENERATION)
            .build()?
            .version(),
        ModelIrVersion::V1
    );
    for op in [OpCode::Sqrt, OpCode::Erf] {
        let old = graph(ModelIrVersion::V1, op)?;
        assert!(matches!(
            old.validate(),
            Err(ModelIrError::UnknownOperator { op_id }) if op_id == op.stable_id()
        ));
        assert!(encode_canonical_model_ir(&old).is_err());
        assert!(MemoryPlan::compile(&old, MemoryPlanLimits::default()).is_err());

        let current = graph(ModelIrVersion::V2, op)?;
        current.validate()?;
        let bytes = encode_canonical_model_ir(&current)?;
        assert!(bytes.starts_with(MODEL_IR_DIGEST_DOMAIN_V2));
        let loaded = decode_canonical_model_ir(&bytes, ContentDigest::sha256(&bytes))?;
        assert_eq!(loaded, current);
        assert_eq!(loaded.version(), ModelIrVersion::V2);
        assert_eq!(loaded.generation(), GENERATION);
    }
    Ok(())
}

#[test]
fn mixed_v2_graph_round_trips_and_liveness_binds_its_generation_and_version() -> Test {
    let current = ModelIrGraph::new_validated(
        "graph:mixed-v2",
        ModelIrVersion::V2,
        GENERATION,
        vec![port("input", DType::F32, &[2, 3])?],
        vec![port("output", DType::F32, &[2, 3])?],
        vec![
            node(OpCode::Relu, "input", "relu")?,
            node(OpCode::Sqrt, "relu", "sqrt")?,
            node(OpCode::Erf, "sqrt", "output")?,
        ],
    )?;
    let bytes = encode_canonical_model_ir(&current)?;
    let loaded = decode_canonical_model_ir(&bytes, ContentDigest::sha256(&bytes))?;
    assert_eq!(current, loaded);
    let plan = MemoryPlan::compile(&loaded, MemoryPlanLimits::default())?;
    assert_eq!(plan.graph_digest(), compute_model_ir_digest(&current)?);
    assert_eq!(plan.input_bytes(), 24);
    assert_eq!(plan.output_bytes(), 24);
    assert_eq!(plan.cumulative_bytes(), 96);
    // Existing liveness keeps the external input resident while consecutive
    // activation input/output payloads overlap: three 24-byte tensors.
    assert_eq!(plan.peak_live_bytes(), 72);
    assert_eq!(plan.values()["input"].release_after(), None);

    let old = graph(ModelIrVersion::V1, OpCode::Relu)?;
    let new = graph(ModelIrVersion::V2, OpCode::Relu)?;
    assert_ne!(
        compute_model_ir_digest(&old)?,
        compute_model_ir_digest(&new)?
    );
    assert_ne!(
        MemoryPlan::compile(&old, MemoryPlanLimits::default())?.digest(),
        MemoryPlan::compile(&new, MemoryPlanLimits::default())?.digest()
    );

    let alien = TensorPort::new("input", DType::F32, Shape::new([2, 3])?, Generation(20))?;
    let invalid = ModelIrGraph::new(
        "mixed-generation",
        ModelIrVersion::V2,
        GENERATION,
        vec![alien],
        vec![port("output", DType::F32, &[2, 3])?],
        vec![node(OpCode::Sqrt, "input", "output")?],
    )?;
    assert!(matches!(
        invalid.validate(),
        Err(ModelIrError::GenerationMismatch { .. })
    ));
    Ok(())
}

#[test]
fn domain_version_and_table_cannot_be_spliced_between_versions() -> Test {
    let old = encode_canonical_model_ir(&graph(ModelIrVersion::V1, OpCode::Relu)?)?;
    let new = encode_canonical_model_ir(&graph(ModelIrVersion::V2, OpCode::Relu)?)?;
    assert_eq!(
        MODEL_IR_DIGEST_DOMAIN.len(),
        MODEL_IR_DIGEST_DOMAIN_V2.len()
    );
    let end_domain = MODEL_IR_DIGEST_DOMAIN.len();
    for (original, other) in [(&old, &new), (&new, &old)] {
        for range in [
            0..end_domain,
            end_domain + 1..end_domain + 5,
            end_domain + 5..end_domain + 37,
        ] {
            let mut changed = original.clone();
            changed[range.clone()].copy_from_slice(&other[range]);
            assert!(matches!(
                decode_canonical_model_ir(&changed, ContentDigest::sha256(&changed)),
                Err(ModelIrDecodeError::Unsupported)
            ));
        }
    }
    // Even rewriting every envelope pin to v1 cannot admit a v2-only operator.
    for op in [OpCode::Sqrt, OpCode::Erf] {
        let mut downgraded = encode_canonical_model_ir(&graph(ModelIrVersion::V2, op)?)?;
        downgraded[..end_domain + 37].copy_from_slice(&old[..end_domain + 37]);
        assert!(matches!(
            decode_canonical_model_ir(&downgraded, ContentDigest::sha256(&downgraded)),
            Err(ModelIrDecodeError::Unsupported)
        ));
    }
    Ok(())
}

#[test]
fn new_operators_refuse_non_f32_inputs_wrong_arity_and_attributes() -> Test {
    for op in [OpCode::Sqrt, OpCode::Erf] {
        for dims in [vec![], vec![0], vec![2, 3], vec![1; 8]] {
            let input = port("input", DType::F32, &dims)?;
            let output = infer_operator_outputs(
                "unary",
                op,
                &[&input],
                &["output".into()],
                &AttributeMap::new(),
                GENERATION,
            )?;
            assert_eq!(output[0].shape(), input.shape());
            assert_eq!(output[0].dtype(), DType::F32);
            assert_eq!(output[0].generation(), GENERATION);
        }
        for dtype in [
            DType::F64,
            DType::F16,
            DType::BF16,
            DType::I8,
            DType::I16,
            DType::I32,
            DType::I64,
            DType::U8,
            DType::U16,
            DType::U32,
            DType::U64,
            DType::Bool,
        ] {
            let input = port("input", dtype, &[2])?;
            assert!(matches!(
                infer_operator_outputs("unary", op, &[&input], &["output".into()], &AttributeMap::new(), GENERATION),
                Err(ModelIrError::DTypeMismatch { expected: DType::F32, actual, .. }) if actual == dtype
            ));
        }
        let input = port("input", DType::F32, &[2])?;
        for inputs in [vec![], vec![&input, &input]] {
            assert!(matches!(
                infer_operator_outputs(
                    "unary",
                    op,
                    &inputs,
                    &["output".into()],
                    &AttributeMap::new(),
                    GENERATION
                ),
                Err(ModelIrError::InvalidPortCount { .. })
            ));
        }
        for outputs in [vec![], vec!["a".into(), "b".into()]] {
            assert!(matches!(
                infer_operator_outputs(
                    "unary",
                    op,
                    &[&input],
                    &outputs,
                    &AttributeMap::new(),
                    GENERATION
                ),
                Err(ModelIrError::InvalidPortCount { .. })
            ));
        }
        let mut attrs = AttributeMap::new();
        attrs.insert("approximate".into(), AttrValue::String("none".into()));
        assert!(matches!(
            infer_operator_outputs(
                "unary",
                op,
                &[&input],
                &["output".into()],
                &attrs,
                GENERATION
            ),
            Err(ModelIrError::InvalidAttribute { .. })
        ));
    }
    Ok(())
}

#[test]
fn v2_loading_requires_exact_digest_complete_bytes_and_canonical_suffix() -> Test {
    let bytes = encode_canonical_model_ir(&graph(ModelIrVersion::V2, OpCode::Erf)?)?;
    assert!(matches!(
        decode_canonical_model_ir(&bytes, ContentDigest::sha256(b"wrong")),
        Err(ModelIrDecodeError::DigestMismatch)
    ));
    for end in 0..bytes.len() {
        let prefix = &bytes[..end];
        assert!(decode_canonical_model_ir(prefix, ContentDigest::sha256(prefix)).is_err());
    }
    let mut extended = bytes;
    extended.push(0);
    assert!(matches!(
        decode_canonical_model_ir(&extended, ContentDigest::sha256(&extended)),
        Err(ModelIrDecodeError::NonCanonical)
    ));
    Ok(())
}

#[test]
fn future_versions_cannot_alias_either_supported_operator_universe() -> Test {
    for version in [ModelIrVersion::V1, ModelIrVersion::V2] {
        assert_eq!(ModelIrVersion::from_u32(version.as_u32())?, version);
        assert!(version.is_supported());
        assert!(ModelIrVersion::unsupported(version.as_u32()).is_err());
    }
    for value in [0, 3, u32::MAX] {
        assert!(matches!(
            ModelIrVersion::from_u32(value),
            Err(ModelIrError::VersionMismatch { .. })
        ));
        let future = ModelIrVersion::unsupported(value)?;
        assert!(!future.is_supported());
        assert!(!OpCode::Sqrt.is_admitted_in(future));
        assert!(operator_specs_for_version(future).is_err());
        assert!(OpCode::all_for_version(future).is_err());
        assert!(OpCode::from_name_for_version("relu", future).is_err());
        assert!(model_ir_digest_domain(future).is_err());
        assert!(compute_operator_table_digest_for_version(future).is_err());
        assert!(verify_operator_table_frozen_for_version(future).is_err());
        assert!(graph(future, OpCode::Relu)?.validate().is_err());
    }
    Ok(())
}
