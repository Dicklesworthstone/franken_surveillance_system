#![forbid(unsafe_code)]
//! ONNX vector MatMul executes through both production engines and native artifacts.

use super::*;
use fss_model_ir::{AttributeMap, GraphNode, ModelIrVersion, OpCode, TensorPort};
use fss_tensor::DType;

fn product_model(
    a: &[usize],
    b: &[usize],
    output: &[usize],
    attrs: &[u8],
    opset: i64,
) -> Vec<u8> {
    let graph = [
        node("MatMul", &["a", "b"], &["output"], attrs),
        bytes(11, &info("a", a, 1)),
        bytes(11, &info("b", b, 1)),
        bytes(12, &info("output", output, 1)),
    ]
    .concat();
    [
        integer(1, 8),
        bytes(8, &integer(2, opset)),
        bytes(7, &graph),
    ]
    .concat()
}

fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter()
        .zip(b)
        .fold(0.0_f32, |sum, (&left, &right)| sum + left * right)
}

// Direct source-coordinate dots, independent of native shape inference and helpers.
fn vector_products(vector: &[f32], matrices: &[f32], dims: &[usize], left: bool) -> Vec<f32> {
    let rows = dims[dims.len() - 2];
    let columns = dims[dims.len() - 1];
    let mut result = Vec::new();
    for matrix in matrices.chunks_exact(rows * columns) {
        for output in 0..if left { columns } else { rows } {
            let mut sum = 0.0_f32;
            for (k, &value) in vector.iter().enumerate() {
                let product = if left {
                    value * matrix[k * columns + output]
                } else {
                    matrix[output * columns + k] * value
                };
                sum += product;
            }
            result.push(sum);
        }
    }
    result
}

#[test]
fn vector_dot_produces_a_scalar_and_preserves_ordered_f32_arithmetic() -> Test {
    for opset in [13, 17] {
        let source = product_model(&[3], &[3], &[], &[], opset);
        let imported = import(&source)?;
        assert_eq!(imported.graph().node_count(), 4);
        assert_eq!(imported.graph().version(), ModelIrVersion::V1);
        assert!(imported.parameters().is_empty());
        assert!(imported.graph().outputs()[0].shape().dims().is_empty());
        for (a, b) in [
            ([1.0, 2.0, 3.0], [4.0, -5.0, 6.0]),
            ([1.0e20, 1.0, -1.0e20], [1.0, 1.0, 1.0]),
            ([-0.0, 0.0, -0.0], [1.0, -1.0, -1.0]),
            ([f32::from_bits(1), 2.0, -2.0], [1.0, 1.0, 1.0]),
        ] {
            let actual = roundtrip(
                &source,
                &[("a", data(&[3], &a)?), ("b", data(&[3], &b)?)],
            )?;
            assert_eq!(bits(&actual["output"]), bits(&[dot(&a, &b)]));
        }
    }
    Ok(())
}

#[test]
fn vectors_broadcast_over_every_matrix_rank_and_keep_existing_singletons() -> Test {
    let vector = [1.25_f32, -0.5, 2.0];
    for rank in 2..=8 {
        for left in [false, true] {
            let mut dims = vec![1; rank];
            if rank > 2 {
                dims[0] = 2;
            }
            dims[rank - 2] = if left { 3 } else { 2 };
            dims[rank - 1] = if left { 2 } else { 3 };
            let mut output = dims[..rank - 2].to_vec();
            output.push(2);
            let values = (0..dims.iter().product::<usize>())
                .map(|index| (index as f32 - 4.0) * 0.25)
                .collect::<Vec<_>>();
            let (a_dims, b_dims) = if left {
                (vec![3], dims.clone())
            } else {
                (dims.clone(), vec![3])
            };
            let source = product_model(&a_dims, &b_dims, &output, &[], 13);
            let imported = import(&source)?;
            assert_eq!(imported.graph().node_count(), 3);
            assert_eq!(imported.graph().outputs()[0].shape().dims(), output);
            let (a, b) = if left {
                (data(&a_dims, &vector)?, data(&b_dims, &values)?)
            } else {
                (data(&a_dims, &values)?, data(&b_dims, &vector)?)
            };
            let actual = roundtrip(&source, &[("a", a), ("b", b)])?;
            assert_eq!(
                bits(&actual["output"]),
                bits(&vector_products(&vector, &values, &dims, left)),
                "rank={rank} left_vector={left}"
            );
        }
    }
    for left in [false, true] {
        let dims = if left { [1, 3, 1] } else { [1, 1, 3] };
        let (a_dims, b_dims) = if left {
            (vec![3], dims.to_vec())
        } else {
            (dims.to_vec(), vec![3])
        };
        let source = product_model(&a_dims, &b_dims, &[1, 1], &[], 17);
        let a = data(&a_dims, &[1.0, 2.0, 3.0])?;
        let b = data(&b_dims, &[4.0, 5.0, 6.0])?;
        assert_eq!(
            bits(&roundtrip(&source, &[("a", a), ("b", b)])?["output"]),
            bits(&[32.0])
        );
        assert_eq!(import(&source)?.graph().outputs()[0].shape().dims(), &[1, 1]);
    }
    Ok(())
}

#[test]
fn constant_vectors_and_constant_only_dot_keep_exact_parameter_bindings() -> Test {
    for both_constant in [false, true] {
        let mut graph = [
            node("MatMul", &["a", "b"], &["output"], &[]),
            weight("b", &[3], &[1.0, 1.0, 1.0]),
            bytes(12, &info("output", &[], 1)),
        ]
        .concat();
        let a = [1.0e20_f32, 1.0, -1.0e20];
        let input = if both_constant {
            graph.extend(weight("a", &[3], &a));
            Vec::new()
        } else {
            graph.extend(bytes(11, &info("a", &[3], 1)));
            vec![("a", data(&[3], &a)?)]
        };
        let source = model(&graph);
        let imported = import(&source)?;
        assert_eq!(imported.runtime_inputs().len(), usize::from(!both_constant));
        assert_eq!(imported.parameters().len(), 1 + usize::from(both_constant));
        assert_eq!(
            bits(&roundtrip(&source, &input)?["output"]),
            bits(&[0.0])
        );
    }
    Ok(())
}

#[test]
fn existing_matrix_graph_retains_identical_canonical_nodes_and_bytes() -> Test {
    let source = product_model(&[2, 3], &[3, 2], &[2, 2], &[], 13);
    let actual = import(&source)?;
    let port = |name: &str, dims: &[usize]| -> Test<TensorPort> {
        Ok(TensorPort::new(
            name,
            DType::F32,
            Shape::new(dims.to_vec())?,
            GENERATION,
        )?)
    };
    let expected = ModelIrGraph::new_validated(
        "onnx-graph",
        ModelIrVersion::V1,
        GENERATION,
        vec![port("a", &[2, 3])?, port("b", &[3, 2])?],
        vec![port("output", &[2, 2])?],
        vec![GraphNode::new(
            "onnx-node-0000",
            OpCode::MatMul,
            "onnx-node-0000",
            vec!["a".into(), "b".into()],
            vec!["output".into()],
            AttributeMap::new(),
        )?],
    )?;
    assert_eq!(actual.graph(), &expected);
    assert_eq!(
        encode_canonical_model_ir(actual.graph())?,
        encode_canonical_model_ir(&expected)?
    );
    Ok(())
}

#[test]
fn malformed_vector_products_and_missing_helper_like_inputs_refuse() {
    for (a, b, output, attrs, expected) in [
        (vec![2], vec![3], vec![], vec![], OnnxError::Graph),
        (vec![], vec![1], vec![], vec![], OnnxError::Unsupported),
        (vec![3], vec![3], vec![1], vec![], OnnxError::Graph),
        (
            vec![3],
            vec![3],
            vec![],
            int_attr("transpose", 1),
            OnnxError::Unsupported,
        ),
    ] {
        assert_eq!(
            refusal(&product_model(&a, &b, &output, &attrs, 13)),
            Some(expected)
        );
    }
    let source = model(
        &[
            node("MatMul", &["a", "b"], &["dot"], &[]),
            node(
                "Relu",
                &["onnx-node-0000-matmul-4"],
                &["output"],
                &[],
            ),
            bytes(11, &info("a", &[3], 1)),
            bytes(11, &info("b", &[3], 1)),
            bytes(12, &info("output", &[1, 3], 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&source), Some(OnnxError::Graph));
}

#[test]
fn vector_lowering_admits_exact_aggregate_limits_and_cancels_at_every_checkpoint() -> Test {
    let source = product_model(&[3], &[3], &[], &[], 13);
    let imported = import(&source)?;
    let digest = ContentDigest::sha256(&source);
    let exact = OnnxLimits {
        nodes: 4,
        tensors: 6,
        tensor_bytes: 12,
        work_units: imported.work_units(),
        ..OnnxLimits::default()
    };
    import_onnx(&source, digest, GENERATION, exact, &|| false)?;
    for limits in [
        OnnxLimits { nodes: 3, ..exact },
        OnnxLimits { tensors: 5, ..exact },
        OnnxLimits { tensor_bytes: 11, ..exact },
    ] {
        assert_eq!(
            import_onnx(&source, digest, GENERATION, limits, &|| false).err(),
            Some(OnnxError::Limit)
        );
    }
    assert_eq!(
        import_onnx(
            &source,
            digest,
            GENERATION,
            OnnxLimits {
                work_units: exact.work_units - 1,
                ..exact
            },
            &|| false,
        )
        .err(),
        Some(OnnxError::WorkBudget)
    );
    let calls = Cell::new(0);
    import_onnx(&source, digest, GENERATION, exact, &|| {
        calls.set(calls.get() + 1);
        false
    })?;
    for stop in 1..=calls.get() {
        let seen = Cell::new(0);
        let cancelled = || {
            seen.set(seen.get() + 1);
            seen.get() == stop
        };
        assert_eq!(
            import_onnx(&source, digest, GENERATION, exact, &cancelled).err(),
            Some(OnnxError::Cancelled),
            "checkpoint {stop}"
        );
    }
    Ok(())
}
