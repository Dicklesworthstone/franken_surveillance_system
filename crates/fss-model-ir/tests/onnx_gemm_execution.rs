#![forbid(unsafe_code)]
//! Complete ONNX protobuf -> frozen Model IR -> the unmodified production scalar executor.
//! Including the self-contained executor source avoids an unrelated async runtime dependency;
//! this target exercises these native kernels/imports, not the whole reference crate or a model.

use std::cell::Cell;
use std::collections::BTreeSet;

use fss_core::{ContentDigest, Generation};
use fss_model_ir::{
    AttributeMap, GraphNode, ImportedOnnx, ModelIrGraph, ModelIrVersion, OnnxError, OnnxLimits,
    OpCode, TensorPort, encode_canonical_model_ir, import_onnx,
};
use fss_tensor::{DType, Shape, Tensor};

#[path = "../../fss-reference/src/scalar_executor.rs"]
pub mod scalar_executor;
use scalar_executor::{ExecBudget, ExecError, ExecOutcome, ScalarExecCx, ScalarExecutor};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const GENERATION: Generation = Generation(7);

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
    [
        varint(tag * 8 + 2),
        varint(value.len() as u64),
        value.to_vec(),
    ]
    .concat()
}
fn info(name: &str, dimensions: &[u64]) -> Vec<u8> {
    let shape: Vec<_> = dimensions
        .iter()
        .flat_map(|&n| bytes(1, &integer(1, n)))
        .collect();
    let tensor = [integer(1, 1), bytes(2, &shape)].concat();
    [bytes(1, name.as_bytes()), bytes(2, &bytes(1, &tensor))].concat()
}
fn weight(name: &str, dimensions: &[u64], values: &[f32]) -> Vec<u8> {
    let dims: Vec<_> = dimensions.iter().flat_map(|&n| integer(1, n)).collect();
    let data: Vec<_> = values.iter().flat_map(|n| n.to_le_bytes()).collect();
    bytes(
        5,
        &[
            dims,
            integer(2, 1),
            bytes(8, name.as_bytes()),
            bytes(9, &data),
        ]
        .concat(),
    )
}
fn attribute(name: &str, ty: u64, payload: &[u8]) -> Vec<u8> {
    bytes(
        5,
        &[bytes(1, name.as_bytes()), integer(20, ty), payload.to_vec()].concat(),
    )
}
fn float_attribute(name: &str, value: f32) -> Vec<u8> {
    attribute(
        name,
        1,
        &[varint(2 * 8 + 5), value.to_le_bytes().to_vec()].concat(),
    )
}
fn int_attribute(name: &str, value: i64) -> Vec<u8> {
    attribute(name, 2, &integer(3, value as u64))
}
fn node(op: &str, inputs: &[&str], output: &str, attributes: &[u8]) -> Vec<u8> {
    let inputs: Vec<_> = inputs
        .iter()
        .flat_map(|name| bytes(1, name.as_bytes()))
        .collect();
    bytes(
        1,
        &[
            inputs,
            bytes(2, output.as_bytes()),
            bytes(4, op.as_bytes()),
            attributes.to_vec(),
        ]
        .concat(),
    )
}
fn model(graph: &[u8]) -> Vec<u8> {
    [integer(1, 8), bytes(8, &integer(2, 13)), bytes(7, graph)].concat()
}
fn import(source: &[u8]) -> Test<ImportedOnnx<'_>> {
    Ok(import_onnx(
        source,
        ContentDigest::sha256(source),
        GENERATION,
        OnnxLimits::default(),
        &|| false,
    )?)
}
fn tensor(dims: &[usize], values: &[f32]) -> Test<Tensor> {
    Ok(Tensor::from_values(
        Shape::new(dims.to_vec())?,
        values,
        GENERATION,
    )?)
}
fn bindings(imported: &ImportedOnnx<'_>, supplied: &[(&str, Tensor)]) -> Vec<(String, Tensor)> {
    imported
        .parameters()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .chain(supplied.iter().map(|(k, v)| ((*k).to_owned(), v.clone())))
        .collect()
}
fn execute(imported: &ImportedOnnx<'_>, supplied: &[(&str, Tensor)]) -> Test<ExecOutcome> {
    Ok(ScalarExecutor::run(
        imported.graph(),
        &bindings(imported, supplied),
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?)
}
fn output(outcome: &ExecOutcome, name: &str) -> Test<Vec<f32>> {
    Ok(outcome
        .get_output(name)
        .ok_or("missing output")?
        .to_vec::<f32>()?)
}
fn reject(source: &[u8], expected: OnnxError) {
    assert_eq!(
        import_onnx(
            source,
            ContentDigest::sha256(source),
            GENERATION,
            OnnxLimits::default(),
            &|| false
        )
        .err(),
        Some(expected),
    );
}

#[test]
fn dense_head_gemm_relu_executes_and_replays_with_exact_weights() -> Test {
    let source = model(
        &[
            bytes(2, b"gemm-dense-head"),
            node("Gemm", &["image", "weights", "bias"], "scores", &[]),
            node("Relu", &["scores"], "output", &[]),
            weight("weights", &[2, 3], &[1., 2., 3., 4., 5., 6.]),
            weight("bias", &[3], &[-9., -0., 1.]),
            bytes(11, &info("image", &[2, 2])),
            bytes(12, &info("output", &[2, 3])),
            bytes(13, &info("scores", &[2, 3])),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    assert_eq!(imported.source(), source);
    assert_eq!(imported.source_digest(), ContentDigest::sha256(&source));
    assert_eq!(imported.runtime_inputs(), ["image"]);
    assert_eq!(
        imported
            .parameters()
            .get("weights")
            .ok_or("weights missing")?
            .to_vec::<f32>()?,
        [1., 2., 3., 4., 5., 6.]
    );
    assert_eq!(
        imported
            .parameters()
            .get("bias")
            .ok_or("bias missing")?
            .to_vec::<f32>()?[1]
            .to_bits(),
        (-0.0_f32).to_bits()
    );
    let supplied = [("image", tensor(&[2, 2], &[1., 2., 3., 4.])?)];
    let first = execute(&imported, &supplied)?;
    assert_eq!(output(&first, "output")?, [0., 12., 16., 10., 26., 34.]);
    assert_eq!(first.nodes_executed(), 5);
    let reimported = import(&source)?;
    let second = execute(&reimported, &supplied)?;
    assert_eq!(
        encode_canonical_model_ir(imported.graph())?,
        encode_canonical_model_ir(reimported.graph())?
    );
    assert_eq!(first.node_output_digests(), second.node_output_digests());
    Ok(())
}

fn transpose(values: &[f32], rows: usize, columns: usize) -> Vec<f32> {
    (0..columns)
        .flat_map(|column| (0..rows).map(move |row| values[row * columns + column]))
        .collect()
}

#[test]
fn all_nonzero_transpose_flags_and_explicit_multipliers_execute() -> Test {
    for trans_a in [0, 1, -1, 2, i64::MIN] {
        for trans_b in [0, 1, -1, 2, i64::MIN] {
            let a = [1., 2., 3., 4., 5., 6.];
            let b = [7., 8., 9., 10., 11., 12.];
            let (a_dims, a_values) = if trans_a == 0 {
                ([2, 3], a.to_vec())
            } else {
                ([3, 2], transpose(&a, 2, 3))
            };
            let (b_dims, b_values) = if trans_b == 0 {
                ([3, 2], b.to_vec())
            } else {
                ([2, 3], transpose(&b, 3, 2))
            };
            let attrs = [
                float_attribute("alpha", 0.5),
                float_attribute("beta", -2.),
                int_attribute("transA", trans_a),
                int_attribute("transB", trans_b),
            ]
            .concat();
            let source = model(
                &[
                    node("Gemm", &["a", "b", "c"], "y", &attrs),
                    weight("b", &b_dims, &b_values),
                    weight("c", &[2], &[1., -2.]),
                    bytes(11, &info("a", &a_dims)),
                    bytes(12, &info("y", &[2, 2])),
                ]
                .concat(),
            );
            let imported = import(&source)?;
            let a_dims: Vec<_> = a_dims.iter().map(|&d| d as usize).collect();
            let result = execute(&imported, &[("a", tensor(&a_dims, &a_values)?)])?;
            // Independent exact arithmetic: A*B = [[58,64],[139,154]].
            assert_eq!(
                output(&result, "y")?,
                [27., 36., 67.5, 81.],
                "flags {trans_a}/{trans_b}"
            );
            assert_eq!(
                result.nodes_executed(),
                4 + usize::from(trans_a != 0) + usize::from(trans_b != 0)
            );
        }
    }
    Ok(())
}

#[test]
fn optional_bias_forms_and_alpha_evaluation_order_preserve_f32_bits() -> Test {
    let mut canonical = None;
    for inputs in [vec!["a", "b"], vec!["a", "b", ""]] {
        let source = model(
            &[
                node(
                    "Gemm",
                    &inputs,
                    "y",
                    &[float_attribute("alpha", 1.3), float_attribute("beta", -19.)].concat(),
                ),
                weight("b", &[1, 1], &[0.1]),
                bytes(11, &info("a", &[1, 1])),
                bytes(12, &info("y", &[1, 1])),
            ]
            .concat(),
        );
        let imported = import(&source)?;
        let result = execute(&imported, &[("a", tensor(&[1, 1], &[0.1])?)])?;
        // (0.1f32*0.1f32)*1.3f32; folding alpha into B instead yields 0x3c54fdf3.
        assert_eq!(output(&result, "y")?[0].to_bits(), 0x3c54_fdf4);
        assert_eq!(result.nodes_executed(), 2);
        assert_eq!(imported.parameters().len(), 2); // B and alpha, no unused beta.
        let encoded = encode_canonical_model_ir(imported.graph())?;
        if let Some(previous) = &canonical {
            assert_eq!(&encoded, previous);
        }
        canonical = Some(encoded);
    }
    for alpha in [0.0_f32, -0.0] {
        let source = model(
            &[
                node("Gemm", &["a", "b"], "y", &float_attribute("alpha", alpha)),
                weight("b", &[1, 1], &[1.]),
                bytes(11, &info("a", &[1, 1])),
                bytes(12, &info("y", &[1, 1])),
            ]
            .concat(),
        );
        let imported = import(&source)?;
        let result = execute(&imported, &[("a", tensor(&[1, 1], &[1.])?)])?;
        assert_eq!(output(&result, "y")?[0].to_bits(), alpha.to_bits());
        assert_eq!(
            imported
                .parameters()
                .get("onnx-node-0000-gemm-alpha")
                .ok_or("alpha missing")?
                .to_vec::<f32>()?[0]
                .to_bits(),
            alpha.to_bits()
        );
    }
    Ok(())
}

#[test]
fn optional_bias_defaults_match_explicit_defaults() -> Test {
    for inputs in [vec!["a", "b"], vec!["a", "b", ""]] {
        let make = |attrs: &[u8]| {
            model(
                &[
                    node("Gemm", &inputs, "y", attrs),
                    weight("b", &[2, 1], &[3., 4.]),
                    bytes(11, &info("a", &[1, 2])),
                    bytes(12, &info("y", &[1, 1])),
                ]
                .concat(),
            )
        };
        let default_source = make(&[]);
        let explicit_source = make(
            &[
                float_attribute("alpha", 1.),
                float_attribute("beta", 1.),
                int_attribute("transA", 0),
                int_attribute("transB", 0),
            ]
            .concat(),
        );
        let default = import(&default_source)?;
        let explicit = import(&explicit_source)?;
        assert_eq!(
            encode_canonical_model_ir(default.graph())?,
            encode_canonical_model_ir(explicit.graph())?
        );
        assert_eq!(
            output(
                &execute(&default, &[("a", tensor(&[1, 2], &[1., 2.])?)])?,
                "y"
            )?,
            [11.]
        );
    }
    Ok(())
}

#[test]
fn scalar_vector_row_column_and_matrix_bias_broadcasts_execute() -> Test {
    let cases: &[(&[u64], &[f32], &[f32])] = &[
        (&[], &[10.], &[21., 22., 23., 24., 25., 26.]),
        (&[1], &[10.], &[21., 22., 23., 24., 25., 26.]),
        (&[1, 1], &[10.], &[21., 22., 23., 24., 25., 26.]),
        (&[3], &[10., 20., 30.], &[21., 42., 63., 24., 45., 66.]),
        (&[1, 3], &[10., 20., 30.], &[21., 42., 63., 24., 45., 66.]),
        (&[2, 1], &[10., 20.], &[21., 22., 23., 44., 45., 46.]),
        (
            &[2, 3],
            &[10., 20., 30., 40., 50., 60.],
            &[21., 42., 63., 84., 105., 126.],
        ),
    ];
    for &(shape, bias, expected) in cases {
        let source = model(
            &[
                node("Gemm", &["a", "b", "c"], "y", &float_attribute("beta", 2.)),
                weight("b", &[2, 3], &[1., 2., 3., 4., 5., 6.]),
                weight("c", shape, bias),
                bytes(11, &info("a", &[2, 2])),
                bytes(12, &info("y", &[2, 3])),
            ]
            .concat(),
        );
        let imported = import(&source)?;
        let result = execute(&imported, &[("a", tensor(&[2, 2], &[1., 0., 0., 1.])?)])?;
        assert_eq!(output(&result, "y")?, expected, "bias shape {shape:?}");
    }
    Ok(())
}

#[test]
fn helper_names_avoid_source_inputs_parameters_future_outputs_and_annotations() -> Test {
    let a = "onnx-node-0000-gemm-alpha";
    let b = "onnx-node-0000-gemm-product";
    let c = "onnx-node-0000-gemm-beta";
    let product = "onnx-node-0000-gemm-scaled-product";
    let intermediate = "onnx-node-0000-gemm-scaled-bias";
    let final_output = "onnx-node-0000-gemm-alpha-1";
    let source = model(
        &[
            node(
                "Gemm",
                &[a, b, c],
                product,
                &[int_attribute("transA", 1), int_attribute("transB", 1)].concat(),
            ),
            node("Identity", &[product], intermediate, &[]),
            node("Identity", &[intermediate], final_output, &[]),
            weight(b, &[2, 2], &[1., 2., 3., 4.]),
            weight(c, &[2], &[1., 2.]),
            bytes(11, &info(a, &[2, 2])),
            bytes(12, &info(final_output, &[2, 2])),
            bytes(13, &info(intermediate, &[2, 2])),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    assert!(
        imported
            .parameters()
            .contains_key("onnx-node-0000-gemm-alpha-2")
    );
    assert!(
        imported
            .parameters()
            .contains_key("onnx-node-0000-gemm-beta-1")
    );
    assert_eq!(imported.runtime_inputs(), [a]);
    let ids: BTreeSet<_> = imported.graph().nodes().iter().map(GraphNode::id).collect();
    assert_eq!(ids.len(), imported.graph().nodes().len());
    let result = execute(&imported, &[(a, tensor(&[2, 2], &[1., 0., 0., 1.])?)])?;
    assert_eq!(output(&result, final_output)?, [2., 5., 3., 6.]);
    Ok(())
}

#[test]
fn generated_helpers_cannot_satisfy_missing_source_values_or_type_witnesses() {
    let base = [
        node("Gemm", &["a", "b"], "y", &[]),
        weight("b", &[1, 1], &[1.]),
        bytes(11, &info("a", &[1, 1])),
    ]
    .concat();
    let helper = "onnx-node-0000-gemm-alpha";
    for extra in [
        [
            node("Add", &["y", helper], "z", &[]),
            bytes(12, &info("z", &[1, 1])),
        ]
        .concat(),
        [
            bytes(12, &info("y", &[1, 1])),
            bytes(13, &info(helper, &[])),
        ]
        .concat(),
        bytes(12, &info(helper, &[])),
    ] {
        reject(&model(&[base.clone(), extra].concat()), OnnxError::Graph);
    }
}

fn shape_model(a: &[u64], b: &[u64], c: Option<&[u64]>, y: &[u64], attrs: &[u8]) -> Vec<u8> {
    let mut graph = [
        node(
            "Gemm",
            if c.is_some() {
                &["a", "b", "c"]
            } else {
                &["a", "b"]
            },
            "y",
            attrs,
        ),
        bytes(11, &info("a", a)),
        bytes(11, &info("b", b)),
        bytes(12, &info("y", y)),
    ]
    .concat();
    if let Some(c) = c {
        graph.extend(bytes(11, &info("c", c)));
    }
    model(&graph)
}

#[test]
fn invalid_matrix_shapes_and_multidirectional_bias_expansion_refuse() {
    for (a, b) in [
        (&[2][..], &[2, 3][..]),
        (&[1, 2][..], &[2][..]),
        (&[1, 1, 2][..], &[2, 3][..]),
        (&[1, 2][..], &[1, 2, 3][..]),
    ] {
        reject(
            &shape_model(a, b, None, &[1, 3], &[]),
            OnnxError::Unsupported,
        );
    }
    reject(
        &shape_model(&[2, 3], &[2, 3], None, &[2, 3], &[]),
        OnnxError::Graph,
    );
    reject(
        &shape_model(&[2, 3], &[3, 2], None, &[2, 2], &int_attribute("transA", 1)),
        OnnxError::Graph,
    );
    for c in [&[2, 3][..], &[1, 1, 3][..], &[4][..], &[3, 1][..]] {
        // Product is [1,3]. Add alone would incorrectly admit [2,3]/[3,1] by expanding it.
        reject(
            &shape_model(&[1, 2], &[2, 3], Some(c), &[1, 3], &[]),
            OnnxError::Graph,
        );
    }
    reject(
        &shape_model(&[1, 2], &[2, 3], None, &[3, 1], &[]),
        OnnxError::Graph,
    );
    reject(
        &shape_model(&[0, 2], &[2, 3], None, &[0, 3], &[]),
        OnnxError::Unsupported,
    );
}

#[test]
fn invalid_optional_input_positions_counts_and_forward_references_refuse() {
    for inputs in [
        vec!["a"],
        vec!["", "b"],
        vec!["a", ""],
        vec!["a", "b", "c", ""],
        vec!["a", "missing"],
    ] {
        let source = model(
            &[
                node("Gemm", &inputs, "y", &[]),
                bytes(11, &info("a", &[1, 1])),
                bytes(11, &info("b", &[1, 1])),
                bytes(12, &info("y", &[1, 1])),
            ]
            .concat(),
        );
        reject(&source, OnnxError::Graph);
    }
}

#[test]
fn nonfinite_malformed_mistyped_duplicate_and_unknown_attributes_refuse() {
    for key in ["alpha", "beta"] {
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            reject(
                &shape_model(
                    &[1, 1],
                    &[1, 1],
                    None,
                    &[1, 1],
                    &float_attribute(key, value),
                ),
                OnnxError::NonFinite,
            );
        }
    }
    let malformed = [
        attribute("alpha", 1, &integer(2, 1)),
        attribute("alpha", 1, &integer(3, 1)),
        attribute("alpha", 1, &[]),
        attribute(
            "alpha",
            1,
            &[varint(21), 1.0_f32.to_le_bytes().to_vec(), integer(3, 1)].concat(),
        ),
        attribute(
            "alpha",
            1,
            &[
                varint(21),
                1.0_f32.to_le_bytes().to_vec(),
                varint(21),
                1.0_f32.to_le_bytes().to_vec(),
            ]
            .concat(),
        ),
        [float_attribute("alpha", 1.), float_attribute("alpha", 2.)].concat(),
    ];
    for attrs in malformed {
        reject(
            &shape_model(&[1, 1], &[1, 1], None, &[1, 1], &attrs),
            OnnxError::Malformed,
        );
    }
    for attrs in [
        int_attribute("alpha", 1),
        int_attribute("beta", 1),
        float_attribute("transA", 1.),
        float_attribute("transB", 1.),
    ] {
        reject(
            &shape_model(&[1, 1], &[1, 1], None, &[1, 1], &attrs),
            OnnxError::Graph,
        );
    }
    reject(
        &shape_model(
            &[1, 1],
            &[1, 1],
            None,
            &[1, 1],
            &float_attribute("unknown", 1.),
        ),
        OnnxError::Unsupported,
    );
}

fn full_expansion_source() -> Vec<u8> {
    model(
        &[
            node(
                "Gemm",
                &["a", "b", "c"],
                "y",
                &[
                    int_attribute("transA", 1),
                    int_attribute("transB", 1),
                    float_attribute("alpha", 0.5),
                    float_attribute("beta", -2.),
                ]
                .concat(),
            ),
            weight("b", &[2, 3], &[7., 9., 11., 8., 10., 12.]),
            weight("c", &[2], &[1., -2.]),
            bytes(11, &info("a", &[3, 2])),
            bytes(12, &info("y", &[2, 2])),
        ]
        .concat(),
    )
}

#[test]
fn lowered_nodes_tensor_names_parameters_and_work_are_bounded_at_exact_limits() -> Test {
    let source = full_expansion_source();
    let limits = OnnxLimits {
        source_bytes: source.len(),
        nodes: 6,
        tensors: 11,
        parameter_bytes: 40,
        tensor_bytes: 24,
        ..OnnxLimits::default()
    };
    let admitted = import_onnx(
        &source,
        ContentDigest::sha256(&source),
        GENERATION,
        limits,
        &|| false,
    )?;
    assert_eq!(admitted.graph().nodes().len(), 6);
    assert_eq!(admitted.graph().inputs().len(), 5);
    assert_eq!(
        admitted
            .parameters()
            .values()
            .map(|t| t.shape().num_elements().map(|n| n * 4))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .sum::<usize>(),
        40
    );
    for denied in [
        OnnxLimits {
            source_bytes: source.len() - 1,
            ..limits
        },
        OnnxLimits { nodes: 5, ..limits },
        OnnxLimits {
            tensors: 10,
            ..limits
        },
        OnnxLimits {
            parameter_bytes: 39,
            ..limits
        },
        OnnxLimits {
            tensor_bytes: 23,
            ..limits
        },
    ] {
        assert_eq!(
            import_onnx(
                &source,
                ContentDigest::sha256(&source),
                GENERATION,
                denied,
                &|| false
            )
            .err(),
            Some(OnnxError::Limit)
        );
    }
    let exact = OnnxLimits {
        work_units: admitted.work_units(),
        ..limits
    };
    assert!(
        import_onnx(
            &source,
            ContentDigest::sha256(&source),
            GENERATION,
            exact,
            &|| false
        )
        .is_ok()
    );
    let denied = OnnxLimits {
        work_units: exact.work_units - 1,
        ..exact
    };
    assert_eq!(
        import_onnx(
            &source,
            ContentDigest::sha256(&source),
            GENERATION,
            denied,
            &|| false
        )
        .err(),
        Some(OnnxError::WorkBudget)
    );
    Ok(())
}

#[test]
fn expansion_cancellation_and_truncated_sources_never_return_partial_imports() -> Test {
    let source = full_expansion_source();
    let probes = Cell::new(0);
    import_onnx(
        &source,
        ContentDigest::sha256(&source),
        GENERATION,
        OnnxLimits::default(),
        &|| {
            probes.set(probes.get() + 1);
            false
        },
    )?;
    for stop_at in 1..=probes.get() {
        let seen = Cell::new(0);
        let result = import_onnx(
            &source,
            ContentDigest::sha256(&source),
            GENERATION,
            OnnxLimits::default(),
            &|| {
                seen.set(seen.get() + 1);
                seen.get() >= stop_at
            },
        );
        assert_eq!(result.err(), Some(OnnxError::Cancelled), "probe {stop_at}");
    }
    for end in 0..source.len() {
        let truncated = &source[..end];
        assert!(
            import_onnx(
                truncated,
                ContentDigest::sha256(truncated),
                GENERATION,
                OnnxLimits::default(),
                &|| false
            )
            .is_err(),
            "prefix {end}"
        );
    }
    Ok(())
}

#[test]
fn native_execution_counts_helpers_and_preserves_budget_and_cancellation_failures() -> Test {
    let source = full_expansion_source();
    let imported = import(&source)?;
    let input = [("a", tensor(&[3, 2], &[1., 4., 2., 5., 3., 6.])?)];
    let supplied = bindings(&imported, &input);
    let result = execute(&imported, &input)?;
    assert_eq!(output(&result, "y")?, [27., 36., 67.5, 81.]);
    assert_eq!(result.node_output_digests().len(), 6);
    let exact = ExecBudget::new(result.executed_macs(), result.allocated_bytes());
    assert!(ScalarExecutor::run(imported.graph(), &supplied, exact, &ScalarExecCx::new()).is_ok());
    for budget in [
        ExecBudget::new(exact.max_macs - 1, exact.max_bytes),
        ExecBudget::new(exact.max_macs, exact.max_bytes - 1),
    ] {
        assert!(matches!(
            ScalarExecutor::run(imported.graph(), &supplied, budget, &ScalarExecCx::new()),
            Err(ExecError::BudgetExceeded { .. })
        ));
    }
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    assert!(matches!(
        ScalarExecutor::run(imported.graph(), &supplied, exact, &cx),
        Err(ExecError::CancellationRequested { .. })
    ));
    assert!(cx.is_drain_completed());
    Ok(())
}

#[test]
fn existing_add_import_keeps_its_original_frozen_graph_bytes() -> Test {
    let source = model(
        &[
            bytes(2, b"legacy-add"),
            node("Add", &["x", "bias"], "y", &[]),
            weight("bias", &[2], &[-0., 2.]),
            bytes(11, &info("x", &[1, 2])),
            bytes(12, &info("y", &[1, 2])),
        ]
        .concat(),
    );
    let port = |name: &str, dims: &[usize]| -> Test<TensorPort> {
        Ok(TensorPort::new(
            name,
            DType::F32,
            Shape::new(dims.to_vec())?,
            GENERATION,
        )?)
    };
    // The pre-Gemm importer emitted this exact graph, with these stable source-node IDs.
    let expected = ModelIrGraph::new_validated(
        "legacy-add",
        ModelIrVersion::V1,
        GENERATION,
        vec![port("x", &[1, 2])?, port("bias", &[2])?],
        vec![port("y", &[1, 2])?],
        vec![GraphNode::new(
            "onnx-node-0000",
            OpCode::Add,
            "onnx-node-0000",
            vec!["x".into(), "bias".into()],
            vec!["y".into()],
            AttributeMap::new(),
        )?],
    )?;
    let imported = import(&source)?;
    assert_eq!(
        encode_canonical_model_ir(imported.graph())?,
        encode_canonical_model_ir(&expected)?
    );
    let frozen: String = encode_canonical_model_ir(imported.graph())?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        frozen,
        include_str!("fixtures/onnx/legacy_add_v1.hex").trim()
    );
    assert_eq!(imported.parameters().len(), 1);
    assert_eq!(imported.runtime_inputs(), ["x"]);
    Ok(())
}
