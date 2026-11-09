#![forbid(unsafe_code)]
//! Detector query broadcasting from static shape calculations, with actual
//! production scalar/optimized execution and real canonical/weight reload.

use super::*;
use fss_model_ir::{ModelIrVersion, OpCode};
use fss_tensor::DType;

fn fill_attr(dimensions: &[usize], values: &[i64]) -> Vec<u8> {
    attribute(
        "value",
        4,
        &bytes(
            5,
            &tensor(
                "",
                dimensions,
                7,
                &values
                    .iter()
                    .flat_map(|v| v.to_le_bytes())
                    .collect::<Vec<_>>(),
            ),
        ),
    )
}

fn attention(condition_dtype: i64) -> Vec<u8> {
    model(
        &[
            node("Shape", &["input"], &["input_shape"], &[]),
            node("Slice", &["input_shape", "start", "end"], &["batch"], &[]),
            node(
                "Concat",
                &["batch", "preserve"],
                &["requested"],
                &int_attr("axis", 0),
            ),
            node("Shape", &["requested"], &["rank"], &[]),
            node(
                "ConstantOfShape",
                &["rank"],
                &["ones"],
                &fill_attr(&[1], &[1]),
            ),
            node("Mul", &["ones", "minus_one"], &["minus_ones"], &[]),
            node("Equal", &["requested", "minus_ones"], &["keep"], &[]),
            node(
                "Where",
                &["keep", "ones", "requested"],
                &["expand_shape"],
                &[],
            ),
            node("Expand", &["queries", "expand_shape"], &["expanded"], &[]),
            node(
                "Transpose",
                &["input"],
                &["keys"],
                &ints_attr("perm", &[0, 2, 1]),
            ),
            node("MatMul", &["expanded", "keys"], &["scores"], &[]),
            node(
                "Softmax",
                &["scores"],
                &["probabilities"],
                &int_attr("axis", -1),
            ),
            node("MatMul", &["probabilities", "input"], &["output"], &[]),
            int_weight("start", &[1], &[0]),
            int_weight("end", &[1], &[1]),
            int_weight("preserve", &[2], &[-1, -1]),
            int_weight("minus_one", &[], &[-1]),
            weight("queries", &[1, 2, 2], &[1.0, 0.0, 0.0, 1.0]),
            bytes(11, &info("input", &[2, 3, 2], 1)),
            bytes(13, &info("keep", &[3], condition_dtype)),
            bytes(12, &info("output", &[2, 2, 2], 1)),
        ]
        .concat(),
    )
}

fn attention_oracle(input: &[f32]) -> Vec<f64> {
    let mut output = Vec::new();
    for batch in input.chunks_exact(6) {
        for query in 0..2 {
            let logits = (0..3)
                .map(|token| f64::from(batch[2 * token + query]))
                .collect::<Vec<_>>();
            let maximum = logits.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            let masses = logits
                .iter()
                .map(|v| (v - maximum).exp())
                .collect::<Vec<_>>();
            let denominator = masses.iter().sum::<f64>();
            for channel in 0..2 {
                output.push(
                    (0..3)
                        .map(|token| {
                            masses[token] / denominator * f64::from(batch[2 * token + channel])
                        })
                        .sum(),
                );
            }
        }
    }
    output
}

#[test]
fn static_query_expansion_executes_input_dependent_attention_before_and_after_reload() -> Test {
    let source = attention(9);
    let imported = import(&source)?;
    assert_eq!(imported.graph().version(), ModelIrVersion::V1);
    assert_eq!(imported.graph().nodes().len(), 5);
    assert_eq!(
        imported
            .parameters()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["queries"]
    );
    assert_eq!(imported.runtime_inputs(), &["input"]);
    assert!(
        imported
            .graph()
            .inputs()
            .iter()
            .all(|p| p.dtype() == DType::F32)
    );
    assert!(imported.graph().nodes().iter().all(|n| matches!(
        n.op(),
        OpCode::Concat | OpCode::Transpose | OpCode::MatMul | OpCode::Softmax
    )));
    let mut previous = None;
    for input in [
        vec![
            1.0, -1.0, 0.5, 2.0, -0.25, 0.0, 3.0, 0.0, 1.0, 2.0, -1.0, -0.5,
        ],
        vec![
            -0.5, 0.25, 1.5, -2.0, 0.0, 0.5, -1.0, 1.0, 2.0, -0.5, 0.5, 0.0,
        ],
    ] {
        let outputs = roundtrip(&source, &[("input", data(&[2, 3, 2], &input)?)])?;
        let actual = &outputs["output"];
        for (actual, expected) in actual.iter().zip(attention_oracle(&input)) {
            assert!((f64::from(*actual) - expected).abs() < 2e-6);
        }
        if let Some(previous) = previous {
            assert_ne!(bits(actual), previous);
        }
        previous = Some(bits(actual));
    }
    Ok(())
}

fn slice_source(
    starts: &[i64],
    ends: &[i64],
    axes: Option<&[i64]>,
    steps: Option<&[i64]>,
    selected: usize,
) -> Vec<u8> {
    let mut inputs = vec!["indices", "starts", "ends"];
    if axes.is_some() || steps.is_some() {
        inputs.push(if axes.is_some() { "axes" } else { "" });
    }
    if steps.is_some() {
        inputs.push("steps");
    }
    let mut graph = vec![
        node("Slice", &inputs, &["sliced"], &[]),
        // The fallback permits exercising an empty control without admitting
        // an empty runtime tensor.
        node(
            "Concat",
            &["sliced", "fallback"],
            &["chosen"],
            &int_attr("axis", 0),
        ),
        node("Gather", &["input", "chosen"], &["output"], &[]),
        int_weight("indices", &[6], &[0, 1, 2, 3, 4, 5]),
        int_weight("starts", &[starts.len()], starts),
        int_weight("ends", &[ends.len()], ends),
        int_weight("fallback", &[1], &[0]),
        bytes(11, &info("input", &[6], 1)),
        bytes(12, &info("output", &[selected + 1], 1)),
    ];
    if let Some(axes) = axes {
        graph.push(int_weight("axes", &[axes.len()], axes));
    }
    if let Some(steps) = steps {
        graph.push(int_weight("steps", &[steps.len()], steps));
    }
    model(&graph.concat())
}

#[test]
fn integer_shape_slices_preserve_order_steps_empty_and_extreme_endpoints() -> Test {
    let input = [-0.0, 1.25, -2.0, 3.5, 4.0, -5.0];
    for (start, end, axis, step, chosen) in [
        (vec![1], vec![4], None, None, vec![1, 2, 3]),
        (
            vec![-4],
            vec![i64::MAX],
            Some(vec![-1]),
            Some(vec![2]),
            vec![2, 4],
        ),
        (
            vec![-1],
            vec![i64::MIN],
            None,
            Some(vec![-1]),
            vec![5, 4, 3, 2, 1, 0],
        ),
        (
            vec![i64::MAX],
            vec![i64::MIN],
            Some(vec![0]),
            Some(vec![i64::MIN]),
            vec![5],
        ),
        (vec![0], vec![i64::MAX], None, Some(vec![i64::MAX]), vec![0]),
        (vec![3], vec![1], None, None, vec![]),
        (
            vec![],
            vec![],
            Some(vec![]),
            Some(vec![]),
            vec![0, 1, 2, 3, 4, 5],
        ),
    ] {
        let source = slice_source(&start, &end, axis.as_deref(), step.as_deref(), chosen.len());
        let output = roundtrip(&source, &[("input", data(&[6], &input)?)])?;
        let mut expected = chosen.into_iter().map(|i| input[i]).collect::<Vec<_>>();
        expected.push(input[0]);
        assert_eq!(bits(&output["output"]), bits(&expected));
    }
    Ok(())
}

#[test]
fn integer_shape_slices_refuse_bad_axes_steps_and_control_lengths() {
    for source in [
        slice_source(&[0], &[3], Some(&[1]), None, 3),
        slice_source(&[0], &[3], Some(&[-2]), None, 3),
        slice_source(&[0], &[3], None, Some(&[0]), 3),
        slice_source(&[0], &[], None, None, 3),
        slice_source(&[0, 0], &[3, 3], Some(&[0, 0]), None, 3),
        slice_source(&[], &[], None, None, 6),
    ] {
        assert_eq!(refusal(&source), Some(OnnxError::Graph));
    }
}

fn selection(
    a_dims: &[usize],
    a: &[i64],
    b_dims: &[usize],
    b: &[i64],
    yes_dims: &[usize],
    yes: &[i64],
    no_dims: &[usize],
    no: &[i64],
    output: &[usize],
) -> Vec<u8> {
    model(
        &[
            node("Equal", &["a", "b"], &["condition"], &[]),
            node("Where", &["condition", "yes", "no"], &["indices"], &[]),
            node("Gather", &["input", "indices"], &["output"], &[]),
            int_weight("a", a_dims, a),
            int_weight("b", b_dims, b),
            int_weight("yes", yes_dims, yes),
            int_weight("no", no_dims, no),
            bytes(11, &info("input", &[3], 1)),
            bytes(12, &info("output", output, 1)),
        ]
        .concat(),
    )
}

#[test]
fn exact_i64_equality_and_three_way_broadcasting_select_scalar_and_vector_controls() -> Test {
    let huge = 9_007_199_254_740_993_i64;
    for (source, expected) in [
        (
            selection(
                &[3],
                &[huge, huge - 1, i64::MIN],
                &[],
                &[huge],
                &[],
                &[2],
                &[3],
                &[0, 1, 0],
                &[3],
            ),
            vec![8.0, 4.0, 2.0],
        ),
        (
            selection(
                &[],
                &[i64::MAX],
                &[],
                &[i64::MAX],
                &[3],
                &[2, 0, 1],
                &[],
                &[1],
                &[3],
            ),
            vec![8.0, 2.0, 4.0],
        ),
        (
            selection(&[], &[1], &[], &[2], &[], &[2], &[], &[1], &[]),
            vec![4.0],
        ),
    ] {
        let output = roundtrip(&source, &[("input", data(&[3], &[2.0, 4.0, 8.0])?)])?;
        assert_eq!(output["output"], expected);
    }
    Ok(())
}

fn fill_source(dimensions: &[i64], attrs: &[u8], output: &[usize]) -> Vec<u8> {
    model(
        &[
            node("ConstantOfShape", &["dimensions"], &["indices"], attrs),
            node("Gather", &["input", "indices"], &["output"], &[]),
            int_weight("dimensions", &[dimensions.len()], dimensions),
            bytes(11, &info("input", &[3], 1)),
            bytes(12, &info("output", output, 1)),
        ]
        .concat(),
    )
}

#[test]
fn integer_constant_of_shape_has_scalar_vector_and_exact_fill_semantics() -> Test {
    for (dimensions, output, count) in [
        (vec![], vec![], 1),
        (vec![1], vec![1], 1),
        (vec![8], vec![8], 8),
    ] {
        let source = fill_source(&dimensions, &fill_attr(&[1], &[-1]), &output);
        let imported = import(&source)?;
        assert!(imported.parameters().is_empty());
        let values = roundtrip(&source, &[("input", data(&[3], &[1.0, -0.0, 3.0])?)])?;
        assert_eq!(values["output"], vec![3.0; count]);
    }
    Ok(())
}

#[test]
fn empty_shape_selections_are_controls_and_embedded_fill_stays_quota_charged() -> Test {
    let source = model(
        &[
            node(
                "ConstantOfShape",
                &["zero_dimension"],
                &["empty"],
                &fill_attr(&[1], &[0]),
            ),
            node("Equal", &["empty", "zero"], &["condition"], &[]),
            node("Where", &["condition", "empty", "zero"], &["selected"], &[]),
            node(
                "Concat",
                &["selected", "target"],
                &["shape"],
                &int_attr("axis", 0),
            ),
            node("Reshape", &["input", "shape"], &["output"], &[]),
            int_weight("zero_dimension", &[1], &[0]),
            int_weight("zero", &[], &[0]),
            int_weight("target", &[1], &[3]),
            bytes(13, &info("condition", &[0], 9)),
            bytes(11, &info("input", &[3], 1)),
            bytes(12, &info("output", &[3], 1)),
        ]
        .concat(),
    );
    let actual = roundtrip(&source, &[("input", data(&[3], &[1.0, -0.0, 3.0])?)])?;
    assert_eq!(bits(&actual["output"]), bits(&[1.0, -0.0, 3.0]));
    let source = fill_source(&[1], &fill_attr(&[1], &[1]), &[1]);
    // Eight bytes each for source dimensions, embedded fill, and evaluated
    // index. No original allocation is refunded after compile-time use.
    for (parameter_bytes, expected) in [(24, None), (23, Some(OnnxError::Limit))] {
        assert_eq!(
            import_onnx(
                &source,
                ContentDigest::sha256(&source),
                GENERATION,
                OnnxLimits {
                    parameter_bytes,
                    ..OnnxLimits::default()
                },
                &|| false
            )
            .err(),
            expected
        );
    }
    Ok(())
}

#[test]
fn constant_of_shape_refuses_coercions_unsupported_rank_and_unbounded_fill() {
    let float_fill = attribute(
        "value",
        4,
        &bytes(5, &tensor("", &[1], 1, &0f32.to_le_bytes())),
    );
    for (source, error) in [
        (fill_source(&[2], &[], &[2]), OnnxError::Unsupported),
        (fill_source(&[2], &float_fill, &[2]), OnnxError::Unsupported),
        (
            fill_source(&[2], &fill_attr(&[2], &[0, 1]), &[2]),
            OnnxError::Limit,
        ),
        (
            fill_source(&[2], &attribute("value_int", 2, &integer(3, 1)), &[2]),
            OnnxError::Unsupported,
        ),
        (
            fill_source(&[1, 2], &fill_attr(&[1], &[1]), &[1, 2]),
            OnnxError::Unsupported,
        ),
        (
            fill_source(&[-1], &fill_attr(&[1], &[1]), &[1]),
            OnnxError::Graph,
        ),
        (
            fill_source(&[9], &fill_attr(&[1], &[1]), &[9]),
            OnnxError::Limit,
        ),
        (
            fill_source(&[i64::MAX], &fill_attr(&[1], &[1]), &[1]),
            OnnxError::Limit,
        ),
        (
            fill_source(
                &[1],
                &[fill_attr(&[1], &[1]), fill_attr(&[1], &[1])].concat(),
                &[1],
            ),
            OnnxError::Malformed,
        ),
    ] {
        assert_eq!(refusal(&source), Some(error));
    }
}

#[test]
fn bool_is_a_compile_time_witness_not_a_runtime_input_output_or_float() {
    assert_eq!(refusal(&attention(7)), Some(OnnxError::Graph));
    for source in [
        model(
            &[
                node("Equal", &["input", "input"], &["condition"], &[]),
                bytes(11, &info("input", &[1], 1)),
                bytes(12, &info("condition", &[1], 9)),
            ]
            .concat(),
        ),
        model(
            &[
                node("Identity", &["condition"], &["output"], &[]),
                bytes(11, &info("condition", &[1], 9)),
                bytes(12, &info("output", &[1], 1)),
            ]
            .concat(),
        ),
        model(
            &[
                node("Equal", &["input", "input"], &["condition"], &[]),
                node("Where", &["condition", "a", "a"], &["shape"], &[]),
                node("Reshape", &["input", "shape"], &["output"], &[]),
                int_weight("a", &[1], &[1]),
                bytes(11, &info("input", &[1], 1)),
                bytes(12, &info("output", &[1], 1)),
            ]
            .concat(),
        ),
    ] {
        assert_eq!(refusal(&source), Some(OnnxError::Unsupported));
    }
    let wrong_condition = model(
        &[
            node("Where", &["a", "a", "a"], &["indices"], &[]),
            node("Gather", &["input", "indices"], &["output"], &[]),
            int_weight("a", &[1], &[0]),
            bytes(11, &info("input", &[1], 1)),
            bytes(12, &info("output", &[1], 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&wrong_condition), Some(OnnxError::Unsupported));
}

#[test]
fn selection_refuses_incompatible_broadcast_and_invalid_unselected_branch() {
    assert_eq!(
        refusal(&selection(
            &[2],
            &[0, 1],
            &[3],
            &[0, 1, 2],
            &[],
            &[0],
            &[],
            &[0],
            &[3]
        )),
        Some(OnnxError::Graph)
    );
    assert_eq!(
        refusal(&selection(
            &[3],
            &[0, 0, 0],
            &[],
            &[0],
            &[2],
            &[0, 1],
            &[],
            &[0],
            &[3]
        )),
        Some(OnnxError::Graph)
    );
    let source = model(
        &[
            node("Equal", &["a", "a"], &["condition"], &[]),
            node("Where", &["condition", "a", "missing"], &["shape"], &[]),
            node("Reshape", &["input", "shape"], &["output"], &[]),
            int_weight("a", &[1], &[1]),
            bytes(11, &info("input", &[1], 1)),
            bytes(12, &info("output", &[1], 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&source), Some(OnnxError::Graph));
}

#[test]
fn selection_preserves_source_identity_and_all_import_limits() -> Test {
    let source = attention(9);
    let imported = import(&source)?;
    assert_eq!(imported.source(), source);
    assert_eq!(imported.source_digest(), ContentDigest::sha256(&source));
    let limits = OnnxLimits::default();
    for limits in [
        OnnxLimits {
            parameter_bytes: 8,
            ..limits
        },
        OnnxLimits {
            nodes: 12,
            ..limits
        },
        OnnxLimits {
            tensors: 9,
            ..limits
        },
        OnnxLimits {
            tensor_bytes: 8,
            ..limits
        },
    ] {
        assert_eq!(
            import_onnx(
                &source,
                ContentDigest::sha256(&source),
                GENERATION,
                limits,
                &|| false
            )
            .err(),
            Some(OnnxError::Limit)
        );
    }
    assert_eq!(
        import_onnx(
            &source,
            ContentDigest::sha256(&source),
            GENERATION,
            OnnxLimits {
                work_units: imported.work_units() - 1,
                ..limits
            },
            &|| false
        )
        .err(),
        Some(OnnxError::WorkBudget)
    );
    assert!(
        import_onnx(
            &source,
            ContentDigest::sha256(&source),
            GENERATION,
            OnnxLimits {
                work_units: imported.work_units(),
                ..limits
            },
            &|| false
        )
        .is_ok()
    );
    assert_eq!(
        import_onnx(
            &source,
            ContentDigest::sha256(b"wrong"),
            GENERATION,
            limits,
            &|| false
        )
        .err(),
        Some(OnnxError::Digest)
    );
    let probes = Cell::new(0);
    let counted = || {
        probes.set(probes.get() + 1);
        false
    };
    import_onnx(
        &source,
        ContentDigest::sha256(&source),
        GENERATION,
        limits,
        &counted,
    )?;
    let maximum = probes.get();
    for stop in [1, maximum / 2, maximum - 1] {
        let seen = Cell::new(0);
        let cancelled = || {
            seen.set(seen.get() + 1);
            seen.get() >= stop
        };
        assert_eq!(
            import_onnx(
                &source,
                ContentDigest::sha256(&source),
                GENERATION,
                limits,
                &cancelled
            )
            .err(),
            Some(OnnxError::Cancelled)
        );
    }
    Ok(())
}
