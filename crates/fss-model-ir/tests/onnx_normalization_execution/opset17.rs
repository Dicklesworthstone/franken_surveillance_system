#![forbid(unsafe_code)]
//! ONNX-17 contracts through the real importer, scalar/optimized execution and
//! native graph/Safetensors reload. No ONNX runtime or duplicated lowerer is used.

use super::*;

fn model_at(graph: &[u8], version: i64) -> Vec<u8> {
    [
        integer(1, 8),
        bytes(8, &integer(2, version)),
        bytes(7, graph),
    ]
    .concat()
}

fn retarget(source: &[u8], version: u8) -> Vec<u8> {
    // All synthetic models in this test host have this exact protobuf prefix.
    assert_eq!(&source[..6], &[8, 8, 66, 2, 16, 13]);
    let mut result = source.to_vec();
    result[5] = version;
    result
}

fn parameter_payload(weights: &[u8]) -> Test<&[u8]> {
    let header = usize::try_from(u64::from_le_bytes(weights[..8].try_into()?))?;
    Ok(weights.get(8 + header..).ok_or("weight payload")?)
}

fn float_attr(name: &str, value: f32) -> Vec<u8> {
    attribute(
        name,
        1,
        &[varint(2 * 8 + 5), value.to_le_bytes().to_vec()].concat(),
    )
}

fn i64_weight(name: &str, values: &[i64]) -> Vec<u8> {
    bytes(
        5,
        &tensor(
            name,
            &[values.len()],
            7,
            &values
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect::<Vec<_>>(),
        ),
    )
}

fn normalization(
    shape: &[usize],
    inputs: &[&str],
    outputs: &[&str],
    attrs: &[u8],
    affine: &[u8],
) -> Vec<u8> {
    model_at(
        &[
            node("LayerNormalization", inputs, outputs, attrs),
            affine.to_vec(),
            bytes(11, &info("input", shape, 1)),
            bytes(12, &info("output", shape, 1)),
        ]
        .concat(),
        17,
    )
}

fn basic(shape: &[usize], attrs: &[u8], bias: bool) -> Vec<u8> {
    let mut affine = weight("scale", &[], &[1.25]);
    if bias {
        affine.extend(weight("bias", &[], &[-0.125]));
    }
    normalization(
        shape,
        if bias {
            &["input", "scale", "bias"]
        } else {
            &["input", "scale"]
        },
        &["output"],
        attrs,
        &affine,
    )
}

// Independent row arithmetic. Each operation has its own F32 result; the
// reciprocal is observable and must not be replaced by centered/stddev.
fn oracle(values: &[f32], width: usize, epsilon: f32, reciprocal: bool) -> Vec<f32> {
    let mut result = Vec::new();
    for row in values.chunks_exact(width) {
        let mut sum = 0.0_f32;
        for &value in row {
            sum += value;
        }
        let mean = sum / width as f32;
        let centered = row.iter().map(|value| value - mean).collect::<Vec<_>>();
        let mut squares = 0.0_f32;
        for &value in &centered {
            let square = value * value;
            squares += square;
        }
        let variance = squares / width as f32;
        let stabilized = variance + epsilon;
        let stddev = stabilized.sqrt();
        let inverse = 1.0_f32 / stddev;
        result.extend(centered.into_iter().map(|value| {
            if reciprocal {
                value * inverse
            } else {
                value / stddev
            }
        }));
    }
    result
}

#[test]
fn layer_normalization_executes_trailing_axes_and_reloads_exact_native_artifacts() -> Test {
    for (shape, axis) in [
        (vec![4], 0),
        (vec![2, 4], 1),
        (vec![2, 3, 4], 1),
        (vec![2, 3, 4], -2),
        (vec![2, 3, 4], -3),
        (vec![1, 1, 1, 1, 1, 2, 3, 4], -3),
    ] {
        let values = (0..shape.iter().product::<usize>())
            .map(|i| ((i * 13 % 37) as f32 - 18.0) * 0.1)
            .collect::<Vec<_>>();
        let normalized_axis = if axis < 0 {
            axis + shape.len() as i64
        } else {
            axis
        } as usize;
        let width = shape[normalized_axis..].iter().product();
        let attrs = [
            int_attr("axis", axis),
            int_attr("stash_type", 1),
            float_attr("epsilon", 1e-5),
        ]
        .concat();
        for bias in [false, true] {
            let source = basic(&shape, &attrs, bias);
            let imported = import(&source)?;
            assert_eq!(imported.graph().version(), ModelIrVersion::V2);
            assert!(
                !imported
                    .graph()
                    .nodes()
                    .iter()
                    .any(|node| node.op() == OpCode::LayerNorm)
            );
            let reductions = imported
                .graph()
                .nodes()
                .iter()
                .filter(|node| node.op() == OpCode::MatMul)
                .collect::<Vec<_>>();
            assert_eq!(reductions.len(), 2);
            assert_eq!(reductions[0].inputs()[1], reductions[1].inputs()[1]);
            assert_eq!(imported.parameters().len(), 5 + usize::from(bias));
            let expected = oracle(&values, width, 1e-5, true)
                .into_iter()
                .map(|value| {
                    let scaled = value * 1.25;
                    if bias { scaled + -0.125 } else { scaled }
                })
                .collect::<Vec<_>>();
            let result = roundtrip(&source, &[("input", data(&shape, &values)?)])?;
            assert_eq!(
                bits(&result["output"]),
                bits(&expected),
                "shape {shape:?}, axis {axis}"
            );
        }
    }
    Ok(())
}

#[test]
fn default_axis_epsilon_and_optional_arguments_have_their_onnx_meanings() -> Test {
    let values = [0.1_f32, 0.2, 0.4, 0.9, 11.0, -9.0, 3.0, 5.0];
    let scale = weight("scale", &[], &[1.0]);
    let expected = oracle(&values, 4, 1e-5_f32, true);
    assert_ne!(
        bits(&expected),
        bits(&oracle(&values, 4, 1e-5_f32, false)),
        "fixture must distinguish reciprocal/multiply from direct division"
    );
    for inputs in [vec!["input", "scale"], vec!["input", "scale", ""]] {
        for outputs in [vec!["output"], vec!["output", ""], vec!["output", "", ""]] {
            let source = normalization(&[2, 4], &inputs, &outputs, &[], &scale);
            let result = roundtrip(&source, &[("input", data(&[2, 4], &values)?)])?;
            assert_eq!(bits(&result["output"]), bits(&expected));
        }
    }
    // A singleton normalized axis uses population variance (zero), with no
    // sample-size subtraction and no special replacement by identity.
    let source = basic(&[2, 1], &[], true);
    assert_eq!(
        roundtrip(&source, &[("input", data(&[2, 1], &[7., -9.])?)])?["output"],
        [-0.125; 2]
    );
    Ok(())
}

#[test]
fn runtime_affine_inputs_broadcast_to_x_without_expanding_its_shape() -> Test {
    let source = model_at(
        &[
            node(
                "LayerNormalization",
                &["input", "scale", "bias"],
                &["output"],
                &[],
            ),
            bytes(11, &info("input", &[2, 3], 1)),
            bytes(11, &info("scale", &[2, 1], 1)),
            bytes(11, &info("bias", &[3], 1)),
            bytes(12, &info("output", &[2, 3], 1)),
        ]
        .concat(),
        17,
    );
    let values = [-3., 2., 8., 1., 9., -5.];
    let scale = [0.5, -2.];
    let bias = [0.1, 0.2, -0.3];
    let result = roundtrip(
        &source,
        &[
            ("input", data(&[2, 3], &values)?),
            ("scale", data(&[2, 1], &scale)?),
            ("bias", data(&[3], &bias)?),
        ],
    )?;
    let expected = oracle(&values, 3, 1e-5, true)
        .into_iter()
        .enumerate()
        .map(|(i, value)| {
            let scaled = value * scale[i / 3];
            scaled + bias[i % 3]
        })
        .collect::<Vec<_>>();
    assert_eq!(bits(&result["output"]), bits(&expected));
    Ok(())
}

#[test]
fn stash_type_one_keeps_f32_cancellation_and_overflow_visible() -> Test {
    let source = normalization(
        &[1, 4],
        &["input", "scale"],
        &["output"],
        &[],
        &weight("scale", &[], &[1.]),
    );
    let values = [16_777_216.0_f32, 1., -16_777_216., 3.];
    let expected = oracle(&values, 4, 1e-5, true);
    let mean = values.iter().map(|&value| f64::from(value)).sum::<f64>() / 4.;
    let variance = values
        .iter()
        .map(|&value| (f64::from(value) - mean).powi(2))
        .sum::<f64>()
        / 4.;
    let denominator = (variance + f64::from(1e-5_f32)).sqrt();
    let widened = values
        .iter()
        .map(|&value| ((f64::from(value) - mean) / denominator) as f32)
        .collect::<Vec<_>>();
    assert_ne!(
        bits(&expected),
        bits(&widened),
        "fixture must expose widened statistics"
    );
    assert_eq!(
        bits(&roundtrip(&source, &[("input", data(&[1, 4], &values)?)])?["output"]),
        bits(&expected)
    );
    let result = roundtrip(&source, &[("input", data(&[1, 4], &[f32::MAX; 4])?)])?;
    assert!(result["output"].iter().all(|value| value.is_nan()));
    Ok(())
}

#[test]
fn layer_normalization_refuses_invalid_axes_precision_affine_and_statistics() {
    for axis in [-3, 2, i64::MIN, i64::MAX] {
        assert_eq!(
            refusal(&basic(&[2, 3], &int_attr("axis", axis), false)),
            Some(OnnxError::Graph)
        );
    }
    for stash in [0, 10, 11, 16, -1] {
        assert_eq!(
            refusal(&basic(&[2, 3], &int_attr("stash_type", stash), false)),
            Some(OnnxError::Unsupported)
        );
    }
    for epsilon in [0.0, -0.0, -1.0] {
        assert_eq!(
            refusal(&basic(&[2, 3], &float_attr("epsilon", epsilon), false)),
            Some(OnnxError::Unsupported)
        );
    }
    for epsilon in [f32::INFINITY, f32::NEG_INFINITY, f32::NAN] {
        assert_eq!(
            refusal(&basic(&[2, 3], &float_attr("epsilon", epsilon), false)),
            Some(OnnxError::NonFinite)
        );
    }
    for attrs in [
        float_attr("axis", 1.),
        float_attr("stash_type", 1.),
        int_attr("epsilon", 1),
    ] {
        assert_eq!(
            refusal(&basic(&[2, 3], &attrs, false)),
            Some(OnnxError::Graph)
        );
    }
    assert_eq!(
        refusal(&basic(&[2, 3], &int_attr("unknown", 0), false)),
        Some(OnnxError::Unsupported)
    );
    for shape in [vec![], vec![2, 0], vec![1; 9]] {
        assert!(refusal(&basic(&shape, &[], false)).is_some());
    }
    for scale_shape in [vec![2], vec![1, 2, 3], vec![2, 2]] {
        let scale = vec![1.; scale_shape.iter().product()];
        let source = normalization(
            &[2, 3],
            &["input", "scale"],
            &["output"],
            &[],
            &weight("scale", &scale_shape, &scale),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Graph));
    }
    for outputs in [
        vec!["output", "mean"],
        vec!["output", "", "inverse"],
        vec!["output", "mean", "inverse"],
    ] {
        let source = normalization(
            &[2, 3],
            &["input", "scale"],
            &outputs,
            &[],
            &weight("scale", &[], &[1.]),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Unsupported));
    }
    for inputs in [
        vec![],
        vec!["input"],
        vec!["", "scale"],
        vec!["input", ""],
        vec!["input", "scale", "", ""],
    ] {
        let source = normalization(
            &[2, 3],
            &inputs,
            &["output"],
            &[],
            &weight("scale", &[], &[1.]),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Graph));
    }
    let integer_scale = normalization(
        &[2, 3],
        &["input", "scale"],
        &["output"],
        &[],
        &i64_weight("scale", &[1]),
    );
    assert_eq!(refusal(&integer_scale), Some(OnnxError::Graph));
    // Other operators retain their historical empty-output refusal in both
    // admitted opsets; optional placeholders apply only to LayerNormalization-17.
    let invalid = [
        node("Identity", &["input"], &[""], &[]),
        bytes(11, &info("input", &[2], 1)),
        bytes(12, &info("output", &[2], 1)),
    ]
    .concat();
    for version in [13, 17] {
        assert_eq!(
            refusal(&model_at(&invalid, version)),
            Some(OnnxError::Limit)
        );
    }
}

#[test]
fn modern_inference_attributes_are_versioned_and_old_native_bytes_stay_identical() -> Test {
    let bn_graph = |attrs: &[u8]| {
        [
            node(
                "BatchNormalization",
                &["input", "scale", "bias", "mean", "variance"],
                &["output"],
                attrs,
            ),
            weight("scale", &[2], &[1.5, 0.5]),
            weight("bias", &[2], &[0.25, -0.75]),
            weight("mean", &[2], &[1., 5.]),
            weight("variance", &[2], &[4., 16.]),
            bytes(11, &info("input", &[2, 2], 1)),
            bytes(12, &info("output", &[2, 2], 1)),
        ]
        .concat()
    };
    let old = model(&bn_graph(&[]));
    let modern = model_at(&bn_graph(&int_attr("training_mode", 0)), 17);
    let old_import = import(&old)?;
    let modern_import = import(&modern)?;
    assert_eq!(
        export(&old_import)?.graph_bytes(),
        export(&modern_import)?.graph_bytes()
    );
    // Safetensors metadata intentionally binds each distinct ONNX source.
    // The native parameter tensor payloads and layouts remain identical.
    assert_eq!(
        parameter_payload(export(&old_import)?.weights_bytes())?,
        parameter_payload(export(&modern_import)?.weights_bytes())?
    );
    let values = [1., 3., -1., 9.];
    let expected = values
        .iter()
        .enumerate()
        .map(|(i, &value)| {
            let channel = i % 2;
            let centered = value - [1., 5.][channel];
            let denominator = ([4.0_f32, 16.][channel] + 1e-5_f32).sqrt();
            let normalized = centered / denominator;
            let scaled = normalized * [1.5, 0.5][channel];
            scaled + [0.25, -0.75][channel]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        bits(&roundtrip(&modern, &[("input", data(&[2, 2], &values)?)])?["output"]),
        bits(&expected)
    );
    assert_eq!(
        refusal(&model(&bn_graph(&int_attr("training_mode", 0)))),
        Some(OnnxError::Unsupported)
    );
    assert_eq!(
        refusal(&model_at(&bn_graph(&int_attr("training_mode", 1)), 17)),
        Some(OnnxError::Unsupported)
    );
    assert_eq!(
        refusal(&model_at(&bn_graph(&float_attr("training_mode", 0.)), 17)),
        Some(OnnxError::Graph)
    );
    // Existing decomposed opset-13 normalization selects exactly the same
    // native graph and weight bytes in the admitted opset-17 profile.
    let decomposed = layer_norm(&[2, 4], 1e-5, &[1.; 4], &[0.; 4]);
    let upgraded = retarget(&decomposed, 17);
    let before = import(&decomposed)?;
    let after = import(&upgraded)?;
    assert_eq!(
        export(&before)?.graph_bytes(),
        export(&after)?.graph_bytes()
    );
    assert_eq!(
        parameter_payload(export(&before)?.weights_bytes())?,
        parameter_payload(export(&after)?.weights_bytes())?
    );
    let mut unavailable = basic(&[2, 3], &[], false);
    unavailable[5] = 13;
    assert_eq!(refusal(&unavailable), Some(OnnxError::Unsupported));
    for version in [12, 14, 15, 16, 18, 20] {
        assert_eq!(
            refusal(&retarget(&decomposed, version)),
            Some(OnnxError::Unsupported)
        );
    }
    Ok(())
}

#[test]
fn reshape_allowzero_is_admitted_only_for_the_matching_inference_schema() -> Test {
    let graph = |attrs: &[u8]| {
        [
            node("Reshape", &["input", "shape"], &["output"], attrs),
            i64_weight("shape", &[0, -1]),
            bytes(11, &info("input", &[2, 3], 1)),
            bytes(12, &info("output", &[2, 3], 1)),
        ]
        .concat()
    };
    let old = model(&graph(&[]));
    let modern = model_at(&graph(&int_attr("allowzero", 0)), 17);
    assert_eq!(
        export(&import(&old)?)?.graph_bytes(),
        export(&import(&modern)?)?.graph_bytes()
    );
    let values = [-0., 1., 2., 3., 4., 5.];
    assert_eq!(
        bits(&roundtrip(&modern, &[("input", data(&[2, 3], &values)?)])?["output"]),
        bits(&values)
    );
    assert_eq!(
        refusal(&model(&graph(&int_attr("allowzero", 0)))),
        Some(OnnxError::Unsupported)
    );
    for value in [1, 2, -1] {
        assert_eq!(
            refusal(&model_at(&graph(&int_attr("allowzero", value)), 17)),
            Some(OnnxError::Unsupported)
        );
    }
    assert_eq!(
        refusal(&model_at(&graph(&float_attr("allowzero", 0.)), 17)),
        Some(OnnxError::Graph)
    );
    Ok(())
}

#[test]
fn shape15_slices_static_metadata_with_negative_clamped_and_empty_bounds() -> Test {
    for (start, end, prefix) in [
        (1, i64::MAX, vec![2]),
        (-2, 3, vec![2]),
        (i64::MIN, i64::MAX, vec![]),
        (4, -4, vec![2, 3, 4]),
        (2, 2, vec![2, 3, 4]),
    ] {
        let graph = [
            node(
                "Shape",
                &["input"],
                &["tail"],
                &[int_attr("start", start), int_attr("end", end)].concat(),
            ),
            node(
                "Concat",
                &["prefix", "tail"],
                &["shape"],
                &int_attr("axis", 0),
            ),
            node("Reshape", &["input", "shape"], &["output"], &[]),
            i64_weight("prefix", &prefix),
            bytes(11, &info("input", &[2, 3, 4], 1)),
            bytes(12, &info("output", &[2, 3, 4], 1)),
        ]
        .concat();
        let values = (0..24).map(|value| value as f32).collect::<Vec<_>>();
        let source = model_at(&graph, 17);
        assert_eq!(
            bits(&roundtrip(&source, &[("input", data(&[2, 3, 4], &values)?)])?["output"]),
            bits(&values)
        );
        assert_eq!(refusal(&model(&graph)), Some(OnnxError::Unsupported));
    }
    Ok(())
}

#[test]
fn complete_expansion_obeys_exact_resource_budgets_and_cancellation() -> Test {
    let source = basic(&[2, 3], &[], true);
    let imported = import(&source)?;
    let exact = OnnxLimits {
        nodes: 12,
        tensors: 19,
        parameter_bytes: 32,
        tensor_bytes: 24,
        work_units: imported.work_units(),
        ..OnnxLimits::default()
    };
    assert_eq!(imported.graph().node_count(), exact.nodes);
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
    for limits in [
        OnnxLimits { nodes: 11, ..exact },
        OnnxLimits {
            tensors: 18,
            ..exact
        },
        OnnxLimits {
            parameter_bytes: 31,
            ..exact
        },
        OnnxLimits {
            tensor_bytes: 23,
            ..exact
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
                work_units: exact.work_units - 1,
                ..exact
            },
            &|| false
        )
        .err(),
        Some(OnnxError::WorkBudget)
    );
    let calls = Cell::new(0);
    import_onnx(
        &source,
        ContentDigest::sha256(&source),
        GENERATION,
        exact,
        &|| {
            calls.set(calls.get() + 1);
            false
        },
    )?;
    for stop in 1..=calls.get() {
        let seen = Cell::new(0);
        assert_eq!(
            import_onnx(
                &source,
                ContentDigest::sha256(&source),
                GENERATION,
                exact,
                &|| {
                    seen.set(seen.get() + 1);
                    seen.get() == stop
                }
            )
            .err(),
            Some(OnnxError::Cancelled)
        );
    }
    Ok(())
}

#[test]
fn generated_normalization_names_cannot_alias_future_source_values() -> Test {
    let source = model_at(
        &[
            node("LayerNormalization", &["input", "scale"], &["output"], &[]),
            node(
                "Identity",
                &["scale"],
                &["onnx-node-0000-layernorm-ones"],
                &[],
            ),
            weight("scale", &[], &[1.]),
            bytes(11, &info("input", &[2, 3], 1)),
            bytes(12, &info("output", &[2, 3], 1)),
            bytes(12, &info("onnx-node-0000-layernorm-ones", &[], 1)),
        ]
        .concat(),
        17,
    );
    let imported = import(&source)?;
    assert!(
        imported
            .parameters()
            .contains_key("onnx-node-0000-layernorm-ones-1")
    );
    let values = [1., 2., 4., -3., 5., 6.];
    let result = roundtrip(&source, &[("input", data(&[2, 3], &values)?)])?;
    assert_eq!(result["onnx-node-0000-layernorm-ones"], [1.]);
    assert_eq!(
        bits(&result["output"]),
        bits(&oracle(&values, 3, 1e-5, true))
    );
    Ok(())
}
