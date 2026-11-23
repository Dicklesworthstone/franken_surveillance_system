#![forbid(unsafe_code)]
//! Static masks select live features through both production executors and
//! canonical graph/Safetensors reload. The coordinate oracle is independent.

use super::*;
use fss_model_ir::{AttrValue, AttributeMap, GraphNode, ModelIrVersion, OpCode, TensorPort};
use fss_tensor::DType;

fn bool_tensor(dims: &[usize], values: &[u8], encoding: usize) -> Vec<u8> {
    let payload = match encoding {
        0 => bytes(9, values),
        1 => values
            .iter()
            .flat_map(|&value| integer(5, i64::from(value)))
            .collect(),
        _ => bytes(
            5,
            &values
                .iter()
                .flat_map(|&value| varint(u64::from(value)))
                .collect::<Vec<_>>(),
        ),
    };
    [
        dims.iter()
            .flat_map(|&dim| integer(1, dim as i64))
            .collect(),
        integer(2, 9),
        bytes(8, b"condition"),
        payload,
    ]
    .concat()
}

fn source(
    mask: &[u8],
    mask_dims: &[usize],
    x_dims: &[usize],
    y_dims: &[usize],
    output: &[usize],
) -> Vec<u8> {
    model(
        &[
            bytes(5, &bool_tensor(mask_dims, mask, 0)),
            node("Where", &["condition", "x", "y"], &["output"], &[]),
            bytes(11, &info("x", x_dims, 1)),
            bytes(11, &info("y", y_dims, 1)),
            bytes(12, &info("output", output, 1)),
        ]
        .concat(),
    )
}

fn coordinates(dims: &[usize]) -> Vec<Vec<usize>> {
    dims.iter().fold(vec![Vec::new()], |prefixes, &dim| {
        prefixes
            .into_iter()
            .flat_map(|prefix| {
                (0..dim).map(move |value| {
                    let mut coordinate = prefix.clone();
                    coordinate.push(value);
                    coordinate
                })
            })
            .collect()
    })
}

fn at<T: Copy>(values: &[T], dims: &[usize], coordinate: &[usize]) -> T {
    let offset = dims
        .iter()
        .zip(&coordinate[coordinate.len() - dims.len()..])
        .fold(0, |offset, (&dim, &index)| {
            offset * dim + if dim == 1 { 0 } else { index }
        });
    values[offset]
}

#[test]
fn all_three_inputs_broadcast_across_scalar_through_rank_eight_outputs() -> Test {
    let mut cases = vec![
        (vec![2, 1], vec![1, 3], vec![], vec![2, 3]),
        (vec![1, 3], vec![2, 1], vec![3], vec![2, 3]),
        (vec![2, 1, 4], vec![3, 1], vec![1, 3, 4], vec![2, 3, 4]),
        (vec![], vec![], vec![], vec![]),
    ];
    for rank in 1..=8 {
        let mut output = vec![1; rank];
        output[rank - 1] = 3;
        cases.push((vec![3], vec![], output.clone(), output));
    }
    for (mask_dims, x_dims, y_dims, output) in cases {
        let mask = (0..mask_dims.iter().product())
            .map(|i: usize| u8::from(i % 3 != 1))
            .collect::<Vec<_>>();
        let x = (0..x_dims.iter().product())
            .map(|i| i as f32 + 0.25)
            .collect::<Vec<_>>();
        let y = (0..y_dims.iter().product())
            .map(|i| -10.0 - i as f32)
            .collect::<Vec<_>>();
        let expected = coordinates(&output)
            .iter()
            .map(|coordinate| {
                if at(&mask, &mask_dims, coordinate) == 1 {
                    at(&x, &x_dims, coordinate)
                } else {
                    at(&y, &y_dims, coordinate)
                }
            })
            .collect::<Vec<_>>();
        let source = source(&mask, &mask_dims, &x_dims, &y_dims, &output);
        let imported = import(&source)?;
        assert_eq!(imported.graph().outputs()[0].shape().dims(), output);
        assert_eq!(imported.graph().version(), ModelIrVersion::V1);
        assert!(imported.parameters().is_empty());
        assert_eq!(imported.runtime_inputs(), &["x", "y"]);
        assert_eq!(
            bits(
                &roundtrip(
                    &source,
                    &[("x", data(&x_dims, &x)?), ("y", data(&y_dims, &y)?)]
                )?["output"]
            ),
            bits(&expected),
            "mask={mask_dims:?}, x={x_dims:?}, y={y_dims:?}"
        );
    }
    Ok(())
}

#[test]
fn bool_initializers_and_constants_accept_raw_packed_and_unpacked_storage() -> Test {
    let mask = [1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1];
    for opset in [13, 17] {
        for dims in [vec![12], vec![3, 4]] {
            for encoding in 0..3 {
                for constant_node in [false, true] {
                    let embedded = bool_tensor(&dims, &mask, encoding);
                    let stored = if constant_node {
                        node(
                            "Constant",
                            &[],
                            &["condition"],
                            &attribute("value", 4, &bytes(5, &embedded)),
                        )
                    } else {
                        bytes(5, &embedded)
                    };
                    let graph = [
                        stored,
                        node("Where", &["condition", "x", "y"], &["output"], &[]),
                        weight("y", &[], &[-0.0]),
                        bytes(11, &info("x", &dims, 1)),
                        bytes(13, &info("condition", &dims, 9)),
                        bytes(12, &info("output", &dims, 1)),
                    ]
                    .concat();
                    let source = [
                        integer(1, 8),
                        bytes(8, &integer(2, opset)),
                        bytes(7, &graph),
                    ]
                    .concat();
                    let input = (0..12).map(|i| i as f32 + 1.0).collect::<Vec<_>>();
                    let expected = input
                        .iter()
                        .zip(mask)
                        .map(|(&x, mask)| if mask == 1 { x } else { -0.0 })
                        .collect::<Vec<_>>();
                    let imported = import(&source)?;
                    assert_eq!(imported.runtime_inputs(), &["x"]);
                    assert_eq!(
                        imported
                            .parameters()
                            .keys()
                            .map(String::as_str)
                            .collect::<Vec<_>>(),
                        ["y"]
                    );
                    assert!(
                        imported
                            .graph()
                            .inputs()
                            .iter()
                            .all(|port| port.dtype() == DType::F32)
                    );
                    assert_eq!(
                        bits(&roundtrip(&source, &[("x", data(&dims, &input)?)])?["output"]),
                        bits(&expected)
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn scalar_and_uniform_masks_retain_both_branch_bindings_and_signed_bits() -> Test {
    for mask in [0, 1] {
        for dims in [vec![], vec![1], vec![2, 3]] {
            let count = dims.iter().product();
            let x = vec![-0.0; count];
            let y = vec![f32::from_bits(1); count];
            let source = source(&[mask], &[], &dims, &dims, &dims);
            let imported = import(&source)?;
            assert_eq!(imported.runtime_inputs(), &["x", "y"]);
            assert_eq!(
                bits(
                    &roundtrip(&source, &[("x", data(&dims, &x)?), ("y", data(&dims, &y)?)])?["output"]
                ),
                bits(if mask == 1 { &x } else { &y })
            );
            assert!(
                ScalarExecutor::run(
                    imported.graph(),
                    &[("x", data(&dims, &x)?)],
                    ExecBudget::unlimited(),
                    &ScalarExecCx::new()
                )
                .is_err()
            );
        }
    }
    let source = source(&[1; 128], &[128], &[128], &[128], &[128]);
    assert_eq!(import(&source)?.graph().node_count(), 6);
    Ok(())
}

#[test]
fn selection_copies_selected_bits_without_nan_or_infinity_contamination() -> Test {
    // Graph executors preserve runtime F32 bits; model initializers and the
    // RGB inference boundary retain their existing finite-value contracts.
    let chosen = [
        -0.0,
        0.0,
        f32::from_bits(1),
        -f32::from_bits(1),
        f32::MIN,
        f32::MAX,
        f32::MIN_POSITIVE,
        f32::from_bits(0x7fc0_1234),
        f32::NEG_INFINITY,
    ];
    let mask = (0..chosen.len())
        .map(|i| u8::from(i % 2 == 0))
        .collect::<Vec<_>>();
    let x = chosen
        .iter()
        .zip(&mask)
        .map(|(&value, &mask)| if mask == 1 { value } else { f32::INFINITY })
        .collect::<Vec<_>>();
    let y = chosen
        .iter()
        .zip(&mask)
        .map(|(&value, &mask)| {
            if mask == 0 {
                value
            } else {
                f32::from_bits(0xffc0_4321)
            }
        })
        .collect::<Vec<_>>();
    let dims = [chosen.len()];
    let source = source(&mask, &dims, &dims, &dims, &dims);
    assert_eq!(
        bits(&roundtrip(&source, &[("x", data(&dims, &x)?), ("y", data(&dims, &y)?)])?["output"]),
        bits(&chosen)
    );
    for nonfinite in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        let source = model(
            &[
                bytes(5, &bool_tensor(&[], &[1], 0)),
                node("Where", &["condition", "x", "y"], &["output"], &[]),
                weight("y", &[], &[nonfinite]),
                bytes(11, &info("x", &[], 1)),
                bytes(12, &info("output", &[], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::NonFinite));
    }
    Ok(())
}

#[test]
fn static_equal_results_can_select_live_feature_columns() -> Test {
    let source = model(
        &[
            node("Shape", &["x"], &["dimensions"], &[]),
            node("Equal", &["dimensions", "two"], &["condition"], &[]),
            node("Where", &["condition", "x", "y"], &["output"], &[]),
            int_weight("two", &[], &[2]),
            bytes(11, &info("x", &[3, 2], 1)),
            bytes(11, &info("y", &[], 1)),
            bytes(13, &info("condition", &[2], 9)),
            bytes(12, &info("output", &[3, 2], 1)),
        ]
        .concat(),
    );
    let actual = roundtrip(
        &source,
        &[
            ("x", data(&[3, 2], &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0])?),
            ("y", data(&[], &[-0.0])?),
        ],
    )?;
    assert_eq!(
        bits(&actual["output"]),
        bits(&[-0.0, 2.0, -0.0, 4.0, -0.0, 6.0])
    );
    assert!(import(&source)?.parameters().is_empty());
    Ok(())
}

#[test]
fn causal_attention_mask_executes_softmax_and_value_projection_after_reload() -> Test {
    let source = model(
        &[
            bytes(5, &bool_tensor(&[3, 3], &[1, 0, 0, 1, 1, 0, 1, 1, 1], 0)),
            node(
                "Where",
                &["condition", "scores", "blocked"],
                &["masked"],
                &[],
            ),
            node(
                "Softmax",
                &["masked"],
                &["probabilities"],
                &int_attr("axis", -1),
            ),
            node("MatMul", &["probabilities", "values"], &["output"], &[]),
            weight("blocked", &[], &[-10_000.0]),
            bytes(11, &info("scores", &[2, 3, 3], 1)),
            bytes(11, &info("values", &[2, 3, 2], 1)),
            bytes(12, &info("output", &[2, 3, 2], 1)),
        ]
        .concat(),
    );
    for shift in [0.0, 0.75] {
        let scores = (0..18)
            .map(|i| (i as f32 * 0.5 + shift).sin())
            .collect::<Vec<_>>();
        let values = (0..12).map(|i| i as f32 / 4.0 - 1.5).collect::<Vec<_>>();
        let actual = roundtrip(
            &source,
            &[
                ("scores", data(&[2, 3, 3], &scores)?),
                ("values", data(&[2, 3, 2], &values)?),
            ],
        )?;
        let mut expected = Vec::new();
        for batch in 0..2 {
            for query in 0..3 {
                let masses = (0..=query)
                    .map(|key| f64::from(scores[batch * 9 + query * 3 + key]).exp())
                    .collect::<Vec<_>>();
                let denominator = masses.iter().sum::<f64>();
                for channel in 0..2 {
                    expected.push(
                        masses
                            .iter()
                            .enumerate()
                            .map(|(key, &mass)| {
                                mass / denominator
                                    * f64::from(values[batch * 6 + key * 2 + channel])
                            })
                            .sum::<f64>(),
                    );
                }
            }
        }
        for (&observed, expected) in actual["output"].iter().zip(expected) {
            assert!(
                (f64::from(observed) - expected).abs() <= 2e-6,
                "{observed} vs {expected}"
            );
        }
    }
    Ok(())
}

#[test]
fn malformed_or_ambiguous_bool_payloads_refuse() {
    let header = [integer(1, 2), integer(2, 9), bytes(8, b"condition")].concat();
    for payload in [
        bytes(9, &[0, 2]),
        bytes(9, &[1]),
        bytes(9, &[1, 0, 1]),
        [integer(5, 0), integer(5, 2)].concat(),
        [integer(5, -1), integer(5, 0)].concat(),
        bytes(5, &[0x80]),
        [bytes(9, &[1, 0]), integer(5, 0)].concat(),
        [bytes(9, &[1, 0]), integer(7, 0)].concat(),
        [bytes(9, &[1, 0]), bytes(4, &0.0_f32.to_le_bytes())].concat(),
        [bytes(9, &[1, 0]), bytes(9, &[1, 0])].concat(),
    ] {
        let source = model(
            &[
                bytes(5, &[header.clone(), payload].concat()),
                node("Where", &["condition", "x", "y"], &["output"], &[]),
                bytes(11, &info("x", &[2], 1)),
                bytes(11, &info("y", &[2], 1)),
                bytes(12, &info("output", &[2], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Malformed));
    }
}

#[test]
fn data_dependent_conditions_empty_tensors_and_invalid_broadcasts_remain_outside_profile() {
    for dtype in [1, 9] {
        let source = model(
            &[
                node("Where", &["condition", "x", "y"], &["output"], &[]),
                bytes(11, &info("condition", &[2], dtype)),
                bytes(11, &info("x", &[2], 1)),
                bytes(11, &info("y", &[2], 1)),
                bytes(12, &info("output", &[2], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Unsupported));
    }
    assert_eq!(
        refusal(&source(&[1, 0], &[2], &[3], &[1], &[3])),
        Some(OnnxError::Graph)
    );
    assert_eq!(
        refusal(&source(&[1], &[], &[2], &[3], &[3])),
        Some(OnnxError::Graph)
    );
    assert_eq!(
        refusal(&source(&[], &[0], &[1], &[1], &[1])),
        Some(OnnxError::Unsupported)
    );
    assert_eq!(
        refusal(&source(&[1], &[], &[1], &[1], &[2])),
        Some(OnnxError::Graph)
    );
    assert_eq!(
        refusal(&source(&[1], &[1; 9], &[1], &[1], &[1])),
        Some(OnnxError::Limit)
    );
    let declarations = [
        bytes(5, &bool_tensor(&[2], &[1, 0], 0)),
        bytes(11, &info("x", &[2], 1)),
        bytes(11, &info("y", &[2], 1)),
        bytes(12, &info("output", &[2], 1)),
    ]
    .concat();
    for (inputs, attrs, error) in [
        (vec!["condition", "x"], vec![], OnnxError::Graph),
        (vec!["condition", "x", "missing"], vec![], OnnxError::Graph),
        (
            vec!["condition", "x", "y"],
            int_attr("axis", 0),
            OnnxError::Unsupported,
        ),
    ] {
        assert_eq!(
            refusal(&model(
                &[
                    node("Where", &inputs, &["output"], &attrs),
                    declarations.clone()
                ]
                .concat()
            )),
            Some(error)
        );
    }
}

#[test]
fn helper_expansion_obeys_exact_original_resource_and_work_limits() -> Test {
    let source = source(&[1, 0, 1, 0], &[4], &[4], &[4], &[4]);
    let imported = import(&source)?;
    assert_eq!(imported.graph().node_count(), 10);
    let digest = ContentDigest::sha256(&source);
    let exact = OnnxLimits {
        source_bytes: source.len(),
        nodes: 10,
        tensors: 13,
        parameter_bytes: 4,
        tensor_bytes: 16,
        work_units: imported.work_units(),
    };
    import_onnx(&source, digest, GENERATION, exact, &|| false)?;
    for limits in [
        OnnxLimits {
            source_bytes: source.len() - 1,
            ..exact
        },
        OnnxLimits { nodes: 9, ..exact },
        OnnxLimits {
            tensors: 12,
            ..exact
        },
        OnnxLimits {
            parameter_bytes: 3,
            ..exact
        },
        OnnxLimits {
            tensor_bytes: 15,
            ..exact
        },
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
            &|| false
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
        assert_eq!(
            import_onnx(&source, digest, GENERATION, exact, &|| {
                seen.set(seen.get() + 1);
                seen.get() == stop
            })
            .err(),
            Some(OnnxError::Cancelled),
            "checkpoint {stop}"
        );
    }
    Ok(())
}

#[test]
fn aggregate_prefix_and_constant_storage_are_charged_before_expansion() -> Test {
    let source = model(
        &[
            node("Identity", &["x"], &["features"], &[]),
            node("Where", &["condition", "features", "y"], &["output"], &[]),
            bytes(5, &bool_tensor(&[4], &[1, 0, 1, 0], 0)),
            weight("y", &[4], &[9.0; 4]),
            bytes(11, &info("x", &[4], 1)),
            bytes(12, &info("output", &[4], 1)),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    assert_eq!(imported.graph().node_count(), 11);
    let exact = OnnxLimits {
        nodes: 11,
        tensors: 14,
        parameter_bytes: 20,
        tensor_bytes: 16,
        ..OnnxLimits::default()
    };
    let digest = ContentDigest::sha256(&source);
    import_onnx(&source, digest, GENERATION, exact, &|| false)?;
    for limits in [
        OnnxLimits { nodes: 10, ..exact },
        OnnxLimits {
            tensors: 13,
            ..exact
        },
        OnnxLimits {
            parameter_bytes: 19,
            ..exact
        },
    ] {
        assert_eq!(
            import_onnx(&source, digest, GENERATION, limits, &|| false).err(),
            Some(OnnxError::Limit)
        );
    }
    assert_eq!(
        roundtrip(&source, &[("x", data(&[4], &[1.0, 2.0, 3.0, 4.0])?)])?["output"],
        [1.0, 9.0, 3.0, 9.0]
    );
    Ok(())
}

#[test]
fn alternating_masks_reach_the_native_ceiling_and_refuse_before_full_broadcast_scan() -> Test {
    let count = 506;
    let mask = (0..count).map(|i| (i % 2) as u8).collect::<Vec<_>>();
    let source = source(&mask, &[count], &[count], &[count], &[count]);
    assert_eq!(import(&source)?.graph().node_count(), 512);
    let expected = mask
        .iter()
        .map(|&value| if value == 1 { 1.0 } else { -0.0 })
        .collect::<Vec<_>>();
    assert_eq!(
        bits(
            &roundtrip(
                &source,
                &[
                    ("x", data(&[count], &vec![1.0; count])?),
                    ("y", data(&[count], &vec![-0.0; count])?)
                ]
            )?["output"]
        ),
        bits(&expected)
    );
    let source = self::source(
        &(0..507).map(|i| (i % 2) as u8).collect::<Vec<_>>(),
        &[507],
        &[507],
        &[507],
        &[507],
    );
    assert_eq!(refusal(&source), Some(OnnxError::Limit));
    // The two-byte mask would repeat into 131,072 individual selection runs.
    // A full scan alone costs over 390k units; the node bound must win much sooner.
    let source = self::source(&[1, 0], &[2], &[65_536, 1], &[], &[65_536, 2]);
    assert_eq!(
        import_onnx(
            &source,
            ContentDigest::sha256(&source),
            GENERATION,
            OnnxLimits {
                work_units: 50_000,
                ..OnnxLimits::default()
            },
            &|| false
        )
        .err(),
        Some(OnnxError::Limit)
    );
    Ok(())
}

#[test]
fn integer_shape_where_keeps_its_previous_canonical_graph() -> Test {
    let source = model(
        &[
            node("Equal", &["test", "one"], &["condition"], &[]),
            node("Where", &["condition", "yes", "no"], &["shape"], &[]),
            node("Reshape", &["input", "shape"], &["output"], &[]),
            int_weight("test", &[2], &[1, 0]),
            int_weight("one", &[], &[1]),
            int_weight("yes", &[2], &[3, 3]),
            int_weight("no", &[2], &[2, 2]),
            bytes(11, &info("input", &[2, 3], 1)),
            bytes(12, &info("output", &[3, 2], 1)),
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
    let expected = ModelIrGraph::new_validated(
        "onnx-graph",
        ModelIrVersion::V1,
        GENERATION,
        vec![port("input", &[2, 3])?],
        vec![port("output", &[3, 2])?],
        vec![GraphNode::new(
            "onnx-node-0002",
            OpCode::Reshape,
            "onnx-node-0002",
            vec!["input".into()],
            vec!["output".into()],
            AttributeMap::from([("shape".into(), AttrValue::IntList(vec![3, 2]))]),
        )?],
    )?;
    assert_eq!(
        encode_canonical_model_ir(import(&source)?.graph())?,
        encode_canonical_model_ir(&expected)?
    );
    assert_eq!(
        bits(
            &roundtrip(
                &source,
                &[("input", data(&[2, 3], &[-0.0, 1.0, 2.0, 3.0, 4.0, 5.0])?)]
            )?["output"]
        ),
        bits(&[-0.0, 1.0, 2.0, 3.0, 4.0, 5.0])
    );
    Ok(())
}
