#![forbid(unsafe_code)]
//! Version-correct ONNX-18 reductions and detector partitions run through the
//! production scalar/optimized kernels and exact canonical artifact reload.

use super::*;
use fss_model_ir::{ModelIrVersion, OpCode};

fn model_at(graph: &[u8], opset: i64) -> Vec<u8> {
    [integer(1, 8), bytes(8, &integer(2, opset)), bytes(7, graph)].concat()
}

fn string_attr(name: &str, value: &str) -> Vec<u8> {
    attribute(name, 3, &bytes(4, value.as_bytes()))
}

#[allow(clippy::too_many_arguments)]
fn reduction(
    op: &str,
    opset: i64,
    dims: &[usize],
    axes: Option<&[i64]>,
    keep: i64,
    noop: Option<i64>,
    output: &[usize],
    placeholder: bool,
) -> Vec<u8> {
    let input_axes = opset == 18 || op == "ReduceSum";
    let inputs = if input_axes && axes.is_some() {
        vec!["input", "axes"]
    } else if placeholder {
        vec!["input", ""]
    } else {
        vec!["input"]
    };
    let attrs = [
        int_attr("keepdims", keep),
        noop.map_or_else(Vec::new, |value| int_attr("noop_with_empty_axes", value)),
        if input_axes {
            Vec::new()
        } else {
            axes.map_or_else(Vec::new, |axes| ints_attr("axes", axes))
        },
    ]
    .concat();
    model_at(
        &[
            node(op, &inputs, &["output"], &attrs),
            if input_axes {
                axes.map_or_else(Vec::new, |axes| int_weight("axes", &[axes.len()], axes))
            } else {
                Vec::new()
            },
            bytes(11, &info("input", dims, 1)),
            bytes(12, &info("output", output, 1)),
        ]
        .concat(),
        opset,
    )
}

// Bin original coordinates directly; neither production reshaping nor native
// reduction code computes the expected values. Each F32 stage rounds separately.
fn reduction_oracle(values: &[f32], dims: &[usize], axes: &[usize], l2: bool) -> Vec<f32> {
    let width = axes.iter().map(|&axis| dims[axis]).product::<usize>();
    let mut sums = vec![0.0_f32; values.len() / width];
    for (flat, &value) in values.iter().enumerate() {
        let mut coordinate = flat;
        let mut output = 0;
        let mut stride = 1;
        for axis in (0..dims.len()).rev() {
            let index = coordinate % dims[axis];
            coordinate /= dims[axis];
            if !axes.contains(&axis) {
                output += index * stride;
                stride *= dims[axis];
            }
        }
        sums[output] += if l2 { value * value } else { value };
    }
    sums.into_iter()
        .map(|value| {
            if l2 {
                value.sqrt()
            } else {
                value / width as f32
            }
        })
        .collect()
}

#[test]
fn input_axes_reductions_keep_legacy_native_graphs_and_ordered_arithmetic() -> Test {
    for rank in 0..=8 {
        let dims = vec![2; rank];
        let values = (0..dims.iter().product::<usize>())
            .map(|i| (i as f32 % 13.0 - 6.0) * 0.25)
            .collect::<Vec<_>>();
        let mut selections = vec![(0..rank).collect::<Vec<_>>()];
        if rank > 1 {
            selections.push(vec![rank - 1]);
            selections.push((0..rank).step_by(2).collect());
        }
        for axes in selections {
            let raw = axes
                .iter()
                .rev()
                .map(|&axis| axis as i64 - rank as i64)
                .collect::<Vec<_>>();
            for keep in [0, 1] {
                let output = dims
                    .iter()
                    .enumerate()
                    .filter_map(|(axis, &dim)| {
                        if axes.contains(&axis) {
                            (keep == 1).then_some(1)
                        } else {
                            Some(dim)
                        }
                    })
                    .collect::<Vec<_>>();
                for op in ["ReduceMean", "ReduceL2"] {
                    let modern = reduction(op, 18, &dims, Some(&raw), keep, None, &output, false);
                    let imported = import(&modern)?;
                    let artifacts = export(&imported)?;
                    for version in [13, 17] {
                        let old =
                            reduction(op, version, &dims, Some(&raw), keep, None, &output, false);
                        let old = import(&old)?;
                        assert_eq!(artifacts.graph_bytes(), export(&old)?.graph_bytes());
                        assert_eq!(
                            imported.parameters().keys().collect::<Vec<_>>(),
                            old.parameters().keys().collect::<Vec<_>>()
                        );
                        for (name, parameter) in imported.parameters() {
                            assert_eq!(
                                bits(&parameter.to_vec::<f32>()?),
                                bits(&old.parameters()[name].to_vec::<f32>()?)
                            );
                        }
                    }
                    assert_eq!(
                        bits(&roundtrip(&modern, &[("input", data(&dims, &values)?)])?["output"]),
                        bits(&reduction_oracle(&values, &dims, &axes, op == "ReduceL2")),
                        "{op}, rank={rank}, axes={axes:?}, keep={keep}"
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn empty_axes_noop_preserves_mean_bits_but_l2_still_squares_and_takes_sqrt() -> Test {
    let values = [
        -0.0,
        0.0,
        f32::from_bits(1),
        -f32::from_bits(1),
        f32::MIN_POSITIVE,
        -0.1,
        3.0,
        -4.0,
        f32::MAX,
        f32::MIN,
    ];
    let dims = [2, 5];
    let l2 = values
        .iter()
        .map(|&value| {
            let square = value * value;
            square.sqrt()
        })
        .collect::<Vec<_>>();
    assert!(l2[8].is_infinite());
    assert_eq!(l2[0].to_bits(), 0);
    assert_eq!(l2[2].to_bits(), 0);
    for op in ["ReduceMean", "ReduceL2"] {
        for (axes, placeholder) in [(None, false), (None, true), (Some(&[][..]), false)] {
            for keep in [0, 1] {
                let source = reduction(op, 18, &dims, axes, keep, Some(1), &dims, placeholder);
                let imported = import(&source)?;
                assert!(imported.parameters().is_empty());
                assert_eq!(imported.runtime_inputs(), &["input"]);
                let operations = imported
                    .graph()
                    .nodes()
                    .iter()
                    .map(|node| node.op())
                    .collect::<Vec<_>>();
                if op == "ReduceMean" {
                    assert_eq!(operations, [OpCode::Reshape]);
                    assert_eq!(imported.graph().version(), ModelIrVersion::V1);
                } else {
                    assert_eq!(operations, [OpCode::Mul, OpCode::Sqrt]);
                    assert_eq!(imported.graph().version(), ModelIrVersion::V2);
                }
                let expected = if op == "ReduceMean" { &values[..] } else { &l2 };
                assert_eq!(
                    bits(&roundtrip(&source, &[("input", data(&dims, &values)?)])?["output"]),
                    bits(expected)
                );
            }
        }
    }
    for op in ["ReduceMean", "ReduceL2"] {
        let source = reduction(op, 18, &[], None, 1, Some(1), &[], false);
        assert_eq!(
            bits(&roundtrip(&source, &[("input", data(&[], &[-0.0])?)])?["output"]),
            bits(&[if op == "ReduceMean" { -0.0 } else { 0.0 }])
        );
    }
    Ok(())
}

#[test]
fn missing_empty_and_metadata_axes_keep_their_onnx18_meaning() -> Test {
    let values = [3.0, 4.0, -5.0, -12.0];
    for op in ["ReduceMean", "ReduceL2"] {
        for (axes, placeholder) in [(None, false), (None, true), (Some(&[][..]), false)] {
            let source = reduction(op, 18, &[2, 2], axes, 0, Some(0), &[], placeholder);
            assert_eq!(
                bits(&roundtrip(&source, &[("input", data(&[2, 2], &values)?)])?["output"]),
                bits(&reduction_oracle(
                    &values,
                    &[2, 2],
                    &[0, 1],
                    op == "ReduceL2"
                ))
            );
        }
        // An explicit no-op flag never disables a nonempty-axis reduction.
        let source = reduction(op, 18, &[2, 2], Some(&[-1]), 0, Some(1), &[2], false);
        assert_eq!(
            bits(&roundtrip(&source, &[("input", data(&[2, 2], &values)?)])?["output"]),
            bits(&reduction_oracle(&values, &[2, 2], &[1], op == "ReduceL2"))
        );
        let source = model_at(
            &[
                node("Constant", &[], &["axes"], &ints_attr("value_ints", &[-1])),
                node(
                    op,
                    &["input", "axes"],
                    &["output"],
                    &int_attr("keepdims", 0),
                ),
                bytes(11, &info("input", &[2, 2], 1)),
                bytes(12, &info("output", &[2], 1)),
            ]
            .concat(),
            18,
        );
        assert_eq!(
            bits(&roundtrip(&source, &[("input", data(&[2, 2], &values)?)])?["output"]),
            bits(&reduction_oracle(&values, &[2, 2], &[1], op == "ReduceL2"))
        );
    }
    Ok(())
}

fn split_source(
    dims: &[usize],
    axis: i64,
    parts: &[usize],
    explicit: bool,
    num_outputs: Option<i64>,
    opset: i64,
) -> Vec<u8> {
    let names = (0..parts.len())
        .map(|index| format!("part-{index}"))
        .collect::<Vec<_>>();
    let named = names.iter().map(String::as_str).collect::<Vec<_>>();
    let normalized_axis = if axis < 0 {
        axis + dims.len() as i64
    } else {
        axis
    } as usize;
    let mut graph = [
        node(
            "Split",
            if explicit {
                &["input", "parts"]
            } else {
                &["input"]
            },
            &named,
            &[
                int_attr("axis", axis),
                num_outputs.map_or_else(Vec::new, |count| int_attr("num_outputs", count)),
            ]
            .concat(),
        ),
        if explicit {
            int_weight(
                "parts",
                &[parts.len()],
                &parts.iter().map(|&size| size as i64).collect::<Vec<_>>(),
            )
        } else {
            Vec::new()
        },
        bytes(11, &info("input", dims, 1)),
    ]
    .concat();
    for (name, &size) in names.iter().zip(parts) {
        let mut output = dims.to_vec();
        output[normalized_axis] = size;
        graph.extend(bytes(12, &info(name, &output, 1)));
    }
    model_at(&graph, opset)
}

fn split_oracle(
    input: &[f32],
    dims: &[usize],
    axis: usize,
    start: usize,
    width: usize,
) -> Vec<f32> {
    let outer = dims[..axis].iter().product::<usize>();
    let inner = dims[axis + 1..].iter().product::<usize>();
    (0..outer)
        .flat_map(|block| {
            let offset = (block * dims[axis] + start) * inner;
            input[offset..offset + width * inner].iter().copied()
        })
        .collect()
}

#[test]
fn split18_even_and_uneven_chunks_keep_exact_layout_and_legacy_slice_bytes() -> Test {
    for (dims, axis, parts) in [
        (vec![6], 0, vec![2, 2, 2]),
        (vec![7], -1, vec![3, 3, 1]),
        (vec![2, 5, 3], 1, vec![3, 2]),
        (vec![2, 5, 3], -2, vec![2, 2, 1]),
        (vec![7, 2], 0, vec![3, 3, 1]),
        (vec![1, 1, 1, 1, 1, 1, 2, 7], -1, vec![3, 3, 1]),
    ] {
        let values = (0..dims.iter().product::<usize>())
            .map(|i| match i % 5 {
                0 => -0.0,
                1 => f32::from_bits(1),
                2 => -f32::from_bits(1),
                _ => i as f32 - 9.0,
            })
            .collect::<Vec<_>>();
        let normalized_axis = if axis < 0 {
            axis + dims.len() as i64
        } else {
            axis
        } as usize;
        for explicit in [false, true] {
            let modern = split_source(
                &dims,
                axis,
                &parts,
                explicit,
                (!explicit).then_some(parts.len() as i64),
                18,
            );
            let imported = import(&modern)?;
            assert_eq!(imported.graph().node_count(), parts.len());
            assert!(imported.parameters().is_empty());
            for version in [13, 17] {
                let old = split_source(&dims, axis, &parts, true, None, version);
                assert_eq!(
                    export(&imported)?.graph_bytes(),
                    export(&import(&old)?)?.graph_bytes()
                );
            }
            let actual = roundtrip(&modern, &[("input", data(&dims, &values)?)])?;
            let mut start = 0;
            for (index, &width) in parts.iter().enumerate() {
                assert_eq!(
                    bits(&actual[&format!("part-{index}")]),
                    bits(&split_oracle(&values, &dims, normalized_axis, start, width))
                );
                start += width;
            }
        }
    }
    Ok(())
}

#[test]
fn pooled_detector_features_feed_uneven_heads_and_a_runtime_projection() -> Test {
    let source = model_at(
        &[
            node(
                "ReduceMean",
                &["input", "axes"],
                &["pooled"],
                &int_attr("keepdims", 0),
            ),
            node(
                "Split",
                &["pooled"],
                &["features", "scores"],
                &[int_attr("axis", -1), int_attr("num_outputs", 2)].concat(),
            ),
            node("MatMul", &["features", "projection"], &["boxes"], &[]),
            node(
                "Concat",
                &["boxes", "scores"],
                &["output"],
                &int_attr("axis", 1),
            ),
            int_weight("axes", &[1], &[-1]),
            weight("projection", &[3, 2], &[1.0, 0.0, 0.0, 1.0, 1.0, -1.0]),
            bytes(11, &info("input", &[1, 5, 4], 1)),
            bytes(12, &info("output", &[1, 4], 1)),
        ]
        .concat(),
        18,
    );
    let values = (0..20).map(|i| i as f32 / 4.0).collect::<Vec<_>>();
    assert_eq!(
        roundtrip(&source, &[("input", data(&[1, 5, 4], &values)?)])?["output"],
        [2.75, -1.0, 3.375, 4.375]
    );
    Ok(())
}

fn resize_graph(extra: &[u8]) -> Vec<u8> {
    [
        node(
            "Resize",
            &["input", "", "scales"],
            &["output"],
            &[
                string_attr("mode", "nearest"),
                string_attr("coordinate_transformation_mode", "asymmetric"),
                string_attr("nearest_mode", "floor"),
                extra.to_vec(),
            ]
            .concat(),
        ),
        weight("scales", &[4], &[1.0, 1.0, 2.0, 2.0]),
        bytes(11, &info("input", &[1, 1, 2, 2], 1)),
        bytes(12, &info("output", &[1, 1, 4, 4], 1)),
    ]
    .concat()
}

fn pad_graph(inputs: &[&str]) -> Vec<u8> {
    [
        node("Pad", inputs, &["output"], &[]),
        int_weight("pads", &[4], &[0, 1, 0, 1]),
        bytes(11, &info("input", &[1, 2], 1)),
        bytes(12, &info("output", &[1, 4], 1)),
    ]
    .concat()
}

#[test]
fn prior_normalization_selection_and_default_resampling_keep_canonical_meanings() -> Test {
    let resize = model_at(
        &resize_graph(
            &[
                int_attr("antialias", 0),
                string_attr("keep_aspect_ratio_policy", "stretch"),
            ]
            .concat(),
        ),
        18,
    );
    let old_resize = model_at(&resize_graph(&[]), 17);
    assert_eq!(
        export(&import(&resize)?)?.graph_bytes(),
        export(&import(&old_resize)?)?.graph_bytes()
    );
    assert_eq!(
        roundtrip(
            &resize,
            &[("input", data(&[1, 1, 2, 2], &[1.0, 2.0, 3.0, 4.0])?)]
        )?["output"],
        [
            1.0, 1.0, 2.0, 2.0, 1.0, 1.0, 2.0, 2.0, 3.0, 3.0, 4.0, 4.0, 3.0, 3.0, 4.0, 4.0
        ]
    );
    let pad = model_at(&pad_graph(&["input", "pads", "", ""]), 18);
    let old_pad = model_at(&pad_graph(&["input", "pads"]), 17);
    assert_eq!(
        export(&import(&pad)?)?.graph_bytes(),
        export(&import(&old_pad)?)?.graph_bytes()
    );
    assert_eq!(
        roundtrip(&pad, &[("input", data(&[1, 2], &[1.0, 2.0])?)])?["output"],
        [0.0, 1.0, 2.0, 0.0]
    );
    let graph = [
        node(
            "LayerNormalization",
            &["input", "scale", ""],
            &["output", "", ""],
            &[],
        ),
        weight("scale", &[], &[1.0]),
        bytes(11, &info("input", &[2, 3], 1)),
        bytes(12, &info("output", &[2, 3], 1)),
    ]
    .concat();
    let old = model_at(&graph, 17);
    let modern = model_at(&graph, 18);
    assert_eq!(
        export(&import(&old)?)?.graph_bytes(),
        export(&import(&modern)?)?.graph_bytes()
    );
    let input = [("input", data(&[2, 3], &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0])?)];
    assert_eq!(
        bits(&roundtrip(&old, &input)?["output"]),
        bits(&roundtrip(&modern, &input)?["output"])
    );
    let graph = [
        node("Where", &["condition", "input", "other"], &["output"], &[]),
        bytes(5, &tensor("condition", &[2], 9, &[1, 0])),
        weight("other", &[], &[-0.0]),
        bytes(11, &info("input", &[2], 1)),
        bytes(12, &info("output", &[2], 1)),
    ]
    .concat();
    let old = model_at(&graph, 17);
    let modern = model_at(&graph, 18);
    assert_eq!(
        export(&import(&old)?)?.graph_bytes(),
        export(&import(&modern)?)?.graph_bytes()
    );
    assert_eq!(
        bits(&roundtrip(&modern, &[("input", data(&[2], &[1.0, 2.0])?)])?["output"]),
        bits(&[1.0, -0.0])
    );
    Ok(())
}

#[test]
fn schema_gates_refuse_old_axis_forms_runtime_controls_and_unimplemented_modes() {
    for op in ["ReduceMean", "ReduceL2"] {
        let graph = [
            node(op, &["input"], &["output"], &ints_attr("axes", &[-1])),
            bytes(11, &info("input", &[2, 3], 1)),
            bytes(12, &info("output", &[2, 1], 1)),
        ]
        .concat();
        assert_eq!(refusal(&model_at(&graph, 18)), Some(OnnxError::Unsupported));
        let graph = [
            node(op, &["input", "axes"], &["output"], &[]),
            int_weight("axes", &[1], &[-1]),
            bytes(11, &info("input", &[2, 3], 1)),
            bytes(12, &info("output", &[2, 1], 1)),
        ]
        .concat();
        for version in [13, 17] {
            assert_eq!(refusal(&model_at(&graph, version)), Some(OnnxError::Graph));
        }
        for dtype in [1, 7] {
            let graph = [
                node(op, &["input", "axes"], &["output"], &[]),
                bytes(11, &info("axes", &[1], dtype)),
                bytes(11, &info("input", &[2, 3], 1)),
                bytes(12, &info("output", &[2, 1], 1)),
            ]
            .concat();
            assert_eq!(refusal(&model_at(&graph, 18)), Some(OnnxError::Unsupported));
        }
        for axes in [&[2][..], &[-3][..], &[0, 0][..], &[0, -2][..]] {
            assert_eq!(
                refusal(&reduction(
                    op,
                    18,
                    &[2, 3],
                    Some(axes),
                    1,
                    None,
                    &[1, 1],
                    false
                )),
                Some(OnnxError::Graph)
            );
        }
        assert_eq!(
            refusal(&reduction(
                op,
                18,
                &[2, 3],
                None,
                1,
                Some(2),
                &[1, 1],
                false
            )),
            Some(OnnxError::Unsupported)
        );
    }
    for attr in [
        int_attr("antialias", 1),
        string_attr("keep_aspect_ratio_policy", "not_larger"),
        string_attr("keep_aspect_ratio_policy", "not_smaller"),
    ] {
        assert_eq!(
            refusal(&model_at(&resize_graph(&attr), 18)),
            Some(OnnxError::Unsupported)
        );
    }
    let graph = [
        pad_graph(&["input", "pads", "", "axes"]),
        int_weight("axes", &[2], &[0, 1]),
    ]
    .concat();
    for version in [13, 17] {
        assert_eq!(refusal(&model_at(&graph, version)), Some(OnnxError::Graph));
    }
    for op in [
        "Mish",
        "GroupNormalization",
        "Col2Im",
        "ReduceMax",
        "BitwiseAnd",
    ] {
        let graph = [
            node(op, &["input"], &["output"], &[]),
            bytes(11, &info("input", &[2], 1)),
            bytes(12, &info("output", &[2], 1)),
        ]
        .concat();
        assert_eq!(refusal(&model_at(&graph, 18)), Some(OnnxError::Unsupported));
    }
}

#[test]
fn split18_requires_one_partition_contract_and_positive_declared_chunks() {
    for (explicit, count) in [
        (true, Some(2)),
        (false, None),
        (false, Some(0)),
        (false, Some(-1)),
        (false, Some(3)),
        (false, Some(i64::MAX)),
    ] {
        assert!(
            refusal(&split_source(&[6], 0, &[3, 3], explicit, count, 18)).is_some(),
            "explicit={explicit}, count={count:?}"
        );
    }
    for version in [13, 17] {
        assert_eq!(
            refusal(&split_source(&[6], 0, &[3, 3], false, Some(2), version)),
            Some(OnnxError::Unsupported)
        );
    }
    // ceil(5/4)=2 would leave a negative last chunk; ceil(6/4)=2 an empty one.
    // Neither may be turned into a silent empty/overlapping native slice.
    for length in [3, 5, 6] {
        assert_eq!(
            refusal(&split_source(
                &[length],
                0,
                &[1, 1, 1, 1],
                false,
                Some(4),
                18
            )),
            Some(OnnxError::Unsupported)
        );
    }
}

#[test]
fn new_axis_and_l2_noop_paths_enforce_exact_limits_and_every_cancellation_checkpoint() -> Test {
    let mean = reduction("ReduceMean", 18, &[2, 3], Some(&[-1]), 0, None, &[2], false);
    let l2 = reduction("ReduceL2", 18, &[2], Some(&[]), 1, Some(1), &[2], false);
    for (source, nodes, tensors, parameter_bytes, tensor_bytes) in [
        (mean, 3, 7, 24, 24),
        (l2, 2, 4, 0, 8),
        (
            split_source(&[7], 0, &[3, 3, 1], false, Some(3), 18),
            3,
            4,
            0,
            28,
        ),
    ] {
        let imported = import(&source)?;
        assert_eq!(imported.graph().node_count(), nodes);
        let digest = ContentDigest::sha256(&source);
        let exact = OnnxLimits {
            source_bytes: source.len(),
            nodes,
            tensors,
            parameter_bytes,
            tensor_bytes,
            work_units: imported.work_units(),
        };
        import_onnx(&source, digest, GENERATION, exact, &|| false)?;
        let mut short = vec![
            OnnxLimits {
                nodes: nodes - 1,
                ..exact
            },
            OnnxLimits {
                tensors: tensors - 1,
                ..exact
            },
            OnnxLimits {
                tensor_bytes: tensor_bytes - 1,
                ..exact
            },
            OnnxLimits {
                source_bytes: source.len() - 1,
                ..exact
            },
        ];
        if parameter_bytes != 0 {
            short.push(OnnxLimits {
                parameter_bytes: parameter_bytes - 1,
                ..exact
            });
        }
        for limits in short {
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
        let total = Cell::new(0);
        import_onnx(&source, digest, GENERATION, exact, &|| {
            total.set(total.get() + 1);
            false
        })?;
        for stop in 1..=total.get() {
            let seen = Cell::new(0);
            assert_eq!(
                import_onnx(&source, digest, GENERATION, exact, &|| {
                    seen.set(seen.get() + 1);
                    seen.get() == stop
                })
                .err(),
                Some(OnnxError::Cancelled),
                "checkpoint={stop}"
            );
        }
    }
    Ok(())
}

#[test]
fn pad18_selected_axes_preserve_order_sign_and_canonical_execution() -> Test {
    // Crop one column at the start, then pad the bottom and right. The
    // fourth input names width first, height second, using negative axes.
    let input = [("input", data(&[1, 2, 3], &[1., 2., 3., 4., 5., 6.])?)];
    for (mode, expected) in [
        ("constant", [2., 3., 0., 5., 6., 0., 0., 0., 0.]),
        ("edge", [2., 3., 3., 5., 6., 6., 5., 6., 6.]),
        ("reflect", [2., 3., 2., 5., 6., 5., 2., 3., 2.]),
    ] {
        let graph = |inputs: &[&str], pads: &[i64], axes: Option<&[i64]>| {
            [
                node("Pad", inputs, &["output"], &string_attr("mode", mode)),
                int_weight("pads", &[pads.len()], pads),
                axes.map_or_else(Vec::new, |a| int_weight("axes", &[a.len()], a)),
                bytes(11, &info("input", &[1, 2, 3], 1)),
                bytes(12, &info("output", &[1, 3, 3], 1)),
            ]
            .concat()
        };
        let selected = |axes: &[i64]| {
            let graph = graph(&["input", "pads", "", "axes"], &[-1, 0, 1, 1], Some(axes));
            model_at(&graph, 18)
        };
        let source = selected(&[-1, -2]);
        let full = model_at(&graph(&["input", "pads"], &[0, 0, -1, 0, 1, 1], None), 17);
        assert_eq!(
            export(&import(&source)?)?.graph_bytes(),
            export(&import(&full)?)?.graph_bytes()
        );
        assert_eq!(roundtrip(&source, &input)?["output"], expected);
        for axes in [&[-1, 2][..], &[3, -2], &[-4, 1], &[2]] {
            assert_eq!(refusal(&selected(axes)), Some(OnnxError::Graph));
        }
    }
    Ok(())
}

#[test]
fn resize18_selected_sizes_and_scales_execute_with_ordered_axes() -> Test {
    let graph = |resize_inputs: &[&str], control: Vec<u8>, attrs: Vec<u8>, dims: &[usize]| {
        [
            node("Resize", resize_inputs, &["output"], &attrs),
            control,
            bytes(11, &info("input", &[1, 1, 2, 3], 1)),
            bytes(12, &info("output", dims, 1)),
        ]
        .concat()
    };
    let image = [("input", data(&[1, 1, 2, 3], &[1., 2., 3., 4., 5., 6.])?)];
    // Scale width by 1.5 and height by 2. Nearest asymmetric/floor maps
    // four output columns to inputs 0,0,1,2 and duplicates both rows.
    let nearest = [
        string_attr("coordinate_transformation_mode", "asymmetric"),
        string_attr("nearest_mode", "floor"),
    ]
    .concat();
    let scale_graph = |axes: &[i64], scales: &[f32]| {
        graph(
            &["input", "", "scale"],
            weight("scale", &[scales.len()], scales),
            [nearest.clone(), ints_attr("axes", axes)].concat(),
            &[1, 1, 4, 4],
        )
    };
    let scaled = scale_graph(&[-1, -2], &[1.5, 2.0]);
    let source = model_at(&scaled, 18);
    let full = graph(
        &["input", "", "scale"],
        weight("scale", &[4], &[1., 1., 2., 1.5]),
        nearest.clone(),
        &[1, 1, 4, 4],
    );
    assert_eq!(
        roundtrip(&source, &image)?["output"],
        [1., 1., 2., 3., 1., 1., 2., 3., 4., 4., 5., 6., 4., 4., 5., 6.]
    );
    assert_eq!(
        export(&import(&source)?)?.graph_bytes(),
        export(&import(&model_at(&full, 17))?)?.graph_bytes()
    );

    // Resize only height. The half-way row is interpolated independently
    // for each column, with width and both non-spatial extents unchanged.
    let sizes = graph(
        &["input", "", "", "size"],
        int_weight("size", &[1], &[3]),
        [
            string_attr("mode", "linear"),
            string_attr("coordinate_transformation_mode", "align_corners"),
            ints_attr("axes", &[2]),
        ]
        .concat(),
        &[1, 1, 3, 3],
    );
    assert_eq!(
        roundtrip(&model_at(&sizes, 18), &image)?["output"],
        [1., 2., 3., 2.5, 3.5, 4.5, 4., 5., 6.]
    );
    for version in [13, 17] {
        assert_eq!(
            refusal(&model_at(&scaled, version)),
            Some(OnnxError::Unsupported)
        );
    }
    for axes in [&[-1, 3][..], &[4, 2], &[-5, 2], &[3]] {
        assert_eq!(
            refusal(&model_at(&scale_graph(axes, &[1.5, 2.0]), 18)),
            Some(OnnxError::Graph)
        );
    }
    assert_eq!(
        refusal(&model_at(&scale_graph(&[0, 1], &[1.5, 2.0]), 18)),
        Some(OnnxError::Unsupported)
    );
    Ok(())
}
