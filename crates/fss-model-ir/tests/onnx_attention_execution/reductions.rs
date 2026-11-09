#![forbid(unsafe_code)]
//! Opset-13 sum and L2 use the parent module's unchanged production executors,
//! canonical graph codec and Safetensors parser, including artifact reload.

use super::*;
use fss_model_ir::{ModelIrVersion, OpCode};

fn sum_model(
    input: &[usize],
    axes: Option<&[i64]>,
    keepdims: Option<i64>,
    noop: Option<i64>,
    output: &[usize],
) -> Vec<u8> {
    let attrs = [
        keepdims.map_or_else(Vec::new, |value| int_attr("keepdims", value)),
        noop.map_or_else(Vec::new, |value| int_attr("noop_with_empty_axes", value)),
    ]
    .concat();
    model(
        &[
            node(
                "ReduceSum",
                if axes.is_some() {
                    &["input", "axes"]
                } else {
                    &["input"]
                },
                &["output"],
                &attrs,
            ),
            axes.map_or_else(Vec::new, |axes| int_weight("axes", &[axes.len()], axes)),
            bytes(11, &info("input", input, 1)),
            bytes(12, &info("output", output, 1)),
        ]
        .concat(),
    )
}

fn l2_model(
    input: &[usize],
    axes: Option<&[i64]>,
    keepdims: Option<i64>,
    output: &[usize],
) -> Vec<u8> {
    model(
        &[
            node(
                "ReduceL2",
                &["input"],
                &["output"],
                &mean_attrs(axes, keepdims),
            ),
            bytes(11, &info("input", input, 1)),
            bytes(12, &info("output", output, 1)),
        ]
        .concat(),
    )
}

// Independent source-coordinate buckets; no production layout or kernel code.
fn oracle(values: &[f32], dims: &[usize], axes: &[usize], l2: bool) -> Vec<f32> {
    let output_count = dims
        .iter()
        .enumerate()
        .filter(|(axis, _)| !axes.contains(axis))
        .map(|(_, &dim)| dim)
        .product();
    let mut result = vec![0.0_f32; output_count];
    for (flat, &value) in values.iter().enumerate() {
        let mut index = flat;
        let mut output = 0;
        let mut stride = 1;
        for axis in (0..dims.len()).rev() {
            let coordinate = index % dims[axis];
            index /= dims[axis];
            if !axes.contains(&axis) {
                output += coordinate * stride;
                stride *= dims[axis];
            }
        }
        result[output] += if l2 { value * value } else { value };
    }
    if l2 {
        for value in &mut result {
            *value = value.sqrt();
        }
    }
    result
}

#[test]
fn sum_and_l2_literals_keepdims_defaults_and_versions_survive_reload() -> Test {
    let dims = [2, 2];
    let input = data(&dims, &[3., 4., -5., -12.])?;
    for keepdims in [None, Some(0), Some(1)] {
        let output = if keepdims == Some(0) {
            vec![2]
        } else {
            vec![2, 1]
        };
        let sum = sum_model(&dims, Some(&[-1]), keepdims, None, &output);
        let l2 = l2_model(&dims, Some(&[-1]), keepdims, &output);
        assert_eq!(import(&sum)?.graph().version(), ModelIrVersion::V1);
        assert_eq!(import(&l2)?.graph().version(), ModelIrVersion::V2);
        assert_eq!(
            roundtrip(&sum, &[("input", input.clone())])?["output"],
            [7., -17.]
        );
        assert_eq!(
            roundtrip(&l2, &[("input", input.clone())])?["output"],
            [5., 13.]
        );
    }
    for axes in [None, Some(&[][..])] {
        let sum = sum_model(&dims, axes, None, None, &[1, 1]);
        let l2 = l2_model(&dims, axes, Some(0), &[]);
        assert_eq!(
            roundtrip(&sum, &[("input", input.clone())])?["output"],
            [-10.]
        );
        assert_eq!(
            roundtrip(&l2, &[("input", input.clone())])?["output"],
            [194.0_f32.sqrt()]
        );
    }
    // Sum-13 permits the empty optional-input placeholder as well as omission.
    let placeholder = model(
        &[
            node(
                "ReduceSum",
                &["input", ""],
                &["output"],
                &int_attr("keepdims", 0),
            ),
            bytes(11, &info("input", &dims, 1)),
            bytes(12, &info("output", &[], 1)),
        ]
        .concat(),
    );
    assert_eq!(
        roundtrip(&placeholder, &[("input", input)])?["output"],
        [-10.]
    );
    Ok(())
}

#[test]
fn every_admitted_rank_and_axis_order_matches_independent_reduction() -> Test {
    for rank in 0..=8 {
        let dims = (0..rank)
            .map(|axis| if axis % 2 == 0 { 2 } else { 3 })
            .collect::<Vec<_>>();
        let count = dims.iter().product();
        let values = (0..count)
            .map(|index| ((index * 7 % 19) as f32 - 9.) / 8.)
            .collect::<Vec<_>>();
        let mut selections = vec![(0..rank).collect::<Vec<_>>()];
        if rank > 1 {
            selections.push((0..rank).step_by(2).collect());
            selections.push(vec![rank - 1]);
        }
        for axes in selections {
            let negative = axes
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
                for l2 in [false, true] {
                    let source = if l2 {
                        l2_model(&dims, Some(&negative), Some(keep), &output)
                    } else {
                        sum_model(&dims, Some(&negative), Some(keep), None, &output)
                    };
                    let actual = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
                    assert_eq!(
                        bits(&actual["output"]),
                        bits(&oracle(&values, &dims, &axes, l2)),
                        "l2={l2} rank={rank} axes={axes:?} keep={keep}"
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn sum_noop_preserves_exact_bits_and_uses_no_generated_parameters() -> Test {
    let dims = [2, 3];
    let values = [
        -0.,
        0.,
        f32::from_bits(1),
        -f32::from_bits(1),
        f32::MAX,
        f32::MIN,
    ];
    for axes in [None, Some(&[][..])] {
        for keep in [0, 1] {
            let source = sum_model(&dims, axes, Some(keep), Some(1), &dims);
            let imported = import(&source)?;
            assert_eq!(imported.graph().node_count(), 1);
            assert_eq!(imported.graph().nodes()[0].op(), OpCode::Reshape);
            assert!(imported.parameters().is_empty());
            assert_eq!(imported.runtime_inputs(), &["input"]);
            assert_eq!(
                bits(&roundtrip(&source, &[("input", data(&dims, &values)?)])?["output"]),
                bits(&values)
            );
            let limits = OnnxLimits {
                nodes: 1,
                tensors: if axes.is_some() { 3 } else { 2 },
                parameter_bytes: 1,
                ..OnnxLimits::default()
            };
            assert!(
                import_onnx(
                    &source,
                    ContentDigest::sha256(&source),
                    GENERATION,
                    limits,
                    &|| false
                )
                .is_ok()
            );
        }
    }
    let scalar = sum_model(&[], None, Some(0), Some(1), &[]);
    assert_eq!(
        bits(&roundtrip(&scalar, &[("input", data(&[], &[-0.])?)])?["output"]),
        bits(&[-0.])
    );
    let placeholder = model(
        &[
            node(
                "ReduceSum",
                &["input", ""],
                &["output"],
                &int_attr("noop_with_empty_axes", 1),
            ),
            bytes(11, &info("input", &dims, 1)),
            bytes(12, &info("output", &dims, 1)),
        ]
        .concat(),
    );
    assert_eq!(
        bits(&roundtrip(&placeholder, &[("input", data(&dims, &values)?)])?["output"]),
        bits(&values)
    );
    // noop only applies to empty axes: nonempty axes still reduce.
    let nonempty = sum_model(&[2], Some(&[0]), Some(0), Some(1), &[]);
    assert_eq!(
        roundtrip(&nonempty, &[("input", data(&[2], &[3., 4.])?)])?["output"],
        [7.]
    );
    Ok(())
}

#[test]
fn sum_axes_from_constant_and_static_shape_program_are_compile_time_only() -> Test {
    for from_shape in [false, true] {
        let controls = if from_shape {
            [
                node("Shape", &["input"], &["shape"], &[]),
                node("Gather", &["shape", "index"], &["axes"], &[]),
                int_weight("index", &[1], &[0]),
            ]
            .concat()
        } else {
            node(
                "Constant",
                &[],
                &["axes"],
                &attribute(
                    "value",
                    4,
                    &bytes(5, &tensor("", &[1], 7, &1_i64.to_le_bytes())),
                ),
            )
        };
        let source = model(
            &[
                controls,
                node(
                    "ReduceSum",
                    &["input", "axes"],
                    &["output"],
                    &int_attr("keepdims", 0),
                ),
                bytes(11, &info("input", &[1, 3], 1)),
                bytes(12, &info("output", &[1], 1)),
            ]
            .concat(),
        );
        let imported = import(&source)?;
        assert_eq!(imported.runtime_inputs(), &["input"]);
        assert_eq!(imported.parameters().len(), 1);
        assert!(
            imported
                .parameters()
                .keys()
                .all(|name| name.ends_with("sum-ones"))
        );
        assert_eq!(
            roundtrip(&source, &[("input", data(&[1, 3], &[2., 3., 4.])?)])?["output"],
            [9.]
        );
    }
    Ok(())
}

#[test]
fn normalized_weighted_feature_head_executes_with_both_reductions() -> Test {
    // A small real composition used by feature heads: weighted token pooling,
    // L2 normalization with an explicit zero-norm floor, then a dense projection.
    let source = model(
        &[
            node("Mul", &["input", "token-weights"], &["weighted"], &[]),
            node(
                "ReduceSum",
                &["weighted", "token-axis"],
                &["pooled"],
                &int_attr("keepdims", 0),
            ),
            node(
                "ReduceL2",
                &["pooled"],
                &["norm"],
                &ints_attr("axes", &[-1]),
            ),
            node("Clip", &["norm", "epsilon"], &["denominator"], &[]),
            node("Div", &["pooled", "denominator"], &["normalized"], &[]),
            node("MatMul", &["normalized", "projection"], &["output"], &[]),
            weight("token-weights", &[1, 2, 1], &[0.25, 0.75]),
            int_weight("token-axis", &[1], &[1]),
            weight("epsilon", &[], &[1e-6]),
            weight("projection", &[2, 2], &[1., 2., 3., 4.]),
            bytes(11, &info("input", &[2, 2, 2], 1)),
            bytes(12, &info("pooled", &[2, 2], 1)),
            bytes(12, &info("norm", &[2, 1], 1)),
            bytes(12, &info("normalized", &[2, 2], 1)),
            bytes(12, &info("output", &[2, 2], 1)),
        ]
        .concat(),
    );
    let actual = roundtrip(
        &source,
        &[(
            "input",
            data(&[2, 2, 2], &[0., 4., 4., 4., 0., 0., 0., 0.])?,
        )],
    )?;
    assert_eq!(actual["pooled"], [3., 4., 0., 0.]);
    assert_eq!(actual["norm"], [5., 0.]);
    assert_eq!(actual["normalized"], [0.6, 0.8, 0., 0.]);
    assert_eq!(actual["output"], [3., 4.4, 0., 0.]);
    assert_eq!(import(&source)?.graph().version(), ModelIrVersion::V2);
    Ok(())
}

#[test]
fn reduction_rounding_signed_zero_underflow_and_overflow_remain_explicit() -> Test {
    for values in [
        vec![-0.],
        vec![-0., -0.],
        vec![f32::from_bits(1), f32::from_bits(1)],
        vec![16_777_216., 1., -16_777_216.],
        vec![16_777_216., -16_777_216., 1.],
        vec![f32::MAX, f32::MAX],
        vec![f32::MIN, f32::MIN],
        vec![-3., 4.],
    ] {
        for l2 in [false, true] {
            let dims = [values.len()];
            let source = if l2 {
                l2_model(&dims, None, Some(0), &[])
            } else {
                sum_model(&dims, None, Some(0), None, &[])
            };
            let actual = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
            assert_eq!(
                bits(&actual["output"]),
                bits(&oracle(&values, &dims, &[0], l2)),
                "l2={l2} {values:?}"
            );
        }
    }
    for l2 in [false, true] {
        let source = if l2 {
            l2_model(&[], None, None, &[])
        } else {
            sum_model(&[], None, None, None, &[])
        };
        assert_eq!(
            bits(&roundtrip(&source, &[("input", data(&[], &[-0.])?)])?["output"]),
            bits(&[0.])
        );
    }
    // Native L2 is square/sum/sqrt, not a scaled robust norm: finite extremes
    // overflow, and tiny squares underflow. Neither is silently repaired.
    let source = l2_model(&[1], None, Some(0), &[]);
    assert_eq!(
        roundtrip(&source, &[("input", data(&[1], &[f32::MAX])?)])?["output"],
        [f32::INFINITY]
    );
    assert_eq!(
        roundtrip(&source, &[("input", data(&[1], &[f32::from_bits(1)])?)])?["output"],
        [0.]
    );
    Ok(())
}

#[test]
fn reductions_refuse_incompatible_opset_forms_and_malformed_controls() {
    for axes in [
        &[1, -1][..],
        &[2][..],
        &[-3][..],
        &[i64::MIN][..],
        &[i64::MAX][..],
    ] {
        assert_eq!(
            refusal(&sum_model(&[2, 3], Some(axes), None, None, &[2, 1])),
            Some(OnnxError::Graph)
        );
        assert_eq!(
            refusal(&l2_model(&[2, 3], Some(axes), None, &[2, 1])),
            Some(OnnxError::Graph)
        );
    }
    for (op, inputs, attrs, expected) in [
        (
            "ReduceSum",
            vec!["input"],
            ints_attr("axes", &[1]),
            OnnxError::Unsupported,
        ),
        (
            "ReduceSum",
            vec!["input"],
            int_attr("noop_with_empty_axes", 2),
            OnnxError::Unsupported,
        ),
        (
            "ReduceSum",
            vec!["input"],
            ints_attr("noop_with_empty_axes", &[1]),
            OnnxError::Graph,
        ),
        (
            "ReduceSum",
            vec!["input"],
            ints_attr("keepdims", &[1]),
            OnnxError::Graph,
        ),
        (
            "ReduceSum",
            vec!["input"],
            int_attr("keepdims", -1),
            OnnxError::Unsupported,
        ),
        ("ReduceSum", vec![], vec![], OnnxError::Graph),
        ("ReduceSum", vec![""], vec![], OnnxError::Graph),
        ("ReduceSum", vec!["input", "", ""], vec![], OnnxError::Graph),
        ("ReduceL2", vec!["input", "input"], vec![], OnnxError::Graph),
        (
            "ReduceL2",
            vec!["input"],
            int_attr("noop_with_empty_axes", 0),
            OnnxError::Unsupported,
        ),
        (
            "ReduceL2",
            vec!["input"],
            int_attr("axes", 1),
            OnnxError::Graph,
        ),
        (
            "ReduceL2",
            vec!["input"],
            int_attr("keepdims", 2),
            OnnxError::Unsupported,
        ),
        ("ReduceL2", vec![], vec![], OnnxError::Graph),
    ] {
        let source = model(
            &[
                node(op, &inputs, &["output"], &attrs),
                bytes(11, &info("input", &[2, 3], 1)),
                bytes(12, &info("output", &[1, 1], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(expected), "{op} {inputs:?}");
    }
    for (control, expected) in [
        (weight("axes", &[1], &[1.]), OnnxError::Graph),
        (int_weight("axes", &[], &[1]), OnnxError::Graph),
        (int_weight("axes", &[1, 1], &[1]), OnnxError::Unsupported),
        (bytes(11, &info("axes", &[1], 1)), OnnxError::Unsupported),
    ] {
        let source = model(
            &[
                node("ReduceSum", &["input", "axes"], &["output"], &[]),
                control,
                bytes(11, &info("input", &[2, 3], 1)),
                bytes(12, &info("output", &[2, 1], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(expected));
    }
    assert_eq!(
        refusal(&sum_model(&[], Some(&[0]), None, None, &[])),
        Some(OnnxError::Graph)
    );
    assert_eq!(
        refusal(&l2_model(&[], Some(&[0]), None, &[])),
        Some(OnnxError::Graph)
    );
    assert_eq!(
        refusal(&sum_model(&[2, 3], Some(&[1]), None, None, &[2])),
        Some(OnnxError::Graph)
    );
    assert_eq!(
        refusal(&l2_model(&[2, 3], Some(&[1]), None, &[2])),
        Some(OnnxError::Graph)
    );
    assert_eq!(
        refusal(&sum_model(&[2, 3], None, Some(0), Some(1), &[])),
        Some(OnnxError::Graph)
    );
}

#[test]
fn reductions_preflight_full_expansion_and_every_cancellation_checkpoint() -> Test {
    for (source, nodes, tensors, parameter_bytes) in [
        (
            sum_model(&[2, 3, 4], Some(&[1]), Some(0), None, &[2, 4]),
            4,
            7,
            20,
        ),
        (l2_model(&[2, 3, 4], Some(&[1]), Some(0), &[2, 4]), 6, 8, 12),
    ] {
        let imported = import(&source)?;
        assert_eq!(imported.graph().node_count(), nodes);
        let limits = OnnxLimits {
            nodes,
            tensors,
            parameter_bytes,
            tensor_bytes: 96,
            work_units: imported.work_units(),
            ..OnnxLimits::default()
        };
        assert!(
            import_onnx(
                &source,
                ContentDigest::sha256(&source),
                GENERATION,
                limits,
                &|| false
            )
            .is_ok()
        );
        for limits in [
            OnnxLimits {
                nodes: nodes - 1,
                ..limits
            },
            OnnxLimits {
                tensors: tensors - 1,
                ..limits
            },
            OnnxLimits {
                parameter_bytes: parameter_bytes - 1,
                ..limits
            },
            OnnxLimits {
                tensor_bytes: 95,
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
                    work_units: limits.work_units - 1,
                    ..limits
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
            limits,
            &|| {
                calls.set(calls.get() + 1);
                false
            },
        )?;
        let total = calls.get();
        for stop in 1..=total {
            calls.set(0);
            assert_eq!(
                import_onnx(
                    &source,
                    ContentDigest::sha256(&source),
                    GENERATION,
                    limits,
                    &|| {
                        calls.set(calls.get() + 1);
                        calls.get() == stop
                    }
                )
                .err(),
                Some(OnnxError::Cancelled),
                "checkpoint {stop}/{total}"
            );
        }
    }
    // Each generated column fits the individual tensor bound but exceeds the
    // aggregate parameter bound. Refuse before materializing millions of ones.
    assert_eq!(
        refusal(&sum_model(&[4_194_305], None, Some(0), None, &[])),
        Some(OnnxError::Limit)
    );
    assert_eq!(
        refusal(&l2_model(&[4_194_305], None, Some(0), &[])),
        Some(OnnxError::Limit)
    );
    Ok(())
}
