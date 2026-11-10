#![forbid(unsafe_code)]
//! Pixel-shuffle contracts use direct coordinate oracles, both production CPU
//! executors, and the actual canonical graph/Safetensors round trip.

use super::*;

fn mode(value: &str) -> Vec<u8> {
    attribute("mode", 3, &bytes(4, value.as_bytes()))
}

fn spatial_model(op: &str, input: &[usize], output: &[usize], attrs: &[u8]) -> Vec<u8> {
    model(
        &[
            node(op, &["input"], &["output"], attrs),
            bytes(11, &info("input", input, 1)),
            bytes(12, &info("output", output, 1)),
        ]
        .concat(),
    )
}

// Direct coordinate lookup without production reshape/transpose/index helpers.
fn shuffle_oracle(input: &[f32], dims: [usize; 4], block: usize, crd: bool) -> Vec<f32> {
    let [batch, channels, height, width] = dims;
    let output_channels = channels / block / block;
    let mut output = Vec::with_capacity(input.len());
    for n in 0..batch {
        for c in 0..output_channels {
            for row in 0..height * block {
                for col in 0..width * block {
                    let offset = (row % block) * block + col % block;
                    let source_channel = if crd {
                        c * block * block + offset
                    } else {
                        offset * output_channels + c
                    };
                    let index = ((n * channels + source_channel) * height + row / block) * width
                        + col / block;
                    output.push(input[index]);
                }
            }
        }
    }
    output
}

fn unshuffle_oracle(input: &[f32], dims: [usize; 4], block: usize) -> Vec<f32> {
    let [batch, channels, height, width] = dims;
    let mut output = Vec::with_capacity(input.len());
    for n in 0..batch {
        for c in 0..channels * block * block {
            let offset = c / channels;
            for row in 0..height / block {
                for col in 0..width / block {
                    let index =
                        ((n * channels + c % channels) * height + row * block + offset / block)
                            * width
                            + col * block
                            + offset % block;
                    output.push(input[index]);
                }
            }
        }
    }
    output
}

#[test]
fn spatial_literal_orders_distinguish_dcr_crd_and_opset13_unshuffle() -> Test {
    let values = (0..16).map(|value| value as f32).collect::<Vec<_>>();
    for (selected, expected) in [
        (
            None,
            vec![
                0., 4., 1., 5., 8., 12., 9., 13., 2., 6., 3., 7., 10., 14., 11., 15.,
            ],
        ),
        (
            Some("DCR"),
            vec![
                0., 4., 1., 5., 8., 12., 9., 13., 2., 6., 3., 7., 10., 14., 11., 15.,
            ],
        ),
        (
            Some("CRD"),
            vec![
                0., 2., 1., 3., 4., 6., 5., 7., 8., 10., 9., 11., 12., 14., 13., 15.,
            ],
        ),
    ] {
        let attrs = [
            int_attr("blocksize", 2),
            selected.map_or_else(Vec::new, mode),
        ]
        .concat();
        let source = spatial_model("DepthToSpace", &[1, 8, 1, 2], &[1, 2, 2, 4], &attrs);
        let actual = roundtrip(&source, &[("input", data(&[1, 8, 1, 2], &values)?)])?;
        assert_eq!(bits(&actual["output"]), bits(&expected));
    }
    let source = spatial_model(
        "SpaceToDepth",
        &[1, 2, 2, 4],
        &[1, 8, 1, 2],
        &int_attr("blocksize", 2),
    );
    let actual = roundtrip(&source, &[("input", data(&[1, 2, 2, 4], &values)?)])?;
    assert_eq!(
        actual["output"],
        [
            0., 2., 8., 10., 1., 3., 9., 11., 4., 6., 12., 14., 5., 7., 13., 15.
        ]
    );
    Ok(())
}

#[test]
fn spatial_batches_rectangles_and_block_sizes_preserve_exact_finite_bits() -> Test {
    let special = [
        -0.0,
        0.,
        f32::from_bits(1),
        -f32::from_bits(1),
        f32::MAX,
        f32::MIN,
    ];
    for block in 1..=3 {
        let dims = [2, 2 * block * block, 2, 3];
        let output_dims = [2, 2, 2 * block, 3 * block];
        let values = (0..dims.iter().product())
            .map(|index| {
                if index < special.len() {
                    special[index]
                } else {
                    index as f32
                }
            })
            .collect::<Vec<_>>();
        for crd in [false, true] {
            let attrs = [
                int_attr("blocksize", block as i64),
                mode(if crd { "CRD" } else { "DCR" }),
            ]
            .concat();
            let source = spatial_model("DepthToSpace", &dims, &output_dims, &attrs);
            let actual = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
            assert_eq!(
                bits(&actual["output"]),
                bits(&shuffle_oracle(&values, dims, block, crd))
            );
        }
        let values = (0..output_dims.iter().product())
            .map(|index| {
                if index < special.len() {
                    special[index]
                } else {
                    -(index as f32)
                }
            })
            .collect::<Vec<_>>();
        let source = spatial_model(
            "SpaceToDepth",
            &output_dims,
            &dims,
            &int_attr("blocksize", block as i64),
        );
        let actual = roundtrip(&source, &[("input", data(&output_dims, &values)?)])?;
        assert_eq!(
            bits(&actual["output"]),
            bits(&unshuffle_oracle(&values, output_dims, block))
        );
    }
    Ok(())
}

#[test]
fn spatial_inverse_composition_preserves_all_pixels_and_ir_v1() -> Test {
    let dims = [2, 3, 4, 6];
    let source = model(
        &[
            node(
                "SpaceToDepth",
                &["input"],
                &["packed"],
                &int_attr("blocksize", 2),
            ),
            node(
                "DepthToSpace",
                &["packed"],
                &["output"],
                &int_attr("blocksize", 2),
            ),
            bytes(11, &info("input", &dims, 1)),
            bytes(12, &info("output", &dims, 1)),
            bytes(13, &info("packed", &[2, 12, 2, 3], 1)),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    assert_eq!(imported.graph().version(), fss_model_ir::ModelIrVersion::V1);
    assert_eq!(imported.graph().node_count(), 6);
    assert!(imported.parameters().is_empty());
    let values = (0..144).map(|index| index as f32 / 8.).collect::<Vec<_>>();
    let actual = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
    assert_eq!(bits(&actual["output"]), bits(&values));
    Ok(())
}

#[test]
fn spatial_learned_convolution_head_executes_after_artifact_reload() -> Test {
    let weights = [1., -1., 2., -2., 0.5, -0.5, 4., -4.];
    let source = model(
        &[
            node("Conv", &["input", "kernel"], &["features"], &[]),
            node(
                "DepthToSpace",
                &["features"],
                &["pixels"],
                &[int_attr("blocksize", 2), mode("CRD")].concat(),
            ),
            node("Relu", &["pixels"], &["output"], &[]),
            weight("kernel", &[8, 1, 1, 1], &weights),
            bytes(11, &info("input", &[1, 1, 2, 3], 1)),
            bytes(12, &info("output", &[1, 2, 4, 6], 1)),
        ]
        .concat(),
    );
    let values = [-2., -1., -0.5, 0.25, 1., 2.];
    let projected = weights
        .iter()
        .flat_map(|weight| values.iter().map(move |value| weight * value))
        .collect::<Vec<_>>();
    let expected = shuffle_oracle(&projected, [1, 8, 2, 3], 2, true)
        .into_iter()
        .map(|value| value.max(0.))
        .collect::<Vec<_>>();
    let actual = roundtrip(&source, &[("input", data(&[1, 1, 2, 3], &values)?)])?;
    assert_eq!(bits(&actual["output"]), bits(&expected));
    assert_eq!(import(&source)?.parameters().len(), 1);
    Ok(())
}

#[test]
fn spatial_bad_shapes_attributes_and_overflow_refuse() -> Test {
    for op in ["DepthToSpace", "SpaceToDepth"] {
        let dims = [1, 4, 2, 2];
        assert_eq!(
            refusal(&spatial_model(op, &dims, &dims, &[])),
            Some(OnnxError::Malformed)
        );
        for block in [0, -1, i64::MIN] {
            assert_eq!(
                refusal(&spatial_model(
                    op,
                    &dims,
                    &dims,
                    &int_attr("blocksize", block)
                )),
                Some(OnnxError::Graph)
            );
        }
        assert_eq!(
            refusal(&spatial_model(
                op,
                &dims,
                &dims,
                &int_attr("blocksize", i64::MAX)
            )),
            Some(OnnxError::Limit)
        );
        for input in [vec![], vec![4], vec![1, 4, 2], vec![1, 4, 1, 2, 2]] {
            assert_eq!(
                refusal(&spatial_model(op, &input, &dims, &int_attr("blocksize", 2))),
                Some(OnnxError::Unsupported)
            );
        }
        assert_eq!(
            refusal(&spatial_model(
                op,
                &dims,
                &dims,
                &[int_attr("blocksize", 2), int_attr("unknown", 1)].concat()
            )),
            Some(OnnxError::Unsupported)
        );
        assert_eq!(
            refusal(&spatial_model(
                op,
                &dims,
                &dims,
                &attribute("blocksize", 3, &bytes(4, b"2"))
            )),
            Some(OnnxError::Graph)
        );
    }
    for input in [vec![1, 3, 2, 2], vec![1, 5, 2, 2]] {
        assert_eq!(
            refusal(&spatial_model(
                "DepthToSpace",
                &input,
                &[1, 1, 4, 4],
                &int_attr("blocksize", 2)
            )),
            Some(OnnxError::Graph)
        );
    }
    for input in [vec![1, 3, 3, 4], vec![1, 3, 4, 3]] {
        assert_eq!(
            refusal(&spatial_model(
                "SpaceToDepth",
                &input,
                &[1, 12, 2, 2],
                &int_attr("blocksize", 2)
            )),
            Some(OnnxError::Graph)
        );
    }
    for value in ["", "crd", "NHWC", "DCR "] {
        assert_eq!(
            refusal(&spatial_model(
                "DepthToSpace",
                &[1, 4, 2, 2],
                &[1, 1, 4, 4],
                &[int_attr("blocksize", 2), mode(value)].concat()
            )),
            Some(OnnxError::Unsupported)
        );
    }
    // SpaceToDepth gains a mode only in a newer schema. Do not import it as 13.
    for value in ["DCR", "CRD"] {
        assert_eq!(
            refusal(&spatial_model(
                "SpaceToDepth",
                &[1, 1, 4, 4],
                &[1, 4, 2, 2],
                &[int_attr("blocksize", 2), mode(value)].concat()
            )),
            Some(OnnxError::Unsupported)
        );
    }
    assert_eq!(
        refusal(&spatial_model(
            "DepthToSpace",
            &[1, 4, 2, 2],
            &[1, 4, 2, 2],
            &int_attr("blocksize", 2)
        )),
        Some(OnnxError::Graph)
    );
    Ok(())
}

#[test]
fn spatial_arity_duplicate_attributes_and_non_f32_data_refuse() -> Test {
    for inputs in [vec![], vec!["input", "input"]] {
        let source = model(
            &[
                node(
                    "DepthToSpace",
                    &inputs,
                    &["output"],
                    &int_attr("blocksize", 2),
                ),
                bytes(11, &info("input", &[1, 4, 1, 1], 1)),
                bytes(12, &info("output", &[1, 1, 2, 2], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Graph));
    }
    let source = spatial_model(
        "DepthToSpace",
        &[1, 4, 1, 1],
        &[1, 1, 2, 2],
        &[int_attr("blocksize", 2), int_attr("blocksize", 2)].concat(),
    );
    assert_eq!(refusal(&source), Some(OnnxError::Malformed));
    let source = model(
        &[
            node(
                "DepthToSpace",
                &["input"],
                &["output"],
                &int_attr("blocksize", 2),
            ),
            int_weight("input", &[1, 4, 1, 1], &[1, 2, 3, 4]),
            bytes(12, &info("output", &[1, 1, 2, 2], 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&source), Some(OnnxError::Unsupported));
    Ok(())
}

#[test]
fn spatial_helpers_cannot_capture_source_names_or_missing_values() -> Test {
    let reserved = "onnx-node-0000-spatial-reshape";
    let source = model(
        &[
            node(
                "DepthToSpace",
                &[reserved],
                &["output"],
                &int_attr("blocksize", 2),
            ),
            bytes(11, &info(reserved, &[1, 4, 1, 1], 1)),
            bytes(12, &info("output", &[1, 1, 2, 2], 1)),
        ]
        .concat(),
    );
    let actual = roundtrip(
        &source,
        &[(reserved, data(&[1, 4, 1, 1], &[1., 2., 3., 4.])?)],
    )?;
    assert_eq!(actual["output"], [1., 2., 3., 4.]);
    let source = model(
        &[
            node(
                "DepthToSpace",
                &["input"],
                &["shuffled"],
                &int_attr("blocksize", 2),
            ),
            node("Identity", &[reserved], &["output"], &[]),
            bytes(11, &info("input", &[1, 4, 1, 1], 1)),
            bytes(12, &info("output", &[1, 1, 2, 2], 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&source), Some(OnnxError::Graph));
    Ok(())
}

#[test]
fn spatial_expansion_obeys_exact_import_allowances_and_cancellation() -> Test {
    let source = spatial_model(
        "DepthToSpace",
        &[1, 4, 2, 3],
        &[1, 1, 4, 6],
        &int_attr("blocksize", 2),
    );
    let mut exact = OnnxLimits {
        source_bytes: source.len(),
        nodes: 3,
        tensors: 4,
        parameter_bytes: 0,
        tensor_bytes: 96,
        ..OnnxLimits::default()
    };
    let imported = import_onnx(
        &source,
        ContentDigest::sha256(&source),
        GENERATION,
        exact,
        &|| false,
    )?;
    exact.work_units = imported.work_units();
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
        OnnxLimits {
            source_bytes: source.len() - 1,
            ..exact
        },
        OnnxLimits { nodes: 2, ..exact },
        OnnxLimits {
            tensors: 3,
            ..exact
        },
        OnnxLimits {
            tensor_bytes: 95,
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
    assert_eq!(
        import_onnx(
            &source,
            ContentDigest::sha256(b"wrong"),
            GENERATION,
            exact,
            &|| false
        )
        .err(),
        Some(OnnxError::Digest)
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
        let count = Cell::new(0);
        assert_eq!(
            import_onnx(
                &source,
                ContentDigest::sha256(&source),
                GENERATION,
                exact,
                &|| {
                    count.set(count.get() + 1);
                    count.get() >= stop
                }
            )
            .err(),
            Some(OnnxError::Cancelled)
        );
    }
    Ok(())
}

#[test]
fn spatial_runtime_budget_generation_and_cancel_fail_without_outputs() -> Test {
    let source = spatial_model(
        "SpaceToDepth",
        &[1, 2, 4, 6],
        &[1, 8, 2, 3],
        &int_attr("blocksize", 2),
    );
    let imported = import(&source)?;
    let input = data(&[1, 2, 4, 6], &[1.; 48])?;
    let optimized = optimized_executor::OptimizedGraph::prepare(
        imported.graph(),
        &BTreeMap::new(),
        &ScalarExecCx::new(),
    )?;
    let bindings = [("input", input)];
    for budget in [ExecBudget::new(0, usize::MAX), ExecBudget::new(u64::MAX, 0)] {
        assert!(
            ScalarExecutor::run(imported.graph(), &bindings, budget, &ScalarExecCx::new()).is_err()
        );
        assert!(
            optimized
                .run(&bindings, budget, &ScalarExecCx::new())
                .is_err()
        );
    }
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    assert!(matches!(
        ScalarExecutor::run(imported.graph(), &bindings, ExecBudget::unlimited(), &cx),
        Err(ExecError::CancellationRequested { .. })
    ));
    assert!(cx.is_drain_completed());
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    assert!(matches!(
        optimized.run(&bindings, ExecBudget::unlimited(), &cx),
        Err(ExecError::CancellationRequested { .. })
    ));
    assert!(cx.is_drain_completed());
    let wrong = [(
        "input",
        Tensor::from_values(
            Shape::new(vec![1, 2, 4, 6])?,
            &[1.; 48],
            Generation(GENERATION.0 + 1),
        )?,
    )];
    assert!(
        ScalarExecutor::run(
            imported.graph(),
            &wrong,
            ExecBudget::unlimited(),
            &ScalarExecCx::new()
        )
        .is_err()
    );
    assert!(
        optimized
            .run(&wrong, ExecBudget::unlimited(), &ScalarExecCx::new())
            .is_err()
    );
    Ok(())
}
