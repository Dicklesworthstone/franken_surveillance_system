#![forbid(unsafe_code)]
//! Ceil-mode averages through real import, native execution and artifact reload.
//! Expected values come from original input coordinates, never generated weights.

use super::*;

fn ceil_attrs(
    kernel: [usize; 2],
    strides: [usize; 2],
    pads: [usize; 4],
    include_pad: bool,
) -> Vec<u8> {
    [
        pool_attrs(kernel, strides, pads, include_pad),
        int_attr("ceil_mode", 1),
    ]
    .concat()
}

fn data(dimensions: &[usize], values: &[f32]) -> Test<Tensor> {
    Ok(Tensor::from_values(
        Shape::new(dimensions.to_vec())?,
        values,
        GENERATION,
    )?)
}

fn weight_bits(artifacts: &OnnxArtifacts<'_>) -> Test<BTreeMap<String, Vec<u32>>> {
    reloaded(artifacts)?
        .into_iter()
        .map(|(name, tensor)| Ok((name, bits(&tensor.to_vec::<f32>()?))))
        .collect()
}

// Find the smallest complete sliding extent by enumeration, rather than using
// the importer's quotient formula. Right-padding-only anchors are discarded.
fn starts(input: usize, kernel: usize, stride: usize, before: usize, after: usize) -> Vec<isize> {
    let padded = input + before + after;
    let Some(extent) = (padded..padded + stride)
        .find(|&extent| extent >= kernel && (extent - kernel).is_multiple_of(stride))
    else {
        return Vec::new();
    };
    (0..extent)
        .step_by(stride)
        .filter(|&start| start + kernel <= extent && start < input + before)
        .map(|start| start as isize - before as isize)
        .collect()
}

fn oracle(
    values: &[f32],
    input: [usize; 4],
    kernel: [usize; 2],
    strides: [usize; 2],
    pads: [usize; 4],
) -> Test<([usize; 4], Vec<f32>)> {
    let ys = starts(input[2], kernel[0], strides[0], pads[0], pads[2]);
    let xs = starts(input[3], kernel[1], strides[1], pads[1], pads[3]);
    let output = [input[0], input[1], ys.len(), xs.len()];
    let mut result = Vec::new();
    for plane in 0..input[0] * input[1] {
        for &y in &ys {
            for &x in &xs {
                let mut sum = 0_f32;
                let mut count = 0;
                for row in 0..input[2] {
                    for col in 0..input[3] {
                        if (row as isize) >= y
                            && (row as isize) < y + kernel[0] as isize
                            && (col as isize) >= x
                            && (col as isize) < x + kernel[1] as isize
                        {
                            sum += values[(plane * input[2] + row) * input[3] + col];
                            count += 1;
                        }
                    }
                }
                if count == 0 {
                    return Err("ceil oracle window is empty".into());
                }
                result.push(sum / count as f32);
            }
        }
    }
    Ok((output, result))
}

#[test]
fn ceil_averages_match_hand_computed_windows_and_do_not_shift_the_input() -> Test {
    for (input, kernel, strides, pads, values, output, expected) in [
        (
            [1, 1, 4, 4],
            [3, 3],
            [2, 2],
            [0; 4],
            (1..=16).map(|n| n as f32).collect::<Vec<_>>(),
            [1, 1, 2, 2],
            vec![6., 7.5, 12., 13.5],
        ),
        (
            [1, 1, 1, 5],
            [1, 4],
            [1, 3],
            [0; 4],
            vec![1., 2., 3., 4., 5.],
            [1, 1, 1, 2],
            // Two extra tail positions must not move the first window.
            vec![2.5, 4.5],
        ),
        (
            [1, 1, 2, 2],
            [3, 3],
            [2, 2],
            [0; 4],
            vec![-4., -3., -2., -1.],
            [1, 1, 1, 1],
            vec![-2.5],
        ),
        (
            [1, 1, 1, 1],
            [7, 7],
            [8, 8],
            [0; 4],
            vec![9.],
            [1, 1, 1, 1],
            vec![9.],
        ),
        (
            [1, 1, 2, 2],
            [1, 1],
            [2, 2],
            [0; 4],
            vec![1., 2., 3., 4.],
            [1, 1, 1, 1],
            vec![1.],
        ),
        (
            [1, 1, 2, 2],
            [2, 2],
            [2, 2],
            [0, 0, 1, 1],
            vec![1., 2., 3., 4.],
            [1, 1, 1, 1],
            vec![2.5],
        ),
        (
            [1, 1, 2, 4],
            [2, 2],
            [2, 2],
            [0, 1, 0, 0],
            (1..=8).map(|n| n as f32).collect(),
            [1, 1, 1, 3],
            vec![3., 4.5, 6.],
        ),
    ] {
        let source = pool_model(
            "AveragePool",
            &input,
            &output,
            &ceil_attrs(kernel, strides, pads, false),
        );
        let actual = roundtrip(&source, &[("input", data(&input, &values)?)])?;
        assert_eq!(bits(&actual["output"]), bits(&expected));
    }
    Ok(())
}

#[test]
fn ceil_averages_match_coordinates_across_batches_channels_and_asymmetric_pads() -> Test {
    let mut executed = 0;
    let mut short_inputs = 0;
    for input in [[1, 1, 1, 2], [2, 3, 3, 4], [1, 2, 5, 6]] {
        let values = (0..input.iter().product::<usize>())
            .map(|n| (n % 31) as f32 * 0.25 - 4.)
            .collect::<Vec<_>>();
        let tensor = data(&input, &values)?;
        for kernel in [[1, 1], [2, 3], [5, 7]] {
            for strides in [[1, 1], [2, 2], [7, 8]] {
                for pads in [
                    [0; 4],
                    [kernel[0] - 1, 0, 0, kernel[1] - 1],
                    [0, kernel[1] - 1, kernel[0] - 1, 0],
                    [kernel[0] - 1, kernel[1] - 1, kernel[0] - 1, kernel[1] - 1],
                ] {
                    let (output, expected) = oracle(&values, input, kernel, strides, pads)?;
                    if output[2] == 0 || output[3] == 0 {
                        continue;
                    }
                    let source = pool_model(
                        "AveragePool",
                        &input,
                        &output,
                        &ceil_attrs(kernel, strides, pads, false),
                    );
                    let actual = roundtrip(&source, &[("input", tensor.clone())])?;
                    assert_eq!(
                        bits(&actual["output"]),
                        bits(&expected),
                        "input={input:?} kernel={kernel:?} strides={strides:?} pads={pads:?}",
                    );
                    executed += 1;
                    if input[2] + pads[0] + pads[2] < kernel[0]
                        || input[3] + pads[1] + pads[3] < kernel[1]
                    {
                        short_inputs += 1;
                    }
                }
            }
        }
    }
    assert!(executed > 80);
    assert!(short_inputs > 0);
    Ok(())
}

#[test]
fn ceil_one_dimensional_averages_restore_ncw_shape_and_keep_f32_sum_then_divide() -> Test {
    let input = [2, 2, 5];
    let values = (1..=20).map(|n| n as f32).collect::<Vec<_>>();
    let attrs = [
        ints_attr("kernel_shape", &[4]),
        ints_attr("strides", &[3]),
        int_attr("ceil_mode", 1),
    ]
    .concat();
    let source = pool_model("AveragePool", &input, &[2, 2, 2], &attrs);
    let imported = import(&source)?;
    assert_eq!(imported.graph().nodes().len(), 4);
    assert_eq!(imported.parameters().len(), 2);
    let actual = roundtrip(&source, &[("input", data(&input, &values)?)])?;
    assert_eq!(
        bits(&actual["output"]),
        bits(&[2.5, 4.5, 7.5, 9.5, 12.5, 14.5, 17.5, 19.5])
    );

    let tiny = f32::from_bits(1);
    for (values, expected) in [
        (vec![tiny, tiny], tiny),
        (vec![-tiny, -tiny], -tiny),
        (vec![f32::MAX, f32::MAX], f32::INFINITY),
        (vec![-0., -0.], 0.),
    ] {
        let source = pool_model(
            "AveragePool",
            &[1, 1, 1, 2],
            &[1, 1, 1, 1],
            &ceil_attrs([1, 3], [1, 2], [0; 4], false),
        );
        let actual = roundtrip(&source, &[("input", data(&[1, 1, 1, 2], &values)?)])?;
        assert_eq!(bits(&actual["output"]), bits(&[expected]));
    }
    Ok(())
}

#[test]
fn ceil_include_padding_accepts_complete_explicit_windows_and_refuses_ambiguous_tails() -> Test {
    let input = [1, 1, 4, 4];
    let values = (1..=16).map(|n| n as f32).collect::<Vec<_>>();
    let source = pool_model(
        "AveragePool",
        &input,
        &[1, 1, 2, 2],
        &ceil_attrs([3, 3], [2, 2], [0, 0, 1, 1], true),
    );
    let actual = roundtrip(&source, &[("input", data(&input, &values)?)])?;
    assert_eq!(bits(&actual["output"]), bits(&[6., 5., 8., 6.]));

    // The last candidate anchor starts wholly in right/bottom padding and is
    // removed before deciding whether any surviving window needs extra padding.
    let source = pool_model(
        "AveragePool",
        &[1, 1, 2, 2],
        &[1, 1, 1, 1],
        &ceil_attrs([3, 3], [3, 3], [1; 4], true),
    );
    let actual = roundtrip(
        &source,
        &[("input", data(&[1, 1, 2, 2], &[1., 2., 3., 4.])?)],
    )?;
    assert_eq!(bits(&actual["output"]), bits(&[10_f32 / 9.]));

    for (input, output, kernel, strides, pads) in [
        ([1, 1, 4, 4], [1, 1, 2, 2], [3, 3], [2, 2], [0; 4]),
        ([1, 1, 2, 4], [1, 1, 1, 3], [2, 2], [2, 2], [0, 1, 0, 0]),
        ([1, 1, 1, 2], [1, 1, 1, 1], [1, 3], [1, 2], [0; 4]),
    ] {
        assert_eq!(
            refusal(&pool_model(
                "AveragePool",
                &input,
                &output,
                &ceil_attrs(kernel, strides, pads, true)
            )),
            Some(OnnxError::Unsupported)
        );
    }
    Ok(())
}

#[test]
fn floor_graph_and_weight_bits_remain_identical_when_ceil_does_not_change_windows() -> Test {
    for include_pad in [false, true] {
        let attrs = pool_attrs([3, 3], [2, 2], [0, 0, 1, 1], include_pad);
        let mut baseline = None;
        for ceil in [None, Some(0), Some(1)] {
            let attrs = match ceil {
                Some(value) => [attrs.clone(), int_attr("ceil_mode", value)].concat(),
                None => attrs.clone(),
            };
            let source = pool_model("AveragePool", &[1, 2, 4, 4], &[1, 2, 2, 2], &attrs);
            let imported = import(&source)?;
            let artifacts = export(&imported)?;
            // Safetensors metadata deliberately binds the differing ONNX source
            // bytes. Compare the graph (including parameter shapes) and decoded
            // payload bits while retaining that distinct provenance.
            let graph_and_weights = (artifacts.graph_bytes().to_vec(), weight_bits(&artifacts)?);
            if let Some(expected) = &baseline {
                assert_eq!(&graph_and_weights, expected);
            } else {
                baseline = Some(graph_and_weights);
            }
        }
    }
    let attrs = [
        ints_attr("kernel_shape", &[3, 3]),
        ints_attr("strides", &[2, 2]),
        int_attr("ceil_mode", 1),
    ]
    .concat();
    let source = pool_model("AveragePool", &[1, 1, 4, 4], &[1, 1, 2, 2], &attrs);
    let notset = pool_model(
        "AveragePool",
        &[1, 1, 4, 4],
        &[1, 1, 2, 2],
        &[attrs, text_attr("auto_pad", "NOTSET")].concat(),
    );
    let imported = import(&source)?;
    let notset = import(&notset)?;
    assert_eq!(
        export(&imported)?.graph_bytes(),
        export(&notset)?.graph_bytes()
    );
    assert_eq!(
        weight_bits(&export(&imported)?)?,
        weight_bits(&export(&notset)?)?
    );
    Ok(())
}

#[test]
fn ceil_profile_refuses_automatic_padding_empty_windows_and_wrong_output_shapes() {
    for mode in ["VALID", "SAME_UPPER", "SAME_LOWER"] {
        let attrs = [
            ints_attr("kernel_shape", &[3, 3]),
            ints_attr("strides", &[2, 2]),
            int_attr("ceil_mode", 1),
            text_attr("auto_pad", mode),
        ]
        .concat();
        assert_eq!(
            refusal(&pool_model(
                "AveragePool",
                &[1, 1, 4, 4],
                &[1, 1, 2, 2],
                &attrs
            )),
            Some(OnnxError::Unsupported)
        );
    }
    for (input, output, kernel, strides) in [
        ([1, 1, 2, 2], [1, 1, 1, 1], [4, 4], [2, 2]),
        ([1, 1, 4, 4], [1, 1, 1, 1], [3, 3], [2, 2]),
        ([1, 1, 2, 2], [1, 1, 2, 2], [1, 1], [2, 2]),
    ] {
        assert_eq!(
            refusal(&pool_model(
                "AveragePool",
                &input,
                &output,
                &ceil_attrs(kernel, strides, [0; 4], false)
            )),
            Some(OnnxError::Graph)
        );
    }
}

#[test]
fn ceil_partial_window_divisors_obey_import_limits_and_cancellation() -> Test {
    let source = pool_model(
        "AveragePool",
        &[1, 2, 4, 4],
        &[1, 2, 2, 2],
        &ceil_attrs([3, 3], [2, 2], [0; 4], false),
    );
    let imported = import(&source)?;
    let exact = OnnxLimits {
        source_bytes: source.len(),
        nodes: 2,
        tensors: 5,
        parameter_bytes: 2 * 3 * 3 * 4 + 2 * 2 * 4,
        tensor_bytes: 2 * 4 * 4 * 4,
        work_units: imported.work_units(),
    };
    import_onnx(
        &source,
        ContentDigest::sha256(&source),
        GENERATION,
        exact,
        &|| false,
    )?;
    for limits in [
        OnnxLimits { nodes: 1, ..exact },
        OnnxLimits {
            tensors: 4,
            ..exact
        },
        OnnxLimits {
            parameter_bytes: exact.parameter_bytes - 1,
            ..exact
        },
        OnnxLimits {
            tensor_bytes: exact.tensor_bytes - 1,
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

    // A short input and huge stride must not permit an enormous synthetic kernel.
    let oversized = pool_model(
        "AveragePool",
        &[1, 1, 1, 1],
        &[1, 1, 1, 1],
        &ceil_attrs([16_777_217, 1], [16_777_218, 1], [0; 4], false),
    );
    assert_eq!(refusal(&oversized), Some(OnnxError::Limit));

    let checkpoints = Cell::new(0_usize);
    import_onnx(
        &source,
        ContentDigest::sha256(&source),
        GENERATION,
        exact,
        &|| {
            checkpoints.set(checkpoints.get() + 1);
            false
        },
    )?;
    for cancel_at in 1..=checkpoints.get() {
        let calls = Cell::new(0_usize);
        assert_eq!(
            import_onnx(
                &source,
                ContentDigest::sha256(&source),
                GENERATION,
                exact,
                &|| {
                    calls.set(calls.get() + 1);
                    calls.get() == cancel_at
                }
            )
            .err(),
            Some(OnnxError::Cancelled)
        );
    }
    Ok(())
}
