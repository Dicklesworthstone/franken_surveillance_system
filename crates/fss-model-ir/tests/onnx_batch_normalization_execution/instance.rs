#![forbid(unsafe_code)]
//! InstanceNormalization exercises the unchanged scalar/optimized executors and
//! real graph/weight reload through the shared normalization test host. The
//! independent oracle derives population variance from pairwise differences;
//! it does not call the production normalization or graph-lowering helpers.

use super::*;

fn instance_model(dims: &[usize], scale: &[f32], bias: &[f32], attrs: &[u8]) -> Vec<u8> {
    model(
        &[
            node(
                "InstanceNormalization",
                &["input", "scale", "bias"],
                &["output"],
                attrs,
            ),
            weight("scale", &[scale.len()], scale),
            weight("bias", &[bias.len()], bias),
            bytes(11, &info("input", dims)),
            bytes(12, &info("output", dims)),
        ]
        .concat(),
    )
}

fn oracle(values: &[f32], dims: &[usize], scale: &[f32], bias: &[f32], epsilon: f32) -> Vec<f32> {
    let width: usize = dims[2..].iter().product();
    let mut expected = Vec::new();
    for (row_index, row) in values.chunks(width).enumerate() {
        let channel = row_index % dims[1];
        let anchor = f64::from(row[0]);
        let mean = anchor + row.iter().map(|&x| f64::from(x) - anchor).sum::<f64>() / width as f64;
        // sum(i<j, (xi-xj)^2) / n^2 is population variance, independently
        // derived without the native kernel's sum of squared mean deviations.
        let mut pairs = 0.0_f64;
        for (index, &x) in row.iter().enumerate() {
            for &y in &row[index + 1..] {
                let difference = f64::from(x) - f64::from(y);
                pairs += difference * difference;
            }
        }
        let variance = pairs / (width * width) as f64;
        let denominator = (variance + f64::from(epsilon)).sqrt();
        for &x in row {
            let normalized = ((f64::from(x) - mean) / denominator) as f32;
            let scaled = normalized * scale[channel];
            expected.push(scaled + bias[channel]);
        }
    }
    expected
}

fn close(actual: &[f32], expected: &[f32]) {
    assert_eq!(actual.len(), expected.len());
    for (index, (&actual, &expected)) in actual.iter().zip(expected).enumerate() {
        assert!(actual.is_finite());
        assert!(
            (actual - expected).abs() <= 5e-6 * (1.0 + expected.abs()),
            "index={index}, actual={actual:?}, expected={expected:?}"
        );
    }
}

#[test]
fn instance_literal_rows_are_independent_by_batch_and_channel() -> Test {
    let dims = [2, 2, 1, 2];
    let values = [-1.0_f32, 1., 10., 12., 3., 5., 4., 4.];
    let source = instance_model(&dims, &[2., -3.], &[0.25, 1.], &float_attr("epsilon", 3.));
    let imported = import(&source)?;
    assert_eq!(imported.graph().node_count(), 5);
    assert_eq!(imported.runtime_inputs(), ["input"]);
    assert_eq!(imported.parameters().len(), 2);
    assert_eq!(
        imported.graph().nodes().iter().map(|node| node.op()).collect::<Vec<_>>(),
        [OpCode::LayerNorm, OpCode::Reshape, OpCode::Reshape, OpCode::Mul, OpCode::Add]
    );
    let result = roundtrip(&source, &[("input", value_tensor(&dims, &values)?)])?;
    assert_eq!(bits(&output(&result, "output")?), bits(&[-0.75, 1.25, 2.5, -0.5, -0.75, 1.25, 1., 1.]));
    Ok(())
}

#[test]
fn instance_all_spatial_ranks_match_independent_population_statistics() -> Test {
    let scale = [1.25_f32, -0.75, 0.0];
    let bias = [0.25_f32, -1., 2.];
    for rank in 3..=8 {
        let mut dims = vec![2, 3];
        dims.extend((2..rank).map(|axis| if axis % 2 == 0 { 2 } else { 3 }));
        let values = (0..dims.iter().product::<usize>())
            .map(|index| ((index * 17 % 101) as f32 - 50.) * 0.125)
            .collect::<Vec<_>>();
        for epsilon in [1e-5_f32, 0.25, f32::MIN_POSITIVE, f32::MAX] {
            let source = instance_model(&dims, &scale, &bias, &float_attr("epsilon", epsilon));
            let actual = roundtrip(&source, &[("input", value_tensor(&dims, &values)?)])?;
            close(&output(&actual, "output")?, &oracle(&values, &dims, &scale, &bias, epsilon));
        }
    }
    // A single spatial sample is still a valid row; its population variance is
    // zero. Batch and channel count must not accidentally become reduction axes.
    let dims = [2, 3, 1, 1, 1];
    let values = [f32::MAX, f32::MIN, -0.0, 5., -2., f32::from_bits(1)];
    let source = instance_model(&dims, &scale, &bias, &[]);
    assert_eq!(
        bits(&output(&roundtrip(&source, &[("input", value_tensor(&dims, &values)?)])?, "output")?),
        bits(&[0.25, -1., 2., 0.25, -1., 2.])
    );
    Ok(())
}

#[test]
fn instance_default_and_extreme_epsilons_preserve_exact_source_float_bits() -> Test {
    let omitted = instance_model(&[1, 1, 3], &[1.], &[0.], &[]);
    let explicit = instance_model(&[1, 1, 3], &[1.], &[0.], &float_attr("epsilon", 1e-5));
    assert_eq!(
        encode_canonical_model_ir(import(&omitted)?.graph())?,
        encode_canonical_model_ir(import(&explicit)?.graph())?
    );
    assert_ne!(f64::from(1e-5_f32).to_bits(), 1e-5_f64.to_bits());
    for epsilon in [f32::from_bits(1), f32::MIN_POSITIVE, 1e-5_f32, 0.123_456_79, f32::MAX] {
        let source = instance_model(&[1, 1, 3], &[1.], &[0.], &float_attr("epsilon", epsilon));
        let imported = import(&source)?;
        assert_eq!(
            imported.graph().nodes()[0].get_attr("epsilon"),
            Some(&fss_model_ir::AttrValue::Float(f64::from(epsilon)))
        );
        let values = [0.000_001_f32, -0.000_002, 0.000_003];
        let actual = roundtrip(&source, &[("input", value_tensor(&[1, 1, 3], &values)?)])?;
        close(&output(&actual, "output")?, &oracle(&values, &[1, 1, 3], &[1.], &[0.], epsilon));
    }
    Ok(())
}

#[test]
fn instance_runtime_and_constant_channel_vectors_keep_their_source_bindings() -> Test {
    let dims = [2, 3, 4];
    let scale = [1.5_f32, -2., -0.0];
    let bias = [0.25_f32, 0.0, -1.];
    let values = (0..24).map(|index| (index as f32 - 11.) * 0.25).collect::<Vec<_>>();
    for constant_nodes in [false, true] {
        let controls = if constant_nodes {
            [constant("scale", &scale), constant("bias", &bias)].concat()
        } else {
            [bytes(11, &info("scale", &[3])), bytes(11, &info("bias", &[3]))].concat()
        };
        let source = model(&[
            controls,
            node("InstanceNormalization", &["input", "scale", "bias"], &["output"], &[]),
            node("Identity", &["scale"], &["scale_copy"], &[]),
            bytes(11, &info("input", &dims)),
            bytes(12, &info("output", &dims)),
            bytes(12, &info("scale_copy", &[3])),
        ].concat());
        let imported = import(&source)?;
        assert_eq!(imported.parameters().len(), if constant_nodes { 2 } else { 0 });
        let mut inputs = vec![("input", value_tensor(&dims, &values)?)];
        if constant_nodes {
            assert_eq!(bits(&imported.parameters()["scale"].to_vec::<f32>()?), bits(&scale));
        } else {
            inputs.push(("scale", value_tensor(&[3], &scale)?));
            inputs.push(("bias", value_tensor(&[3], &bias)?));
        }
        let actual = roundtrip(&source, &inputs)?;
        close(&output(&actual, "output")?, &oracle(&values, &dims, &scale, &bias, 1e-5));
        assert_eq!(bits(&output(&actual, "scale_copy")?), bits(&scale));
    }
    // A prior runtime operator can produce a channel vector; it is data, not a
    // compile-time control silently frozen by the importer.
    let source = model(&[
        node("Mul", &["channel_scale", "gain"], &["scale"], &[]),
        node("InstanceNormalization", &["input", "scale", "bias"], &["output"], &[]),
        weight("gain", &[], &[2.]),
        weight("bias", &[3], &bias),
        bytes(11, &info("input", &dims)),
        bytes(11, &info("channel_scale", &[3])),
        bytes(12, &info("output", &dims)),
    ].concat());
    let actual = roundtrip(&source, &[
        ("input", value_tensor(&dims, &values)?),
        ("channel_scale", value_tensor(&[3], &scale)?),
    ])?;
    close(&output(&actual, "output")?, &oracle(&values, &dims, &scale.map(|x| x * 2.), &bias, 1e-5));
    Ok(())
}

#[test]
fn grouped_feature_normalization_composes_with_static_shape_programs() -> Test {
    let dims = [2, 4, 2, 3];
    let values = (0..48).map(|i| ((i * 11 % 31) as f32 - 15.) * 0.125).collect::<Vec<_>>();
    let channel_scale = [1.5_f32, -0.25, 2., 0.5];
    let channel_bias = [0.25_f32, 1., -0.5, 2.];
    for groups in [1_usize, 2, 4] {
        // The usual static grouped-normalization decomposition: gather each
        // channel group into one instance row, normalize, restore, then affine.
        let source = model(&[
            node("Shape", &["input"], &["original_shape"], &[]),
            node("Reshape", &["input", "group_shape"], &["grouped"], &[]),
            node("InstanceNormalization", &["grouped", "ones", "zeros"], &["normalized"], &float_attr("epsilon", 0.25)),
            node("Reshape", &["normalized", "original_shape"], &["restored"], &[]),
            node("Mul", &["restored", "channel_scale"], &["scaled"], &[]),
            node("Add", &["scaled", "channel_bias"], &["output"], &[]),
            int_weight("group_shape", &[0, groups as i64, -1]),
            weight("ones", &[groups], &vec![1.; groups]),
            weight("zeros", &[groups], &vec![0.; groups]),
            weight("channel_scale", &[1, 4, 1, 1], &channel_scale),
            weight("channel_bias", &[1, 4, 1, 1], &channel_bias),
            bytes(11, &info("input", &dims)),
            bytes(12, &info("output", &dims)),
        ].concat());
        let mut expected = oracle(&values, &[2, groups, 24 / groups], &vec![1.; groups], &vec![0.; groups], 0.25);
        for (index, value) in expected.iter_mut().enumerate() {
            let channel = (index / 6) % 4;
            let scaled = *value * channel_scale[channel];
            *value = scaled + channel_bias[channel];
        }
        let imported = import(&source)?;
        assert_eq!(imported.runtime_inputs(), ["input"]);
        assert!(!imported.parameters().contains_key("group_shape"));
        assert!(!imported.parameters().contains_key("original_shape"));
        close(&output(&roundtrip(&source, &[("input", value_tensor(&dims, &values)?)])?, "output")?, &expected);
    }
    Ok(())
}

fn bilinear_double(values: &[f32], channels: usize, height: usize, width: usize) -> Vec<f32> {
    let mut result = Vec::new();
    for channel in 0..channels {
        for y in 0..height * 2 {
            let sy = ((y as f64 + 0.5) / 2.0 - 0.5).clamp(0.0, (height - 1) as f64);
            let y0 = sy.floor() as usize;
            let y1 = (y0 + 1).min(height - 1);
            let dy = sy - y0 as f64;
            for x in 0..width * 2 {
                let sx = ((x as f64 + 0.5) / 2.0 - 0.5).clamp(0.0, (width - 1) as f64);
                let x0 = sx.floor() as usize;
                let x1 = (x0 + 1).min(width - 1);
                let dx = sx - x0 as f64;
                let get = |y, x| f64::from(values[(channel * height + y) * width + x]);
                result.push((get(y0, x0) * (1. - dx) * (1. - dy)
                    + get(y0, x1) * dx * (1. - dy)
                    + get(y1, x0) * (1. - dx) * dy
                    + get(y1, x1) * dx * dy) as f32);
            }
        }
    }
    result
}

#[test]
fn convolution_instance_normalization_and_bilinear_features_feed_a_dense_head() -> Test {
    let dims = [1, 3, 2, 3];
    let values = (0..18).map(|i| ((i * 7 % 17) as f32 - 8.) * 0.25).collect::<Vec<_>>();
    let kernel = [1.0_f32, 0.5, -0.25, -0.5, 0.25, 1.];
    let scale = [1.5_f32, -0.75];
    let bias = [0.25_f32, 0.5];
    let source = model(&[
        node("Conv", &["input", "kernel"], &["feature"], &[]),
        node("InstanceNormalization", &["feature", "scale", "bias"], &["normalized"], &float_attr("epsilon", 0.25)),
        node("Resize", &["normalized", "", "", "size"], &["resized"], &attribute("mode", 3, &bytes(4, b"linear"))),
        node("Relu", &["resized"], &["activated"], &[]),
        node("GlobalAveragePool", &["activated"], &["pooled"], &[]),
        node("Flatten", &["pooled"], &["flat"], &[]),
        node("Gemm", &["flat", "dense", "dense_bias"], &["output"], &[]),
        weight("kernel", &[2, 3, 1, 1], &kernel),
        weight("scale", &[2], &scale),
        weight("bias", &[2], &bias),
        weight("dense", &[2, 3], &[1., -0.5, 0.25, 0.5, 1.5, -1.]),
        weight("dense_bias", &[3], &[0.25, -0.25, 1.]),
        int_weight("size", &[1, 2, 4, 6]),
        bytes(11, &info("input", &dims)),
        bytes(12, &info("normalized", &[1, 2, 2, 3])),
        bytes(12, &info("output", &[1, 3])),
    ].concat());
    let mut conv = Vec::new();
    for out_channel in 0..2 {
        for position in 0..6 {
            conv.push((0..3).map(|channel| f64::from(values[channel * 6 + position])
                * f64::from(kernel[out_channel * 3 + channel])).sum::<f64>() as f32);
        }
    }
    let normalized = oracle(&conv, &[1, 2, 2, 3], &scale, &bias, 0.25);
    let resized = bilinear_double(&normalized, 2, 2, 3);
    let pooled = resized.chunks(24).map(|row| row.iter().map(|&x| f64::from(x.max(0.0))).sum::<f64>() / 24.0).collect::<Vec<_>>();
    let expected = [
        (pooled[0] + 0.5 * pooled[1] + 0.25) as f32,
        (-0.5 * pooled[0] + 1.5 * pooled[1] - 0.25) as f32,
        (0.25 * pooled[0] - pooled[1] + 1.) as f32,
    ];
    let actual = roundtrip(&source, &[("input", value_tensor(&dims, &values)?)])?;
    close(&output(&actual, "normalized")?, &normalized);
    close(&output(&actual, "output")?, &expected);
    Ok(())
}

#[test]
fn instance_helper_count_and_parameter_storage_do_not_grow_with_spatial_area() -> Test {
    for dims in [[1, 64, 2, 2], [1, 64, 320, 320]] {
        let source = instance_model(&dims, &[1.; 64], &[0.; 64], &[]);
        let imported = import(&source)?;
        assert_eq!(imported.graph().node_count(), 5);
        assert_eq!(imported.parameters().len(), 2);
        let size = imported.parameters().values()
            .map(|tensor| tensor.shape().size_bytes(fss_tensor::DType::F32))
            .collect::<Result<Vec<_>, _>>()?.into_iter().sum::<usize>();
        assert_eq!(size, 512);
        assert_eq!(imported.graph().nodes()[0].get_attr("normalized_shape"),
            Some(&fss_model_ir::AttrValue::IntList(dims[2..].iter().map(|&n| n as i64).collect())));
    }
    Ok(())
}

#[test]
fn instance_bad_shapes_types_epsilons_and_unsupported_attributes_refuse() {
    for epsilon in [0.0_f32, -0.0, -1.] {
        refuse(&instance_model(&[1, 2, 3], &[1., 1.], &[0., 0.], &float_attr("epsilon", epsilon)), OnnxError::Unsupported);
    }
    for epsilon in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        refuse(&instance_model(&[1, 2, 3], &[1., 1.], &[0., 0.], &float_attr("epsilon", epsilon)), OnnxError::NonFinite);
    }
    for attrs in [int_attr("epsilon", 1), ints_attr("epsilon", &[1])] {
        refuse(&instance_model(&[1, 2, 3], &[1., 1.], &[0., 0.], &attrs), OnnxError::Graph);
    }
    for attrs in [float_attr("momentum", 0.9), int_attr("training_mode", 0), int_attr("axis", 1)] {
        refuse(&instance_model(&[1, 2, 3], &[1., 1.], &[0., 0.], &attrs), OnnxError::Unsupported);
    }
    for dims in [&[][..], &[3][..], &[2, 3][..]] {
        refuse(&instance_model(dims, &[1., 1., 1.], &[0., 0., 0.], &[]), OnnxError::Unsupported);
    }
    refuse(&instance_model(&[1; 9], &[1.], &[0.], &[]), OnnxError::Limit);
    for (shape, dtype) in [(vec![], 1), (vec![1, 2], 1), (vec![3], 1), (vec![2], 7)] {
        let values = if dtype == 1 {
            vec![0_u8; shape.iter().product::<usize>() * 4]
        } else {
            vec![0_u8; 16]
        };
        let source = model(&[
            node("InstanceNormalization", &["input", "scale", "bias"], &["output"], &[]),
            bytes(5, &tensor("scale", &shape, dtype, &values)),
            weight("bias", &[2], &[0., 0.]),
            bytes(11, &info("input", &[1, 2, 3])),
            bytes(12, &info("output", &[1, 2, 3])),
        ].concat());
        refuse(&source, OnnxError::Graph);
    }
    for inputs in [vec!["input", "scale"], vec!["input", "scale", "bias", "scale"], vec!["input", "missing", "bias"]] {
        let source = model(&[
            node("InstanceNormalization", &inputs, &["output"], &[]),
            weight("scale", &[2], &[1., 1.]), weight("bias", &[2], &[0., 0.]),
            bytes(11, &info("input", &[1, 2, 3])), bytes(12, &info("output", &[1, 2, 3])),
        ].concat());
        refuse(&source, OnnxError::Graph);
    }
    let wrong_output = model(&[
        node("InstanceNormalization", &["input", "scale", "bias"], &["output"], &[]),
        weight("scale", &[2], &[1., 1.]), weight("bias", &[2], &[0., 0.]),
        bytes(11, &info("input", &[1, 2, 3])), bytes(12, &info("output", &[1, 2, 2])),
    ].concat());
    refuse(&wrong_output, OnnxError::Graph);
}

#[test]
fn instance_complete_expansion_work_and_every_cancellation_checkpoint_are_bounded() -> Test {
    let source = instance_model(&[2, 3, 2, 3], &[1., -2., 0.5], &[0., 0.25, 1.], &[]);
    let imported = import(&source)?;
    let limits = OnnxLimits { nodes: 5, tensors: 8, parameter_bytes: 24, tensor_bytes: 144,
        work_units: imported.work_units(), ..OnnxLimits::default() };
    let exact = import_onnx(&source, ContentDigest::sha256(&source), GENERATION, limits, &|| false)?;
    assert_eq!(encode_canonical_model_ir(exact.graph())?, encode_canonical_model_ir(imported.graph())?);
    for limits in [
        OnnxLimits { nodes: 4, ..limits }, OnnxLimits { tensors: 7, ..limits },
        OnnxLimits { parameter_bytes: 23, ..limits }, OnnxLimits { tensor_bytes: 143, ..limits },
    ] {
        assert_eq!(import_onnx(&source, ContentDigest::sha256(&source), GENERATION, limits, &|| false).err(), Some(OnnxError::Limit));
    }
    assert_eq!(import_onnx(&source, ContentDigest::sha256(&source), GENERATION,
        OnnxLimits { work_units: limits.work_units - 1, ..limits }, &|| false).err(), Some(OnnxError::WorkBudget));
    assert_eq!(import_onnx(&source, ContentDigest::sha256(b"different"), GENERATION, limits, &|| false).err(), Some(OnnxError::Digest));
    let calls = Cell::new(0);
    import_onnx(&source, ContentDigest::sha256(&source), GENERATION, limits, &|| {
        calls.set(calls.get() + 1);
        false
    })?;
    let total = calls.get();
    for stop in 1..=total {
        calls.set(0);
        assert_eq!(import_onnx(&source, ContentDigest::sha256(&source), GENERATION, limits, &|| {
            calls.set(calls.get() + 1);
            calls.get() == stop
        }).err(), Some(OnnxError::Cancelled), "checkpoint {stop}/{total}");
    }
    Ok(())
}

#[test]
fn instance_helpers_cannot_capture_future_outputs_or_repair_forward_references() -> Test {
    for suffix in ["normalize", "scale", "bias", "affine"] {
        let collision = format!("onnx-node-0000-instancenorm-{suffix}");
        let make = |forward: bool| model(&[
            node("InstanceNormalization", &[if forward { &collision } else { "input" }, "scale", "bias"], &["output"], &float_attr("epsilon", 3.)),
            node("Identity", &["input"], &[&collision], &[]),
            weight("scale", &[2], &[2., -3.]), weight("bias", &[2], &[0.25, 1.]),
            bytes(11, &info("input", &[1, 2, 2])), bytes(12, &info("output", &[1, 2, 2])),
            bytes(12, &info(&collision, &[1, 2, 2])),
        ].concat());
        let source = make(false);
        let values = [-1., 1., 10., 12.];
        let imported = import(&source)?;
        assert!(imported.graph().nodes()[..5].iter().all(|node| !node.outputs().contains(&collision)));
        let actual = roundtrip(&source, &[("input", value_tensor(&[1, 2, 2], &values)?)])?;
        assert_eq!(bits(&output(&actual, &collision)?), bits(&values));
        assert_eq!(bits(&output(&actual, "output")?), bits(&[-0.75, 1.25, 2.5, -0.5]));
        refuse(&make(true), OnnxError::Graph);
    }
    Ok(())
}

#[test]
fn instance_extrema_and_nonfinite_rows_keep_the_declared_native_numeric_contract() -> Test {
    let dims = [1, 3, 4];
    let scale = [1.0_f32, -2., 0.5];
    let bias = [0.0_f32, 0.25, -0.5];
    let values = [f32::MAX, f32::MIN, 0., -0., 4., 4., 4., 4.,
        f32::from_bits(1), -f32::from_bits(1), 0., -0.];
    let source = instance_model(&dims, &scale, &bias, &float_attr("epsilon", f32::from_bits(1)));
    let finite = roundtrip(&source, &[("input", value_tensor(&dims, &values)?)])?;
    close(&output(&finite, "output")?, &oracle(&values, &dims, &scale, &bias, f32::from_bits(1)));
    for nonfinite in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        let mut changed = values;
        changed[1] = nonfinite;
        let actual = output(&roundtrip(&source, &[("input", value_tensor(&dims, &changed)?)])?, "output")?;
        assert!(actual[..4].iter().all(|value| value.is_nan()));
        assert_eq!(bits(&actual[4..]), bits(&output(&finite, "output")?[4..]));
    }
    // A finite normalized value can overflow the separate F32 channel affine
    // operation. This low-level tensor is not a retained inference acceptance.
    let source = instance_model(&[1, 1, 3], &[f32::MAX], &[0.], &[]);
    let actual = output(&roundtrip(&source, &[("input", value_tensor(&[1, 1, 3], &[-1., 0., 1.])?)])?, "output")?;
    assert!(actual[0].is_infinite() && actual[0].is_sign_negative());
    assert_eq!(actual[1], 0.);
    assert!(actual[2].is_infinite() && actual[2].is_sign_positive());
    Ok(())
}

#[test]
fn instance_actual_execution_refuses_short_budgets_stale_generations_and_cancellation() -> Test {
    let source = instance_model(&[1, 2, 3], &[1., -2.], &[0.25, 0.5], &[]);
    let imported = import(&source)?;
    let values = [-1.0_f32, 0., 1., 2., 3., 4.];
    let input = [("input", value_tensor(&[1, 2, 3], &values)?)];
    let constants = imported.parameters().iter()
        .map(|(name, tensor)| Ok((name.clone(), tensor.to_vec::<f32>()?)))
        .collect::<Result<BTreeMap<_, _>, fss_tensor::TensorError>>()?;
    let optimized = optimized_executor::OptimizedGraph::prepare(imported.graph(), &constants, &ScalarExecCx::new())?;
    let mut bindings = imported.parameters().clone();
    bindings.insert("input".into(), input[0].1.clone());
    let bindings = bindings.into_iter().collect::<Vec<_>>();
    let baseline = ScalarExecutor::run(imported.graph(), &bindings, ExecBudget::unlimited(), &ScalarExecCx::new())?;
    for budget in [
        ExecBudget::new(baseline.executed_macs() - 1, baseline.allocated_bytes()),
        ExecBudget::new(baseline.executed_macs(), baseline.allocated_bytes() - 1),
    ] {
        assert!(matches!(ScalarExecutor::run(imported.graph(), &bindings, budget, &ScalarExecCx::new()), Err(ExecError::BudgetExceeded { .. })));
        assert!(matches!(optimized.run(&input, budget, &ScalarExecCx::new()), Err(ExecError::BudgetExceeded { .. })));
    }
    let stale = Tensor::from_values(Shape::new(vec![1, 2, 3])?, &values, Generation(GENERATION.0 + 1))?;
    let mut stale_bindings = bindings.clone();
    stale_bindings.iter_mut().find(|(name, _)| name == "input").ok_or("missing input")?.1 = stale.clone();
    assert!(matches!(ScalarExecutor::run(imported.graph(), &stale_bindings, ExecBudget::unlimited(), &ScalarExecCx::new()), Err(ExecError::GenerationMismatch { .. })));
    assert!(matches!(optimized.run(&[("input", stale)], ExecBudget::unlimited(), &ScalarExecCx::new()), Err(ExecError::GenerationMismatch { .. })));
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    assert!(matches!(ScalarExecutor::run(imported.graph(), &bindings, ExecBudget::unlimited(), &cx), Err(ExecError::CancellationRequested { .. })));
    assert!(cx.is_drain_completed());
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    assert!(matches!(optimized.run(&input, ExecBudget::unlimited(), &cx), Err(ExecError::CancellationRequested { .. })));
    assert!(cx.is_drain_completed());
    Ok(())
}
