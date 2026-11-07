#![forbid(unsafe_code)]
//! Linear Resize contracts use the actual scalar and optimized executors, then
//! repeat after canonical-graph and production Safetensors reload. The numerical
//! oracle evaluates direct four-neighbor bilinear interpolation in binary64;
//! it shares neither source-coordinate planning nor emitted graph helpers.

use super::*;

const MODES: [&str; 4] = [
    "half_pixel",
    "pytorch_half_pixel",
    "align_corners",
    "asymmetric",
];

fn attrs(mode: &str) -> Vec<u8> {
    [
        text_attr("mode", "linear"),
        text_attr("coordinate_transformation_mode", mode),
    ].concat()
}

fn sizes_model(dims: [usize; 4], output: [usize; 4], mode: &str) -> Vec<u8> {
    resize_graph(
        dims.map(|n| n as u64),
        output.map(|n| n as u64),
        &["input", "", "", "sizes"],
        &int_weight("sizes", &output.map(|n| n as i64)),
        &attrs(mode),
    )
}

fn scales_model(dims: [usize; 4], factors: [f32; 2], mode: &str) -> Vec<u8> {
    let output = [
        dims[0], dims[1],
        (dims[2] as f64 * f64::from(factors[0])).floor() as usize,
        (dims[3] as f64 * f64::from(factors[1])).floor() as usize,
    ];
    resize_graph(
        dims.map(|n| n as u64),
        output.map(|n| n as u64),
        &["input", "", "scales"],
        &weight("scales", &[4], &[1., 1., factors[0], factors[1]]),
        &attrs(mode),
    )
}

fn data(dims: &[usize], values: &[f32]) -> Test<Tensor> {
    Ok(Tensor::from_values(Shape::new(dims.to_vec())?, values, GENERATION)?)
}

fn execute(
    graph: &fss_model_ir::ModelIrGraph,
    mut parameters: BTreeMap<String, Tensor>,
    input: &[(&str, Tensor)],
) -> Test<BTreeMap<String, Vec<f32>>> {
    let constants = parameters.iter()
        .map(|(name, tensor)| Ok((name.clone(), tensor.to_vec::<f32>()?)))
        .collect::<Result<BTreeMap<_, _>, fss_tensor::TensorError>>()?;
    let prepared = optimized_executor::OptimizedGraph::prepare(
        graph, &constants, &ScalarExecCx::new(),
    )?;
    let optimized = prepared.run(input, ExecBudget::unlimited(), &ScalarExecCx::new())?;
    parameters.extend(input.iter().map(|(name, tensor)| ((*name).to_owned(), tensor.clone())));
    let bindings = parameters.into_iter().collect::<Vec<_>>();
    let scalar = ScalarExecutor::run(
        graph, &bindings, ExecBudget::unlimited(), &ScalarExecCx::new(),
    )?;
    assert_eq!(optimized.executed_macs(), scalar.executed_macs());
    assert_eq!(optimized.allocated_bytes(), scalar.allocated_bytes());
    graph.outputs().iter().map(|port| {
        let actual = optimized.get_output(port.name()).ok_or("missing optimized output")?
            .to_vec::<f32>()?;
        let expected = scalar.get_output(port.name()).ok_or("missing scalar output")?
            .to_vec::<f32>()?;
        assert_eq!(bits(&actual), bits(&expected), "executor output {}", port.name());
        Ok((port.name().to_owned(), expected))
    }).collect()
}

fn roundtrip(source: &[u8], input: &[(&str, Tensor)]) -> Test<BTreeMap<String, Vec<f32>>> {
    let imported = import(source)?;
    let before = execute(imported.graph(), imported.parameters().clone(), input)?;
    let artifacts = export(&imported)?;
    assert_eq!(artifacts.source(), source);
    assert_eq!(artifacts.source_digest(), ContentDigest::sha256(source));
    let graph = decode_canonical_model_ir(artifacts.graph_bytes(), artifacts.graph_digest())?;
    assert_eq!(encode_canonical_model_ir(&graph)?, artifacts.graph_bytes());
    let parameters = reloaded(&artifacts)?;
    for (name, expected) in imported.parameters() {
        let actual = parameters.get(name).ok_or("missing reloaded coefficient")?;
        assert_eq!(actual.shape(), expected.shape());
        assert_eq!(bits(&actual.to_vec::<f32>()?), bits(&expected.to_vec::<f32>()?));
    }
    let after = execute(&graph, parameters, input)?;
    for (name, expected) in &before {
        assert_eq!(bits(&after[name]), bits(expected), "artifact output {name}");
    }
    Ok(after)
}

fn coordinate(input: usize, output: usize, scale: f64, x: usize, mode: &str) -> f64 {
    assert!(MODES.contains(&mode), "unknown test coordinate mode: {mode}");
    let x = x as f64;
    let position = match mode {
        "half_pixel" => (x + 0.5) / scale - 0.5,
        "pytorch_half_pixel" if output > 1 => (x + 0.5) / scale - 0.5,
        "align_corners" if output > 1 => x * (input - 1) as f64 / (output - 1) as f64,
        "asymmetric" => x / scale,
        // The validated remaining cases are the two singleton conventions.
        _ => 0.0,
    };
    position.max(0.0).min((input - 1) as f64)
}

fn oracle(
    input: &[f32],
    dims: [usize; 4],
    output: [usize; 4],
    scales: [f64; 2],
    mode: &str,
) -> Vec<f32> {
    let mut result = Vec::new();
    for plane in 0..dims[0] * dims[1] {
        for y in 0..output[2] {
            let sy = coordinate(dims[2], output[2], scales[0], y, mode);
            let y0 = sy.floor() as usize;
            let y1 = (y0 + 1).min(dims[2] - 1);
            let dy = sy - y0 as f64;
            for x in 0..output[3] {
                let sx = coordinate(dims[3], output[3], scales[1], x, mode);
                let x0 = sx.floor() as usize;
                let x1 = (x0 + 1).min(dims[3] - 1);
                let dx = sx - x0 as f64;
                let get = |y, x| f64::from(input[(plane * dims[2] + y) * dims[3] + x]);
                let value = get(y0, x0) * (1.0 - dx) * (1.0 - dy)
                    + get(y0, x1) * dx * (1.0 - dy)
                    + get(y1, x0) * (1.0 - dx) * dy
                    + get(y1, x1) * dx * dy;
                result.push(value as f32);
            }
        }
    }
    result
}

fn close(actual: &[f32], expected: &[f32]) {
    assert_eq!(actual.len(), expected.len());
    for (index, (&actual, &expected)) in actual.iter().zip(expected).enumerate() {
        assert!(actual.is_finite());
        assert!((actual - expected).abs() <= 2e-5 * (1.0 + expected.abs()),
            "index={index}, actual={actual:?}, expected={expected:?}");
    }
}

fn parameter_bytes(imported: &ImportedOnnx<'_>) -> Test<usize> {
    Ok(imported.parameters().values()
        .map(|tensor| tensor.shape().size_bytes(fss_tensor::DType::F32))
        .collect::<Result<Vec<_>, _>>()?.into_iter().sum())
}

#[test]
fn literal_linear_profiles_clamp_edges_and_distinguish_singleton_semantics() -> Test {
    let input = data(&[1, 1, 1, 4], &[0., 10., 20., 30.])?;
    for (mode, output, expected) in [
        ("half_pixel", 8, vec![0., 2.5, 7.5, 12.5, 17.5, 22.5, 27.5, 30.]),
        ("pytorch_half_pixel", 8, vec![0., 2.5, 7.5, 12.5, 17.5, 22.5, 27.5, 30.]),
        ("asymmetric", 8, vec![0., 5., 10., 15., 20., 25., 30., 30.]),
        ("align_corners", 7, vec![0., 5., 10., 15., 20., 25., 30.]),
        ("half_pixel", 1, vec![15.]),
        ("pytorch_half_pixel", 1, vec![0.]),
        ("align_corners", 1, vec![0.]),
        ("asymmetric", 1, vec![0.]),
    ] {
        let source = sizes_model([1, 1, 1, 4], [1, 1, 1, output], mode);
        assert_eq!(bits(&roundtrip(&source, &[("input", input.clone())])?["output"]), bits(&expected));
    }
    Ok(())
}

#[test]
fn all_linear_profiles_match_direct_bilinear_oracle_for_batches_channels_and_mixed_axes() -> Test {
    for dims in [[2, 3, 3, 5], [1, 2, 5, 7], [1, 1, 1, 4]] {
        let values = (0..dims.iter().product::<usize>())
            .map(|i| ((i * 17 % 43) as f32 - 21.) * 0.125).collect::<Vec<_>>();
        for factors in [[1.5_f32, 2.5], [0.5, 0.75], [0.75, 1.5], [1.5, 0.5], [0.6, 1.125], [1., 1.]] {
            let output = [
                dims[0], dims[1],
                (dims[2] as f64 * f64::from(factors[0])).floor() as usize,
                (dims[3] as f64 * f64::from(factors[1])).floor() as usize,
            ];
            if output.contains(&0) {
                continue;
            }
            for mode in MODES {
                for sizes in [false, true] {
                    let (source, scales) = if sizes {
                        (sizes_model(dims, output, mode),
                         [output[2] as f64 / dims[2] as f64, output[3] as f64 / dims[3] as f64])
                    } else {
                        (scales_model(dims, factors, mode), factors.map(f64::from))
                    };
                    let actual = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
                    close(&actual["output"], &oracle(&values, dims, output, scales, mode));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn original_f32_scales_are_not_replaced_by_rounded_output_size_ratios() -> Test {
    for mode in MODES {
        for (width, factor) in [
            (7, 0.6_f32), (4, 1.125),
            (5, f32::from_bits(1.5_f32.to_bits() - 1)),
            (5, f32::from_bits(1.5_f32.to_bits() + 1)),
        ] {
            let dims = [1, 1, 1, width];
            let output = [1, 1, 1, (width as f64 * f64::from(factor)).floor() as usize];
            let values = (0..width).map(|x| x as f32).collect::<Vec<_>>();
            let source = scales_model(dims, [1., factor], mode);
            let actual = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
            close(&actual["output"], &oracle(&values, dims, output, [1., f64::from(factor)], mode));
            if mode != "align_corners" && factor == 0.6 {
                let sizes = sizes_model(dims, output, mode);
                let sized = roundtrip(&sizes, &[("input", data(&dims, &values)?)])?;
                assert_ne!(bits(&actual["output"]), bits(&sized["output"]));
            }
            if width == output[3] && mode != "align_corners" {
                assert!(!import(&source)?.parameters().is_empty());
                assert_ne!(bits(&actual["output"]), bits(&values));
            }
        }
    }
    Ok(())
}

#[test]
fn identity_and_exact_grid_sampling_preserve_f32_bits_without_generated_weights() -> Test {
    let special = [
        -0.0_f32, f32::from_bits(1), -f32::from_bits(1), f32::MIN_POSITIVE,
        f32::MAX, f32::MIN, 0.0, -1.25,
    ];
    for mode in MODES {
        let dims = [1, 2, 2, 2];
        let source = sizes_model(dims, dims, mode);
        let imported = import(&source)?;
        assert_eq!(imported.graph().node_count(), 1);
        assert_eq!(imported.graph().nodes()[0].op(), fss_model_ir::OpCode::Reshape);
        assert!(imported.parameters().is_empty());
        assert_eq!(bits(&roundtrip(&source, &[("input", data(&dims, &special)?)])?["output"]), bits(&special));
        let source = sizes_model([1, 1, 1, 1], [1, 1, 7, 9], mode);
        assert!(import(&source)?.parameters().is_empty());
        assert_eq!(
            bits(&roundtrip(&source, &[("input", data(&[1, 1, 1, 1], &[-0.0])?)])?["output"]),
            vec![(-0.0_f32).to_bits(); 63]
        );
    }
    let values = [-0.0_f32, 9., f32::from_bits(1), 8., f32::MAX, 7., f32::MIN, 6.];
    let source = sizes_model([1, 1, 1, 8], [1, 1, 1, 4], "asymmetric");
    let imported = import(&source)?;
    assert_eq!(imported.graph().node_count(), 1);
    assert!(imported.parameters().is_empty());
    assert_eq!(
        bits(&roundtrip(&source, &[("input", data(&[1, 1, 1, 8], &values)?)])?["output"]),
        bits(&[values[0], values[2], values[4], values[6]])
    );
    Ok(())
}

#[test]
fn practical_feature_scales_use_linear_weights_and_shrink_before_growth() -> Test {
    for (dims, output) in [
        ([1, 8, 80, 80], [1, 8, 160, 160]),
        ([1, 3, 480, 640], [1, 3, 360, 480]),
        ([1, 1, 1, 64], [1, 1, 1, 4096]),
    ] {
        let source = sizes_model(dims, output, "half_pixel");
        let imported = import(&source)?;
        assert!(imported.graph().node_count() <= 64);
        let expected = (if dims[2] == output[2] { 0 } else { output[2] }
            + if dims[3] == output[3] { 0 } else { output[3] }) * 8;
        assert_eq!(parameter_bytes(&imported)?, expected);
        for node in imported.graph().nodes() {
            assert!(matches!(node.op(),
                fss_model_ir::OpCode::Slice | fss_model_ir::OpCode::Concat |
                fss_model_ir::OpCode::Reshape | fss_model_ir::OpCode::Mul | fss_model_ir::OpCode::Add
            ));
        }
    }
    // The original decimal scale uses a short phase hint without replacing
    // any source coordinate by the nearby mathematical 3/5 ratio.
    let source = scales_model([1, 1, 320, 640], [0.6, 0.6], "half_pixel");
    let imported = import(&source)?;
    assert!(imported.graph().node_count() <= 64);
    assert_eq!(parameter_bytes(&imported)?, (192 + 384) * 8);

    for factors in [[0.5, 2.0], [2.0, 0.5]] {
        let source = scales_model([1, 1, 4, 4], factors, "half_pixel");
        let imported = import_onnx(
            &source, ContentDigest::sha256(&source), GENERATION,
            OnnxLimits { tensor_bytes: 64, ..OnnxLimits::default() }, &|| false,
        )?;
        assert_eq!(imported.graph().nodes()[0].op(), fss_model_ir::OpCode::Slice);
        let values = (0..16).map(|n| n as f32).collect::<Vec<_>>();
        let output = [1, 1, (4. * factors[0]) as usize, (4. * factors[1]) as usize];
        let actual = roundtrip(&source, &[("input", data(&[1, 1, 4, 4], &values)?)])?;
        close(&actual["output"], &oracle(&values, [1, 1, 4, 4], output, factors.map(f64::from), "half_pixel"));
    }
    for output in [4097, 8194] {
        reject(&sizes_model([1, 1, 1, 4097], [1, 1, 1, output], "half_pixel"), OnnxError::Limit);
    }
    Ok(())
}

#[test]
fn linear_admission_counts_controls_coefficients_helpers_work_and_cancellation() -> Test {
    let source = scales_model([1, 1, 3, 5], [1.5, 2.5], "half_pixel");
    let imported = import(&source)?;
    let nodes = imported.graph().node_count();
    let parameters = imported.parameters().len();
    assert_eq!(parameters, 4);
    assert_eq!(parameter_bytes(&imported)?, 128);
    // Input and scales are already known. The source scales' 16 control bytes
    // remain charged even though only the four generated vectors are exported.
    let limits = OnnxLimits {
        nodes, tensors: nodes + parameters + 2,
        parameter_bytes: 144, tensor_bytes: 192,
        work_units: imported.work_units(), ..OnnxLimits::default()
    };
    let exact = import_onnx(&source, ContentDigest::sha256(&source), GENERATION, limits, &|| false)?;
    assert_eq!(encode_canonical_model_ir(exact.graph())?, encode_canonical_model_ir(imported.graph())?);
    for limits in [
        OnnxLimits { nodes: nodes - 1, ..limits },
        OnnxLimits { tensors: limits.tensors - 1, ..limits },
        OnnxLimits { parameter_bytes: limits.parameter_bytes - 1, ..limits },
        OnnxLimits { tensor_bytes: limits.tensor_bytes - 1, ..limits },
    ] {
        assert_eq!(
            import_onnx(&source, ContentDigest::sha256(&source), GENERATION, limits, &|| false).err(),
            Some(OnnxError::Limit)
        );
    }
    assert_eq!(
        import_onnx(&source, ContentDigest::sha256(&source), GENERATION,
            OnnxLimits { work_units: limits.work_units - 1, ..limits }, &|| false).err(),
        Some(OnnxError::WorkBudget)
    );
    assert_eq!(
        import_onnx(&source, ContentDigest::sha256(b"wrong source"), GENERATION, limits, &|| false).err(),
        Some(OnnxError::Digest)
    );
    let calls = Cell::new(0);
    import_onnx(&source, ContentDigest::sha256(&source), GENERATION, limits, &|| {
        calls.set(calls.get() + 1);
        false
    })?;
    let total = calls.get();
    for stop in 1..=total {
        calls.set(0);
        assert_eq!(
            import_onnx(&source, ContentDigest::sha256(&source), GENERATION, limits, &|| {
                calls.set(calls.get() + 1);
                calls.get() == stop
            }).err(),
            Some(OnnxError::Cancelled), "checkpoint {stop}/{total}"
        );
    }
    Ok(())
}

#[test]
fn unsupported_linear_modes_attributes_and_nonempty_roi_remain_explicit_refusals() -> Test {
    for extra in [
        text_attr("coordinate_transformation_mode", "tf_crop_and_resize"),
        text_attr("coordinate_transformation_mode", "tf_half_pixel_for_nn"),
        text_attr("coordinate_transformation_mode", "half_pixel_symmetric"),
        text_attr("nearest_mode", "unknown"),
        attribute("exclude_outside", 2, &integer(3, 1)),
        attribute("antialias", 2, &integer(3, 0)),
        ints_attr("axes", &[2, 3]),
    ] {
        let attrs = [text_attr("mode", "linear"), extra].concat();
        reject(&resize_graph([1, 1, 2, 2], [1, 1, 3, 3], &["input", "", "scales"],
            &weight("scales", &[4], &[1., 1., 1.5, 1.5]), &attrs), OnnxError::Unsupported);
    }
    for name in ["coordinate_transformation_mode", "nearest_mode", "mode"] {
        let attributes = if name == "mode" {
            attribute(name, 2, &integer(3, 0))
        } else {
            [text_attr("mode", "linear"), attribute(name, 2, &integer(3, 0))].concat()
        };
        reject(&resize_graph([1, 1, 2, 2], [1, 1, 3, 3], &["input", "", "scales"],
            &weight("scales", &[4], &[1., 1., 1.5, 1.5]), &attributes), OnnxError::Graph);
    }
    reject(&resize_graph([1, 1, 2, 2], [1, 1, 3, 3], &["input", "roi", "scales"],
        &[weight("roi", &[8], &[0., 0., 0., 0., 1., 1., 1., 1.]),
          weight("scales", &[4], &[1., 1., 1.5, 1.5])].concat(),
        &attrs("half_pixel")), OnnxError::Unsupported);
    let input = data(&[1, 1, 2, 2], &[1., 2., 3., 4.])?;
    let baseline = roundtrip(&scales_model([1, 1, 2, 2], [1.5, 1.5], "half_pixel"),
        &[("input", input.clone())])?;
    for nearest in ["round_prefer_floor", "round_prefer_ceil", "floor", "ceil"] {
        let source = resize_graph([1, 1, 2, 2], [1, 1, 3, 3], &["input", "", "scales"],
            &weight("scales", &[4], &[1., 1., 1.5, 1.5]),
            &[attrs("half_pixel"), text_attr("nearest_mode", nearest)].concat());
        assert_eq!(bits(&roundtrip(&source, &[("input", input.clone())])?["output"]), bits(&baseline["output"]));
    }
    Ok(())
}

#[test]
fn linear_helpers_and_coefficients_cannot_capture_later_source_values() -> Test {
    let baseline = scales_model([1, 1, 2, 3], [1.5, 2.0], "half_pixel");
    let imported = import(&baseline)?;
    let candidates = [
        imported.graph().nodes()[0].outputs()[0].clone(),
        imported.parameters().keys().next().ok_or("missing coefficients")?.clone(),
    ];
    let values = [0., 1., 2., 3., 4., 5.];
    for collision in candidates {
        let make = |forward: bool| model(&[
            node("Resize", &[if forward { &collision } else { "input" }, "", "scales"], "resized", &attrs("half_pixel")),
            node("Identity", &["input"], &collision, &[]),
            weight("scales", &[4], &[1., 1., 1.5, 2.]),
            bytes(11, &info("input", &[1, 1, 2, 3])),
            bytes(12, &info("resized", &[1, 1, 3, 6])),
            bytes(12, &info(&collision, &[1, 1, 2, 3])),
        ].concat());
        let source = make(false);
        let imported = import(&source)?;
        assert!(!imported.parameters().contains_key(&collision));
        for helper in &imported.graph().nodes()[..imported.graph().node_count() - 1] {
            assert!(!helper.outputs().contains(&collision));
        }
        let actual = roundtrip(&source, &[("input", data(&[1, 1, 2, 3], &values)?)])?;
        assert_eq!(bits(&actual[&collision]), bits(&values));
        close(&actual["resized"], &oracle(&values, [1, 1, 2, 3], [1, 1, 3, 6], [1.5, 2.], "half_pixel"));
        reject(&make(true), OnnxError::Graph);
    }
    Ok(())
}

#[test]
fn convolution_linear_upsampling_pooling_and_dense_features_execute_as_one_model() -> Test {
    let input = [0.5_f32, -1., 2., 3., -0.25, 1.5, -2., 1., 0.25, -0.5, 2.5, 0.75];
    let dense = (0..90).map(|i| ((i * 5 % 9) as f32 - 4.) * 0.125).collect::<Vec<_>>();
    let bias = [0.25_f32, -0.5, 1.];
    let source = model(&[
        node("Conv", &["input", "kernel", "conv_bias"], "feature", &[]),
        node("Resize", &["feature", "", "scales"], "upsampled", &attrs("half_pixel")),
        node("AveragePool", &["upsampled"], "pooled",
            &[ints_attr("kernel_shape", &[2, 2]), ints_attr("strides", &[1, 1])].concat()),
        node("Flatten", &["pooled"], "flat", &[]),
        node("Gemm", &["flat", "dense", "bias"], "output", &[]),
        weight("kernel", &[2, 2, 1, 1], &[1., 0.5, -0.25, 2.]),
        weight("conv_bias", &[2], &[0.25, -0.5]),
        weight("scales", &[4], &[1., 1., 2., 2.]),
        weight("dense", &[30, 3], &dense),
        weight("bias", &[3], &bias),
        bytes(11, &info("input", &[1, 2, 2, 3])),
        bytes(12, &info("output", &[1, 3])),
    ].concat());
    let mut conv = Vec::new();
    for (weights, bias) in [([1.0_f64, 0.5], 0.25), ([-0.25, 2.0], -0.5)] {
        for position in 0..6 {
            conv.push((f64::from(input[position]) * weights[0]
                + f64::from(input[6 + position]) * weights[1] + bias) as f32);
        }
    }
    let resized = oracle(&conv, [1, 2, 2, 3], [1, 2, 4, 6], [2., 2.], "half_pixel");
    let mut pooled = Vec::new();
    for channel in 0..2 {
        for y in 0..3 {
            for x in 0..5 {
                let mut sum = 0.0_f64;
                for dy in 0..2 {
                    for dx in 0..2 {
                        sum += f64::from(resized[(channel * 4 + y + dy) * 6 + x + dx]);
                    }
                }
                pooled.push(sum / 4.0);
            }
        }
    }
    let expected = (0..3).map(|column| {
        (pooled.iter().enumerate().map(|(row, value)| value * f64::from(dense[row * 3 + column]))
            .sum::<f64>() + f64::from(bias[column])) as f32
    }).collect::<Vec<_>>();
    let actual = roundtrip(&source, &[("input", data(&[1, 2, 2, 3], &input)?)])?;
    close(&actual["output"], &expected);
    Ok(())
}

#[test]
fn linear_execution_enforces_actual_work_memory_generation_and_cancellation() -> Test {
    let source = scales_model([1, 1, 2, 3], [1.5, 2.0], "half_pixel");
    let imported = import(&source)?;
    let input = [("input", data(&[1, 1, 2, 3], &[1., 2., 3., 4., 5., 6.])?)];
    let constants = imported.parameters().iter()
        .map(|(name, tensor)| Ok((name.clone(), tensor.to_vec::<f32>()?)))
        .collect::<Result<BTreeMap<_, _>, fss_tensor::TensorError>>()?;
    let optimized = optimized_executor::OptimizedGraph::prepare(
        imported.graph(), &constants, &ScalarExecCx::new(),
    )?;
    let mut bindings = imported.parameters().clone();
    bindings.insert("input".into(), input[0].1.clone());
    let bindings = bindings.into_iter().collect::<Vec<_>>();
    let actual = ScalarExecutor::run(
        imported.graph(), &bindings, ExecBudget::unlimited(), &ScalarExecCx::new(),
    )?;
    for budget in [
        ExecBudget::new(actual.executed_macs() - 1, actual.allocated_bytes()),
        ExecBudget::new(actual.executed_macs(), actual.allocated_bytes() - 1),
    ] {
        assert!(matches!(ScalarExecutor::run(imported.graph(), &bindings, budget, &ScalarExecCx::new()),
            Err(ExecError::BudgetExceeded { .. })));
        assert!(matches!(optimized.run(&input, budget, &ScalarExecCx::new()),
            Err(ExecError::BudgetExceeded { .. })));
    }
    let stale = Tensor::from_values(Shape::new(vec![1, 1, 2, 3])?,
        &[1.0_f32, 2., 3., 4., 5., 6.], Generation(GENERATION.0 + 1))?;
    let mut stale_bindings = bindings.clone();
    stale_bindings.iter_mut().find(|(name, _)| name == "input").ok_or("missing input")?.1 = stale.clone();
    assert!(matches!(
        ScalarExecutor::run(imported.graph(), &stale_bindings, ExecBudget::unlimited(), &ScalarExecCx::new()),
        Err(ExecError::GenerationMismatch { .. })
    ));
    assert!(matches!(
        optimized.run(&[("input", stale)], ExecBudget::unlimited(), &ScalarExecCx::new()),
        Err(ExecError::GenerationMismatch { .. })
    ));
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    assert!(matches!(ScalarExecutor::run(imported.graph(), &bindings, ExecBudget::unlimited(), &cx),
        Err(ExecError::CancellationRequested { .. })));
    assert!(cx.is_drain_completed());
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    assert!(matches!(optimized.run(&input, ExecBudget::unlimited(), &cx),
        Err(ExecError::CancellationRequested { .. })));
    assert!(cx.is_drain_completed());
    Ok(())
}
