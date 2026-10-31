#![forbid(unsafe_code)]
//! RGB bytes -> native preprocessing -> transformed ONNX -> canonical artifacts -> scalar
//! inference. Production resize, weight parsing and scalar execution sources are unchanged.
//! This target deliberately has no asynchronous reference-runtime dependency.

use std::cell::Cell;
use std::collections::BTreeMap;

use fss_core::{ContentDigest, Generation};
use fss_model_ir::{
    ImportedOnnx, OnnxArtifacts, OnnxChannelOrder, OnnxError, OnnxExportLimits, OnnxImageTransform,
    OnnxLimits, decode_canonical_model_ir, encode_canonical_model_ir, export_onnx_artifacts,
    import_onnx, transform_onnx_image,
};
use fss_tensor::{Shape, Tensor};

#[path = "../../fss-reference/src/preprocess.rs"]
pub mod preprocess;
#[path = "../../fss-reference/src/ingest/model_import/safetensors.rs"]
mod safetensors;
#[path = "../../fss-reference/src/scalar_executor.rs"]
pub mod scalar_executor;

// Only the data-only host vocabulary required by the actual Safetensors parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ImportError {
    Limit,
    MalformedWeights,
    DuplicateKey,
    UnsupportedDType,
    NonFinite,
}
impl std::fmt::Display for ImportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for ImportError {}
struct ImportLimits {
    maximum_header_bytes: usize,
    maximum_tensors: usize,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum WeightFloatPolicy {
    F32Only,
    ExpandFloat16,
}

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Outputs = BTreeMap<String, Vec<f32>>;
const GENERATION: Generation = Generation(41);
const SOURCE: &[u8] =
    include_bytes!("../../fss-reference/tests/fixtures/onnx_package/normalization_detector.onnx");
const PIXELS: [u8; 12] = [10, 50, 90, 20, 100, 180, 30, 150, 210, 40, 200, 240];

fn transform(order: OnnxChannelOrder, unit: bool) -> OnnxImageTransform {
    OnnxImageTransform {
        channel_order: order,
        mean: if unit {
            [0.1, 0.2, 0.3]
        } else {
            [11.0, 22.0, 33.0]
        },
        standard_deviation: if unit {
            [0.25, 0.5, 0.75]
        } else {
            [12.0, 17.0, 23.0]
        },
    }
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
fn adapted(source: &[u8], value: OnnxImageTransform) -> Test<ImportedOnnx<'_>> {
    Ok(transform_onnx_image(
        import(source)?,
        "image",
        value,
        OnnxLimits::default(),
        &|| false,
    )?)
}
fn export<'a>(imported: &ImportedOnnx<'a>) -> Test<OnnxArtifacts<'a>> {
    Ok(export_onnx_artifacts(
        imported,
        OnnxExportLimits::default(),
        &|| false,
    )?)
}
fn parameters(artifacts: &OnnxArtifacts<'_>) -> Test<BTreeMap<String, Tensor>> {
    let parsed = safetensors::Weights::parse(
        artifacts.weights_bytes(),
        &ImportLimits {
            maximum_header_bytes: 256 * 1024,
            maximum_tensors: 256,
        },
    )?;
    let mut tensors = BTreeMap::new();
    for (name, entry) in &parsed.entries {
        let values = parsed.data[entry.start..entry.end]
            .chunks_exact(entry.width())
            .map(|bytes| safetensors::value(entry.dtype, bytes, WeightFloatPolicy::F32Only))
            .collect::<Result<Vec<_>, _>>()?;
        tensors.insert(
            name.clone(),
            Tensor::from_values(Shape::new(entry.shape.clone())?, &values, GENERATION)?,
        );
    }
    Ok(tensors)
}
fn resized(pixels: &[u8], unit: bool) -> Test<Tensor> {
    let program =
        scalar_executor::PreprocessProgram::new(2, 2, scalar_executor::ChannelTransform::Rgb, unit);
    Ok(program
        .execute_resized_bytes(
            preprocess::ImageBytes {
                bytes: pixels,
                height: 2,
                width: 2,
                channels: 3,
                generation: GENERATION,
            },
            preprocess::ResizeOptions {
                filter: preprocess::ResizeFilter::Nearest,
                aspect: preprocess::ResizeAspect::Stretch,
                budget: scalar_executor::ExecBudget::new(100_000, 1 << 20),
            },
            &scalar_executor::ScalarExecCx::new(),
        )?
        .tensor)
}
fn run(artifacts: &OnnxArtifacts<'_>, image: Tensor) -> Test<Outputs> {
    let graph = decode_canonical_model_ir(artifacts.graph_bytes(), artifacts.graph_digest())?;
    let mut inputs = parameters(artifacts)?;
    inputs.insert("image".into(), image);
    let outputs = scalar_executor::ScalarExecutor::run(
        &graph,
        &inputs.into_iter().collect::<Vec<_>>(),
        scalar_executor::ExecBudget::unlimited(),
        &scalar_executor::ScalarExecCx::new(),
    )?;
    graph
        .outputs()
        .iter()
        .map(|port| {
            Ok((
                port.name().to_owned(),
                outputs
                    .get_output(port.name())
                    .ok_or("missing model output")?
                    .to_vec::<f32>()?,
            ))
        })
        .collect()
}
fn bits(values: &[f32]) -> Vec<u32> {
    values.iter().map(|v| v.to_bits()).collect()
}

// Independent, explicit fixture oracle: HWC bytes -> ordered normalized planes ->
// row-major spatial mean -> the authored 3x6 dense projection and bias.
fn oracle(pixels: &[u8], value: OnnxImageTransform, unit: bool) -> (Vec<f32>, Vec<f32>) {
    let order = match value.channel_order {
        OnnxChannelOrder::Rgb => [0, 1, 2],
        OnnxChannelOrder::Bgr => [2, 1, 0],
    };
    let scale = if unit { 1.0_f32 / 255.0_f32 } else { 1.0_f32 };
    let mut normalized = Vec::new();
    let mut means = [0.0_f32; 3];
    for channel in 0..3 {
        for pixel in 0..4 {
            let x = f32::from(pixels[pixel * 3 + order[channel]]) * scale;
            let n = (x - value.mean[channel]) / value.standard_deviation[channel];
            normalized.push(n);
            means[channel] += n;
        }
        means[channel] /= 4.0_f32;
    }
    let weights = [
        [0.0, 0.0, 0.0, 0.0, 0.125, 0.0],
        [0.0, 0.0, 0.0, 0.0, 0.0, 0.125],
        [0.0, 0.0, 0.0, 0.0, 0.0625, -0.0625],
    ];
    let bias = [0.0, 0.0, 2.0, 2.0, 0.6, 0.4];
    let mut head = vec![0.0_f32; 6];
    for field in 0..6 {
        for channel in 0..3 {
            head[field] += means[channel] * weights[channel][field];
        }
        head[field] += bias[field];
    }
    (normalized, head)
}

#[test]
fn rgb_and_bgr_raw_and_unit_pixels_match_oracle_after_native_artifact_reload() -> Test {
    assert_eq!(SOURCE.len(), 484);
    assert_eq!(
        ContentDigest::sha256(SOURCE).to_text(),
        "sha256:4ab4d26e5635ff624d1230095ae640b56e0173188f69a23b5ab62b70d701ea5c"
    );
    for order in [OnnxChannelOrder::Rgb, OnnxChannelOrder::Bgr] {
        for unit in [false, true] {
            let value = transform(order, unit);
            value.validate_rgb_range(unit)?;
            let converted = adapted(SOURCE, value)?;
            let artifacts = export(&converted)?;
            let result = run(&artifacts, resized(&PIXELS, unit)?)?;
            let (pixels, head) = oracle(&PIXELS, value, unit);
            assert_eq!(bits(&result["model_pixels"]), bits(&pixels));
            assert_eq!(bits(&result["head"]), bits(&head));
            assert_eq!(artifacts.source(), SOURCE);
            assert!(std::ptr::eq(artifacts.source().as_ptr(), SOURCE.as_ptr()));
            assert_eq!(artifacts.source_digest(), ContentDigest::sha256(SOURCE));
            assert_eq!(converted.runtime_inputs(), ["image"]);
            assert_eq!(
                artifacts.graph_bytes(),
                encode_canonical_model_ir(converted.graph())?
            );
            let reloaded = parameters(&artifacts)?;
            for (name, tensor) in converted.parameters() {
                assert_eq!(
                    bits(&reloaded[name].to_vec::<f32>()?),
                    bits(&tensor.to_vec::<f32>()?)
                );
            }
        }
    }
    Ok(())
}

#[test]
fn source_parameters_and_default_import_are_preserved_and_transforms_bind_identity() -> Test {
    let original = import(SOURCE)?;
    let before = export(&original)?;
    let rgb = adapted(SOURCE, transform(OnnxChannelOrder::Rgb, true))?;
    let bgr = adapted(SOURCE, transform(OnnxChannelOrder::Bgr, true))?;
    assert_eq!(
        rgb.graph().nodes().len(),
        original.graph().nodes().len() + 2
    );
    assert_eq!(
        bgr.graph().nodes().len(),
        original.graph().nodes().len() + 6
    );
    for (name, tensor) in original.parameters() {
        assert_eq!(
            bits(&tensor.to_vec::<f32>()?),
            bits(&bgr.parameters()[name].to_vec::<f32>()?)
        );
    }
    let a = export(&rgb)?;
    let b = export(&bgr)?;
    assert_ne!(a.graph_digest(), b.graph_digest());
    assert_ne!(before.graph_digest(), b.graph_digest());
    let mut changed = transform(OnnxChannelOrder::Bgr, true);
    changed.mean[2] = 0.31;
    assert_ne!(
        b.weights_digest(),
        export(&adapted(SOURCE, changed)?)?.weights_digest()
    );
    assert_eq!(
        before.graph_bytes(),
        export(&import(SOURCE)?)?.graph_bytes()
    );
    assert_eq!(
        before.weights_bytes(),
        export(&import(SOURCE)?)?.weights_bytes()
    );
    Ok(())
}

#[test]
fn explicit_identity_transform_preserves_values_and_original_input_names() -> Test {
    let value = OnnxImageTransform {
        channel_order: OnnxChannelOrder::Rgb,
        mean: [0.0; 3],
        standard_deviation: [1.0; 3],
    };
    let original = export(&import(SOURCE)?)?;
    let adapted = export(&adapted(SOURCE, value)?)?;
    for unit in [false, true] {
        let a = run(&original, resized(&PIXELS, unit)?)?;
        let b = run(&adapted, resized(&PIXELS, unit)?)?;
        for (name, values) in &a {
            assert_eq!(bits(values), bits(&b[name]));
        }
    }
    Ok(())
}

#[test]
fn image_transform_keeps_subtract_then_divide_f32_order() -> Test {
    // A folded reciprocal multiply produces different F32 bits for this fixture.
    let value = OnnxImageTransform {
        channel_order: OnnxChannelOrder::Rgb,
        mean: [0.1; 3],
        standard_deviation: [0.7; 3],
    };
    let artifacts = export(&adapted(SOURCE, value)?)?;
    let pixels = [25_u8; 12];
    let result = run(&artifacts, resized(&pixels, true)?)?;
    let x = 25.0_f32 * (1.0_f32 / 255.0_f32);
    let expected = (x - 0.1_f32) / 0.7_f32;
    assert_ne!(
        expected.to_bits(),
        ((x - 0.1_f32) * (1.0_f32 / 0.7_f32)).to_bits()
    );
    assert!(
        result["model_pixels"]
            .iter()
            .all(|v| v.to_bits() == expected.to_bits())
    );
    Ok(())
}

#[test]
fn nonfinite_nonpositive_and_rgb_interval_overflow_are_refused() -> Test {
    for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        let mut value = transform(OnnxChannelOrder::Bgr, true);
        value.mean[1] = bad;
        assert_eq!(
            transform_onnx_image(
                import(SOURCE)?,
                "image",
                value,
                OnnxLimits::default(),
                &|| false
            )
            .err(),
            Some(OnnxError::NonFinite)
        );
    }
    for bad in [0.0, -0.0, -1.0, f32::NAN, f32::INFINITY] {
        let mut value = transform(OnnxChannelOrder::Rgb, true);
        value.standard_deviation[2] = bad;
        assert!(value.validate().is_err());
    }
    let mut value = transform(OnnxChannelOrder::Rgb, true);
    value.standard_deviation[0] = f32::from_bits(1);
    assert_eq!(value.validate_rgb_range(true), Err(OnnxError::NonFinite));
    value.mean = [0.0; 3];
    value.standard_deviation = [1e-37; 3];
    assert!(value.validate_rgb_range(true).is_ok());
    assert_eq!(value.validate_rgb_range(false), Err(OnnxError::NonFinite));
    Ok(())
}

#[test]
fn transform_bounds_count_existing_generated_parameters_and_cumulative_work() -> Test {
    let original = import(SOURCE)?;
    let value = transform(OnnxChannelOrder::Bgr, true);
    let complete = adapted(SOURCE, value)?;
    let base = OnnxLimits::default();
    let parameters_bytes = complete
        .parameters()
        .values()
        .try_fold(0_usize, |sum, tensor| {
            Ok::<_, Box<dyn std::error::Error>>(sum + tensor.shape().size_bytes(tensor.dtype())?)
        })?;
    // GlobalAveragePool has already generated two parameters; these cannot be refunded.
    assert!(parameters_bytes > 96 + 24);
    let exact = OnnxLimits {
        nodes: complete.graph().nodes().len(),
        parameter_bytes: parameters_bytes,
        work_units: complete.work_units(),
        ..base
    };
    assert!(transform_onnx_image(import(SOURCE)?, "image", value, exact, &|| false).is_ok());
    for limits in [
        OnnxLimits {
            nodes: exact.nodes - 1,
            ..exact
        },
        OnnxLimits {
            parameter_bytes: exact.parameter_bytes - 1,
            ..exact
        },
        OnnxLimits {
            tensor_bytes: 47,
            ..exact
        },
        OnnxLimits {
            tensors: 1,
            ..exact
        },
    ] {
        assert_eq!(
            transform_onnx_image(import(SOURCE)?, "image", value, limits, &|| false).err(),
            Some(OnnxError::Limit)
        );
    }
    assert_eq!(
        transform_onnx_image(
            import(SOURCE)?,
            "image",
            value,
            OnnxLimits {
                work_units: complete.work_units() - 1,
                ..exact
            },
            &|| false
        )
        .err(),
        Some(OnnxError::WorkBudget)
    );
    assert!(complete.work_units() > original.work_units());
    Ok(())
}

#[test]
fn cancellation_is_observed_before_during_and_after_graph_rewriting() -> Test {
    let value = transform(OnnxChannelOrder::Bgr, true);
    let count = Cell::new(0_usize);
    transform_onnx_image(
        import(SOURCE)?,
        "image",
        value,
        OnnxLimits::default(),
        &|| {
            count.set(count.get() + 1);
            false
        },
    )?;
    for boundary in [1, count.get() / 2, count.get()] {
        let calls = Cell::new(0_usize);
        assert_eq!(
            transform_onnx_image(
                import(SOURCE)?,
                "image",
                value,
                OnnxLimits::default(),
                &|| {
                    calls.set(calls.get() + 1);
                    calls.get() >= boundary
                }
            )
            .err(),
            Some(OnnxError::Cancelled)
        );
    }
    Ok(())
}

#[test]
fn only_declared_runtime_image_inputs_can_be_transformed() -> Test {
    for input in ["missing", "weights", "means", "head"] {
        assert_eq!(
            transform_onnx_image(
                import(SOURCE)?,
                input,
                transform(OnnxChannelOrder::Rgb, true),
                OnnxLimits::default(),
                &|| false
            )
            .err(),
            Some(OnnxError::Graph)
        );
    }
    // Repeated explicit composition keeps every prior generated name/parameter distinct.
    let value = transform(OnnxChannelOrder::Bgr, true);
    let first = adapted(SOURCE, value)?;
    let first_count = first.parameters().len();
    let second = transform_onnx_image(first, "image", value, OnnxLimits::default(), &|| false)?;
    assert_eq!(second.parameters().len(), first_count + 2);
    assert!(export(&second).is_ok());
    Ok(())
}

fn varint(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        bytes.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 {
            return bytes;
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
fn info(name: &str, dimensions: &[usize]) -> Vec<u8> {
    let shape: Vec<_> = dimensions
        .iter()
        .flat_map(|&n| bytes(1, &integer(1, n as u64)))
        .collect();
    let tensor = [integer(1, 1), bytes(2, &shape)].concat();
    [bytes(1, name.as_bytes()), bytes(2, &bytes(1, &tensor))].concat()
}
fn small_source(dimensions: &[usize], direct: bool, control: bool, collision: bool) -> Vec<u8> {
    let parameter = if control {
        "shape"
    } else {
        "fss:image-preprocess:mean"
    };
    let mut inputs = bytes(1, b"image");
    if control || collision {
        inputs.extend(bytes(1, parameter.as_bytes()));
    }
    let op = if control {
        "Reshape"
    } else if collision {
        "Add"
    } else {
        "Identity"
    };
    let node = bytes(
        1,
        &[inputs, bytes(2, b"output"), bytes(4, op.as_bytes())].concat(),
    );
    let mut graph = [
        node,
        bytes(11, &info("image", dimensions)),
        bytes(
            12,
            &info(if direct { "image" } else { "output" }, dimensions),
        ),
    ]
    .concat();
    if control || collision {
        let dims: &[usize] = if control { &[4] } else { &[1, 3, 1, 1] };
        let values: Vec<_> = if control {
            [1_i64, 3, 2, 2]
                .into_iter()
                .flat_map(i64::to_le_bytes)
                .collect()
        } else {
            [1.0_f32, 2.0, 3.0]
                .into_iter()
                .flat_map(f32::to_le_bytes)
                .collect()
        };
        let tensor = [
            dims.iter().flat_map(|&n| integer(1, n as u64)).collect(),
            integer(2, if control { 7 } else { 1 }),
            bytes(8, parameter.as_bytes()),
            bytes(9, &values),
        ]
        .concat();
        graph.extend(bytes(5, &tensor));
    }
    [integer(1, 8), bytes(7, &graph), bytes(8, &integer(2, 13))].concat()
}

#[test]
fn unsupported_input_shapes_and_direct_input_outputs_refuse_without_aliasing() -> Test {
    for dims in [vec![1, 1, 2, 2], vec![2, 3, 2, 2], vec![1, 3, 4]] {
        let source = small_source(&dims, false, false, false);
        assert_eq!(
            transform_onnx_image(
                import(&source)?,
                "image",
                transform(OnnxChannelOrder::Rgb, true),
                OnnxLimits::default(),
                &|| false
            )
            .err(),
            Some(OnnxError::Unsupported)
        );
    }
    let source = small_source(&[1, 3, 2, 2], true, false, false);
    assert_eq!(
        transform_onnx_image(
            import(&source)?,
            "image",
            transform(OnnxChannelOrder::Rgb, true),
            OnnxLimits::default(),
            &|| false
        )
        .err(),
        Some(OnnxError::Unsupported)
    );
    Ok(())
}

#[test]
fn discarded_int64_controls_remain_charged_and_source_parameter_names_cannot_collide() -> Test {
    let source = small_source(&[1, 3, 2, 2], false, true, false);
    assert!(import(&source)?.parameters().is_empty());
    let value = transform(OnnxChannelOrder::Bgr, true);
    let exact = OnnxLimits {
        parameter_bytes: 32 + 24,
        ..OnnxLimits::default()
    };
    assert!(transform_onnx_image(import(&source)?, "image", value, exact, &|| false).is_ok());
    assert_eq!(
        transform_onnx_image(
            import(&source)?,
            "image",
            value,
            OnnxLimits {
                parameter_bytes: 55,
                ..exact
            },
            &|| false
        )
        .err(),
        Some(OnnxError::Limit)
    );
    let source = small_source(&[1, 3, 2, 2], false, false, true);
    let converted = adapted(&source, value)?;
    assert_eq!(
        converted.parameters()["fss:image-preprocess:mean"].to_vec::<f32>()?,
        [1.0, 2.0, 3.0]
    );
    assert_eq!(
        converted.parameters()["fss:image-preprocess:mean-1"].to_vec::<f32>()?,
        value.mean
    );
    let result = run(&export(&converted)?, resized(&PIXELS, true)?)?;
    let (mut expected, _) = oracle(&PIXELS, value, true);
    for (channel, plane) in expected.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        for pixel in plane {
            *pixel += (channel + 1) as f32;
        }
    }
    assert_eq!(bits(&result["output"]), bits(&expected));
    Ok(())
}
