#![forbid(unsafe_code)]
//! ONNX Resize-13 -> native artifacts -> unchanged scalar/optimized execution.
//! The production Safetensors parser is included unchanged with its small data-only
//! host types below. This isolates the actual parser/kernel path from unrelated async
//! dependencies; it does not claim to compile the full reference crate or package CLI.

use std::cell::Cell;
use std::collections::BTreeMap;

use fss_core::{ContentDigest, Generation};
use fss_model_ir::{
    ImportedOnnx, OnnxArtifacts, OnnxError, OnnxExportLimits, OnnxLimits,
    decode_canonical_model_ir, encode_canonical_model_ir, export_onnx_artifacts, import_onnx,
};
use fss_tensor::{Shape, Tensor};

#[path = "../../fss-reference/src/ingest/model_import/safetensors.rs"]
mod safetensors;
#[path = "../../fss-reference/src/scalar_executor.rs"]
pub mod scalar_executor;
pub use scalar_executor::{
    ExecBudget, ExecError, ExecOutcome, ScalarExecCx, ScalarExecutor, deterministic_sigmoid_f32,
};
#[path = "../../fss-reference/src/optimized_executor.rs"]
pub mod optimized_executor;
#[path = "onnx_resize_execution/linear.rs"]
mod linear;

// These are only the limits, refusal variants and policy expected by the unchanged
// production parser. All byte parsing, escaping, span checks and F32 decoding are
// provided by that included production module, not by a test implementation.
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
const GENERATION: Generation = Generation(17);

fn varint(mut value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        output.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 {
            return output;
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
fn info(name: &str, dimensions: &[u64]) -> Vec<u8> {
    let shape: Vec<_> = dimensions
        .iter()
        .flat_map(|&n| bytes(1, &integer(1, n)))
        .collect();
    let tensor = [integer(1, 1), bytes(2, &shape)].concat();
    [bytes(1, name.as_bytes()), bytes(2, &bytes(1, &tensor))].concat()
}
fn weight(name: &str, dimensions: &[u64], values: &[f32]) -> Vec<u8> {
    bytes(
        5,
        &[
            dimensions.iter().flat_map(|&n| integer(1, n)).collect(),
            integer(2, 1),
            bytes(8, name.as_bytes()),
            bytes(
                9,
                &values
                    .iter()
                    .flat_map(|value| value.to_le_bytes())
                    .collect::<Vec<_>>(),
            ),
        ]
        .concat(),
    )
}
fn attribute(name: &str, kind: u64, payload: &[u8]) -> Vec<u8> {
    bytes(
        5,
        &[
            bytes(1, name.as_bytes()),
            integer(20, kind),
            payload.to_vec(),
        ]
        .concat(),
    )
}
fn float_attribute(name: &str, value: f32) -> Vec<u8> {
    attribute(
        name,
        1,
        &[varint(2 * 8 + 5), value.to_le_bytes().to_vec()].concat(),
    )
}
fn node(op: &str, inputs: &[&str], output: &str, attributes: &[u8]) -> Vec<u8> {
    bytes(
        1,
        &[
            inputs
                .iter()
                .flat_map(|name| bytes(1, name.as_bytes()))
                .collect(),
            bytes(2, output.as_bytes()),
            bytes(4, op.as_bytes()),
            attributes.to_vec(),
        ]
        .concat(),
    )
}
fn model(graph: &[u8]) -> Vec<u8> {
    [integer(1, 8), bytes(8, &integer(2, 13)), bytes(7, graph)].concat()
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
fn export<'a>(imported: &ImportedOnnx<'a>) -> Test<OnnxArtifacts<'a>> {
    Ok(export_onnx_artifacts(
        imported,
        OnnxExportLimits::default(),
        &|| false,
    )?)
}
fn parsed<'a>(artifacts: &'a OnnxArtifacts<'_>) -> Test<safetensors::Weights<'a>> {
    Ok(safetensors::Weights::parse(
        artifacts.weights_bytes(),
        &ImportLimits {
            maximum_header_bytes: 256 * 1024,
            maximum_tensors: 256,
        },
    )?)
}
fn reloaded(artifacts: &OnnxArtifacts<'_>) -> Test<BTreeMap<String, Tensor>> {
    let weights = parsed(artifacts)?;
    let mut output = BTreeMap::new();
    for (name, entry) in &weights.entries {
        let values = weights.data[entry.start..entry.end]
            .chunks_exact(entry.width())
            .map(|bytes| safetensors::value(entry.dtype, bytes, WeightFloatPolicy::F32Only))
            .collect::<Result<Vec<_>, _>>()?;
        output.insert(
            name.clone(),
            Tensor::from_values(Shape::new(entry.shape.clone())?, &values, GENERATION)?,
        );
    }
    Ok(output)
}
fn run(artifacts: &OnnxArtifacts<'_>, input: &[(&str, Tensor)], output: &str) -> Test<Vec<f32>> {
    let graph = decode_canonical_model_ir(artifacts.graph_bytes(), artifacts.graph_digest())?;
    assert_eq!(encode_canonical_model_ir(&graph)?, artifacts.graph_bytes());
    let mut inputs: Vec<_> = reloaded(artifacts)?.into_iter().collect();
    inputs.extend(
        input
            .iter()
            .map(|(name, tensor)| ((*name).to_owned(), tensor.clone())),
    );
    let result = scalar_executor::ScalarExecutor::run(
        &graph,
        &inputs,
        scalar_executor::ExecBudget::unlimited(),
        &scalar_executor::ScalarExecCx::new(),
    )?;
    Ok(result
        .get_output(output)
        .ok_or("missing output")?
        .to_vec::<f32>()?)
}
fn bits(values: &[f32]) -> Vec<u32> {
    values.iter().map(|value| value.to_bits()).collect()
}

fn int_weight(name: &str, values: &[i64]) -> Vec<u8> {
    bytes(
        5,
        &[
            integer(1, values.len() as u64),
            integer(2, 7),
            bytes(8, name.as_bytes()),
            bytes(
                9,
                &values
                    .iter()
                    .flat_map(|n| n.to_le_bytes())
                    .collect::<Vec<_>>(),
            ),
        ]
        .concat(),
    )
}
fn text_attr(name: &str, value: &str) -> Vec<u8> {
    attribute(name, 3, &bytes(4, value.as_bytes()))
}
fn ints_attr(name: &str, values: &[i64]) -> Vec<u8> {
    attribute(
        name,
        7,
        &values
            .iter()
            .flat_map(|&v| integer(8, v as u64))
            .collect::<Vec<_>>(),
    )
}
fn asymmetric() -> Vec<u8> {
    [
        text_attr("coordinate_transformation_mode", "asymmetric"),
        text_attr("nearest_mode", "floor"),
    ]
    .concat()
}
fn resize_graph(
    dims: [u64; 4],
    output: [u64; 4],
    inputs: &[&str],
    controls: &[u8],
    attrs: &[u8],
) -> Vec<u8> {
    model(
        &[
            node("Resize", inputs, "output", attrs),
            controls.to_vec(),
            bytes(11, &info("input", &dims)),
            bytes(12, &info("output", &output)),
        ]
        .concat(),
    )
}
fn reject(source: &[u8], expected: OnnxError) {
    assert_eq!(
        import_onnx(
            source,
            ContentDigest::sha256(source),
            GENERATION,
            OnnxLimits::default(),
            &|| false
        )
        .err(),
        Some(expected)
    );
}

// Independent coordinate-formula oracle, deliberately not a reshape/concat
// implementation. For the small dimensions used here, these rationals are exact
// enough in f64 to exclude any midpoint ambiguity in half-pixel nearest rounding.
fn coordinate_oracle(
    input: &[f32],
    dims: [usize; 4],
    factors: [usize; 2],
    half_pixel: bool,
) -> Vec<f32> {
    let [batch, channels, height, width] = dims;
    let [sh, sw] = factors;
    let source = |p: usize, scale: usize, length: usize| {
        let x = if half_pixel {
            (p as f64 + 0.5) / scale as f64 - 0.5
        } else {
            p as f64 / scale as f64
        };
        let nearest = if half_pixel {
            (x - 0.5).ceil()
        } else {
            x.floor()
        };
        nearest.max(0.0).min((length - 1) as f64) as usize
    };
    let mut out = Vec::new();
    for n in 0..batch {
        for c in 0..channels {
            for y in 0..height * sh {
                for x in 0..width * sw {
                    let (sy, sx) = (source(y, sh, height), source(x, sw, width));
                    out.push(input[((n * channels + c) * height + sy) * width + sx]);
                }
            }
        }
    }
    out
}

#[test]
fn scales_and_sizes_replay_exact_nearest_pixels_for_both_coordinate_profiles() -> Test {
    let dims = [2_usize, 2, 2, 3];
    let input: Vec<f32> = (0..24)
        .map(|v| match v {
            0 => -0.0,
            1 => f32::from_bits(1),
            2 => f32::MIN,
            3 => f32::MAX,
            _ => (v as f32 - 12.0) / 8.0,
        })
        .collect();
    for half_pixel in [false, true] {
        for sh in 1..=5 {
            for sw in 1..=5 {
                let attrs = if half_pixel { Vec::new() } else { asymmetric() };
                let output = [2, 2, 2 * sh, 3 * sw];
                let expected =
                    coordinate_oracle(&input, dims, [sh as usize, sw as usize], half_pixel);
                for use_sizes in [false, true] {
                    let controls = if use_sizes {
                        [
                            weight("roi", &[0], &[]),
                            weight("scales", &[0], &[]),
                            int_weight("sizes", &output.map(|d| d as i64)),
                        ]
                        .concat()
                    } else {
                        [
                            weight("roi", &[0], &[]),
                            weight("scales", &[4], &[1., 1., sh as f32, sw as f32]),
                        ]
                        .concat()
                    };
                    let inputs = if use_sizes {
                        vec!["input", "roi", "scales", "sizes"]
                    } else {
                        vec!["input", "roi", "scales"]
                    };
                    let source =
                        resize_graph(dims.map(|d| d as u64), output, &inputs, &controls, &attrs);
                    let imported = import(&source)?;
                    assert!(
                        imported.parameters().is_empty(),
                        "shape controls must not be execution weights"
                    );
                    assert_eq!(imported.runtime_inputs(), ["input"]);
                    let artifacts = export(&imported)?;
                    assert_eq!(artifacts.source(), source);
                    assert_eq!(artifacts.source_digest(), ContentDigest::sha256(&source));
                    assert!(reloaded(&artifacts)?.is_empty());
                    let tensor =
                        Tensor::from_values(Shape::new(dims.to_vec())?, &input, GENERATION)?;
                    assert_eq!(
                        bits(&run(&artifacts, &[("input", tensor)], "output")?),
                        bits(&expected)
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn convolution_feature_map_upsampling_becomes_an_executable_dense_head() -> Test {
    let source = model(
        &[
            node("Conv", &["image", "kernel"], "features", &[]),
            // Empty ONNX optional names are distinct from runtime zero-sized tensors.
            node(
                "Resize",
                &["features", "", "scales"],
                "upsampled",
                &asymmetric(),
            ),
            node(
                "Transpose",
                &["upsampled"],
                "nhwc",
                &ints_attr("perm", &[0, 2, 3, 1]),
            ),
            node("Reshape", &["nhwc", "head_shape"], "head", &[]),
            weight(
                "kernel",
                &[6, 3, 1, 1],
                &[
                    1., 0., 0., 0., 1., 0., 0., 0., 1., 0.5, 0., 0., 0., 0.5, 0., 0., 0., 0.5,
                ],
            ),
            weight("scales", &[4], &[1., 1., 2., 3.]),
            int_weight("head_shape", &[1, 24, 6]),
            bytes(11, &info("image", &[1, 3, 2, 2])),
            bytes(12, &info("head", &[1, 24, 6])),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    assert_eq!(
        imported
            .parameters()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["kernel"]
    );
    let artifacts = export(&imported)?;
    assert_eq!(reloaded(&artifacts)?.len(), 1);
    let image = [1., 2., 3., 4., 10., 20., 30., 40., 100., 200., 300., 400.];
    let input = Tensor::from_values(Shape::new(vec![1, 3, 2, 2])?, &image, GENERATION)?;
    let result = run(&artifacts, &[("image", input)], "head")?;
    let mut expected = Vec::new();
    for y in 0..4 {
        for x in 0..6 {
            let pixel = (y / 2) * 2 + x / 3;
            let rgb = [image[pixel], image[4 + pixel], image[8 + pixel]];
            expected.extend(rgb);
            expected.extend(rgb.map(|v| v * 0.5));
        }
    }
    assert_eq!(bits(&result), bits(&expected));
    Ok(())
}

#[test]
fn unsupported_interpolation_coordinate_profiles_and_dynamic_controls_refuse() {
    let controls = weight("scales", &[4], &[1., 1., 2., 2.]);
    for attrs in [
        text_attr("mode", "cubic"),
        text_attr("coordinate_transformation_mode", "align_corners"),
        text_attr("coordinate_transformation_mode", "tf_crop_and_resize"),
        text_attr("nearest_mode", "ceil"),
        text_attr("nearest_mode", "floor"),
        text_attr("coordinate_transformation_mode", "asymmetric"),
        attribute("exclude_outside", 2, &integer(3, 1)),
        attribute("antialias", 2, &integer(3, 0)),
    ] {
        reject(
            &resize_graph(
                [1, 1, 2, 2],
                [1, 1, 4, 4],
                &["input", "", "scales"],
                &controls,
                &attrs,
            ),
            OnnxError::Unsupported,
        );
    }
    for scales in [
        [1., 1., 0.25, 2.], // A zero output extent stays outside the profile.
        [1., 1., 65., 2.],
        [2., 1., 2., 2.],
        [1., 2., 2., 2.],
        [1., 1., 0., 2.],
    ] {
        reject(
            &resize_graph(
                [1, 1, 2, 2],
                [1, 1, 4, 4],
                &["input", "", "scales"],
                &weight("scales", &[4], &scales),
                &[],
            ),
            OnnxError::Unsupported,
        );
    }
    let dynamic = model(
        &[
            node("Resize", &["input", "", "scales"], "output", &[]),
            bytes(11, &info("input", &[1, 1, 2, 2])),
            bytes(11, &info("scales", &[4])),
            bytes(12, &info("output", &[1, 1, 4, 4])),
        ]
        .concat(),
    );
    assert!(import(&dynamic).is_err());
}

#[test]
fn optional_inputs_sizes_and_declared_output_are_strictly_checked() {
    let good = weight("scales", &[4], &[1., 1., 2., 2.]);
    for controls in [Vec::new(), weight("scales", &[0], &[])] {
        let scale = if controls.is_empty() { "" } else { "scales" };
        reject(
            &resize_graph(
                [1, 1, 2, 2],
                [1, 1, 4, 4],
                &["input", "", scale],
                &controls,
                &[],
            ),
            OnnxError::Graph,
        );
    }
    reject(
        &resize_graph(
            [1, 1, 2, 2],
            [1, 1, 4, 4],
            &["input", "", "scales", "sizes"],
            &[good.clone(), int_weight("sizes", &[1, 1, 4, 4])].concat(),
            &[],
        ),
        OnnxError::Graph,
    );
    reject(
        &resize_graph(
            [1, 1, 2, 2],
            [1, 1, 4, 4],
            &["input", "roi", "scales"],
            &[
                good.clone(),
                weight("roi", &[8], &[0., 0., 0., 0., 1., 1., 1., 1.]),
            ]
            .concat(),
            &[],
        ),
        OnnxError::Unsupported,
    );
    for sizes in [vec![1, 1, 4], vec![1, 1, 4, 4, 1]] {
        reject(
            &resize_graph(
                [1, 1, 2, 2],
                [1, 1, 4, 4],
                &["input", "", "", "sizes"],
                &int_weight("sizes", &sizes),
                &[],
            ),
            OnnxError::Graph,
        );
    }
    for sizes in [
        [2, 1, 4, 4],
        [1, 1, 0, 4],
        [1, 1, -4, 4],
        [1, 1, 130, 4],
    ] {
        reject(
            &resize_graph(
                [1, 1, 2, 2],
                [1, 1, 4, 4],
                &["input", "", "", "sizes"],
                &int_weight("sizes", &sizes),
                &[],
            ),
            OnnxError::Unsupported,
        );
    }
    reject(
        &resize_graph(
            [1, 1, 2, 2],
            [1, 1, 4, 5],
            &["input", "", "scales"],
            &good,
            &[],
        ),
        OnnxError::Graph,
    );
    let mistyped = attribute("mode", 2, &integer(3, 0));
    reject(
        &resize_graph(
            [1, 1, 2, 2],
            [1, 1, 4, 4],
            &["input", "", "scales"],
            &good,
            &mistyped,
        ),
        OnnxError::Graph,
    );
}

#[test]
fn lowering_enforces_expansion_tensor_work_and_cancellation_limits() -> Test {
    let source = resize_graph(
        [1, 1, 2, 2],
        [1, 1, 4, 4],
        &["input", "", "scales"],
        &weight("scales", &[4], &[1., 1., 2., 2.]),
        &[],
    );
    let imported = import(&source)?;
    let work = imported.work_units();
    for limits in [
        OnnxLimits {
            nodes: 3,
            ..OnnxLimits::default()
        },
        OnnxLimits {
            tensor_bytes: 63,
            ..OnnxLimits::default()
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
    for (limit, succeeds) in [(work - 1, false), (work, true)] {
        let result = import_onnx(
            &source,
            ContentDigest::sha256(&source),
            GENERATION,
            OnnxLimits {
                work_units: limit,
                ..OnnxLimits::default()
            },
            &|| false,
        );
        assert_eq!(result.is_ok(), succeeds);
        if !succeeds {
            assert_eq!(result.err(), Some(OnnxError::WorkBudget));
        }
    }
    let calls = Cell::new(0);
    assert!(
        import_onnx(
            &source,
            ContentDigest::sha256(&source),
            GENERATION,
            OnnxLimits::default(),
            &|| {
                calls.set(calls.get() + 1);
                false
            }
        )
        .is_ok()
    );
    let total = calls.get();
    for stop in [1, total / 2, total - 1] {
        calls.set(0);
        assert_eq!(
            import_onnx(
                &source,
                ContentDigest::sha256(&source),
                GENERATION,
                OnnxLimits::default(),
                &|| {
                    calls.set(calls.get() + 1);
                    calls.get() >= stop
                }
            )
            .err(),
            Some(OnnxError::Cancelled)
        );
    }
    Ok(())
}

#[test]
fn helper_names_cannot_alias_later_source_values() -> Test {
    let source = model(
        &[
            node("Resize", &["input", "", "scales"], "output", &[]),
            node("Relu", &["output"], "onnx-node-0000-resize-unit", &[]),
            weight("scales", &[4], &[1., 1., 2., 2.]),
            bytes(11, &info("input", &[1, 1, 1, 1])),
            bytes(12, &info("onnx-node-0000-resize-unit", &[1, 1, 2, 2])),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    let names: Vec<_> = imported
        .graph()
        .nodes()
        .iter()
        .flat_map(|node| node.outputs())
        .collect();
    let unique: std::collections::BTreeSet<_> = names.iter().collect();
    assert_eq!(names.len(), unique.len());
    let artifacts = export(&imported)?;
    let input = Tensor::from_values(Shape::new(vec![1, 1, 1, 1])?, &[-2_f32], GENERATION)?;
    assert_eq!(
        run(
            &artifacts,
            &[("input", input)],
            "onnx-node-0000-resize-unit"
        )?,
        [0., 0., 0., 0.]
    );
    Ok(())
}

#[test]
fn exporter_constant_nodes_and_unused_mode_defaults_are_admitted_without_losing_data_uses() -> Test
{
    let float_tensor = |dims: &[u64], values: &[f32]| {
        [
            dims.iter().flat_map(|&n| integer(1, n)).collect(),
            integer(2, 1),
            bytes(
                9,
                &values
                    .iter()
                    .flat_map(|v| v.to_le_bytes())
                    .collect::<Vec<_>>(),
            ),
        ]
        .concat()
    };
    let constant = |name: &str, dims: &[u64], values: &[f32]| {
        node(
            "Constant",
            &[],
            name,
            &attribute("value", 4, &bytes(5, &float_tensor(dims, values))),
        )
    };
    let defaults = [
        float_attribute("cubic_coeff_a", -0.75),
        float_attribute("extrapolation_value", 0.0),
    ]
    .concat();
    let source = model(
        &[
            constant("roi", &[0], &[]),
            constant("scales", &[4], &[1., 1., 2., 3.]),
            node("Resize", &["input", "roi", "scales"], "output", &defaults),
            node("Identity", &["scales"], "echo", &[]),
            bytes(11, &info("input", &[1, 1, 1, 1])),
            bytes(12, &info("output", &[1, 1, 2, 3])),
            bytes(12, &info("echo", &[4])),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    assert_eq!(
        imported
            .parameters()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["scales"]
    );
    let artifacts = export(&imported)?;
    let input = Tensor::from_values(Shape::new(vec![1, 1, 1, 1])?, &[7_f32], GENERATION)?;
    assert_eq!(
        run(&artifacts, &[("input", input.clone())], "output")?,
        [7., 7., 7., 7., 7., 7.]
    );
    assert_eq!(
        run(&artifacts, &[("input", input)], "echo")?,
        [1., 1., 2., 3.]
    );
    Ok(())
}

// Coordinate-formula oracle follows the Resize-13 definition directly, without
// integer ratios, run partitioning, Slice or Concat. Literal boundary cases below
// separately pin exact ties and adjacent F32 scales.
fn resampling_oracle(
    input: &[f32],
    dims: [usize; 4],
    output: [usize; 4],
    scales: [f64; 2],
    half_pixel: bool,
) -> Vec<f32> {
    let selected = |position: usize, scale: f64, length: usize| {
        let coordinate = if half_pixel {
            (position as f64 + 0.5) / scale - 0.5
        } else {
            position as f64 / scale
        };
        let rounded = if half_pixel {
            (coordinate - 0.5).ceil()
        } else {
            coordinate.floor()
        };
        rounded.max(0.0).min((length - 1) as f64) as usize
    };
    let mut values = Vec::new();
    for batch in 0..output[0] {
        for channel in 0..output[1] {
            for y in 0..output[2] {
                for x in 0..output[3] {
                    let sy = selected(y, scales[0], dims[2]);
                    let sx = selected(x, scales[1], dims[3]);
                    values.push(input[((batch * dims[1] + channel) * dims[2] + sy) * dims[3] + sx]);
                }
            }
        }
    }
    values
}

#[test]
fn fractional_scales_and_sizes_execute_exact_pixels_after_artifact_reload() -> Test {
    for dims in [[2, 2, 3, 5], [1, 3, 5, 7], [1, 1, 1, 3]] {
        let length = dims.iter().product::<usize>();
        let mut values: Vec<_> = (0..length).map(|n| n as f32 - 9.0).collect();
        for (target, special) in values.iter_mut().zip([
            -0.0,
            0.0,
            f32::from_bits(1),
            f32::MIN_POSITIVE,
            f32::MAX,
            f32::MIN,
        ]) {
            *target = special;
        }
        for scales in [
            [0.5_f32, 0.75],
            [0.75, 1.5],
            [1.5, 0.5],
            [2.5, 1.25],
            [1.0, 0.6],
            [0.6, 1.0],
            [2.0, 0.75],
            [0.75, 2.0],
            [3.5, 1.0],
            [1.0, 3.5],
        ] {
            let output = [
                dims[0],
                dims[1],
                (dims[2] as f64 * f64::from(scales[0])).floor() as usize,
                (dims[3] as f64 * f64::from(scales[1])).floor() as usize,
            ];
            if output.contains(&0) {
                continue;
            }
            for half_pixel in [false, true] {
                for sizes in [false, true] {
                    let (controls, inputs, oracle_scales) = if sizes {
                        (
                            int_weight("sizes", &output.map(|n| n as i64)),
                            vec!["input", "", "", "sizes"],
                            [
                                output[2] as f64 / dims[2] as f64,
                                output[3] as f64 / dims[3] as f64,
                            ],
                        )
                    } else {
                        (
                            weight("scales", &[4], &[1., 1., scales[0], scales[1]]),
                            vec!["input", "", "scales"],
                            scales.map(f64::from),
                        )
                    };
                    let source = resize_graph(
                        dims.map(|n| n as u64),
                        output.map(|n| n as u64),
                        &inputs,
                        &controls,
                        &if half_pixel { Vec::new() } else { asymmetric() },
                    );
                    let imported = import(&source)?;
                    assert!(imported.parameters().is_empty());
                    let artifacts = export(&imported)?;
                    let input =
                        Tensor::from_values(Shape::new(dims.to_vec())?, &values, GENERATION)?;
                    assert_eq!(
                        bits(&run(&artifacts, &[("input", input)], "output")?),
                        bits(&resampling_oracle(
                            &values,
                            dims,
                            output,
                            oracle_scales,
                            half_pixel
                        )),
                        "dims={dims:?}, scales={scales:?}, sizes={sizes}, half_pixel={half_pixel}"
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn original_scale_rounding_ties_and_adjacent_f32_values_select_the_right_samples() -> Test {
    // Original scale .6 and derived size 4/7 have the same output extent but
    // different selected pixels. Nearest ties must round down exactly.
    for (length, scale, half_pixel, expected) in [
        (7, 0.6, false, vec![0., 1., 3., 4.]),
        (7, 0.6, true, vec![0., 2., 4., 5.]),
        (5, 1.5, true, vec![0., 0., 1., 2., 2., 3., 4.]),
        (
            5,
            f32::from_bits(1.5_f32.to_bits() - 1),
            true,
            vec![0., 1., 1., 2., 3., 3., 4.],
        ),
        (
            5,
            f32::from_bits(1.5_f32.to_bits() + 1),
            true,
            vec![0., 0., 1., 2., 2., 3., 4.],
        ),
        (7, 0.5, false, vec![0., 2., 4.]),
        (7, 0.5, true, vec![0., 2., 4.]),
        (9, 0.25, false, vec![0., 4.]),
        (9, 0.25, true, vec![1., 5.]),
        (4, 1.125, false, vec![0., 0., 1., 2.]),
        (4, 1.125, true, vec![0., 1., 2., 3.]),
        (
            4,
            f32::from_bits(1.0_f32.to_bits() + 1),
            false,
            vec![0., 0., 1., 2.],
        ),
        (
            7,
            f32::from_bits(0.5_f32.to_bits() + 1),
            false,
            vec![0., 1., 3.],
        ),
        (1, 63.5, true, vec![0.; 63]),
    ] {
        let source = resize_graph(
            [1, 1, 1, length],
            [1, 1, 1, expected.len() as u64],
            &["input", "", "scales"],
            &weight("scales", &[4], &[1., 1., 1., scale]),
            &if half_pixel { Vec::new() } else { asymmetric() },
        );
        let values: Vec<_> = (0..length).map(|n| n as f32).collect();
        let input = Tensor::from_values(
            Shape::new(vec![1, 1, 1, length as usize])?,
            &values,
            GENERATION,
        )?;
        assert_eq!(
            run(&export(&import(&source)?)?, &[("input", input)], "output")?,
            expected
        );
    }
    for (half_pixel, expected) in [(false, vec![0., 1., 3., 5.]), (true, vec![0., 2., 4., 6.])] {
        let source = resize_graph(
            [1, 1, 1, 7],
            [1, 1, 1, 4],
            &["input", "", "", "sizes"],
            &int_weight("sizes", &[1, 1, 1, 4]),
            &if half_pixel { Vec::new() } else { asymmetric() },
        );
        let input = Tensor::from_values(
            Shape::new(vec![1, 1, 1, 7])?,
            &[0.0_f32, 1., 2., 3., 4., 5., 6.],
            GENERATION,
        )?;
        assert_eq!(
            run(&export(&import(&source)?)?, &[("input", input)], "output")?,
            expected
        );
    }
    Ok(())
}

#[test]
fn compact_strided_downsampling_and_mixed_directions_fit_the_actual_tensor_budget() -> Test {
    for scales in [[0.5, 2.0], [2.0, 0.5]] {
        let output = [1, 1, (4. * scales[0]) as u64, (4. * scales[1]) as u64];
        let source = resize_graph(
            [1, 1, 4, 4],
            output,
            &["input", "", "scales"],
            &weight("scales", &[4], &[1., 1., scales[0], scales[1]]),
            &[],
        );
        let imported = import_onnx(
            &source,
            ContentDigest::sha256(&source),
            GENERATION,
            OnnxLimits {
                tensor_bytes: 64,
                ..OnnxLimits::default()
            },
            &|| false,
        )?;
        let values: Vec<_> = (0..16).map(|n| n as f32).collect();
        let input = Tensor::from_values(Shape::new(vec![1, 1, 4, 4])?, &values, GENERATION)?;
        assert_eq!(
            run(&export(&imported)?, &[("input", input)], "output")?,
            resampling_oracle(
                &values,
                [1, 1, 4, 4],
                output.map(|n| n as usize),
                scales.map(f64::from),
                true
            )
        );
        assert_eq!(
            imported.graph().nodes()[0].op(),
            fss_model_ir::OpCode::Slice
        );
    }
    let source = resize_graph(
        [1, 1, 480, 640],
        [1, 1, 240, 320],
        &["input", "", "scales"],
        &weight("scales", &[4], &[1., 1., 0.5, 0.5]),
        &[],
    );
    let imported = import_onnx(
        &source,
        ContentDigest::sha256(&source),
        GENERATION,
        OnnxLimits {
            nodes: 2,
            ..OnnxLimits::default()
        },
        &|| false,
    )?;
    assert_eq!(imported.graph().node_count(), 2);
    let values: Vec<_> = (0..480 * 640).map(|n| n as f32).collect();
    let input = Tensor::from_values(Shape::new(vec![1, 1, 480, 640])?, &values, GENERATION)?;
    assert_eq!(
        run(&export(&imported)?, &[("input", input)], "output")?,
        resampling_oracle(
            &values,
            [1, 1, 480, 640],
            [1, 1, 240, 320],
            [0.5, 0.5],
            true
        )
    );
    Ok(())
}

#[test]
fn fractional_expansion_enforces_coordinate_node_tensor_and_work_boundaries() -> Test {
    let source = resize_graph(
        [1, 1, 3, 5],
        [1, 1, 4, 12],
        &["input", "", "scales"],
        &weight("scales", &[4], &[1., 1., 1.5, 2.5]),
        &[],
    );
    let imported = import(&source)?;
    let nodes = imported.graph().node_count();
    for (limits, error) in [
        (
            OnnxLimits {
                nodes: nodes - 1,
                ..OnnxLimits::default()
            },
            OnnxError::Limit,
        ),
        (
            OnnxLimits {
                tensors: nodes + 1,
                ..OnnxLimits::default()
            },
            OnnxError::Limit,
        ),
        (
            OnnxLimits {
                tensor_bytes: 191,
                ..OnnxLimits::default()
            },
            OnnxError::Limit,
        ),
        (
            OnnxLimits {
                work_units: imported.work_units() - 1,
                ..OnnxLimits::default()
            },
            OnnxError::WorkBudget,
        ),
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
            Some(error)
        );
    }
    let exact = import_onnx(
        &source,
        ContentDigest::sha256(&source),
        GENERATION,
        OnnxLimits {
            nodes,
            tensors: nodes + 2,
            tensor_bytes: 192,
            work_units: imported.work_units(),
            ..OnnxLimits::default()
        },
        &|| false,
    )?;
    assert_eq!(
        encode_canonical_model_ir(exact.graph())?,
        encode_canonical_model_ir(imported.graph())?
    );

    // A simple run can fill the coordinate ceiling. A larger run still refuses
    // before planning; the historical integer path keeps its original bound.
    for (input_width, output_width, scale, succeeds) in [
        (8192, 4096, 0.5, true),
        (8194, 4097, 0.5, false),
        (4097, 8194, 2.0, true),
    ] {
        for sizes in [false, true] {
            let (inputs, controls) = if sizes {
                (
                    vec!["input", "", "", "sizes"],
                    int_weight("sizes", &[1, 1, 1, output_width]),
                )
            } else {
                (
                    vec!["input", "", "scales"],
                    weight("scales", &[4], &[1., 1., 1., scale]),
                )
            };
            let source = resize_graph(
                [1, 1, 1, input_width],
                [1, 1, 1, output_width as u64],
                &inputs,
                &controls,
                &[],
            );
            if succeeds {
                let imported = import(&source)?;
                assert_eq!(
                    imported.graph().node_count(),
                    if scale == 2.0 { 4 } else { 1 }
                );
                let values: Vec<_> = (0..input_width).map(|n| n as f32).collect();
                let input = Tensor::from_values(
                    Shape::new(vec![1, 1, 1, input_width as usize])?,
                    &values,
                    GENERATION,
                )?;
                assert_eq!(
                    run(&export(&imported)?, &[("input", input)], "output")?,
                    resampling_oracle(
                        &values,
                        [1, 1, 1, input_width as usize],
                        [1, 1, 1, output_width as usize],
                        [1., f64::from(scale)],
                        true
                    )
                );
            } else {
                reject(&source, OnnxError::Limit);
            }
        }
    }
    reject(
        &resize_graph(
            [1, 1, 600, 600],
            [1, 1, 900, 900],
            &["input", "", "scales"],
            &weight("scales", &[4], &[1., 1., 1.5, 1.5]),
            &[],
        ),
        OnnxError::Limit,
    );
    Ok(())
}

#[test]
fn fractional_planning_cancellation_never_returns_a_partial_artifact() -> Test {
    let source = resize_graph(
        [1, 1, 3, 5],
        [1, 1, 4, 12],
        &["input", "", "scales"],
        &weight("scales", &[4], &[1., 1., 1.5, 2.5]),
        &[],
    );
    let calls = Cell::new(0);
    let baseline = import_onnx(
        &source,
        ContentDigest::sha256(&source),
        GENERATION,
        OnnxLimits::default(),
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
                OnnxLimits::default(),
                &|| {
                    calls.set(calls.get() + 1);
                    calls.get() == stop
                },
            )
            .err(),
            Some(OnnxError::Cancelled),
            "cancellation checkpoint {stop}/{total}"
        );
    }
    assert_eq!(
        encode_canonical_model_ir(import(&source)?.graph())?,
        encode_canonical_model_ir(baseline.graph())?
    );
    Ok(())
}

#[test]
fn scale_extrema_and_inconsistent_fractional_shapes_refuse_without_unbounded_arithmetic() -> Test {
    for scale in [
        0.0,
        -0.0,
        -1.0,
        f32::from_bits(1),
        f32::from_bits(0x7f_ffff),
        f32::MIN_POSITIVE,
        2.0_f32.powi(-25),
        65.0,
        f32::MAX,
    ] {
        reject(
            &resize_graph(
                [1, 1, 1, 16_777_216],
                [1, 1, 1, 1],
                &["input", "", "scales"],
                &weight("scales", &[4], &[1., 1., 1., scale]),
                &[],
            ),
            OnnxError::Unsupported,
        );
    }
    for scale in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        reject(
            &resize_graph(
                [1, 1, 1, 1],
                [1, 1, 1, 1],
                &["input", "", "scales"],
                &weight("scales", &[4], &[1., 1., 1., scale]),
                &[],
            ),
            OnnxError::NonFinite,
        );
    }
    // Smallest useful dyadic scale at the full tensor-byte ceiling. Inspect the
    // exact selection without allocating a 64 MiB runtime input just for a test.
    for (attrs, selected) in [(asymmetric(), 0), (Vec::new(), 8_388_607)] {
        let source = resize_graph(
            [1, 1, 1, 16_777_216],
            [1, 1, 1, 1],
            &["input", "", "scales"],
            &weight("scales", &[4], &[1., 1., 1., 2.0_f32.powi(-24)]),
            &attrs,
        );
        let imported = import(&source)?;
        assert_eq!(
            imported.graph().nodes()[0].get_attr("starts"),
            Some(&fss_model_ir::AttrValue::IntList(vec![selected]))
        );
    }
    for source in [
        resize_graph(
            [1, 1, 2, 2],
            [1, 1, 4, 4],
            &["input", "", "scales"],
            &weight("scales", &[4], &[1., 1., 1.5, 2.]),
            &[],
        ),
        resize_graph(
            [1, 1, 2, 2],
            [1, 1, 4, 4],
            &["input", "", "", "sizes"],
            &int_weight("sizes", &[1, 1, 3, 4]),
            &[],
        ),
    ] {
        reject(&source, OnnxError::Graph);
    }
    reject(
        &resize_graph(
            [1, 1, 2, 2],
            [1, 1, 1, 1],
            &["input", "", "", "sizes"],
            &int_weight("sizes", &[1, 1, i64::MAX, 1]),
            &[],
        ),
        OnnxError::Unsupported,
    );
    Ok(())
}

#[test]
fn fractional_helpers_cannot_alias_later_source_values() -> Test {
    let collision = "onnx-node-0000-resize-axis-3-0-slice";
    let source = model(
        &[
            node("Resize", &["input", "", "scales"], "resized", &[]),
            node("Identity", &["resized"], collision, &[]),
            weight("scales", &[4], &[1., 1., 1., 1.5]),
            bytes(11, &info("input", &[1, 1, 1, 3])),
            bytes(12, &info(collision, &[1, 1, 1, 4])),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    assert_eq!(
        imported.graph().nodes()[0].outputs()[0],
        format!("{collision}-1")
    );
    let input = Tensor::from_values(
        Shape::new(vec![1, 1, 1, 3])?,
        &[-0.0, f32::from_bits(1), f32::MAX],
        GENERATION,
    )?;
    assert_eq!(
        bits(&run(&export(&imported)?, &[("input", input)], collision)?),
        bits(&[-0.0, -0.0, f32::from_bits(1), f32::MAX])
    );
    Ok(())
}

#[test]
fn integer_resize_preserves_the_original_canonical_graph_bytes() -> Test {
    use fss_model_ir::{
        AttrValue, AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort,
    };
    use fss_tensor::DType;

    let make = |id: &str, op, inputs: Vec<&str>, output: &str, name: &str, value| {
        GraphNode::new(
            id,
            op,
            "onnx-node-0000",
            inputs.into_iter().map(str::to_owned).collect(),
            vec![output.to_owned()],
            AttributeMap::from([(name.to_owned(), value)]),
        )
    };
    let expected = ModelIrGraph::new_validated(
        "onnx-graph",
        ModelIrVersion::V1,
        GENERATION,
        vec![TensorPort::new(
            "input",
            DType::F32,
            Shape::new(vec![1, 2, 3, 4])?,
            GENERATION,
        )?],
        vec![TensorPort::new(
            "output",
            DType::F32,
            Shape::new(vec![1, 2, 6, 12])?,
            GENERATION,
        )?],
        vec![
            make(
                "onnx-node-0000-unit",
                OpCode::Reshape,
                vec!["input"],
                "onnx-node-0000-resize-unit",
                "shape",
                AttrValue::IntList(vec![1, 2, 3, 1, 4, 1]),
            )?,
            make(
                "onnx-node-0000-width",
                OpCode::Concat,
                vec!["onnx-node-0000-resize-unit"; 3],
                "onnx-node-0000-resize-wide",
                "axis",
                AttrValue::Int(5),
            )?,
            make(
                "onnx-node-0000-height",
                OpCode::Concat,
                vec!["onnx-node-0000-resize-wide"; 2],
                "onnx-node-0000-resize-tall",
                "axis",
                AttrValue::Int(3),
            )?,
            make(
                "onnx-node-0000",
                OpCode::Reshape,
                vec!["onnx-node-0000-resize-tall"],
                "output",
                "shape",
                AttrValue::IntList(vec![1, 2, 6, 12]),
            )?,
        ],
    )?;
    let expected = encode_canonical_model_ir(&expected)?;
    for attrs in [Vec::new(), asymmetric()] {
        for (inputs, controls) in [
            (
                vec!["input", "", "scales"],
                weight("scales", &[4], &[1., 1., 2., 3.]),
            ),
            (
                vec!["input", "", "", "sizes"],
                int_weight("sizes", &[1, 2, 6, 12]),
            ),
        ] {
            let source = resize_graph([1, 2, 3, 4], [1, 2, 6, 12], &inputs, &controls, &attrs);
            let imported = import(&source)?;
            assert_eq!(encode_canonical_model_ir(imported.graph())?, expected);
            assert_eq!(export(&imported)?.graph_bytes(), expected);
        }
    }
    Ok(())
}
