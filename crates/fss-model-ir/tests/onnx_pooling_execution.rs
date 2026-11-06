#![forbid(unsafe_code)]
//! Average/global pooling through real ONNX/artifact parsing
//! and the unchanged production scalar executor. This target does not compile or
//! qualify the complete asynchronous reference crate or package CLI.

use std::cell::Cell;
use std::collections::BTreeMap;

use fss_core::{ContentDigest, Generation};
use fss_model_ir::{
    ImportedOnnx, ModelIrGraph, OnnxArtifacts, OnnxError, OnnxExportLimits, OnnxLimits,
    decode_canonical_model_ir, encode_canonical_model_ir, export_onnx_artifacts, import_onnx,
};
use fss_tensor::{Shape, Tensor};

#[path = "../../fss-reference/src/ingest/model_import/safetensors.rs"]
mod safetensors;
#[path = "../../fss-reference/src/scalar_executor.rs"]
pub mod scalar_executor;

// Data-only host types required by the unchanged production Safetensors parser.
// All weight-byte parsing, escaping, span validation and F32 decoding is real.
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
const GENERATION: Generation = Generation(31);
const DETECTOR: &[u8] = include_bytes!("fixtures/onnx/detector_average_pool.onnx");

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
fn integer(tag: u64, value: i64) -> Vec<u8> {
    [varint(tag * 8), varint(value as u64)].concat()
}
fn bytes(tag: u64, value: &[u8]) -> Vec<u8> {
    [
        varint(tag * 8 + 2),
        varint(value.len() as u64),
        value.to_vec(),
    ]
    .concat()
}
fn info(name: &str, dimensions: &[usize], dtype: i64) -> Vec<u8> {
    let shape: Vec<_> = dimensions
        .iter()
        .flat_map(|&n| bytes(1, &integer(1, n as i64)))
        .collect();
    let tensor = [integer(1, dtype), bytes(2, &shape)].concat();
    [bytes(1, name.as_bytes()), bytes(2, &bytes(1, &tensor))].concat()
}
fn tensor(name: &str, dimensions: &[usize], dtype: i64, values: &[u8]) -> Vec<u8> {
    [
        dimensions
            .iter()
            .flat_map(|&n| integer(1, n as i64))
            .collect(),
        integer(2, dtype),
        bytes(8, name.as_bytes()),
        bytes(9, values),
    ]
    .concat()
}
fn weight(name: &str, dimensions: &[usize], values: &[f32]) -> Vec<u8> {
    bytes(
        5,
        &tensor(
            name,
            dimensions,
            1,
            &values
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect::<Vec<_>>(),
        ),
    )
}
fn integer_tensor(name: &str, values: &[i64]) -> Vec<u8> {
    tensor(
        name,
        &[values.len()],
        7,
        &values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<_>>(),
    )
}
fn attribute(name: &str, kind: i64, payload: &[u8]) -> Vec<u8> {
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
fn int_attr(name: &str, value: i64) -> Vec<u8> {
    attribute(name, 2, &integer(3, value))
}
fn ints_attr(name: &str, values: &[i64]) -> Vec<u8> {
    attribute(
        name,
        7,
        &values
            .iter()
            .flat_map(|&v| integer(8, v))
            .collect::<Vec<_>>(),
    )
}
fn text_attr(name: &str, value: &str) -> Vec<u8> {
    attribute(name, 3, &bytes(4, value.as_bytes()))
}
fn node(op: &str, inputs: &[&str], outputs: &[&str], attributes: &[u8]) -> Vec<u8> {
    bytes(
        1,
        &[
            inputs
                .iter()
                .flat_map(|name| bytes(1, name.as_bytes()))
                .collect(),
            outputs
                .iter()
                .flat_map(|name| bytes(2, name.as_bytes()))
                .collect(),
            bytes(4, op.as_bytes()),
            attributes.to_vec(),
        ]
        .concat(),
    )
}
fn int_constant(name: &str, values: &[i64]) -> Vec<u8> {
    node(
        "Constant",
        &[],
        &[name],
        &attribute("value", 4, &bytes(5, &integer_tensor("metadata", values))),
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
fn refusal(source: &[u8]) -> Option<OnnxError> {
    import_onnx(
        source,
        ContentDigest::sha256(source),
        GENERATION,
        OnnxLimits::default(),
        &|| false,
    )
    .err()
}
fn export<'a>(imported: &ImportedOnnx<'a>) -> Test<OnnxArtifacts<'a>> {
    Ok(export_onnx_artifacts(
        imported,
        OnnxExportLimits::default(),
        &|| false,
    )?)
}
fn reloaded(artifacts: &OnnxArtifacts<'_>) -> Test<BTreeMap<String, Tensor>> {
    let weights = safetensors::Weights::parse(
        artifacts.weights_bytes(),
        &ImportLimits {
            maximum_header_bytes: 256 * 1024,
            maximum_tensors: 256,
        },
    )?;
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
fn execute(
    graph: &ModelIrGraph,
    mut inputs: BTreeMap<String, Tensor>,
    input: &[(&str, Tensor)],
) -> Test<Outputs> {
    inputs.extend(
        input
            .iter()
            .map(|(name, tensor)| ((*name).to_owned(), tensor.clone())),
    );
    let values = inputs.into_iter().collect::<Vec<_>>();
    let result = scalar_executor::ScalarExecutor::run(
        graph,
        &values,
        scalar_executor::ExecBudget::unlimited(),
        &scalar_executor::ScalarExecCx::new(),
    )?;
    graph
        .outputs()
        .iter()
        .map(|port| {
            Ok((
                port.name().to_owned(),
                result
                    .get_output(port.name())
                    .ok_or("missing output")?
                    .to_vec::<f32>()?,
            ))
        })
        .collect()
}
fn roundtrip(source: &[u8], input: &[(&str, Tensor)]) -> Test<Outputs> {
    let imported = import(source)?;
    let before = execute(imported.graph(), imported.parameters().clone(), input)?;
    let artifacts = export(&imported)?;
    assert_eq!(artifacts.source(), source);
    assert_eq!(artifacts.source_digest(), ContentDigest::sha256(source));
    let graph = decode_canonical_model_ir(artifacts.graph_bytes(), artifacts.graph_digest())?;
    assert_eq!(encode_canonical_model_ir(&graph)?, artifacts.graph_bytes());
    let after = execute(&graph, reloaded(&artifacts)?, input)?;
    for (name, expected) in &before {
        assert_eq!(bits(&after[name]), bits(expected), "artifact output {name}");
    }
    Ok(after)
}
fn bits(values: &[f32]) -> Vec<u32> {
    values.iter().map(|value| value.to_bits()).collect()
}

fn pool_attrs(
    kernel: [usize; 2],
    strides: [usize; 2],
    pads: [usize; 4],
    include_pad: bool,
) -> Vec<u8> {
    [
        ints_attr("kernel_shape", &kernel.map(|n| n as i64)),
        ints_attr("strides", &strides.map(|n| n as i64)),
        ints_attr("pads", &pads.map(|n| n as i64)),
        int_attr("count_include_pad", i64::from(include_pad)),
    ]
    .concat()
}

fn pool_model(op: &str, dims: &[usize], output: &[usize], attrs: &[u8]) -> Vec<u8> {
    model(
        &[
            node(op, &["input"], &["output"], attrs),
            bytes(11, &info("input", dims, 1)),
            bytes(12, &info("output", output, 1)),
        ]
        .concat(),
    )
}

/// Independent coordinate oracle: enumerate real samples, then divide their sum.
/// No generated weights, divisor tensor or native shape/operator API is consulted.
fn average(
    values: &[f32],
    dims: [usize; 4],
    kernel: [usize; 2],
    strides: [usize; 2],
    pads: [usize; 4],
    include_pad: bool,
) -> Test<([usize; 4], Vec<f32>)> {
    let out = [
        dims[0],
        dims[1],
        (dims[2] + pads[0] + pads[2] - kernel[0]) / strides[0] + 1,
        (dims[3] + pads[1] + pads[3] - kernel[1]) / strides[1] + 1,
    ];
    let mut result = Vec::new();
    for plane in 0..dims[0] * dims[1] {
        for oy in 0..out[2] {
            for ox in 0..out[3] {
                let start_y = (oy * strides[0]) as isize - pads[0] as isize;
                let start_x = (ox * strides[1]) as isize - pads[1] as isize;
                let mut sum = 0_f32;
                let mut count = 0;
                for y in 0..dims[2] {
                    for x in 0..dims[3] {
                        if y as isize >= start_y
                            && (y as isize) < start_y + kernel[0] as isize
                            && x as isize >= start_x
                            && (x as isize) < start_x + kernel[1] as isize
                        {
                            sum += values[(plane * dims[2] + y) * dims[3] + x];
                            count += 1;
                        }
                    }
                }
                if count == 0 {
                    return Err("admitted average window is empty".into());
                }
                let denominator = if include_pad {
                    kernel[0] * kernel[1]
                } else {
                    count
                };
                result.push(sum / denominator as f32);
            }
        }
    }
    Ok((out, result))
}

#[test]
fn average_pool_matches_coordinate_oracle_for_padding_strides_batches_and_channels() -> Test {
    let dims = [2, 3, 4, 5];
    let values: Vec<_> = (0..120).map(|n| (n % 23) as f32 * 0.25 - 6.).collect();
    let mut cases = 0;
    for kernel in [[1, 1], [2, 3], [3, 2], [3, 3], [5, 7]] {
        for strides in [[1, 1], [2, 3], [3, 2]] {
            for pads in [
                [0; 4],
                [kernel[0] - 1, 0, 0, kernel[1] - 1],
                [kernel[0] / 2, kernel[1] / 2, kernel[0] / 2, kernel[1] / 2],
            ] {
                if dims[2] + pads[0] + pads[2] < kernel[0]
                    || dims[3] + pads[1] + pads[3] < kernel[1]
                {
                    continue;
                }
                for include_pad in [false, true] {
                    let (output, expected) =
                        average(&values, dims, kernel, strides, pads, include_pad)?;
                    let source = pool_model(
                        "AveragePool",
                        &dims,
                        &output,
                        &pool_attrs(kernel, strides, pads, include_pad),
                    );
                    let imported = import(&source)?;
                    assert_eq!(imported.graph().nodes().len(), 2);
                    assert_eq!(imported.parameters().len(), 2);
                    let input =
                        Tensor::from_values(Shape::new(dims.to_vec())?, &values, GENERATION)?;
                    assert_eq!(
                        bits(&roundtrip(&source, &[("input", input)])?["output"]),
                        bits(&expected)
                    );
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 84);
    Ok(())
}

#[test]
fn defaults_and_smallest_overlap_preserve_include_and_exclude_padding_meanings() -> Test {
    let source = pool_model(
        "AveragePool",
        &[1, 1, 2, 3],
        &[1, 1, 1, 2],
        &ints_attr("kernel_shape", &[2, 2]),
    );
    let input = Tensor::from_values(
        Shape::new(vec![1, 1, 2, 3])?,
        &[1_f32, 2., 3., 4., 5., 6.],
        GENERATION,
    )?;
    assert_eq!(roundtrip(&source, &[("input", input)])?["output"], [3., 4.]);

    for include_pad in [false, true] {
        let attrs = [
            pool_attrs([3, 3], [2, 2], [2; 4], include_pad),
            int_attr("ceil_mode", 0),
            text_attr("auto_pad", "NOTSET"),
        ]
        .concat();
        let source = pool_model("AveragePool", &[1, 1, 1, 1], &[1, 1, 2, 2], &attrs);
        let input = Tensor::from_values(Shape::new(vec![1, 1, 1, 1])?, &[-18_f32], GENERATION)?;
        assert_eq!(
            roundtrip(&source, &[("input", input)])?["output"],
            [if include_pad { -2. } else { -18. }; 4]
        );
    }
    Ok(())
}

#[test]
fn global_average_preserves_batches_channels_and_output_rank_three_through_eight() -> Test {
    for dims in [
        vec![2, 3, 5],
        vec![2, 3, 2, 5],
        vec![2, 3, 2, 1, 5],
        vec![2, 3, 2, 1, 5, 2],
        vec![2, 3, 1, 2, 1, 5, 2],
        vec![2, 3, 1, 2, 1, 5, 2, 1],
    ] {
        let spatial: usize = dims[2..].iter().product();
        let count: usize = dims.iter().product();
        let values: Vec<_> = (0..count).map(|n| (n % 41) as f32 * 0.25 - 6.).collect();
        let mut output = dims.clone();
        output[2..].fill(1);
        let source = pool_model("GlobalAveragePool", &dims, &output, &[]);
        let imported = import(&source)?;
        assert_eq!(
            imported.graph().nodes().len(),
            if dims.len() == 4 { 2 } else { 4 }
        );
        assert_eq!(imported.graph().outputs()[0].shape().dims(), output);
        assert_eq!(imported.runtime_inputs(), ["input"]);
        let expected: Vec<_> = values
            .chunks_exact(spatial)
            .map(|plane| plane.iter().fold(0_f32, |sum, value| sum + value) / spatial as f32)
            .collect();
        let input = Tensor::from_values(Shape::new(dims)?, &values, GENERATION)?;
        assert_eq!(
            bits(&roundtrip(&source, &[("input", input)])?["output"]),
            bits(&expected)
        );
    }
    Ok(())
}

#[test]
fn pooling_sums_before_dividing_without_reciprocal_weights_or_f64_reduction() -> Test {
    let tiny = f32::from_bits(1);
    for (values, expected) in [
        (vec![tiny, tiny], tiny),
        (vec![-tiny, -tiny], -tiny),
        (vec![f32::MAX, f32::MAX], f32::INFINITY),
        (vec![-f32::MAX, -f32::MAX], f32::NEG_INFINITY),
        (vec![-0., -0.], 0.),
        (vec![16_777_216., 1., -16_777_216.], 0.),
    ] {
        for op in ["AveragePool", "GlobalAveragePool"] {
            let dims = [1, 1, 1, values.len()];
            let attrs = if op == "AveragePool" {
                ints_attr("kernel_shape", &[1, values.len() as i64])
            } else {
                Vec::new()
            };
            let source = pool_model(op, &dims, &[1, 1, 1, 1], &attrs);
            let input = Tensor::from_values(Shape::new(dims.to_vec())?, &values, GENERATION)?;
            assert_eq!(
                bits(&roundtrip(&source, &[("input", input)])?["output"]),
                bits(&[expected])
            );
        }
    }
    Ok(())
}

fn detector_source() -> Vec<u8> {
    model(
        &[
            node(
                "Conv",
                &["image", "stem_kernel", "stem_bias"],
                &["features"],
                &[],
            ),
            node(
                "AveragePool",
                &["features"],
                &["downsampled"],
                &pool_attrs([2, 3], [2, 2], [1, 1, 0, 1], false),
            ),
            node("GlobalAveragePool", &["downsampled"], &["context"], &[]),
            node(
                "Flatten",
                &["context"],
                &["embedding"],
                &int_attr("axis", 1),
            ),
            node(
                "Gemm",
                &["embedding", "head_kernel", "head_bias"],
                &["logits"],
                &[],
            ),
            node("Sigmoid", &["logits"], &["scores"], &[]),
            int_constant("head_shape", &[1, 1, 6]),
            node("Reshape", &["scores", "head_shape"], &["head"], &[]),
            weight(
                "stem_kernel",
                &[4, 3, 1, 1],
                &[1., 0., 0., 0., 0.5, 0., 0., 0., -0.25, 0.5, 0.25, 0.],
            ),
            weight("stem_bias", &[4], &[-1., 0.25, 2., -0.5]),
            weight(
                "head_kernel",
                &[4, 6],
                &[
                    1., 0., 0., 0., 0.5, -0.25, 0., 1., 0., 0., 0.25, 0.5, 0., 0., 1., 0., -0.5,
                    0.25, 0., 0., 0., 1., 0.25, -0.5,
                ],
            ),
            weight("head_bias", &[6], &[0., 0.25, -0.5, 0.75, -1., 1.]),
            bytes(11, &info("image", &[1, 3, 4, 5], 1)),
            bytes(12, &info("head", &[1, 1, 6], 1)),
            bytes(12, &info("context", &[1, 4, 1, 1], 1)),
        ]
        .concat(),
    )
}

#[test]
fn retained_convolution_average_global_pool_dense_head_executes_and_exports_exactly() -> Test {
    assert_eq!(detector_source(), DETECTOR);
    assert_eq!(
        ContentDigest::sha256(DETECTOR).to_text(),
        "sha256:408633ceb55af769ac529ed31046fd7da77df505b9e5780a38ab7f99e9866905"
    );
    let imported = import(DETECTOR)?;
    assert_eq!(imported.graph().nodes().len(), 12);
    assert_eq!(imported.parameters().len(), 10);
    for image in [
        (0..60).map(|n| (n % 17) as f32 - 8.).collect::<Vec<_>>(),
        (0..60).map(|n| (n % 13) as f32 * -0.25).collect(),
    ] {
        let mut features = Vec::new();
        features.extend(image[..20].iter().map(|value| value - 1.));
        features.extend(image[20..40].iter().map(|value| value * 0.5 + 0.25));
        features.extend(image[40..].iter().map(|value| value * -0.25 + 2.));
        features.extend((0..20).map(|pixel| image[pixel] * 0.5 + image[20 + pixel] * 0.25 - 0.5));
        let (_, downsampled) =
            average(&features, [1, 4, 4, 5], [2, 3], [2, 2], [1, 1, 0, 1], false)?;
        let context: Vec<_> = downsampled
            .as_chunks::<6>()
            .0
            .iter()
            .map(|plane| plane.iter().fold(0_f32, |sum, value| sum + value) / 6.)
            .collect();
        let logits = [
            context[0],
            context[1] + 0.25,
            context[2] - 0.5,
            context[3] + 0.75,
            ((context[0] * 0.5 + context[1] * 0.25) + context[2] * -0.5) + context[3] * 0.25 - 1.,
            ((context[0] * -0.25 + context[1] * 0.5) + context[2] * 0.25) + context[3] * -0.5 + 1.,
        ];
        let input = Tensor::from_values(Shape::new(vec![1, 3, 4, 5])?, &image, GENERATION)?;
        let outputs = roundtrip(DETECTOR, &[("image", input)])?;
        assert_eq!(bits(&outputs["context"]), bits(&context));
        for (&actual, logit) in outputs["head"].iter().zip(logits) {
            let expected = 1_f64 / (1. + (-(logit as f64)).exp());
            assert!(
                (f64::from(actual) - expected).abs() < 2e-7,
                "sigmoid {actual} != {expected}"
            );
        }
    }
    Ok(())
}

#[test]
fn malformed_and_unimplemented_pooling_attributes_refuse() {
    for (attrs, expected) in [
        (Vec::new(), OnnxError::Graph),
        (int_attr("kernel_shape", 2), OnnxError::Graph),
        (ints_attr("kernel_shape", &[2]), OnnxError::Graph),
        (ints_attr("kernel_shape", &[0, 2]), OnnxError::Graph),
        (ints_attr("kernel_shape", &[-1, 2]), OnnxError::Graph),
        (ints_attr("kernel_shape", &[5, 5]), OnnxError::Graph),
        (
            [
                ints_attr("kernel_shape", &[2, 2]),
                ints_attr("strides", &[0, 1]),
            ]
            .concat(),
            OnnxError::Graph,
        ),
        (
            [
                ints_attr("kernel_shape", &[2, 2]),
                ints_attr("pads", &[0, -1, 0, 0]),
            ]
            .concat(),
            OnnxError::Graph,
        ),
        (
            [
                ints_attr("kernel_shape", &[2, 2]),
                ints_attr("pads", &[2, 0, 0, 0]),
            ]
            .concat(),
            OnnxError::Unsupported,
        ),
        (
            [
                ints_attr("kernel_shape", &[2, 2]),
                int_attr("count_include_pad", 2),
            ]
            .concat(),
            OnnxError::Graph,
        ),
        (
            [
                ints_attr("kernel_shape", &[2, 2]),
                text_attr("count_include_pad", "0"),
            ]
            .concat(),
            OnnxError::Graph,
        ),
        (
            [ints_attr("kernel_shape", &[2, 2]), int_attr("ceil_mode", 1)].concat(),
            OnnxError::Unsupported,
        ),
        (
            [
                ints_attr("kernel_shape", &[2, 2]),
                text_attr("ceil_mode", "0"),
            ]
            .concat(),
            OnnxError::Graph,
        ),
        (
            [
                ints_attr("kernel_shape", &[2, 2]),
                text_attr("auto_pad", "SAME"),
            ]
            .concat(),
            OnnxError::Unsupported,
        ),
        (
            [
                ints_attr("kernel_shape", &[2, 2]),
                text_attr("auto_pad", "same_upper"),
            ]
            .concat(),
            OnnxError::Unsupported,
        ),
        (
            [ints_attr("kernel_shape", &[2, 2]), int_attr("auto_pad", 0)].concat(),
            OnnxError::Graph,
        ),
        (
            [
                ints_attr("kernel_shape", &[2, 2]),
                ints_attr("dilations", &[1, 1]),
            ]
            .concat(),
            OnnxError::Unsupported,
        ),
        (
            [
                ints_attr("kernel_shape", &[2, 2]),
                ints_attr("kernel_shape", &[2, 2]),
            ]
            .concat(),
            OnnxError::Malformed,
        ),
        (
            [
                ints_attr("kernel_shape", &[2, 2]),
                int_attr("storage_order", 0),
            ]
            .concat(),
            OnnxError::Unsupported,
        ),
        (
            ints_attr("kernel_shape", &[i64::MAX, i64::MAX]),
            OnnxError::Graph,
        ),
    ] {
        let source = pool_model("AveragePool", &[1, 1, 4, 4], &[1, 1, 3, 3], &attrs);
        assert_eq!(refusal(&source), Some(expected), "attributes {attrs:?}");
    }
    assert_eq!(
        refusal(&pool_model(
            "GlobalAveragePool",
            &[1, 1, 4, 4],
            &[1, 1, 1, 1],
            &int_attr("keepdims", 1)
        )),
        Some(OnnxError::Unsupported)
    );
}

#[test]
fn pooling_bad_ranks_bindings_output_shapes_and_generated_name_collisions_refuse() -> Test {
    for dims in [
        vec![],
        vec![4],
        vec![2, 4],
        vec![1, 2, 4],
        vec![1, 2, 2, 2, 2],
    ] {
        assert_eq!(
            refusal(&pool_model(
                "AveragePool",
                &dims,
                &[1, 1, 1, 1],
                &ints_attr("kernel_shape", &[2, 2])
            )),
            Some(OnnxError::Unsupported)
        );
    }
    for dims in [vec![], vec![4], vec![2, 4]] {
        assert_eq!(
            refusal(&pool_model("GlobalAveragePool", &dims, &dims, &[])),
            Some(OnnxError::Unsupported)
        );
    }
    for inputs in [vec![], vec!["input", "input"], vec!["missing"]] {
        let source = model(
            &[
                node("GlobalAveragePool", &inputs, &["output"], &[]),
                bytes(11, &info("input", &[1, 2, 3], 1)),
                bytes(12, &info("output", &[1, 2, 1], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Graph));
    }
    assert_eq!(
        refusal(&pool_model(
            "GlobalAveragePool",
            &[1, 2, 3],
            &[1, 2, 1, 1],
            &[]
        )),
        Some(OnnxError::Graph)
    );
    assert_eq!(
        refusal(&pool_model(
            "AveragePool",
            &[1, 1, 4, 4],
            &[1, 1, 4, 4],
            &ints_attr("kernel_shape", &[2, 2])
        )),
        Some(OnnxError::Graph)
    );

    let colliding = "onnx-node-0000-pool-ones";
    let source = model(
        &[
            node("GlobalAveragePool", &[colliding], &["output"], &[]),
            bytes(11, &info(colliding, &[1, 1, 2, 2], 1)),
            bytes(12, &info("output", &[1, 1, 1, 1], 1)),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    assert!(
        imported
            .parameters()
            .contains_key(&format!("{colliding}-1"))
    );
    let input = Tensor::from_values(
        Shape::new(vec![1, 1, 2, 2])?,
        &[1_f32, 2., 3., 4.],
        GENERATION,
    )?;
    assert_eq!(roundtrip(&source, &[(colliding, input)])?["output"], [2.5]);
    for name in [
        "onnx-node-0000-pool-ones",
        "onnx-node-0000-pool-divisors",
        "onnx-node-0000-pool-sum",
    ] {
        let source = model(
            &[
                node("GlobalAveragePool", &["input"], &["output"], &[]),
                node("Add", &["output", name], &["head"], &[]),
                bytes(11, &info("input", &[1, 1, 2, 2], 1)),
                bytes(12, &info("head", &[1, 1, 1, 1], 1)),
            ]
            .concat(),
        );
        assert_eq!(
            refusal(&source),
            Some(OnnxError::Graph),
            "missing input {name}"
        );
    }
    Ok(())
}

#[test]
fn generated_parameters_helpers_and_work_obey_exact_aggregate_bounds() -> Test {
    let source = pool_model(
        "AveragePool",
        &[1, 2, 2, 2],
        &[1, 2, 2, 2],
        &pool_attrs([3, 3], [1, 1], [1; 4], false),
    );
    let imported = import(&source)?;
    let exact = OnnxLimits {
        source_bytes: source.len(),
        nodes: 2,
        tensors: 5,
        parameter_bytes: 2 * 3 * 3 * 4 + 2 * 2 * 4,
        tensor_bytes: 2 * 3 * 3 * 4,
        work_units: imported.work_units(),
    };
    let admitted = import_onnx(
        &source,
        ContentDigest::sha256(&source),
        GENERATION,
        exact,
        &|| false,
    )?;
    assert_eq!(
        encode_canonical_model_ir(admitted.graph())?,
        encode_canonical_model_ir(imported.graph())?
    );
    for limits in [
        OnnxLimits {
            source_bytes: source.len() - 1,
            ..exact
        },
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

    let global = pool_model("GlobalAveragePool", &[1, 1, 3], &[1, 1, 1], &[]);
    for limits in [
        OnnxLimits {
            nodes: 3,
            ..OnnxLimits::default()
        },
        OnnxLimits {
            tensors: 6,
            ..OnnxLimits::default()
        },
        OnnxLimits {
            parameter_bytes: 15,
            ..OnnxLimits::default()
        },
    ] {
        assert_eq!(
            import_onnx(
                &global,
                ContentDigest::sha256(&global),
                GENERATION,
                limits,
                &|| false
            )
            .err(),
            Some(OnnxError::Limit)
        );
    }
    import_onnx(
        &global,
        ContentDigest::sha256(&global),
        GENERATION,
        OnnxLimits {
            nodes: 4,
            tensors: 7,
            parameter_bytes: 16,
            tensor_bytes: 12,
            ..OnnxLimits::default()
        },
        &|| false,
    )?;

    // The original initializer remains quota-charged alongside both generated tensors.
    let embedded = model(
        &[
            node("GlobalAveragePool", &["input"], &["output"], &[]),
            weight("input", &[1, 1, 1, 2], &[2., 4.]),
            bytes(12, &info("output", &[1, 1, 1, 1], 1)),
        ]
        .concat(),
    );
    assert_eq!(
        import_onnx(
            &embedded,
            ContentDigest::sha256(&embedded),
            GENERATION,
            OnnxLimits {
                parameter_bytes: 19,
                ..OnnxLimits::default()
            },
            &|| false
        )
        .err(),
        Some(OnnxError::Limit)
    );
    let embedded = import_onnx(
        &embedded,
        ContentDigest::sha256(&embedded),
        GENERATION,
        OnnxLimits {
            parameter_bytes: 20,
            ..OnnxLimits::default()
        },
        &|| false,
    )?;
    assert_eq!(embedded.parameters().len(), 3);
    assert_eq!(
        execute(embedded.graph(), embedded.parameters().clone(), &[])?["output"],
        [3.]
    );

    // No giant synthetic kernel or denominator allocation may bypass the caps.
    let too_large = pool_model("GlobalAveragePool", &[1, 1, 4_194_304], &[1, 1, 1], &[]);
    assert_eq!(refusal(&too_large), Some(OnnxError::Limit));
    Ok(())
}

#[test]
fn import_cancellation_is_honored_at_every_pooling_checkpoint_and_source_is_pinned() -> Test {
    let source = pool_model(
        "AveragePool",
        &[1, 2, 2, 2],
        &[1, 2, 2, 2],
        &pool_attrs([3, 3], [1, 1], [1; 4], false),
    );
    let calls = Cell::new(0_usize);
    import_onnx(
        &source,
        ContentDigest::sha256(&source),
        GENERATION,
        OnnxLimits::default(),
        &|| {
            calls.set(calls.get() + 1);
            false
        },
    )?;
    for at in 1..=calls.get() {
        let current = Cell::new(0_usize);
        assert_eq!(
            import_onnx(
                &source,
                ContentDigest::sha256(&source),
                GENERATION,
                OnnxLimits::default(),
                &|| {
                    current.set(current.get() + 1);
                    current.get() == at
                }
            )
            .err(),
            Some(OnnxError::Cancelled),
            "checkpoint {at}"
        );
    }
    for end in 0..DETECTOR.len() {
        let truncated = &DETECTOR[..end];
        assert!(refusal(truncated).is_some(), "truncation {end}");
    }
    let mut changed = DETECTOR.to_vec();
    changed[10] ^= 1;
    assert_eq!(
        import_onnx(
            &changed,
            ContentDigest::sha256(DETECTOR),
            GENERATION,
            OnnxLimits::default(),
            &|| false
        )
        .err(),
        Some(OnnxError::Digest)
    );
    Ok(())
}

#[test]
fn lowered_pooling_keeps_native_execution_budget_generation_and_cancellation_checks() -> Test {
    let source = pool_model("GlobalAveragePool", &[1, 2, 2, 2], &[1, 2, 1, 1], &[]);
    let imported = import(&source)?;
    let input = Tensor::from_values(Shape::new(vec![1, 2, 2, 2])?, &[1_f32; 8], GENERATION)?;
    let mut bindings: Vec<_> = imported
        .parameters()
        .iter()
        .map(|(name, tensor)| (name.clone(), tensor.clone()))
        .collect();
    bindings.push(("input".to_owned(), input));
    let result = scalar_executor::ScalarExecutor::run(
        imported.graph(),
        &bindings,
        scalar_executor::ExecBudget::unlimited(),
        &scalar_executor::ScalarExecCx::new(),
    )?;
    assert_eq!(result.nodes_executed(), 2);
    for budget in [
        scalar_executor::ExecBudget::new(result.executed_macs() - 1, usize::MAX),
        scalar_executor::ExecBudget::new(u64::MAX, result.allocated_bytes() - 1),
    ] {
        assert!(matches!(
            scalar_executor::ScalarExecutor::run(
                imported.graph(),
                &bindings,
                budget,
                &scalar_executor::ScalarExecCx::new()
            ),
            Err(scalar_executor::ExecError::BudgetExceeded { .. })
        ));
    }
    let cx = scalar_executor::ScalarExecCx::new();
    cx.request_cancellation();
    assert!(matches!(
        scalar_executor::ScalarExecutor::run(
            imported.graph(),
            &bindings,
            scalar_executor::ExecBudget::unlimited(),
            &cx
        ),
        Err(scalar_executor::ExecError::CancellationRequested { .. })
    ));
    bindings.pop();
    bindings.push((
        "input".to_owned(),
        Tensor::from_values(Shape::new(vec![1, 2, 2, 2])?, &[1_f32; 8], Generation(32))?,
    ));
    assert!(matches!(
        scalar_executor::ScalarExecutor::run(
            imported.graph(),
            &bindings,
            scalar_executor::ExecBudget::unlimited(),
            &scalar_executor::ScalarExecCx::new()
        ),
        Err(scalar_executor::ExecError::GenerationMismatch { .. })
    ));
    Ok(())
}
