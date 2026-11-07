#![forbid(unsafe_code)]
//! Static ConvTranspose executes through the unchanged production scalar and
//! optimized kernels, then through real canonical-graph/Safetensors reload.
//! The oracle scatters original source samples and unmodified source weights
//! directly into output coordinates; it does not reuse the lowering geometry,
//! zero expansion, weight reversal or native convolution implementation.

use std::cell::Cell;
use std::collections::BTreeMap;

use fss_core::{ContentDigest, Generation};
use fss_model_ir::{
    ImportedOnnx, ModelIrGraph, OnnxArtifacts, OnnxError, OnnxExportLimits, OnnxLimits,
    decode_canonical_model_ir, encode_canonical_model_ir, export_onnx_artifacts, import_onnx,
    onnx_importer_identity,
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
const GENERATION: Generation = Generation(59);

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
    let constants = inputs
        .iter()
        .map(|(name, tensor)| Ok((name.clone(), tensor.to_vec::<f32>()?)))
        .collect::<Result<BTreeMap<_, _>, fss_tensor::TensorError>>()?;
    let optimized =
        optimized_executor::OptimizedGraph::prepare(graph, &constants, &ScalarExecCx::new())?;
    let fast = optimized.run(input, ExecBudget::unlimited(), &ScalarExecCx::new())?;
    inputs.extend(
        input
            .iter()
            .map(|(name, tensor)| ((*name).to_owned(), tensor.clone())),
    );
    let values = inputs.into_iter().collect::<Vec<_>>();
    let scalar = ScalarExecutor::run(
        graph,
        &values,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    assert_eq!(fast.executed_macs(), scalar.executed_macs());
    assert_eq!(fast.allocated_bytes(), scalar.allocated_bytes());
    graph
        .outputs()
        .iter()
        .map(|port| {
            let expected = scalar
                .get_output(port.name())
                .ok_or("missing scalar output")?
                .to_vec::<f32>()?;
            let actual = fast
                .get_output(port.name())
                .ok_or("missing optimized output")?
                .to_vec::<f32>()?;
            same_values(&actual, &expected, port.name());
            Ok((port.name().to_owned(), expected))
        })
        .collect()
}
fn roundtrip(source: &[u8], input: &[(&str, Tensor)]) -> Test<Outputs> {
    let imported = import(source)?;
    let before = execute(imported.graph(), imported.parameters().clone(), input)?;
    let artifacts = export(&imported)?;
    assert_eq!(artifacts.source(), source);
    assert_eq!(artifacts.source_digest(), ContentDigest::sha256(source));
    assert_eq!(artifacts.importer_identity(), onnx_importer_identity());
    assert_eq!(
        artifacts.weights_digest(),
        ContentDigest::sha256(artifacts.weights_bytes())
    );
    let graph = decode_canonical_model_ir(artifacts.graph_bytes(), artifacts.graph_digest())?;
    assert_eq!(encode_canonical_model_ir(&graph)?, artifacts.graph_bytes());
    let after = execute(&graph, reloaded(&artifacts)?, input)?;
    for (name, expected) in &before {
        same_values(&after[name], expected, name);
    }
    Ok(after)
}
fn bits(values: &[f32]) -> Vec<u32> {
    values.iter().map(|value| value.to_bits()).collect()
}

fn same_values(actual: &[f32], expected: &[f32], context: &str) {
    assert_eq!(actual.len(), expected.len(), "{context}");
    for (index, (&actual, &expected)) in actual.iter().zip(expected).enumerate() {
        if actual.is_nan() && expected.is_nan() {
            continue;
        }
        assert_eq!(actual.to_bits(), expected.to_bits(), "{context}[{index}]");
    }
}

fn data(dimensions: &[usize], values: &[f32]) -> Test<Tensor> {
    Ok(Tensor::from_values(
        Shape::new(dimensions.to_vec())?,
        values,
        GENERATION,
    )?)
}

fn string_attr(name: &str, value: &str) -> Vec<u8> {
    attribute(name, 3, &bytes(4, value.as_bytes()))
}

fn constant(name: &str, dimensions: &[usize], values: &[f32]) -> Vec<u8> {
    node(
        "Constant",
        &[],
        &[name],
        &attribute(
            "value",
            4,
            &bytes(
                5,
                &tensor(
                    "",
                    dimensions,
                    1,
                    &values
                        .iter()
                        .flat_map(|x| x.to_le_bytes())
                        .collect::<Vec<_>>(),
                ),
            ),
        ),
    )
}

fn generated_values(count: usize, phase: usize) -> Vec<f32> {
    (0..count)
        .map(|index| (((index * 7 + phase) % 19) as f32 - 9.) * 0.125)
        .collect()
}

#[derive(Clone, Debug)]
struct Case {
    input: [usize; 4],
    weight: [usize; 4],
    output: [usize; 4],
    strides: [usize; 2],
    dilations: [usize; 2],
    // Oracle coordinates are specified independently, including for auto_pad
    // and output_shape. They are never obtained from production inference.
    pad_begin: [usize; 2],
    groups: usize,
    attributes: Vec<u8>,
}

impl Case {
    fn source(&self, weights: &[f32], bias: Option<&[f32]>) -> Vec<u8> {
        let mut graph = node(
            "ConvTranspose",
            if bias.is_some() {
                &["input", "weight", "bias"]
            } else {
                &["input", "weight"]
            },
            &["output"],
            &self.attributes,
        );
        graph.extend(weight("weight", &self.weight, weights));
        if let Some(bias) = bias {
            graph.extend(weight("bias", &[bias.len()], bias));
        }
        graph.extend(bytes(11, &info("input", &self.input, 1)));
        graph.extend(bytes(12, &info("output", &self.output, 1)));
        model(&graph)
    }
}

// The original operator's scatter definition. Accumulation is binary64 only
// in this independent oracle; fixtures use bounded dyadic values whose sums
// and products are exactly representable in F32, independent of term order.
fn scatter(case: &Case, input: &[f32], weight: &[f32], bias: Option<&[f32]>) -> Vec<f32> {
    let [batches, input_channels, height, width] = case.input;
    let [_, channels_per_group, kernel_h, kernel_w] = case.weight;
    let [_, output_channels, output_h, output_w] = case.output;
    assert_eq!(output_channels, channels_per_group * case.groups);
    assert_eq!(input.len(), case.input.iter().product());
    assert_eq!(weight.len(), case.weight.iter().product());
    let mut output = vec![0.0_f64; case.output.iter().product()];
    for batch in 0..batches {
        for channel in 0..output_channels {
            for pixel in 0..output_h * output_w {
                output[(batch * output_channels + channel) * output_h * output_w + pixel] =
                    bias.map_or(0., |bias| f64::from(bias[channel]));
            }
        }
    }
    for batch in 0..batches {
        for channel in 0..input_channels {
            let group = channel / (input_channels / case.groups);
            for y in 0..height {
                for x in 0..width {
                    let value = f64::from(
                        input[((batch * input_channels + channel) * height + y) * width + x],
                    );
                    for local_output in 0..channels_per_group {
                        let out_channel = group * channels_per_group + local_output;
                        for ky in 0..kernel_h {
                            for kx in 0..kernel_w {
                                let oy = (y * case.strides[0] + ky * case.dilations[0]) as i64
                                    - case.pad_begin[0] as i64;
                                let ox = (x * case.strides[1] + kx * case.dilations[1]) as i64
                                    - case.pad_begin[1] as i64;
                                if oy < 0
                                    || oy >= output_h as i64
                                    || ox < 0
                                    || ox >= output_w as i64
                                {
                                    continue;
                                }
                                let kernel = weight[((channel * channels_per_group
                                    + local_output)
                                    * kernel_h
                                    + ky)
                                    * kernel_w
                                    + kx];
                                let destination = ((batch * output_channels + out_channel)
                                    * output_h
                                    + oy as usize)
                                    * output_w
                                    + ox as usize;
                                output[destination] += value * f64::from(kernel);
                            }
                        }
                    }
                }
            }
        }
    }
    output.into_iter().map(|value| value as f32).collect()
}

fn run_case(case: &Case) -> Test {
    let input = generated_values(case.input.iter().product(), 1);
    let weights = generated_values(case.weight.iter().product(), 3);
    let bias = generated_values(case.output[1], 5);
    for bias in [None, Some(bias.as_slice())] {
        let source = case.source(&weights, bias);
        let imported = import(&source)?;
        assert_eq!(imported.runtime_inputs(), &["input"]);
        assert_eq!(imported.graph().outputs()[0].shape().dims(), case.output);
        let actual = roundtrip(&source, &[("input", data(&case.input, &input)?)])?;
        same_values(
            &actual["output"],
            &scatter(case, &input, &weights, bias),
            &format!("{case:?}"),
        );
    }
    Ok(())
}

fn basic_case() -> Case {
    Case {
        input: [1, 1, 2, 2],
        weight: [1, 1, 2, 2],
        output: [1, 1, 3, 3],
        strides: [1, 1],
        dilations: [1, 1],
        pad_begin: [0, 0],
        groups: 1,
        attributes: Vec::new(),
    }
}

#[test]
fn transpose_literal_kernel_orientation_and_overlap_are_exact() -> Test {
    let case = basic_case();
    let source = case.source(&[1., 2., 3., 4.], None);
    let result = roundtrip(&source, &[("input", data(&case.input, &[1., 2., 3., 4.])?)])?;
    assert_eq!(result["output"], [1., 4., 4., 6., 20., 16., 9., 24., 16.]);
    Ok(())
}

#[test]
fn transpose_grouped_multibatch_dilated_asymmetric_and_cropped_outputs_match_scatter() -> Test {
    for case in [
        basic_case(),
        Case {
            input: [2, 4, 3, 4],
            weight: [4, 3, 2, 3],
            output: [2, 6, 5, 11],
            strides: [2, 3],
            dilations: [2, 1],
            pad_begin: [1, 2],
            groups: 2,
            attributes: [
                ints_attr("strides", &[2, 3]),
                ints_attr("dilations", &[2, 1]),
                ints_attr("pads", &[1, 2, 2, 1]),
                ints_attr("output_padding", &[1, 2]),
                ints_attr("kernel_shape", &[2, 3]),
                int_attr("group", 2),
            ]
            .concat(),
        },
        Case {
            input: [2, 3, 2, 3],
            weight: [3, 2, 3, 2],
            output: [2, 6, 4, 6],
            strides: [2, 2],
            dilations: [1, 2],
            pad_begin: [0, 1],
            groups: 3,
            attributes: [
                ints_attr("strides", &[2, 2]),
                ints_attr("dilations", &[1, 2]),
                ints_attr("pads", &[0, 1, 2, 0]),
                ints_attr("output_padding", &[1, 0]),
                int_attr("group", 3),
            ]
            .concat(),
        },
        Case {
            // Start padding exceeds the effective kernel radius on both axes.
            input: [1, 2, 4, 5],
            weight: [2, 2, 2, 3],
            output: [1, 2, 5, 9],
            strides: [2, 3],
            dilations: [2, 1],
            pad_begin: [3, 4],
            groups: 1,
            attributes: [
                ints_attr("strides", &[2, 3]),
                ints_attr("dilations", &[2, 1]),
                ints_attr("pads", &[3, 4, 1, 2]),
            ]
            .concat(),
        },
        Case {
            // output_padding may exceed stride while remaining below dilation.
            input: [1, 1, 2, 3],
            weight: [1, 1, 2, 3],
            output: [1, 1, 7, 8],
            strides: [1, 1],
            dilations: [3, 2],
            pad_begin: [0, 0],
            groups: 1,
            attributes: [
                ints_attr("dilations", &[3, 2]),
                ints_attr("output_padding", &[2, 1]),
            ]
            .concat(),
        },
        Case {
            // Real zero-valued holes and a bias-only trailing row/column region.
            input: [1, 1, 2, 2],
            weight: [1, 2, 1, 1],
            output: [1, 2, 8, 6],
            strides: [4, 3],
            dilations: [1, 1],
            pad_begin: [0, 0],
            groups: 1,
            attributes: [
                ints_attr("strides", &[4, 3]),
                ints_attr("output_padding", &[3, 2]),
            ]
            .concat(),
        },
        Case {
            // Singleton spatial axes require no input zero expansion.
            input: [1, 2, 1, 1],
            weight: [2, 3, 3, 2],
            output: [1, 3, 7, 3],
            strides: [5, 2],
            dilations: [1, 1],
            pad_begin: [0, 0],
            groups: 1,
            attributes: [
                ints_attr("strides", &[5, 2]),
                ints_attr("output_padding", &[4, 1]),
            ]
            .concat(),
        },
    ] {
        run_case(&case)?;
    }
    Ok(())
}

#[test]
fn transpose_auto_padding_and_explicit_output_shape_keep_the_source_coordinate_origin() -> Test {
    for (mode, begin, side) in [
        ("SAME_UPPER", [0, 0], 4),
        ("SAME_LOWER", [1, 1], 4),
        ("VALID", [0, 0], 5),
        ("NOTSET", [0, 0], 5),
    ] {
        run_case(&Case {
            input: [1, 1, 2, 2],
            weight: [1, 2, 3, 3],
            output: [1, 2, side, side],
            strides: [2, 2],
            dilations: [1, 1],
            pad_begin: begin,
            groups: 1,
            attributes: [ints_attr("strides", &[2, 2]), string_attr("auto_pad", mode)].concat(),
        })?;
    }
    for (mode, begin) in [
        (None, [1, 1]),
        (Some("NOTSET"), [1, 1]),
        (Some("SAME_UPPER"), [0, 0]),
        (Some("SAME_LOWER"), [1, 1]),
        (Some("VALID"), [1, 1]),
    ] {
        let mut attributes = [
            ints_attr("strides", &[2, 2]),
            ints_attr("output_shape", &[4, 5]),
        ]
        .concat();
        if let Some(mode) = mode {
            attributes.extend(string_attr("auto_pad", mode));
        }
        if mode.is_none() || mode == Some("NOTSET") {
            // Well-typed explicit pads are ignored when output_shape is present.
            attributes.extend(ints_attr("pads", &[99, 98, 97, 96]));
        }
        run_case(&Case {
            input: [1, 1, 2, 3],
            weight: [1, 2, 3, 2],
            output: [1, 2, 4, 5],
            strides: [2, 2],
            dilations: [1, 1],
            pad_begin: begin,
            groups: 1,
            attributes,
        })?;
    }
    // Explicit output shape uses output_padding when deriving its pads.
    run_case(&Case {
        input: [1, 1, 2, 3],
        weight: [1, 1, 3, 2],
        output: [1, 1, 5, 6],
        strides: [2, 2],
        dilations: [1, 1],
        pad_begin: [1, 0],
        groups: 1,
        attributes: [
            ints_attr("strides", &[2, 2]),
            ints_attr("output_padding", &[1, 0]),
            ints_attr("output_shape", &[5, 6]),
        ]
        .concat(),
    })?;
    Ok(())
}

#[test]
fn transpose_constant_and_shared_weights_preserve_original_values_and_runtime_bias() -> Test {
    let case = Case {
        input: [2, 2, 2, 3],
        weight: [2, 3, 2, 2],
        output: [2, 3, 4, 6],
        strides: [2, 2],
        dilations: [1, 1],
        pad_begin: [0, 0],
        groups: 1,
        attributes: ints_attr("strides", &[2, 2]),
    };
    let values = generated_values(case.input.iter().product(), 2);
    let mut weights = generated_values(case.weight.iter().product(), 5);
    weights[0] = -0.;
    let bias = [0.25_f32, -0.5, 1.];
    for as_constant in [false, true] {
        let source = model(
            &[
                if as_constant {
                    constant("weight", &case.weight, &weights)
                } else {
                    weight("weight", &case.weight, &weights)
                },
                node(
                    "ConvTranspose",
                    &["input", "weight", "bias"],
                    &["output"],
                    &case.attributes,
                ),
                node("Identity", &["weight"], &["original-weight"], &[]),
                node("Identity", &["bias"], &["original-bias"], &[]),
                bytes(11, &info("input", &case.input, 1)),
                bytes(11, &info("bias", &[3], 1)),
                bytes(12, &info("output", &case.output, 1)),
                bytes(12, &info("original-weight", &case.weight, 1)),
                bytes(12, &info("original-bias", &[3], 1)),
            ]
            .concat(),
        );
        let imported = import(&source)?;
        assert_eq!(imported.runtime_inputs(), &["input", "bias"]);
        assert_eq!(
            bits(&imported.parameters()["weight"].to_vec::<f32>()?),
            bits(&weights)
        );
        for bias in [bias, [-1., 0.125, 0.]] {
            let actual = roundtrip(
                &source,
                &[
                    ("input", data(&case.input, &values)?),
                    ("bias", data(&[3], &bias)?),
                ],
            )?;
            same_values(
                &actual["output"],
                &scatter(&case, &values, &weights, Some(&bias)),
                "runtime bias",
            );
            assert_eq!(bits(&actual["original-weight"]), bits(&weights));
            assert_eq!(bits(&actual["original-bias"]), bits(&bias));
        }
    }
    // The optional third operand may be absent or the explicitly empty spelling.
    let plain = case.source(&weights, None);
    let empty = model(
        &[
            node(
                "ConvTranspose",
                &["input", "weight", ""],
                &["output"],
                &case.attributes,
            ),
            weight("weight", &case.weight, &weights),
            bytes(11, &info("input", &case.input, 1)),
            bytes(12, &info("output", &case.output, 1)),
        ]
        .concat(),
    );
    assert_eq!(
        encode_canonical_model_ir(import(&plain)?.graph())?,
        encode_canonical_model_ir(import(&empty)?.graph())?
    );
    Ok(())
}

#[test]
fn transpose_composes_with_an_actual_convolutional_encoder_and_sigmoid_decoder_head() -> Test {
    let input_shape = [2, 2, 2, 3];
    let encoded_shape = [2, 3, 2, 3];
    let case = Case {
        input: encoded_shape,
        weight: [3, 2, 3, 3],
        output: [2, 2, 4, 6],
        strides: [2, 2],
        dilations: [1, 1],
        pad_begin: [1, 1],
        groups: 1,
        attributes: [
            ints_attr("strides", &[2, 2]),
            ints_attr("pads", &[1, 1, 0, 0]),
        ]
        .concat(),
    };
    let inputs = generated_values(input_shape.iter().product(), 4);
    let encoder = [0.5_f32, -0.25, 0.125, 0.75, -0.5, 0.25];
    let decoder = generated_values(case.weight.iter().product(), 6);
    let source = model(
        &[
            node("Conv", &["input", "encoder"], &["encoded"], &[]),
            node(
                "ConvTranspose",
                &["encoded", "decoder"],
                &["logits"],
                &case.attributes,
            ),
            node("Sigmoid", &["logits"], &["output"], &[]),
            weight("encoder", &[3, 2, 1, 1], &encoder),
            weight("decoder", &case.weight, &decoder),
            bytes(11, &info("input", &input_shape, 1)),
            bytes(12, &info("encoded", &encoded_shape, 1)),
            bytes(12, &info("logits", &case.output, 1)),
            bytes(12, &info("output", &case.output, 1)),
        ]
        .concat(),
    );
    let mut encoded = Vec::new();
    for batch in 0..2 {
        for output in 0..3 {
            for pixel in 0..6 {
                encoded.push(
                    inputs[batch * 12 + pixel] * encoder[output * 2]
                        + inputs[batch * 12 + 6 + pixel] * encoder[output * 2 + 1],
                );
            }
        }
    }
    let logits = scatter(&case, &encoded, &decoder, None);
    let actual = roundtrip(&source, &[("input", data(&input_shape, &inputs)?)])?;
    same_values(&actual["encoded"], &encoded, "encoder");
    same_values(&actual["logits"], &logits, "decoder");
    for (&actual, &expected) in actual["output"].iter().zip(&logits) {
        let probability = 1. / (1. + (-f64::from(expected)).exp());
        assert!((f64::from(actual) - probability).abs() <= 8. * f64::from(f32::EPSILON));
    }
    Ok(())
}

#[test]
fn transpose_inserted_zeros_do_not_inherit_nonfinite_source_values() -> Test {
    let case = Case {
        input: [1, 1, 2, 2],
        weight: [1, 1, 1, 1],
        output: [1, 1, 6, 6],
        strides: [3, 3],
        dilations: [1, 1],
        pad_begin: [0, 0],
        groups: 1,
        attributes: [
            ints_attr("strides", &[3, 3]),
            ints_attr("output_padding", &[2, 2]),
        ]
        .concat(),
    };
    let source = case.source(&[2.], None);
    for values in [
        [f32::INFINITY, 2., 3., f32::NEG_INFINITY],
        [f32::NAN, 2., 3., 4.],
        [f32::MAX, f32::MIN, 0., -0.],
    ] {
        let actual = roundtrip(&source, &[("input", data(&case.input, &values)?)])?;
        same_values(
            &actual["output"],
            &scatter(&case, &values, &[2.], None),
            "nonfinite source support",
        );
        for (index, &value) in actual["output"].iter().enumerate() {
            if ![0, 3, 18, 21].contains(&index) {
                assert_eq!(value.to_bits(), 0.0_f32.to_bits(), "true zero at {index}");
            }
        }
    }
    // Finite original model input may overflow in an upstream operator. The
    // importer must not derive padding by subtracting a feature from itself.
    let source = model(
        &[
            node("Conv", &["input", "double"], &["overflow"], &[]),
            node(
                "ConvTranspose",
                &["overflow", "unit"],
                &["output"],
                &case.attributes,
            ),
            weight("double", &[1, 1, 1, 1], &[2.]),
            weight("unit", &[1, 1, 1, 1], &[1.]),
            bytes(11, &info("input", &case.input, 1)),
            bytes(12, &info("output", &case.output, 1)),
        ]
        .concat(),
    );
    let values = [f32::MAX, 1., 2., 3.];
    let actual = roundtrip(&source, &[("input", data(&case.input, &values)?)])?;
    same_values(
        &actual["output"],
        &scatter(&case, &[f32::INFINITY, 2., 4., 6.], &[1.], None),
        "upstream overflow support",
    );
    Ok(())
}

fn malformed_source(input: &[usize], filter: &[usize], output: &[usize], attrs: &[u8]) -> Vec<u8> {
    model(
        &[
            node("ConvTranspose", &["input", "weight"], &["output"], attrs),
            weight("weight", filter, &vec![0.5; filter.iter().product()]),
            bytes(11, &info("input", input, 1)),
            bytes(12, &info("output", output, 1)),
        ]
        .concat(),
    )
}

#[test]
fn transpose_refuses_invalid_geometry_attributes_and_inconsistent_declared_shapes() {
    let case = basic_case();
    for attrs in [
        int_attr("group", 0),
        int_attr("group", -1),
        int_attr("group", 2),
        ints_attr("group", &[1]),
        ints_attr("strides", &[0, 1]),
        ints_attr("strides", &[-1, 1]),
        ints_attr("strides", &[1]),
        ints_attr("strides", &[1, 1, 1]),
        int_attr("strides", 1),
        ints_attr("dilations", &[1, 0]),
        ints_attr("dilations", &[1, -1]),
        ints_attr("pads", &[0, -1, 0, 0]),
        ints_attr("pads", &[0, 0]),
        ints_attr("pads", &[3, 0, 0, 0]),
        ints_attr("output_padding", &[1, 0]),
        ints_attr("output_padding", &[-1, 0]),
        ints_attr("output_padding", &[0, 0, 0, 0]),
        ints_attr("kernel_shape", &[3, 2]),
        ints_attr("kernel_shape", &[2]),
        ints_attr("output_shape", &[0, 3]),
        ints_attr("output_shape", &[-1, 3]),
        ints_attr("output_shape", &[1, 1, 3, 3]),
        int_attr("output_shape", 3),
        int_attr("auto_pad", 0),
        [
            string_attr("auto_pad", "VALID"),
            ints_attr("pads", &[0, 0, 0, 0]),
        ]
        .concat(),
        [ints_attr("output_shape", &[3, 3]), int_attr("pads", 0)].concat(),
    ] {
        assert_eq!(
            refusal(&malformed_source(
                &case.input,
                &case.weight,
                &case.output,
                &attrs
            )),
            Some(OnnxError::Graph),
            "{attrs:?}"
        );
    }
    for attrs in [
        string_attr("auto_pad", "SAME"),
        int_attr("ceil_mode", 1),
        int_attr("training_mode", 1),
    ] {
        assert_eq!(
            refusal(&malformed_source(
                &case.input,
                &case.weight,
                &case.output,
                &attrs
            )),
            Some(OnnxError::Unsupported)
        );
    }
    assert_eq!(
        refusal(&malformed_source(
            &case.input,
            &case.weight,
            &[1, 1, 4, 3],
            &[]
        )),
        Some(OnnxError::Graph),
    );
    assert_eq!(
        refusal(&malformed_source(
            &[1, 2, 2, 2],
            &case.weight,
            &case.output,
            &[]
        )),
        Some(OnnxError::Graph),
    );
    for (input, filter, output) in [
        (vec![1, 1, 2], vec![1, 1, 2], vec![1, 1, 3]),
        (
            vec![1, 1, 2, 2, 2],
            vec![1, 1, 2, 2, 2],
            vec![1, 1, 3, 3, 3],
        ),
        (vec![1, 1, 2, 2], vec![1, 1, 2], vec![1, 1, 3, 3]),
    ] {
        assert_eq!(
            refusal(&malformed_source(&input, &filter, &output, &[])),
            Some(OnnxError::Unsupported)
        );
    }
    // Desired SAME/output_shape larger than the uncropped extent needs negative
    // padding, which is outside this declared profile and must not be clamped.
    for attrs in [
        [
            ints_attr("strides", &[3, 3]),
            string_attr("auto_pad", "SAME_UPPER"),
        ]
        .concat(),
        [
            ints_attr("strides", &[3, 3]),
            string_attr("auto_pad", "SAME_LOWER"),
        ]
        .concat(),
        [
            ints_attr("strides", &[3, 3]),
            ints_attr("output_shape", &[6, 6]),
        ]
        .concat(),
    ] {
        assert_eq!(
            refusal(&malformed_source(
                &[1, 1, 2, 2],
                &[1, 1, 1, 1],
                &[1, 1, 6, 6],
                &attrs
            )),
            Some(OnnxError::Unsupported)
        );
    }
    let duplicate = [int_attr("group", 1), int_attr("group", 1)].concat();
    assert_eq!(
        refusal(&malformed_source(
            &case.input,
            &case.weight,
            &case.output,
            &duplicate
        )),
        Some(OnnxError::Malformed)
    );
}

#[test]
fn transpose_refuses_dynamic_nonfinite_or_rebound_weights_and_invalid_biases() {
    let case = basic_case();
    let dynamic = model(
        &[
            node("ConvTranspose", &["input", "weight"], &["output"], &[]),
            bytes(11, &info("input", &case.input, 1)),
            bytes(11, &info("weight", &case.weight, 1)),
            bytes(12, &info("output", &case.output, 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&dynamic), Some(OnnxError::Unsupported));
    let from_runtime = model(
        &[
            node("Identity", &["runtime-weight"], &["weight"], &[]),
            node("ConvTranspose", &["input", "weight"], &["output"], &[]),
            bytes(11, &info("input", &case.input, 1)),
            bytes(11, &info("runtime-weight", &case.weight, 1)),
            bytes(12, &info("output", &case.output, 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&from_runtime), Some(OnnxError::Unsupported));
    let rebound = model(
        &[
            node("ConvTranspose", &["input", "weight"], &["output"], &[]),
            weight("weight", &case.weight, &[1.; 4]),
            bytes(11, &info("input", &case.input, 1)),
            bytes(11, &info("weight", &case.weight, 1)),
            bytes(12, &info("output", &case.output, 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&rebound), Some(OnnxError::Malformed));
    for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        assert_eq!(
            refusal(&case.source(&[1., value, 2., 3.], None)),
            Some(OnnxError::NonFinite)
        );
        assert_eq!(
            refusal(&case.source(&[1.; 4], Some(&[value]))),
            Some(OnnxError::NonFinite)
        );
    }
    for shape in [vec![], vec![2], vec![1, 1, 1, 1]] {
        let source = model(
            &[
                node(
                    "ConvTranspose",
                    &["input", "weight", "bias"],
                    &["output"],
                    &[],
                ),
                weight("weight", &case.weight, &[1.; 4]),
                bytes(11, &info("input", &case.input, 1)),
                bytes(11, &info("bias", &shape, 1)),
                bytes(12, &info("output", &case.output, 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Graph));
    }
    for inputs in [
        vec!["input"],
        vec!["input", ""],
        vec!["", "weight"],
        vec!["input", "weight", "", "weight"],
    ] {
        let source = model(
            &[
                node("ConvTranspose", &inputs, &["output"], &[]),
                weight("weight", &case.weight, &[1.; 4]),
                bytes(11, &info("input", &case.input, 1)),
                bytes(12, &info("output", &case.output, 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Graph));
    }
}

fn limited_import(source: &[u8], limits: OnnxLimits) -> Result<ImportedOnnx<'_>, OnnxError> {
    import_onnx(
        source,
        ContentDigest::sha256(source),
        GENERATION,
        limits,
        &|| false,
    )
}

// Find the boundary using public outcomes, without duplicating the lowering's
// helper-count, reserved-name or allocation accounting formulas.
fn minimum_limit(
    source: &[u8],
    upper: usize,
    configure: impl Fn(usize) -> OnnxLimits,
) -> Test<usize> {
    assert!(limited_import(source, configure(upper)).is_ok());
    let (mut lower, mut upper) = (0, upper);
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        match limited_import(source, configure(middle)) {
            Ok(_) => upper = middle,
            Err(OnnxError::Limit) => lower = middle + 1,
            Err(error) => return Err(format!("unexpected bound failure: {error:?}").into()),
        }
    }
    assert!(lower > 0);
    assert_eq!(
        limited_import(source, configure(lower - 1)).err(),
        Some(OnnxError::Limit)
    );
    Ok(lower)
}

#[test]
fn transpose_admission_bounds_cover_all_helpers_original_and_generated_parameters_and_work() -> Test
{
    let case = Case {
        input: [1, 1, 2, 3],
        weight: [1, 2, 2, 3],
        output: [1, 2, 4, 9],
        strides: [2, 3],
        dilations: [1, 1],
        pad_begin: [0, 0],
        groups: 1,
        attributes: ints_attr("strides", &[2, 3]),
    };
    let source = case.source(&generated_values(12, 0), None);
    let imported = import(&source)?;
    let defaults = OnnxLimits::default();
    let nodes = minimum_limit(&source, defaults.nodes, |nodes| OnnxLimits {
        nodes,
        ..defaults
    })?;
    let tensors = minimum_limit(&source, defaults.tensors, |tensors| OnnxLimits {
        tensors,
        ..defaults
    })?;
    let parameter_bytes = minimum_limit(&source, defaults.parameter_bytes, |parameter_bytes| {
        OnnxLimits {
            parameter_bytes,
            ..defaults
        }
    })?;
    let tensor_bytes = minimum_limit(&source, defaults.tensor_bytes, |tensor_bytes| OnnxLimits {
        tensor_bytes,
        ..defaults
    })?;
    assert_eq!(nodes, imported.graph().node_count());
    assert!(parameter_bytes > case.weight.iter().product::<usize>() * 4);
    let limits = OnnxLimits {
        source_bytes: source.len(),
        nodes,
        tensors,
        parameter_bytes,
        tensor_bytes,
        work_units: imported.work_units(),
    };
    assert!(limited_import(&source, limits).is_ok());
    assert_eq!(
        limited_import(
            &source,
            OnnxLimits {
                source_bytes: source.len() - 1,
                ..limits
            }
        )
        .err(),
        Some(OnnxError::Limit)
    );
    assert_eq!(
        limited_import(
            &source,
            OnnxLimits {
                work_units: imported.work_units() - 1,
                ..limits
            }
        )
        .err(),
        Some(OnnxError::WorkBudget)
    );
    assert_eq!(
        import_onnx(
            &source,
            ContentDigest::sha256(b"other source"),
            GENERATION,
            limits,
            &|| false
        )
        .err(),
        Some(OnnxError::Digest)
    );
    let calls = Cell::new(0_usize);
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
            "checkpoint {stop}/{total}",
        );
    }
    Ok(())
}

#[test]
fn transpose_expansion_is_bounded_even_when_the_final_crop_is_tiny() -> Test {
    let tiny_crop = malformed_source(
        &[1, 1, 2, 2],
        &[1, 1, 1, 1],
        &[1, 1, 1, 1],
        &[
            ints_attr("strides", &[8, 8]),
            ints_attr("pads", &[0, 0, 8, 8]),
        ]
        .concat(),
    );
    assert!(limited_import(&tiny_crop, OnnxLimits::default()).is_ok());
    // The source and result each fit, but necessary expanded intermediates do not.
    assert_eq!(
        limited_import(
            &tiny_crop,
            OnnxLimits {
                tensor_bytes: 16,
                ..OnnxLimits::default()
            }
        )
        .err(),
        Some(OnnxError::Limit)
    );
    let huge = malformed_source(
        &[1, 1, 2, 2],
        &[1, 1, 1, 1],
        &[1, 1, 1, 1],
        &[
            ints_attr("strides", &[i64::MAX, i64::MAX]),
            ints_attr("output_shape", &[1, 1]),
        ]
        .concat(),
    );
    assert_eq!(refusal(&huge), Some(OnnxError::Limit));
    let ordinary = Case {
        input: [1, 4, 16, 16],
        weight: [4, 8, 3, 3],
        output: [1, 8, 63, 63],
        strides: [4, 4],
        dilations: [1, 1],
        pad_begin: [0, 0],
        groups: 1,
        attributes: ints_attr("strides", &[4, 4]),
    };
    let source = ordinary.source(&generated_values(288, 1), None);
    let imported = import(&source)?;
    let bytes = imported
        .parameters()
        .values()
        .map(|tensor| tensor.to_vec::<f32>().map(|values| values.len() * 4))
        .collect::<Result<Vec<_>, _>>()?;
    // Source + transformed filters + one scalar are a conservative upper bound;
    // no image-sized zero parameter or dense interpolation matrix may appear.
    assert!(bytes.iter().sum::<usize>() <= 2 * 288 * 4 + 4);
    assert!(imported.graph().node_count() < 96);
    Ok(())
}

#[test]
fn transpose_generated_names_cannot_capture_future_source_outputs_or_forward_references() -> Test {
    let case = Case {
        input: [1, 1, 2, 3],
        weight: [1, 2, 2, 2],
        output: [1, 2, 4, 8],
        strides: [2, 3],
        dilations: [1, 1],
        pad_begin: [0, 0],
        groups: 1,
        attributes: ints_attr("strides", &[2, 3]),
    };
    let weights = generated_values(8, 1);
    let values = generated_values(6, 4);
    let source = case.source(&weights, None);
    let imported = import(&source)?;
    let names = imported
        .graph()
        .nodes()
        .iter()
        .flat_map(|node| node.outputs().iter().cloned())
        .chain(imported.parameters().keys().cloned())
        .filter(|name| name != "output" && name != "weight")
        .collect::<std::collections::BTreeSet<_>>();
    assert!(!names.is_empty());
    for name in names {
        let source = model(
            &[
                node(
                    "ConvTranspose",
                    &["input", "weight"],
                    &["output"],
                    &case.attributes,
                ),
                node("Identity", &["input"], &[&name], &[]),
                weight("weight", &case.weight, &weights),
                bytes(11, &info("input", &case.input, 1)),
                bytes(12, &info("output", &case.output, 1)),
                bytes(12, &info(&name, &case.input, 1)),
            ]
            .concat(),
        );
        let actual = roundtrip(&source, &[("input", data(&case.input, &values)?)])?;
        same_values(
            &actual["output"],
            &scatter(&case, &values, &weights, None),
            "reserved output",
        );
        assert_eq!(bits(&actual[&name]), bits(&values));
        let forward = model(
            &[
                node(
                    "ConvTranspose",
                    &[&name, "weight"],
                    &["output"],
                    &case.attributes,
                ),
                node("Identity", &["input"], &[&name], &[]),
                weight("weight", &case.weight, &weights),
                bytes(11, &info("input", &case.input, 1)),
                bytes(12, &info("output", &case.output, 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&forward), Some(OnnxError::Graph));
    }
    Ok(())
}

#[test]
fn transpose_real_executors_enforce_exact_budgets_generations_and_cancellation() -> Test {
    let case = Case {
        input: [1, 1, 2, 3],
        weight: [1, 2, 2, 2],
        output: [1, 2, 4, 6],
        strides: [2, 2],
        dilations: [1, 1],
        pad_begin: [0, 0],
        groups: 1,
        attributes: ints_attr("strides", &[2, 2]),
    };
    let source = case.source(&generated_values(8, 4), None);
    let imported = import(&source)?;
    let input = [("input", data(&case.input, &generated_values(6, 2))?)];
    let constants = imported
        .parameters()
        .iter()
        .map(|(name, tensor)| Ok((name.clone(), tensor.to_vec::<f32>()?)))
        .collect::<Result<BTreeMap<_, _>, fss_tensor::TensorError>>()?;
    let optimized = optimized_executor::OptimizedGraph::prepare(
        imported.graph(),
        &constants,
        &ScalarExecCx::new(),
    )?;
    let mut bindings = imported.parameters().clone();
    bindings.insert("input".into(), input[0].1.clone());
    let bindings = bindings.into_iter().collect::<Vec<_>>();
    let outcome = ScalarExecutor::run(
        imported.graph(),
        &bindings,
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    let exact = ExecBudget::new(outcome.executed_macs(), outcome.allocated_bytes());
    assert!(ScalarExecutor::run(imported.graph(), &bindings, exact, &ScalarExecCx::new()).is_ok());
    assert!(optimized.run(&input, exact, &ScalarExecCx::new()).is_ok());
    for budget in [
        ExecBudget::new(outcome.executed_macs() - 1, outcome.allocated_bytes()),
        ExecBudget::new(outcome.executed_macs(), outcome.allocated_bytes() - 1),
    ] {
        assert!(matches!(
            ScalarExecutor::run(imported.graph(), &bindings, budget, &ScalarExecCx::new()),
            Err(ExecError::BudgetExceeded { .. })
        ));
        assert!(matches!(
            optimized.run(&input, budget, &ScalarExecCx::new()),
            Err(ExecError::BudgetExceeded { .. })
        ));
    }
    let stale = Tensor::from_values(
        Shape::new(case.input.to_vec())?,
        &generated_values(6, 2),
        Generation(GENERATION.0 + 1),
    )?;
    let mut stale_bindings = bindings.clone();
    stale_bindings
        .iter_mut()
        .find(|(name, _)| name == "input")
        .ok_or("input binding")?
        .1 = stale.clone();
    assert!(matches!(
        ScalarExecutor::run(
            imported.graph(),
            &stale_bindings,
            exact,
            &ScalarExecCx::new()
        ),
        Err(ExecError::GenerationMismatch { .. })
    ));
    assert!(matches!(
        optimized.run(&[("input", stale)], exact, &ScalarExecCx::new()),
        Err(ExecError::GenerationMismatch { .. })
    ));
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    assert!(matches!(
        ScalarExecutor::run(imported.graph(), &bindings, exact, &cx),
        Err(ExecError::CancellationRequested { .. })
    ));
    assert!(cx.is_drain_completed());
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    assert!(matches!(
        optimized.run(&input, exact, &cx),
        Err(ExecError::CancellationRequested { .. })
    ));
    assert!(cx.is_drain_completed());
    Ok(())
}
