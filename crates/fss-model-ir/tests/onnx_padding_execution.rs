#![forbid(unsafe_code)]
//! Static ONNX automatic padding through the real importer and artifact parsing
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Padding {
    Valid,
    Upper,
    Lower,
}
impl Padding {
    fn name(self) -> &'static str {
        match self {
            Self::Valid => "VALID",
            Self::Upper => "SAME_UPPER",
            Self::Lower => "SAME_LOWER",
        }
    }
}

/// Independent small-fixture oracle: enumerate the complete windows in each
/// candidate padded extent, and take the smallest extent reaching SAME's number
/// of stride anchors. It never reads the importer's pads or native shape code.
fn starts(
    input: usize,
    kernel: usize,
    stride: usize,
    dilation: usize,
    mode: Padding,
) -> Vec<isize> {
    let footprint = (kernel - 1) * dilation + 1;
    let complete = |extent: usize| {
        (0..extent)
            .step_by(stride)
            .filter(|&start| start + footprint <= extent)
            .collect::<Vec<_>>()
    };
    if mode == Padding::Valid {
        return complete(input).into_iter().map(|n| n as isize).collect();
    }
    let desired = (0..input).step_by(stride).count();
    for extension in 0..footprint {
        let positions = complete(input + extension);
        if positions.len() == desired {
            let leading = match mode {
                Padding::Upper => extension / 2,
                Padding::Lower => extension.div_ceil(2),
                Padding::Valid => 0,
            };
            return positions
                .into_iter()
                .map(|n| n as isize - leading as isize)
                .collect();
        }
    }
    Vec::new()
}

fn attrs(kernel: [usize; 2], stride: [usize; 2], mode: Padding) -> Vec<u8> {
    [
        ints_attr("kernel_shape", &kernel.map(|n| n as i64)),
        ints_attr("strides", &stride.map(|n| n as i64)),
        text_attr("auto_pad", mode.name()),
    ]
    .concat()
}

fn pool_source(op: &str, input: [usize; 4], output: [usize; 4], attrs: &[u8]) -> Vec<u8> {
    model(
        &[
            node(op, &["input"], &["output"], attrs),
            bytes(11, &info("input", &input, 1)),
            bytes(12, &info("output", &output, 1)),
        ]
        .concat(),
    )
}

fn conv_source(
    input: [usize; 4],
    output: [usize; 4],
    weight_shape: [usize; 4],
    weights: &[f32],
    bias: Option<&[f32]>,
    attrs: &[u8],
) -> Vec<u8> {
    let inputs = if bias.is_some() {
        vec!["input", "kernel", "bias"]
    } else {
        vec!["input", "kernel"]
    };
    model(
        &[
            node("Conv", &inputs, &["output"], attrs),
            weight("kernel", &weight_shape, weights),
            bias.map_or_else(Vec::new, |b| weight("bias", &[output[1]], b)),
            bytes(11, &info("input", &input, 1)),
            bytes(12, &info("output", &output, 1)),
        ]
        .concat(),
    )
}

/// A real-coordinate pooling oracle: only original input samples participate in
/// the maximum/sum. Average padding changes the denominator, never the samples.
fn pool_oracle(
    values: &[f32],
    input: [usize; 4],
    kernel: [usize; 2],
    stride: [usize; 2],
    mode: Padding,
    average: Option<bool>,
) -> ([usize; 4], Vec<f32>) {
    let ys = starts(input[2], kernel[0], stride[0], 1, mode);
    let xs = starts(input[3], kernel[1], stride[1], 1, mode);
    let output = [input[0], input[1], ys.len(), xs.len()];
    let mut result = Vec::new();
    for plane in 0..input[0] * input[1] {
        for &y in &ys {
            for &x in &xs {
                let mut sum = 0_f32;
                let mut maximum = f32::NEG_INFINITY;
                let mut count = 0_usize;
                for row in 0..input[2] {
                    for col in 0..input[3] {
                        if (row as isize) < y
                            || (row as isize) >= y + kernel[0] as isize
                            || (col as isize) < x
                            || (col as isize) >= x + kernel[1] as isize
                        {
                            continue;
                        }
                        let value = values[(plane * input[2] + row) * input[3] + col];
                        sum += value;
                        maximum = maximum.max(value);
                        count += 1;
                    }
                }
                assert!(count > 0, "oracle fixture must overlap real input");
                result.push(match average {
                    None => maximum,
                    Some(include_padding) => {
                        let divisor = if include_padding {
                            kernel[0] * kernel[1]
                        } else {
                            count
                        };
                        sum / divisor as f32
                    }
                });
            }
        }
    }
    (output, result)
}

struct Convolution {
    input: [usize; 4],
    outputs: usize,
    kernel: [usize; 2],
    stride: [usize; 2],
    dilation: [usize; 2],
    groups: usize,
}

fn conv_oracle(
    values: &[f32],
    weights: &[f32],
    bias: Option<&[f32]>,
    spec: &Convolution,
    mode: Padding,
) -> ([usize; 4], Vec<f32>) {
    let ys = starts(
        spec.input[2],
        spec.kernel[0],
        spec.stride[0],
        spec.dilation[0],
        mode,
    );
    let xs = starts(
        spec.input[3],
        spec.kernel[1],
        spec.stride[1],
        spec.dilation[1],
        mode,
    );
    let output = [spec.input[0], spec.outputs, ys.len(), xs.len()];
    let mut result = Vec::new();
    let channels = spec.input[1] / spec.groups;
    let kernel_size = spec.kernel[0] * spec.kernel[1];
    let per_output = channels * kernel_size;
    for batch in 0..spec.input[0] {
        for channel in 0..spec.outputs {
            let group = channel / (spec.outputs / spec.groups);
            let selected = &weights[channel * per_output..(channel + 1) * per_output];
            for &y in &ys {
                for &x in &xs {
                    let mut sum = 0_f32;
                    for (index, &coefficient) in selected.iter().enumerate() {
                        let input_channel = group * channels + index / kernel_size;
                        let row = y
                            + ((index % kernel_size / spec.kernel[1]) * spec.dilation[0]) as isize;
                        let col = x + ((index % spec.kernel[1]) * spec.dilation[1]) as isize;
                        if row < 0
                            || row >= spec.input[2] as isize
                            || col < 0
                            || col >= spec.input[3] as isize
                        {
                            continue;
                        }
                        let source = ((batch * spec.input[1] + input_channel) * spec.input[2]
                            + row as usize)
                            * spec.input[3]
                            + col as usize;
                        sum += values[source] * coefficient;
                    }
                    result.push(sum + bias.map_or(0., |b| b[channel]));
                }
            }
        }
    }
    (output, result)
}

#[test]
fn odd_padding_has_independent_hand_computed_upper_lower_and_valid_outputs() -> Test {
    let input = [1, 1, 3, 4];
    let values: Vec<_> = (1..=12).map(|n| n as f32).collect();
    let tensor = Tensor::from_values(Shape::new(input.to_vec())?, &values, GENERATION)?;
    for (mode, output, sums, maxima, include, exclude) in [
        (
            Padding::Upper,
            [1, 1, 2, 2],
            vec![24.5, 22.5, 30.5, 23.5],
            vec![7., 8., 11., 12.],
            vec![4., 22_f32 / 6., 5., 23_f32 / 6.],
            vec![4., 5.5, 10., 11.5],
        ),
        (
            Padding::Lower,
            [1, 1, 2, 2],
            vec![3.5, 9.5, 30.5, 54.5],
            vec![2., 4., 10., 12.],
            vec![0.5, 1.5, 5., 9.],
            vec![1.5, 3., 7.5, 9.],
        ),
        (
            Padding::Valid,
            [1, 1, 1, 1],
            vec![24.5],
            vec![7.],
            vec![4.],
            vec![4.],
        ),
    ] {
        let attributes = attrs([2, 3], [2, 2], mode);
        let source = conv_source(
            input,
            output,
            [1, 1, 2, 3],
            &[1.; 6],
            Some(&[0.5]),
            &attributes,
        );
        assert_eq!(
            bits(&roundtrip(&source, &[("input", tensor.clone())])?["output"]),
            bits(&sums),
            "{mode:?} convolution",
        );
        for (op, include_padding, expected) in [
            ("MaxPool", None, maxima),
            ("AveragePool", Some(true), include),
            ("AveragePool", Some(false), exclude),
        ] {
            let mut attributes = attributes.clone();
            if let Some(include_padding) = include_padding {
                attributes.extend(int_attr("count_include_pad", i64::from(include_padding)));
            }
            let source = pool_source(op, input, output, &attributes);
            assert_eq!(
                bits(&roundtrip(&source, &[("input", tensor.clone())])?["output"]),
                bits(&expected),
                "{mode:?} {op} {include_padding:?}",
            );
        }
    }
    Ok(())
}

#[test]
fn automatic_pooling_matches_coordinate_oracle_across_static_shapes_and_wide_strides() -> Test {
    let mut cases = 0;
    for input in [[1, 1, 1, 1], [2, 3, 3, 4], [1, 2, 5, 6]] {
        let count = input.iter().product::<usize>();
        // All-negative inputs make accidental zero padding of MaxPool visible.
        let values: Vec<_> = (0..count).map(|n| -((n % 29 + 1) as f32) * 0.25).collect();
        let tensor = Tensor::from_values(Shape::new(input.to_vec())?, &values, GENERATION)?;
        for kernel in [[1, 1], [2, 3], [5, 7]] {
            for stride in [[1, 1], [2, 2], [7, 8]] {
                for mode in [Padding::Valid, Padding::Upper, Padding::Lower] {
                    for average in [None, Some(false), Some(true)] {
                        let (output, expected) =
                            pool_oracle(&values, input, kernel, stride, mode, average);
                        if output[2] == 0 || output[3] == 0 {
                            continue;
                        }
                        let op = if average.is_some() {
                            "AveragePool"
                        } else {
                            "MaxPool"
                        };
                        let mut attributes = attrs(kernel, stride, mode);
                        if let Some(include_padding) = average {
                            attributes
                                .extend(int_attr("count_include_pad", i64::from(include_padding)));
                        }
                        let source = pool_source(op, input, output, &attributes);
                        assert_eq!(
                            bits(&roundtrip(&source, &[("input", tensor.clone())])?["output"]),
                            bits(&expected),
                            "{op} {input:?} kernel={kernel:?} stride={stride:?} {mode:?} {average:?}",
                        );
                        cases += 1;
                    }
                }
            }
        }
    }
    assert_eq!(cases, 207);
    Ok(())
}

#[test]
fn automatic_convolution_matches_coordinate_oracle_with_groups_dilation_and_bias() -> Test {
    let input = [2, 4, 5, 6];
    let values: Vec<_> = (0..240).map(|n| (n % 31) as f32 * 0.25 - 4.).collect();
    let tensor = Tensor::from_values(Shape::new(input.to_vec())?, &values, GENERATION)?;
    let biases = [-0.5, 0.25, 1.5, -2.];
    let mut cases = 0;
    for groups in [1, 2, 4] {
        let weight_shape = [4, 4 / groups, 2, 3];
        let weights: Vec<_> = (0..weight_shape.iter().product::<usize>())
            .map(|n| ((n * 7 % 17) as f32 - 8.) * 0.125)
            .collect();
        for dilation in [[1, 1], [2, 3]] {
            for stride in [[1, 1], [2, 2], [3, 7]] {
                let spec = Convolution {
                    input,
                    outputs: 4,
                    kernel: [2, 3],
                    stride,
                    dilation,
                    groups,
                };
                for mode in [Padding::Valid, Padding::Upper, Padding::Lower] {
                    for bias in [None, Some(biases.as_slice())] {
                        let (output, expected) = conv_oracle(&values, &weights, bias, &spec, mode);
                        if output[2] == 0 || output[3] == 0 {
                            continue;
                        }
                        let attributes = [
                            attrs(spec.kernel, stride, mode),
                            ints_attr("dilations", &dilation.map(|n| n as i64)),
                            int_attr("group", groups as i64),
                        ]
                        .concat();
                        let source =
                            conv_source(input, output, weight_shape, &weights, bias, &attributes);
                        assert_eq!(
                            bits(&roundtrip(&source, &[("input", tensor.clone())])?["output"]),
                            bits(&expected),
                            "groups={groups} dilation={dilation:?} stride={stride:?} {mode:?} bias={bias:?}",
                        );
                        cases += 1;
                    }
                }
            }
        }
    }
    assert_eq!(cases, 90);
    Ok(())
}

fn operation(op: &str, output: [usize; 4], attributes: &[u8]) -> Vec<u8> {
    let input = [1, 1, 3, 4];
    if op == "Conv" {
        conv_source(input, output, [1, 1, 2, 3], &[1.; 6], None, attributes)
    } else {
        pool_source(op, input, output, attributes)
    }
}

#[test]
fn notset_and_absent_auto_pad_preserve_explicit_padding_graph_and_parameter_semantics() -> Test {
    for op in ["Conv", "MaxPool", "AveragePool"] {
        let attributes = [
            ints_attr("kernel_shape", &[2, 3]),
            ints_attr("strides", &[2, 2]),
            ints_attr("pads", &[1, 0, 0, 1]),
        ]
        .concat();
        let original = operation(op, [1, 1, 2, 2], &attributes);
        let explicit_notset = operation(
            op,
            [1, 1, 2, 2],
            &[attributes, text_attr("auto_pad", "NOTSET")].concat(),
        );
        let original = import(&original)?;
        let explicit_notset = import(&explicit_notset)?;
        let a = export(&original)?;
        let b = export(&explicit_notset)?;
        assert_ne!(a.source_digest(), b.source_digest());
        assert_eq!(a.graph_bytes(), b.graph_bytes(), "{op}");
        // Safetensors metadata binds each distinct original ONNX source. The
        // parameter semantics agree even though those provenance bytes differ.
        assert_ne!(
            a.weights_bytes(),
            b.weights_bytes(),
            "{op} source provenance"
        );
        let original_parameters = reloaded(&a)?;
        let notset_parameters = reloaded(&b)?;
        assert!(
            original_parameters.keys().eq(notset_parameters.keys()),
            "{op} parameter names",
        );
        for (name, original) in &original_parameters {
            let notset = notset_parameters
                .get(name)
                .ok_or("missing NOTSET parameter")?;
            assert_eq!(
                original.shape().dims(),
                notset.shape().dims(),
                "{op} {name}"
            );
            assert_eq!(
                bits(&original.to_vec::<f32>()?),
                bits(&notset.to_vec::<f32>()?),
                "{op} {name} parameter values",
            );
        }
        assert_eq!(a.importer_identity(), b.importer_identity());
    }
    Ok(())
}

#[test]
fn all_automatic_modes_refuse_explicit_pads_even_when_they_are_zero() {
    for op in ["Conv", "MaxPool", "AveragePool"] {
        for mode in [Padding::Valid, Padding::Upper, Padding::Lower] {
            for pads in [[0; 4], [1, 0, 0, 1]] {
                let attributes = [attrs([2, 3], [1, 1], mode), ints_attr("pads", &pads)].concat();
                let source = operation(op, [1, 1, 3, 4], &attributes);
                assert_eq!(
                    refusal(&source),
                    Some(OnnxError::Graph),
                    "{op} {mode:?} {pads:?}"
                );
            }
        }
    }
}

#[test]
fn malformed_automatic_padding_and_shape_disagreements_refuse_before_execution() {
    for op in ["Conv", "MaxPool", "AveragePool"] {
        for (extra, expected) in [
            (text_attr("auto_pad", "same_upper"), OnnxError::Unsupported),
            (text_attr("auto_pad", "SAME"), OnnxError::Unsupported),
            (text_attr("auto_pad", ""), OnnxError::Unsupported),
            (int_attr("auto_pad", 0), OnnxError::Graph),
            (ints_attr("auto_pad", &[1]), OnnxError::Graph),
            (
                [
                    text_attr("auto_pad", "SAME_UPPER"),
                    text_attr("auto_pad", "SAME_LOWER"),
                ]
                .concat(),
                OnnxError::Malformed,
            ),
        ] {
            let source = operation(
                op,
                [1, 1, 3, 4],
                &[ints_attr("kernel_shape", &[2, 3]), extra].concat(),
            );
            assert_eq!(refusal(&source), Some(expected), "{op}");
        }
        for extra in [
            ints_attr("strides", &[0, 1]),
            ints_attr("strides", &[-1, 1]),
            ints_attr("strides", &[1]),
            int_attr("strides", 1),
        ] {
            let source = operation(
                op,
                [1, 1, 3, 4],
                &[
                    ints_attr("kernel_shape", &[2, 3]),
                    text_attr("auto_pad", "SAME_UPPER"),
                    extra,
                ]
                .concat(),
            );
            assert_eq!(refusal(&source), Some(OnnxError::Graph), "{op}");
        }
        for output in [[1, 1, 3, 3], [1, 1, 2, 4], [1, 1, 4, 3]] {
            let source = operation(op, output, &attrs([2, 3], [1, 1], Padding::Upper));
            assert_eq!(refusal(&source), Some(OnnxError::Graph), "{op} {output:?}");
        }
    }
}

#[test]
fn huge_stride_is_exact_but_dilated_extent_overflow_is_a_bounded_refusal() -> Test {
    let stride = i64::MAX;
    let values: Vec<_> = (1..=12).map(|n| n as f32).collect();
    let input = Tensor::from_values(Shape::new(vec![1, 1, 3, 4])?, &values, GENERATION)?;
    for op in ["Conv", "MaxPool", "AveragePool"] {
        let source = operation(
            op,
            [1, 1, 1, 1],
            &[
                ints_attr("kernel_shape", &[2, 3]),
                ints_attr("strides", &[stride, stride]),
                text_attr("auto_pad", "SAME_LOWER"),
            ]
            .concat(),
        );
        let expected = match op {
            "Conv" => 24.,
            "MaxPool" => 7.,
            _ => 4.,
        };
        assert_eq!(
            roundtrip(&source, &[("input", input.clone())])?["output"],
            [expected]
        );
    }
    let overflow = conv_source(
        [1, 1, 3, 4],
        [1, 1, 3, 4],
        [1, 1, 3, 3],
        &[1.; 9],
        None,
        &[
            ints_attr("kernel_shape", &[3, 3]),
            ints_attr("dilations", &[i64::MAX, 1]),
            text_attr("auto_pad", "SAME_UPPER"),
        ]
        .concat(),
    );
    assert_eq!(refusal(&overflow), Some(OnnxError::Limit));
    Ok(())
}

#[test]
fn automatic_padding_retains_exact_import_resource_ceilings() -> Test {
    for op in ["Conv", "MaxPool", "AveragePool"] {
        let source = operation(op, [1, 1, 3, 4], &attrs([2, 3], [1, 1], Padding::Upper));
        let imported = import(&source)?;
        let parameter_bytes = imported
            .parameters()
            .values()
            .map(|tensor| tensor.shape().num_elements().map(|n| n * 4))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .sum::<usize>();
        let exact = OnnxLimits {
            source_bytes: source.len(),
            nodes: imported.graph().nodes().len(),
            parameter_bytes,
            work_units: imported.work_units(),
            ..OnnxLimits::default()
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
            encode_canonical_model_ir(imported.graph())?,
        );
        for limits in [
            OnnxLimits {
                source_bytes: source.len() - 1,
                ..exact
            },
            OnnxLimits {
                nodes: exact.nodes - 1,
                ..exact
            },
            OnnxLimits {
                tensor_bytes: 47,
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
                Some(OnnxError::Limit),
                "{op} {limits:?}",
            );
        }
        if parameter_bytes > 0 {
            assert_eq!(
                import_onnx(
                    &source,
                    ContentDigest::sha256(&source),
                    GENERATION,
                    OnnxLimits {
                        parameter_bytes: parameter_bytes - 1,
                        ..exact
                    },
                    &|| false
                )
                .err(),
                Some(OnnxError::Limit),
                "{op} generated/embedded parameters",
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
            Some(OnnxError::WorkBudget),
            "{op} work",
        );
        let artifacts = export(&imported)?;
        assert_eq!(
            export_onnx_artifacts(
                &imported,
                OnnxExportLimits {
                    work_units: artifacts.work_units() - 1,
                    ..OnnxExportLimits::default()
                },
                &|| false
            )
            .err(),
            Some(OnnxError::WorkBudget),
        );
    }
    Ok(())
}

#[test]
fn every_automatic_padding_import_checkpoint_honors_cancellation_and_source_digest() -> Test {
    for op in ["Conv", "MaxPool", "AveragePool"] {
        let source = operation(op, [1, 1, 3, 4], &attrs([2, 3], [1, 1], Padding::Lower));
        let checks = Cell::new(0_usize);
        import_onnx(
            &source,
            ContentDigest::sha256(&source),
            GENERATION,
            OnnxLimits::default(),
            &|| {
                checks.set(checks.get() + 1);
                false
            },
        )?;
        for stop in 1..=checks.get() {
            let current = Cell::new(0_usize);
            assert_eq!(
                import_onnx(
                    &source,
                    ContentDigest::sha256(&source),
                    GENERATION,
                    OnnxLimits::default(),
                    &|| {
                        current.set(current.get() + 1);
                        current.get() == stop
                    }
                )
                .err(),
                Some(OnnxError::Cancelled),
                "{op} checkpoint {stop}",
            );
        }
        assert_eq!(
            import_onnx(
                &source,
                ContentDigest::sha256(b"another model"),
                GENERATION,
                OnnxLimits::default(),
                &|| false
            )
            .err(),
            Some(OnnxError::Digest),
        );
    }
    Ok(())
}
