#![forbid(unsafe_code)]
//! Static detector branches and padded pooling through real ONNX/artifact parsing
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
const GENERATION: Generation = Generation(23);
const DETECTOR: &[u8] = include_bytes!("fixtures/onnx/detector_split_pool.onnx");

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

fn split_model(
    dims: &[usize],
    axis: i64,
    parts: Option<&[i64]>,
    count: usize,
    empty_slot: bool,
) -> Vec<u8> {
    let names: Vec<_> = (0..count).map(|n| format!("part-{n}")).collect();
    let outputs: Vec<_> = names.iter().map(String::as_str).collect();
    let inputs = if parts.is_some() {
        vec!["input", "parts"]
    } else if empty_slot {
        vec!["input", ""]
    } else {
        vec!["input"]
    };
    let mut graph = vec![node("Split", &inputs, &outputs, &int_attr("axis", axis))];
    if let Some(parts) = parts {
        graph.push(bytes(5, &integer_tensor("parts", parts)));
    }
    graph.push(bytes(11, &info("input", dims, 1)));
    let normalized = if axis < 0 {
        axis + dims.len() as i64
    } else {
        axis
    };
    for (index, name) in names.iter().enumerate().rev() {
        let mut shape = dims.to_vec();
        if let Some(dimension) = usize::try_from(normalized)
            .ok()
            .and_then(|n| shape.get_mut(n))
        {
            *dimension = parts
                .and_then(|p| p.get(index))
                .and_then(|&n| usize::try_from(n).ok())
                .filter(|&n| n > 0)
                .unwrap_or_else(|| (*dimension / count.max(1)).max(1));
        }
        graph.push(bytes(12, &info(name, &shape, 1)));
    }
    model(&graph.concat())
}

/// Independent coordinate oracle: assign each source element to its output part.
fn partition(values: &[f32], dims: &[usize], axis: usize, parts: &[usize]) -> Vec<Vec<f32>> {
    let stride: usize = dims[axis + 1..].iter().product();
    let mut outputs = vec![Vec::new(); parts.len()];
    for (index, &value) in values.iter().enumerate() {
        let coordinate = index / stride % dims[axis];
        let mut boundary = 0;
        for (part, &length) in parts.iter().enumerate() {
            boundary += length;
            if coordinate < boundary {
                outputs[part].push(value);
                break;
            }
        }
    }
    outputs
}

#[test]
fn split_axes_uneven_and_equal_parts_preserve_f32_bits_and_output_order() -> Test {
    let patterns = [
        0.,
        -0.,
        f32::from_bits(1),
        f32::from_bits(0x8000_0001),
        -f32::MAX,
        f32::MAX,
        -7.,
        9.,
    ];
    for dims in [
        vec![8],
        vec![2, 8],
        vec![2, 8, 2],
        vec![2, 2, 8, 2],
        vec![1, 1, 1, 1, 1, 1, 2, 8],
    ] {
        for axis in 0..dims.len() {
            let count = dims[axis].min(3);
            let mut uneven = vec![1; count];
            uneven[count - 1] += dims[axis] - count;
            for parts in [None, Some(uneven)] {
                let count = parts.as_ref().map_or(dims[axis].min(2), Vec::len);
                let expected_parts = parts
                    .clone()
                    .unwrap_or_else(|| vec![dims[axis] / count; count]);
                let explicit = parts.map(|p| p.into_iter().map(|n| n as i64).collect::<Vec<_>>());
                let count_values: usize = dims.iter().product();
                let values: Vec<_> = (0..count_values)
                    .map(|i| patterns[i % patterns.len()])
                    .collect();
                let expected = partition(&values, &dims, axis, &expected_parts);
                for negative in [false, true] {
                    let source = split_model(
                        &dims,
                        if negative {
                            axis as i64 - dims.len() as i64
                        } else {
                            axis as i64
                        },
                        explicit.as_deref(),
                        count,
                        negative,
                    );
                    let imported = import(&source)?;
                    assert!(imported.parameters().is_empty());
                    let order: Vec<_> = imported
                        .graph()
                        .outputs()
                        .iter()
                        .map(|p| p.name())
                        .collect();
                    let names: Vec<_> = (0..count).rev().map(|n| format!("part-{n}")).collect();
                    assert_eq!(order, names.iter().map(String::as_str).collect::<Vec<_>>());
                    let tensor =
                        Tensor::from_values(Shape::new(dims.clone())?, &values, GENERATION)?;
                    let actual = roundtrip(&source, &[("input", tensor)])?;
                    for (index, expected) in expected.iter().enumerate() {
                        assert_eq!(bits(&actual[&format!("part-{index}")]), bits(expected));
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn split_default_axis_all_eight_outputs_and_single_output_execute() -> Test {
    for count in [1, 8] {
        let names: Vec<_> = (0..count).map(|n| format!("part-{n}")).collect();
        let refs: Vec<_> = names.iter().map(String::as_str).collect();
        let mut graph = vec![
            node("Split", &["input"], &refs, &[]),
            bytes(11, &info("input", &[8], 1)),
        ];
        graph.extend(
            names
                .iter()
                .map(|name| bytes(12, &info(name, &[8 / count], 1))),
        );
        let source = model(&graph.concat());
        let values = [1_f32, 2., 3., 4., 5., 6., 7., 8.];
        let tensor = Tensor::from_values(Shape::new(vec![8])?, &values, GENERATION)?;
        let actual = roundtrip(&source, &[("input", tensor)])?;
        for (part, name) in names.iter().enumerate() {
            assert_eq!(
                actual[name],
                values[part * (8 / count)..(part + 1) * (8 / count)]
            );
        }
    }
    Ok(())
}

fn pool_attrs(kernel: [usize; 2], strides: [usize; 2], pads: [usize; 4]) -> Vec<u8> {
    [
        ints_attr("kernel_shape", &kernel.map(|n| n as i64)),
        ints_attr("strides", &strides.map(|n| n as i64)),
        ints_attr("pads", &pads.map(|n| n as i64)),
    ]
    .concat()
}

/// Independent oracle enumerates real input coordinates inside each window.
fn pool(
    values: &[f32],
    dims: [usize; 4],
    kernel: [usize; 2],
    strides: [usize; 2],
    pads: [usize; 4],
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
                let candidates = (0..dims[2])
                    .flat_map(|y| (0..dims[3]).map(move |x| (y, x)))
                    .filter(|&(y, x)| {
                        y as isize >= start_y
                            && (y as isize) < start_y + kernel[0] as isize
                            && x as isize >= start_x
                            && (x as isize) < start_x + kernel[1] as isize
                    })
                    .map(|(y, x)| values[(plane * dims[2] + y) * dims[3] + x]);
                let maximum = candidates
                    .reduce(|a, b| if b > a { b } else { a })
                    .ok_or("admitted pooling window is empty")?;
                result.push(maximum);
            }
        }
    }
    Ok((out, result))
}

#[test]
fn padded_pooling_excludes_padding_for_negative_values_asymmetry_and_strides() -> Test {
    let dims = [2, 2, 4, 5];
    let values: Vec<_> = (0..80).map(|n| -((n % 17 + 1) as f32)).collect();
    let mut cases = 0;
    for kernel in [[1, 1], [2, 3], [3, 2], [3, 3], [5, 7]] {
        for strides in [[1, 1], [2, 3], [3, 2]] {
            for pads in [
                [0, 0, 0, 0],
                [kernel[0] - 1, 0, 0, kernel[1] - 1],
                [kernel[0] / 2, kernel[1] / 2, kernel[0] / 2, kernel[1] / 2],
            ] {
                if dims[2] + pads[0] + pads[2] < kernel[0]
                    || dims[3] + pads[1] + pads[3] < kernel[1]
                {
                    continue;
                }
                let (out, expected) = pool(&values, dims, kernel, strides, pads)?;
                let source = model(
                    &[
                        node(
                            "MaxPool",
                            &["input"],
                            &["output"],
                            &pool_attrs(kernel, strides, pads),
                        ),
                        bytes(11, &info("input", &dims, 1)),
                        bytes(12, &info("output", &out, 1)),
                    ]
                    .concat(),
                );
                let input = Tensor::from_values(Shape::new(dims.to_vec())?, &values, GENERATION)?;
                assert_eq!(
                    bits(&roundtrip(&source, &[("input", input)])?["output"]),
                    bits(&expected)
                );
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 42);
    Ok(())
}

#[test]
fn padded_pooling_retains_first_maximum_ties_and_extreme_finite_values() -> Test {
    for values in [
        [-0., 0., -0., 0.],
        [0., -0., 0., -0.],
        [-f32::MAX; 4],
        [f32::from_bits(1), 0., -f32::MAX, f32::MAX],
    ] {
        let (out, expected) = pool(&values, [1, 1, 2, 2], [3, 3], [1, 1], [1; 4])?;
        let source = model(
            &[
                node(
                    "MaxPool",
                    &["input"],
                    &["output"],
                    &pool_attrs([3, 3], [1, 1], [1; 4]),
                ),
                bytes(11, &info("input", &[1, 1, 2, 2], 1)),
                bytes(12, &info("output", &out, 1)),
            ]
            .concat(),
        );
        let input = Tensor::from_values(Shape::new(vec![1, 1, 2, 2])?, &values, GENERATION)?;
        assert_eq!(
            bits(&roundtrip(&source, &[("input", input)])?["output"]),
            bits(&expected)
        );
    }
    Ok(())
}

fn detector_source() -> Vec<u8> {
    let mut head = vec![0_f32; 6 * 7];
    for channel in 0..5 {
        head[channel * 7 + channel] = 1.;
    }
    head[5 * 7 + 5] = 1.;
    head[5 * 7 + 6] = 0.5;
    model(
        &[
            node(
                "Conv",
                &["image", "stem_kernel", "stem_bias"],
                &["features"],
                &[],
            ),
            int_constant("parts", &[1, 1, 2]),
            node(
                "Split",
                &["features", "parts"],
                &["bypass", "pool_seed", "branch"],
                &int_attr("axis", 1),
            ),
            node("Relu", &["branch"], &["branch_relu"], &[]),
            node(
                "MaxPool",
                &["pool_seed"],
                &["pool1"],
                &pool_attrs([3, 3], [1, 1], [1; 4]),
            ),
            node(
                "MaxPool",
                &["pool1"],
                &["pool2"],
                &pool_attrs([3, 3], [1, 1], [1; 4]),
            ),
            node(
                "MaxPool",
                &["pool2"],
                &["pool3"],
                &pool_attrs([3, 3], [1, 1], [1; 4]),
            ),
            node(
                "Concat",
                &[
                    "bypass",
                    "pool_seed",
                    "pool1",
                    "pool2",
                    "pool3",
                    "branch_relu",
                ],
                &["combined"],
                &int_attr("axis", 1),
            ),
            node("Conv", &["combined", "head_kernel"], &["head_nchw"], &[]),
            node(
                "Transpose",
                &["head_nchw"],
                &["head_nhwc"],
                &ints_attr("perm", &[0, 2, 3, 1]),
            ),
            int_constant("head_shape", &[1, 16, 6]),
            node("Reshape", &["head_nhwc", "head_shape"], &["head"], &[]),
            weight(
                "stem_kernel",
                &[4, 3, 1, 1],
                &[1., 0., 0., 0., 1., 0., 0., 0., 1., 0.5, 0.25, 0.],
            ),
            weight("stem_bias", &[4], &[-1., 2., -3., 0.]),
            weight("head_kernel", &[6, 7, 1, 1], &head),
            bytes(11, &info("image", &[1, 3, 4, 4], 1)),
            bytes(12, &info("head", &[1, 16, 6], 1)),
            bytes(12, &info("pool_seed", &[1, 1, 4, 4], 1)),
        ]
        .concat(),
    )
}

#[test]
fn retained_detector_branch_and_spatial_pyramid_fixture_executes_before_and_after_export() -> Test {
    assert_eq!(detector_source(), DETECTOR);
    assert_eq!(
        ContentDigest::sha256(DETECTOR).to_text(),
        "sha256:8df7f45bdab665b2c105b0c5ee77be79a0748c6a4ee4b1082f6c79213c79cad5"
    );
    let imported = import(DETECTOR)?;
    assert_eq!(imported.graph().nodes().len(), 12);
    assert_eq!(
        imported
            .parameters()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["head_kernel", "stem_bias", "stem_kernel"]
    );
    for image in [
        (0..48).map(|n| -(n as f32) - 1.).collect::<Vec<_>>(),
        (0..48)
            .map(|n| {
                if n % 2 == 0 {
                    n as f32 - 20.
                } else {
                    7. - n as f32
                }
            })
            .collect(),
    ] {
        let seed: Vec<_> = image[16..32].iter().map(|&v| v + 2.).collect();
        let (_, pool1) = pool(&seed, [1, 1, 4, 4], [3, 3], [1, 1], [1; 4])?;
        let (_, pool2) = pool(&pool1, [1, 1, 4, 4], [3, 3], [1, 1], [1; 4])?;
        let (_, pool3) = pool(&pool2, [1, 1, 4, 4], [3, 3], [1, 1], [1; 4])?;
        let mut expected = Vec::new();
        for pixel in 0..16 {
            expected.extend([
                image[pixel] - 1.,
                seed[pixel],
                pool1[pixel],
                pool2[pixel],
                pool3[pixel],
                (image[32 + pixel] - 3.).max(0.)
                    + 0.5 * (0.5 * image[pixel] + 0.25 * image[16 + pixel]).max(0.),
            ]);
        }
        let input = Tensor::from_values(Shape::new(vec![1, 3, 4, 4])?, &image, GENERATION)?;
        let outputs = roundtrip(DETECTOR, &[("image", input)])?;
        assert_eq!(bits(&outputs["head"]), bits(&expected));
        assert_eq!(bits(&outputs["pool_seed"]), bits(&seed));
    }
    Ok(())
}

#[test]
fn invalid_split_axis_and_attribute_schemas_refuse() {
    for axis in [i64::MIN, -3, 2, i64::MAX] {
        assert_eq!(
            refusal(&split_model(&[2, 8], axis, None, 2, false)),
            Some(OnnxError::Graph)
        );
    }
    for (attrs, expected) in [
        (text_attr("axis", "1"), OnnxError::Graph),
        (int_attr("num_outputs", 2), OnnxError::Unsupported),
        (ints_attr("split", &[1, 1]), OnnxError::Unsupported),
        (
            [int_attr("axis", 0), int_attr("axis", 0)].concat(),
            OnnxError::Malformed,
        ),
    ] {
        let source = model(
            &[
                node("Split", &["input"], &["a", "b"], &attrs),
                bytes(11, &info("input", &[2], 1)),
                bytes(12, &info("a", &[1], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(expected));
    }
    let scalar = model(
        &[
            node("Split", &["input"], &["a"], &[]),
            bytes(11, &info("input", &[], 1)),
            bytes(12, &info("a", &[], 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&scalar), Some(OnnxError::Unsupported));
}

#[test]
fn invalid_split_partitions_and_output_expansion_refuse() {
    for (parts, expected) in [
        (vec![], OnnxError::Graph),
        (vec![8], OnnxError::Graph),
        (vec![1, 1], OnnxError::Graph),
        (vec![-1, 9], OnnxError::Graph),
        (vec![0, 8], OnnxError::Unsupported),
        (vec![i64::MAX, 1], OnnxError::Limit),
    ] {
        assert_eq!(
            refusal(&split_model(&[8], 0, Some(&parts), 2, false)),
            Some(expected)
        );
    }
    assert_eq!(
        refusal(&split_model(&[8], 0, None, 3, false)),
        Some(OnnxError::Graph)
    );
    assert_eq!(
        refusal(&split_model(&[9], 0, None, 9, false)),
        Some(OnnxError::Limit)
    );
    let empty_outputs = model(
        &[
            node("Split", &["input"], &[], &[]),
            bytes(11, &info("input", &[8], 1)),
            bytes(12, &info("input", &[8], 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&empty_outputs), Some(OnnxError::Graph));
}

#[test]
fn split_dynamic_wrong_type_missing_and_forward_controls_refuse() {
    let split = node("Split", &["input", "parts"], &["a", "b"], &[]);
    let ports = [
        bytes(11, &info("input", &[4], 1)),
        bytes(12, &info("a", &[2], 1)),
    ]
    .concat();
    assert_eq!(
        refusal(&model(&[split.clone(), ports.clone()].concat())),
        Some(OnnxError::Unsupported)
    );
    let forward = model(&[split.clone(), int_constant("parts", &[2, 2]), ports.clone()].concat());
    assert_eq!(refusal(&forward), Some(OnnxError::Unsupported));
    let wrong_type = model(
        &[
            split.clone(),
            weight("parts", &[2], &[2., 2.]),
            ports.clone(),
        ]
        .concat(),
    );
    assert_eq!(refusal(&wrong_type), Some(OnnxError::Graph));
    let dynamic = model(&[split, bytes(11, &info("parts", &[2], 7)), ports].concat());
    assert_eq!(refusal(&dynamic), Some(OnnxError::Unsupported));
    for inputs in [vec![], vec![""], vec!["input", "", ""]] {
        let source = model(
            &[
                node("Split", &inputs, &["a", "b"], &[]),
                bytes(11, &info("input", &[4], 1)),
                bytes(12, &info("a", &[2], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Graph));
    }
}

#[test]
fn split_output_collisions_and_declared_shapes_refuse() {
    for outputs in [vec!["a", "a"], vec!["a", "input"]] {
        let source = model(
            &[
                node("Split", &["input"], &outputs, &[]),
                bytes(11, &info("input", &[4], 1)),
                bytes(12, &info("a", &[2], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Graph));
    }
    let mismatch = model(
        &[
            node("Split", &["input"], &["a", "b"], &[]),
            bytes(11, &info("input", &[4], 1)),
            bytes(12, &info("a", &[3], 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&mismatch), Some(OnnxError::Graph));
    let witness = model(
        &[
            node("Split", &["input"], &["a", "b"], &[]),
            bytes(11, &info("input", &[4], 1)),
            bytes(12, &info("a", &[2], 1)),
            bytes(13, &info("b", &[3], 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&witness), Some(OnnxError::Graph));
}

#[test]
fn split_generated_node_namespace_does_not_capture_source_values() -> Test {
    let source = model(
        &[
            node(
                "Split",
                &["input"],
                &["onnx-node-0000-split-0", "right"],
                &[],
            ),
            node(
                "Split",
                &["right", "parts"],
                &["middle", "last"],
                &int_attr("axis", 1),
            ),
            node("Add", &["middle", "onnx-node-0000-split-1"], &["sum"], &[]),
            bytes(5, &integer_tensor("parts", &[1, 1])),
            bytes(11, &info("input", &[2, 2], 1)),
            bytes(11, &info("onnx-node-0000-split-1", &[1, 1], 1)),
            bytes(12, &info("sum", &[1, 1], 1)),
            bytes(12, &info("last", &[1, 1], 1)),
            bytes(12, &info("onnx-node-0000-split-0", &[1, 2], 1)),
        ]
        .concat(),
    );
    let input = Tensor::from_values(Shape::new(vec![2, 2])?, &[1_f32, 2., 3., 4.], GENERATION)?;
    let other = Tensor::from_values(Shape::new(vec![1, 1])?, &[10_f32], GENERATION)?;
    let actual = roundtrip(
        &source,
        &[("input", input), ("onnx-node-0000-split-1", other)],
    )?;
    assert_eq!(actual["sum"], [13.]);
    assert_eq!(actual["last"], [4.]);
    assert_eq!(actual["onnx-node-0000-split-0"], [1., 2.]);
    Ok(())
}

#[test]
fn non_split_operators_keep_their_multiple_output_refusal() {
    for op in [
        "MaxPool",
        "Relu",
        "Gemm",
        "Dropout",
        "BatchNormalization",
        "Constant",
    ] {
        let source = model(
            &[
                node(op, &["input"], &["a", "b"], &[]),
                bytes(11, &info("input", &[2], 1)),
                bytes(12, &info("a", &[2], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Limit), "{op}");
    }
}

#[test]
fn padded_pooling_retains_all_other_profile_and_shape_refusals() {
    for (extra, expected) in [
        (ints_attr("pads", &[3, 0, 0, 0]), OnnxError::Graph),
        (ints_attr("pads", &[0, 0, 3, 0]), OnnxError::Graph),
        (ints_attr("pads", &[0, 3, 0, 0]), OnnxError::Graph),
        (ints_attr("pads", &[0, 0, 0, 3]), OnnxError::Graph),
        (ints_attr("pads", &[-1, 0, 0, 0]), OnnxError::Graph),
        (ints_attr("pads", &[1, 1]), OnnxError::Graph),
        (ints_attr("strides", &[0, 1]), OnnxError::Graph),
        (ints_attr("dilations", &[2, 1]), OnnxError::Unsupported),
        (int_attr("ceil_mode", 1), OnnxError::Unsupported),
        (int_attr("storage_order", 1), OnnxError::Unsupported),
        (text_attr("auto_pad", "SAME_UPPER"), OnnxError::Unsupported),
        (int_attr("unknown", 0), OnnxError::Unsupported),
    ] {
        let source = model(
            &[
                node(
                    "MaxPool",
                    &["input"],
                    &["output"],
                    &[ints_attr("kernel_shape", &[3, 3]), extra].concat(),
                ),
                bytes(11, &info("input", &[1, 1, 4, 4], 1)),
                bytes(12, &info("output", &[1, 1, 2, 2], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(expected));
    }
    let wrong_shape = model(
        &[
            node(
                "MaxPool",
                &["input"],
                &["output"],
                &pool_attrs([3, 3], [1, 1], [1; 4]),
            ),
            bytes(11, &info("input", &[1, 1, 4, 4], 1)),
            bytes(12, &info("output", &[1, 1, 2, 2], 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&wrong_shape), Some(OnnxError::Graph));
}

#[test]
fn split_lowering_uses_the_same_aggregate_source_node_tensor_parameter_and_work_quotas() -> Test {
    let source = split_model(&[8], 0, Some(&[1, 2, 5]), 3, false);
    let imported = import(&source)?;
    for limits in [
        OnnxLimits {
            source_bytes: source.len() - 1,
            ..OnnxLimits::default()
        },
        OnnxLimits {
            nodes: 2,
            ..OnnxLimits::default()
        },
        OnnxLimits {
            tensors: 4,
            ..OnnxLimits::default()
        },
        OnnxLimits {
            parameter_bytes: 23,
            ..OnnxLimits::default()
        },
        OnnxLimits {
            tensor_bytes: 31,
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
    let exact = OnnxLimits {
        source_bytes: source.len(),
        nodes: 3,
        tensors: 5,
        parameter_bytes: 24,
        tensor_bytes: 32,
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
    assert_eq!(admitted.work_units(), exact.work_units);
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
    Ok(())
}

#[test]
fn detector_source_truncation_cancellation_and_source_identity_are_not_bypassed() -> Test {
    let calls = Cell::new(0_usize);
    let imported = import_onnx(
        DETECTOR,
        ContentDigest::sha256(DETECTOR),
        GENERATION,
        OnnxLimits::default(),
        &|| {
            calls.set(calls.get() + 1);
            false
        },
    )?;
    for at in [1, calls.get() / 2, calls.get()] {
        let observed = Cell::new(0_usize);
        let result = import_onnx(
            DETECTOR,
            ContentDigest::sha256(DETECTOR),
            GENERATION,
            OnnxLimits::default(),
            &|| {
                observed.set(observed.get() + 1);
                observed.get() == at
            },
        );
        assert_eq!(result.err(), Some(OnnxError::Cancelled), "checkpoint {at}");
    }
    for end in 0..DETECTOR.len() {
        let source = &DETECTOR[..end];
        assert!(
            import_onnx(
                source,
                ContentDigest::sha256(source),
                GENERATION,
                OnnxLimits::default(),
                &|| false
            )
            .is_err(),
            "truncation {end}"
        );
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
    assert_eq!(export(&imported)?.source(), DETECTOR);
    Ok(())
}
