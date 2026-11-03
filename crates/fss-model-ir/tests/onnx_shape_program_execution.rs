#![forbid(unsafe_code)]
//! Static shape subgraphs through actual ONNX import, canonical graph and
//! Safetensors reload, and the unchanged production scalar executor. This target
//! does not compile or qualify the asynchronous reference crate or package CLI.

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
const DETECTOR: &[u8] = include_bytes!("fixtures/onnx/detector_shape_program.onnx");

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

fn integers(name: &str, dimensions: &[usize], values: &[i64]) -> Vec<u8> {
    bytes(
        5,
        &tensor(
            name,
            dimensions,
            7,
            &values
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect::<Vec<_>>(),
        ),
    )
}

fn reshape_with_controls(input: &[usize], output: &[usize], controls: Vec<Vec<u8>>) -> Vec<u8> {
    model(
        &[
            controls.concat(),
            node("Reshape", &["input", "target"], &["output"], &[]),
            bytes(11, &info("input", input, 1)),
            bytes(12, &info("output", output, 1)),
        ]
        .concat(),
    )
}

fn check_reshape(source: &[u8], dimensions: &[usize], values: &[f32]) -> Test {
    let input = Tensor::from_values(Shape::new(dimensions.to_vec())?, values, GENERATION)?;
    assert_eq!(
        bits(&roundtrip(source, &[("input", input)])?["output"]),
        bits(values)
    );
    Ok(())
}

fn detector_source() -> Vec<u8> {
    model(
        &[
            node("Conv", &["image", "kernel", "bias"], &["features"], &[]),
            node("Shape", &["features"], &["dimensions"], &[]),
            node("Gather", &["dimensions", "batch_index"], &["batch"], &[]),
            node(
                "Gather",
                &["dimensions", "channel_index"],
                &["channels"],
                &[],
            ),
            node("Gather", &["dimensions", "height_index"], &["height"], &[]),
            node("Gather", &["dimensions", "width_index"], &["width"], &[]),
            node("Mul", &["height", "width"], &["area"], &[]),
            node("Add", &["area", "zero"], &["row_count"], &[]),
            node("Unsqueeze", &["batch", "axes"], &["batch_vector"], &[]),
            node("Unsqueeze", &["channels", "axes"], &["channel_vector"], &[]),
            node("Unsqueeze", &["row_count", "axes"], &["row_vector"], &[]),
            node(
                "Concat",
                &["batch_vector", "channel_vector", "row_vector"],
                &["target"],
                &int_attr("axis", 0),
            ),
            node("Reshape", &["features", "target"], &["flat"], &[]),
            node(
                "Transpose",
                &["flat"],
                &["rows"],
                &ints_attr("perm", &[0, 2, 1]),
            ),
            node("Div", &["channels", "divisor"], &["class_count"], &[]),
            node("Sub", &["channels", "class_count"], &["box_count"], &[]),
            node(
                "Unsqueeze",
                &["class_count", "axes"],
                &["class_vector"],
                &[],
            ),
            node("Unsqueeze", &["box_count", "axes"], &["box_vector"], &[]),
            node(
                "Concat",
                &["box_vector", "class_vector"],
                &["parts"],
                &int_attr("axis", -1),
            ),
            node(
                "Split",
                &["rows", "parts"],
                &["boxes", "logits"],
                &int_attr("axis", -1),
            ),
            node("Sigmoid", &["logits"], &["scores"], &[]),
            node(
                "Concat",
                &["boxes", "scores"],
                &["head"],
                &int_attr("axis", -1),
            ),
            weight(
                "kernel",
                &[6, 3, 1, 1],
                &[
                    1., 0., 0., 0., 1., 0., 0., 0., 1., 0.5, 0.25, 0., 0.25, 0., -0.25, 0., -0.5,
                    0.5,
                ],
            ),
            weight("bias", &[6], &[1., -2., 3., 0., 0.5, -0.25]),
            integers("batch_index", &[], &[0]),
            integers("channel_index", &[], &[1]),
            integers("height_index", &[], &[2]),
            integers("width_index", &[], &[3]),
            integers("axes", &[1], &[0]),
            integers("divisor", &[], &[3]),
            integers("zero", &[], &[0]),
            bytes(11, &info("image", &[1, 3, 2, 4], 1)),
            bytes(12, &info("head", &[1, 8, 6], 1)),
            bytes(13, &info("dimensions", &[4], 7)),
            bytes(13, &info("batch", &[], 7)),
            bytes(13, &info("target", &[3], 7)),
            bytes(13, &info("parts", &[2], 7)),
        ]
        .concat(),
    )
}

#[test]
fn retained_detector_shape_program_executes_before_and_after_artifact_reload() -> Test {
    assert_eq!(detector_source(), DETECTOR);
    assert_eq!(
        ContentDigest::sha256(DETECTOR).to_text(),
        "sha256:96c73cc29267c78d4a78e603a20dcc70cf44163b78222c966c963868d1825f18"
    );
    let imported = import(DETECTOR)?;
    assert_eq!(imported.graph().nodes().len(), 7);
    assert_eq!(imported.runtime_inputs(), ["image"]);
    assert_eq!(
        imported
            .parameters()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["bias", "kernel"]
    );
    for image in [
        vec![0.; 24],
        (0..24).map(|i| (i as f32 - 6.) * 0.25).collect(),
    ] {
        let input = Tensor::from_values(Shape::new(vec![1, 3, 2, 4])?, &image, GENERATION)?;
        let actual = roundtrip(DETECTOR, &[("image", input)])?;
        let sigmoid = |x: f64| (1. / (1. + (-x).exp())) as f32;
        let mut expected = Vec::new();
        for p in 0..8 {
            let (r, g, b) = (image[p], image[8 + p], image[16 + p]);
            expected.extend([
                r + 1.,
                g - 2.,
                b + 3.,
                0.5 * r + 0.25 * g,
                sigmoid(0.25 * f64::from(r) - 0.25 * f64::from(b) + 0.5),
                sigmoid(-0.5 * f64::from(g) + 0.5 * f64::from(b) - 0.25),
            ]);
        }
        for (actual, expected) in actual["head"].iter().zip(expected) {
            assert!((actual - expected).abs() <= 3e-7, "{actual} != {expected}");
        }
    }
    Ok(())
}

#[test]
fn shape_roundtrips_scalar_through_rank_eight_without_changing_bits() -> Test {
    let samples = [
        0.,
        -0.,
        f32::from_bits(1),
        -f32::from_bits(1),
        f32::MIN,
        f32::MAX,
    ];
    for rank in 0..=8 {
        let dimensions = (0..rank)
            .map(|i| if i < 3 { 2 } else { 1 })
            .collect::<Vec<_>>();
        let count: usize = dimensions.iter().product();
        let values = (0..count)
            .map(|i| samples[i % samples.len()])
            .collect::<Vec<_>>();
        let source = reshape_with_controls(
            &dimensions,
            &dimensions,
            vec![node("Shape", &["input"], &["target"], &[])],
        );
        let imported = import(&source)?;
        assert!(imported.parameters().is_empty());
        assert_eq!(imported.graph().nodes().len(), 1);
        assert_eq!(imported.runtime_inputs(), ["input"]);
        check_reshape(&source, &dimensions, &values)?;
    }
    Ok(())
}

#[test]
fn gather_preserves_scalar_vector_order_duplicates_and_negative_indices() -> Test {
    for (indices, output) in [
        (vec![0, 1, 2], vec![2, 3, 4]),
        (vec![-1, -2, -3], vec![4, 3, 2]),
        (vec![0, 0], vec![2, 2]),
    ] {
        let count: usize = output.iter().product();
        let source = reshape_with_controls(
            &[count],
            &output,
            vec![
                int_constant("dimensions", &[2, 3, 4]),
                integers("indices", &[indices.len()], &indices),
                node(
                    "Gather",
                    &["dimensions", "indices"],
                    &["target"],
                    &int_attr("axis", -1),
                ),
            ],
        );
        check_reshape(
            &source,
            &[count],
            &(0..count).map(|i| i as f32).collect::<Vec<_>>(),
        )?;
    }
    let source = reshape_with_controls(
        &[3],
        &[3],
        vec![
            int_constant("dimensions", &[2, 3, 4]),
            integers("index", &[], &[-2]),
            int_constant("axes", &[-1]),
            node("Gather", &["dimensions", "index"], &["scalar"], &[]),
            node("Unsqueeze", &["scalar", "axes"], &["target"], &[]),
            bytes(13, &info("scalar", &[], 7)),
        ],
    );
    check_reshape(&source, &[3], &[1., -0., 3.])?;
    Ok(())
}

#[test]
fn scalar_and_length_one_controls_are_not_interchangeable() {
    let source = reshape_with_controls(
        &[3],
        &[3],
        vec![
            int_constant("dimensions", &[2, 3]),
            integers("index", &[], &[1]),
            node("Gather", &["dimensions", "index"], &["target"], &[]),
        ],
    );
    assert_eq!(refusal(&source), Some(OnnxError::Graph));
    let source = reshape_with_controls(
        &[3],
        &[3],
        vec![
            integers("scalar", &[], &[3]),
            node("Concat", &["scalar"], &["target"], &int_attr("axis", 0)),
        ],
    );
    assert_eq!(refusal(&source), Some(OnnxError::Graph));
}

#[test]
fn integer_arithmetic_uses_exact_i64_values_and_numpy_broadcasting() -> Test {
    for (op, a_shape, a, b_shape, b, dimensions) in [
        (
            "Add",
            vec![],
            vec![1],
            vec![3],
            vec![1, 2, 3],
            vec![2, 3, 4],
        ),
        (
            "Sub",
            vec![3],
            vec![3, 4, 5],
            vec![1],
            vec![1],
            vec![2, 3, 4],
        ),
        (
            "Mul",
            vec![1],
            vec![2],
            vec![3],
            vec![1, 2, 3],
            vec![2, 4, 6],
        ),
        (
            "Div",
            vec![3],
            vec![5, 10, 13],
            vec![],
            vec![3],
            vec![1, 3, 4],
        ),
        ("Add", vec![], vec![2], vec![0], vec![], vec![]),
        ("Mul", vec![0], vec![], vec![1], vec![2], vec![]),
    ] {
        let count = dimensions.iter().product::<usize>();
        let source = reshape_with_controls(
            &[count],
            &dimensions,
            vec![
                integers("a", &a_shape, &a),
                integers("b", &b_shape, &b),
                node(op, &["a", "b"], &["target"], &[]),
            ],
        );
        check_reshape(
            &source,
            &[count],
            &(0..count).map(|i| i as f32).collect::<Vec<_>>(),
        )?;
    }
    let source = reshape_with_controls(
        &[1],
        &[1],
        vec![
            integers("a", &[], &[9_007_199_254_740_993]),
            integers("b", &[], &[9_007_199_254_740_992]),
            int_constant("axes", &[0]),
            node("Sub", &["a", "b"], &["difference"], &[]),
            node("Unsqueeze", &["difference", "axes"], &["target"], &[]),
        ],
    );
    check_reshape(&source, &[1], &[-0.])?;
    Ok(())
}

#[test]
fn signed_integer_division_truncates_toward_zero() -> Test {
    for (a, b) in [(-11, 3), (11, -3)] {
        let source = reshape_with_controls(
            &[3],
            &[3],
            vec![
                integers("a", &[], &[a]),
                integers("b", &[], &[b]),
                int_constant("choices", &[2, 3, 5, 7]),
                int_constant("axes", &[0]),
                node("Div", &["a", "b"], &["index"], &[]),
                node("Gather", &["choices", "index"], &["dimension"], &[]),
                node("Unsqueeze", &["dimension", "axes"], &["target"], &[]),
            ],
        );
        check_reshape(&source, &[3], &[1., 2., 3.])?;
    }
    Ok(())
}

#[test]
fn overflow_division_by_zero_and_incompatible_broadcasts_refuse() {
    for (op, a, b, expected) in [
        ("Add", i64::MAX, 1, OnnxError::Limit),
        ("Sub", i64::MIN, 1, OnnxError::Limit),
        ("Mul", i64::MAX, 2, OnnxError::Limit),
        ("Div", i64::MIN, -1, OnnxError::Limit),
        ("Div", 1, 0, OnnxError::Graph),
    ] {
        let source = reshape_with_controls(
            &[1],
            &[1],
            vec![
                integers("a", &[1], &[a]),
                integers("b", &[1], &[b]),
                node(op, &["a", "b"], &["target"], &[]),
            ],
        );
        assert_eq!(refusal(&source), Some(expected), "{op}");
    }
    let source = reshape_with_controls(
        &[1],
        &[1],
        vec![
            int_constant("a", &[1, 2]),
            int_constant("b", &[1, 2, 3]),
            node("Add", &["a", "b"], &["target"], &[]),
        ],
    );
    assert_eq!(refusal(&source), Some(OnnxError::Graph));
}

#[test]
fn squeeze_unsqueeze_identity_and_empty_vectors_compose() -> Test {
    for (axes, explicit_empty) in [(vec![0], false), (vec![-1], false), (vec![], true)] {
        let mut controls = vec![int_constant("dimension", &[3]), int_constant("axes", &axes)];
        if explicit_empty {
            controls.extend([
                node("Squeeze", &["dimension", "axes"], &["same"], &[]),
                node("Identity", &["same"], &["target"], &[]),
            ]);
        } else {
            controls.extend([
                node("Squeeze", &["dimension", "axes"], &["scalar"], &[]),
                node("Unsqueeze", &["scalar", "axes"], &["target"], &[]),
            ]);
        }
        check_reshape(
            &reshape_with_controls(&[3], &[3], controls),
            &[3],
            &[1., 2., 3.],
        )?;
    }
    for inputs in [vec!["dimension"], vec!["dimension", ""]] {
        let source = reshape_with_controls(
            &[3],
            &[3],
            vec![
                int_constant("dimension", &[3]),
                int_constant("axes", &[0]),
                node("Squeeze", &inputs, &["scalar"], &[]),
                node("Unsqueeze", &["scalar", "axes"], &["target"], &[]),
            ],
        );
        check_reshape(&source, &[3], &[1., 2., 3.])?;
    }
    let source = reshape_with_controls(
        &[],
        &[],
        vec![
            node("Shape", &["input"], &["empty"], &[]),
            int_constant("none", &[]),
            node(
                "Concat",
                &["empty", "none"],
                &["target"],
                &int_attr("axis", 0),
            ),
        ],
    );
    check_reshape(&source, &[], &[-0.])?;
    Ok(())
}

#[test]
fn metadata_only_parameters_are_omitted_but_data_uses_remain_bound() -> Test {
    let weights = [1., 2., 3., 4., 5., 6.];
    for also_data in [false, true] {
        let source = model(
            &[
                weight("weight", &[2, 3], &weights),
                node("Shape", &["weight"], &["target"], &[]),
                if also_data {
                    node("Add", &["input", "weight"], &["sum"], &[])
                } else {
                    Vec::new()
                },
                node(
                    "Reshape",
                    &[if also_data { "sum" } else { "input" }, "target"],
                    &["output"],
                    &[],
                ),
                bytes(11, &info("input", &[2, 3], 1)),
                bytes(12, &info("output", &[2, 3], 1)),
            ]
            .concat(),
        );
        let imported = import(&source)?;
        assert_eq!(imported.parameters().contains_key("weight"), also_data);
        assert_eq!(imported.runtime_inputs(), ["input"]);
        let input = Tensor::from_values(Shape::new(vec![2, 3])?, &[0_f32; 6], GENERATION)?;
        assert_eq!(
            roundtrip(&source, &[("input", input)])?["output"],
            if also_data {
                weights.to_vec()
            } else {
                vec![0.; 6]
            }
        );
    }
    Ok(())
}

#[test]
fn generated_controls_are_charged_even_when_not_exported() -> Test {
    let source = reshape_with_controls(
        &[1; 8],
        &[1; 8],
        vec![node("Shape", &["input"], &["target"], &[])],
    );
    let limits = OnnxLimits {
        nodes: 2,
        tensors: 3,
        parameter_bytes: 64,
        tensor_bytes: 64,
        ..OnnxLimits::default()
    };
    let import_with = |limits| {
        import_onnx(
            &source,
            ContentDigest::sha256(&source),
            GENERATION,
            limits,
            &|| false,
        )
    };
    assert!(import_with(limits)?.parameters().is_empty());
    for limits in [
        OnnxLimits { nodes: 1, ..limits },
        OnnxLimits {
            tensors: 2,
            ..limits
        },
        OnnxLimits {
            parameter_bytes: 63,
            ..limits
        },
        OnnxLimits {
            tensor_bytes: 63,
            ..limits
        },
    ] {
        assert_eq!(import_with(limits).err(), Some(OnnxError::Limit));
    }
    // 96 F32 weight bytes + 56 embedded INT64 bytes + 176 evaluated control bytes.
    let limits = OnnxLimits {
        parameter_bytes: 328,
        ..OnnxLimits::default()
    };
    assert_eq!(
        import_onnx(
            DETECTOR,
            ContentDigest::sha256(DETECTOR),
            GENERATION,
            limits,
            &|| false
        )?
        .parameters()
        .len(),
        2
    );
    assert_eq!(
        import_onnx(
            DETECTOR,
            ContentDigest::sha256(DETECTOR),
            GENERATION,
            OnnxLimits {
                parameter_bytes: 327,
                ..limits
            },
            &|| false
        )
        .err(),
        Some(OnnxError::Limit)
    );
    Ok(())
}

#[test]
fn every_shape_program_cancellation_checkpoint_and_exact_work_limit_refuses_atomically() -> Test {
    let probes = Cell::new(0_usize);
    let imported = import_onnx(
        DETECTOR,
        ContentDigest::sha256(DETECTOR),
        GENERATION,
        OnnxLimits::default(),
        &|| {
            probes.set(probes.get() + 1);
            false
        },
    )?;
    let work = imported.work_units();
    for units in [work, work - 1] {
        let result = import_onnx(
            DETECTOR,
            ContentDigest::sha256(DETECTOR),
            GENERATION,
            OnnxLimits {
                work_units: units,
                ..OnnxLimits::default()
            },
            &|| false,
        );
        if units == work {
            assert_eq!(result?.work_units(), work);
        } else {
            assert_eq!(result.err(), Some(OnnxError::WorkBudget));
        }
    }
    for cancel_at in 1..=probes.get() {
        let calls = Cell::new(0);
        assert_eq!(
            import_onnx(
                DETECTOR,
                ContentDigest::sha256(DETECTOR),
                GENERATION,
                OnnxLimits::default(),
                &|| {
                    calls.set(calls.get() + 1);
                    calls.get() == cancel_at
                }
            )
            .err(),
            Some(OnnxError::Cancelled),
            "checkpoint {cancel_at}"
        );
    }
    Ok(())
}

#[test]
fn wrong_shape_witnesses_shadowing_forward_and_unused_controls_refuse() {
    for controls in [
        vec![node("Shape", &["missing"], &["target"], &[])],
        vec![
            node("Shape", &["input"], &["input"], &[]),
            int_constant("target", &[2]),
        ],
        vec![
            node("Shape", &["input"], &["target"], &[]),
            int_constant("target", &[2]),
        ],
        vec![
            node("Shape", &["input"], &["target"], &[]),
            bytes(13, &info("target", &[], 7)),
        ],
        vec![
            node("Shape", &["input"], &["target"], &[]),
            bytes(13, &info("target", &[1], 1)),
        ],
        vec![
            node("Shape", &["input"], &["unused"], &[]),
            int_constant("target", &[2]),
        ],
        vec![
            node("Add", &["later", "later"], &["target"], &[]),
            int_constant("later", &[1]),
        ],
    ] {
        assert!(refusal(&reshape_with_controls(&[2], &[2], controls)).is_some());
    }
}

#[test]
fn shape_and_control_attributes_are_opset_specific() {
    for attrs in [
        int_attr("start", 0),
        int_attr("end", 1),
        text_attr("axis", "0"),
    ] {
        let source = reshape_with_controls(
            &[2],
            &[2],
            vec![node("Shape", &["input"], &["target"], &attrs)],
        );
        assert_eq!(refusal(&source), Some(OnnxError::Unsupported));
    }
    for (attrs, expected) in [
        (vec![], OnnxError::Malformed),
        (text_attr("axis", "0"), OnnxError::Graph),
        (int_attr("axis", 1), OnnxError::Graph),
        (int_attr("unknown", 1), OnnxError::Unsupported),
    ] {
        let source = reshape_with_controls(
            &[2],
            &[2],
            vec![
                int_constant("a", &[2]),
                node("Concat", &["a"], &["target"], &attrs),
            ],
        );
        assert_eq!(refusal(&source), Some(expected));
    }
}

#[test]
fn invalid_indices_control_ranks_axis_sets_and_arity_refuse() {
    for index in [i64::MIN, -3, 2, i64::MAX] {
        let source = reshape_with_controls(
            &[2],
            &[2],
            vec![
                int_constant("a", &[2, 3]),
                integers("i", &[1], &[index]),
                node("Gather", &["a", "i"], &["target"], &[]),
            ],
        );
        assert_eq!(refusal(&source), Some(OnnxError::Graph));
    }
    for controls in [
        vec![
            integers("a", &[], &[2]),
            integers("i", &[], &[0]),
            node("Gather", &["a", "i"], &["target"], &[]),
        ],
        vec![
            int_constant("a", &[2]),
            integers("i", &[1, 1], &[0]),
            node("Gather", &["a", "i"], &["target"], &[]),
        ],
        vec![
            int_constant("a", &[2]),
            int_constant("axes", &[0, -1]),
            node("Squeeze", &["a", "axes"], &["target"], &[]),
        ],
        vec![
            int_constant("a", &[2, 3]),
            int_constant("axes", &[0]),
            node("Squeeze", &["a", "axes"], &["target"], &[]),
        ],
        vec![
            int_constant("a", &[2]),
            int_constant("axes", &[0]),
            node("Unsqueeze", &["a", "axes"], &["target"], &[]),
        ],
        vec![node("Shape", &[], &["target"], &[])],
        vec![node("Shape", &["input", "input"], &["target"], &[])],
    ] {
        assert!(refusal(&reshape_with_controls(&[2], &[2], controls)).is_some());
    }
}

#[test]
fn control_growth_and_nonconstant_integer_execution_remain_outside_profile() {
    let source = reshape_with_controls(
        &[1],
        &[1],
        vec![
            int_constant("a", &[1; 8]),
            int_constant("b", &[1]),
            node("Concat", &["a", "b"], &["target"], &int_attr("axis", 0)),
        ],
    );
    assert_eq!(refusal(&source), Some(OnnxError::Limit));
    let source = model(
        &[
            node("Identity", &["input"], &["output"], &[]),
            bytes(11, &info("input", &[1], 7)),
            bytes(12, &info("output", &[1], 7)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&source), Some(OnnxError::Unsupported));
    let source = reshape_with_controls(
        &[2],
        &[2],
        vec![
            integers("index", &[1], &[0]),
            node("Gather", &["input", "index"], &["target"], &[]),
        ],
    );
    assert_eq!(refusal(&source), Some(OnnxError::Unsupported));
    let source = model(
        &[
            node("Shape", &["input"], &["output"], &[]),
            bytes(11, &info("input", &[2], 1)),
            bytes(12, &info("output", &[1], 7)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&source), Some(OnnxError::Unsupported));
}

#[test]
fn static_shape_evaluation_preserves_runtime_input_binding_checks() -> Test {
    let source = reshape_with_controls(
        &[2, 3],
        &[2, 3],
        vec![node("Shape", &["input"], &["target"], &[])],
    );
    let imported = import(&source)?;
    for shape in [vec![3, 2], vec![6]] {
        let input = Tensor::from_values(Shape::new(shape)?, &[0_f32; 6], GENERATION)?;
        let error = execute(
            imported.graph(),
            imported.parameters().clone(),
            &[("input", input)],
        )
        .err()
        .ok_or("a shape-only use must retain runtime shape validation")?;
        assert!(matches!(
            error.downcast_ref::<scalar_executor::ExecError>(),
            Some(scalar_executor::ExecError::ShapeMismatch { .. })
        ));
    }
    let error = execute(imported.graph(), imported.parameters().clone(), &[])
        .err()
        .ok_or("a shape-only use must retain the required runtime binding")?;
    assert!(matches!(
        error.downcast_ref::<scalar_executor::ExecError>(),
        Some(scalar_executor::ExecError::MissingInputPort { .. })
    ));
    Ok(())
}

#[test]
fn retained_shape_program_rejects_every_truncated_prefix() {
    for length in 0..DETECTOR.len() {
        assert!(refusal(&DETECTOR[..length]).is_some(), "prefix {length}");
    }
}
