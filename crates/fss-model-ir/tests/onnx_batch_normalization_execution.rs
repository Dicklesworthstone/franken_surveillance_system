#![forbid(unsafe_code)]
//! Inference BatchNormalization through the production importer, canonical graph,
//! Safetensors loader and scalar executor. The retained detector fixture is
//! synthetic and untrained; this target does not qualify the full package CLI.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use fss_core::{ContentDigest, Generation};
use fss_model_ir::{
    ImportedOnnx, ModelIrGraph, OnnxArtifacts, OnnxError, OnnxExportLimits, OnnxLimits, OpCode,
    decode_canonical_model_ir, encode_canonical_model_ir, export_onnx_artifacts, import_onnx,
    onnx_importer_identity,
};
use fss_tensor::{Shape, Tensor};

#[path = "../../fss-reference/src/ingest/model_import/safetensors.rs"]
mod safetensors;
#[path = "../../fss-reference/src/scalar_executor.rs"]
pub mod scalar_executor;
use scalar_executor::{ExecBudget, ExecError, ExecOutcome, ScalarExecCx, ScalarExecutor};

// Data-only host types; all actual decoding remains in the production parser.
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
const GENERATION: Generation = Generation(29);
const DETECTOR: &[u8] = include_bytes!("fixtures/onnx/detector_batch_normalization.onnx");
const PARAMETER_NAMES: [&str; 4] = ["scale", "bias", "mean", "variance"];

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
fn info(name: &str, dimensions: &[usize]) -> Vec<u8> {
    let shape: Vec<_> = dimensions
        .iter()
        .flat_map(|&n| bytes(1, &integer(1, n as i64)))
        .collect();
    let tensor = [integer(1, 1), bytes(2, &shape)].concat();
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
fn float_tensor(name: &str, dimensions: &[usize], values: &[f32]) -> Vec<u8> {
    tensor(
        name,
        dimensions,
        1,
        &values
            .iter()
            .flat_map(|n| n.to_le_bytes())
            .collect::<Vec<_>>(),
    )
}
fn weight(name: &str, dimensions: &[usize], values: &[f32]) -> Vec<u8> {
    bytes(5, &float_tensor(name, dimensions, values))
}
fn int_weight(name: &str, values: &[i64]) -> Vec<u8> {
    bytes(
        5,
        &tensor(
            name,
            &[values.len()],
            7,
            &values
                .iter()
                .flat_map(|n| n.to_le_bytes())
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
fn float_attr(name: &str, value: f32) -> Vec<u8> {
    attribute(
        name,
        1,
        &[varint(2 * 8 + 5), value.to_le_bytes().to_vec()].concat(),
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
            .flat_map(|&value| integer(8, value))
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
fn constant(name: &str, values: &[f32]) -> Vec<u8> {
    node(
        "Constant",
        &[],
        &[name],
        &attribute(
            "value",
            4,
            &bytes(5, &float_tensor("metadata", &[values.len()], values)),
        ),
    )
}
fn model(graph: &[u8]) -> Vec<u8> {
    [integer(1, 8), bytes(8, &integer(2, 13)), bytes(7, graph)].concat()
}
fn parameters(values: &[Vec<f32>; 4]) -> Vec<u8> {
    PARAMETER_NAMES
        .iter()
        .zip(values)
        .flat_map(|(name, values)| weight(name, &[values.len()], values))
        .collect()
}
fn batchnorm(dimensions: &[usize], values: &[Vec<f32>; 4], attributes: &[u8]) -> Vec<u8> {
    model(
        &[
            node(
                "BatchNormalization",
                &["input", "scale", "bias", "mean", "variance"],
                &["output"],
                attributes,
            ),
            parameters(values),
            bytes(11, &info("input", dimensions)),
            bytes(12, &info("output", dimensions)),
        ]
        .concat(),
    )
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
fn refuse(source: &[u8], expected: OnnxError) {
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
fn value_tensor(dimensions: &[usize], values: &[f32]) -> Test<Tensor> {
    Ok(Tensor::from_values(
        Shape::new(dimensions.to_vec())?,
        values,
        GENERATION,
    )?)
}
fn execute(
    graph: &ModelIrGraph,
    mut weights: BTreeMap<String, Tensor>,
    input: &[(&str, Tensor)],
) -> Test<ExecOutcome> {
    weights.extend(
        input
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone())),
    );
    Ok(ScalarExecutor::run(
        graph,
        &weights.into_iter().collect::<Vec<_>>(),
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
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
    weights
        .entries
        .iter()
        .map(|(name, entry)| {
            let values = weights.data[entry.start..entry.end]
                .chunks_exact(entry.width())
                .map(|bytes| safetensors::value(entry.dtype, bytes, WeightFloatPolicy::F32Only))
                .collect::<Result<Vec<_>, _>>()?;
            Ok((name.clone(), value_tensor(&entry.shape, &values)?))
        })
        .collect()
}
fn bits(values: &[f32]) -> Vec<u32> {
    values.iter().map(|value| value.to_bits()).collect()
}
fn output(outcome: &ExecOutcome, name: &str) -> Test<Vec<f32>> {
    Ok(outcome
        .get_output(name)
        .ok_or("missing output")?
        .to_vec::<f32>()?)
}
fn roundtrip(source: &[u8], input: &[(&str, Tensor)]) -> Test<ExecOutcome> {
    let imported = import(source)?;
    let before = execute(imported.graph(), imported.parameters().clone(), input)?;
    let artifacts = export_onnx_artifacts(&imported, OnnxExportLimits::default(), &|| false)?;
    assert_eq!(artifacts.source(), source);
    assert_eq!(artifacts.source_digest(), ContentDigest::sha256(source));
    assert_eq!(artifacts.importer_identity(), onnx_importer_identity());
    let graph = decode_canonical_model_ir(artifacts.graph_bytes(), artifacts.graph_digest())?;
    assert_eq!(encode_canonical_model_ir(&graph)?, artifacts.graph_bytes());
    let after = execute(&graph, reloaded(&artifacts)?, input)?;
    assert_eq!(before.node_output_digests(), after.node_output_digests());
    for name in before.outputs().keys() {
        assert_eq!(bits(&output(&before, name)?), bits(&output(&after, name)?));
    }
    Ok(after)
}

fn detector_source() -> Vec<u8> {
    model(
        &[
            node(
                "Conv",
                &["image", "kernel", "conv_bias"],
                &["features"],
                &[],
            ),
            node(
                "BatchNormalization",
                &["features", "scale", "bias", "mean", "variance"],
                &["normalized"],
                &float_attr("epsilon", 0.25),
            ),
            node("Relu", &["normalized"], &["activated"], &[]),
            node("Reshape", &["activated", "target"], &["flat"], &[]),
            node(
                "Transpose",
                &["flat"],
                &["rows"],
                &ints_attr("perm", &[0, 2, 1]),
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
                    1., 0., 0., 0., 1., 0., 0., 0., 1., 1., -1., 0., 0., 1., -1., 1., 0., 1.,
                ],
            ),
            weight("conv_bias", &[6], &[0.5, -1., 2., 0., -0.5, 1.]),
            weight("scale", &[6], &[2., -3., 0.5, 1., 0., -1.]),
            weight("bias", &[6], &[-1., 2., 0., 0.25, 0.25, 3.]),
            weight("mean", &[6], &[1., -2., 0.5, 0., -1., 2.]),
            weight("variance", &[6], &[0.75, 3.75, 8.75, 15.75, 0., 24.75]),
            int_weight("target", &[1, 6, -1]),
            int_weight("parts", &[4, 2]),
            bytes(11, &info("image", &[1, 3, 2, 4])),
            bytes(12, &info("head", &[1, 8, 6])),
            bytes(12, &info("normalized", &[1, 6, 2, 4])),
        ]
        .concat(),
    )
}

#[test]
fn retained_unfused_detector_runs_and_reloads_against_independent_affine_oracle() -> Test {
    assert_eq!(detector_source(), DETECTOR);
    let imported = import(DETECTOR)?;
    assert_eq!(imported.runtime_inputs(), ["image"]);
    assert_eq!(imported.graph().nodes().len(), 12);
    assert_eq!(imported.parameters().len(), 6);
    assert_eq!(
        imported.graph().nodes()[1..5]
            .iter()
            .map(|node| node.op())
            .collect::<Vec<_>>(),
        [OpCode::Sub, OpCode::Div, OpCode::Mul, OpCode::Add]
    );
    let image: Vec<f32> = (0..24).map(|index| (index as f32 - 9.) * 0.125).collect();
    let result = roundtrip(DETECTOR, &[("image", value_tensor(&[1, 3, 2, 4], &image)?)])?;
    let normalized = output(&result, "normalized")?;
    let head = output(&result, "head")?;
    // These six explicit pointwise affine functions come from the fixture's
    // selected RGB kernels and channel statistics, independently of graph lowering.
    for pixel in 0..8 {
        let r = f64::from(image[pixel]);
        let g = f64::from(image[8 + pixel]);
        let b = f64::from(image[16 + pixel]);
        let expected = [
            2. * (r - 0.5) - 1.,
            -1.5 * (g + 1.) + 2.,
            (b + 1.5) / 6.,
            (r - g) * 0.25 + 0.25,
            0.25,
            3. - (r + b - 1.) / 5.,
        ];
        for channel in 0..6 {
            assert!((f64::from(normalized[channel * 8 + pixel]) - expected[channel]).abs() < 2e-6);
            let activated = expected[channel].max(0.);
            let expected_head = if channel < 4 {
                activated
            } else {
                1. / (1. + (-activated).exp())
            };
            assert!((f64::from(head[pixel * 6 + channel]) - expected_head).abs() < 2e-6);
        }
    }
    Ok(())
}

// Independent scalar oracle: evaluate each primitive in binary64, explicitly
// round its result to binary32, and select channels by flat N,C,spatial coordinates.
fn oracle(
    dimensions: &[usize],
    input: &[f32],
    parameters: &[Vec<f32>; 4],
    epsilon: f32,
) -> Vec<f32> {
    let channels = if dimensions.len() == 1 {
        1
    } else {
        dimensions[1]
    };
    let spatial: usize = dimensions.iter().skip(2).product();
    input
        .iter()
        .enumerate()
        .map(|(index, &value)| {
            let channel = if dimensions.len() == 1 {
                0
            } else {
                (index / spatial) % channels
            };
            let shifted = (f64::from(parameters[3][channel]) + f64::from(epsilon)) as f32;
            let denominator = f64::from(shifted).sqrt() as f32;
            let centered = (f64::from(value) - f64::from(parameters[2][channel])) as f32;
            let normalized = (f64::from(centered) / f64::from(denominator)) as f32;
            let scaled = (f64::from(normalized) * f64::from(parameters[0][channel])) as f32;
            (f64::from(scaled) + f64::from(parameters[1][channel])) as f32
        })
        .collect()
}

#[test]
fn ranks_one_through_eight_and_large_channel_vectors_use_channel_broadcast() -> Test {
    let mut cases = 0;
    for rank in 1..=8 {
        for channels in [1, 3, 11] {
            if rank == 1 && channels != 1 {
                continue;
            }
            let mut dimensions = vec![2; rank];
            if rank > 1 {
                dimensions[1] = channels;
            }
            let count: usize = dimensions.iter().product();
            let input: Vec<_> = (0..count).map(|n| (n % 29) as f32 * 0.13 - 1.25).collect();
            let values = [
                (0..channels).map(|n| n as f32 * 0.25 - 1.5).collect(),
                (0..channels).map(|n| n as f32 * 0.125 - 0.5).collect(),
                (0..channels).map(|n| n as f32 * 0.5 - 1.75).collect(),
                (0..channels).map(|n| n as f32 * 0.3 + 0.125).collect(),
            ];
            for epsilon in [None, Some(0.), Some(0.125)] {
                let attrs = epsilon.map_or_else(Vec::new, |e| {
                    [float_attr("epsilon", e), float_attr("momentum", -2.)].concat()
                });
                let source = batchnorm(&dimensions, &values, &attrs);
                let result = roundtrip(&source, &[("input", value_tensor(&dimensions, &input)?)])?;
                assert_eq!(
                    bits(&output(&result, "output")?),
                    bits(&oracle(
                        &dimensions,
                        &input,
                        &values,
                        epsilon.unwrap_or(1e-5_f32)
                    ))
                );
                assert_eq!(result.nodes_executed(), 4);
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 66);
    Ok(())
}

#[test]
fn constants_shared_data_parameters_and_source_bits_survive_export() -> Test {
    let values = [vec![-0., 2.], vec![-0., 0.], vec![-0., 1.], vec![1., 4.]];
    let constants: Vec<_> = PARAMETER_NAMES
        .iter()
        .zip(&values)
        .flat_map(|(name, values)| constant(name, values))
        .collect();
    let source = model(
        &[
            constants,
            node(
                "BatchNormalization",
                &["input", "scale", "bias", "mean", "variance"],
                &["output"],
                &float_attr("epsilon", 0.),
            ),
            node("Identity", &["scale"], &["scale_copy"], &[]),
            node("Identity", &["bias"], &["bias_copy"], &[]),
            node("Identity", &["mean"], &["mean_copy"], &[]),
            bytes(11, &info("input", &[1, 2, 1, 1])),
            bytes(12, &info("output", &[1, 2, 1, 1])),
            bytes(12, &info("scale_copy", &[2])),
            bytes(12, &info("bias_copy", &[2])),
            bytes(12, &info("mean_copy", &[2])),
            bytes(12, &info("variance", &[2])),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    for (name, expected) in PARAMETER_NAMES.iter().zip(&values) {
        assert_eq!(
            bits(
                &imported
                    .parameters()
                    .get(*name)
                    .ok_or("lost shared parameter")?
                    .to_vec::<f32>()?
            ),
            bits(expected)
        );
    }
    assert_eq!(imported.parameters().len(), 8);
    let input = [-0., 3.];
    let result = roundtrip(&source, &[("input", value_tensor(&[1, 2, 1, 1], &input)?)])?;
    assert_eq!(
        bits(&output(&result, "output")?),
        bits(&oracle(&[1, 2, 1, 1], &input, &values, 0.))
    );
    for (name, expected) in ["scale_copy", "bias_copy", "mean_copy", "variance"]
        .iter()
        .zip(&values)
    {
        assert_eq!(bits(&output(&result, name)?), bits(expected));
    }
    Ok(())
}

#[test]
fn arithmetic_is_not_reassociated_or_fused_away() -> Test {
    // Divide-before-multiply avoids an infinity that multiplying first produces.
    let values = [vec![2.], vec![0.], vec![0.], vec![4.]];
    let source = batchnorm(&[1, 1], &values, &float_attr("epsilon", 0.));
    assert_eq!(
        output(
            &roundtrip(&source, &[("input", value_tensor(&[1, 1], &[f32::MAX])?)])?,
            "output"
        )?,
        [f32::MAX]
    );
    // Conversely, centering must overflow before the very small scale is applied.
    // An affine/Conv fusion could manufacture a finite result and erase this fact.
    let values = [vec![f32::MIN_POSITIVE], vec![0.], vec![-f32::MAX], vec![4.]];
    let source = batchnorm(&[1, 1], &values, &float_attr("epsilon", 0.));
    assert_eq!(
        output(
            &roundtrip(&source, &[("input", value_tensor(&[1, 1], &[f32::MAX])?)])?,
            "output"
        )?,
        [f32::INFINITY]
    );
    for epsilon in [0., f32::from_bits(1)] {
        let values = [vec![-0.], vec![-0.], vec![0.], vec![f32::from_bits(1)]];
        let input = [0., -0., f32::from_bits(1), -f32::from_bits(1)];
        let source = batchnorm(&[4], &values, &float_attr("epsilon", epsilon));
        assert_eq!(
            bits(&output(
                &roundtrip(&source, &[("input", value_tensor(&[4], &input)?)])?,
                "output"
            )?),
            bits(&oracle(&[4], &input, &values, epsilon))
        );
    }
    Ok(())
}

#[test]
fn invalid_statistics_attributes_training_and_dynamic_parameters_refuse() {
    let good = [vec![1., 2.], vec![0., -1.], vec![0.5, 0.], vec![1., 4.]];
    for field in 0..4 {
        for nonfinite in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let mut bad = good.clone();
            bad[field][0] = nonfinite;
            refuse(&batchnorm(&[1, 2, 1, 1], &bad, &[]), OnnxError::NonFinite);
        }
        let mut wrong = good.clone();
        wrong[field].push(1.);
        refuse(&batchnorm(&[1, 2, 1, 1], &wrong, &[]), OnnxError::Graph);
    }
    for name in ["epsilon", "momentum"] {
        refuse(
            &batchnorm(&[1, 2], &good, &int_attr(name, 0)),
            OnnxError::Graph,
        );
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            refuse(
                &batchnorm(&[1, 2], &good, &float_attr(name, value)),
                OnnxError::NonFinite,
            );
        }
    }
    for (name, value) in [
        ("training_mode", 0),
        ("training_mode", 1),
        ("spatial", 1),
        ("is_test", 1),
    ] {
        refuse(
            &batchnorm(&[1, 2], &good, &int_attr(name, value)),
            OnnxError::Unsupported,
        );
    }
    refuse(
        &batchnorm(&[1, 2], &good, &float_attr("epsilon", -0.25)),
        OnnxError::Graph,
    );
    let mut bad = good.clone();
    bad[3][0] = -1.;
    refuse(
        &batchnorm(&[1, 2], &bad, &float_attr("epsilon", 2.)),
        OnnxError::Graph,
    );
    bad[3][0] = 0.;
    refuse(
        &batchnorm(&[1, 2], &bad, &float_attr("epsilon", 0.)),
        OnnxError::Graph,
    );
    bad[3][0] = f32::MAX;
    refuse(
        &batchnorm(&[1, 2], &bad, &float_attr("epsilon", f32::MAX)),
        OnnxError::NonFinite,
    );
    refuse(&batchnorm(&[], &good, &[]), OnnxError::Unsupported);
    for outputs in [
        vec!["output", "running_mean"],
        vec![
            "output",
            "running_mean",
            "running_var",
            "saved_mean",
            "saved_var",
        ],
    ] {
        refuse(
            &model(
                &[
                    node(
                        "BatchNormalization",
                        &["input", "scale", "bias", "mean", "variance"],
                        &outputs,
                        &[],
                    ),
                    parameters(&good),
                    bytes(11, &info("input", &[1, 2])),
                    bytes(12, &info("output", &[1, 2])),
                ]
                .concat(),
            ),
            OnnxError::Limit,
        );
    }
    // Each of the four channel inputs must be embedded, including scale and bias.
    for (dynamic, dynamic_name) in PARAMETER_NAMES.iter().enumerate() {
        let constants: Vec<_> = PARAMETER_NAMES
            .iter()
            .zip(&good)
            .enumerate()
            .filter(|(index, _)| *index != dynamic)
            .flat_map(|(_, (name, value))| weight(name, &[2], value))
            .collect();
        refuse(
            &model(
                &[
                    node(
                        "BatchNormalization",
                        &["input", "scale", "bias", "mean", "variance"],
                        &["output"],
                        &[],
                    ),
                    constants,
                    bytes(11, &info("input", &[1, 2])),
                    bytes(11, &info(dynamic_name, &[2])),
                    bytes(12, &info("output", &[1, 2])),
                ]
                .concat(),
            ),
            OnnxError::Unsupported,
        );
    }
}

#[test]
fn helpers_cannot_alias_source_names_or_repair_missing_data() -> Test {
    let values = [vec![2.], vec![1.], vec![0.], vec![1.]];
    let input_name = "onnx-node-0000-batchnorm-denominator";
    let output_name = "onnx-node-0000-batchnorm-center";
    let source = model(
        &[
            node(
                "BatchNormalization",
                &[input_name, "scale", "bias", "mean", "variance"],
                &[output_name],
                &float_attr("epsilon", 0.),
            ),
            parameters(&values),
            bytes(11, &info(input_name, &[1, 1, 1, 1])),
            bytes(12, &info(output_name, &[1, 1, 1, 1])),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    let names: Vec<_> = imported
        .graph()
        .inputs()
        .iter()
        .map(|port| port.name())
        .chain(
            imported
                .graph()
                .nodes()
                .iter()
                .flat_map(|node| node.outputs().iter().map(String::as_str)),
        )
        .collect();
    assert_eq!(names.len(), names.iter().collect::<BTreeSet<_>>().len());
    assert_eq!(
        output(
            &roundtrip(
                &source,
                &[(input_name, value_tensor(&[1, 1, 1, 1], &[3.])?)]
            )?,
            output_name
        )?,
        [7.]
    );
    let missing = model(
        &[
            node(
                "BatchNormalization",
                &["input", "scale", "bias", "mean", "variance"],
                &["normalized"],
                &[],
            ),
            node(
                "Add",
                &["normalized", "onnx-node-0000-batchnorm-center"],
                &["output"],
                &[],
            ),
            parameters(&values),
            bytes(11, &info("input", &[1, 1, 1, 1])),
            bytes(12, &info("output", &[1, 1, 1, 1])),
        ]
        .concat(),
    );
    refuse(&missing, OnnxError::Graph);
    Ok(())
}

#[test]
fn generated_views_and_denominator_obey_cumulative_limits_and_every_cancel_point() -> Test {
    let source = batchnorm(
        &[1, 2, 1, 1],
        &[vec![1., 2.], vec![0., 0.], vec![0., 0.], vec![1., 4.]],
        &[],
    );
    let digest = ContentDigest::sha256(&source);
    let exact = OnnxLimits {
        nodes: 4,
        tensors: 13,
        parameter_bytes: 64,
        tensor_bytes: 8,
        ..OnnxLimits::default()
    };
    let imported = import_onnx(&source, digest, GENERATION, exact, &|| false)?;
    assert_eq!(imported.parameters().len(), 4);
    for limits in [
        OnnxLimits { nodes: 3, ..exact },
        OnnxLimits {
            tensors: 12,
            ..exact
        },
        OnnxLimits {
            parameter_bytes: 63,
            ..exact
        },
        OnnxLimits {
            tensor_bytes: 7,
            ..exact
        },
    ] {
        assert_eq!(
            import_onnx(&source, digest, GENERATION, limits, &|| false).err(),
            Some(OnnxError::Limit)
        );
    }
    let work = imported.work_units();
    assert!(
        import_onnx(
            &source,
            digest,
            GENERATION,
            OnnxLimits {
                work_units: work,
                ..exact
            },
            &|| false
        )
        .is_ok()
    );
    assert_eq!(
        import_onnx(
            &source,
            digest,
            GENERATION,
            OnnxLimits {
                work_units: work - 1,
                ..exact
            },
            &|| false
        )
        .err(),
        Some(OnnxError::WorkBudget)
    );
    let calls = Cell::new(0);
    import_onnx(&source, digest, GENERATION, exact, &|| {
        calls.set(calls.get() + 1);
        false
    })?;
    let total = calls.get();
    for stop in 1..=total {
        calls.set(0);
        assert_eq!(
            import_onnx(&source, digest, GENERATION, exact, &|| {
                calls.set(calls.get() + 1);
                calls.get() == stop
            })
            .err(),
            Some(OnnxError::Cancelled)
        );
    }
    Ok(())
}

#[test]
fn lowered_execution_retains_generation_budget_and_cancellation_checks() -> Test {
    let source = batchnorm(
        &[1, 2],
        &[vec![1., 2.], vec![0., 0.], vec![0., 0.], vec![1., 4.]],
        &[],
    );
    let imported = import(&source)?;
    let supplied = [("input", value_tensor(&[1, 2], &[1., 2.])?)];
    let result = execute(imported.graph(), imported.parameters().clone(), &supplied)?;
    let bindings: Vec<_> = imported
        .parameters()
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .chain(
            supplied
                .iter()
                .map(|(name, value)| ((*name).to_owned(), value.clone())),
        )
        .collect();
    assert!(
        ScalarExecutor::run(
            imported.graph(),
            &bindings,
            ExecBudget::new(result.executed_macs(), result.allocated_bytes()),
            &ScalarExecCx::new()
        )
        .is_ok()
    );
    assert!(matches!(
        ScalarExecutor::run(
            imported.graph(),
            &bindings,
            ExecBudget::new(result.executed_macs() - 1, result.allocated_bytes()),
            &ScalarExecCx::new()
        ),
        Err(ExecError::BudgetExceeded { .. })
    ));
    let cancelled = ScalarExecCx::new();
    cancelled.request_cancellation();
    assert!(matches!(
        ScalarExecutor::run(
            imported.graph(),
            &bindings,
            ExecBudget::unlimited(),
            &cancelled
        ),
        Err(ExecError::CancellationRequested { .. })
    ));
    let wrong = Tensor::from_values(Shape::new(vec![1, 2])?, &[1_f32, 2.], Generation(30))?;
    let bad: Vec<_> = imported
        .parameters()
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .chain([(String::from("input"), wrong)])
        .collect();
    assert!(matches!(
        ScalarExecutor::run(
            imported.graph(),
            &bad,
            ExecBudget::unlimited(),
            &ScalarExecCx::new()
        ),
        Err(ExecError::GenerationMismatch { .. })
    ));
    Ok(())
}
