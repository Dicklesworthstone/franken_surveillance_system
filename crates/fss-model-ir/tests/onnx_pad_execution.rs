#![forbid(unsafe_code)]
//! Static ONNX Pad through real artifacts and both unchanged production executors.
//! Expected values come from explicit output-to-input coordinates and literal
//! examples, independently of the lowering strategy.

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
const GENERATION: Generation = Generation(37);

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
    model_version(graph, 13)
}
fn model_version(graph: &[u8], version: i64) -> Vec<u8> {
    [
        integer(1, 8),
        bytes(8, &integer(2, version)),
        bytes(7, graph),
    ]
    .concat()
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
            assert_eq!(
                bits(&actual),
                bits(&expected),
                "optimized output {}",
                port.name()
            );
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

fn int_weight(name: &str, dimensions: &[usize], values: &[i64]) -> Vec<u8> {
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
fn float_attr(name: &str, value: f32) -> Vec<u8> {
    attribute(
        name,
        1,
        &[varint(2 * 8 + 5), value.to_le_bytes().to_vec()].concat(),
    )
}
fn data(dimensions: &[usize], values: &[f32]) -> Test<Tensor> {
    Ok(Tensor::from_values(
        Shape::new(dimensions.to_vec())?,
        values,
        GENERATION,
    )?)
}
fn shape_after(dims: &[usize], pads: &[i64]) -> Vec<usize> {
    dims.iter()
        .enumerate()
        .map(|(axis, &dim)| (dim as i64 + pads[axis] + pads[axis + dims.len()]) as usize)
        .collect()
}
fn pad_model(
    dims: &[usize],
    output: &[usize],
    pads: &[i64],
    fill: Option<f32>,
    attrs: &[u8],
) -> Vec<u8> {
    pad_model_version(dims, output, pads, fill, attrs, 13)
}
fn pad_model_version(
    dims: &[usize],
    output: &[usize],
    pads: &[i64],
    fill: Option<f32>,
    attrs: &[u8],
    version: i64,
) -> Vec<u8> {
    let (inputs, value) = if let Some(value) = fill {
        (vec!["input", "pads", "fill"], weight("fill", &[], &[value]))
    } else {
        (vec!["input", "pads"], Vec::new())
    };
    model_version(
        &[
            node("Pad", &inputs, &["output"], attrs),
            int_weight("pads", &[pads.len()], pads),
            value,
            bytes(11, &info("input", dims, 1)),
            bytes(12, &info("output", output, 1)),
        ]
        .concat(),
        version,
    )
}

// Independent output-to-original-input coordinates. This does not inspect any
// generated Slice/Concat, border shape, cropped intermediate or native shape code.
fn coordinate_oracle(input: &[f32], dims: &[usize], pads: &[i64], fill: f32) -> Vec<f32> {
    let output = shape_after(dims, pads);
    (0..output.iter().product())
        .map(|mut index| {
            let mut source = 0;
            let mut stride = 1;
            let mut padded = false;
            for axis in (0..dims.len()).rev() {
                let coordinate = index % output[axis];
                index /= output[axis];
                let original = coordinate as i128 - i128::from(pads[axis]);
                if original < 0 || original >= dims[axis] as i128 {
                    padded = true;
                } else {
                    source += original as usize * stride;
                }
                stride *= dims[axis];
            }
            if padded { fill } else { input[source] }
        })
        .collect()
}

#[test]
fn mixed_signed_padding_matches_literal_examples() -> Test {
    for (dims, values, pads, output, expected) in [
        (
            vec![4],
            vec![1., 2., 3., 4.],
            vec![-1, 2],
            vec![5],
            vec![2., 3., 4., 9., 9.],
        ),
        (
            vec![4],
            vec![1., 2., 3., 4.],
            vec![2, -1],
            vec![5],
            vec![9., 9., 1., 2., 3.],
        ),
        (
            vec![2, 3],
            vec![1., 2., 3., 4., 5., 6.],
            vec![-1, 1, 1, -1],
            vec![2, 3],
            vec![9., 4., 5., 9., 9., 9.],
        ),
        (
            vec![3, 3],
            vec![1., 2., 3., 4., 5., 6., 7., 8., 9.],
            vec![1, -1, -1, 2],
            vec![3, 4],
            vec![9., 9., 9., 9., 2., 3., 9., 9., 5., 6., 9., 9.],
        ),
    ] {
        let source = pad_model(&dims, &output, &pads, Some(9.0), &[]);
        let result = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
        assert_eq!(bits(&result["output"]), bits(&expected));
    }
    Ok(())
}

#[test]
fn every_supported_rank_preserves_input_and_fill_bits_after_artifact_reload() -> Test {
    for rank in 1..=4 {
        let dims: Vec<_> = (0..rank).map(|axis| 3 + axis % 2).collect();
        let special = [
            -0.0_f32,
            0.0,
            f32::from_bits(1),
            -f32::from_bits(1),
            f32::MIN,
            f32::MAX,
        ];
        let values: Vec<_> = (0..dims.iter().product())
            .map(|index| special[index % special.len()])
            .collect();
        for mode in 0..5 {
            let mut pads = vec![0; 2 * rank];
            for axis in 0..rank {
                (pads[axis], pads[axis + rank]) = match mode {
                    0 => (0, 0),
                    1 => (1, 2),
                    2 => (-1, -1),
                    3 if axis % 2 == 0 => (-1, 2),
                    3 => (2, -1),
                    _ if axis % 2 == 0 => (1, 0),
                    _ => (0, 1),
                };
            }
            for fill in [
                None,
                Some(0.0_f32),
                Some(-0.0),
                Some(f32::from_bits(1)),
                Some(-3.5),
            ] {
                let output = shape_after(&dims, &pads);
                let source = pad_model(&dims, &output, &pads, fill, &text_attr("mode", "constant"));
                let result = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
                assert_eq!(
                    bits(&result["output"]),
                    bits(&coordinate_oracle(
                        &values,
                        &dims,
                        &pads,
                        fill.unwrap_or(0.0)
                    )),
                    "rank={rank}, mode={mode}, fill={fill:?}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn identity_and_crop_only_need_no_generated_parameters() -> Test {
    for pads in [[0, 0, 0, 0], [-1, 0, 0, -1]] {
        let dims = [3, 4];
        let values: Vec<f32> = (0..12).map(|index| index as f32 - 3.).collect();
        let output = shape_after(&dims, &pads);
        let source = pad_model(&dims, &output, &pads, Some(-0.0), &[]);
        let imported = import(&source)?;
        assert!(imported.parameters().is_empty());
        assert_eq!(imported.graph().node_count(), 1);
        assert_eq!(
            imported.graph().nodes()[0].op(),
            if pads[0] == 0 {
                fss_model_ir::OpCode::Reshape
            } else {
                fss_model_ir::OpCode::Slice
            }
        );
        let result = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
        assert_eq!(
            bits(&result["output"]),
            bits(&coordinate_oracle(&values, &dims, &pads, -0.0))
        );
    }
    // An explicitly empty optional input name means the same default zero fill
    // as omitting that input. An empty tensor is not a scalar fill.
    let source = model(
        &[
            node("Pad", &["input", "pads", ""], &["output"], &[]),
            int_weight("pads", &[2], &[1, 1]),
            bytes(11, &info("input", &[1], 1)),
            bytes(12, &info("output", &[3], 1)),
        ]
        .concat(),
    );
    let result = roundtrip(&source, &[("input", data(&[1], &[-0.0])?)])?;
    assert_eq!(bits(&result["output"]), bits(&[0.0, -0.0, 0.0]));
    Ok(())
}

#[test]
fn explicit_pad_convolution_block_executes_after_native_export() -> Test {
    let source = model(
        &[
            node("Pad", &["input", "pads"], &["padded"], &[]),
            node("Conv", &["padded", "kernel"], &["output"], &[]),
            int_weight("pads", &[8], &[0, 0, 1, 2, 0, 0, 1, 0]),
            weight(
                "kernel",
                &[1, 1, 3, 3],
                &[1., 0., 0., 0., 1., 0., 0., 0., 1.],
            ),
            bytes(11, &info("input", &[1, 1, 2, 3], 1)),
            bytes(13, &info("padded", &[1, 1, 4, 5], 1)),
            bytes(12, &info("output", &[1, 1, 2, 3], 1)),
        ]
        .concat(),
    );
    let result = roundtrip(
        &source,
        &[("input", data(&[1, 1, 2, 3], &[1., 2., 3., 4., 5., 6.])?)],
    )?;
    assert_eq!(result["output"], [4., 6., 8., 0., 4., 6.]);
    Ok(())
}

#[test]
fn static_shape_controls_and_shared_scalar_fill_keep_their_distinct_uses() -> Test {
    let source = model(
        &[
            node(
                "Constant",
                &[],
                &["begins"],
                &ints_attr("value_ints", &[-1, 1]),
            ),
            node(
                "Constant",
                &[],
                &["ends"],
                &ints_attr("value_ints", &[1, -1]),
            ),
            node("Constant", &[], &["fill"], &float_attr("value_float", -0.0)),
            node(
                "Concat",
                &["begins", "ends"],
                &["pads"],
                &int_attr("axis", 0),
            ),
            node("Pad", &["input", "pads", "fill"], &["output"], &[]),
            node("Identity", &["fill"], &["echo"], &[]),
            bytes(11, &info("input", &[2, 3], 1)),
            bytes(12, &info("output", &[2, 3], 1)),
            bytes(12, &info("echo", &[], 1)),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    assert!(imported.parameters().contains_key("fill"));
    assert!(!imported.parameters().contains_key("pads"));
    assert!(!imported.parameters().contains_key("begins"));
    assert!(!imported.parameters().contains_key("ends"));
    let result = roundtrip(
        &source,
        &[("input", data(&[2, 3], &[1., 2., 3., 4., 5., 6.])?)],
    )?;
    assert_eq!(
        bits(&result["output"]),
        bits(&[-0.0, 4., 5., -0.0, -0.0, -0.0])
    );
    assert_eq!(bits(&result["echo"]), bits(&[-0.0]));
    Ok(())
}

#[test]
fn padding_helpers_cannot_alias_later_source_values() -> Test {
    let collision_names = [
        "onnx-node-0000-pad-crop",
        "onnx-node-0000-pad-axis-0-after",
        "onnx-node-0000-pad-axis-0-value",
        "onnx-node-0000-pad-axis-1-before",
    ];
    let mut graph = node("Pad", &["input", "pads", "fill"], &["padded"], &[]);
    let mut previous = "padded";
    for name in &collision_names {
        graph.extend(node("Identity", &[previous], &[name], &[]));
        previous = name;
    }
    graph.extend(int_weight("pads", &[4], &[-1, 1, 1, 0]));
    graph.extend(weight("fill", &[], &[-0.0]));
    graph.extend(bytes(11, &info("input", &[3, 2], 1)));
    graph.extend(bytes(12, &info(previous, &[3, 3], 1)));
    let source = model(&graph);
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
    let unique: std::collections::BTreeSet<_> = names.iter().collect();
    assert_eq!(names.len(), unique.len());
    for name in collision_names {
        assert!(
            names.contains(&format!("{name}-1").as_str()),
            "missing reserved-name suffix for {name}"
        );
    }
    let result = roundtrip(
        &source,
        &[("input", data(&[3, 2], &[1., 2., 3., 4., 5., 6.])?)],
    )?;
    assert_eq!(
        bits(&result[previous]),
        bits(&[-0.0, 3., 4., -0.0, 5., 6., -0.0, -0.0, -0.0])
    );
    Ok(())
}

#[test]
fn malformed_and_dynamic_controls_and_unsupported_profiles_refuse() {
    for attrs in [
        text_attr("mode", "wrap"),
        text_attr("mode", "unknown"),
        int_attr("axes", 0),
        ints_attr("pads", &[1, 1]),
    ] {
        assert_eq!(
            refusal(&pad_model(&[2], &[4], &[1, 1], None, &attrs)),
            Some(OnnxError::Unsupported)
        );
    }
    assert_eq!(
        refusal(&pad_model(&[2], &[4], &[1, 1], None, &int_attr("mode", 0))),
        Some(OnnxError::Graph)
    );
    for pads in [vec![], vec![1], vec![1, 1, 0]] {
        assert_eq!(
            refusal(&pad_model(&[2], &[4], &pads, None, &[])),
            Some(OnnxError::Graph)
        );
    }
    for fill in [
        weight("fill", &[1], &[1.]),
        weight("fill", &[0], &[]),
        int_weight("fill", &[], &[1]),
    ] {
        let source = model(
            &[
                node("Pad", &["input", "pads", "fill"], &["output"], &[]),
                int_weight("pads", &[2], &[1, 1]),
                fill,
                bytes(11, &info("input", &[2], 1)),
                bytes(12, &info("output", &[4], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Graph));
    }
    for pads in [
        weight("pads", &[2], &[1., 1.]),
        int_weight("pads", &[], &[1]),
    ] {
        let source = model(
            &[
                node("Pad", &["input", "pads"], &["output"], &[]),
                pads,
                bytes(11, &info("input", &[2], 1)),
                bytes(12, &info("output", &[4], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Graph));
    }
    for inputs in [
        vec!["input"],
        vec!["", "pads"],
        vec!["input", ""],
        vec!["input", "pads", "", ""],
    ] {
        let source = model(
            &[
                node("Pad", &inputs, &["output"], &[]),
                int_weight("pads", &[2], &[1, 1]),
                bytes(11, &info("input", &[2], 1)),
                bytes(12, &info("output", &[4], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Graph));
    }
    for dynamic_fill in [false, true] {
        let source = model(
            &[
                node(
                    "Pad",
                    &if dynamic_fill {
                        vec!["input", "pads", "fill"]
                    } else {
                        vec!["input", "pads"]
                    },
                    &["output"],
                    &[],
                ),
                if dynamic_fill {
                    int_weight("pads", &[2], &[1, 1])
                } else {
                    Vec::new()
                },
                bytes(
                    11,
                    &info(
                        if dynamic_fill { "fill" } else { "pads" },
                        if dynamic_fill { &[] } else { &[2] },
                        1,
                    ),
                ),
                bytes(11, &info("input", &[2], 1)),
                bytes(12, &info("output", &[4], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Unsupported));
    }
    assert_eq!(
        refusal(&pad_model(&[], &[], &[], None, &[])),
        Some(OnnxError::Unsupported)
    );
    assert_eq!(
        refusal(&pad_model(
            &[1, 1, 1, 1, 1],
            &[1, 1, 1, 1, 1],
            &[0; 8],
            None,
            &[]
        )),
        Some(OnnxError::Unsupported)
    );
    for fill in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        assert_eq!(
            refusal(&pad_model(&[2], &[4], &[1, 1], Some(fill), &[])),
            Some(OnnxError::NonFinite)
        );
    }
    // Declared shape witnesses cannot replace the shape implied by the pads.
    assert_eq!(
        refusal(&pad_model(&[2], &[5], &[1, 1], None, &[])),
        Some(OnnxError::Graph)
    );
}

#[test]
fn empty_crops_and_overflowing_pad_counts_refuse_before_allocation() {
    for pads in [[-4, 1], [-2, -2], [-5, 5], [5, -5]] {
        assert_eq!(
            refusal(&pad_model(&[4], &[1], &pads, None, &[])),
            Some(OnnxError::Unsupported)
        );
    }
    for pads in [[i64::MIN, 0], [i64::MAX, 0], [i64::MAX, i64::MAX]] {
        assert_eq!(
            refusal(&pad_model(&[4], &[1], &pads, None, &[])),
            Some(OnnxError::Limit)
        );
    }
}

#[test]
fn crop_first_order_and_exact_resource_boundaries_are_enforced() -> Test {
    let source = pad_model(&[3, 4], &[3, 9], &[-1, 2, 1, 3], Some(-0.0), &[]);
    let imported = import(&source)?;
    assert_eq!(imported.graph().node_count(), 3);
    assert_eq!(imported.parameters().len(), 3);
    assert_eq!(
        imported
            .parameters()
            .values()
            .map(|value| value.shape().size_bytes(value.dtype()))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .sum::<usize>(),
        76
    );
    let limits = OnnxLimits {
        nodes: 3,
        tensors: 9,
        parameter_bytes: 112, // Original pads/fill:36; generated borders:76.
        tensor_bytes: 108,
        work_units: imported.work_units(),
        ..OnnxLimits::default()
    };
    assert!(
        import_onnx(
            &source,
            ContentDigest::sha256(&source),
            GENERATION,
            limits,
            &|| false
        )
        .is_ok()
    );
    for (limits, expected) in [
        (OnnxLimits { nodes: 2, ..limits }, OnnxError::Limit),
        (
            OnnxLimits {
                tensors: 8,
                ..limits
            },
            OnnxError::Limit,
        ),
        (
            OnnxLimits {
                parameter_bytes: 111,
                ..limits
            },
            OnnxError::Limit,
        ),
        (
            OnnxLimits {
                tensor_bytes: 107,
                ..limits
            },
            OnnxError::Limit,
        ),
        (
            OnnxLimits {
                work_units: imported.work_units() - 1,
                ..limits
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
            Some(expected)
        );
    }
    let source = pad_model(&[10, 10], &[1, 100], &[-9, 0, 0, 90], Some(-0.0), &[]);
    let imported = import_onnx(
        &source,
        ContentDigest::sha256(&source),
        GENERATION,
        OnnxLimits {
            tensor_bytes: 400,
            ..OnnxLimits::default()
        },
        &|| false,
    )?;
    assert_eq!(imported.graph().node_count(), 2);
    assert_eq!(
        imported.graph().nodes()[0].op(),
        fss_model_ir::OpCode::Slice
    );
    let values: Vec<f32> = (0..100).map(|index| index as f32).collect();
    let result = roundtrip(&source, &[("input", data(&[10, 10], &values)?)])?;
    assert_eq!(
        bits(&result["output"]),
        bits(&coordinate_oracle(
            &values,
            &[10, 10],
            &[-9, 0, 0, 90],
            -0.0
        ))
    );
    Ok(())
}

#[test]
fn cancellation_at_every_import_checkpoint_returns_no_partial_result() -> Test {
    let source = pad_model(&[3, 4], &[3, 9], &[-1, 2, 1, 3], Some(-0.0), &[]);
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
            "checkpoint {stop}/{total}"
        );
    }
    assert_eq!(
        encode_canonical_model_ir(import(&source)?.graph())?,
        encode_canonical_model_ir(baseline.graph())?
    );
    Ok(())
}

// Map each output coordinate directly into the surviving original interval.
// Reflection is a geometric mirror at either endpoint, independent of native
// Slice/Concat schedules, bit decomposition, or the order of padded axes.
fn copied_coordinate_oracle(values: &[f32], dims: &[usize], pads: &[i64], mode: &str) -> Vec<f32> {
    let shape = shape_after(dims, pads);
    (0..shape.iter().product())
        .map(|mut index| {
            let mut source = 0;
            let mut stride = 1;
            for axis in (0..dims.len()).rev() {
                let coordinate = index % shape[axis];
                index /= shape[axis];
                let low = i128::from((-pads[axis]).max(0));
                let high = dims[axis] as i128 - 1 - i128::from((-pads[axis + dims.len()]).max(0));
                let original = coordinate as i128 - i128::from(pads[axis]);
                let selected = if mode == "edge" {
                    original.clamp(low, high)
                } else if original < low {
                    2 * low - original
                } else if original > high {
                    2 * high - original
                } else {
                    original
                };
                assert!((low..=high).contains(&selected));
                source += selected as usize * stride;
                stride *= dims[axis];
            }
            values[source]
        })
        .collect()
}

#[test]
fn copied_padding_matches_literal_examples_in_every_admitted_opset() -> Test {
    for version in [13, 17, 18] {
        for (mode, pads, expected) in [
            ("edge", [2, 1], vec![1., 1., 1., 2., 3., 4., 4.]),
            ("reflect", [2, 1], vec![3., 2., 1., 2., 3., 4., 3.]),
            ("edge", [-1, 2], vec![2., 3., 4., 4., 4.]),
            ("reflect", [-1, 2], vec![2., 3., 4., 3., 2.]),
            ("edge", [2, -1], vec![1., 1., 1., 2., 3.]),
            ("reflect", [2, -1], vec![3., 2., 1., 2., 3.]),
        ] {
            let source = pad_model_version(
                &[4],
                &[expected.len()],
                &pads,
                Some(99.0), // Present but semantically unused outside constant mode.
                &text_attr("mode", mode),
                version,
            );
            let imported = import(&source)?;
            assert!(imported.parameters().is_empty());
            assert_eq!(imported.graph().inputs().len(), 1);
            let result = roundtrip(&source, &[("input", data(&[4], &[1., 2., 3., 4.])?)])?;
            assert_eq!(bits(&result["output"]), bits(&expected));
        }
        let source = pad_model_version(
            &[2, 3],
            &[4, 6],
            &[1, 1, 1, 2],
            None,
            &text_attr("mode", "reflect"),
            version,
        );
        let result = roundtrip(
            &source,
            &[("input", data(&[2, 3], &[1., 2., 3., 4., 5., 6.])?)],
        )?;
        assert_eq!(
            result["output"],
            [
                5., 4., 5., 6., 5., 4., 2., 1., 2., 3., 2., 1., 5., 4., 5., 6., 5., 4., 2., 1., 2.,
                3., 2., 1.,
            ]
        );
    }
    Ok(())
}

#[test]
fn copied_borders_preserve_runtime_bits_for_every_supported_rank() -> Test {
    let special = [
        -0.0_f32,
        0.0,
        f32::from_bits(1),
        -f32::from_bits(1),
        f32::MAX,
        f32::MIN,
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::from_bits(0x7fc1_2345),
        f32::from_bits(0xffc5_4321),
        f32::from_bits(0x7f80_0123),
    ];
    for rank in 1..=4 {
        let dims: Vec<_> = (0..rank).map(|axis| 3 + axis % 2).collect();
        let values: Vec<_> = (0..dims.iter().product())
            .map(|index| special[index % special.len()])
            .collect();
        for mode in ["edge", "reflect"] {
            for pattern in 0..5 {
                let mut pads = vec![0; 2 * rank];
                for axis in 0..rank {
                    (pads[axis], pads[axis + rank]) = match pattern {
                        0 => (0, 0),
                        1 => (1, 2),
                        2 => (-1, -1),
                        3 if axis % 2 == 0 => (-1, 1),
                        3 => (1, -1),
                        _ if axis % 2 == 0 => (2, 0),
                        _ => (0, 2),
                    };
                }
                let output = shape_after(&dims, &pads);
                let source = pad_model(&dims, &output, &pads, None, &text_attr("mode", mode));
                let imported = import(&source)?;
                assert!(imported.parameters().is_empty());
                if pattern == 0 || pattern == 2 {
                    assert_eq!(imported.graph().node_count(), 1);
                }
                let actual = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
                assert_eq!(
                    bits(&actual["output"]),
                    bits(&copied_coordinate_oracle(&values, &dims, &pads, mode)),
                    "rank={rank}, mode={mode}, pattern={pattern}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn large_non_power_of_two_edge_padding_uses_a_small_copy_graph() -> Test {
    let source = pad_model(
        &[1],
        &[65_557],
        &[65_539, 17],
        None,
        &text_attr("mode", "edge"),
    );
    let imported = import_onnx(
        &source,
        ContentDigest::sha256(&source),
        GENERATION,
        OnnxLimits {
            nodes: 23,
            tensors: 25,
            parameter_bytes: 16,
            tensor_bytes: 65_557 * 4,
            ..OnnxLimits::default()
        },
        &|| false,
    )?;
    assert_eq!(imported.graph().node_count(), 23);
    assert!(imported.parameters().is_empty());
    let result = roundtrip(&source, &[("input", data(&[1], &[-0.0])?)])?;
    assert_eq!(bits(&result["output"]), vec![(-0.0_f32).to_bits(); 65_557]);
    Ok(())
}

#[test]
fn copied_padding_resource_boundaries_and_every_cancellation_checkpoint() -> Test {
    for (mode, nodes) in [("edge", 8), ("reflect", 9)] {
        let source = pad_model(
            &[3, 4],
            &[3, 9],
            &[-1, 2, 1, 3],
            None,
            &text_attr("mode", mode),
        );
        let imported = import(&source)?;
        assert_eq!(imported.graph().node_count(), nodes);
        assert!(imported.parameters().is_empty());
        let limits = OnnxLimits {
            nodes,
            tensors: nodes + 2,
            parameter_bytes: 32,
            tensor_bytes: 108,
            work_units: imported.work_units(),
            ..OnnxLimits::default()
        };
        assert!(
            import_onnx(
                &source,
                ContentDigest::sha256(&source),
                GENERATION,
                limits,
                &|| false,
            )
            .is_ok()
        );
        for (limits, expected) in [
            (
                OnnxLimits {
                    nodes: nodes - 1,
                    ..limits
                },
                OnnxError::Limit,
            ),
            (
                OnnxLimits {
                    tensors: nodes + 1,
                    ..limits
                },
                OnnxError::Limit,
            ),
            (
                OnnxLimits {
                    parameter_bytes: 31,
                    ..limits
                },
                OnnxError::Limit,
            ),
            (
                OnnxLimits {
                    tensor_bytes: 107,
                    ..limits
                },
                OnnxError::Limit,
            ),
            (
                OnnxLimits {
                    work_units: imported.work_units() - 1,
                    ..limits
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
                    &|| false,
                )
                .err(),
                Some(expected),
                "mode={mode}, limits={limits:?}"
            );
        }
        let calls = Cell::new(0);
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
                "{mode}, checkpoint {stop}/{total}"
            );
        }
    }
    // A valid geometry still refuses when its exact copy expansion exceeds the
    // node ceiling; the importer never walks or allocates the requested border.
    assert_eq!(
        refusal(&pad_model(
            &[1024],
            &[2047],
            &[1023, 0],
            None,
            &text_attr("mode", "reflect"),
        )),
        Some(OnnxError::Limit)
    );
    Ok(())
}

#[test]
fn reflection_validates_cropped_extent_and_common_refusals_remain() {
    for (dim, pads) in [
        (1, [1, 0]),
        (1, [0, 1]),
        (4, [4, 0]),
        (4, [0, 4]),
        (4, [-2, 2]),
        (4, [2, -2]),
        (4, [-3, 1]),
        (4, [1, -3]),
    ] {
        let dims = [dim];
        assert_eq!(
            refusal(&pad_model(
                &dims,
                &shape_after(&dims, &pads),
                &pads,
                None,
                &text_attr("mode", "reflect"),
            )),
            Some(OnnxError::Unsupported),
            "dim={dim}, pads={pads:?}"
        );
    }
    for mode in ["edge", "reflect"] {
        for pads in [[-4, 1], [-2, -2], [-5, 5], [5, -5]] {
            assert_eq!(
                refusal(&pad_model(
                    &[4],
                    &[1],
                    &pads,
                    None,
                    &text_attr("mode", mode)
                )),
                Some(OnnxError::Unsupported),
            );
        }
        assert_eq!(
            refusal(&pad_model(
                &[4],
                &[1],
                &[i64::MIN, 0],
                None,
                &text_attr("mode", mode)
            )),
            Some(OnnxError::Limit),
        );
        assert_eq!(
            refusal(&pad_model(
                &[2],
                &[5],
                &[1, 1],
                None,
                &text_attr("mode", mode)
            )),
            Some(OnnxError::Graph),
        );
        let source = model(
            &[
                node(
                    "Pad",
                    &["input", "pads", "fill"],
                    &["output"],
                    &text_attr("mode", mode),
                ),
                int_weight("pads", &[2], &[1, 1]),
                bytes(11, &info("input", &[2], 1)),
                bytes(11, &info("fill", &[], 1)),
                bytes(12, &info("output", &[4], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Unsupported));
    }
}

#[test]
fn copied_padding_helpers_cannot_alias_future_source_values() -> Test {
    for mode in ["edge", "reflect"] {
        let mut collision_names = vec![
            "onnx-node-0000-pad-crop",
            "onnx-node-0000-pad-axis-0-after-sample-0",
            "onnx-node-0000-pad-axis-0-value",
            "onnx-node-0000-pad-axis-1-before-sample-0",
        ];
        if mode == "edge" {
            collision_names.push("onnx-node-0000-pad-axis-1-before-repeat-0");
        }
        let mut graph = node(
            "Pad",
            &["input", "pads"],
            &["padded"],
            &text_attr("mode", mode),
        );
        let mut previous = "padded";
        for name in &collision_names {
            graph.extend(node("Identity", &[previous], &[name], &[]));
            previous = name;
        }
        graph.extend(int_weight("pads", &[4], &[-1, 2, 1, 3]));
        graph.extend(bytes(11, &info("input", &[3, 4], 1)));
        graph.extend(bytes(12, &info(previous, &[3, 9], 1)));
        let source = model(&graph);
        let imported = import(&source)?;
        let names: Vec<_> = imported
            .graph()
            .nodes()
            .iter()
            .flat_map(|node| node.outputs().iter().map(String::as_str))
            .collect();
        let unique: std::collections::BTreeSet<_> = names.iter().collect();
        assert_eq!(names.len(), unique.len());
        for name in &collision_names {
            assert!(names.contains(&format!("{name}-1").as_str()));
        }
        let values: Vec<f32> = (0..12).map(|index| index as f32).collect();
        let result = roundtrip(&source, &[("input", data(&[3, 4], &values)?)])?;
        assert_eq!(
            bits(&result[previous]),
            bits(&copied_coordinate_oracle(
                &values,
                &[3, 4],
                &[-1, 2, 1, 3],
                mode
            )),
        );
    }
    Ok(())
}

#[test]
fn copied_padding_composes_with_real_convolution_after_artifact_reload() -> Test {
    let dims = [1, 1, 2, 3];
    let pads = [0, 0, 1, 2, 0, 0, 1, 0];
    let values = [1., 2., 3., 4., 5., 6.];
    for mode in ["edge", "reflect"] {
        let source = model(
            &[
                node(
                    "Pad",
                    &["input", "pads"],
                    &["padded"],
                    &text_attr("mode", mode),
                ),
                node("Conv", &["padded", "kernel"], &["output"], &[]),
                int_weight("pads", &[8], &pads),
                weight(
                    "kernel",
                    &[1, 1, 3, 3],
                    &[1., 0., 0., 0., 1., 0., 0., 0., 1.],
                ),
                bytes(11, &info("input", &dims, 1)),
                bytes(13, &info("padded", &[1, 1, 4, 5], 1)),
                bytes(12, &info("output", &[1, 1, 2, 3], 1)),
            ]
            .concat(),
        );
        let padded = copied_coordinate_oracle(&values, &dims, &pads, mode);
        let mut expected = Vec::new();
        for row in 0..2 {
            for column in 0..3 {
                let mut sum = 0.0_f32;
                for y in 0..3 {
                    for x in 0..3 {
                        let weight = if y == x { 1.0 } else { 0.0 };
                        sum += padded[(row + y) * 5 + column + x] * weight;
                    }
                }
                expected.push(sum);
            }
        }
        let result = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
        assert_eq!(bits(&result["output"]), bits(&expected));
    }
    Ok(())
}

#[test]
fn legacy_constant_graph_bytes_are_unchanged() -> Test {
    // Captured with the original production constant Pad implementation before
    // adding edge/reflect. Importer source identity changes; native graph bytes do not.
    for (dims, pads, fill, expected) in [
        (
            vec![3, 4],
            vec![-1, 2, 1, 3],
            Some(-0.0),
            "sha256:d35ec32042e8a59a1489c454e5b0d0b4f5b728639921972e7a9cae92895616d0",
        ),
        (
            vec![2],
            vec![1, 2],
            Some(9.0),
            "sha256:4e5406f5fd6f925833228660e0952f2827d8ca2294fb69673c9e7a23b192e463",
        ),
        (
            vec![2],
            vec![0, 0],
            None,
            "sha256:a0e7e35c27ab2c56d983dd1ff3065343de2b18e18c2de53d5ae9e5df57371bf1",
        ),
        (
            vec![4],
            vec![-1, -1],
            None,
            "sha256:de57ccef995edfbabbced705b66f6331f6cd3e1991845d1d268ed8d48f7110ff",
        ),
    ] {
        let source = pad_model(&dims, &shape_after(&dims, &pads), &pads, fill, &[]);
        let imported = import(&source)?;
        assert_eq!(
            ContentDigest::sha256(&encode_canonical_model_ir(imported.graph())?).to_string(),
            expected,
        );
    }
    Ok(())
}
