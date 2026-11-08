#![forbid(unsafe_code)]
//! ONNX Clip-13 finite F32 semantics through real artifact parsing and both
//! production CPU executors. A direct scalar comparison oracle checks exact bits,
//! including signed-zero ties, independently of the native lowering. Embedded
//! nonfinite values refuse import; direct executor inputs stay inside the declared
//! finite-input profile, rather than pretending these kernels validate host input.

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
const GENERATION: Generation = Generation(41);

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

fn clip_graph(dims: &[usize], min: Option<f32>, max: Option<f32>) -> Vec<u8> {
    let mut inputs = vec!["input"];
    if min.is_some() || max.is_some() {
        inputs.push(if min.is_some() { "min" } else { "" });
    }
    if max.is_some() {
        inputs.push("max");
    }
    let mut graph = [
        node("Clip", &inputs, &["output"], &[]),
        bytes(11, &info("input", dims, 1)),
        bytes(12, &info("output", dims, 1)),
    ]
    .concat();
    if let Some(value) = min {
        graph.extend(weight("min", &[], &[value]));
    }
    if let Some(value) = max {
        graph.extend(weight("max", &[], &[value]));
    }
    graph
}

fn clip_model(dims: &[usize], min: Option<f32>, max: Option<f32>) -> Vec<u8> {
    model(&clip_graph(dims, min, max))
}

fn runtime_clip_model(dims: &[usize], lower: bool, upper: bool) -> Vec<u8> {
    let mut inputs = vec!["input"];
    if lower || upper {
        inputs.push(if lower { "min" } else { "" });
    }
    if upper {
        inputs.push("max");
    }
    let mut graph = [
        node("Clip", &inputs, &["output"], &[]),
        bytes(11, &info("input", dims, 1)),
        bytes(12, &info("output", dims, 1)),
    ]
    .concat();
    if lower {
        graph.extend(bytes(11, &info("min", &[], 1)));
    }
    if upper {
        graph.extend(bytes(11, &info("max", &[], 1)));
    }
    model(&graph)
}

/// Source-level min(max(x, min), max). Ordered comparisons deliberately select
/// the bound on equality; f32::clamp would reject inverted bounds and generic
/// min/max operations could obscure signed-zero behavior.
fn oracle(input: &[f32], min: Option<f32>, max: Option<f32>) -> Vec<f32> {
    let min = min.unwrap_or(f32::MIN);
    let max = max.unwrap_or(f32::MAX);
    input
        .iter()
        .map(|&x| {
            let lower = if x > min { x } else { min };
            if lower < max { lower } else { max }
        })
        .collect()
}

#[test]
fn defaults_and_one_or_two_bounds_preserve_all_admitted_ranks() -> Test {
    for rank in 0..=8 {
        let dims = vec![2; rank];
        let special = [-f32::MAX, -0.0_f32, 0.0, -3.5, 2.0, 7.0, f32::MAX];
        let values = (0..dims.iter().product::<usize>())
            .map(|index| special[index % special.len()])
            .collect::<Vec<_>>();
        for (min, max) in [
            (None, None),
            (Some(0.0), None),
            (None, Some(6.0)),
            (Some(0.0), Some(6.0)),
            (Some(-3.0), Some(4.0)),
            (Some(6.0), Some(-2.0)),
        ] {
            let source = clip_model(&dims, min, max);
            let result = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
            assert_eq!(bits(&result["output"]), bits(&oracle(&values, min, max)));
            assert_eq!(import(&source)?.graph().outputs()[0].shape().dims(), &dims);
        }
    }
    Ok(())
}

#[test]
fn omitted_and_empty_optional_ports_share_default_semantics() -> Test {
    let values = [-f32::MAX, -0.0_f32, 0.0, f32::from_bits(1), f32::MAX];
    for inputs in [vec!["input"], vec!["input", ""], vec!["input", "", ""]] {
        let source = model(
            &[
                node("Clip", &inputs, &["output"], &[]),
                bytes(11, &info("input", &[5], 1)),
                bytes(12, &info("output", &[5], 1)),
            ]
            .concat(),
        );
        let imported = import(&source)?;
        assert_eq!(imported.graph().node_count(), 1);
        assert!(imported.parameters().is_empty());
        assert_eq!(
            bits(&roundtrip(&source, &[("input", data(&[5], &values)?)])?["output"]),
            bits(&values)
        );
    }
    let trailing_empty = model(
        &[
            node("Clip", &["input", "min", ""], &["output"], &[]),
            weight("min", &[], &[-1.0]),
            bytes(11, &info("input", &[5], 1)),
            bytes(12, &info("output", &[5], 1)),
        ]
        .concat(),
    );
    assert_eq!(
        bits(&roundtrip(&trailing_empty, &[("input", data(&[5], &values)?)])?["output"]),
        bits(&oracle(&values, Some(-1.0), None))
    );
    Ok(())
}

#[test]
fn all_finite_exponents_extrema_and_subnormals_use_exact_comparisons() -> Test {
    let mut values = Vec::new();
    for exponent in 0_u32..255 {
        for mantissa in [0, 1, 2, 3, 0x3f_ffff, 0x40_0000, 0x7f_fffe, 0x7f_ffff] {
            for sign in [0, 1 << 31] {
                values.push(f32::from_bits(sign | exponent << 23 | mantissa));
            }
        }
    }
    assert_eq!(values.len(), 4080);
    assert!(values.iter().all(|value| value.is_finite()));
    for (min, max) in [
        (-f32::MAX, f32::MAX),
        (-1.0, 1.0),
        (-f32::from_bits(1), f32::from_bits(1)),
        (-f32::MAX, -f32::MAX),
        (f32::MAX, f32::MAX),
        (5.0, -5.0),
        (0.0, -0.0),
        (-0.0, 0.0),
    ] {
        let source = clip_model(&[values.len()], Some(min), Some(max));
        let result = roundtrip(&source, &[("input", data(&[values.len()], &values)?)])?;
        assert_eq!(
            bits(&result["output"]),
            bits(&oracle(&values, Some(min), Some(max))),
            "bounds [{min:?}, {max:?}]"
        );
    }
    Ok(())
}

#[test]
fn signed_zero_bounds_choose_limit_bits_and_survive_weight_reload() -> Test {
    let values = [
        -f32::from_bits(1),
        -0.0_f32,
        0.0,
        f32::from_bits(1),
        -f32::MAX,
        f32::MAX,
    ];
    for min in [None, Some(-0.0_f32), Some(0.0)] {
        for max in [None, Some(-0.0_f32), Some(0.0)] {
            let source = clip_model(&[6], min, max);
            let result = roundtrip(&source, &[("input", data(&[6], &values)?)])?;
            assert_eq!(bits(&result["output"]), bits(&oracle(&values, min, max)));
            let imported = import(&source)?;
            for (name, value) in [("min", min), ("max", max)] {
                if let Some(value) = value {
                    let parameter = imported.parameters().get(name).ok_or("missing bound")?;
                    assert_eq!(bits(&parameter.to_vec::<f32>()?), vec![value.to_bits()]);
                }
            }
        }
    }
    let negative = clip_model(&[6], Some(-0.0), None);
    let positive = clip_model(&[6], Some(0.0), None);
    assert_ne!(
        export(&import(&negative)?)?.weights_digest(),
        export(&import(&positive)?)?.weights_digest()
    );
    Ok(())
}

#[test]
fn runtime_scalar_bounds_remain_live_after_artifact_export() -> Test {
    let values = [-8.0_f32, -1.0, -0.0, 0.0, 0.5, 3.0, 7.0, f32::MAX];
    for (lower, upper) in [(true, false), (false, true), (true, true)] {
        let source = runtime_clip_model(&[8], lower, upper);
        let imported = import(&source)?;
        assert_eq!(
            imported.runtime_inputs().len(),
            1 + usize::from(lower) + usize::from(upper)
        );
        for (min, max) in [(-2.0, 6.0), (-0.0, -0.0), (4.0, -3.0)] {
            let mut inputs = vec![("input", data(&[8], &values)?)];
            if lower {
                inputs.push(("min", data(&[], &[min])?));
            }
            if upper {
                inputs.push(("max", data(&[], &[max])?));
            }
            let result = roundtrip(&source, &inputs)?;
            assert_eq!(
                bits(&result["output"]),
                bits(&oracle(&values, lower.then_some(min), upper.then_some(max)))
            );
        }
    }
    Ok(())
}

#[test]
fn constant_nodes_and_earlier_native_scalar_results_supply_bounds() -> Test {
    let values = [-2.0_f32, -0.0, 0.0, 1.0, 7.0, f32::MAX];
    let source = model(
        &[
            node("Constant", &[], &["min"], &float_attr("value_float", -0.0)),
            node("Add", &["ceiling", "offset"], &["max"], &[]),
            node("Clip", &["input", "min", "max"], &["output"], &[]),
            weight("offset", &[], &[1.0]),
            bytes(11, &info("input", &[6], 1)),
            bytes(11, &info("ceiling", &[], 1)),
            bytes(12, &info("output", &[6], 1)),
        ]
        .concat(),
    );
    for ceiling in [5.0_f32, -2.0] {
        let result = roundtrip(
            &source,
            &[
                ("input", data(&[6], &values)?),
                ("ceiling", data(&[], &[ceiling])?),
            ],
        )?;
        assert_eq!(
            bits(&result["output"]),
            bits(&oracle(&values, Some(-0.0), Some(ceiling + 1.0)))
        );
    }

    let tensor_constant = model(
        &[
            node(
                "Constant",
                &[],
                &["max"],
                &attribute(
                    "value",
                    4,
                    &bytes(
                        5,
                        &tensor("metadata-only-name", &[], 1, &6.0_f32.to_le_bytes()),
                    ),
                ),
            ),
            node("Clip", &["input", "", "max"], &["output"], &[]),
            bytes(11, &info("input", &[6], 1)),
            bytes(12, &info("output", &[6], 1)),
        ]
        .concat(),
    );
    assert_eq!(
        bits(&roundtrip(&tensor_constant, &[("input", data(&[6], &values)?)])?["output"]),
        bits(&oracle(&values, None, Some(6.0)))
    );
    Ok(())
}

#[test]
fn constant_input_and_multiple_clips_keep_distinct_bound_uses() -> Test {
    let values = [-5.0_f32, -0.0, 0.0, 0.25, 1.0, 8.0];
    let source = model(
        &[
            node("Clip", &["input", "min", "max"], &["middle"], &[]),
            node("Clip", &["middle", "", "ceiling"], &["output"], &[]),
            weight("input", &[6], &values),
            weight("min", &[], &[-1.0]),
            weight("max", &[], &[1.0]),
            weight("ceiling", &[], &[0.5]),
            bytes(12, &info("middle", &[6], 1)),
            bytes(12, &info("output", &[6], 1)),
        ]
        .concat(),
    );
    let result = roundtrip(&source, &[])?;
    let middle = oracle(&values, Some(-1.0), Some(1.0));
    assert_eq!(bits(&result["middle"]), bits(&middle));
    assert_eq!(
        bits(&result["output"]),
        bits(&oracle(&middle, None, Some(0.5)))
    );
    Ok(())
}

#[test]
fn conv_relu6_flatten_dense_chain_preserves_unclipped_branch() -> Test {
    let source = model(
        &[
            node(
                "Conv",
                &["input", "conv-weight", "conv-bias"],
                &["raw"],
                &ints_attr("kernel_shape", &[1, 1]),
            ),
            node("Clip", &["raw", "min", "max"], &["activated"], &[]),
            node("Flatten", &["activated"], &["flat"], &[]),
            node(
                "Gemm",
                &["flat", "dense-weight", "dense-bias"],
                &["output"],
                &[],
            ),
            weight("conv-weight", &[1, 1, 1, 1], &[2.0]),
            weight("conv-bias", &[1], &[1.0]),
            weight("min", &[], &[0.0]),
            weight("max", &[], &[6.0]),
            weight(
                "dense-weight",
                &[4, 2],
                &[1., -1., 2., 1., 3., 0.5, 4., -2.],
            ),
            weight("dense-bias", &[2], &[-1., 0.25]),
            bytes(11, &info("input", &[1, 1, 2, 2], 1)),
            bytes(12, &info("raw", &[1, 1, 2, 2], 1)),
            bytes(12, &info("activated", &[1, 1, 2, 2], 1)),
            bytes(12, &info("output", &[1, 2], 1)),
        ]
        .concat(),
    );
    let result = roundtrip(
        &source,
        &[("input", data(&[1, 1, 2, 2], &[-2., 0., 2., 5.])?)],
    )?;
    assert_eq!(bits(&result["raw"]), bits(&[-3., 1., 5., 11.]));
    assert_eq!(bits(&result["activated"]), bits(&[0., 1., 5., 6.]));
    assert_eq!(bits(&result["output"]), bits(&[40., -8.25]));
    Ok(())
}

#[test]
fn future_source_names_cannot_alias_generated_clip_values() -> Test {
    let dims = [4];
    let values = [-3.0_f32, -0.0, 0.0, 7.0];
    let baseline = clip_model(&dims, Some(0.0), Some(6.0));
    let imported = import(&baseline)?;
    let names = imported
        .graph()
        .nodes()
        .iter()
        .flat_map(|node| node.outputs().iter())
        .chain(imported.parameters().keys())
        .filter(|name| !["input", "min", "max", "output"].contains(&name.as_str()))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    assert!(!names.is_empty());
    for collision in names {
        let source = model(
            &[
                clip_graph(&dims, Some(0.0), Some(6.0)),
                node("Identity", &["input"], &[&collision], &[]),
                bytes(12, &info(&collision, &dims, 1)),
            ]
            .concat(),
        );
        let result = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
        assert_eq!(
            bits(&result["output"]),
            bits(&oracle(&values, Some(0.0), Some(6.0)))
        );
        assert_eq!(bits(&result[&collision]), bits(&values));

        let forward = model(
            &[
                node("Clip", &["input", &collision], &["output"], &[]),
                node(
                    "Constant",
                    &[],
                    &[&collision],
                    &float_attr("value_float", 0.0),
                ),
                bytes(11, &info("input", &dims, 1)),
                bytes(12, &info("output", &dims, 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&forward), Some(OnnxError::Graph));
    }
    Ok(())
}

#[test]
fn nonscalar_nonfloat_nonfinite_bounds_attributes_and_bad_shapes_refuse() {
    for dims in [vec![1], vec![2], vec![1, 1], vec![0]] {
        let values = vec![0.0_f32; dims.iter().product()];
        let source = model(
            &[
                node("Clip", &["input", "min"], &["output"], &[]),
                weight("min", &dims, &values),
                bytes(11, &info("input", &[2], 1)),
                bytes(12, &info("output", &[2], 1)),
            ]
            .concat(),
        );
        assert!(refusal(&source).is_some(), "bound shape {dims:?}");
    }
    let integer_bound = model(
        &[
            node("Clip", &["input", "min"], &["output"], &[]),
            bytes(5, &tensor("min", &[], 7, &0_i64.to_le_bytes())),
            bytes(11, &info("input", &[2], 1)),
            bytes(12, &info("output", &[2], 1)),
        ]
        .concat(),
    );
    assert!(refusal(&integer_bound).is_some());
    for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        assert_eq!(
            refusal(&clip_model(&[2], Some(value), None)),
            Some(OnnxError::NonFinite)
        );
        assert_eq!(
            refusal(&clip_model(&[2], None, Some(value))),
            Some(OnnxError::NonFinite)
        );
    }
    for attrs in [
        float_attr("min", 0.0),
        float_attr("max", 6.0),
        int_attr("axis", 0),
        text_attr("mode", "clip"),
    ] {
        let source = model(
            &[
                node("Clip", &["input"], &["output"], &attrs),
                bytes(11, &info("input", &[2], 1)),
                bytes(12, &info("output", &[2], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Unsupported));
    }
    for inputs in [
        vec![],
        vec![""],
        vec!["input", "missing"],
        vec!["input", "", "", ""],
    ] {
        let source = model(
            &[
                node("Clip", &inputs, &["output"], &[]),
                bytes(11, &info("input", &[2], 1)),
                bytes(12, &info("output", &[2], 1)),
            ]
            .concat(),
        );
        assert!(refusal(&source).is_some(), "inputs {inputs:?}");
    }
    for (input_dims, output_dims) in [
        (vec![2], vec![3]),
        (vec![2], vec![]),
        (vec![0], vec![0]),
        (vec![1; 9], vec![1; 9]),
    ] {
        let source = model(
            &[
                node("Clip", &["input"], &["output"], &[]),
                bytes(11, &info("input", &input_dims, 1)),
                bytes(12, &info("output", &output_dims, 1)),
            ]
            .concat(),
        );
        assert!(refusal(&source).is_some());
    }
}

#[test]
fn helper_graph_and_scalar_parameter_cost_do_not_scale_with_pixels() -> Test {
    for (lower, upper, nodes) in [
        (false, false, 1),
        (true, false, 7),
        (false, true, 10),
        (true, true, 13),
    ] {
        for elements in [8_usize, 4096] {
            let source = runtime_clip_model(&[elements], lower, upper);
            let imported = import(&source)?;
            assert_eq!(imported.graph().node_count(), nodes);
            let parameter_bytes = usize::from(lower || upper) * 4;
            assert_eq!(
                imported
                    .parameters()
                    .values()
                    .map(|v| v.to_vec::<f32>().map(|x| x.len() * 4))
                    .collect::<Result<Vec<_>, _>>()?
                    .iter()
                    .sum::<usize>(),
                parameter_bytes
            );
            let limits = OnnxLimits {
                source_bytes: source.len(),
                nodes,
                tensors: imported.graph().input_count() + nodes,
                parameter_bytes,
                tensor_bytes: elements * if lower || upper { 8 } else { 4 },
                work_units: imported.work_units(),
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
            let mut insufficient = vec![
                OnnxLimits {
                    source_bytes: source.len() - 1,
                    ..limits
                },
                OnnxLimits {
                    tensors: limits.tensors - 1,
                    ..limits
                },
                OnnxLimits {
                    tensor_bytes: limits.tensor_bytes - 1,
                    ..limits
                },
            ];
            if nodes > 1 {
                insufficient.push(OnnxLimits {
                    nodes: nodes - 1,
                    ..limits
                });
                insufficient.push(OnnxLimits {
                    parameter_bytes: parameter_bytes - 1,
                    ..limits
                });
            }
            for limit in insufficient {
                assert_eq!(
                    import_onnx(
                        &source,
                        ContentDigest::sha256(&source),
                        GENERATION,
                        limit,
                        &|| false
                    )
                    .err(),
                    Some(OnnxError::Limit)
                );
            }
        }
    }
    Ok(())
}

#[test]
fn exact_import_work_digest_and_every_cancellation_checkpoint_fail_closed() -> Test {
    let source = runtime_clip_model(&[8], true, true);
    let imported = import(&source)?;
    assert_eq!(
        import_onnx(
            &source,
            ContentDigest::sha256(&source),
            GENERATION,
            OnnxLimits {
                work_units: imported.work_units() - 1,
                ..OnnxLimits::default()
            },
            &|| false,
        )
        .err(),
        Some(OnnxError::WorkBudget)
    );
    assert_eq!(
        import_onnx(
            &source,
            ContentDigest::sha256(b"wrong source"),
            GENERATION,
            OnnxLimits::default(),
            &|| false
        )
        .err(),
        Some(OnnxError::Digest)
    );
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
                }
            )
            .err(),
            Some(OnnxError::Cancelled),
            "checkpoint {stop}/{total}"
        );
    }
    Ok(())
}

#[test]
fn both_executors_observe_exact_budgets_generation_and_cancellation() -> Test {
    let source = runtime_clip_model(&[8], true, true);
    let imported = import(&source)?;
    let input = [
        ("input", data(&[8], &[-1., 2., -3., 4., -5., 6., -7., 8.])?),
        ("min", data(&[], &[0.0])?),
        ("max", data(&[], &[6.0])?),
    ];
    let constants = imported
        .parameters()
        .iter()
        .map(|(name, value)| Ok((name.clone(), value.to_vec::<f32>()?)))
        .collect::<Result<BTreeMap<_, _>, fss_tensor::TensorError>>()?;
    let optimized = optimized_executor::OptimizedGraph::prepare(
        imported.graph(),
        &constants,
        &ScalarExecCx::new(),
    )?;
    let mut bindings = imported.parameters().clone();
    bindings.extend(
        input
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone())),
    );
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
        ExecBudget::new(exact.max_macs - 1, exact.max_bytes),
        ExecBudget::new(exact.max_macs, exact.max_bytes - 1),
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

    let wrong_generation = Tensor::from_values(Shape::new(vec![])?, &[0.0_f32], Generation(42))?;
    let mut invalid = input.to_vec();
    invalid[1].1 = wrong_generation.clone();
    let mut invalid_bindings = bindings.clone();
    let bound = invalid_bindings
        .iter_mut()
        .find(|(name, _)| name == "min")
        .ok_or("min binding")?;
    bound.1 = wrong_generation;
    assert!(matches!(
        ScalarExecutor::run(
            imported.graph(),
            &invalid_bindings,
            exact,
            &ScalarExecCx::new()
        ),
        Err(ExecError::GenerationMismatch { .. })
    ));
    assert!(matches!(
        optimized.run(&invalid, exact, &ScalarExecCx::new()),
        Err(ExecError::GenerationMismatch { .. })
    ));

    let scalar_cx = ScalarExecCx::new();
    scalar_cx.request_cancellation();
    assert!(matches!(
        ScalarExecutor::run(imported.graph(), &bindings, exact, &scalar_cx),
        Err(ExecError::CancellationRequested { .. })
    ));
    assert!(scalar_cx.is_drain_completed());
    let fast_cx = ScalarExecCx::new();
    fast_cx.request_cancellation();
    assert!(matches!(
        optimized.run(&input, exact, &fast_cx),
        Err(ExecError::CancellationRequested { .. })
    ));
    assert!(fast_cx.is_drain_completed());
    Ok(())
}
