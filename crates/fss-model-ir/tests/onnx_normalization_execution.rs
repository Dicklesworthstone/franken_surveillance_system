#![forbid(unsafe_code)]
//! Decomposed LayerNorm and exact-Erf GELU retain their explicit F32 operation
//! order through ONNX import, both production executors and canonical graph /
//! production Safetensors reload. No foreign inference runtime is used.

use std::cell::Cell;
use std::collections::BTreeMap;

use fss_core::{ContentDigest, Generation};
use fss_model_ir::{
    ImportedOnnx, ModelIrGraph, ModelIrVersion, OnnxArtifacts, OnnxError, OnnxExportLimits,
    OnnxLimits, OpCode, decode_canonical_model_ir, encode_canonical_model_ir,
    export_onnx_artifacts, import_onnx,
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
const GENERATION: Generation = Generation(57);

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

fn data(dimensions: &[usize], values: &[f32]) -> Test<Tensor> {
    Ok(Tensor::from_values(
        Shape::new(dimensions.to_vec())?,
        values,
        GENERATION,
    )?)
}
fn constant(name: &str, shape: &[usize], values: &[f32]) -> Vec<u8> {
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
                    "original-constant-metadata",
                    shape,
                    1,
                    &values
                        .iter()
                        .flat_map(|v| v.to_le_bytes())
                        .collect::<Vec<_>>(),
                ),
            ),
        ),
    )
}
fn unary(op: &str, input: &[usize], output: &[usize], attrs: &[u8]) -> Vec<u8> {
    model(
        &[
            node(op, &["input"], &["output"], attrs),
            bytes(11, &info("input", input, 1)),
            bytes(12, &info("output", output, 1)),
        ]
        .concat(),
    )
}
fn power(shape: &[usize], exponent_shape: &[usize], exponent: f32, embedded_node: bool) -> Vec<u8> {
    model(
        &[
            if embedded_node {
                constant("exponent", exponent_shape, &[exponent])
            } else {
                weight("exponent", exponent_shape, &[exponent])
            },
            node("Pow", &["input", "exponent"], &["output"], &[]),
            bytes(11, &info("input", shape, 1)),
            bytes(12, &info("output", shape, 1)),
        ]
        .concat(),
    )
}

fn layer_norm(shape: &[usize], epsilon: f32, scale: &[f32], bias: &[f32]) -> Vec<u8> {
    let mean = [ints_attr("axes", &[-1]), int_attr("keepdims", 1)].concat();
    model(
        &[
            node("ReduceMean", &["input"], &["mean"], &mean),
            node("Sub", &["input", "mean"], &["centered"], &[]),
            node("Pow", &["centered", "two"], &["squared"], &[]),
            node("ReduceMean", &["squared"], &["variance"], &mean),
            node("Add", &["variance", "epsilon"], &["stabilized"], &[]),
            node("Sqrt", &["stabilized"], &["denominator"], &[]),
            node("Div", &["centered", "denominator"], &["normalized"], &[]),
            node("Mul", &["normalized", "scale"], &["scaled"], &[]),
            node("Add", &["scaled", "bias"], &["output"], &[]),
            weight("two", &[], &[2.]),
            weight("epsilon", &[], &[epsilon]),
            weight("scale", &[scale.len()], scale),
            weight("bias", &[bias.len()], bias),
            bytes(11, &info("input", shape, 1)),
            bytes(12, &info("output", shape, 1)),
        ]
        .concat(),
    )
}

// Independent row indexing and explicit F32 staging, without invoking any graph,
// normalization helper or production reduction. This checks the source sequence;
// the native LayerNorm instead uses binary64 statistics and must not replace it.
fn layer_norm_oracle(
    values: &[f32],
    width: usize,
    epsilon: f32,
    scale: &[f32],
    bias: &[f32],
) -> Vec<f32> {
    let mut output = Vec::new();
    for row in values.chunks(width) {
        let mut sum = 0.0_f32;
        for &x in row {
            sum += x;
        }
        let mean = sum / width as f32;
        let centered = row.iter().map(|&x| x - mean).collect::<Vec<_>>();
        let mut sum_squares = 0.0_f32;
        for &x in &centered {
            sum_squares += x * x;
        }
        let variance = sum_squares / width as f32;
        let denominator = (variance + epsilon).sqrt();
        for (index, x) in centered.into_iter().enumerate() {
            let normalized = x / denominator;
            let scaled = normalized * scale[index];
            output.push(scaled + bias[index]);
        }
    }
    output
}

#[test]
fn decomposed_layer_norm_preserves_source_order_and_native_artifact_reload() -> Test {
    let scale = [0.5_f32, -1.5, 1.25, 2.];
    let bias = [0.125_f32, -0.25, 1., -2.];
    for shape in [
        vec![4],
        vec![2, 4],
        vec![1, 2, 3, 4],
        vec![1, 1, 1, 1, 1, 2, 1, 4],
    ] {
        let values = (0..shape.iter().product::<usize>())
            .map(|i| ((i * 7 % 31) as f32 - 15.) * 0.125)
            .collect::<Vec<_>>();
        let source = layer_norm(&shape, 1e-5_f32, &scale, &bias);
        let imported = import(&source)?;
        assert_eq!(imported.graph().version(), ModelIrVersion::V2);
        assert!(
            !imported
                .graph()
                .nodes()
                .iter()
                .any(|n| n.op() == OpCode::LayerNorm)
        );
        assert_eq!(
            imported
                .graph()
                .nodes()
                .iter()
                .filter(|n| n.op() == OpCode::Sqrt)
                .count(),
            1
        );
        assert_eq!(imported.runtime_inputs(), ["input"]);
        assert!(!imported.parameters().contains_key("two"));
        let actual = roundtrip(&source, &[("input", data(&shape, &values)?)])?;
        assert_eq!(
            bits(&actual["output"]),
            bits(&layer_norm_oracle(&values, 4, 1e-5_f32, &scale, &bias)),
            "shape={shape:?}"
        );
    }
    Ok(())
}

#[test]
fn decomposition_keeps_population_statistics_rounding_and_overflow_visible() -> Test {
    for values in [
        vec![4., 4., 4., 4.],
        vec![16_777_216., 1., -16_777_216., 4.],
        vec![f32::from_bits(1), -f32::from_bits(1), 0., -0.],
        vec![f32::MAX, f32::MAX, f32::MAX, f32::MAX],
    ] {
        let source = layer_norm(&[1, 4], 1e-5_f32, &[1.; 4], &[0.; 4]);
        let output = roundtrip(&source, &[("input", data(&[1, 4], &values)?)])?;
        let expected = layer_norm_oracle(&values, 4, 1e-5_f32, &[1.; 4], &[0.; 4]);
        for (&actual, &expected) in output["output"].iter().zip(&expected) {
            if expected.is_nan() {
                assert!(actual.is_nan());
            } else {
                assert_eq!(actual.to_bits(), expected.to_bits());
            }
        }
        if values[0] == f32::MAX {
            // An overflowed source reduction must not be repaired by silently
            // replacing this graph with the robust native LayerNorm operator.
            assert!(output["output"].iter().all(|x| x.is_nan()));
        }
    }
    Ok(())
}

fn gelu(shape: &[usize], half_first: bool) -> Vec<u8> {
    let tail = if half_first {
        [
            node("Mul", &["input", "half"], &["scaled"], &[]),
            node("Mul", &["scaled", "shifted"], &["output"], &[]),
        ]
        .concat()
    } else {
        [
            node("Mul", &["input", "shifted"], &["scaled"], &[]),
            node("Mul", &["scaled", "half"], &["output"], &[]),
        ]
        .concat()
    };
    model(
        &[
            node("Div", &["input", "sqrt_two"], &["argument"], &[]),
            node("Erf", &["argument"], &["erf"], &[]),
            node("Add", &["erf", "one"], &["shifted"], &[]),
            tail,
            weight("sqrt_two", &[], &[2.0_f32.sqrt()]),
            weight("one", &[], &[1.]),
            weight("half", &[], &[0.5]),
            bytes(11, &info("input", shape, 1)),
            bytes(12, &info("output", shape, 1)),
        ]
        .concat(),
    )
}

// Composite Simpson integration of erf's defining integral is independent of the
// production series/normal-tail implementation. The ordinary GELU fixtures use
// |x/sqrt(2)| < 4; 4096 subintervals make quadrature error negligible at F32 scale.
fn erf_integral(x: f64) -> f64 {
    let steps = 4096;
    let upper = x.abs();
    let step = upper / steps as f64;
    let mut total = 1.0 + (-upper * upper).exp();
    for index in 1..steps {
        let value = index as f64 * step;
        total += if index % 2 == 0 { 2. } else { 4. } * (-value * value).exp();
    }
    (2. / std::f64::consts::PI.sqrt() * step / 3. * total).copysign(x)
}

#[test]
fn decomposed_erf_gelu_executes_and_reloads_without_reassociation() -> Test {
    let values = [-5.0_f32, -3., -1., -0.01, -0., 0., 0.01, 1., 3., 5.];
    for half_first in [false, true] {
        let source = gelu(&[2, 5], half_first);
        let imported = import(&source)?;
        assert_eq!(imported.graph().version(), ModelIrVersion::V2);
        assert_eq!(
            imported
                .graph()
                .nodes()
                .iter()
                .map(|n| n.op())
                .collect::<Vec<_>>(),
            [
                OpCode::Div,
                OpCode::Erf,
                OpCode::Add,
                OpCode::Mul,
                OpCode::Mul
            ]
        );
        let output = roundtrip(&source, &[("input", data(&[2, 5], &values)?)])?;
        for (&actual, &input) in output["output"].iter().zip(&values) {
            let argument = input / 2.0_f32.sqrt();
            let expected = 0.5 * f64::from(input) * (1. + erf_integral(f64::from(argument)));
            assert!((f64::from(actual) - expected).abs() <= 2e-6 * (1. + expected.abs()));
        }
        assert_eq!(output["output"][4].to_bits(), (-0.0_f32).to_bits());
        assert_eq!(output["output"][5].to_bits(), 0.0_f32.to_bits());
    }
    let early = gelu(&[1], true);
    let late = gelu(&[1], false);
    let input = [("input", data(&[1], &[f32::MAX])?)];
    assert_eq!(roundtrip(&early, &input)?["output"], [f32::MAX]);
    assert_eq!(roundtrip(&late, &input)?["output"], [f32::INFINITY]);
    assert_ne!(
        encode_canonical_model_ir(import(&early)?.graph())?,
        encode_canonical_model_ir(import(&late)?.graph())?
    );
    Ok(())
}

#[test]
fn scalar_constant_powers_keep_v1_bits_controls_and_original_source() -> Test {
    let values = [
        -3.0_f32,
        -1.,
        -0.,
        0.,
        f32::from_bits(1),
        f32::MIN_POSITIVE,
        -f32::MIN_POSITIVE,
        0.125,
        1.,
        1.000_000_1,
        8.,
        f32::MAX,
    ];
    for exponent in [2.0_f32, 3.] {
        for embedded_node in [false, true] {
            let source = power(&[3, 4], &[], exponent, embedded_node);
            let imported = import(&source)?;
            assert_eq!(imported.graph().version(), ModelIrVersion::V1);
            assert_eq!(
                imported.graph().node_count(),
                if exponent == 2. { 1 } else { 2 }
            );
            assert!(
                imported
                    .graph()
                    .nodes()
                    .iter()
                    .all(|n| n.op() == OpCode::Mul)
            );
            assert!(imported.parameters().is_empty());
            assert_eq!(imported.source(), source);
            assert_eq!(imported.source_digest(), ContentDigest::sha256(&source));
            let expected = values
                .iter()
                .map(|&x| {
                    let square = x * x;
                    if exponent == 2. { square } else { square * x }
                })
                .collect::<Vec<_>>();
            assert_eq!(
                bits(&roundtrip(&source, &[("input", data(&[3, 4], &values)?)])?["output"]),
                bits(&expected)
            );
        }
    }
    // A source control can simultaneously be runtime data. Retain that binding
    // and avoid colliding with a source name resembling the cubic helper.
    let source = model(
        &[
            weight("exponent", &[], &[3.]),
            node("Pow", &["input", "exponent"], &["output"], &[]),
            node(
                "Identity",
                &["exponent"],
                &["onnx-node-0000-pow-square"],
                &[],
            ),
            bytes(11, &info("input", &[], 1)),
            bytes(12, &info("output", &[], 1)),
            bytes(12, &info("onnx-node-0000-pow-square", &[], 1)),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    assert_eq!(imported.parameters().len(), 1);
    assert_eq!(
        imported.graph().nodes()[0].outputs(),
        ["onnx-node-0000-pow-square-1"]
    );
    let output = roundtrip(&source, &[("input", data(&[], &[-2.])?)])?;
    assert_eq!(output["output"], [-8.]);
    assert_eq!(output["onnx-node-0000-pow-square"], [3.]);
    Ok(())
}

#[test]
fn power_refuses_runtime_exponents_other_numbers_dtypes_and_shapes() {
    for exponent in [
        -3.,
        -2.,
        -1.,
        -0.,
        0.,
        1.,
        2.5,
        4.,
        2.0_f32.next_up(),
        3.0_f32.next_down(),
    ] {
        assert_eq!(
            refusal(&power(&[2], &[], exponent, false)),
            Some(OnnxError::Unsupported)
        );
    }
    for exponent in [f32::INFINITY, f32::NEG_INFINITY, f32::NAN] {
        assert_eq!(
            refusal(&power(&[2], &[], exponent, false)),
            Some(OnnxError::NonFinite)
        );
    }
    for shape in [&[1][..], &[1, 1][..]] {
        assert_eq!(
            refusal(&power(&[2], shape, 2., false)),
            Some(OnnxError::Unsupported)
        );
    }
    let runtime = model(
        &[
            node("Pow", &["input", "exponent"], &["output"], &[]),
            bytes(11, &info("input", &[2], 1)),
            bytes(11, &info("exponent", &[], 1)),
            bytes(12, &info("output", &[2], 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&runtime), Some(OnnxError::Unsupported));
    let computed = model(
        &[
            weight("literal", &[], &[2.]),
            node("Identity", &["literal"], &["exponent"], &[]),
            node("Pow", &["input", "exponent"], &["output"], &[]),
            bytes(11, &info("input", &[2], 1)),
            bytes(12, &info("output", &[2], 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&computed), Some(OnnxError::Unsupported));
    let integer = model(
        &[
            bytes(5, &tensor("exponent", &[], 7, &2_i64.to_le_bytes())),
            node("Pow", &["input", "exponent"], &["output"], &[]),
            bytes(11, &info("input", &[2], 1)),
            bytes(12, &info("output", &[2], 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&integer), Some(OnnxError::Unsupported));
}

#[test]
fn new_imports_enforce_exact_arity_shapes_and_attribute_contracts() {
    for op in ["Sqrt", "Erf"] {
        assert_eq!(refusal(&unary(op, &[2], &[3], &[])), Some(OnnxError::Graph));
        assert_eq!(
            refusal(&unary(op, &[2], &[2], &int_attr("axis", 0))),
            Some(OnnxError::Unsupported)
        );
        for inputs in [vec![], vec!["input", "input"]] {
            let source = model(
                &[
                    node(op, &inputs, &["output"], &[]),
                    bytes(11, &info("input", &[2], 1)),
                    bytes(12, &info("output", &[2], 1)),
                ]
                .concat(),
            );
            assert!(
                refusal(&source).is_some(),
                "operator={op} inputs={inputs:?}"
            );
        }
        let integer = model(
            &[
                bytes(5, &tensor("input", &[], 7, &2_i64.to_le_bytes())),
                node(op, &["input"], &["output"], &[]),
                bytes(12, &info("output", &[], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&integer), Some(OnnxError::Unsupported));
    }
    for (inputs, output, attrs) in [
        (vec!["input"], vec![2], vec![]),
        (vec!["input", "exponent", "input"], vec![2], vec![]),
        (vec!["input", "exponent"], vec![3], vec![]),
        (vec!["input", "exponent"], vec![2], int_attr("broadcast", 1)),
    ] {
        let source = model(
            &[
                weight("exponent", &[], &[2.]),
                node("Pow", &inputs, &["output"], &attrs),
                bytes(11, &info("input", &[2], 1)),
                bytes(12, &info("output", &output, 1)),
            ]
            .concat(),
        );
        assert!(refusal(&source).is_some());
    }
}

#[test]
fn generated_power_resources_and_cumulative_import_cancellation_are_bounded() -> Test {
    let source = power(&[2], &[], 3., false);
    let run = |limits, cancelled: &dyn Fn() -> bool| {
        import_onnx(
            &source,
            ContentDigest::sha256(&source),
            GENERATION,
            limits,
            cancelled,
        )
    };
    for limits in [
        OnnxLimits {
            nodes: 1,
            ..OnnxLimits::default()
        },
        OnnxLimits {
            tensors: 3,
            ..OnnxLimits::default()
        },
        OnnxLimits {
            parameter_bytes: 3,
            ..OnnxLimits::default()
        },
        OnnxLimits {
            tensor_bytes: 7,
            ..OnnxLimits::default()
        },
    ] {
        assert_eq!(run(limits, &|| false).err(), Some(OnnxError::Limit));
    }
    let exact = run(
        OnnxLimits {
            nodes: 2,
            tensors: 4,
            parameter_bytes: 4,
            tensor_bytes: 8,
            ..OnnxLimits::default()
        },
        &|| false,
    )?;
    assert_eq!(exact.graph().node_count(), 2);
    for source in [
        source,
        layer_norm(&[2, 4], 1e-5_f32, &[1.; 4], &[0.; 4]),
        gelu(&[2, 4], true),
    ] {
        let checks = Cell::new(0_usize);
        let count = || {
            checks.set(checks.get() + 1);
            false
        };
        let imported = import_onnx(
            &source,
            ContentDigest::sha256(&source),
            GENERATION,
            OnnxLimits::default(),
            &count,
        )?;
        let total = checks.get();
        let work = imported.work_units();
        assert_eq!(
            import_onnx(
                &source,
                ContentDigest::sha256(&source),
                GENERATION,
                OnnxLimits {
                    work_units: work - 1,
                    ..OnnxLimits::default()
                },
                &|| false
            )
            .err(),
            Some(OnnxError::WorkBudget)
        );
        assert!(
            import_onnx(
                &source,
                ContentDigest::sha256(&source),
                GENERATION,
                OnnxLimits {
                    work_units: work,
                    ..OnnxLimits::default()
                },
                &|| false
            )
            .is_ok()
        );
        for stop in [1, total / 2, total] {
            let checks = Cell::new(0_usize);
            let cancelled = || {
                checks.set(checks.get() + 1);
                checks.get() >= stop
            };
            assert_eq!(
                import_onnx(
                    &source,
                    ContentDigest::sha256(&source),
                    GENERATION,
                    OnnxLimits::default(),
                    &cancelled
                )
                .err(),
                Some(OnnxError::Cancelled)
            );
        }
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
        let artifacts = export(&imported)?;
        assert_eq!(artifacts.source(), source);
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
            Some(OnnxError::WorkBudget)
        );
        assert_eq!(
            export_onnx_artifacts(&imported, OnnxExportLimits::default(), &|| true).err(),
            Some(OnnxError::Cancelled)
        );
    }
    Ok(())
}

#[test]
fn composed_v2_execution_preserves_finite_budgets_generations_and_cancellation() -> Test {
    for source in [
        layer_norm(&[2, 4], 1e-5_f32, &[1.; 4], &[0.; 4]),
        gelu(&[2, 4], true),
    ] {
        let imported = import(&source)?;
        let input = [(
            "input",
            data(&[2, 4], &[-4., -3., -2., -1., 0., 1., 2., 3.])?,
        )];
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
        bindings.insert("input".into(), input[0].1.clone());
        let bindings = bindings.into_iter().collect::<Vec<_>>();
        let result = ScalarExecutor::run(
            imported.graph(),
            &bindings,
            ExecBudget::unlimited(),
            &ScalarExecCx::new(),
        )?;
        let exact = ExecBudget::new(result.executed_macs(), result.allocated_bytes());
        assert!(
            ScalarExecutor::run(imported.graph(), &bindings, exact, &ScalarExecCx::new()).is_ok()
        );
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
        let stale = Tensor::from_values(
            Shape::new(vec![2, 4])?,
            &[1.0_f32; 8],
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
    }
    Ok(())
}
