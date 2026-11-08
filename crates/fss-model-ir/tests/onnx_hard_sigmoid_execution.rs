#![forbid(unsafe_code)]
//! Exact finite-input ONNX HardSigmoid-6 semantics through real canonical
//! artifacts, Safetensors and both production CPU executors. Expected values use
//! source-ordered F32 multiply, then add, then scalar comparison/clamp branches;
//! the oracle neither shares the lowering nor approximates overflowing inputs.

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

fn hard_model(dims: &[usize], output: &[usize], attrs: &[u8]) -> Vec<u8> {
    model(
        &[
            node("HardSigmoid", &["input"], &["output"], attrs),
            bytes(11, &info("input", dims, 1)),
            bytes(12, &info("output", output, 1)),
        ]
        .concat(),
    )
}

fn coefficients(alpha: Option<f32>, beta: Option<f32>) -> Vec<u8> {
    let mut attrs = Vec::new();
    if let Some(value) = alpha {
        attrs.extend(float_attr("alpha", value));
    }
    if let Some(value) = beta {
        attrs.extend(float_attr("beta", value));
    }
    attrs
}

fn oracle(input: &[f32], alpha: f32, beta: f32) -> Vec<f32> {
    input
        .iter()
        .map(|&x| {
            let product = alpha * x;
            let affine = product + beta;
            let lower = if affine > 0.0 { affine } else { 0.0 };
            if lower < 1.0 { lower } else { 1.0 }
        })
        .collect()
}

#[test]
fn defaults_and_independent_attributes_preserve_every_admitted_rank() -> Test {
    for rank in 0..=8 {
        let dims = vec![2; rank];
        let special = [-f32::MAX, -3.0_f32, -0.0, 0.0, 0.25, 2.5, 3.0, f32::MAX];
        let values = (0..dims.iter().product::<usize>())
            .map(|index| special[index % special.len()])
            .collect::<Vec<_>>();
        for (alpha, beta) in [
            (None, None),
            (Some(0.25_f32), None),
            (None, Some(0.25)),
            (Some(-0.25), Some(0.75)),
            (Some(0.0), Some(0.3)),
        ] {
            let source = hard_model(&dims, &dims, &coefficients(alpha, beta));
            let result = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
            assert_eq!(
                bits(&result["output"]),
                bits(&oracle(&values, alpha.unwrap_or(0.2), beta.unwrap_or(0.5)))
            );
            assert_eq!(import(&source)?.graph().outputs()[0].shape().dims(), &dims);
        }
    }
    Ok(())
}

#[test]
fn full_finite_exponents_negative_slopes_and_large_offsets_remain_exact() -> Test {
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
    for (alpha, beta) in [
        (0.2_f32, 0.5_f32),
        (1.0 / 6.0, 0.5),
        (-1.0 / 6.0, 0.5),
        (1.0, 0.5),
        (-1.0, -0.0),
        (0.0, f32::MAX),
        (-0.0, -f32::MAX),
        (f32::from_bits(1), 0.5),
        (f32::MIN_POSITIVE, -f32::MIN_POSITIVE),
        (0.5, f32::MAX * 0.25),
        (-0.5, -f32::MAX * 0.25),
    ] {
        let source = hard_model(
            &[values.len()],
            &[values.len()],
            &coefficients(Some(alpha), Some(beta)),
        );
        let result = roundtrip(&source, &[("input", data(&[values.len()], &values)?)])?;
        assert_eq!(
            bits(&result["output"]),
            bits(&oracle(&values, alpha, beta)),
            "alpha={alpha:?}, beta={beta:?}"
        );
        assert!(result["output"].iter().all(|x| (0.0..=1.0).contains(x)));
    }
    Ok(())
}

#[test]
fn multiply_then_add_rounding_is_not_replaced_by_a_fused_affine() -> Test {
    // The exact source bits make separate rounded multiply/add produce 2^-25.
    // A single-rounding affine result would instead have bits 0x332c_cccd.
    let values = [f32::from_bits(0xc01f_ffff), -2.5_f32, 2.5];
    let source = hard_model(&[3], &[3], &[]);
    let result = roundtrip(&source, &[("input", data(&[3], &values)?)])?;
    assert_eq!(result["output"][0].to_bits(), 0x3300_0000);
    assert_eq!(bits(&result["output"]), bits(&oracle(&values, 0.2, 0.5)));
    assert_eq!(bits(&result["output"][1..]), bits(&[0.0, 1.0]));
    Ok(())
}

#[test]
fn signed_zero_coefficients_are_retained_while_clamp_ties_choose_positive_zero() -> Test {
    let values = [
        -f32::MAX,
        -f32::from_bits(1),
        -0.0_f32,
        0.0,
        f32::from_bits(1),
        f32::MAX,
    ];
    let mut weight_digests = Vec::new();
    for alpha in [-0.0_f32, 0.0] {
        for beta in [-0.0_f32, 0.0] {
            let source = hard_model(&[6], &[6], &coefficients(Some(alpha), Some(beta)));
            let result = roundtrip(&source, &[("input", data(&[6], &values)?)])?;
            assert_eq!(bits(&result["output"]), vec![0_u32; 6]);
            weight_digests.push(export(&import(&source)?)?.weights_digest());
        }
    }
    for (index, digest) in weight_digests.iter().enumerate() {
        assert!(!weight_digests[..index].contains(digest));
    }
    let implicit = hard_model(&[6], &[6], &[]);
    let explicit = hard_model(&[6], &[6], &coefficients(Some(0.2), Some(0.5)));
    let implicit = import(&implicit)?;
    let explicit = import(&explicit)?;
    assert_eq!(
        encode_canonical_model_ir(implicit.graph())?,
        encode_canonical_model_ir(explicit.graph())?
    );
    let implicit = export(&implicit)?;
    let explicit = export(&explicit)?;
    // The numerical defaults agree, while each artifact still binds its exact
    // source bytes through the Safetensors source_sha256 metadata.
    assert_ne!(implicit.source_digest(), explicit.source_digest());
    assert_ne!(implicit.weights_digest(), explicit.weights_digest());
    let implicit = reloaded(&implicit)?;
    let explicit = reloaded(&explicit)?;
    assert_eq!(
        implicit.keys().collect::<Vec<_>>(),
        explicit.keys().collect::<Vec<_>>()
    );
    for (name, value) in &implicit {
        let other = explicit
            .get(name)
            .ok_or("missing explicit-default parameter")?;
        assert_eq!(value.shape(), other.shape(), "parameter shape {name}");
        assert_eq!(
            bits(&value.to_vec::<f32>()?),
            bits(&other.to_vec::<f32>()?),
            "parameter bits {name}"
        );
    }
    Ok(())
}

#[test]
fn exported_hardswish_composition_executes_without_admitting_newer_opsets() -> Test {
    let values = [
        -f32::MAX,
        -4.0_f32,
        -3.0,
        -2.0,
        -0.0,
        0.0,
        2.0,
        3.0,
        4.0,
        f32::MAX,
    ];
    let alpha = 1.0_f32 / 6.0;
    let source = model(
        &[
            node(
                "HardSigmoid",
                &["input"],
                &["gate"],
                &coefficients(Some(alpha), Some(0.5)),
            ),
            node("Mul", &["input", "gate"], &["output"], &[]),
            bytes(11, &info("input", &[10], 1)),
            bytes(12, &info("gate", &[10], 1)),
            bytes(12, &info("output", &[10], 1)),
        ]
        .concat(),
    );
    let result = roundtrip(&source, &[("input", data(&[10], &values)?)])?;
    let gate = oracle(&values, alpha, 0.5);
    let expected = values
        .iter()
        .zip(&gate)
        .map(|(x, gate)| x * gate)
        .collect::<Vec<_>>();
    assert_eq!(bits(&result["gate"]), bits(&gate));
    assert_eq!(bits(&result["output"]), bits(&expected));
    assert_eq!(result["output"][0].to_bits(), (-0.0_f32).to_bits());
    assert_eq!(result["output"][9].to_bits(), f32::MAX.to_bits());

    let newer_operator = model(
        &[
            node("HardSwish", &["input"], &["output"], &[]),
            bytes(11, &info("input", &[10], 1)),
            bytes(12, &info("output", &[10], 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&newer_operator), Some(OnnxError::Unsupported));
    Ok(())
}

#[test]
fn conv_gated_activation_flatten_dense_chain_is_complete() -> Test {
    let source = model(
        &[
            node(
                "Conv",
                &["input", "conv-weight", "conv-bias"],
                &["raw"],
                &ints_attr("kernel_shape", &[1, 1]),
            ),
            node(
                "HardSigmoid",
                &["raw"],
                &["gate"],
                &coefficients(Some(0.25), Some(0.5)),
            ),
            node("Mul", &["raw", "gate"], &["activated"], &[]),
            node("Flatten", &["activated"], &["flat"], &[]),
            node(
                "Gemm",
                &["flat", "dense-weight", "dense-bias"],
                &["output"],
                &[],
            ),
            weight("conv-weight", &[1, 1, 1, 1], &[2.0]),
            weight("conv-bias", &[1], &[0.0]),
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
        &[("input", data(&[1, 1, 2, 2], &[-2., -1., 0., 1.])?)],
    )?;
    assert_eq!(bits(&result["raw"]), bits(&[-4., -2., 0., 2.]));
    assert_eq!(bits(&result["activated"]), bits(&[-0.0, -0.0, 0.0, 2.0]));
    assert_eq!(bits(&result["output"]), bits(&[7., -3.75]));
    Ok(())
}

#[test]
fn initializer_inputs_and_all_generated_value_name_collisions_are_isolated() -> Test {
    let values = [-3.0_f32, -0.0, 0.0, 7.0];
    let source = model(
        &[
            node("HardSigmoid", &["input"], &["output"], &[]),
            weight("input", &[4], &values),
            bytes(12, &info("output", &[4], 1)),
        ]
        .concat(),
    );
    assert_eq!(
        bits(&roundtrip(&source, &[])?["output"]),
        bits(&oracle(&values, 0.2, 0.5))
    );

    let baseline = hard_model(&[4], &[4], &[]);
    let imported = import(&baseline)?;
    let names = imported
        .graph()
        .nodes()
        .iter()
        .flat_map(|node| node.outputs().iter())
        .chain(imported.parameters().keys())
        .filter(|name| !["input", "output"].contains(&name.as_str()))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    assert!(!names.is_empty());
    for collision in names {
        let source = model(
            &[
                node("HardSigmoid", &["input"], &["output"], &[]),
                node("Identity", &["input"], &[&collision], &[]),
                bytes(11, &info("input", &[4], 1)),
                bytes(12, &info("output", &[4], 1)),
                bytes(12, &info(&collision, &[4], 1)),
            ]
            .concat(),
        );
        let result = roundtrip(&source, &[("input", data(&[4], &values)?)])?;
        assert_eq!(bits(&result["output"]), bits(&oracle(&values, 0.2, 0.5)));
        assert_eq!(bits(&result[&collision]), bits(&values));
        let forward = model(
            &[
                node("HardSigmoid", &[&collision], &["output"], &[]),
                node("Identity", &["input"], &[&collision], &[]),
                bytes(11, &info("input", &[4], 1)),
                bytes(12, &info("output", &[4], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&forward), Some(OnnxError::Graph));
    }
    Ok(())
}

#[test]
fn full_finite_safety_envelope_is_checked_before_execution() -> Test {
    for (alpha, beta) in [
        (2.0_f32, 0.0_f32),
        (-2.0, 0.0),
        (f32::from_bits(1.0_f32.to_bits() + 1), 0.0),
        (1.0, f32::MAX),
        (0.5, f32::MAX),
        (f32::MAX, 0.0),
        (1.0, f32::from_bits(0x7300_0000)),
    ] {
        let source = hard_model(&[1], &[1], &coefficients(Some(alpha), Some(beta)));
        assert_eq!(
            refusal(&source),
            Some(OnnxError::Unsupported),
            "alpha={alpha:?}, beta={beta:?}"
        );
    }
    // Just below the overflow-rounding threshold, the worst affine still rounds
    // to finite MAX; refusing every positive beta with alpha=1 is too strict.
    let beta = f32::from_bits(0x72ff_ffff);
    let source = hard_model(&[2], &[2], &coefficients(Some(1.0), Some(beta)));
    let values = [-f32::MAX, f32::MAX];
    let result = roundtrip(&source, &[("input", data(&[2], &values)?)])?;
    assert_eq!(bits(&result["output"]), bits(&[0.0, 1.0]));
    Ok(())
}

#[test]
fn nonfinite_wrong_attributes_bad_arity_and_shape_mismatch_refuse() {
    for key in ["alpha", "beta"] {
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            assert_eq!(
                refusal(&hard_model(&[2], &[2], &float_attr(key, value))),
                Some(OnnxError::NonFinite)
            );
        }
        for attrs in [
            int_attr(key, 1),
            text_attr(key, "0.2"),
            ints_attr(key, &[1]),
        ] {
            assert_eq!(
                refusal(&hard_model(&[2], &[2], &attrs)),
                Some(OnnxError::Graph)
            );
        }
        assert_eq!(
            refusal(&hard_model(
                &[2],
                &[2],
                &[float_attr(key, 0.2), float_attr(key, 0.3)].concat()
            )),
            Some(OnnxError::Malformed)
        );
    }
    assert_eq!(
        refusal(&hard_model(&[2], &[2], &float_attr("gamma", 0.2))),
        Some(OnnxError::Unsupported)
    );
    for inputs in [vec![], vec![""], vec!["input", "input"]] {
        let source = model(
            &[
                node("HardSigmoid", &inputs, &["output"], &[]),
                bytes(11, &info("input", &[2], 1)),
                bytes(12, &info("output", &[2], 1)),
            ]
            .concat(),
        );
        assert!(refusal(&source).is_some());
    }
    assert_eq!(
        refusal(&hard_model(&[2], &[3], &[])),
        Some(OnnxError::Graph)
    );
    assert!(refusal(&hard_model(&[0], &[0], &[])).is_some());
    assert!(refusal(&hard_model(&[1; 9], &[1; 9], &[])).is_some());
}

#[test]
fn helpers_reserve_fixed_graph_weights_and_exact_tensor_bounds() -> Test {
    for elements in [8_usize, 4096] {
        let source = hard_model(&[elements], &[elements], &[]);
        let imported = import(&source)?;
        assert_eq!(imported.graph().node_count(), 15);
        assert_eq!(imported.parameters().len(), 5);
        for tensor in imported.parameters().values() {
            assert_eq!(tensor.shape().rank(), 0);
            assert_eq!(tensor.to_vec::<f32>()?.len(), 1);
        }
        let limits = OnnxLimits {
            source_bytes: source.len(),
            nodes: 15,
            tensors: 21,
            parameter_bytes: 20,
            tensor_bytes: elements * 8,
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
        for limits in [
            OnnxLimits {
                source_bytes: source.len() - 1,
                ..limits
            },
            OnnxLimits {
                nodes: 14,
                ..limits
            },
            OnnxLimits {
                tensors: 20,
                ..limits
            },
            OnnxLimits {
                parameter_bytes: 19,
                ..limits
            },
            OnnxLimits {
                tensor_bytes: elements * 8 - 1,
                ..limits
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
    }
    Ok(())
}

#[test]
fn import_work_source_digest_and_every_cancellation_checkpoint_are_enforced() -> Test {
    let source = hard_model(&[8], &[8], &[]);
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
fn scalar_and_optimized_execution_enforce_exact_budget_and_quiescence() -> Test {
    let source = hard_model(&[8], &[8], &[]);
    let imported = import(&source)?;
    let input = [(
        "input",
        data(
            &[8],
            &[-f32::MAX, -2.5, -1.0, -0.0, 0.0, 1.0, 2.5, f32::MAX],
        )?,
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
