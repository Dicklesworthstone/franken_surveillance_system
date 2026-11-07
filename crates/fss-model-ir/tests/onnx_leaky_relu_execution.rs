#![forbid(unsafe_code)]
//! Exact admitted ONNX LeakyRelu through real artifact parsing and both production
//! CPU executors. Expected bits come from the source operator branch, independent
//! of the native graph lowering; no epsilon or reduced finite input range is used.

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
fn leaky_model(dims: &[usize], output: &[usize], attrs: &[u8]) -> Vec<u8> {
    model(
        &[
            node("LeakyRelu", &["input"], &["output"], attrs),
            bytes(11, &info("input", dims, 1)),
            bytes(12, &info("output", output, 1)),
        ]
        .concat(),
    )
}
fn oracle(input: &[f32], alpha: f32) -> Vec<f32> {
    input
        .iter()
        .map(|&x| if x < 0.0 { alpha * x } else { x })
        .collect()
}

#[test]
fn default_and_explicit_alpha_preserve_every_admitted_rank() -> Test {
    for rank in 0..=8 {
        let dims = vec![2; rank];
        let special = [-0.0_f32, 0.0, -3.5, 2.0, -f32::from_bits(1), f32::MAX];
        let values = (0..dims.iter().product())
            .map(|index| special[index % special.len()])
            .collect::<Vec<_>>();
        for alpha in [None, Some(0.1_f32), Some(0.5), Some(1.0)] {
            let attrs = alpha.map_or_else(Vec::new, |value| float_attr("alpha", value));
            let source = leaky_model(&dims, &dims, &attrs);
            let result = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
            assert_eq!(
                bits(&result["output"]),
                bits(&oracle(&values, alpha.unwrap_or(0.01)))
            );
            assert_eq!(import(&source)?.graph().outputs()[0].shape().dims(), &dims);
        }
    }
    Ok(())
}

#[test]
fn all_finite_exponents_and_rounding_boundaries_match_exact_source_semantics() -> Test {
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
    for alpha in [
        0.0_f32,
        -0.0,
        f32::from_bits(1),
        f32::MIN_POSITIVE,
        0.01,
        0.1,
        0.5,
        f32::from_bits(1.0_f32.to_bits() - 1),
        1.0,
    ] {
        let source = leaky_model(
            &[values.len()],
            &[values.len()],
            &float_attr("alpha", alpha),
        );
        let result = roundtrip(&source, &[("input", data(&[values.len()], &values)?)])?;
        assert_eq!(
            bits(&result["output"]),
            bits(&oracle(&values, alpha)),
            "alpha={alpha:?}"
        );
    }
    Ok(())
}

#[test]
fn signed_zero_parameters_and_input_ties_survive_export() -> Test {
    let values = [
        -0.0_f32,
        0.0,
        -f32::from_bits(1),
        f32::from_bits(1),
        -1.0,
        1.0,
    ];
    let mut digests = Vec::new();
    for alpha in [0.0_f32, -0.0] {
        let source = leaky_model(&[6], &[6], &float_attr("alpha", alpha));
        let imported = import(&source)?;
        let parameter = imported
            .parameters()
            .values()
            .next()
            .ok_or("alpha parameter")?;
        assert_eq!(parameter.to_vec::<f32>()?[0].to_bits(), alpha.to_bits());
        digests.push(export(&imported)?.weights_digest());
        let result = roundtrip(&source, &[("input", data(&[6], &values)?)])?;
        assert_eq!(bits(&result["output"]), bits(&oracle(&values, alpha)));
        assert_eq!(result["output"][0].to_bits(), (-0.0_f32).to_bits());
        assert_eq!(result["output"][1].to_bits(), 0.0_f32.to_bits());
    }
    assert_ne!(digests[0], digests[1]);
    Ok(())
}

#[test]
fn conv_leaky_flatten_gemm_chain_and_branch_outputs_are_exact() -> Test {
    let source = model(
        &[
            node(
                "Conv",
                &["input", "conv-weight", "conv-bias"],
                &["raw"],
                &ints_attr("kernel_shape", &[1, 1]),
            ),
            node(
                "LeakyRelu",
                &["raw"],
                &["activated"],
                &float_attr("alpha", 0.25),
            ),
            node("Flatten", &["activated"], &["flat"], &[]),
            node(
                "Gemm",
                &["flat", "gemm-weight", "gemm-bias"],
                &["projection"],
                &[],
            ),
            node("LeakyRelu", &["projection"], &["output"], &[]),
            weight("conv-weight", &[1, 1, 1, 1], &[2.0]),
            weight("conv-bias", &[1], &[1.0]),
            weight(
                "gemm-weight",
                &[4, 2],
                &[1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 1.0],
            ),
            weight("gemm-bias", &[2], &[-1.25, -4.5]),
            bytes(11, &info("input", &[1, 1, 2, 2], 1)),
            bytes(12, &info("raw", &[1, 1, 2, 2], 1)),
            bytes(12, &info("output", &[1, 2], 1)),
        ]
        .concat(),
    );
    let result = roundtrip(
        &source,
        &[("input", data(&[1, 1, 2, 2], &[1., -2., 3., -4.])?)],
    )?;
    assert_eq!(bits(&result["raw"]), bits(&[3., -3., 7., -7.]));
    assert_eq!(bits(&result["output"]), bits(&[6.25, -0.0625]));
    Ok(())
}

#[test]
fn initializer_inputs_and_future_source_name_collisions_remain_well_scoped() -> Test {
    let values = [-0.0_f32, -7., 5., -f32::from_bits(1)];
    let source = model(
        &[
            node(
                "LeakyRelu",
                &["constant"],
                &["output"],
                &float_attr("alpha", 0.5),
            ),
            weight("constant", &[4], &values),
            bytes(12, &info("output", &[4], 1)),
        ]
        .concat(),
    );
    assert_eq!(
        bits(&roundtrip(&source, &[])?["output"]),
        bits(&oracle(&values, 0.5))
    );
    for suffix in ["alpha", "flat", "scaled", "stacked", "selected"] {
        let collision = format!("onnx-node-0000-leaky-{suffix}");
        let source = model(
            &[
                node("LeakyRelu", &["input"], &["output"], &[]),
                node("Identity", &["input"], &[&collision], &[]),
                bytes(11, &info("input", &[4], 1)),
                bytes(12, &info("output", &[4], 1)),
                bytes(12, &info(&collision, &[4], 1)),
            ]
            .concat(),
        );
        let result = roundtrip(&source, &[("input", data(&[4], &values)?)])?;
        assert_eq!(bits(&result["output"]), bits(&oracle(&values, 0.01)));
        assert_eq!(bits(&result[&collision]), bits(&values));
        let forward = model(
            &[
                node("LeakyRelu", &[&collision], &["output"], &[]),
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
fn unsupported_slopes_attributes_arity_and_output_shapes_refuse() {
    for alpha in [
        -f32::from_bits(1),
        -0.1,
        -1.0,
        f32::from_bits(1.0_f32.to_bits() + 1),
        f32::MAX,
    ] {
        assert_eq!(
            refusal(&leaky_model(&[2], &[2], &float_attr("alpha", alpha))),
            Some(OnnxError::Unsupported)
        );
    }
    for alpha in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        assert_eq!(
            refusal(&leaky_model(&[2], &[2], &float_attr("alpha", alpha))),
            Some(OnnxError::NonFinite)
        );
    }
    for attrs in [
        int_attr("alpha", 1),
        text_attr("alpha", "0.1"),
        ints_attr("alpha", &[1]),
    ] {
        assert_eq!(
            refusal(&leaky_model(&[2], &[2], &attrs)),
            Some(OnnxError::Graph)
        );
    }
    assert_eq!(
        refusal(&leaky_model(&[2], &[2], &float_attr("beta", 0.1))),
        Some(OnnxError::Unsupported)
    );
    assert_eq!(
        refusal(&leaky_model(
            &[2],
            &[2],
            &[float_attr("alpha", 0.1), float_attr("alpha", 0.2)].concat()
        )),
        Some(OnnxError::Malformed)
    );
    for (inputs, expected) in [
        (vec![], OnnxError::Graph),
        // Required inputs cannot use the wire-level optional-input spelling.
        // The shared source parser rejects this before operator admission.
        (vec![""], OnnxError::Limit),
        (vec!["input", "input"], OnnxError::Graph),
    ] {
        let source = model(
            &[
                node("LeakyRelu", &inputs, &["output"], &[]),
                bytes(11, &info("input", &[2], 1)),
                bytes(12, &info("output", &[2], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(expected));
    }
    assert_eq!(
        refusal(&leaky_model(&[2], &[3], &[])),
        Some(OnnxError::Graph)
    );
}

#[test]
fn exact_aggregate_limits_and_identity_shortcut_are_enforced() -> Test {
    let source = leaky_model(&[8], &[8], &[]);
    let imported = import(&source)?;
    assert_eq!(imported.graph().node_count(), 5);
    assert_eq!(imported.parameters().len(), 1);
    let limits = OnnxLimits {
        nodes: 5,
        tensors: 7,
        parameter_bytes: 4,
        tensor_bytes: 64,
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
    for limits in [
        OnnxLimits { nodes: 4, ..limits },
        OnnxLimits {
            tensors: 6,
            ..limits
        },
        OnnxLimits {
            parameter_bytes: 3,
            ..limits
        },
        OnnxLimits {
            tensor_bytes: 63,
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
    let identity = leaky_model(&[8], &[8], &float_attr("alpha", 1.0));
    let imported = import_onnx(
        &identity,
        ContentDigest::sha256(&identity),
        GENERATION,
        OnnxLimits {
            nodes: 1,
            tensors: 2,
            parameter_bytes: 0,
            tensor_bytes: 32,
            ..OnnxLimits::default()
        },
        &|| false,
    )?;
    assert_eq!(imported.graph().node_count(), 1);
    assert!(imported.parameters().is_empty());
    Ok(())
}

#[test]
fn cumulative_work_cancellation_and_source_digest_fail_closed() -> Test {
    let source = leaky_model(&[8], &[8], &[]);
    let imported = import(&source)?;
    let limits = OnnxLimits {
        work_units: imported.work_units() - 1,
        ..OnnxLimits::default()
    };
    assert_eq!(
        import_onnx(
            &source,
            ContentDigest::sha256(&source),
            GENERATION,
            limits,
            &|| false
        )
        .err(),
        Some(OnnxError::WorkBudget)
    );
    assert_eq!(
        import_onnx(
            &source,
            ContentDigest::sha256(b"wrong-source"),
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
fn both_executors_enforce_work_allocation_and_cancellation_without_outputs() -> Test {
    let source = leaky_model(&[8], &[8], &[]);
    let imported = import(&source)?;
    let input = [("input", data(&[8], &[-1., 2., -3., 4., -5., 6., -7., 8.])?)];
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
    let scalar_cx = ScalarExecCx::new();
    scalar_cx.request_cancellation();
    assert!(matches!(
        ScalarExecutor::run(
            imported.graph(),
            &bindings,
            ExecBudget::unlimited(),
            &scalar_cx
        ),
        Err(ExecError::CancellationRequested { .. })
    ));
    assert!(scalar_cx.is_drain_completed());
    let optimized_cx = ScalarExecCx::new();
    optimized_cx.request_cancellation();
    assert!(matches!(
        optimized.run(&input, ExecBudget::unlimited(), &optimized_cx),
        Err(ExecError::CancellationRequested { .. })
    ));
    assert!(optimized_cx.is_drain_completed());
    Ok(())
}
