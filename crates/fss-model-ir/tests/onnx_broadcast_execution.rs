#![forbid(unsafe_code)]
//! Static ONNX Expand/Tile through real artifact parsing and both unchanged
//! production CPU executors. Coordinate oracles use the source layout rules,
//! independently of the lowering, with exact F32 bits through canonical reload.

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
const GENERATION: Generation = Generation(47);

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
fn data(dimensions: &[usize], values: &[f32]) -> Test<Tensor> {
    Ok(Tensor::from_values(
        Shape::new(dimensions.to_vec())?,
        values,
        GENERATION,
    )?)
}
fn repeat_model(op: &str, dims: &[usize], control: &[i64], output: &[usize]) -> Vec<u8> {
    model(
        &[
            node(op, &["input", "control"], &["output"], &[]),
            int_weight("control", &[control.len()], control),
            bytes(11, &info("input", dims, 1)),
            bytes(12, &info("output", output, 1)),
        ]
        .concat(),
    )
}
// Derive source coordinates from the declared output. Broadcasting repeats a
// singleton coordinate; tiling wraps each source axis at its original length.
// This is independent of the lowering's Concat ordering and binary factors.
fn coordinate_oracle(values: &[f32], input: &[usize], output: &[usize]) -> Vec<f32> {
    let offset = output.len() - input.len();
    (0..output.iter().product())
        .map(|mut flat| {
            let mut source = 0;
            let mut stride = 1;
            for axis in (0..output.len()).rev() {
                let coordinate = flat % output[axis];
                flat /= output[axis];
                if axis >= offset {
                    let dimension = input[axis - offset];
                    source += coordinate % dimension * stride;
                    stride *= dimension;
                }
            }
            values[source]
        })
        .collect()
}
fn check(op: &str, input: &[usize], control: &[i64], output: &[usize], values: &[f32]) -> Test {
    let source = repeat_model(op, input, control, output);
    let imported = import(&source)?;
    assert_eq!(imported.graph().outputs()[0].shape().dims(), output);
    assert_eq!(imported.runtime_inputs(), &["input"]);
    assert!(imported.parameters().is_empty());
    let actual = roundtrip(&source, &[("input", data(input, values)?)])?;
    assert_eq!(
        bits(&actual["output"]),
        bits(&coordinate_oracle(values, input, output)),
        "{op} {input:?} {control:?}"
    );
    Ok(())
}

#[test]
fn broadcast_expand_uses_multidirectional_shapes_and_scalar_identity() -> Test {
    // The opset-13 example's target is deliberately not the output shape.
    check("Expand", &[3, 1], &[2, 1, 6], &[2, 3, 6], &[1., 2., 3.])?;
    check("Expand", &[2, 3], &[1], &[2, 3], &[0., -0., 2., 3., 4., 5.])?;
    check("Expand", &[2, 1], &[3], &[2, 3], &[2., -3.])?;
    check("Expand", &[3], &[], &[3], &[-0., 1., -2.])?;
    check("Expand", &[], &[], &[], &[-0.])?;
    check("Expand", &[], &[2, 3], &[2, 3], &[-f32::from_bits(1)])?;
    check("Expand", &[3], &[1, 3], &[1, 3], &[f32::MIN, -0., f32::MAX])?;
    check("Tile", &[], &[], &[], &[-0.])?;
    Ok(())
}

#[test]
fn broadcast_tile_repeats_complete_axis_blocks() -> Test {
    let source = repeat_model("Tile", &[2, 2], &[2, 3], &[4, 6]);
    let actual = roundtrip(&source, &[("input", data(&[2, 2], &[0., -0., 2., 3.])?)])?;
    assert_eq!(
        bits(&actual["output"]),
        bits(&[
            0., -0., 0., -0., 0., -0., 2., 3., 2., 3., 2., 3., 0., -0., 0., -0., 0., -0., 2., 3.,
            2., 3., 2., 3.,
        ])
    );
    Ok(())
}

#[test]
fn broadcast_every_admitted_rank_preserves_finite_boundary_bits() -> Test {
    let special = [
        -0.0_f32,
        0.0,
        -f32::from_bits(1),
        f32::from_bits(1),
        f32::MIN,
        f32::MAX,
        f32::MIN_POSITIVE,
        -1.25,
    ];
    for rank in 0..=8 {
        let input = (0..rank)
            .map(|axis| if axis % 2 == 0 { 1 } else { 2 })
            .collect::<Vec<_>>();
        let values = (0..input.iter().product())
            .map(|index| special[index % special.len()])
            .collect::<Vec<_>>();
        let target = input
            .iter()
            .map(|&dim| if dim == 1 { 3 } else { 1 })
            .collect::<Vec<_>>();
        let expanded = input
            .iter()
            .zip(&target)
            .map(|(&a, &b)| a.max(b))
            .collect::<Vec<_>>();
        let repeats = (0..rank)
            .map(|axis| if axis % 3 == 0 { 3 } else { 2 })
            .collect::<Vec<_>>();
        let tiled = input
            .iter()
            .zip(&repeats)
            .map(|(&a, &b)| a * b)
            .collect::<Vec<_>>();
        check(
            "Expand",
            &input,
            &target.iter().map(|&v| v as i64).collect::<Vec<_>>(),
            &expanded,
            &values,
        )?;
        check(
            "Tile",
            &input,
            &repeats.iter().map(|&v| v as i64).collect::<Vec<_>>(),
            &tiled,
            &values,
        )?;
    }
    Ok(())
}

#[test]
fn broadcast_binary_prefix_lowering_is_bounded_and_exact_for_odd_factors() -> Test {
    for factor in [1_usize, 2, 3, 5, 7, 13, 257, 1025] {
        for op in ["Expand", "Tile"] {
            check(op, &[1], &[factor as i64], &[factor], &[-0.])?;
            let source = repeat_model(op, &[1], &[factor as i64], &[factor]);
            let imported = import(&source)?;
            let expected_nodes =
                (factor.ilog2() as usize + factor.count_ones() as usize - 1).max(1);
            assert_eq!(imported.graph().node_count(), expected_nodes);
            assert!(
                imported
                    .graph()
                    .nodes()
                    .iter()
                    .all(|node| node.inputs().len() <= 2)
            );
        }
        check(
            "Tile",
            &[2, 1],
            &[1, factor as i64],
            &[2, factor],
            &[f32::MAX, f32::MIN],
        )?;
    }
    // Large logical outputs do not allocate expanded constants during import.
    // At the per-tensor ceiling, 24 binary helpers replace 2^24 input copies.
    for op in ["Expand", "Tile"] {
        let source = repeat_model(op, &[1], &[1 << 24], &[1 << 24]);
        let imported = import(&source)?;
        assert_eq!(imported.graph().node_count(), 24);
        assert!(imported.parameters().is_empty());
        assert_eq!(
            refusal(&repeat_model(op, &[1], &[(1 << 24) + 1], &[(1 << 24) + 1])),
            Some(OnnxError::Limit)
        );
    }
    Ok(())
}

#[test]
fn broadcast_static_shape_programs_and_anchor_tiles_feed_runtime_arithmetic() -> Test {
    let source = model(
        &[
            node("Shape", &["input"], &["shape"], &[]),
            node("Mul", &["shape", "repeats"], &["target"], &[]),
            node("Expand", &["input", "target"], &["expanded"], &[]),
            node("Tile", &["anchor", "repeats"], &["tiled"], &[]),
            node("Add", &["expanded", "tiled"], &["output"], &[]),
            int_weight("repeats", &[3], &[1, 2, 1]),
            weight("anchor", &[1, 1, 3], &[10., 20., 30.]),
            bytes(11, &info("input", &[1, 1, 3], 1)),
            bytes(12, &info("expanded", &[1, 2, 3], 1)),
            bytes(12, &info("tiled", &[1, 2, 3], 1)),
            bytes(12, &info("output", &[1, 2, 3], 1)),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    assert_eq!(
        imported
            .parameters()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["anchor"]
    );
    assert_eq!(imported.runtime_inputs(), &["input"]);
    let actual = roundtrip(&source, &[("input", data(&[1, 1, 3], &[1., -2., 3.])?)])?;
    assert_eq!(bits(&actual["expanded"]), bits(&[1., -2., 3., 1., -2., 3.]));
    assert_eq!(
        bits(&actual["tiled"]),
        bits(&[10., 20., 30., 10., 20., 30.])
    );
    assert_eq!(
        bits(&actual["output"]),
        bits(&[11., 18., 33., 11., 18., 33.])
    );
    for op in ["Expand", "Tile"] {
        let source = model(
            &[
                node(
                    "Constant",
                    &[],
                    &["control"],
                    &ints_attr("value_ints", &[3]),
                ),
                node(op, &["input", "control"], &["output"], &[]),
                bytes(11, &info("input", &[1], 1)),
                bytes(12, &info("output", &[3], 1)),
            ]
            .concat(),
        );
        assert_eq!(
            bits(&roundtrip(&source, &[("input", data(&[1], &[-0.])?)])?["output"]),
            bits(&[-0.; 3])
        );
    }
    Ok(())
}

#[test]
fn broadcast_constant_inputs_and_future_names_remain_well_scoped() -> Test {
    for op in ["Expand", "Tile"] {
        let source = model(
            &[
                node(op, &["constant", "control"], &["output"], &[]),
                weight("constant", &[1], &[-0.]),
                int_weight("control", &[1], &[5]),
                bytes(12, &info("output", &[5], 1)),
            ]
            .concat(),
        );
        assert_eq!(bits(&roundtrip(&source, &[])?["output"]), bits(&[-0.; 5]));
        for ordinal in [2, 3] {
            let collision = format!("onnx-node-0000-repeat-{ordinal}");
            let source = model(
                &[
                    node(op, &["input", "control"], &["output"], &[]),
                    node("Identity", &["input"], &[&collision], &[]),
                    int_weight("control", &[1], &[5]),
                    bytes(11, &info("input", &[1], 1)),
                    bytes(12, &info("output", &[5], 1)),
                    bytes(12, &info(&collision, &[1], 1)),
                ]
                .concat(),
            );
            let actual = roundtrip(&source, &[("input", data(&[1], &[-f32::from_bits(1)])?)])?;
            assert_eq!(bits(&actual["output"]), bits(&[-f32::from_bits(1); 5]));
            assert_eq!(bits(&actual[&collision]), bits(&[-f32::from_bits(1)]));
            let forward = model(
                &[
                    node(op, &[&collision, "control"], &["output"], &[]),
                    node("Identity", &["input"], &[&collision], &[]),
                    int_weight("control", &[1], &[5]),
                    bytes(11, &info("input", &[1], 1)),
                    bytes(12, &info("output", &[5], 1)),
                ]
                .concat(),
            );
            assert_eq!(refusal(&forward), Some(OnnxError::Graph));
        }
    }
    Ok(())
}

#[test]
fn broadcast_refuses_dynamic_zero_negative_malformed_and_conflicting_controls() {
    for op in ["Expand", "Tile"] {
        for control in [0, -1, i64::MIN] {
            assert_eq!(
                refusal(&repeat_model(op, &[1], &[control], &[1])),
                Some(OnnxError::Unsupported)
            );
        }
        assert_eq!(
            refusal(&repeat_model(op, &[1], &[i64::MAX], &[1])),
            Some(OnnxError::Limit)
        );
        assert_eq!(
            refusal(&repeat_model(op, &[1], &[2], &[3])),
            Some(OnnxError::Graph)
        );
        assert_eq!(
            refusal(&repeat_model(op, &[1], &[1; 9], &[1])),
            Some(OnnxError::Limit)
        );
        for control in [
            int_weight("control", &[], &[2]),
            weight("control", &[1], &[2.]),
        ] {
            let source = model(
                &[
                    node(op, &["input", "control"], &["output"], &[]),
                    control,
                    bytes(11, &info("input", &[1], 1)),
                    bytes(12, &info("output", &[2], 1)),
                ]
                .concat(),
            );
            assert_eq!(refusal(&source), Some(OnnxError::Graph));
        }
        let dynamic = model(
            &[
                node(op, &["input", "control"], &["output"], &[]),
                bytes(11, &info("input", &[1], 1)),
                bytes(11, &info("control", &[1], 1)),
                bytes(12, &info("output", &[2], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&dynamic), Some(OnnxError::Unsupported));
        let attribute = model(
            &[
                node(op, &["input", "control"], &["output"], &int_attr("axis", 0)),
                int_weight("control", &[1], &[2]),
                bytes(11, &info("input", &[1], 1)),
                bytes(12, &info("output", &[2], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&attribute), Some(OnnxError::Unsupported));
        for (inputs, expected) in [
            (vec![], OnnxError::Graph),
            (vec!["input"], OnnxError::Graph),
            (vec!["input", ""], OnnxError::Limit),
            (vec!["input", "control", "control"], OnnxError::Graph),
        ] {
            let source = model(
                &[
                    node(op, &inputs, &["output"], &[]),
                    int_weight("control", &[1], &[2]),
                    bytes(11, &info("input", &[1], 1)),
                    bytes(12, &info("output", &[2], 1)),
                ]
                .concat(),
            );
            assert_eq!(refusal(&source), Some(expected));
        }
    }
    assert_eq!(
        refusal(&repeat_model("Expand", &[2, 3], &[2, 4], &[2, 4])),
        Some(OnnxError::Graph)
    );
    assert_eq!(
        refusal(&repeat_model("Tile", &[3], &[i64::MAX], &[3])),
        Some(OnnxError::Limit)
    );
    for repeats in [&[][..], &[1][..], &[1, 1, 1][..]] {
        assert_eq!(
            refusal(&repeat_model("Tile", &[2, 3], repeats, &[2, 3])),
            Some(OnnxError::Graph)
        );
    }
}

#[test]
fn broadcast_exact_aggregate_limits_and_identity_paths_are_enforced() -> Test {
    for op in ["Expand", "Tile"] {
        let source = repeat_model(op, &[1], &[5], &[5]);
        let imported = import(&source)?;
        let limits = OnnxLimits {
            nodes: 3,
            tensors: 5,
            parameter_bytes: 8,
            tensor_bytes: 20,
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
            OnnxLimits { nodes: 2, ..limits },
            OnnxLimits {
                tensors: 4,
                ..limits
            },
            OnnxLimits {
                parameter_bytes: 7,
                ..limits
            },
            OnnxLimits {
                tensor_bytes: 19,
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
        assert_eq!(
            import_onnx(
                &source,
                ContentDigest::sha256(&source),
                GENERATION,
                OnnxLimits {
                    work_units: limits.work_units - 1,
                    ..limits
                },
                &|| false
            )
            .err(),
            Some(OnnxError::WorkBudget)
        );
        let identity = repeat_model(op, &[], &[], &[]);
        let admitted = import_onnx(
            &identity,
            ContentDigest::sha256(&identity),
            GENERATION,
            OnnxLimits {
                nodes: 1,
                tensors: 3,
                parameter_bytes: 0,
                tensor_bytes: 4,
                ..OnnxLimits::default()
            },
            &|| false,
        )?;
        assert_eq!(admitted.graph().node_count(), 1);
        assert!(admitted.parameters().is_empty());
    }
    Ok(())
}

#[test]
fn broadcast_import_cancellation_and_source_identity_fail_closed() -> Test {
    for op in ["Expand", "Tile"] {
        let source = repeat_model(op, &[1, 1], &[5, 7], &[5, 7]);
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
                "{op} checkpoint {stop}/{total}"
            );
        }
    }
    Ok(())
}

#[test]
fn broadcast_both_native_executors_enforce_work_memory_and_cancellation() -> Test {
    for op in ["Expand", "Tile"] {
        let source = repeat_model(op, &[1, 1], &[5, 7], &[5, 7]);
        let imported = import(&source)?;
        let input = [("input", data(&[1, 1], &[-0.])?)];
        let bindings = [("input".to_owned(), input[0].1.clone())];
        let optimized = optimized_executor::OptimizedGraph::prepare(
            imported.graph(),
            &BTreeMap::new(),
            &ScalarExecCx::new(),
        )?;
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
        let cx = ScalarExecCx::new();
        cx.request_cancellation();
        assert!(matches!(
            ScalarExecutor::run(imported.graph(), &bindings, ExecBudget::unlimited(), &cx),
            Err(ExecError::CancellationRequested { .. })
        ));
        assert!(cx.is_drain_completed());
        let cx = ScalarExecCx::new();
        cx.request_cancellation();
        assert!(matches!(
            optimized.run(&input, ExecBudget::unlimited(), &cx),
            Err(ExecError::CancellationRequested { .. })
        ));
        assert!(cx.is_drain_completed());
    }
    Ok(())
}
