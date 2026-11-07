#![forbid(unsafe_code)]
//! Static F32 Gather and ordered ReduceMean unlock imported attention and pooled
//! features. Both production executors and actual artifacts run unchanged.
//! Layout/reduction oracles are independent; the composed attention oracle uses
//! binary64 math on explicitly bounded ordinary fixtures, not trained weights.

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
const GENERATION: Generation = Generation(53);

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
fn gather_model(
    input: &[usize],
    index_dims: &[usize],
    indices: &[i64],
    axis: i64,
    output: &[usize],
) -> Vec<u8> {
    model(
        &[
            node(
                "Gather",
                &["input", "indices"],
                &["output"],
                &int_attr("axis", axis),
            ),
            int_weight("indices", index_dims, indices),
            bytes(11, &info("input", input, 1)),
            bytes(12, &info("output", output, 1)),
        ]
        .concat(),
    )
}
fn mean_attrs(axes: Option<&[i64]>, keepdims: Option<i64>) -> Vec<u8> {
    [
        axes.map_or_else(Vec::new, |axes| ints_attr("axes", axes)),
        keepdims.map_or_else(Vec::new, |keep| int_attr("keepdims", keep)),
    ]
    .concat()
}
fn mean_model(
    input: &[usize],
    axes: Option<&[i64]>,
    keepdims: Option<i64>,
    output: &[usize],
) -> Vec<u8> {
    model(
        &[
            node(
                "ReduceMean",
                &["input"],
                &["output"],
                &mean_attrs(axes, keepdims),
            ),
            bytes(11, &info("input", input, 1)),
            bytes(12, &info("output", output, 1)),
        ]
        .concat(),
    )
}

// Direct source-coordinate selection, independent of Slice/Concat runs.
fn gather_oracle(values: &[f32], dims: &[usize], axis: usize, indices: &[i64]) -> Vec<f32> {
    let before: usize = dims[..axis].iter().product();
    let after: usize = dims[axis + 1..].iter().product();
    let extent = dims[axis] as i64;
    let mut result = Vec::new();
    for outer in 0..before {
        for &index in indices {
            let index = if index < 0 { index + extent } else { index } as usize;
            for inner in 0..after {
                result.push(values[(outer * dims[axis] + index) * after + inner]);
            }
        }
    }
    result
}

// Traverse the original tensor once, accumulating each output bucket in original
// row-major order. No production permutation, MatMul or shape helper is reused.
fn mean_oracle(values: &[f32], dims: &[usize], axes: &[usize]) -> Vec<f32> {
    let output_count = dims
        .iter()
        .enumerate()
        .filter(|(axis, _)| !axes.contains(axis))
        .map(|(_, &dim)| dim)
        .product();
    let width: usize = axes.iter().map(|&axis| dims[axis]).product();
    let mut result = vec![0.0_f32; output_count];
    for (flat, &value) in values.iter().enumerate() {
        let mut index = flat;
        let mut output = 0;
        let mut stride = 1;
        for axis in (0..dims.len()).rev() {
            let coordinate = index % dims[axis];
            index /= dims[axis];
            if !axes.contains(&axis) {
                output += coordinate * stride;
                stride *= dims[axis];
            }
        }
        result[output] += value;
    }
    for value in &mut result {
        *value /= width as f32;
    }
    result
}

#[test]
fn gather_literals_distinguish_scalar_vector_and_repeated_indices() -> Test {
    let input = data(&[2, 3], &[1., 2., 3., 4., 5., 6.])?;
    let source = gather_model(&[2, 3], &[3], &[-1, 0, -1], -1, &[2, 3]);
    assert_eq!(
        bits(&roundtrip(&source, &[("input", input.clone())])?["output"]),
        bits(&[3., 1., 3., 6., 4., 6.])
    );
    for (index_dims, output) in [(vec![], vec![2]), (vec![1], vec![2, 1])] {
        let source = gather_model(&[2, 3], &index_dims, &[1], 1, &output);
        assert_eq!(import(&source)?.graph().outputs()[0].shape().dims(), output);
        assert_eq!(
            bits(&roundtrip(&source, &[("input", input.clone())])?["output"]),
            bits(&[2., 5.])
        );
    }
    let source = gather_model(&[2], &[], &[-1], 0, &[]);
    assert_eq!(
        bits(&roundtrip(&source, &[("input", data(&[2], &[1., -0.])?)])?["output"]),
        bits(&[-0.])
    );
    // A contiguous selection is one range, including negative source indices.
    let source = gather_model(&[2, 3], &[3], &[-3, -2, -1], 1, &[2, 3]);
    assert_eq!(import(&source)?.graph().node_count(), 1);
    assert_eq!(
        bits(&roundtrip(&source, &[("input", input)])?["output"]),
        bits(&[1., 2., 3., 4., 5., 6.])
    );
    Ok(())
}

#[test]
fn gather_every_rank_and_axis_preserves_exact_finite_bits() -> Test {
    let special = [
        -0.0_f32,
        0.,
        f32::from_bits(1),
        -f32::from_bits(1),
        f32::MIN,
        f32::MAX,
        f32::MIN_POSITIVE,
        -3.25,
    ];
    for rank in 1..=8 {
        let dims = vec![2; rank];
        let values = (0..dims.iter().product())
            .map(|index| special[index % special.len()])
            .collect::<Vec<_>>();
        for axis in 0..rank {
            for (index_dims, indices) in [(vec![], vec![-1]), (vec![4], vec![1, 0, 1, -2])] {
                let mut output = dims.clone();
                if index_dims.is_empty() {
                    output.remove(axis);
                } else {
                    output[axis] = indices.len();
                }
                let source = gather_model(
                    &dims,
                    &index_dims,
                    &indices,
                    axis as i64 - rank as i64,
                    &output,
                );
                let imported = import(&source)?;
                assert!(imported.parameters().is_empty());
                assert_eq!(imported.runtime_inputs(), &["input"]);
                let actual = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
                assert_eq!(
                    bits(&actual["output"]),
                    bits(&gather_oracle(&values, &dims, axis, &indices)),
                    "rank={rank} axis={axis} scalar={}",
                    index_dims.is_empty()
                );
            }
        }
    }
    Ok(())
}

#[test]
fn gather_static_shape_controls_and_constant_data_keep_distinct_dispatch() -> Test {
    let source = model(
        &[
            node("Shape", &["input"], &["shape"], &[]),
            node("Gather", &["shape", "axis-index"], &["dimension"], &[]),
            node("Sub", &["dimension", "one"], &["last"], &[]),
            node(
                "Gather",
                &["input", "last"],
                &["output"],
                &int_attr("axis", 1),
            ),
            int_weight("axis-index", &[], &[1]),
            int_weight("one", &[], &[1]),
            bytes(11, &info("input", &[2, 3], 1)),
            bytes(12, &info("output", &[2], 1)),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    assert!(imported.parameters().is_empty());
    assert_eq!(imported.graph().node_count(), 2);
    assert_eq!(
        bits(
            &roundtrip(
                &source,
                &[("input", data(&[2, 3], &[1., 2., 3., 4., 5., 6.])?)]
            )?["output"]
        ),
        bits(&[3., 6.])
    );
    let source = model(
        &[
            node("Constant", &[], &["index"], &int_attr("value_int", -1)),
            node("Gather", &["data", "index"], &["output"], &[]),
            weight("data", &[3], &[1., 2., -f32::from_bits(1)]),
            bytes(12, &info("output", &[], 1)),
        ]
        .concat(),
    );
    assert_eq!(
        bits(&roundtrip(&source, &[])?["output"]),
        bits(&[-f32::from_bits(1)])
    );
    assert_eq!(
        import(&source)?
            .parameters()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["data"]
    );
    Ok(())
}

#[test]
fn mean_noncontiguous_negative_axes_keepdims_and_empty_axes_are_exact() -> Test {
    let dims = [2, 3, 4];
    let values = (0..24).map(|index| index as f32 - 11.).collect::<Vec<_>>();
    for (axes, keep, output) in [
        (Some(vec![0, 2]), Some(0), vec![3]),
        (Some(vec![-1, 0]), None, vec![1, 3, 1]),
        (None, Some(0), vec![]),
        (Some(vec![]), None, vec![1, 1, 1]),
    ] {
        let source = mean_model(&dims, axes.as_deref(), keep, &output);
        let expected = if axes.as_ref().is_none_or(Vec::is_empty) {
            vec![0.5]
        } else {
            vec![-3.5, 0.5, 4.5]
        };
        let actual = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
        assert_eq!(bits(&actual["output"]), bits(&expected));
        assert_eq!(import(&source)?.graph().outputs()[0].shape().dims(), output);
    }
    Ok(())
}

#[test]
fn empty_integer_attributes_accept_both_protobuf_encodings_without_type_confusion() -> Test {
    let reference = mean_model(&[2, 3], None, None, &[1, 1]);
    let reference = export(&import(&reference)?)?;
    for payload in [Vec::new(), bytes(8, &[])] {
        let source = model(
            &[
                node(
                    "ReduceMean",
                    &["input"],
                    &["output"],
                    &attribute("axes", 7, &payload),
                ),
                bytes(11, &info("input", &[2, 3], 1)),
                bytes(12, &info("output", &[1, 1], 1)),
            ]
            .concat(),
        );
        let imported = import(&source)?;
        let artifacts = export(&imported)?;
        assert_eq!(artifacts.graph_bytes(), reference.graph_bytes());
        // Parameter bits agree, while the Safetensors provenance header keeps
        // the distinct original source bytes bound to each exported artifact.
        let expected = reloaded(&reference)?;
        let actual = reloaded(&artifacts)?;
        assert_eq!(
            actual.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>()
        );
        for (name, tensor) in actual {
            assert_eq!(tensor.shape(), expected[&name].shape());
            assert_eq!(
                bits(&tensor.to_vec::<f32>()?),
                bits(&expected[&name].to_vec::<f32>()?)
            );
        }
        assert_ne!(artifacts.weights_digest(), reference.weights_digest());
        assert_eq!(
            roundtrip(
                &source,
                &[("input", data(&[2, 3], &[1., 2., 3., 4., 5., 6.])?)]
            )?["output"],
            [3.5]
        );
    }
    for attrs in [
        // A list discriminator cannot be paired with a scalar payload.
        attribute("axes", 7, &integer(3, 0)),
        // A scalar discriminator cannot be paired with an empty list payload.
        attribute("axes", 2, &bytes(8, &[])),
        // An empty list still requires the explicit INTS discriminator.
        bytes(5, &bytes(1, b"axes")),
        bytes(5, &[bytes(1, b"axes"), bytes(8, &[])].concat()),
        // A mismatched scalar payload remains ambiguous even alongside a list.
        attribute("axes", 7, &[integer(3, 0), bytes(8, &[])].concat()),
    ] {
        let source = model(
            &[
                node("ReduceMean", &["input"], &["output"], &attrs),
                bytes(11, &info("input", &[2, 3], 1)),
                bytes(12, &info("output", &[1, 1], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(OnnxError::Malformed));
    }
    Ok(())
}

#[test]
fn mean_every_admitted_rank_matches_independent_coordinate_accumulation() -> Test {
    for rank in 0..=8 {
        let dims = (0..rank)
            .map(|axis| if axis % 2 == 0 { 2 } else { 3 })
            .collect::<Vec<_>>();
        let values = (0..dims.iter().product())
            .map(|index| ((index * 7 % 19) as f32 - 9.) / 8.)
            .collect::<Vec<_>>();
        let selections = [
            (0..rank).collect::<Vec<_>>(),
            (0..rank).filter(|axis| axis % 2 == 0).collect::<Vec<_>>(),
            (0..rank).rev().take(1).collect::<Vec<_>>(),
        ];
        for axes in selections {
            for keep in [false, true] {
                let raw = axes
                    .iter()
                    .rev()
                    .map(|&axis| axis as i64 - rank as i64)
                    .collect::<Vec<_>>();
                let output = dims
                    .iter()
                    .enumerate()
                    .filter_map(|(axis, &dim)| {
                        if axes.contains(&axis) {
                            keep.then_some(1)
                        } else {
                            Some(dim)
                        }
                    })
                    .collect::<Vec<_>>();
                let source = mean_model(&dims, Some(&raw), Some(i64::from(keep)), &output);
                let actual = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
                assert_eq!(
                    bits(&actual["output"]),
                    bits(&mean_oracle(&values, &dims, &axes)),
                    "rank={rank} axes={axes:?} keep={keep}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn mean_signed_zeros_subnormal_rounding_and_overflow_follow_native_order() -> Test {
    for (dims, values) in [
        (vec![], vec![-0.]),
        (vec![1], vec![-0.]),
        (vec![2], vec![-0., -0.]),
        (vec![2], vec![f32::from_bits(1), f32::from_bits(1)]),
        (vec![2], vec![f32::from_bits(1), 0.]),
        (vec![2], vec![-f32::from_bits(1), 0.]),
        (vec![3], vec![16_777_216., 1., -16_777_216.]),
        (vec![3], vec![16_777_216., -16_777_216., 1.]),
        (vec![2], vec![f32::MAX, f32::MAX]),
        (vec![2], vec![f32::MIN, f32::MIN]),
    ] {
        let source = mean_model(&dims, None, Some(0), &[]);
        let actual = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
        let expected = mean_oracle(&values, &dims, &(0..dims.len()).collect::<Vec<_>>());
        assert_eq!(bits(&actual["output"]), bits(&expected), "{values:?}");
    }
    let source = mean_model(&[2], None, Some(0), &[]);
    let overflow = roundtrip(&source, &[("input", data(&[2], &[f32::MAX, f32::MAX])?)])?;
    // The sum overflows before division. It must not become a plausible finite
    // feature, a clamped maximum, or an empty output. This is not a robust mean.
    assert_eq!(overflow["output"], [f32::INFINITY]);
    let source = mean_model(&[], None, None, &[]);
    assert_eq!(
        bits(&roundtrip(&source, &[("input", data(&[], &[-0.])?)])?["output"]),
        bits(&[0.])
    );
    Ok(())
}

fn qkv_weights() -> Vec<f32> {
    (0..48)
        .map(|index| ((index * 5 % 13) as f32 - 6.) / 16.)
        .collect()
}
fn qkv_bias() -> Vec<f32> {
    (0..12).map(|index| (index as f32 - 6.) / 32.).collect()
}
fn output_weights() -> Vec<f32> {
    (0..12)
        .map(|index| ((index % 7) as f32 - 3.) / 8.)
        .collect()
}

// Two batches, two heads, four feature channels. Q/K/V are packed into one
// projection, then selected from the permuted block with scalar Gather nodes.
// A nontrivial residual and token mean feed selected features and a dense head.
fn attention_model(tokens: usize) -> Vec<u8> {
    model(
        &[
            node("MatMul", &["input", "qkv-weight"], &["projected"], &[]),
            node("Add", &["projected", "qkv-bias"], &["biased"], &[]),
            node("Reshape", &["biased", "packed-shape"], &["packed"], &[]),
            node(
                "Transpose",
                &["packed"],
                &["qkv"],
                &ints_attr("perm", &[2, 0, 3, 1, 4]),
            ),
            node("Gather", &["qkv", "query-index"], &["queries"], &[]),
            node("Gather", &["qkv", "key-index"], &["keys"], &[]),
            node("Gather", &["qkv", "value-index"], &["values"], &[]),
            node("Mul", &["queries", "scale"], &["scaled"], &[]),
            node(
                "Transpose",
                &["keys"],
                &["transposed-keys"],
                &ints_attr("perm", &[0, 1, 3, 2]),
            ),
            node("MatMul", &["scaled", "transposed-keys"], &["scores"], &[]),
            node(
                "Softmax",
                &["scores"],
                &["attention"],
                &int_attr("axis", -1),
            ),
            node("MatMul", &["attention", "values"], &["context"], &[]),
            node(
                "Transpose",
                &["context"],
                &["ordered"],
                &ints_attr("perm", &[0, 2, 1, 3]),
            ),
            node("Reshape", &["ordered", "token-shape"], &["unpacked"], &[]),
            node("Add", &["unpacked", "input"], &["tokens"], &[]),
            node(
                "ReduceMean",
                &["tokens"],
                &["features"],
                &mean_attrs(Some(&[1]), Some(0)),
            ),
            node(
                "Gather",
                &["features", "feature-indices"],
                &["selected"],
                &int_attr("axis", -1),
            ),
            node(
                "Gemm",
                &["selected", "output-weight", "output-bias"],
                &["embedding"],
                &[],
            ),
            weight("qkv-weight", &[4, 12], &qkv_weights()),
            weight("qkv-bias", &[12], &qkv_bias()),
            weight("scale", &[], &[std::f32::consts::FRAC_1_SQRT_2]),
            weight("output-weight", &[4, 3], &output_weights()),
            weight("output-bias", &[3], &[0.125, -0.25, 0.5]),
            int_weight("packed-shape", &[5], &[2, tokens as i64, 3, 2, 2]),
            int_weight("token-shape", &[3], &[2, tokens as i64, 4]),
            int_weight("query-index", &[], &[0]),
            int_weight("key-index", &[], &[1]),
            int_weight("value-index", &[], &[-1]),
            int_weight("feature-indices", &[4], &[3, 1, 3, 0]),
            bytes(11, &info("input", &[2, tokens, 4], 1)),
            bytes(12, &info("queries", &[2, 2, tokens, 2], 1)),
            bytes(12, &info("keys", &[2, 2, tokens, 2], 1)),
            bytes(12, &info("values", &[2, 2, tokens, 2], 1)),
            bytes(12, &info("attention", &[2, 2, tokens, tokens], 1)),
            bytes(12, &info("tokens", &[2, tokens, 4], 1)),
            bytes(12, &info("features", &[2, 4], 1)),
            bytes(12, &info("selected", &[2, 4], 1)),
            bytes(12, &info("embedding", &[2, 3], 1)),
        ]
        .concat(),
    )
}

fn attention_input(tokens: usize) -> Vec<f32> {
    (0..2 * tokens * 4)
        .map(|index| ((index * 3 % 17) as f32 - 8.) / 8.)
        .collect()
}

fn attention_oracle(input: &[f32], tokens: usize) -> BTreeMap<String, Vec<f64>> {
    let weights = qkv_weights();
    let bias = qkv_bias();
    let mut projected = vec![0.0_f64; 2 * tokens * 12];
    for batch in 0..2 {
        for token in 0..tokens {
            for field in 0..12 {
                let mut value = f64::from(bias[field]);
                for channel in 0..4 {
                    value += f64::from(input[(batch * tokens + token) * 4 + channel])
                        * f64::from(weights[channel * 12 + field]);
                }
                projected[(batch * tokens + token) * 12 + field] = value;
            }
        }
    }
    let mut qkv = [Vec::new(), Vec::new(), Vec::new()];
    for (kind, values) in qkv.iter_mut().enumerate() {
        for batch in 0..2 {
            for head in 0..2 {
                for token in 0..tokens {
                    for channel in 0..2 {
                        values.push(
                            projected
                                [(batch * tokens + token) * 12 + kind * 4 + head * 2 + channel],
                        );
                    }
                }
            }
        }
    }
    let offset = |batch: usize, head: usize, token: usize, channel: usize| {
        ((batch * 2 + head) * tokens + token) * 2 + channel
    };
    let mut probabilities = Vec::new();
    let mut contextual = vec![0.0_f64; 2 * tokens * 4];
    for batch in 0..2 {
        for head in 0..2 {
            for query in 0..tokens {
                let mut scores = Vec::new();
                for key in 0..tokens {
                    let score = (0..2)
                        .map(|channel| {
                            qkv[0][offset(batch, head, query, channel)]
                                * f64::from(std::f32::consts::FRAC_1_SQRT_2)
                                * qkv[1][offset(batch, head, key, channel)]
                        })
                        .sum::<f64>();
                    scores.push(score);
                }
                let max = scores.iter().copied().fold(f64::NEG_INFINITY, f64::max);
                let exponentials = scores
                    .iter()
                    .map(|score| (score - max).exp())
                    .collect::<Vec<_>>();
                let total: f64 = exponentials.iter().sum();
                let row = exponentials
                    .iter()
                    .map(|value| value / total)
                    .collect::<Vec<_>>();
                probabilities.extend(&row);
                for channel in 0..2 {
                    contextual[(batch * tokens + query) * 4 + head * 2 + channel] = (0..tokens)
                        .map(|key| row[key] * qkv[2][offset(batch, head, key, channel)])
                        .sum::<f64>()
                        + f64::from(input[(batch * tokens + query) * 4 + head * 2 + channel]);
                }
            }
        }
    }
    let mut pooled = Vec::new();
    for batch in 0..2 {
        for channel in 0..4 {
            pooled.push(
                (0..tokens)
                    .map(|token| contextual[(batch * tokens + token) * 4 + channel])
                    .sum::<f64>()
                    / tokens as f64,
            );
        }
    }
    let selected = (0..2)
        .flat_map(|batch| [3, 1, 3, 0].map(|channel| pooled[batch * 4 + channel]))
        .collect::<Vec<_>>();
    let out_weights = output_weights();
    let mut embedding = Vec::new();
    for batch in 0..2 {
        for field in 0..3 {
            embedding.push(
                (0..4)
                    .map(|channel| {
                        selected[batch * 4 + channel] * f64::from(out_weights[channel * 3 + field])
                    })
                    .sum::<f64>()
                    + [0.125, -0.25, 0.5][field],
            );
        }
    }
    BTreeMap::from([
        ("queries".into(), qkv[0].clone()),
        ("keys".into(), qkv[1].clone()),
        ("values".into(), qkv[2].clone()),
        ("attention".into(), probabilities),
        ("tokens".into(), contextual),
        ("features".into(), pooled),
        ("selected".into(), selected),
        ("embedding".into(), embedding),
    ])
}

#[test]
fn attention_qkv_batched_softmax_and_pooled_features_run_through_real_artifacts() -> Test {
    for tokens in [2, 4, 7] {
        let source = attention_model(tokens);
        let input = attention_input(tokens);
        let expected = attention_oracle(&input, tokens);
        let actual = roundtrip(&source, &[("input", data(&[2, tokens, 4], &input)?)])?;
        for (name, expected) in &expected {
            assert_eq!(actual[name].len(), expected.len());
            for (index, (&actual, &expected)) in actual[name].iter().zip(expected).enumerate() {
                // Bound selected before execution for these small, O(1) inputs:
                // at most seven positive Softmax terms, two dot-product terms,
                // seven context terms and four head terms. This numerical test
                // is separate from exact scalar/optimized/reload comparisons.
                let bound = 32. * f64::from(f32::EPSILON) * expected.abs().max(1.);
                assert!(
                    (f64::from(actual) - expected).abs() <= bound,
                    "{name}[{index}] tokens={tokens}: {actual} vs {expected}, bound {bound}"
                );
            }
        }
        assert!(
            actual["attention"][..tokens]
                .windows(2)
                .any(|pair| pair[0].to_bits() != pair[1].to_bits())
        );
        let imported = import(&source)?;
        assert_eq!(imported.runtime_inputs(), &["input"]);
        assert!(
            imported
                .parameters()
                .keys()
                .all(|name| !name.ends_with("index")
                    && !name.ends_with("indices")
                    && !name.ends_with("shape"))
        );
    }
    Ok(())
}

#[test]
fn attention_practical_token_sizes_have_constant_helper_count_and_checked_matrix_size() -> Test {
    let small = attention_model(4);
    let large = attention_model(2048);
    let small = import(&small)?;
    let large = import(&large)?;
    assert_eq!(small.graph().node_count(), large.graph().node_count());
    assert!(large.graph().node_count() < 40);
    // QKV weights/bias (240), attention scale (4), output weights/bias (60),
    // the Gemm alpha/beta scalars (8), and ReduceMean ones/divisor (8196).
    assert_eq!(
        large
            .parameters()
            .values()
            .map(|tensor| tensor.shape().size_bytes(fss_tensor::DType::F32))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .sum::<usize>(),
        8_508
    );
    assert_eq!(refusal(&attention_model(2049)), Some(OnnxError::Limit));
    // A full-input mean can require more ones than the separate parameter quota
    // permits. Refuse before allocating that generated column.
    assert_eq!(
        refusal(&mean_model(&[4_194_304], None, Some(0), &[])),
        Some(OnnxError::Limit)
    );
    Ok(())
}

#[test]
fn gather_and_mean_refuse_invalid_controls_attributes_and_output_witnesses() {
    for index in [3, -4, i64::MIN, i64::MAX] {
        assert_eq!(
            refusal(&gather_model(&[2, 3], &[], &[index], 1, &[2])),
            Some(OnnxError::Graph)
        );
    }
    for axis in [-3, 2, i64::MIN, i64::MAX] {
        assert_eq!(
            refusal(&gather_model(&[2, 3], &[], &[0], axis, &[2])),
            Some(OnnxError::Graph)
        );
    }
    assert_eq!(
        refusal(&gather_model(&[], &[], &[0], 0, &[])),
        Some(OnnxError::Unsupported)
    );
    assert_eq!(
        refusal(&gather_model(&[2, 3], &[0], &[], 1, &[2])),
        Some(OnnxError::Unsupported)
    );
    assert_eq!(
        refusal(&gather_model(&[2, 3], &[1, 1], &[0], 1, &[2, 1, 1])),
        Some(OnnxError::Unsupported)
    );
    assert_eq!(
        refusal(&gather_model(&[2, 3], &[9], &[0; 9], 1, &[2, 9])),
        Some(OnnxError::Limit)
    );
    assert_eq!(
        refusal(&gather_model(&[2, 3], &[], &[0], 1, &[2, 1])),
        Some(OnnxError::Graph)
    );
    let float_indices = model(
        &[
            node("Gather", &["input", "indices"], &["output"], &[]),
            weight("indices", &[], &[0.]),
            bytes(11, &info("input", &[2], 1)),
            bytes(12, &info("output", &[], 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&float_indices), Some(OnnxError::Graph));
    let dynamic_indices = model(
        &[
            node("Gather", &["input", "indices"], &["output"], &[]),
            bytes(11, &info("indices", &[], 1)),
            bytes(11, &info("input", &[2], 1)),
            bytes(12, &info("output", &[], 1)),
        ]
        .concat(),
    );
    assert_eq!(refusal(&dynamic_indices), Some(OnnxError::Unsupported));
    for attrs in [ints_attr("axis", &[0]), int_attr("batch_dims", 1)] {
        let expected = if attrs == ints_attr("axis", &[0]) {
            OnnxError::Graph
        } else {
            OnnxError::Unsupported
        };
        let source = model(
            &[
                node("Gather", &["input", "indices"], &["output"], &attrs),
                int_weight("indices", &[], &[0]),
                bytes(11, &info("input", &[2], 1)),
                bytes(12, &info("output", &[], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(expected));
    }
    for axes in [
        &[1, -1][..],
        &[2][..],
        &[-3][..],
        &[i64::MIN][..],
        &[i64::MAX][..],
    ] {
        assert_eq!(
            refusal(&mean_model(&[2, 3], Some(axes), None, &[2, 1])),
            Some(OnnxError::Graph)
        );
    }
    assert_eq!(
        refusal(&mean_model(&[], Some(&[0]), None, &[])),
        Some(OnnxError::Graph)
    );
    assert_eq!(
        refusal(&mean_model(&[2, 3], Some(&[1]), Some(2), &[2, 1])),
        Some(OnnxError::Unsupported)
    );
    assert_eq!(
        refusal(&mean_model(&[2, 3], Some(&[1]), None, &[2])),
        Some(OnnxError::Graph)
    );
    for (attrs, expected) in [
        (int_attr("axes", 1), OnnxError::Graph),
        (int_attr("noop_with_empty_axes", 1), OnnxError::Unsupported),
    ] {
        let source = model(
            &[
                node("ReduceMean", &["input"], &["output"], &attrs),
                bytes(11, &info("input", &[2, 3], 1)),
                bytes(12, &info("output", &[1, 1], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(expected));
    }
    for (op, inputs, expected) in [
        ("Gather", vec!["input"], OnnxError::Graph),
        ("Gather", vec!["input", ""], OnnxError::Limit),
        ("Gather", vec!["input", "input", "input"], OnnxError::Graph),
        ("ReduceMean", vec![], OnnxError::Graph),
        ("ReduceMean", vec![""], OnnxError::Limit),
        ("ReduceMean", vec!["input", "input"], OnnxError::Graph),
    ] {
        let source = model(
            &[
                node(op, &inputs, &["output"], &[]),
                bytes(11, &info("input", &[2], 1)),
                bytes(12, &info("output", &[1], 1)),
            ]
            .concat(),
        );
        assert_eq!(refusal(&source), Some(expected));
    }
}

#[test]
fn gather_and_mean_helpers_cannot_capture_future_source_names() -> Test {
    let dims = [2, 3, 4];
    let values = (0..24).map(|index| index as f32 - 10.).collect::<Vec<_>>();
    for suffix in [
        "gather-4",
        "gather-3",
        "mean-ones",
        "mean-divisor",
        "mean-5",
    ] {
        let collision = format!("onnx-node-0000-{suffix}");
        let gather = suffix.starts_with("gather");
        let mut graph = if gather {
            [
                node(
                    "Gather",
                    &["input", "indices"],
                    &["output"],
                    &int_attr("axis", 1),
                ),
                int_weight("indices", &[3], &[2, 0, 2]),
            ]
            .concat()
        } else {
            node(
                "ReduceMean",
                &["input"],
                &["output"],
                &mean_attrs(Some(&[1]), Some(0)),
            )
        };
        graph.extend(node("Identity", &["input"], &[&collision], &[]));
        graph.extend(bytes(11, &info("input", &dims, 1)));
        graph.extend(bytes(
            12,
            &info("output", if gather { &dims[..] } else { &[2, 4][..] }, 1),
        ));
        graph.extend(bytes(12, &info(&collision, &dims, 1)));
        let source = model(&graph);
        let actual = roundtrip(&source, &[("input", data(&dims, &values)?)])?;
        let expected = if gather {
            gather_oracle(&values, &dims, 1, &[2, 0, 2])
        } else {
            mean_oracle(&values, &dims, &[1])
        };
        assert_eq!(bits(&actual["output"]), bits(&expected));
        assert_eq!(bits(&actual[&collision]), bits(&values));
        let mut forward = if gather {
            [
                node(
                    "Gather",
                    &[&collision, "indices"],
                    &["output"],
                    &int_attr("axis", 1),
                ),
                int_weight("indices", &[3], &[2, 0, 2]),
            ]
            .concat()
        } else {
            node(
                "ReduceMean",
                &[&collision],
                &["output"],
                &mean_attrs(Some(&[1]), Some(0)),
            )
        };
        forward.extend(node("Identity", &["input"], &[&collision], &[]));
        forward.extend(bytes(11, &info("input", &dims, 1)));
        forward.extend(bytes(
            12,
            &info("output", if gather { &dims[..] } else { &[2, 4][..] }, 1),
        ));
        assert_eq!(refusal(&model(&forward)), Some(OnnxError::Graph));
    }
    Ok(())
}

#[test]
fn gather_and_mean_aggregate_admission_work_and_cancellation_are_exact() -> Test {
    let cases = [
        (
            gather_model(&[2, 3], &[3], &[2, 0, 2], 1, &[2, 3]),
            4,
            6,
            24,
            24,
        ),
        (
            mean_model(&[2, 3, 4], Some(&[1]), Some(0), &[2, 4]),
            5,
            8,
            16,
            96,
        ),
    ];
    for (source, nodes, tensors, parameter_bytes, tensor_bytes) in cases {
        let imported = import(&source)?;
        assert_eq!(imported.graph().node_count(), nodes);
        let limits = OnnxLimits {
            nodes,
            tensors,
            parameter_bytes,
            tensor_bytes,
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
            OnnxLimits {
                nodes: nodes - 1,
                ..limits
            },
            OnnxLimits {
                tensors: tensors - 1,
                ..limits
            },
            OnnxLimits {
                parameter_bytes: parameter_bytes - 1,
                ..limits
            },
            OnnxLimits {
                tensor_bytes: tensor_bytes - 1,
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
        assert_eq!(
            import_onnx(
                &source,
                ContentDigest::sha256(b"wrong"),
                GENERATION,
                limits,
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
            limits,
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
                    limits,
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
    }
    Ok(())
}

#[test]
fn attention_real_execution_refuses_short_budgets_stale_inputs_and_cancellation() -> Test {
    let source = attention_model(4);
    let imported = import(&source)?;
    let input = [("input", data(&[2, 4, 4], &attention_input(4))?)];
    let constants = imported
        .parameters()
        .iter()
        .map(|(name, tensor)| Ok((name.clone(), tensor.to_vec::<f32>()?)))
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
    let stale = Tensor::from_values(
        Shape::new(vec![2, 4, 4])?,
        &attention_input(4),
        Generation(GENERATION.0 + 1),
    )?;
    let mut stale_bindings = bindings.clone();
    let entry = stale_bindings
        .iter_mut()
        .find(|(name, _)| name == "input")
        .ok_or("input binding")?;
    entry.1 = stale.clone();
    assert!(matches!(
        ScalarExecutor::run(
            imported.graph(),
            &stale_bindings,
            ExecBudget::unlimited(),
            &ScalarExecCx::new()
        ),
        Err(ExecError::GenerationMismatch { .. })
    ));
    assert!(matches!(
        optimized.run(
            &[("input", stale)],
            ExecBudget::unlimited(),
            &ScalarExecCx::new()
        ),
        Err(ExecError::GenerationMismatch { .. })
    ));
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
    Ok(())
}
