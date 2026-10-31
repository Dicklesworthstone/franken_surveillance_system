#![forbid(unsafe_code)]
//! Native ONNX -> exported graph/Safetensors -> reloaded production scalar execution.
//! The production Safetensors parser is included unchanged with its small data-only
//! host types below. This isolates the actual parser/kernel path from unrelated async
//! dependencies; it does not claim to compile the full reference crate or package CLI.

use std::cell::Cell;
use std::collections::BTreeMap;

use fss_core::{ContentDigest, Generation};
use fss_model_ir::{
    ImportedOnnx, OnnxArtifacts, OnnxError, OnnxExportLimits, OnnxLimits,
    decode_canonical_model_ir, encode_canonical_model_ir, export_onnx_artifacts, import_onnx,
    onnx_importer_identity,
};
use fss_tensor::{Shape, Tensor};

#[path = "../../fss-reference/src/ingest/model_import/safetensors.rs"]
mod safetensors;
#[path = "../../fss-reference/src/scalar_executor.rs"]
pub mod scalar_executor;

// These are only the limits, refusal variants and policy expected by the unchanged
// production parser. All byte parsing, escaping, span checks and F32 decoding are
// provided by that included production module, not by a test implementation.
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
const GENERATION: Generation = Generation(17);
const RGB: &[u8] = include_bytes!("fixtures/onnx/rgb_dense_head.onnx");

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
fn integer(tag: u64, value: u64) -> Vec<u8> {
    [varint(tag * 8), varint(value)].concat()
}
fn bytes(tag: u64, value: &[u8]) -> Vec<u8> {
    [
        varint(tag * 8 + 2),
        varint(value.len() as u64),
        value.to_vec(),
    ]
    .concat()
}
fn info(name: &str, dimensions: &[u64]) -> Vec<u8> {
    let shape: Vec<_> = dimensions
        .iter()
        .flat_map(|&n| bytes(1, &integer(1, n)))
        .collect();
    let tensor = [integer(1, 1), bytes(2, &shape)].concat();
    [bytes(1, name.as_bytes()), bytes(2, &bytes(1, &tensor))].concat()
}
fn weight(name: &str, dimensions: &[u64], values: &[f32]) -> Vec<u8> {
    bytes(
        5,
        &[
            dimensions.iter().flat_map(|&n| integer(1, n)).collect(),
            integer(2, 1),
            bytes(8, name.as_bytes()),
            bytes(
                9,
                &values
                    .iter()
                    .flat_map(|value| value.to_le_bytes())
                    .collect::<Vec<_>>(),
            ),
        ]
        .concat(),
    )
}
fn attribute(name: &str, kind: u64, payload: &[u8]) -> Vec<u8> {
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
fn int_attribute(name: &str, value: i64) -> Vec<u8> {
    attribute(name, 2, &integer(3, value as u64))
}
fn float_attribute(name: &str, value: f32) -> Vec<u8> {
    attribute(
        name,
        1,
        &[varint(2 * 8 + 5), value.to_le_bytes().to_vec()].concat(),
    )
}
fn node(op: &str, inputs: &[&str], output: &str, attributes: &[u8]) -> Vec<u8> {
    bytes(
        1,
        &[
            inputs
                .iter()
                .flat_map(|name| bytes(1, name.as_bytes()))
                .collect(),
            bytes(2, output.as_bytes()),
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
fn export<'a>(imported: &ImportedOnnx<'a>) -> Test<OnnxArtifacts<'a>> {
    Ok(export_onnx_artifacts(
        imported,
        OnnxExportLimits::default(),
        &|| false,
    )?)
}
fn parsed<'a>(artifacts: &'a OnnxArtifacts<'_>) -> Test<safetensors::Weights<'a>> {
    Ok(safetensors::Weights::parse(
        artifacts.weights_bytes(),
        &ImportLimits {
            maximum_header_bytes: 256 * 1024,
            maximum_tensors: 256,
        },
    )?)
}
fn reloaded(artifacts: &OnnxArtifacts<'_>) -> Test<BTreeMap<String, Tensor>> {
    let weights = parsed(artifacts)?;
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
fn run(artifacts: &OnnxArtifacts<'_>, input: &[(&str, Tensor)], output: &str) -> Test<Vec<f32>> {
    let graph = decode_canonical_model_ir(artifacts.graph_bytes(), artifacts.graph_digest())?;
    assert_eq!(encode_canonical_model_ir(&graph)?, artifacts.graph_bytes());
    let mut inputs: Vec<_> = reloaded(artifacts)?.into_iter().collect();
    inputs.extend(
        input
            .iter()
            .map(|(name, tensor)| ((*name).to_owned(), tensor.clone())),
    );
    let result = scalar_executor::ScalarExecutor::run(
        &graph,
        &inputs,
        scalar_executor::ExecBudget::unlimited(),
        &scalar_executor::ScalarExecCx::new(),
    )?;
    Ok(result
        .get_output(output)
        .ok_or("missing output")?
        .to_vec::<f32>()?)
}
fn bits(values: &[f32]) -> Vec<u32> {
    values.iter().map(|value| value.to_bits()).collect()
}
fn header_size(artifacts: &OnnxArtifacts<'_>) -> Test<usize> {
    Ok(usize::try_from(u64::from_le_bytes(
        artifacts.weights_bytes()[..8].try_into()?,
    ))?)
}

#[test]
fn rgb_dense_head_round_trips_exported_artifacts_through_native_execution() -> Test {
    assert_eq!(RGB.len(), 428);
    assert_eq!(
        ContentDigest::sha256(RGB).to_string(),
        "sha256:68213c84617ee3045aaa90a8d72d5a1686e9509d8a52b4b7ffb7cbe81b2b6d4f"
    );
    let imported = import(RGB)?;
    let artifacts = export(&imported)?;
    let input = Tensor::from_values(Shape::new(vec![1, 3, 1, 1])?, &[1_f32, 2., 3.], GENERATION)?;
    assert_eq!(
        run(&artifacts, &[("image", input)], "head")?,
        [0.125, 0.25, 0.75, 0.75, 0.875, 0.75]
    );
    assert_eq!(
        artifacts.graph_bytes(),
        encode_canonical_model_ir(imported.graph())?
    );
    assert_eq!(
        artifacts.graph_digest(),
        ContentDigest::sha256(artifacts.graph_bytes())
    );
    assert_eq!(
        artifacts.weights_digest(),
        ContentDigest::sha256(artifacts.weights_bytes())
    );
    assert_eq!(artifacts.importer_identity(), onnx_importer_identity());
    assert_eq!(artifacts.source(), RGB);
    assert_eq!(artifacts.source_digest(), ContentDigest::sha256(RGB));
    assert!(std::ptr::eq(artifacts.source().as_ptr(), RGB.as_ptr()));
    assert!(artifacts.work_units() > imported.work_units());
    Ok(())
}

#[test]
fn generated_gemm_parameters_and_scalars_survive_packaging_and_execution() -> Test {
    let source = model(
        &[
            node(
                "Gemm",
                &["image", "weights", "bias"],
                "head",
                &[float_attribute("alpha", 0.5), float_attribute("beta", 2.)].concat(),
            ),
            weight("weights", &[2, 3], &[1., 2., 3., 4., 5., 6.]),
            weight("bias", &[3], &[1., -2., 3.]),
            bytes(11, &info("image", &[1, 2])),
            bytes(12, &info("head", &[1, 3])),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    let artifacts = export(&imported)?;
    let decoded = reloaded(&artifacts)?;
    assert_eq!(decoded.len(), 4);
    for (name, tensor) in imported.parameters() {
        assert_eq!(
            bits(&decoded[name].to_vec::<f32>()?),
            bits(&tensor.to_vec::<f32>()?)
        );
        assert_eq!(decoded[name].shape(), tensor.shape());
    }
    let input = Tensor::from_values(Shape::new(vec![1, 2])?, &[2_f32, 3.], GENERATION)?;
    assert_eq!(
        run(&artifacts, &[("image", input)], "head")?,
        [9., 5.5, 18.]
    );
    Ok(())
}

#[test]
fn all_finite_f32_bits_including_signed_zero_and_subnormals_are_exact() -> Test {
    let values = [
        0.,
        -0.,
        f32::from_bits(1),
        f32::from_bits(0x8000_0001),
        f32::MIN_POSITIVE,
        f32::MAX,
        -f32::MAX,
    ];
    let source = model(
        &[
            node("Relu", &["values"], "output", &[]),
            weight("values", &[7], &values),
            bytes(12, &info("output", &[7])),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    let artifacts = export(&imported)?;
    let weights = parsed(&artifacts)?;
    assert_eq!(
        weights.data,
        values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        bits(&reloaded(&artifacts)?["values"].to_vec::<f32>()?),
        bits(&values)
    );
    Ok(())
}

#[test]
fn escaped_names_unicode_and_literal_unicode_escape_text_remain_distinct() -> Test {
    let names = ["weight\"\\🦀/", "literal\\u0061", "literala"];
    let source = model(
        &[
            node("Add", &["x", names[0]], "one", &[]),
            node("Add", &["one", names[1]], "two", &[]),
            node("Add", &["two", names[2]], "y", &[]),
            weight(names[0], &[1], &[1.]),
            weight(names[1], &[1], &[2.]),
            weight(names[2], &[1], &[4.]),
            bytes(11, &info("x", &[1])),
            bytes(12, &info("y", &[1])),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    let artifacts = export(&imported)?;
    let decoded = reloaded(&artifacts)?;
    assert_eq!(decoded.len(), 3);
    for (name, expected) in names.into_iter().zip([1., 2., 4.]) {
        assert_eq!(decoded[name].to_vec::<f32>()?, [expected]);
    }
    let raw = std::str::from_utf8(&artifacts.weights_bytes()[8..8 + header_size(&artifacts)?])?;
    assert!(raw.contains("weight\\\"\\\\🦀/"));
    assert!(raw.contains("literal\\\\u0061"));
    let input = Tensor::from_values(Shape::new(vec![1])?, &[8_f32], GENERATION)?;
    assert_eq!(run(&artifacts, &[("x", input)], "y")?, [15.]);
    Ok(())
}

#[test]
fn safetensors_reserved_metadata_parameter_refuses_without_renaming() -> Test {
    let source = model(
        &[
            node("Relu", &["__metadata__"], "output", &[]),
            weight("__metadata__", &[], &[2.]),
            bytes(12, &info("output", &[])),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    assert_eq!(
        export_onnx_artifacts(&imported, OnnxExportLimits::default(), &|| false).err(),
        Some(OnnxError::Unsupported)
    );
    Ok(())
}

#[test]
fn models_without_parameters_export_a_valid_empty_weights_container() -> Test {
    let source = model(
        &[
            node("Relu", &["x"], "y", &[]),
            bytes(11, &info("x", &[2])),
            bytes(12, &info("y", &[2])),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    let artifacts = export_onnx_artifacts(
        &imported,
        OnnxExportLimits {
            parameter_tensors: 0,
            ..Default::default()
        },
        &|| false,
    )?;
    let weights = parsed(&artifacts)?;
    assert!(weights.entries.is_empty());
    assert!(weights.data.is_empty());
    let input = Tensor::from_values(Shape::new(vec![2])?, &[-1_f32, 2.], GENERATION)?;
    assert_eq!(run(&artifacts, &[("x", input)], "y")?, [0., 2.]);
    Ok(())
}

#[test]
fn repeated_exports_have_identical_bytes_and_work_and_sorted_parameter_spans() -> Test {
    let imported = import(RGB)?;
    let first = export(&imported)?;
    let second = export(&imported)?;
    assert_eq!(first.graph_bytes(), second.graph_bytes());
    assert_eq!(first.weights_bytes(), second.weights_bytes());
    assert_eq!(first.work_units(), second.work_units());
    let weights = parsed(&first)?;
    assert_eq!(weights.entries["bias"].start, 0);
    assert_eq!(weights.entries["bias"].end, 24);
    assert_eq!(weights.entries["weights"].start, 24);
    assert_eq!(weights.entries["weights"].end, weights.data.len());
    Ok(())
}

#[test]
fn source_only_metadata_change_is_retained_and_bound_into_exported_weights() -> Test {
    let source_a = [RGB, bytes(4, b"example-a").as_slice()].concat();
    let source_b = [RGB, bytes(4, b"example-b").as_slice()].concat();
    let imported_a = import(&source_a)?;
    let imported_b = import(&source_b)?;
    let a = export(&imported_a)?;
    let b = export(&imported_b)?;
    assert_eq!(a.graph_bytes(), b.graph_bytes());
    assert_eq!(parsed(&a)?.data, parsed(&b)?.data);
    assert_ne!(a.weights_digest(), b.weights_digest());
    assert_ne!(a.source_digest(), b.source_digest());
    assert_eq!(a.source(), source_a);
    assert_eq!(b.source(), source_b);
    Ok(())
}

#[test]
fn exact_output_and_cumulative_work_boundaries_pass_and_one_less_refuses() -> Test {
    let imported = import(RGB)?;
    let artifacts = export(&imported)?;
    let exact = OnnxExportLimits {
        graph_bytes: artifacts.graph_bytes().len(),
        weights_bytes: artifacts.weights_bytes().len(),
        header_bytes: header_size(&artifacts)?,
        parameter_tensors: imported.parameters().len(),
        bundle_bytes: RGB.len() + artifacts.graph_bytes().len() + artifacts.weights_bytes().len(),
        work_units: artifacts.work_units(),
    };
    assert_eq!(
        export_onnx_artifacts(&imported, exact, &|| false)?.weights_bytes(),
        artifacts.weights_bytes()
    );
    for limits in [
        OnnxExportLimits {
            graph_bytes: exact.graph_bytes - 1,
            ..exact
        },
        OnnxExportLimits {
            weights_bytes: exact.weights_bytes - 1,
            ..exact
        },
        OnnxExportLimits {
            header_bytes: exact.header_bytes - 1,
            ..exact
        },
        OnnxExportLimits {
            parameter_tensors: exact.parameter_tensors - 1,
            ..exact
        },
        OnnxExportLimits {
            bundle_bytes: exact.bundle_bytes - 1,
            ..exact
        },
    ] {
        assert_eq!(
            export_onnx_artifacts(&imported, limits, &|| false).err(),
            Some(OnnxError::Limit)
        );
    }
    for work_units in [
        0,
        imported.work_units() - 1,
        imported.work_units(),
        exact.work_units - 1,
    ] {
        assert_eq!(
            export_onnx_artifacts(
                &imported,
                OnnxExportLimits {
                    work_units,
                    ..exact
                },
                &|| false
            )
            .err(),
            Some(OnnxError::WorkBudget)
        );
    }
    Ok(())
}

#[test]
fn caller_limits_cannot_expand_hard_profile_bounds() -> Test {
    let imported = import(RGB)?;
    let base = OnnxExportLimits::default();
    for limits in [
        OnnxExportLimits {
            graph_bytes: 0,
            ..base
        },
        OnnxExportLimits {
            weights_bytes: 0,
            ..base
        },
        OnnxExportLimits {
            header_bytes: 0,
            ..base
        },
        OnnxExportLimits {
            bundle_bytes: 0,
            ..base
        },
        OnnxExportLimits {
            graph_bytes: base.graph_bytes + 1,
            ..base
        },
        OnnxExportLimits {
            weights_bytes: base.weights_bytes + 1,
            ..base
        },
        OnnxExportLimits {
            header_bytes: base.header_bytes + 1,
            ..base
        },
        OnnxExportLimits {
            parameter_tensors: base.parameter_tensors + 1,
            ..base
        },
        OnnxExportLimits {
            bundle_bytes: base.bundle_bytes + 1,
            ..base
        },
    ] {
        assert_eq!(
            export_onnx_artifacts(&imported, limits, &|| false).err(),
            Some(OnnxError::Limit)
        );
    }
    Ok(())
}

#[test]
fn cancellation_stops_before_or_during_header_parameter_and_hash_traversal() -> Test {
    let values: Vec<_> = (0..32_769).map(|n| n as f32).collect();
    let source = model(
        &[
            node("Relu", &["values"], "output", &[]),
            weight("values", &[32_769], &values),
            bytes(12, &info("output", &[32_769])),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    let calls = Cell::new(0_usize);
    export_onnx_artifacts(&imported, OnnxExportLimits::default(), &|| {
        calls.set(calls.get() + 1);
        false
    })?;
    let complete = calls.get();
    assert!(complete > 40);
    for stop in [
        0,
        1,
        8,
        complete / 2,
        complete - 40,
        complete - 3,
        complete - 1,
    ] {
        calls.set(0);
        let result = export_onnx_artifacts(&imported, OnnxExportLimits::default(), &|| {
            let before = calls.get();
            calls.set(before + 1);
            before >= stop
        });
        assert_eq!(
            result.err(),
            Some(OnnxError::Cancelled),
            "checkpoint {stop}/{complete}"
        );
    }
    Ok(())
}

#[test]
fn canonical_default_normalization_is_measured_exactly_for_a_complete_cnn_head() -> Test {
    let source = model(
        &[
            node("Conv", &["image", "kernel"], "conv", &[]),
            node("Relu", &["conv"], "positive", &[]),
            node(
                "MaxPool",
                &["positive"],
                "pool",
                &attribute("kernel_shape", 7, &[integer(8, 2), integer(8, 2)].concat()),
            ),
            node("Transpose", &["pool"], "transposed", &[]),
            node("Flatten", &["transposed"], "flat", &[]),
            node("Gemm", &["flat", "dense"], "scores", &[]),
            node(
                "Concat",
                &["scores", "scores"],
                "both",
                &int_attribute("axis", -1),
            ),
            node("Softmax", &["both"], "head", &[]),
            weight("kernel", &[1, 3, 1, 1], &[1., 1., 1.]),
            weight("dense", &[1, 2], &[0.125, -0.125]),
            bytes(11, &info("image", &[1, 3, 2, 2])),
            bytes(12, &info("head", &[1, 4])),
        ]
        .concat(),
    );
    let imported = import(&source)?;
    let artifacts = export(&imported)?;
    let input = Tensor::from_values(
        Shape::new(vec![1, 3, 2, 2])?,
        &(0..12).map(|n| n as f32).collect::<Vec<_>>(),
        GENERATION,
    )?;
    let actual = run(&artifacts, &[("image", input.clone())], "head")?;
    let bindings: Vec<_> = imported
        .parameters()
        .iter()
        .map(|(n, t)| (n.clone(), t.clone()))
        .chain([("image".to_owned(), input)])
        .collect();
    let original = scalar_executor::ScalarExecutor::run(
        imported.graph(),
        &bindings,
        scalar_executor::ExecBudget::unlimited(),
        &scalar_executor::ScalarExecCx::new(),
    )?;
    assert_eq!(
        bits(&actual),
        bits(&original.get_output("head").ok_or("head")?.to_vec::<f32>()?)
    );
    assert_eq!(actual.len(), 4);
    assert_eq!(actual[0], actual[2]);
    assert!(actual[0] > actual[1]);
    assert!((actual.iter().sum::<f32>() - 1.).abs() < 1e-6);
    Ok(())
}
