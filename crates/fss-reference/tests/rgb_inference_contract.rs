#![forbid(unsafe_code)]
//! Native JPEG -> masked RGB -> resizing -> actual Conv2d/Sigmoid execution.
//! The explicit numeric weights are fixtures, not a trained detector or quality claim.
use fss_codec_mjpeg::{ComponentInterpretation as Color, DecodeBudget};
use fss_core::{ContentDigest, Generation};
use fss_model_ir::{AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort};
use fss_reference::ingest::rgb_inference::*;
use fss_reference::preprocess::{ResizeAspect, ResizeFilter};
use fss_reference::scalar_executor::deterministic_sigmoid_f32;
use fss_reference::{ChannelTransform, ExecBudget, PreprocessProgram, ScalarExecCx};
use fss_tensor::{DType, Shape};
use std::collections::BTreeMap;
#[path = "../../fss-codec-mjpeg/tests/rgb_support/mod.rs"]
mod rgb_support;
type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn graph() -> Test<ModelIrGraph> {
    let generation = Generation(3);
    let image = Shape::new(vec![1, 3, 8, 8])?;
    let output = Shape::new(vec![1, 2, 8, 8])?;
    Ok(ModelIrGraph::new_validated(
        "model:rgb-numeric-fixture",
        ModelIrVersion::V1,
        generation,
        vec![
            TensorPort::new("image", DType::F32, image, generation)?,
            TensorPort::new(
                "weights",
                DType::F32,
                Shape::new(vec![2, 3, 1, 1])?,
                generation,
            )?,
        ],
        vec![
            TensorPort::new("features", DType::F32, output.clone(), generation)?,
            TensorPort::new("scores", DType::F32, output, generation)?,
        ],
        vec![
            GraphNode::new(
                "node:conv",
                OpCode::Conv2d,
                "numeric fixture: select red and green",
                vec!["image".to_owned(), "weights".to_owned()],
                vec!["features".to_owned()],
                AttributeMap::new(),
            )?,
            GraphNode::new(
                "node:sigmoid",
                OpCode::Sigmoid,
                "numeric fixture, not calibrated confidence",
                vec!["features".to_owned()],
                vec!["scores".to_owned()],
                AttributeMap::new(),
            )?,
        ],
    )?)
}
fn spec() -> RgbModelSpec {
    RgbModelSpec {
        image_input: "image".to_owned(),
        preprocess: PreprocessProgram::new(8, 8, ChannelTransform::Rgb, true),
        filter: ResizeFilter::Bilinear,
        aspect: ResizeAspect::Stretch,
        masked_rgb: [0; 3],
    }
}
fn parameters() -> BTreeMap<String, Vec<f32>> {
    BTreeMap::from([("weights".to_owned(), vec![1.0, 0.0, 0.0, 0.0, 1.0, 0.0])])
}
fn model() -> Test<RgbInferenceModel> {
    Ok(RgbInferenceModel::new(
        &graph()?,
        parameters(),
        spec(),
        &ScalarExecCx::new(),
    )?)
}
fn limits() -> RgbRunLimits {
    RgbRunLimits {
        decode: Default::default(),
        preprocess: ExecBudget::new(10_000_000, 16 * 1024 * 1024),
        execution: ExecBudget::new(10_000_000, 64 * 1024 * 1024),
        maximum_output_bytes: 1024 * 1024,
    }
}
fn source(bytes: &[u8], mask: &[u8]) -> RgbSourceBinding {
    RgbSourceBinding {
        encoded_sha256: ContentDigest::sha256(bytes).bytes(),
        exposure: [1; 32],
        camera: 1,
        clock: 2,
        capture: [10, 12],
        image_domain: [3; 32],
        calibration: [4; 32],
        permission_mask: ContentDigest::sha256(mask).bytes(),
    }
}
fn run(model: &RgbInferenceModel, bytes: &[u8], mask: &[u8]) -> Test<RgbInference> {
    Ok(model.run_jpeg(
        bytes,
        Color::YCbCr,
        source(bytes, mask),
        mask,
        limits(),
        &mut DecodeBudget::new(100_000_000),
        &ScalarExecCx::new(),
    )?)
}
fn jpeg(samples: &[[u8; 3]]) -> Vec<u8> {
    rgb_support::jpeg(16, 8, [1, 1], false, false, false, samples)
}
#[test]
fn full_pipeline_reconstructs_color_and_runs_real_convolution_and_activation() -> Test {
    let model = model()?;
    let bytes = jpeg(&[[100, 150, 200]]);
    let mask = [1; 128];
    let result = run(&model, &bytes, &mask)?;
    let features = result
        .outputs()
        .get("features")
        .ok_or("missing convolution output")?;
    let scores = result
        .outputs()
        .get("scores")
        .ok_or("missing activation output")?;
    assert_eq!(features.shape(), [1, 2, 8, 8]);
    let r = 201.0_f32 * (1.0_f32 / 255.0);
    let g = 41.0_f32 * (1.0_f32 / 255.0);
    assert!(features.values()[..64].iter().all(|v| *v == r));
    assert!(features.values()[64..].iter().all(|v| *v == g));
    assert!(
        scores.values()[..64]
            .iter()
            .all(|v| *v == deterministic_sigmoid_f32(r))
    );
    assert!(
        scores.values()[64..]
            .iter()
            .all(|v| *v == deterministic_sigmoid_f32(g))
    );
    assert_eq!(result.source(), source(&bytes, &mask));
    assert_eq!(
        result.decode_receipt().encoded_sha256,
        ContentDigest::sha256(&bytes).bytes()
    );
    assert_eq!(result.model_digest(), model.digest());
    assert_eq!(result.executed_macs(), 512);
    Ok(())
}
#[test]
fn equal_luma_different_chroma_changes_neural_outputs() -> Test {
    let model = model()?;
    let mask = [1; 128];
    let neutral = jpeg(&[[100, 128, 128]]);
    let colored = jpeg(&[[100, 150, 200]]);
    let a = run(&model, &neutral, &mask)?;
    let b = run(&model, &colored, &mask)?;
    assert_ne!(a.output_digest(), b.output_digest());
    assert_ne!(a.input_digest(), b.input_digest());
    Ok(())
}
#[test]
fn denied_source_changes_do_not_reach_interpolation_or_neural_inputs() -> Test {
    let model = model()?;
    let a = jpeg(&[[100, 150, 200], [10, 20, 30]]);
    let b = jpeg(&[[100, 150, 200], [230, 220, 210]]);
    let mask: Vec<_> = (0..128).map(|i| u8::from(i % 16 < 8)).collect();
    let a = run(&model, &a, &mask)?;
    let b = run(&model, &b, &mask)?;
    assert_ne!(a.decode_receipt().rgb_sha256, b.decode_receipt().rgb_sha256);
    assert_eq!(a.masked_digest(), b.masked_digest());
    assert_eq!(a.input_digest(), b.input_digest());
    assert_eq!(a.output_digest(), b.output_digest());
    assert_ne!(a.identity(), b.identity()); // Original source custody is never erased by masking.
    Ok(())
}
#[test]
fn fully_masked_inputs_use_explicit_fill_not_private_pixels() -> Test {
    let model = model()?;
    let mask = [0; 128];
    let a = run(&model, &jpeg(&[[100, 150, 200]]), &mask)?;
    let b = run(&model, &jpeg(&[[230, 90, 20]]), &mask)?;
    assert_eq!(a.output_digest(), b.output_digest());
    assert!(a.outputs()["features"].values().iter().all(|v| *v == 0.0));
    assert!(a.outputs()["scores"].values().iter().all(|v| *v == 0.5));
    Ok(())
}
#[test]
fn letterbox_reversal_retains_exact_source_geometry_and_rejects_padding_only_boxes() -> Test {
    let mut s = spec();
    s.aspect = ResizeAspect::Letterbox(114);
    let model = RgbInferenceModel::new(&graph()?, parameters(), s, &ScalarExecCx::new())?;
    let result = run(&model, &jpeg(&[[100, 150, 200]]), &[1; 128])?;
    let g = result.geometry();
    assert_eq!((g.image_width, g.image_height, g.left, g.top), (8, 4, 0, 2));
    assert_eq!(
        g.source_box([0.0, 2.0, 8.0, 6.0]),
        Some([0.0, 0.0, 16.0, 8.0])
    );
    assert_eq!(g.source_box([0.0, 0.0, 8.0, 1.0]), None);
    assert_eq!(result.source().capture, [10, 12]);
    Ok(())
}
#[test]
fn missing_extra_wrong_length_and_nonfinite_parameters_are_refused() -> Test {
    let graph = graph()?;
    for p in [
        BTreeMap::new(),
        BTreeMap::from([("unknown".to_owned(), vec![0.0; 6])]),
        BTreeMap::from([("weights".to_owned(), vec![0.0; 5])]),
        BTreeMap::from([("weights".to_owned(), vec![f32::NAN; 6])]),
    ] {
        assert!(RgbInferenceModel::new(&graph, p, spec(), &ScalarExecCx::new()).is_err());
    }
    let mut wrong = spec();
    wrong.preprocess.channel_transform = ChannelTransform::LumaOnly;
    assert!(RgbInferenceModel::new(&graph, parameters(), wrong, &ScalarExecCx::new()).is_err());
    let mut wrong = spec();
    wrong.preprocess.target_width = 9;
    assert!(RgbInferenceModel::new(&graph, parameters(), wrong, &ScalarExecCx::new()).is_err());
    Ok(())
}
#[test]
fn model_identity_pins_every_parameter_and_preprocessing_choice() -> Test {
    let graph = graph()?;
    let original = model()?;
    let mut changed_parameters = parameters();
    changed_parameters
        .get_mut("weights")
        .ok_or("missing weight")?[0] = 2.0;
    let other = RgbInferenceModel::new(&graph, changed_parameters, spec(), &ScalarExecCx::new())?;
    assert_ne!(original.digest(), other.digest());
    let mut changed = spec();
    changed.masked_rgb = [114; 3];
    let mask = RgbInferenceModel::new(&graph, parameters(), changed, &ScalarExecCx::new())?;
    assert_ne!(original.digest(), mask.digest());
    Ok(())
}
#[test]
fn source_and_mask_digest_failures_cannot_return_successful_tensors() -> Test {
    let model = model()?;
    let bytes = jpeg(&[[100, 150, 200]]);
    let mask = [1; 128];
    let good = source(&bytes, &mask);
    for binding in [
        RgbSourceBinding {
            permission_mask: [8; 32],
            ..good
        },
        RgbSourceBinding {
            encoded_sha256: [8; 32],
            ..good
        },
        RgbSourceBinding {
            capture: [12, 10],
            ..good
        },
    ] {
        assert!(
            model
                .run_jpeg(
                    &bytes,
                    Color::YCbCr,
                    binding,
                    &mask,
                    limits(),
                    &mut DecodeBudget::new(100_000_000),
                    &ScalarExecCx::new()
                )
                .is_err()
        );
    }
    let mask = [2; 128];
    assert!(
        model
            .run_jpeg(
                &bytes,
                Color::YCbCr,
                source(&bytes, &mask),
                &mask,
                limits(),
                &mut DecodeBudget::new(100_000_000),
                &ScalarExecCx::new()
            )
            .is_err()
    );
    Ok(())
}
#[test]
fn each_resource_boundary_refuses_and_retry_does_not_change_results() -> Test {
    let model = model()?;
    let bytes = jpeg(&[[100, 150, 200]]);
    let mask = [1; 128];
    let original = run(&model, &bytes, &mask)?;
    let mut decode = limits();
    decode.decode.maximum_output_bytes = 1;
    let mut preprocessing = limits();
    preprocessing.preprocess = ExecBudget::new(1, 1);
    let mut execution = limits();
    execution.execution.max_macs = 1;
    let mut output = limits();
    output.maximum_output_bytes = 1;
    for limit in [decode, preprocessing, execution, output] {
        assert!(
            model
                .run_jpeg(
                    &bytes,
                    Color::YCbCr,
                    source(&bytes, &mask),
                    &mask,
                    limit,
                    &mut DecodeBudget::new(100_000_000),
                    &ScalarExecCx::new()
                )
                .is_err()
        );
        assert_eq!(run(&model, &bytes, &mask)?.identity(), original.identity());
    }
    Ok(())
}
#[test]
fn cancellation_precedes_decode_and_budget_sizes_do_not_change_identity() -> Test {
    let model = model()?;
    let bytes = jpeg(&[[100, 150, 200]]);
    let mask = [1; 128];
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    let mut decoder = DecodeBudget::new(100_000_000);
    assert!(
        model
            .run_jpeg(
                &bytes,
                Color::YCbCr,
                source(&bytes, &mask),
                &mask,
                limits(),
                &mut decoder,
                &cx
            )
            .is_err()
    );
    assert_eq!(decoder.used(), 0);
    let original = run(&model, &bytes, &mask)?;
    let mut more = limits();
    more.execution.max_macs *= 2;
    more.preprocess.max_macs *= 2;
    let retry = model.run_jpeg(
        &bytes,
        Color::YCbCr,
        source(&bytes, &mask),
        &mask,
        more,
        &mut DecodeBudget::new(100_000_000),
        &ScalarExecCx::new(),
    )?;
    assert_eq!(retry.identity(), original.identity());
    Ok(())
}

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId};
use fss_reference::ReplayCx;
use fss_reference::ingest::model_import::rgb::{
    ImportedRgbModel, RgbImportError, RgbModelImportRequest,
};
use fss_reference::ingest::model_import::{
    ImportBudget, ImportError, ImportLimits, WeightFloatPolicy,
};
fn import_context() -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rgb-import-test".to_owned(),
        operation_id: OperationId::parse("operation:rgb-import-test")?,
        principal: "principal:rgb-import-test".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(b"site:rgb-import-test"),
        generation: 1,
    })?;
    // No test file is created or read: import consumes only the explicit borrowed bytes.
    Ok(ReplayCx::from_context_authority(
        &authority,
        std::env::temp_dir(),
    )?)
}
fn source_weights(dtype: &str, name: &str, data: &[u8]) -> Vec<u8> {
    let header = format!(
        "{{\"__metadata__\":{{\"fixture\":\"numeric control, not trained\"}},\"{name}\":{{\"dtype\":\"{dtype}\",\"shape\":[2,3,1,1],\"data_offsets\":[0,{}]}}}}",
        data.len()
    );
    let mut out = (header.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(data);
    out
}
fn weight_request<'a>(
    graph: &'a [u8],
    weights: &'a [u8],
    float_policy: WeightFloatPolicy,
) -> RgbModelImportRequest<'a> {
    RgbModelImportRequest {
        graph,
        graph_digest: ContentDigest::sha256(graph),
        weights,
        weights_digest: ContentDigest::sha256(weights),
        spec: spec(),
        float_policy,
        bindings: BTreeMap::new(),
    }
}
#[test]
fn actual_safetensors_parameters_reach_color_convolution_and_keep_original_sources() -> Test {
    let graph = fss_model_ir::encode_canonical_model_ir(&graph()?)?;
    let values = parameters()
        .remove("weights")
        .ok_or("missing fixture weights")?;
    let data: Vec<u8> = values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    let weights = source_weights("F32", "weights", &data);
    let request = weight_request(&graph, &weights, WeightFloatPolicy::F32Only);
    let imported = ImportedRgbModel::build(
        &request,
        ImportLimits::default(),
        &mut ImportBudget::new(100_000_000),
        &import_context()?,
        &ScalarExecCx::new(),
    )?;
    assert_eq!(imported.graph_source(), graph);
    assert_eq!(imported.weights_source(), weights);
    assert_eq!(imported.expanded_bytes(), 24);
    assert_eq!(imported.model().digest(), model()?.digest());
    let bytes = jpeg(&[[100, 150, 200]]);
    assert_eq!(
        run(imported.model(), &bytes, &[1; 128])?.output_digest(),
        run(&model()?, &bytes, &[1; 128])?.output_digest()
    );
    Ok(())
}
#[test]
fn float16_and_bfloat16_expand_exactly_without_changing_rgb_model_values() -> Test {
    let graph = fss_model_ir::encode_canonical_model_ir(&graph()?)?;
    let cx = import_context()?;
    let expected = model()?.digest();
    for (dtype, one) in [("F16", 0x3c00_u16), ("BF16", 0x3f80_u16)] {
        let data: Vec<u8> = [one, 0, 0, 0, one, 0]
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        let weights = source_weights(dtype, "weights", &data);
        let request = weight_request(&graph, &weights, WeightFloatPolicy::ExpandFloat16);
        let imported = ImportedRgbModel::build(
            &request,
            ImportLimits::default(),
            &mut ImportBudget::new(100_000_000),
            &cx,
            &ScalarExecCx::new(),
        )?;
        assert_eq!(imported.model().digest(), expected);
        assert_eq!(imported.weights_source(), weights);
        let refused = weight_request(&graph, &weights, WeightFloatPolicy::F32Only);
        assert!(matches!(
            ImportedRgbModel::build(
                &refused,
                ImportLimits::default(),
                &mut ImportBudget::new(100_000_000),
                &cx,
                &ScalarExecCx::new()
            ),
            Err(RgbImportError::Import(ImportError::UnsupportedDType))
        ));
    }
    Ok(())
}
#[test]
fn explicit_weight_names_require_complete_binding_without_hidden_discard() -> Test {
    let graph = fss_model_ir::encode_canonical_model_ir(&graph()?)?;
    let data: Vec<u8> = parameters()["weights"]
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    let weights = source_weights("F32", "conv.weight", &data);
    let cx = import_context()?;
    let mut request = weight_request(&graph, &weights, WeightFloatPolicy::F32Only);
    assert!(
        ImportedRgbModel::build(
            &request,
            ImportLimits::default(),
            &mut ImportBudget::new(100_000_000),
            &cx,
            &ScalarExecCx::new()
        )
        .is_err()
    );
    request
        .bindings
        .insert("weights".to_owned(), "conv.weight".to_owned());
    let imported = ImportedRgbModel::build(
        &request,
        ImportLimits::default(),
        &mut ImportBudget::new(100_000_000),
        &cx,
        &ScalarExecCx::new(),
    )?;
    assert_eq!(imported.model().digest(), model()?.digest());
    assert_eq!(imported.bindings()["weights"], "conv.weight");
    request
        .bindings
        .insert("extra".to_owned(), "conv.weight".to_owned());
    assert!(
        ImportedRgbModel::build(
            &request,
            ImportLimits::default(),
            &mut ImportBudget::new(100_000_000),
            &cx,
            &ScalarExecCx::new()
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn malformed_digest_suffix_and_nonfinite_weight_inputs_cannot_become_models() -> Test {
    let graph = fss_model_ir::encode_canonical_model_ir(&graph()?)?;
    let data: Vec<u8> = parameters()["weights"]
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    let weights = source_weights("F32", "weights", &data);
    let cx = import_context()?;
    let mut request = weight_request(&graph, &weights, WeightFloatPolicy::F32Only);
    request.weights_digest = ContentDigest::sha256(b"wrong source");
    assert!(matches!(
        ImportedRgbModel::build(
            &request,
            ImportLimits::default(),
            &mut ImportBudget::new(100_000_000),
            &cx,
            &ScalarExecCx::new()
        ),
        Err(RgbImportError::Import(ImportError::DigestMismatch))
    ));
    let mut suffix = weights.clone();
    suffix.push(0);
    let mut bad_data = data.clone();
    bad_data[..4].copy_from_slice(&f32::INFINITY.to_le_bytes());
    for malformed in [
        suffix,
        source_weights("F32", "weights", &bad_data),
        weights[..7].to_vec(),
    ] {
        let request = weight_request(&graph, &malformed, WeightFloatPolicy::F32Only);
        assert!(
            ImportedRgbModel::build(
                &request,
                ImportLimits::default(),
                &mut ImportBudget::new(100_000_000),
                &cx,
                &ScalarExecCx::new()
            )
            .is_err()
        );
    }
    Ok(())
}
#[test]
fn import_limit_budget_and_cancellation_refusals_leave_sources_retryable() -> Test {
    let graph = fss_model_ir::encode_canonical_model_ir(&graph()?)?;
    let data: Vec<u8> = parameters()["weights"]
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    let weights = source_weights("F32", "weights", &data);
    let cx = import_context()?;
    let request = weight_request(&graph, &weights, WeightFloatPolicy::F32Only);
    let small = ImportLimits {
        maximum_expanded_bytes: 23,
        ..ImportLimits::default()
    };
    assert!(
        ImportedRgbModel::build(
            &request,
            small,
            &mut ImportBudget::new(100_000_000),
            &cx,
            &ScalarExecCx::new()
        )
        .is_err()
    );
    assert!(matches!(
        ImportedRgbModel::build(
            &request,
            ImportLimits::default(),
            &mut ImportBudget::new(0),
            &cx,
            &ScalarExecCx::new()
        ),
        Err(RgbImportError::Import(ImportError::BudgetExceeded))
    ));
    let cancelled = ScalarExecCx::new();
    cancelled.request_cancellation();
    assert!(
        ImportedRgbModel::build(
            &request,
            ImportLimits::default(),
            &mut ImportBudget::new(100_000_000),
            &cx,
            &cancelled
        )
        .is_err()
    );
    let a = ImportedRgbModel::build(
        &request,
        ImportLimits::default(),
        &mut ImportBudget::new(100_000_000),
        &cx,
        &ScalarExecCx::new(),
    )?;
    let b = ImportedRgbModel::build(
        &request,
        ImportLimits::default(),
        &mut ImportBudget::new(100_000_000),
        &cx,
        &ScalarExecCx::new(),
    )?;
    assert_eq!(a.identity(), b.identity());
    assert_eq!(a.weights_source(), weights);
    Ok(())
}
