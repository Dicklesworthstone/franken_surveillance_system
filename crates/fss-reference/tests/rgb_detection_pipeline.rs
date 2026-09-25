#![forbid(unsafe_code)]
//! Actual JPEG -> RGB -> Conv2d -> Reshape -> dense head -> source-space proposals.
//! Coefficients are explicit numeric fixtures, not a trained person detector.
use fss_codec_mjpeg::{ComponentInterpretation as Color, DecodeBudget};
use fss_core::{ContentDigest, Generation};
use fss_model_ir::{
    AttrValue, AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort,
};
use fss_reference::ingest::rgb_detections::pipeline::*;
use fss_reference::ingest::rgb_detections::*;
use fss_reference::ingest::rgb_inference::*;
use fss_reference::preprocess::{ResizeAspect, ResizeFilter};
use fss_reference::{ChannelTransform, ExecBudget, PreprocessProgram, ScalarExecCx};
use fss_tensor::{DType, Shape};
use std::collections::BTreeMap;
#[path = "../../fss-codec-mjpeg/tests/rgb_support/mod.rs"]
mod rgb_support;
type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn model(layout: HeadLayout) -> Test<RgbInferenceModel> {
    let generation = Generation(7);
    let image = Shape::new(vec![1, 3, 8, 8])?;
    let raw = Shape::new(vec![1, 6, 1, 1])?;
    let head_shape = match layout {
        HeadLayout::Channels => vec![1, 6, 1],
        HeadLayout::Rows => vec![1, 1, 6],
    };
    let mut reshape = AttributeMap::new();
    reshape.insert("shape".into(), AttrValue::IntList(head_shape.clone()));
    let graph = ModelIrGraph::new_validated(
        "model:dense-numeric-fixture",
        ModelIrVersion::V1,
        generation,
        vec![
            TensorPort::new("image", DType::F32, image, generation)?,
            TensorPort::new(
                "weight",
                DType::F32,
                Shape::new(vec![6, 3, 8, 8])?,
                generation,
            )?,
            TensorPort::new("bias", DType::F32, Shape::new(vec![6])?, generation)?,
        ],
        vec![
            TensorPort::new(
                "head",
                DType::F32,
                Shape::new(head_shape.iter().map(|n| *n as usize).collect::<Vec<_>>())?,
                generation,
            )?,
            TensorPort::new("raw", DType::F32, raw, generation)?,
        ],
        vec![
            GraphNode::new(
                "node:conv",
                OpCode::Conv2d,
                "numeric fixture: pixels affect corners and scores",
                vec!["image".into(), "weight".into(), "bias".into()],
                vec!["raw".into()],
                AttributeMap::new(),
            )?,
            GraphNode::new(
                "node:reshape",
                OpCode::Reshape,
                "explicit dense head axes",
                vec!["raw".into()],
                vec!["head".into()],
                reshape,
            )?,
        ],
    )?;
    let mut weight = vec![0.0; 6 * 3 * 64];
    // Same actually observed interior pixel drives x1, x2 and red/green class scores.
    for (field, channel) in [(0, 0), (2, 0), (4, 0), (5, 1)] {
        weight[(field * 3 + channel) * 64 + 3 * 8 + 1] = 1.0;
    }
    Ok(RgbInferenceModel::new(
        &graph,
        BTreeMap::from([
            ("weight".into(), weight),
            ("bias".into(), vec![1.0, 3.0, 3.0, 5.0, 0.0, 0.0]),
        ]),
        RgbModelSpec {
            image_input: "image".into(),
            preprocess: PreprocessProgram::new(8, 8, ChannelTransform::Rgb, true),
            filter: ResizeFilter::Bilinear,
            aspect: ResizeAspect::Letterbox(114),
            masked_rgb: [0; 3],
        },
        &ScalarExecCx::new(),
    )?)
}
fn spec(model: &RgbInferenceModel, layout: HeadLayout) -> RgbDetectionSpec {
    RgbDetectionSpec {
        model: model.digest(),
        output_port: "head".into(),
        labels: vec!["numeric-red".into(), "numeric-green".into()],
        layout,
        boxes: HeadBoxes::PixelCorners,
        class_score: HeadScore::Probability,
        objectness: None,
        classes: HeadClasses::Best,
        minimum_score_ppm: 500_000,
        nms_iou_ppm: 500_000,
        maximum_rows: 100,
        maximum_candidates: 100,
        maximum_detections: 100,
    }
}
fn limits() -> RgbRunLimits {
    RgbRunLimits {
        decode: Default::default(),
        preprocess: ExecBudget::new(10_000_000, 16 * 1024 * 1024),
        execution: ExecBudget::new(10_000_000, 64 * 1024 * 1024),
        maximum_output_bytes: 1024 * 1024,
    }
}
fn budget() -> RgbDetectionBudget {
    RgbDetectionBudget::new(100_000_000, 32 * 1024 * 1024)
}
fn jpeg(samples: &[[u8; 3]]) -> Vec<u8> {
    rgb_support::jpeg(16, 8, [1, 1], false, false, false, samples)
}
fn source(bytes: &[u8], allowed: &[u8], exposure: u8) -> RgbSourceBinding {
    RgbSourceBinding {
        encoded_sha256: ContentDigest::sha256(bytes).bytes(),
        exposure: [exposure; 32],
        camera: 1,
        clock: 2,
        capture: [10, 12],
        image_domain: [3; 32],
        calibration: [4; 32],
        permission_mask: ContentDigest::sha256(allowed).bytes(),
    }
}
fn input<'a>(bytes: &'a [u8], allowed: &'a [u8], exposure: u8) -> RgbDetectionInput<'a> {
    RgbDetectionInput {
        bytes,
        allowed,
        interpretation: Color::YCbCr,
        source: source(bytes, allowed, exposure),
        mask: &fss_reference::ingest::privacy_mask::live::NO_POLICY,
    }
}
fn run(
    detector: &mut RgbDetector<'_>,
    bytes: &[u8],
    allowed: &[u8],
    exposure: u8,
) -> Test<RgbDetectionRun> {
    match detector.run_jpeg(
        input(bytes, allowed, exposure),
        limits(),
        &mut DecodeBudget::new(100_000_000),
        &mut budget(),
        &ScalarExecCx::new(),
    )? {
        RgbDetectionStep::Complete(run) => Ok(run),
        RgbDetectionStep::Pending(e) => Err(e.into()),
    }
}
#[test]
fn source_chroma_changes_executed_class_and_box_not_just_receipt_hashes() -> Test {
    let model = model(HeadLayout::Channels)?;
    let contract = RgbDetectionContract::new(spec(&model, HeadLayout::Channels))?;
    let mut detector = RgbDetector::new(&model, &contract)?;
    let a = run(&mut detector, &jpeg(&[[100, 150, 200]]), &[1; 128], 1)?;
    let b = run(&mut detector, &jpeg(&[[100, 128, 64]]), &[1; 128], 2)?;
    assert_eq!(a.report().detections().len(), 1);
    assert_eq!(b.report().detections().len(), 1);
    assert_eq!(a.report().detections()[0].class_index(), 0);
    assert_eq!(b.report().detections()[0].class_index(), 1);
    assert_ne!(
        a.report().detections()[0].bounds(),
        b.report().detections()[0].bounds()
    );
    assert!(a.inference().executed_macs() > 0);
    assert_eq!(a.inference().outputs().len(), 2);
    assert_eq!(a.report().inference_identity(), a.inference().identity());
    assert_eq!(a.report().contract_digest(), contract.digest());
    assert_eq!(a.report().source(), a.inference().source());
    assert_eq!(a.report().source().capture, [10, 12]);
    assert_eq!(a.mask_copy_work(), 128);
    assert_eq!(a.allowed(), &[1; 128]);
    Ok(())
}
#[test]
fn rows_layout_is_executed_as_declared_without_shape_guessing() -> Test {
    let model = model(HeadLayout::Rows)?;
    let contract = RgbDetectionContract::new(spec(&model, HeadLayout::Rows))?;
    let result = run(
        &mut RgbDetector::new(&model, &contract)?,
        &jpeg(&[[100, 150, 200]]),
        &[1; 128],
        1,
    )?;
    assert_eq!(result.inference().outputs()["head"].shape(), [1, 1, 6]);
    assert_eq!(result.report().detections()[0].class_index(), 0);
    Ok(())
}
#[test]
fn postprocessing_pressure_retains_inference_blocks_new_input_and_resumes_without_decode() -> Test {
    let model = model(HeadLayout::Channels)?;
    let contract = RgbDetectionContract::new(spec(&model, HeadLayout::Channels))?;
    let mut detector = RgbDetector::new(&model, &contract)?;
    let bytes = jpeg(&[[100, 150, 200]]);
    let mut allowed = [1; 128];
    let mut decode = DecodeBudget::new(100_000_000);
    let cx = ScalarExecCx::new();
    assert!(matches!(
        detector.run_jpeg(
            input(&bytes, &allowed, 1),
            limits(),
            &mut decode,
            &mut RgbDetectionBudget::new(0, 32 * 1024 * 1024),
            &cx
        )?,
        RgbDetectionStep::Pending(RgbDetectionError::BudgetExceeded)
    ));
    let identity = detector
        .pending()
        .ok_or("lost pending")?
        .inference()
        .identity();
    let used = decode.used();
    allowed.fill(0); // Owner-retained mask must not alias this changed source buffer.
    assert!(matches!(
        detector.run_jpeg(
            input(&bytes, &allowed, 2),
            limits(),
            &mut decode,
            &mut budget(),
            &cx
        ),
        Err(RgbDetectorError::PendingFrame)
    ));
    assert_eq!(decode.used(), used);
    assert_eq!(
        detector
            .pending()
            .ok_or("lost pending")?
            .inference()
            .identity(),
        identity
    );
    let RgbDetectionStep::Complete(result) = detector.resume(&mut budget(), &cx)? else {
        return Err("resume failed".into());
    };
    assert_eq!(result.inference().identity(), identity);
    assert_eq!(result.allowed(), &[1; 128]);
    assert_eq!(result.report().detections().len(), 1);
    assert_eq!(decode.used(), used);
    assert!(detector.pending().is_none());
    assert!(matches!(
        detector.resume(&mut budget(), &cx),
        Err(RgbDetectorError::NoPendingFrame)
    ));
    Ok(())
}
#[test]
fn direct_projection_and_owned_pipeline_have_identical_receipts() -> Test {
    let model = model(HeadLayout::Channels)?;
    let contract = RgbDetectionContract::new(spec(&model, HeadLayout::Channels))?;
    let bytes = jpeg(&[[100, 150, 200]]);
    let mask = [1; 128];
    let cx = ScalarExecCx::new();
    let inference = model.run_jpeg(
        &bytes,
        Color::YCbCr,
        source(&bytes, &mask, 1),
        &mask,
        limits(),
        &mut DecodeBudget::new(100_000_000),
        &cx,
    )?;
    let direct = project_rgb_detections(&inference, &contract, &mask, &mut budget(), &cx)?;
    let composed = run(&mut RgbDetector::new(&model, &contract)?, &bytes, &mask, 1)?;
    assert_eq!(direct.digest(), composed.report().digest());
    assert_eq!(inference.identity(), composed.inference().identity());
    Ok(())
}
#[test]
fn denied_source_changes_leave_proposals_unchanged_but_keep_distinct_source_provenance() -> Test {
    let model = model(HeadLayout::Channels)?;
    let contract = RgbDetectionContract::new(spec(&model, HeadLayout::Channels))?;
    let a = jpeg(&[[100, 150, 200], [10, 20, 30]]);
    let b = jpeg(&[[100, 150, 200], [230, 220, 210]]);
    let mask: Vec<_> = (0..128).map(|i| u8::from(i % 16 < 8)).collect();
    let mut detector = RgbDetector::new(&model, &contract)?;
    let a = run(&mut detector, &a, &mask, 1)?;
    let b = run(&mut detector, &b, &mask, 2)?;
    assert_eq!(a.inference().input_digest(), b.inference().input_digest());
    assert_eq!(a.report().detections(), b.report().detections());
    assert_eq!(a.report().detections().len(), 1);
    assert_ne!(a.report().digest(), b.report().digest());
    Ok(())
}
#[test]
fn model_proposals_touching_denied_pixels_are_not_promoted() -> Test {
    let model = model(HeadLayout::Channels)?;
    let contract = RgbDetectionContract::new(spec(&model, HeadLayout::Channels))?;
    let mut mask = [1; 128];
    mask[5 * 16 + 5] = 0; // Away from sampled convolution pixel, within predicted box.
    let result = run(
        &mut RgbDetector::new(&model, &contract)?,
        &jpeg(&[[100, 150, 200]]),
        &mask,
        1,
    )?;
    assert_eq!(
        result.report().rows()[0].disposition,
        HeadRowDisposition::PrivateFootprint
    );
    assert!(result.report().detections().is_empty());
    Ok(())
}
#[test]
fn malformed_head_keeps_complete_inference_for_explicit_retirement() -> Test {
    let model = model(HeadLayout::Channels)?;
    let contract = RgbDetectionContract::new(RgbDetectionSpec {
        output_port: "raw".into(),
        ..spec(&model, HeadLayout::Channels)
    })?;
    let mut detector = RgbDetector::new(&model, &contract)?;
    let bytes = jpeg(&[[100, 150, 200]]);
    assert!(matches!(
        detector.run_jpeg(
            input(&bytes, &[1; 128], 1),
            limits(),
            &mut DecodeBudget::new(100_000_000),
            &mut budget(),
            &ScalarExecCx::new()
        )?,
        RgbDetectionStep::Pending(RgbDetectionError::InvalidOutput)
    ));
    let pending = detector.retire().ok_or("lost failed-stage input")?;
    assert_eq!(pending.inference().outputs().len(), 2);
    assert_eq!(pending.mask_copy_work(), 128);
    let (inference, mask) = pending.into_parts();
    let valid = RgbDetectionContract::new(spec(&model, HeadLayout::Channels))?;
    assert_eq!(
        project_rgb_detections(
            &inference,
            &valid,
            &mask,
            &mut budget(),
            &ScalarExecCx::new()
        )?
        .detections()
        .len(),
        1
    );
    Ok(())
}
#[test]
fn cancelled_projection_retains_the_pending_result_and_permissions() -> Test {
    let model = model(HeadLayout::Channels)?;
    let contract = RgbDetectionContract::new(spec(&model, HeadLayout::Channels))?;
    let mut detector = RgbDetector::new(&model, &contract)?;
    let bytes = jpeg(&[[100, 150, 200]]);
    let _step = detector.run_jpeg(
        input(&bytes, &[1; 128], 1),
        limits(),
        &mut DecodeBudget::new(100_000_000),
        &mut RgbDetectionBudget::new(0, 32 * 1024 * 1024),
        &ScalarExecCx::new(),
    )?;
    let original = detector
        .pending()
        .ok_or("missing pending")?
        .inference()
        .identity();
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    assert!(matches!(
        detector.resume(&mut budget(), &cx)?,
        RgbDetectionStep::Pending(RgbDetectionError::Cancelled)
    ));
    let pending = detector.retire().ok_or("lost cancellation evidence")?;
    assert_eq!(pending.inference().identity(), original);
    assert_eq!(pending.allowed(), &[1; 128]);
    Ok(())
}
#[test]
fn invalid_source_mask_reservation_and_model_contract_fail_before_acceptance() -> Test {
    let model = model(HeadLayout::Channels)?;
    let contract = RgbDetectionContract::new(spec(&model, HeadLayout::Channels))?;
    let other = RgbDetectionContract::new(RgbDetectionSpec {
        model: ContentDigest::sha256(b"other-model"),
        ..spec(&model, HeadLayout::Channels)
    })?;
    assert!(matches!(
        RgbDetector::new(&model, &other),
        Err(RgbDetectorError::ModelContractMismatch)
    ));
    let mut detector = RgbDetector::new(&model, &contract)?;
    let bytes = jpeg(&[[100, 150, 200]]);
    let mut decoder = DecodeBudget::new(100_000_000);
    let mut low = limits();
    low.preprocess.max_bytes = 1;
    assert!(matches!(
        detector.run_jpeg(
            input(&bytes, &[1; 128], 1),
            low,
            &mut decoder,
            &mut budget(),
            &ScalarExecCx::new()
        ),
        Err(RgbDetectorError::InputLimit)
    ));
    assert_eq!(decoder.used(), 0);
    assert!(
        detector
            .run_jpeg(
                input(b"not jpeg", &[1; 128], 1),
                limits(),
                &mut decoder,
                &mut budget(),
                &ScalarExecCx::new()
            )
            .is_err()
    );
    assert!(detector.pending().is_none());
    Ok(())
}
#[test]
fn all_public_projection_budget_cuts_preserve_inputs_and_reproduce_receipts() -> Test {
    let model = model(HeadLayout::Channels)?;
    let contract = RgbDetectionContract::new(spec(&model, HeadLayout::Channels))?;
    let bytes = jpeg(&[[100, 150, 200]]);
    let mask = [1; 128];
    let cx = ScalarExecCx::new();
    let inference = model.run_jpeg(
        &bytes,
        Color::YCbCr,
        source(&bytes, &mask, 1),
        &mask,
        limits(),
        &mut DecodeBudget::new(100_000_000),
        &cx,
    )?;
    let original = inference.identity();
    let mut full = budget();
    let expected = project_rgb_detections(&inference, &contract, &mask, &mut full, &cx)?;
    for limit in 0..full.used() {
        assert!(matches!(
            project_rgb_detections(
                &inference,
                &contract,
                &mask,
                &mut RgbDetectionBudget::new(limit, 32 * 1024 * 1024),
                &cx
            ),
            Err(RgbDetectionError::BudgetExceeded)
        ));
        assert_eq!(inference.identity(), original);
    }
    assert_eq!(
        project_rgb_detections(&inference, &contract, &mask, &mut budget(), &cx)?.digest(),
        expected.digest()
    );
    let mut changed = mask;
    changed[0] = 0;
    assert!(matches!(
        project_rgb_detections(&inference, &contract, &changed, &mut budget(), &cx),
        Err(RgbDetectionError::MaskMismatch)
    ));
    Ok(())
}
