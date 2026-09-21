#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Actual JPEG/convolution fixtures. Coefficients are not a trained detector.
use std::collections::BTreeMap;
use fss_codec_mjpeg::{ComponentInterpretation as Color, DecodeBudget};
use fss_core::{ContentDigest, Generation};
use fss_geometry::WorkBudget;
use fss_model_ir::{AttrValue, AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort};
use fss_reference::{ChannelTransform, ExecBudget, PreprocessProgram, ScalarExecCx};
use fss_reference::preprocess::{ResizeAspect, ResizeFilter};
use fss_reference::ingest::rgb_inference::*;
use fss_reference::ingest::rgb_detections::*;
use fss_reference::ingest::rgb_detections::pipeline::*;
use fss_reference::ingest::rgb_tracking::*;
use fss_tensor::{DType, Shape};
use fss_twin::image_tracking::{ImageTrackingPolicy, TrackingAvailability};
use fss_twin::image_zones::{ImageZoneBasis, ImageZonePolicy, ImageZoneSpec};
#[path = "../../../fss-codec-mjpeg/tests/rgb_support/mod.rs"]
mod jpeg_support;
pub type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub const WORK: u64 = 100_000_000;
pub fn model(rows: usize) -> Test<RgbInferenceModel> {
    let g = Generation(7); let fields = rows * 6;
    let mut shape = AttributeMap::new();
    shape.insert("shape".into(), AttrValue::IntList(vec![1, rows as i64, 6]));
    let graph = ModelIrGraph::new_validated("model:rgb-zone-numeric", ModelIrVersion::V1, g,
        vec![TensorPort::new("image", DType::F32, Shape::new(vec![1, 3, 8, 8])?, g)?,
            TensorPort::new("weight", DType::F32, Shape::new(vec![fields, 3, 8, 8])?, g)?,
            TensorPort::new("bias", DType::F32, Shape::new(vec![fields])?, g)?],
        vec![TensorPort::new("head", DType::F32, Shape::new(vec![1, rows, 6])?, g)?],
        vec![GraphNode::new("node:conv", OpCode::Conv2d, "pixels move a numeric box",
            vec!["image".into(), "weight".into(), "bias".into()], vec!["raw".into()], AttributeMap::new())?,
            GraphNode::new("node:shape", OpCode::Reshape, "explicit rows",
                vec!["raw".into()], vec!["head".into()], shape)?])?;
    let mut weights = vec![0.0; fields * 3 * 64]; let mut biases = Vec::new();
    for row in 0..rows {
        for field in [row * 6, row * 6 + 2] { weights[field * 3 * 64 + 3 * 8 + 1] = 4.0; }
        biases.extend_from_slice(&[1.0, 3.0, 2.0, 4.0, 1.0, 0.9]);
    }
    Ok(RgbInferenceModel::new(&graph, BTreeMap::from([("weight".into(), weights), ("bias".into(), biases)]),
        RgbModelSpec { image_input: "image".into(),
            preprocess: PreprocessProgram::new(8, 8, ChannelTransform::Rgb, true),
            filter: ResizeFilter::Bilinear, aspect: ResizeAspect::Letterbox(114), masked_rgb: [0; 3] },
        &ScalarExecCx::new())?)
}
pub fn head(model: &RgbInferenceModel) -> Test<RgbDetectionContract> {
    Ok(RgbDetectionContract::new(RgbDetectionSpec { model: model.digest(), output_port: "head".into(),
        labels: vec!["numeric-a".into(), "numeric-b".into()], layout: HeadLayout::Rows,
        boxes: HeadBoxes::PixelCorners, class_score: HeadScore::Probability, objectness: None,
        classes: HeadClasses::MultiLabel, minimum_score_ppm: 500_000, nms_iou_ppm: 1_000_000,
        maximum_rows: 100, maximum_candidates: 200, maximum_detections: 200 })?)
}
pub fn limits() -> RgbRunLimits {
    RgbRunLimits { decode: Default::default(), preprocess: ExecBudget::new(WORK, 32 * 1024 * 1024),
        execution: ExecBudget::new(WORK, 64 * 1024 * 1024), maximum_output_bytes: 1024 * 1024 }
}
pub fn post() -> RgbDetectionBudget { RgbDetectionBudget::new(WORK, 32 * 1024 * 1024) }
pub fn jpeg(value: u8) -> Vec<u8> { jpeg_support::jpeg(32, 16, [1, 1], false, false, false, &[[value, 128, 128]]) }
pub fn source(bytes: &[u8], mask: &[u8], n: u8) -> RgbSourceBinding {
    RgbSourceBinding { encoded_sha256: ContentDigest::sha256(bytes).bytes(), exposure: [n; 32], camera: 1, clock: 2,
        capture: [u64::from(n) * 1_000_000_000; 2], image_domain: [3; 32], calibration: [4; 32],
        permission_mask: ContentDigest::sha256(mask).bytes() }
}
pub fn input<'a>(bytes: &'a [u8], mask: &'a [u8], n: u8) -> RgbDetectionInput<'a> {
    RgbDetectionInput { bytes, allowed: mask, interpretation: Color::YCbCr, source: source(bytes, mask, n) }
}
pub fn detection(model: &RgbInferenceModel, head: &RgbDetectionContract, value: u8, n: u8) -> Test<RgbDetectionRun> {
    let mut detector = RgbDetector::new(model, head)?; let bytes = jpeg(value);
    match detector.run_jpeg(input(&bytes, &[1; 512], n), limits(), &mut DecodeBudget::new(WORK), &mut post(), &ScalarExecCx::new())? {
        RgbDetectionStep::Complete(run) => Ok(run), RgbDetectionStep::Pending(e) => Err(e.into()),
    }
}
pub fn admission(source: RgbSourceBinding, available: TrackingAvailability) -> Test<RgbFrameAdmission> {
    Ok(RgbFrameAdmission::new(source, available, ContentDigest::sha256(b"test owner screening declaration"))?)
}
pub fn tracking_policy() -> ImageTrackingPolicy {
    ImageTrackingPolicy { maximum_tracks: 8, maximum_detections: 8, maximum_exposures: 100,
        minimum_observations: 2, maximum_misses: 2, maximum_gap_ns: 10_000_000_000,
        maximum_speed: 100, gate_padding: 4, miss_cost: 1000, ambiguity_margin: 0 }
}
pub fn tracker(head: &RgbDetectionContract, policy: ImageTrackingPolicy) -> Test<RgbZoneTracker> {
    Ok(RgbZoneTracker::new([9; 32], RgbTrackingContract::new(head, 0, ContentDigest::sha256(b"selected numeric-a"))?, policy,
        ImageZoneBasis { camera: 1, clock: 2, image_domain: [3; 32], calibration: [4; 32], dimensions: [32, 16] },
        ImageZonePolicy { selection_evidence: [8; 32], maximum_sample_gap_ns: 10_000_000_000 },
        &[ImageZoneSpec { id: 1, vertices: vec![[14, 1], [30, 1], [30, 15], [14, 15]], margin: 0,
            dwell_ns: Some(1_000_000_000) }], &mut WorkBudget::new(WORK))?)
}
pub fn observe(tracker: &mut RgbZoneTracker, run: &RgbDetectionRun, available: TrackingAvailability) -> Test<RgbZoneProgress> {
    Ok(tracker.observe(run.inference(), run.report(), admission(run.report().source(), available)?, &mut WorkBudget::new(WORK))?)
}
