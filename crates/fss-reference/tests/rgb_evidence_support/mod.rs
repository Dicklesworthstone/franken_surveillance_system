#![forbid(unsafe_code)]
//! Original JPEG + canonical graph + Safetensors numerical fixtures, not trained weights.
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, Generation, OperationId};
use fss_model_ir::{
    AttrValue, AttributeMap, GraphNode, ModelIrGraph, ModelIrVersion, OpCode, TensorPort,
};
use fss_reference::ingest::model_import::rgb::{ImportedRgbModel, RgbModelImportRequest};
use fss_reference::ingest::model_import::{ImportBudget, ImportLimits, WeightFloatPolicy};
use fss_reference::ingest::rgb_detections::pipeline::*;
use fss_reference::ingest::rgb_detections::*;
use fss_reference::ingest::rgb_evidence::*;
use fss_reference::ingest::rgb_inference::*;
use fss_reference::ingest::rgb_tracking::RgbFrameAdmission;
use fss_reference::preprocess::{ResizeAspect, ResizeFilter};
use fss_reference::{ChannelTransform, ExecBudget, PreprocessProgram, ReplayCx, ScalarExecCx};
use fss_tensor::{DType, Shape};
use fss_twin::image_tracking::TrackingAvailability;
use std::collections::BTreeMap;
use std::path::Path;
#[path = "../../../fss-codec-mjpeg/tests/rgb_support/mod.rs"]
mod rgb_support;
pub type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub const WORK: u64 = 100_000_000;
pub fn context(root: &Path) -> Test<ReplayCx> {
    let a = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rgb-evidence".into(),
        operation_id: OperationId::parse("operation:rgb-evidence")?,
        principal: "principal:rgb-evidence".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:rgb-evidence"),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(&a, root.to_path_buf())?)
}
pub fn limits() -> RgbReplayLimits {
    RgbReplayLimits {
        import: ImportLimits::default(),
        run: RgbRunLimits {
            decode: Default::default(),
            preprocess: ExecBudget::new(WORK, 16 * 1024 * 1024),
            execution: ExecBudget::new(WORK, 64 * 1024 * 1024),
            maximum_output_bytes: 1024 * 1024,
        },
    }
}
pub fn graph() -> Test<Vec<u8>> {
    let g = Generation(7);
    let mut attrs = AttributeMap::new();
    attrs.insert("shape".into(), AttrValue::IntList(vec![1, 6, 1]));
    let graph = ModelIrGraph::new_validated(
        "model:rgb-evidence-fixture",
        ModelIrVersion::V1,
        g,
        vec![
            TensorPort::new("image", DType::F32, Shape::new(vec![1, 3, 8, 8])?, g)?,
            TensorPort::new("weight", DType::F32, Shape::new(vec![6, 3, 8, 8])?, g)?,
            TensorPort::new("bias", DType::F32, Shape::new(vec![6])?, g)?,
        ],
        vec![TensorPort::new(
            "head",
            DType::F32,
            Shape::new(vec![1, 6, 1])?,
            g,
        )?],
        vec![
            GraphNode::new(
                "node:conv",
                OpCode::Conv2d,
                "actual pixels change coordinates and class scores",
                vec!["image".into(), "weight".into(), "bias".into()],
                vec!["raw".into()],
                AttributeMap::new(),
            )?,
            GraphNode::new(
                "node:reshape",
                OpCode::Reshape,
                "exact dense layout",
                vec!["raw".into()],
                vec!["head".into()],
                attrs,
            )?,
        ],
    )?;
    Ok(fss_model_ir::encode_canonical_model_ir(&graph)?)
}
pub fn weights() -> Vec<u8> {
    let mut values = vec![0.0_f32; 6 * 3 * 64];
    for (field, channel) in [(0, 0), (2, 0), (4, 0), (5, 1)] {
        values[(field * 3 + channel) * 64 + 3 * 8 + 1] = 1.0;
    }
    let mut data: Vec<u8> = [1.0_f32, 3.0, 3.0, 5.0, 0.0, 0.0]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    data.extend(values.iter().flat_map(|v| v.to_le_bytes()));
    let header = format!(
        "{{\"__metadata__\":{{\"fixture\":\"not a trained detector\"}},\"bias\":{{\"dtype\":\"F32\",\"shape\":[6],\"data_offsets\":[0,24]}},\"weight\":{{\"dtype\":\"F32\",\"shape\":[6,3,8,8],\"data_offsets\":[24,{}]}}}}",
        data.len()
    );
    let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend(data);
    bytes
}
pub fn jpeg(exposure: u8) -> Vec<u8> {
    rgb_support::jpeg(
        16,
        8,
        [1, 1],
        false,
        false,
        false,
        &[[100, 150, 200 - exposure]],
    )
}
pub fn capture(
    exposure: u8,
    availability: TrackingAvailability,
    cx: &ReplayCx,
) -> Test<RgbEvidence> {
    let graph = graph()?;
    let weights = weights();
    let jpeg = jpeg(exposure);
    let mask = vec![1; 128];
    let spec = RgbModelSpec {
        image_input: "image".into(),
        preprocess: PreprocessProgram::new(8, 8, ChannelTransform::Rgb, true),
        filter: ResizeFilter::Bilinear,
        aspect: ResizeAspect::Letterbox(114),
        masked_rgb: [0; 3],
    };
    let request = RgbModelImportRequest {
        graph: &graph,
        graph_digest: ContentDigest::sha256(&graph),
        weights: &weights,
        weights_digest: ContentDigest::sha256(&weights),
        spec,
        float_policy: WeightFloatPolicy::F32Only,
        bindings: BTreeMap::new(),
    };
    let scalar = ScalarExecCx::new();
    let imported = ImportedRgbModel::build(
        &request,
        ImportLimits::default(),
        &mut ImportBudget::new(WORK),
        cx,
        &scalar,
    )?;
    let head = RgbDetectionContract::new(RgbDetectionSpec {
        model: imported.model().digest(),
        output_port: "head".into(),
        labels: vec!["numeric-red".into(), "numeric-green".into()],
        layout: HeadLayout::Channels,
        boxes: HeadBoxes::PixelCorners,
        class_score: HeadScore::Probability,
        objectness: None,
        classes: HeadClasses::Best,
        minimum_score_ppm: 500_000,
        nms_iou_ppm: 500_000,
        maximum_rows: 8,
        maximum_candidates: 8,
        maximum_detections: 8,
    })?;
    let source = RgbSourceBinding {
        encoded_sha256: ContentDigest::sha256(&jpeg).bytes(),
        exposure: [exposure; 32],
        camera: 1,
        clock: 2,
        capture: [
            u64::from(exposure) * 1_000_000_000,
            u64::from(exposure) * 1_000_000_000 + 1,
        ],
        image_domain: [3; 32],
        calibration: [4; 32],
        permission_mask: ContentDigest::sha256(&mask).bytes(),
    };
    let admission = RgbFrameAdmission::new(
        source,
        availability,
        ContentDigest::new(fss_core::DigestAlgorithm::Sha256, [5; 32]),
    )?;
    let mut detector = RgbDetector::new(imported.model(), &head)?;
    let RgbDetectionStep::Complete(run) = detector.run_jpeg(
        RgbDetectionInput {
            bytes: &jpeg,
            allowed: &mask,
            source,
            interpretation: ComponentInterpretation::YCbCr,
        },
        limits().run,
        &mut DecodeBudget::new(WORK),
        &mut RgbDetectionBudget::new(WORK, 32 * 1024 * 1024),
        &scalar,
    )?
    else {
        return Err("fixture head failed".into());
    };
    Ok(RgbEvidence::capture(
        &imported,
        &head,
        &jpeg,
        &run,
        admission,
        RgbEvidenceLimits::default(),
        &mut RgbEvidenceBudget::new(WORK),
        cx,
    )?)
}
pub fn replay(e: &RgbEvidence, cx: &ReplayCx) -> Test<ReplayedRgbEvidence> {
    Ok(e.replay(
        limits(),
        &mut RgbEvidenceBudget::new(WORK),
        &mut ImportBudget::new(WORK),
        &mut DecodeBudget::new(WORK),
        &mut RgbDetectionBudget::new(WORK, 32 * 1024 * 1024),
        cx,
        &ScalarExecCx::new(),
    )?)
}
