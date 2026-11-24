#![forbid(unsafe_code)]
//! Pure-Rust inference kernel runners for verified resident `.fmpk` activity and RGB detector
//! artifacts.
//!
//! Separated from pool lifecycle management ([`super::registry`]) so each module remains cohesive
//! and easy to audit. All arithmetic is deterministic pure Rust with zero weight reloads and zero
//! mutable shared state.

use fss_codec_mjpeg::ComponentInterpretation;
use fss_codec_mjpeg::color::RgbDecodeReceipt;
use fss_core::{CanonicalEncoder, CaptureInterval, ContentDigest, SensorId};
use fss_tensor::Tensor;

use super::ModelPoolError;
use super::receipt::{ModelDetectionSummary, RESIDENT_MODEL_DOMAIN};
use crate::executor_activity::{ActivityThresholdPolicy, MAX_ACTIVITY_MODEL_PIXELS};
use crate::executor_activity_package::{
    ACTIVITY_FRAME_INPUT, ACTIVITY_REFERENCE_INPUT, ACTIVITY_SCORE_OUTPUT,
    ACTIVITY_TENSOR_GENERATION, ACTIVITY_WEIGHTS_INPUT, VerifiedActivityPackage,
};
use crate::ingest::rgb_detections::{
    RgbDetectionBudget, RgbDetectionContract, project_rgb_detections,
};
use crate::ingest::rgb_inference::{RgbRunLimits, RgbSourceBinding};
use crate::ingest::rgb_package::RgbDetectorPackage;
use crate::preprocess::{ImageBytes, ResizeOptions};
use crate::{ExecBudget, OptimizedGraph, ScalarExecCx, ScalarExecutor};

/// Fixed preprocessing budget for the 32x32 activity model (independent of executor MAC ceiling).
const ACTIVITY_PREPROCESS_BUDGET: ExecBudget = ExecBudget {
    max_macs: 64 * 1024 * 1024,
    max_bytes: 64 * 1024 * 1024,
};

/// Output of one deterministic pure-Rust ML inference executed on a resident model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelInferenceOutput {
    /// Uncalibrated object detections (populated for RGB detector packages; empty for activity).
    pub detections: Vec<ModelDetectionSummary>,
    /// Exact IEEE-754 F32 bit pattern of the uncalibrated activity score (for activity models).
    pub activity_score_bits: Option<u32>,
    /// Canonical SHA-256 digest of the model's numerical output tensor(s).
    pub output_digest: ContentDigest,
    /// Multiply-accumulate operations executed by the model graph.
    pub executed_macs: u64,
    /// Total deterministic logical work units (preprocessing + graph execution + head decode).
    pub work_units: u64,
}

/// Runs a verified `fss_activity_v1.fmpk` artifact against an evaluated frame and reference frame.
#[allow(clippy::too_many_arguments)]
pub(super) fn run_activity_inference(
    resident_digest: ContentDigest,
    package: &VerifiedActivityPackage,
    prepared: Option<&OptimizedGraph>,
    weights: &Tensor,
    threshold_policy: &ActivityThresholdPolicy,
    frame_pixels: &[u8],
    frame_channels: usize,
    reference_pixels: &[u8],
    reference_channels: usize,
    dimensions: [u32; 2],
    budget: ExecBudget,
    cx: &ScalarExecCx,
) -> Result<ModelInferenceOutput, ModelPoolError> {
    cx.checkpoint("model_pool:infer_activity")?;
    let (w, h) = (dimensions[0] as usize, dimensions[1] as usize);
    let pixel_count = w
        .checked_mul(h)
        .filter(|&n| n > 0 && n <= MAX_ACTIVITY_MODEL_PIXELS)
        .ok_or(ModelPoolError::InvalidInput(
            "activity frame dimensions out of bounds",
        ))?;
    if (frame_channels != 1 && frame_channels != 3)
        || (reference_channels != 1 && reference_channels != 3)
        || frame_pixels.len() != pixel_count.saturating_mul(frame_channels)
        || reference_pixels.len() != pixel_count.saturating_mul(reference_channels)
    {
        return Err(ModelPoolError::InvalidInput(
            "activity pixel buffer length does not match dimensions and channels",
        ));
    }

    let spec = package.spec();
    let resize_opts = ResizeOptions {
        filter: spec.filter,
        aspect: spec.aspect,
        budget: ACTIVITY_PREPROCESS_BUDGET,
    };
    let frame_resized = spec.program.execute_resized_bytes(
        ImageBytes {
            bytes: frame_pixels,
            height: h,
            width: w,
            channels: frame_channels,
            generation: ACTIVITY_TENSOR_GENERATION,
        },
        resize_opts,
        cx,
    )?;
    let ref_resized = spec.program.execute_resized_bytes(
        ImageBytes {
            bytes: reference_pixels,
            height: h,
            width: w,
            channels: reference_channels,
            generation: ACTIVITY_TENSOR_GENERATION,
        },
        resize_opts,
        cx,
    )?;

    let outcome = match prepared {
        Some(opt_graph) => opt_graph.run(
            &[
                (ACTIVITY_FRAME_INPUT, frame_resized.tensor),
                (ACTIVITY_REFERENCE_INPUT, ref_resized.tensor),
            ],
            budget,
            cx,
        )?,
        None => ScalarExecutor::run(
            package.graph(),
            &[
                (ACTIVITY_FRAME_INPUT, frame_resized.tensor),
                (ACTIVITY_REFERENCE_INPUT, ref_resized.tensor),
                (ACTIVITY_WEIGHTS_INPUT, weights.clone()),
            ],
            budget,
            cx,
        )?,
    };

    let values = outcome
        .get_output(ACTIVITY_SCORE_OUTPUT)
        .ok_or(ModelPoolError::InvalidInput(
            "activity graph missing score output",
        ))?
        .to_vec::<f32>()?;
    let [score] = values.as_slice() else {
        return Err(ModelPoolError::InvalidInput(
            "activity score tensor must be [1,1]",
        ));
    };
    if !score.is_finite() {
        return Err(ModelPoolError::InvalidInput(
            "activity score output was non-finite",
        ));
    }
    let normalized_score = if *score == 0.0 { 0.0_f32 } else { *score };
    let _classified = threshold_policy.classify(normalized_score);

    let mut out_enc = CanonicalEncoder::new();
    out_enc.text(RESIDENT_MODEL_DOMAIN);
    out_enc.text("activity_output");
    out_enc.digest(resident_digest);
    out_enc.u32(normalized_score.to_bits());
    let output_digest = ContentDigest::sha256(&out_enc.finish());

    let work_units = frame_resized
        .work_units
        .saturating_add(ref_resized.work_units)
        .saturating_add(outcome.executed_macs());
    Ok(ModelInferenceOutput {
        detections: Vec::new(),
        activity_score_bits: Some(normalized_score.to_bits()),
        output_digest,
        executed_macs: outcome.executed_macs(),
        work_units,
    })
}

/// Runs a verified [`RgbDetectorPackage`] on packed RGB pixels and projects dense head proposals.
#[allow(clippy::too_many_arguments)]
pub(super) fn run_rgb_detector_inference(
    package: &RgbDetectorPackage,
    contract_override: Option<&RgbDetectionContract>,
    rgb_pixels: &[u8],
    dimensions: [u32; 2],
    source_digest: ContentDigest,
    sensor_id: &SensorId,
    capture: CaptureInterval,
    limits: RgbRunLimits,
    detection_work_units: u64,
    cx: &ScalarExecCx,
) -> Result<ModelInferenceOutput, ModelPoolError> {
    cx.checkpoint("model_pool:infer_rgb_detector")?;
    let pixel_count = (dimensions[0] as usize)
        .checked_mul(dimensions[1] as usize)
        .filter(|&n| n > 0 && n <= 4_194_304)
        .ok_or(ModelPoolError::InvalidInput(
            "invalid RGB detector dimensions",
        ))?;
    if rgb_pixels.len() != pixel_count.saturating_mul(3) || source_digest.bytes() == [0; 32] {
        return Err(ModelPoolError::InvalidInput(
            "RGB pixel length or source digest invalid",
        ));
    }

    let allowed = vec![1_u8; pixel_count];
    let permission_mask = ContentDigest::sha256(&allowed).bytes();
    let rgb_sha256 = ContentDigest::sha256(rgb_pixels).bytes();
    let earliest = u64::try_from(capture.earliest.0)
        .map_err(|_| ModelPoolError::InvalidInput("capture earliest outside u64"))?;
    let latest = u64::try_from(capture.latest.0)
        .map_err(|_| ModelPoolError::InvalidInput("capture latest outside u64"))?;

    let source = RgbSourceBinding {
        encoded_sha256: source_digest.bytes(),
        exposure: rgb_sha256,
        camera: nonzero_u64(ContentDigest::sha256(sensor_id.as_str().as_bytes())),
        clock: 1,
        capture: [earliest, latest],
        image_domain: ContentDigest::sha256(b"model-pool:rgb-image-domain").bytes(),
        calibration: ContentDigest::sha256(b"model-pool:uncalibrated").bytes(),
        permission_mask,
    };
    let receipt = RgbDecodeReceipt {
        encoded_sha256: source_digest.bytes(),
        rgb_sha256,
        decoder: ContentDigest::sha256(b"model-pool:caller-rgb-pixels").bytes(),
        interpretation: ComponentInterpretation::YCbCr,
        dimensions,
        mcus: 0,
        entropy_blocks: 0,
        restarts: 0,
        metadata_segments: 0,
        metadata_bytes: 0,
    };
    let inference = package
        .model()
        .run_rgb_pixels(rgb_pixels, receipt, source, &allowed, limits, cx)?;
    let contract = contract_override.unwrap_or_else(|| package.contract());
    let mut det_budget = RgbDetectionBudget::new(detection_work_units, 64 * 1024 * 1024);
    let report = project_rgb_detections(&inference, contract, &allowed, &mut det_budget, cx)?;
    let labels = &contract.spec().labels;
    let detections = report
        .detections()
        .iter()
        .map(|d| ModelDetectionSummary {
            class_index: d.class_index(),
            label: labels
                .get(d.class_index())
                .cloned()
                .unwrap_or_else(|| format!("class_{}", d.class_index())),
            score_bits: d.score().to_bits(),
            bounds: d.bounds(),
        })
        .collect();

    let work_units = inference
        .preprocess_work()
        .saturating_add(inference.executed_macs())
        .saturating_add(det_budget.used());
    Ok(ModelInferenceOutput {
        detections,
        activity_score_bits: None,
        output_digest: inference.output_digest(),
        executed_macs: inference.executed_macs(),
        work_units,
    })
}

fn nonzero_u64(digest: ContentDigest) -> u64 {
    let b = digest.bytes();
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]).max(1)
}
