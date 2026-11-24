#![forbid(unsafe_code)]
//! Canonical per-frame cascade receipts, multi-stream batch execution receipts, and non-identity
//! JSONL benchmark telemetry for the resident ML inference pool.
//!
//! Every canonical digest excludes wall-clock timings and worker thread count so that executing
//! the same batch with 1, 2, 4, or 8 workers yields bit-for-bit identical receipts and digests.
//! No receipt in this module ever certifies scene absence (`absence_certifiable == false`) or
//! grants effect authority (`effects_authorized == false`).

use std::fmt::Write as _;

use fss_core::{BudgetVector, CanonicalEncode, CanonicalEncoder, ContentDigest, SensorId};

pub use super::gap::{
    MARGINAL_WORK_DECLINED_DOMAIN, MarginalWorkDeclinedReceipt, UNSAMPLED_GAP_DOMAIN,
    UnsampledGapLedger, UnsampledGapRecord, UnsampledReason,
};
pub use super::scheduler::{CameraPriorityTier, DeclineReason, ResourcePressure};

/// Canonical digest domain for verified immutable resident models in the pool.
pub const RESIDENT_MODEL_DOMAIN: &str = "fss.model_pool.resident_model.v1";
/// Canonical digest domain for per-frame two-stage cascade inference receipts.
pub const CASCADE_RECEIPT_DOMAIN: &str = "fss.model_pool.cascade_receipt.v1";
/// Canonical digest domain for multi-stream epoch batch execution receipts.
pub const BATCH_RECEIPT_DOMAIN: &str = "fss.model_pool.batch_receipt.v1";

/// Outcome of the two-stage motion/sentinel cascade and budget scheduler for one frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum StageDecision {
    /// Stage-1 OSD-masked foreground motion triggered immediate Stage-2 ML inference.
    MotionTriggered = 0,
    /// Periodic keyframe sentinel triggered Stage-2 ML inference on a quiescent stream.
    SentinelSweep = 1,
    /// Stage-1 determined the frame was quiescent and not due for a sentinel sweep.
    QuiescentSkipped = 2,
    /// Stage-1 requested ML inference, but the fair-share budget scheduler declined it.
    BudgetDeclined = 3,
}

impl StageDecision {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MotionTriggered => "motion_triggered",
            Self::SentinelSweep => "sentinel_sweep",
            Self::QuiescentSkipped => "quiescent_skipped",
            Self::BudgetDeclined => "budget_declined",
        }
    }

    /// Compact canonical tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Returns `true` iff Stage-2 ML inference executed on this frame.
    #[must_use]
    pub const fn ran_ml_inference(self) -> bool {
        matches!(self, Self::MotionTriggered | Self::SentinelSweep)
    }
}

impl CanonicalEncode for StageDecision {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        e.u8(self.tag());
        e.text(self.as_str());
    }
}

/// Bit-exact uncalibrated detection proposal emitted by a resident RGB detector package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelDetectionSummary {
    /// Index into the package's frozen label vocabulary.
    pub class_index: usize,
    /// Frozen class label string.
    pub label: String,
    /// Exact IEEE-754 F32 score bit pattern (uncalibrated).
    pub score_bits: u32,
    /// Source-space half-open XYXY bounding box in 1/256-pixel units.
    pub bounds: [u32; 4],
}

impl ModelDetectionSummary {
    /// Returns the uncalibrated F32 detection score.
    #[must_use]
    pub fn score(&self) -> f32 {
        f32::from_bits(self.score_bits)
    }
}

impl CanonicalEncode for ModelDetectionSummary {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        e.u64(self.class_index as u64);
        e.text(&self.label);
        e.u32(self.score_bits);
        for coord in self.bounds {
            e.u32(coord);
        }
    }
}

/// Deterministic Stage-1 motion, OSD-masking, and optional sensor-health telemetry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1Telemetry {
    /// Total foreground pixels detected outside caller-supplied OSD ignore rectangles.
    pub foreground_pixels: usize,
    /// Connected foreground bounding box count meeting minimum area.
    pub foreground_box_count: usize,
    /// Canonical digest of the caller-supplied OSD ignore-region set.
    pub osd_ignore_regions_digest: ContentDigest,
    /// Count of explicit OSD ignore rectangles applied during Stage-1 motion subtraction.
    pub osd_ignore_region_count: usize,
    /// Count of optional `sensor_health` findings emitted on the unmasked luma plane.
    pub health_findings_count: usize,
    /// Deterministic Stage-1 logical work units charged for this frame.
    pub work_units: u64,
}

impl CanonicalEncode for Stage1Telemetry {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        e.u64(self.foreground_pixels as u64);
        e.u64(self.foreground_box_count as u64);
        e.digest(self.osd_ignore_regions_digest);
        e.u64(self.osd_ignore_region_count as u64);
        e.u64(self.health_findings_count as u64);
        e.u64(self.work_units);
    }
}

/// Canonical per-frame receipt emitted by the two-stage cascade and resident inference pool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CascadeFrameReceipt {
    /// Deterministic stream ordinal.
    pub stream_order: u32,
    /// Monotonic frame sequence within the stream.
    pub frame_sequence: u64,
    /// Camera sensor identity.
    pub sensor_id: SensorId,
    /// Immutable source payload digest.
    pub source_digest: ContentDigest,
    /// Whether this frame was flagged as a codec keyframe.
    pub is_keyframe: bool,
    /// Camera priority tier under fair-share scheduling.
    pub priority: CameraPriorityTier,
    /// Verified resident model identifier.
    pub model_id: String,
    /// Pinned whole-archive SHA-256 of the verified `.fmpk` model package.
    pub package_digest: ContentDigest,
    /// Immutable model generation string.
    pub model_generation: String,
    /// Execution profile digest binding backend kernel generation.
    pub execution_profile_digest: ContentDigest,
    /// Two-stage cascade and scheduler decision for this frame.
    pub stage_decision: StageDecision,
    /// Deterministic Stage-1 measurements.
    pub stage1: Stage1Telemetry,
    /// Surviving uncalibrated detections (RGB detector packages; empty for activity models).
    pub detections: Vec<ModelDetectionSummary>,
    /// Exact IEEE-754 F32 bit pattern of the uncalibrated activity score (when running activity).
    pub activity_score_bits: Option<u32>,
    /// Canonical output tensor digest when Stage-2 ML executed.
    pub inference_output_digest: Option<ContentDigest>,
    /// Multiply-accumulate operations executed by Stage-2 ML (0 when skipped or declined).
    pub executed_macs: u64,
    /// Whether an explicit [`UnsampledGapRecord`] was emitted into the epoch gap ledger.
    pub unsampled_gap_recorded: bool,
    /// Typed unsampled reason when Stage-2 ML did not execute.
    pub unsampled_reason: Option<UnsampledReason>,
    /// Explicit decline receipt when `stage_decision == StageDecision::BudgetDeclined`.
    pub decline_receipt: Option<MarginalWorkDeclinedReceipt>,
    /// Total logical work units spent on this frame (Stage-1 + Stage-2).
    pub work_units_spent: u64,
    /// Always `false`: cognition receipts never certify scene absence.
    pub absence_certifiable: bool,
    /// Always `false`: cognition receipts never grant effect authority.
    pub effects_authorized: bool,
    /// Domain-separated canonical SHA-256 digest of this frame receipt.
    pub receipt_digest: ContentDigest,
}

impl CascadeFrameReceipt {
    /// Seals a frame receipt from Stage-1 context, pinned model key, and Stage-2 outcome.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn seal(
        s1: &super::cascade::Stage1Decision,
        model_key: &super::registry::ResidentModelKey,
        stage_decision: StageDecision,
        detections: Vec<ModelDetectionSummary>,
        activity_score_bits: Option<u32>,
        inference_output_digest: Option<ContentDigest>,
        executed_macs: u64,
        unsampled_reason: Option<UnsampledReason>,
        decline_receipt: Option<MarginalWorkDeclinedReceipt>,
        work_units_spent: u64,
    ) -> Self {
        let unsampled_gap_recorded = unsampled_reason.is_some();
        let mut e = CanonicalEncoder::new();
        e.text(CASCADE_RECEIPT_DOMAIN);
        e.u32(s1.stream_order);
        e.u64(s1.frame_sequence);
        s1.sensor_id.encode_canonical(&mut e);
        e.digest(s1.source_digest);
        e.bool(s1.is_keyframe);
        s1.priority.encode_canonical(&mut e);
        e.text(&model_key.model_id);
        e.digest(model_key.package_digest);
        e.text(&model_key.model_generation);
        e.digest(model_key.execution_profile_digest);
        stage_decision.encode_canonical(&mut e);
        s1.telemetry.encode_canonical(&mut e);
        e.u64(detections.len() as u64);
        for d in &detections {
            d.encode_canonical(&mut e);
        }
        e.bool(activity_score_bits.is_some());
        if let Some(bits) = activity_score_bits {
            e.u32(bits);
        }
        e.bool(inference_output_digest.is_some());
        if let Some(digest) = inference_output_digest {
            e.digest(digest);
        }
        e.u64(executed_macs);
        e.bool(unsampled_gap_recorded);
        e.bool(unsampled_reason.is_some());
        if let Some(reason) = unsampled_reason {
            reason.encode_canonical(&mut e);
        }
        e.bool(decline_receipt.is_some());
        if let Some(decline) = &decline_receipt {
            e.digest(decline.receipt_digest);
        }
        e.u64(work_units_spent);
        e.bool(false);
        e.bool(false);
        let receipt_digest = ContentDigest::sha256(&e.finish());

        Self {
            stream_order: s1.stream_order,
            frame_sequence: s1.frame_sequence,
            sensor_id: s1.sensor_id.clone(),
            source_digest: s1.source_digest,
            is_keyframe: s1.is_keyframe,
            priority: s1.priority,
            model_id: model_key.model_id.clone(),
            package_digest: model_key.package_digest,
            model_generation: model_key.model_generation.clone(),
            execution_profile_digest: model_key.execution_profile_digest,
            stage_decision,
            stage1: s1.telemetry,
            detections,
            activity_score_bits,
            inference_output_digest,
            executed_macs,
            unsampled_gap_recorded,
            unsampled_reason,
            decline_receipt,
            work_units_spent,
            absence_certifiable: false,
            effects_authorized: false,
            receipt_digest,
        }
    }

    /// Returns the uncalibrated F32 activity score if produced by an activity model.
    #[must_use]
    pub fn activity_score(&self) -> Option<f32> {
        self.activity_score_bits.map(f32::from_bits)
    }
}

/// Complete canonical receipt of one multi-stream inference epoch.
#[derive(Clone, Debug, PartialEq)]
pub struct BatchExecutionReceipt {
    /// Caller-supplied monotonic epoch identifier.
    pub epoch_id: u64,
    /// Resident model identifier.
    pub model_id: String,
    /// Verified `.fmpk` archive SHA-256.
    pub package_digest: ContentDigest,
    /// Immutable model generation string.
    pub model_generation: String,
    /// Execution profile digest.
    pub execution_profile_digest: ContentDigest,
    /// Canonical per-frame receipts sorted by `(stream_order, frame_sequence, sensor_id)`.
    pub frames: Vec<CascadeFrameReceipt>,
    /// Complete ledger of every frame that did not execute Stage-2 ML.
    pub unsampled_gaps: UnsampledGapLedger,
    /// All marginal-work decline receipts in canonical frame order.
    pub declined: Vec<MarginalWorkDeclinedReceipt>,
    /// Configured `fss_core::BudgetVector` ceiling for this epoch.
    pub budget_limit: BudgetVector,
    /// Consumed `fss_core::BudgetVector` for this epoch.
    pub budget_consumed: BudgetVector,
    /// Configured logical work-unit ceiling for this epoch.
    pub work_units_limit: u64,
    /// Actual logical work units consumed across Stage-1 and Stage-2.
    pub work_units_spent: u64,
    /// Total multiply-accumulate operations executed in Stage-2 ML.
    pub macs_executed: u64,
    /// Peak resource pressure observed during this epoch.
    pub pressure: ResourcePressure,
    /// Total source frames submitted in this epoch.
    pub frames_total: u64,
    /// Frames on which Stage-2 ML executed (`MotionTriggered` + `SentinelSweep`).
    pub frames_inferred: u64,
    /// Frames inferred due to Stage-1 motion trigger.
    pub frames_motion_triggered: u64,
    /// Frames inferred due to periodic keyframe sentinel sweep.
    pub frames_sentinel_swept: u64,
    /// Frames skipped as quiescent by Stage-1.
    pub frames_quiescent_skipped: u64,
    /// Frames declined by the fair-share budget scheduler.
    pub frames_throttled: u64,
    /// Total detections emitted across all inferred frames.
    pub detections_total: u64,
    /// Always `false`: batch receipts never certify absence.
    pub absence_certifiable: bool,
    /// Always `false`: batch receipts never grant effect authority.
    pub effects_authorized: bool,
    /// Domain-separated canonical SHA-256 digest of the entire batch receipt.
    pub batch_digest: ContentDigest,
}

impl BatchExecutionReceipt {
    /// Seals a complete [`BatchExecutionReceipt`] under [`BATCH_RECEIPT_DOMAIN`].
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn seal(
        epoch_id: u64,
        model_key: &super::registry::ResidentModelKey,
        frames: Vec<CascadeFrameReceipt>,
        mut unsampled_gaps: UnsampledGapLedger,
        declined: Vec<MarginalWorkDeclinedReceipt>,
        budget_limit: BudgetVector,
        budget_consumed: BudgetVector,
        work_units_limit: u64,
        work_units_spent: u64,
        macs_executed: u64,
        pressure: ResourcePressure,
    ) -> Self {
        unsampled_gaps.sort_canonical();
        let (mut motion, mut sentinel, mut skipped, mut throttled, mut dets) = (0, 0, 0, 0, 0_u64);
        for frame in &frames {
            match frame.stage_decision {
                StageDecision::MotionTriggered => motion += 1,
                StageDecision::SentinelSweep => sentinel += 1,
                StageDecision::QuiescentSkipped => skipped += 1,
                StageDecision::BudgetDeclined => throttled += 1,
            }
            dets = dets.saturating_add(frame.detections.len() as u64);
        }
        let frames_total = frames.len() as u64;
        let frames_inferred = motion + sentinel;
        let mut e = CanonicalEncoder::new();
        e.text(BATCH_RECEIPT_DOMAIN);
        e.u64(epoch_id);
        e.text(&model_key.model_id);
        e.digest(model_key.package_digest);
        e.text(&model_key.model_generation);
        e.digest(model_key.execution_profile_digest);
        for n in [
            frames_total,
            frames_inferred,
            motion,
            sentinel,
            skipped,
            throttled,
            dets,
        ] {
            e.u64(n);
        }
        budget_limit.encode_canonical(&mut e);
        budget_consumed.encode_canonical(&mut e);
        e.u64(work_units_limit);
        e.u64(work_units_spent);
        e.u64(macs_executed);
        pressure.encode_canonical(&mut e);
        e.digest(unsampled_gaps.ledger_digest());
        e.u64(declined.len() as u64);
        for d in &declined {
            e.digest(d.receipt_digest);
        }
        for f in &frames {
            e.digest(f.receipt_digest);
        }
        e.bool(false);
        e.bool(false);
        let batch_digest = ContentDigest::sha256(&e.finish());
        Self {
            epoch_id,
            model_id: model_key.model_id.clone(),
            package_digest: model_key.package_digest,
            model_generation: model_key.model_generation.clone(),
            execution_profile_digest: model_key.execution_profile_digest,
            frames,
            unsampled_gaps,
            declined,
            budget_limit,
            budget_consumed,
            work_units_limit,
            work_units_spent,
            macs_executed,
            pressure,
            frames_total,
            frames_inferred,
            frames_motion_triggered: motion,
            frames_sentinel_swept: sentinel,
            frames_quiescent_skipped: skipped,
            frames_throttled: throttled,
            detections_total: dets,
            absence_certifiable: false,
            effects_authorized: false,
            batch_digest,
        }
    }
}

/// Non-identity wall-clock throughput and idle-reduction telemetry emitted alongside a batch.
#[derive(Clone, Debug, PartialEq)]
pub struct BatchBenchmarkMetrics {
    /// Worker count used for this execution.
    pub worker_count: usize,
    /// Wall-clock duration of the epoch execution in milliseconds.
    pub elapsed_ms: f64,
    /// Measured Stage-2 ML throughput in inferences per second.
    pub inferences_per_sec: f64,
    /// 99th-percentile per-inference latency in milliseconds.
    pub p99_inference_ms: f64,
    /// Total frames presented in the batch.
    pub frames_total: u64,
    /// Total frames inferred by Stage-2 ML.
    pub frames_inferred: u64,
    /// Total frames throttled by budget limits.
    pub frames_throttled: u64,
    /// Percentage of submitted frames that avoided Stage-2 ML inference (`0.0..=100.0`).
    pub idle_reduction_pct: f64,
    /// Cumulative model weight loads recorded by the pool.
    pub weight_loads: u64,
    /// Cumulative resident cache hits recorded by the pool.
    pub cache_hits: u64,
    /// Total detections emitted in this batch.
    pub detections_total: u64,
}

impl BatchBenchmarkMetrics {
    /// Renders a single-line structured JSONL metrics record without external serialization crates.
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        let mut out = String::with_capacity(256);
        let _ = write!(
            out,
            concat!(
                "{{\"worker_count\":{},\"elapsed_ms\":{:.3},\"inferences_per_sec\":{:.2},",
                "\"p99_inference_ms\":{:.4},\"frames_total\":{},\"frames_inferred\":{},",
                "\"frames_throttled\":{},\"idle_reduction_pct\":{:.2},\"weight_loads\":{},",
                "\"cache_hits\":{},\"detections_total\":{}}}"
            ),
            self.worker_count,
            self.elapsed_ms,
            self.inferences_per_sec,
            self.p99_inference_ms,
            self.frames_total,
            self.frames_inferred,
            self.frames_throttled,
            self.idle_reduction_pct,
            self.weight_loads,
            self.cache_hits,
            self.detections_total,
        );
        out
    }
}
