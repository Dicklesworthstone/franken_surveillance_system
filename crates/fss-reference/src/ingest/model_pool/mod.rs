#![forbid(unsafe_code)]
//! Multi-stream batched pure-Rust ML inference worker pool with adaptive keyframe throttling,
//! explicit OSD ignore masking, and fair-share bounded resource budgets.
//!
//! Cognition-plane orchestration only:
//! - Models are verified and pinned ONCE into immutable `Arc<VerifiedResidentModel>` memory by
//!   `(model_id, package_digest, model_generation, execution_profile_digest)`.
//! - Stage 1 runs cheap OSD-masked foreground subtraction and tracks per-stream quiescence,
//!   recording every skipped or throttled frame in an explicit [`UnsampledGapLedger`] so no
//!   absence claim is ever fabricated.
//! - [`FairShareScheduler`] guarantees anti-starvation per-camera floors before priority-tiered
//!   burst admission, emitting canonical [`MarginalWorkDeclinedReceipt`] records under pressure.
//! - [`WorkerPoolExecutor`] runs admitted inferences across `1..=16` scoped threads with zero
//!   detached threads and bit-for-bit identical canonical receipts across all worker counts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Instant;

use fss_core::{BudgetError, BudgetVector};
use fss_tensor::TensorError;

use crate::executor_activity::ExecutorActivityError;
use crate::executor_activity_package::ActivityPackageError;
use crate::ingest::foreground::ForegroundError;
use crate::ingest::osd_mask::OsdMaskError;
use crate::ingest::rgb_detections::RgbDetectionError;
use crate::ingest::rgb_inference::RgbInferenceError;
use crate::ingest::rgb_package::RgbPackageError;
use crate::ingest::sensor_health::HealthError;
use crate::{ExecError, ReplayCx, ScalarExecCx};

/// Two-stage motion-gated cascade, OSD ignore-mask integration, and periodic keyframe sentinel.
pub mod cascade;
/// Pure-Rust inference kernel runners for verified activity and RGB detector packages.
pub mod exec;
/// Explicit unsampled gap ledger and marginal-work decline receipts.
pub mod gap;
/// Canonical receipts and JSONL telemetry.
pub mod receipt;
/// Digest-pinned resident model pool with zero-reload atomic metrics.
pub mod registry;
/// Per-camera fair-share budget scheduler and priority queue.
pub mod scheduler;
/// Bounded scoped multi-worker ML inference executor.
pub mod worker;

#[cfg(test)]
mod tests;

pub use cascade::{
    CascadePolicyConfig, FramePixelInput, MAX_POOL_STREAMS, ReferenceFramePixels, Stage1Decision,
    StreamActivityState, StreamFrameInput, StreamRegistration, TwoStageCascade,
};
pub use receipt::{
    BATCH_RECEIPT_DOMAIN, BatchBenchmarkMetrics, BatchExecutionReceipt, CASCADE_RECEIPT_DOMAIN,
    CascadeFrameReceipt, MARGINAL_WORK_DECLINED_DOMAIN, MarginalWorkDeclinedReceipt,
    ModelDetectionSummary, RESIDENT_MODEL_DOMAIN, Stage1Telemetry, StageDecision,
    UNSAMPLED_GAP_DOMAIN, UnsampledGapLedger, UnsampledGapRecord, UnsampledReason,
};
pub use registry::{
    DEFAULT_MAX_RESIDENT_BYTES, MAX_RESIDENT_MODELS, ModelInferenceOutput, ModelLoadMetrics,
    ModelLoadMetricsSnapshot, ResidentModelKey, ResidentModelPool, VerifiedResidentModel,
    pool_execution_profile_digest,
};
pub use scheduler::{
    CameraPriorityTier, CameraQuotaConfig, DeclineReason, EpochScheduleOutcome, FairShareScheduler,
    PoolBudgetConfig, ResourcePressure, ScheduledCandidate,
};
pub use worker::{
    InferenceTask, MAX_POOL_WORKERS, WorkerPoolConfig, WorkerPoolExecutor, WorkerTaskResult,
};

/// Typed non-disclosing error surface for the resident multi-stream inference pool.
#[derive(Debug)]
pub enum ModelPoolError {
    /// Configuration ceiling or parameter is outside its admitted contract.
    InvalidConfig(&'static str),
    /// Frame input, pixel buffer, or model kind does not match its contract.
    InvalidInput(&'static str),
    /// Frame references a camera stream not registered with [`TwoStageCascade`].
    UnknownStream(String),
    /// Two frames in the same epoch claim the exact same `(sensor_id, frame_sequence)`.
    DuplicateFrame {
        /// Sensor identity.
        sensor_id: String,
        /// Duplicate sequence number.
        frame_sequence: u64,
    },
    /// Requested model key is not currently loaded in [`ResidentModelPool`].
    ModelNotLoaded(String),
    /// Adding a verified model would exceed the pool's model count or resident-byte cap.
    PoolCapacityExceeded {
        /// Configured model count ceiling.
        max_models: usize,
        /// Configured resident byte ceiling.
        max_bytes: usize,
    },
    /// Supplied `.fmpk` archive bytes did not match the independently pinned SHA-256 digest.
    DigestMismatch,
    /// First-party activity package verification failed.
    ActivityPackage(ActivityPackageError),
    /// Activity threshold or execution error.
    ActivityExecution(ExecutorActivityError),
    /// RGB detector package verification failed.
    RgbPackage(RgbPackageError),
    /// RGB inference execution failed.
    RgbInference(RgbInferenceError),
    /// RGB detection head projection failed.
    RgbDetection(RgbDetectionError),
    /// Pure-Rust Model IR executor or preprocessor failed.
    Execution(ExecError),
    /// Stage-1 foreground subtraction refused the frame or config.
    Foreground(ForegroundError),
    /// Explicit OSD ignore-region validation failed.
    OsdMask(OsdMaskError),
    /// Optional sensor-health screen failed.
    Health(HealthError),
    /// Tensor construction or readback failed.
    Tensor(TensorError),
    /// `fss_core::BudgetVector` validation or arithmetic failed.
    Budget(BudgetError),
    /// Internal resident pool `RwLock` was poisoned by an external failure.
    LockPoisoned,
    /// A scoped worker thread terminated unexpectedly.
    WorkerPanicked,
    /// Cooperative cancellation was observed before completion.
    Cancelled,
}

impl ModelPoolError {
    /// Stable diagnostic identifier for structured logging and receipts.
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::InvalidConfig(_) => "ERR-MODEL-POOL-CONFIG-001",
            Self::InvalidInput(_) | Self::UnknownStream(_) | Self::DuplicateFrame { .. } => {
                "ERR-MODEL-POOL-INPUT-001"
            }
            Self::ModelNotLoaded(_) => "ERR-MODEL-POOL-NOT-LOADED-001",
            Self::PoolCapacityExceeded { .. } => "ERR-MODEL-POOL-CAPACITY-001",
            Self::DigestMismatch => "ERR-MODEL-PACKAGE-DIGEST-001",
            Self::ActivityPackage(_) | Self::RgbPackage(_) => "ERR-MODEL-PACKAGE-INVALID-001",
            Self::ActivityExecution(_)
            | Self::RgbInference(_)
            | Self::RgbDetection(_)
            | Self::Execution(_)
            | Self::Tensor(_) => "ERR-MODEL-POOL-EXEC-001",
            Self::Foreground(_) | Self::OsdMask(_) | Self::Health(_) => "ERR-MODEL-POOL-STAGE1-001",
            Self::Budget(_) => "ERR-MODEL-POOL-BUDGET-001",
            Self::LockPoisoned | Self::WorkerPanicked => "ERR-MODEL-POOL-RUNTIME-001",
            Self::Cancelled => "ERR-MODEL-POOL-CANCELLED-001",
        }
    }
}

impl fmt::Display for ModelPoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(why) => write!(f, "invalid model pool configuration: {why}"),
            Self::InvalidInput(why) => write!(f, "invalid model pool input: {why}"),
            Self::UnknownStream(sensor) => write!(f, "unregistered stream sensor: {sensor}"),
            Self::DuplicateFrame {
                sensor_id,
                frame_sequence,
            } => {
                write!(
                    f,
                    "duplicate frame {frame_sequence} for sensor {sensor_id} in epoch"
                )
            }
            Self::ModelNotLoaded(id) => write!(f, "resident model not loaded in pool: {id}"),
            Self::PoolCapacityExceeded {
                max_models,
                max_bytes,
            } => {
                write!(
                    f,
                    "resident pool capacity exceeded (max_models={max_models}, max_bytes={max_bytes})"
                )
            }
            Self::DigestMismatch => {
                f.write_str("model package digest differs from pinned identity")
            }
            Self::ActivityPackage(e) => write!(f, "activity package refused: {e}"),
            Self::ActivityExecution(e) => write!(f, "activity execution failed: {e}"),
            Self::RgbPackage(e) => write!(f, "RGB detector package refused: {e}"),
            Self::RgbInference(e) => write!(f, "RGB inference failed: {e}"),
            Self::RgbDetection(e) => write!(f, "RGB detection projection failed: {e}"),
            Self::Execution(e) => write!(f, "model executor refused: {e}"),
            Self::Foreground(e) => write!(f, "stage-1 foreground detector refused: {e}"),
            Self::OsdMask(e) => write!(f, "OSD ignore region refused: {e}"),
            Self::Health(e) => write!(f, "stage-1 sensor health refused: {e}"),
            Self::Tensor(e) => write!(f, "tensor operation failed: {e}"),
            Self::Budget(e) => write!(f, "budget vector error: {e}"),
            Self::LockPoisoned => f.write_str("resident model pool lock poisoned"),
            Self::WorkerPanicked => f.write_str("scoped inference worker terminated unexpectedly"),
            Self::Cancelled => f.write_str("model pool execution cancelled"),
        }
    }
}

impl std::error::Error for ModelPoolError {}

impl From<ActivityPackageError> for ModelPoolError {
    fn from(e: ActivityPackageError) -> Self {
        match e {
            ActivityPackageError::Cancelled => Self::Cancelled,
            ActivityPackageError::DigestMismatch => Self::DigestMismatch,
            other => Self::ActivityPackage(other),
        }
    }
}
impl From<ExecutorActivityError> for ModelPoolError {
    fn from(e: ExecutorActivityError) -> Self {
        match e {
            ExecutorActivityError::Cancelled => Self::Cancelled,
            other => Self::ActivityExecution(other),
        }
    }
}
impl From<RgbPackageError> for ModelPoolError {
    fn from(e: RgbPackageError) -> Self {
        match e {
            RgbPackageError::Cancelled => Self::Cancelled,
            RgbPackageError::DigestMismatch => Self::DigestMismatch,
            other => Self::RgbPackage(other),
        }
    }
}
impl From<RgbInferenceError> for ModelPoolError {
    fn from(e: RgbInferenceError) -> Self {
        match e {
            RgbInferenceError::Execution(ExecError::CancellationRequested { .. }) => {
                Self::Cancelled
            }
            other => Self::RgbInference(other),
        }
    }
}
impl From<RgbDetectionError> for ModelPoolError {
    fn from(e: RgbDetectionError) -> Self {
        match e {
            RgbDetectionError::Cancelled => Self::Cancelled,
            other => Self::RgbDetection(other),
        }
    }
}
impl From<ExecError> for ModelPoolError {
    fn from(e: ExecError) -> Self {
        match e {
            ExecError::CancellationRequested { .. } => Self::Cancelled,
            other => Self::Execution(other),
        }
    }
}
impl From<ForegroundError> for ModelPoolError {
    fn from(e: ForegroundError) -> Self {
        Self::Foreground(e)
    }
}
impl From<OsdMaskError> for ModelPoolError {
    fn from(e: OsdMaskError) -> Self {
        Self::OsdMask(e)
    }
}
impl From<HealthError> for ModelPoolError {
    fn from(e: HealthError) -> Self {
        match e {
            HealthError::Cancelled => Self::Cancelled,
            other => Self::Health(other),
        }
    }
}
impl From<TensorError> for ModelPoolError {
    fn from(e: TensorError) -> Self {
        Self::Tensor(e)
    }
}
impl From<BudgetError> for ModelPoolError {
    fn from(e: BudgetError) -> Self {
        Self::Budget(e)
    }
}

/// Integrated multi-stream engine combining [`TwoStageCascade`], [`FairShareScheduler`], and
/// [`WorkerPoolExecutor`] over a shared [`ResidentModelPool`].
pub struct ModelPoolEngine {
    cascade: TwoStageCascade,
    scheduler: FairShareScheduler,
    workers: WorkerPoolExecutor,
}

impl ModelPoolEngine {
    /// Constructs a validated multi-stream inference engine.
    pub fn new(
        cascade: TwoStageCascade,
        scheduler: FairShareScheduler,
        workers: WorkerPoolExecutor,
    ) -> Self {
        Self {
            cascade,
            scheduler,
            workers,
        }
    }

    /// Mutable access to the two-stage cascade (e.g. to register streams).
    #[must_use]
    pub fn cascade_mut(&mut self) -> &mut TwoStageCascade {
        &mut self.cascade
    }
    /// Read-only access to the two-stage cascade.
    #[must_use]
    pub const fn cascade(&self) -> &TwoStageCascade {
        &self.cascade
    }
    /// Read-only access to the fair-share budget scheduler.
    #[must_use]
    pub const fn scheduler(&self) -> &FairShareScheduler {
        &self.scheduler
    }
    /// Read-only access to the scoped worker pool executor.
    #[must_use]
    pub const fn workers(&self) -> &WorkerPoolExecutor {
        &self.workers
    }

    /// Processes one multi-stream epoch end-to-end and returns canonical receipts plus metrics.
    #[allow(clippy::too_many_arguments)]
    pub fn process_epoch(
        &mut self,
        pool: &ResidentModelPool,
        model_key: &ResidentModelKey,
        epoch_id: u64,
        frames: &[StreamFrameInput],
        replay_cx: Option<&ReplayCx>,
        scalar_cx: &ScalarExecCx,
    ) -> Result<(BatchExecutionReceipt, BatchBenchmarkMetrics), ModelPoolError> {
        self.process_epoch_inner(
            pool, model_key, epoch_id, frames, replay_cx, scalar_cx, false,
        )
    }

    /// Processes an explicit operator/agent-requested probe epoch where every submitted frame
    /// forces Stage-2 ML sentinel admission through the already-pinned [`ResidentModelPool`]
    /// (zero weight reloads) while preserving Stage-1 validation, OSD masks, fair-share budgets,
    /// and cancellation boundaries.
    #[allow(clippy::too_many_arguments)]
    pub fn process_forced_probe_epoch(
        &mut self,
        pool: &ResidentModelPool,
        model_key: &ResidentModelKey,
        epoch_id: u64,
        frames: &[StreamFrameInput],
        replay_cx: Option<&ReplayCx>,
        scalar_cx: &ScalarExecCx,
    ) -> Result<(BatchExecutionReceipt, BatchBenchmarkMetrics), ModelPoolError> {
        self.process_epoch_inner(
            pool, model_key, epoch_id, frames, replay_cx, scalar_cx, true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn process_epoch_inner(
        &mut self,
        pool: &ResidentModelPool,
        model_key: &ResidentModelKey,
        epoch_id: u64,
        frames: &[StreamFrameInput],
        replay_cx: Option<&ReplayCx>,
        scalar_cx: &ScalarExecCx,
        force_stage2_sentinel: bool,
    ) -> Result<(BatchExecutionReceipt, BatchBenchmarkMetrics), ModelPoolError> {
        let epoch_started = Instant::now();
        scalar_cx.checkpoint("model_pool:epoch_begin")?;
        if let Some(rcx) = replay_cx {
            rcx.checkpoint("model_pool:epoch_begin")
                .map_err(|_| ModelPoolError::Cancelled)?;
        }

        let resident_meta = pool.inspect(model_key)?;
        let mut ordered: Vec<(u32, u64, &StreamFrameInput)> = Vec::with_capacity(frames.len());
        let mut seen = BTreeSet::new();
        for frame in frames {
            let (stream_order, _) = self.cascade.stream_metadata(&frame.sensor_id)?;
            if !seen.insert((stream_order, frame.frame_sequence, frame.sensor_id.as_str())) {
                return Err(ModelPoolError::DuplicateFrame {
                    sensor_id: frame.sensor_id.as_str().to_owned(),
                    frame_sequence: frame.frame_sequence,
                });
            }
            ordered.push((stream_order, frame.frame_sequence, frame));
        }
        ordered.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.cmp(&b.1))
                .then_with(|| a.2.sensor_id.cmp(&b.2.sensor_id))
        });

        let mut stage1_decisions = Vec::with_capacity(ordered.len());
        let mut candidates = Vec::new();
        let budget_cfg = self.scheduler.config();
        for (canonical_index, (_, _, frame)) in ordered.iter().enumerate() {
            scalar_cx.checkpoint("model_pool:stage1")?;
            let mut decision = self.cascade.evaluate_stage1(frame, replay_cx)?;
            if force_stage2_sentinel && !decision.stage_decision.ran_ml_inference() {
                decision.stage_decision = StageDecision::SentinelSweep;
                decision.unsampled_reason = None;
            }
            if decision.stage_decision.ran_ml_inference() {
                candidates.push(ScheduledCandidate {
                    canonical_index,
                    stream_order: decision.stream_order,
                    frame_sequence: decision.frame_sequence,
                    sensor_id: decision.sensor_id.clone(),
                    priority: decision.priority,
                    stage_decision: decision.stage_decision,
                    requested_work_units: budget_cfg.estimated_work_units_per_inference,
                    requested_macs: budget_cfg.estimated_macs_per_inference,
                    requested_bytes: budget_cfg.estimated_bytes_per_inference,
                });
            }
            stage1_decisions.push(decision);
        }

        let schedule = self.scheduler.schedule_epoch(&candidates)?;
        let mut tasks = Vec::with_capacity(schedule.admitted_indices.len());
        for &canonical_index in &schedule.admitted_indices {
            let frame = ordered[canonical_index].2;
            let s1 = &stage1_decisions[canonical_index];
            tasks.push(InferenceTask {
                canonical_index,
                stream_order: s1.stream_order,
                frame_sequence: s1.frame_sequence,
                sensor_id: &frame.sensor_id,
                source_digest: frame.source_digest,
                capture_interval: frame.capture_interval,
                dimensions: frame.dimensions,
                pixels: &frame.pixels,
                reference_pixels: s1.reference_pixels.clone(),
                model_key: resident_meta.key(),
            });
        }

        let worker_results = self.workers.execute_tasks(pool, &tasks, scalar_cx)?;
        let mut by_idx: BTreeMap<usize, WorkerTaskResult> = BTreeMap::new();
        let mut durations_ns = Vec::with_capacity(worker_results.len());
        for res in worker_results {
            durations_ns.push(res.duration_ns);
            by_idx.insert(res.canonical_index, res);
        }

        let mut frame_receipts = Vec::with_capacity(ordered.len());
        let mut unsampled_gaps = UnsampledGapLedger::default();
        let mut declined_list = Vec::with_capacity(schedule.declined.len());
        let (mut total_work, mut total_macs, mut inferred_count) = (0_u64, 0_u64, 0_u32);

        for (idx, s1) in stage1_decisions.iter().enumerate() {
            let receipt = if let Some(wr) = by_idx.remove(&idx) {
                inferred_count = inferred_count.saturating_add(1);
                let frame_work = s1.telemetry.work_units.saturating_add(wr.output.work_units);
                total_work = total_work.saturating_add(frame_work);
                total_macs = total_macs.saturating_add(wr.output.executed_macs);
                CascadeFrameReceipt::seal(
                    s1,
                    resident_meta.key(),
                    s1.stage_decision,
                    wr.output.detections,
                    wr.output.activity_score_bits,
                    Some(wr.output.output_digest),
                    wr.output.executed_macs,
                    None,
                    None,
                    frame_work,
                )
            } else if let Some(decline) = schedule.declined.get(&idx).cloned() {
                total_work = total_work.saturating_add(s1.telemetry.work_units);
                unsampled_gaps.push(UnsampledGapRecord::new(
                    s1.stream_order,
                    s1.frame_sequence,
                    s1.sensor_id.clone(),
                    s1.capture_interval,
                    s1.source_digest,
                    s1.is_keyframe,
                    UnsampledReason::BudgetThrottled,
                ));
                declined_list.push(decline.clone());
                CascadeFrameReceipt::seal(
                    s1,
                    resident_meta.key(),
                    StageDecision::BudgetDeclined,
                    Vec::new(),
                    None,
                    None,
                    0,
                    Some(UnsampledReason::BudgetThrottled),
                    Some(decline),
                    s1.telemetry.work_units,
                )
            } else {
                let reason = s1
                    .unsampled_reason
                    .unwrap_or(UnsampledReason::QuiescentNonKeyframe);
                total_work = total_work.saturating_add(s1.telemetry.work_units);
                unsampled_gaps.push(UnsampledGapRecord::new(
                    s1.stream_order,
                    s1.frame_sequence,
                    s1.sensor_id.clone(),
                    s1.capture_interval,
                    s1.source_digest,
                    s1.is_keyframe,
                    reason,
                ));
                CascadeFrameReceipt::seal(
                    s1,
                    resident_meta.key(),
                    StageDecision::QuiescentSkipped,
                    Vec::new(),
                    None,
                    None,
                    0,
                    Some(reason),
                    None,
                    s1.telemetry.work_units,
                )
            };
            frame_receipts.push(receipt);
        }

        let budget_consumed = BudgetVector::builder()
            .model_calls(inferred_count)
            .bytes(schedule.memory_bytes_reserved as u64)
            .build()?;
        let batch = BatchExecutionReceipt::seal(
            epoch_id,
            resident_meta.key(),
            frame_receipts,
            unsampled_gaps,
            declined_list,
            budget_cfg.budget_vector,
            budget_consumed,
            budget_cfg.max_work_units_per_epoch,
            total_work,
            total_macs,
            schedule.pressure,
        );

        let elapsed_secs = epoch_started.elapsed().as_secs_f64().max(1e-9);
        let pool_metrics = pool.metrics_snapshot();
        let idle_reduction_pct = if batch.frames_total == 0 {
            0.0
        } else {
            (batch.frames_total.saturating_sub(batch.frames_inferred) as f64 * 100.0)
                / (batch.frames_total as f64)
        };
        let metrics = BatchBenchmarkMetrics {
            worker_count: self.workers.config().worker_count,
            elapsed_ms: elapsed_secs * 1000.0,
            inferences_per_sec: (batch.frames_inferred as f64) / elapsed_secs,
            p99_inference_ms: compute_p99_ms(&mut durations_ns),
            frames_total: batch.frames_total,
            frames_inferred: batch.frames_inferred,
            frames_throttled: batch.frames_throttled,
            idle_reduction_pct,
            weight_loads: pool_metrics.loads,
            cache_hits: pool_metrics.cache_hits,
            detections_total: batch.detections_total,
        };
        Ok((batch, metrics))
    }
}

fn compute_p99_ms(durations_ns: &mut [u64]) -> f64 {
    if durations_ns.is_empty() {
        return 0.0;
    }
    durations_ns.sort_unstable();
    let idx = ((durations_ns.len().saturating_mul(99)).div_ceil(100)).saturating_sub(1);
    (durations_ns[idx.min(durations_ns.len() - 1)] as f64) / 1_000_000.0
}
