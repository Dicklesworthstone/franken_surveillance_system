#![forbid(unsafe_code)]
//! Bounded scoped multi-worker ML inference executor (`WorkerPoolExecutor`).
//!
//! Dispatches admitted Stage-2 ML tasks across `1..=16` scoped threads via [`std::thread::scope`],
//! never spawning detached threads and never leaking work across cancellation or error boundaries.
//! Every worker resolves immutable `Arc<VerifiedResidentModel>` handles from [`ResidentModelPool`]
//! and produces results sorted strictly by canonical `(stream_order, frame_sequence, sensor_id)`
//! index so output tensors, detections, and digests are bit-identical for `worker_count` in
//! `1..=16`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use fss_codec_mjpeg::color::RgbDecodeLimits;
use fss_core::{CaptureInterval, ContentDigest, SensorId};

use super::ModelPoolError;
use super::cascade::{FramePixelInput, ReferenceFramePixels};
use super::registry::{ModelInferenceOutput, ResidentModelKey, ResidentModelPool};
use crate::ingest::rgb_inference::RgbRunLimits;
use crate::{ExecBudget, ScalarExecCx};

/// Hard ceiling on parallel scoped worker threads admitted by one pool executor.
pub const MAX_POOL_WORKERS: usize = 16;

/// Validated execution configuration for [`WorkerPoolExecutor`].
#[derive(Clone, Copy, Debug)]
pub struct WorkerPoolConfig {
    /// Explicit worker thread count in `1..=16`. `1` executes inline without spawning threads.
    pub worker_count: usize,
    /// Per-inference execution budget for activity `.fmpk` models.
    pub activity_exec_budget: ExecBudget,
    /// Per-inference preprocessing and graph execution limits for RGB detector `.fmpk` models.
    pub rgb_run_limits: RgbRunLimits,
    /// Per-inference head-projection work-unit allowance for RGB detector `.fmpk` models.
    pub rgb_detection_work_units: u64,
}

impl Default for WorkerPoolConfig {
    fn default() -> Self {
        Self {
            worker_count: 1,
            activity_exec_budget: ExecBudget::new(100_000_000, 64 * 1024 * 1024),
            rgb_run_limits: RgbRunLimits {
                decode: RgbDecodeLimits::default(),
                preprocess: ExecBudget::new(2_000_000_000, 128 * 1024 * 1024),
                execution: ExecBudget::new(8_000_000_000, 128 * 1024 * 1024),
                maximum_output_bytes: 16 * 1024 * 1024,
            },
            rgb_detection_work_units: 2_000_000_000,
        }
    }
}

impl WorkerPoolConfig {
    /// Creates a default config with an explicit `worker_count` (`1..=16`).
    pub fn with_workers(worker_count: usize) -> Result<Self, ModelPoolError> {
        let cfg = Self {
            worker_count,
            ..Self::default()
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validates worker count bounds before any inference runs.
    pub fn validate(&self) -> Result<(), ModelPoolError> {
        if self.worker_count == 0 || self.worker_count > MAX_POOL_WORKERS {
            return Err(ModelPoolError::InvalidConfig(
                "worker_count must be in 1..=16",
            ));
        }
        if self.activity_exec_budget.max_macs == 0 || self.activity_exec_budget.max_bytes == 0 {
            return Err(ModelPoolError::InvalidConfig(
                "activity_exec_budget limits must be positive",
            ));
        }
        Ok(())
    }
}

/// One admitted Stage-2 inference task borrowing caller frame pixels cleanly within a thread scope.
#[derive(Clone, Debug)]
pub struct InferenceTask<'a> {
    /// Canonical position in the epoch's sorted `(stream_order, frame_sequence, sensor_id)` array.
    pub canonical_index: usize,
    /// Deterministic stream ordinal.
    pub stream_order: u32,
    /// Monotonic frame sequence within the stream.
    pub frame_sequence: u64,
    /// Camera sensor identity.
    pub sensor_id: &'a SensorId,
    /// Immutable source payload digest.
    pub source_digest: ContentDigest,
    /// Conservative source capture interval.
    pub capture_interval: CaptureInterval,
    /// Frame dimensions `[width, height]`.
    pub dimensions: [u32; 2],
    /// Borrowed frame pixel buffer.
    pub pixels: &'a FramePixelInput,
    /// Baseline reference frame for two-frame activity models.
    pub reference_pixels: Option<Arc<ReferenceFramePixels>>,
    /// Exact resident model key to acquire from [`ResidentModelPool`].
    pub model_key: &'a ResidentModelKey,
}

/// Output of one executed [`InferenceTask`], carrying non-identity wall-clock timing separately.
#[derive(Clone, Debug)]
pub struct WorkerTaskResult {
    /// Original canonical frame index.
    pub canonical_index: usize,
    /// Bit-exact numerical inference output.
    pub output: ModelInferenceOutput,
    /// Non-identity inference duration in nanoseconds (telemetry only; excluded from all digests).
    pub duration_ns: u64,
}

/// Scoped, bounded multi-worker ML inference executor with deterministic canonical result merging.
#[derive(Clone, Copy, Debug)]
pub struct WorkerPoolExecutor {
    config: WorkerPoolConfig,
}

impl WorkerPoolExecutor {
    /// Validates configuration and constructs a new executor.
    pub fn new(config: WorkerPoolConfig) -> Result<Self, ModelPoolError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Returns the validated worker configuration.
    #[must_use]
    pub const fn config(&self) -> WorkerPoolConfig {
        self.config
    }

    /// Executes `tasks` across `1..=worker_count` scoped threads and returns results sorted
    /// strictly by `canonical_index`.
    ///
    /// Cancellation through `cx` stops pending tasks cooperatively and completes drain/finalize
    /// before joining every scoped thread. No detached thread is ever created.
    #[allow(clippy::result_large_err)]
    pub fn execute_tasks(
        &self,
        pool: &ResidentModelPool,
        tasks: &[InferenceTask<'_>],
        cx: &ScalarExecCx,
    ) -> Result<Vec<WorkerTaskResult>, ModelPoolError> {
        cx.checkpoint("model_pool:worker_begin")?;
        if tasks.is_empty() {
            return Ok(Vec::new());
        }

        let worker_count = self.config.worker_count.min(tasks.len());
        if worker_count == 1 {
            let mut results = Vec::with_capacity(tasks.len());
            for task in tasks {
                cx.checkpoint("model_pool:worker_task")?;
                results.push(self.execute_one(pool, task, cx)?);
            }
            results.sort_by_key(|r| r.canonical_index);
            return Ok(results);
        }

        let next_idx = AtomicUsize::new(0);
        let abort_flag = AtomicBool::new(false);

        let worker_outputs = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(worker_count);
            for _ in 0..worker_count {
                let next_idx_ref = &next_idx;
                let abort_ref = &abort_flag;
                let handle = scope.spawn(
                    move || -> Result<Vec<WorkerTaskResult>, (usize, ModelPoolError)> {
                        let mut local = Vec::new();
                        loop {
                            if cx.is_cancelled() {
                                cx.drain_and_finalize();
                                abort_ref.store(true, Ordering::Release);
                                return Err((usize::MAX, ModelPoolError::Cancelled));
                            }
                            if abort_ref.load(Ordering::Acquire) {
                                break;
                            }
                            let idx = next_idx_ref.fetch_add(1, Ordering::Relaxed);
                            if idx >= tasks.len() {
                                break;
                            }
                            let task = &tasks[idx];
                            match self.execute_one(pool, task, cx) {
                                Ok(res) => local.push(res),
                                Err(err) => {
                                    abort_ref.store(true, Ordering::Release);
                                    return Err((task.canonical_index, err));
                                }
                            }
                        }
                        Ok(local)
                    },
                );
                handles.push(handle);
            }

            let mut merged = Vec::with_capacity(tasks.len());
            let mut first_error: Option<(usize, ModelPoolError)> = None;
            let mut panicked = false;

            for handle in handles {
                match handle.join() {
                    Ok(Ok(mut local)) => merged.append(&mut local),
                    Ok(Err((idx, err))) => {
                        let replace = match &first_error {
                            None => true,
                            Some((prev_idx, _)) => idx < *prev_idx,
                        };
                        if replace {
                            first_error = Some((idx, err));
                        }
                    }
                    Err(_) => {
                        panicked = true;
                    }
                }
            }

            if panicked {
                return Err(ModelPoolError::WorkerPanicked);
            }
            if cx.is_cancelled() {
                cx.drain_and_finalize();
                return Err(ModelPoolError::Cancelled);
            }
            if let Some((_, err)) = first_error {
                return Err(err);
            }
            Ok(merged)
        })?;

        let mut results = worker_outputs;
        results.sort_by_key(|r| r.canonical_index);
        cx.checkpoint("model_pool:worker_complete")?;
        Ok(results)
    }

    fn execute_one(
        &self,
        pool: &ResidentModelPool,
        task: &InferenceTask<'_>,
        cx: &ScalarExecCx,
    ) -> Result<WorkerTaskResult, ModelPoolError> {
        cx.checkpoint("model_pool:execute_one")?;
        let started = Instant::now();
        let model = pool.acquire(task.model_key)?;
        let output = if model.is_activity() {
            let reference = task
                .reference_pixels
                .as_ref()
                .ok_or(ModelPoolError::InvalidInput(
                    "activity inference task missing baseline reference frame",
                ))?;
            model.infer_activity(
                task.pixels.as_bytes(),
                task.pixels.channels(),
                &reference.bytes,
                reference.channels,
                task.dimensions,
                self.config.activity_exec_budget,
                cx,
            )?
        } else {
            let rgb_owned;
            let rgb_slice = match task.pixels {
                FramePixelInput::Rgb { pixels } => pixels.as_slice(),
                FramePixelInput::Luma { .. } => {
                    rgb_owned = task.pixels.to_rgb_bytes();
                    rgb_owned.as_slice()
                }
            };
            model.infer_rgb_detector(
                rgb_slice,
                task.dimensions,
                task.source_digest,
                task.sensor_id,
                task.capture_interval,
                self.config.rgb_run_limits,
                self.config.rgb_detection_work_units,
                cx,
            )?
        };
        pool.record_inference();
        let duration_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        Ok(WorkerTaskResult {
            canonical_index: task.canonical_index,
            output,
            duration_ns,
        })
    }
}
