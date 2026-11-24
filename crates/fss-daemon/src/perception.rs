#![forbid(unsafe_code)]
//! Live perception pipeline (`PerceptionRegion`) uniting `C3` OSD ignore regions, `C5`
//! `ResidentModelPool` / `TwoStageCascade` / `FairShareScheduler`, and `C8`
//! `LiveCorroborationEngine` (`fss-fusion` milliban LLR).
//!
//! Semantic plane: `"cognition"`.
//!
//! # Constitutional Boundary (Cognition != Authority)
//! This module NEVER executes external alert effects or mutates policies. Corroborated
//! multi-camera detections emit verified canonical `EventHypothesis` revisions (`Corroborated`
//! with `PrepareAlert`, or `Indeterminate` with `Hold` for shared failure domains / insufficient
//! evidence), which are committed to the canonical ledger and pushed to `fss-ipc` subscribers.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    SensorId, TimestampNs,
};
use fss_fusion::ScoreCalibration;
use fss_reference::ingest::live_corroborate::{
    ClockEstimatorConfig, ClockObservationSample, CorroborationOutcome, LiveCorroborationConfig,
    LiveCorroborationDecision, LiveCorroborationEngine, LiveFusionConfig, LiveObservation,
    SlidingWindowConfig,
};
use fss_reference::ingest::model_pool::{
    BatchBenchmarkMetrics, BatchExecutionReceipt, CameraQuotaConfig, CascadePolicyConfig,
    FairShareScheduler, ModelPoolEngine, PoolBudgetConfig, ResidentModelKey, ResidentModelPool,
    ResourcePressure, StageDecision, StreamFrameInput, StreamRegistration, TwoStageCascade,
    WorkerPoolConfig, WorkerPoolExecutor,
};
use fss_reference::{KernelBackend, ReplayCx, ScalarExecCx};

use crate::error::DaemonError;
use crate::manifest::SiteManifest;
use crate::sensor::CameraFrame;

const MAX_DETECTOR_PACKAGE_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_DETECTOR_IMPORT_WORK: u64 = 64_000_000;

/// Configuration for [`PerceptionEngine`].
#[derive(Clone, Debug)]
pub struct PerceptionConfig {
    /// Number of scoped worker threads for `WorkerPoolExecutor` (`1..=16`).
    pub worker_count: usize,
    /// Periodic keyframe sentinel interval in quiescent keyframes.
    pub sentinel_interval_frames: u64,
    /// Minimum foreground pixel count outside OSD ignore regions to trigger Stage-2 ML.
    pub min_foreground_pixels_trigger: usize,
    /// Optional explicit verified `.fmpk` RGB detector package path (overrides manifest).
    pub detector_package_path: Option<PathBuf>,
    /// Required pinned SHA-256 digest of `detector_package_path` whenever configured.
    pub detector_package_digest: Option<ContentDigest>,
    /// Optional detection score threshold override in parts per million (`1..=1_000_000`).
    pub detector_min_score_ppm: Option<u32>,
    /// Optional explicit calibrated [`ScoreCalibration`] table for `"person"` / default detections.
    pub default_calibration: Option<ScoreCalibration>,
    /// Optional explicit per-class [`ScoreCalibration`] overrides.
    pub class_calibrations: BTreeMap<String, ScoreCalibration>,
    /// Optional custom [`ClockEstimatorConfig`].
    pub clock_config: ClockEstimatorConfig,
    /// Optional custom [`SlidingWindowConfig`].
    pub window_config: SlidingWindowConfig,
}

impl Default for PerceptionConfig {
    fn default() -> Self {
        Self {
            worker_count: 2,
            sentinel_interval_frames: 16,
            min_foreground_pixels_trigger: 8,
            detector_package_path: None,
            detector_package_digest: None,
            detector_min_score_ppm: None,
            default_calibration: None,
            class_calibrations: BTreeMap::new(),
            clock_config: ClockEstimatorConfig::default(),
            window_config: SlidingWindowConfig::default(),
        }
    }
}

/// Complete deterministic output of one perception epoch tick.
#[derive(Clone, Debug)]
pub struct PerceptionTickOutcome {
    /// Canonical `C5` batch execution receipt (including `UnsampledGapLedger`).
    pub batch_receipt: BatchExecutionReceipt,
    /// Non-identity throughput, latency, and zero-reload metrics.
    pub metrics: BatchBenchmarkMetrics,
    /// All cross-camera corroboration decisions produced during this tick.
    pub decisions: Vec<LiveCorroborationDecision>,
    /// Peak inference-pool resource pressure observed in this tick.
    pub pressure: ResourcePressure,
    /// Count of `Corroborated` decisions emitted in this tick.
    pub corroborated_count: u64,
    /// Count of `SharedFailureDomainHeld` decisions emitted in this tick.
    pub shared_domain_held_count: u64,
    /// Count of `ClockUncertaintyAbstained` decisions emitted in this tick.
    pub abstained_count: u64,
    /// Count of `InsufficientEvidenceHeld` decisions emitted in this tick.
    pub insufficient_evidence_count: u64,
}

/// Cognition-plane orchestrator executing `C3` + `C5` + `C8` across all supervised cameras.
pub struct PerceptionEngine {
    config: PerceptionConfig,
    pool: ResidentModelPool,
    model_key: ResidentModelKey,
    rgb_detector_active: bool,
    model_engine: ModelPoolEngine,
    corroborator: LiveCorroborationEngine,
    scalar_cx: ScalarExecCx,
    epoch_id: u64,
    next_track_id: u64,
}

impl PerceptionEngine {
    /// Constructs a validated [`PerceptionEngine`] bound to `manifest`, verifying and pinning
    /// the pure-Rust resident `.fmpk` model ONCE into [`ResidentModelPool`].
    ///
    /// When `config.detector_package_path` (or `manifest.detector_package_path`) is configured
    /// with its required pinned SHA-256 `detector_package_digest`, the real offline RGB detector
    /// `.fmpk` (e.g., YOLOX-Nano) is verified and pinned; otherwise the committed pure-Rust
    /// activity `.fmpk` package is pinned.
    pub fn new(manifest: &SiteManifest, config: PerceptionConfig) -> Result<Self, DaemonError> {
        let scalar_cx = ScalarExecCx::new();
        let pool = ResidentModelPool::default_bounded();
        let (model_key, rgb_detector_active) =
            resolve_resident_model(&pool, manifest, &config, &scalar_cx)?;

        let model_engine = build_model_engine(manifest, &config)?;
        let corroborator = build_corroborator(manifest, &config)?;

        Ok(Self {
            config,
            pool,
            model_key,
            rgb_detector_active,
            model_engine,
            corroborator,
            scalar_cx,
            epoch_id: 0,
            next_track_id: 1,
        })
    }

    /// Returns `true` when an offline verified RGB detector `.fmpk` (e.g. YOLOX-Nano) is active.
    #[must_use]
    pub const fn is_rgb_detector_active(&self) -> bool {
        self.rgb_detector_active
    }

    /// Rebuilds the cascade, fair-share quotas, and site corroboration topology from a newly
    /// validated `SiteManifest` while retaining the already-pinned `ResidentModelPool` with
    /// zero weight reloads when the pinned detector package is unchanged (or verifying and
    /// pinning an updated manifest detector package when explicitly changed).
    pub fn reload_manifest(&mut self, manifest: &SiteManifest) -> Result<(), DaemonError> {
        let (model_key, rgb_detector_active) =
            resolve_resident_model(&self.pool, manifest, &self.config, &self.scalar_cx)?;
        let model_engine = build_model_engine(manifest, &self.config)?;
        let corroborator = build_corroborator(manifest, &self.config)?;
        self.model_key = model_key;
        self.rgb_detector_active = rgb_detector_active;
        self.model_engine = model_engine;
        self.corroborator = corroborator;
        Ok(())
    }

    /// Runs an explicit operator-triggered Stage-2 ML probe over the provided frames by forcing
    /// Stage-2 sentinel admission through the already-pinned `ResidentModelPool` (zero weight
    /// reloads) without mutating source custody bytes.
    pub fn probe_frames(
        &mut self,
        frames: &[Arc<CameraFrame>],
    ) -> Result<Option<PerceptionTickOutcome>, DaemonError> {
        if frames.is_empty() {
            return Ok(None);
        }
        let mut probed = Vec::with_capacity(frames.len());
        for (idx, frame) in frames.iter().enumerate() {
            let mut copy = (**frame).clone();
            copy.is_keyframe = true;
            // Assign a distinct probe sequence strictly ahead of live sequence collisions within
            // this probe epoch so duplicate-frame guards never reject a re-probed latest frame.
            copy.sequence = frame
                .sequence
                .saturating_add(1_000_000_000)
                .saturating_add(self.epoch_id.saturating_mul(64))
                .saturating_add(idx as u64);
            probed.push(Arc::new(copy));
        }
        self.process_frames_inner(&probed, true)
    }

    /// Runs one multi-camera perception epoch: Stage-1 OSD-masked motion watch -> `FairShareScheduler`
    /// -> Stage-2 `ResidentModelPool` inference -> `LiveCorroborationEngine` (`fss-fusion`).
    pub fn process_frames(
        &mut self,
        frames: &[Arc<CameraFrame>],
    ) -> Result<Option<PerceptionTickOutcome>, DaemonError> {
        self.process_frames_inner(frames, false)
    }

    fn process_frames_inner(
        &mut self,
        frames: &[Arc<CameraFrame>],
        force_stage2_probe: bool,
    ) -> Result<Option<PerceptionTickOutcome>, DaemonError> {
        if frames.is_empty() {
            return Ok(None);
        }
        self.epoch_id = self.epoch_id.saturating_add(1);

        let mut inputs = Vec::with_capacity(frames.len());
        let mut frame_lookup: BTreeMap<(SensorId, u64), &Arc<CameraFrame>> = BTreeMap::new();
        for frame in frames {
            let earliest = TimestampNs(
                frame
                    .host_receive_ns
                    .saturating_sub(i128::from(frame.rtt_jitter_ns))
                    .saturating_sub(i128::from(frame.node_clock_uncertainty_ns)),
            );
            let latest = TimestampNs(
                frame
                    .host_receive_ns
                    .saturating_add(i128::from(frame.node_clock_uncertainty_ns)),
            );
            let capture_interval = CaptureInterval::new(earliest, latest)?;
            inputs.push(StreamFrameInput {
                sensor_id: frame.sensor_id.clone(),
                frame_sequence: frame.sequence,
                capture_interval,
                source_digest: frame.source_digest,
                dimensions: frame.dimensions,
                is_keyframe: frame.is_keyframe,
                pixels: frame.pixels.clone(),
            });
            frame_lookup.insert((frame.sensor_id.clone(), frame.sequence), frame);
        }

        let (batch_receipt, metrics) = if force_stage2_probe {
            self.model_engine.process_forced_probe_epoch(
                &self.pool,
                &self.model_key,
                self.epoch_id,
                &inputs,
                None,
                &self.scalar_cx,
            )?
        } else {
            self.model_engine.process_epoch(
                &self.pool,
                &self.model_key,
                self.epoch_id,
                &inputs,
                None,
                &self.scalar_cx,
            )?
        };

        let mut decisions = Vec::new();
        for frame_receipt in &batch_receipt.frames {
            let Some(orig_frame) = frame_lookup.get(&(
                frame_receipt.sensor_id.clone(),
                frame_receipt.frame_sequence,
            )) else {
                continue;
            };
            let clock_sample = ClockObservationSample {
                media_pts_ns: orig_frame.media_pts_ns,
                host_receive_ns: orig_frame.host_receive_ns,
                rtt_jitter_ns: orig_frame.rtt_jitter_ns,
                node_clock_uncertainty_ns: orig_frame.node_clock_uncertainty_ns,
            };
            let bounded_capture = self
                .corroborator
                .observe_clock_sample(orig_frame.sensor_id.as_str(), clock_sample)?;

            if !frame_receipt.stage_decision.ran_ml_inference() {
                continue;
            }

            if !frame_receipt.detections.is_empty() {
                let base_track = self.alloc_track_id();
                let mut found = self.corroborator.ingest_cascade_receipt(
                    frame_receipt,
                    orig_frame.stream_id.as_str(),
                    &orig_frame.zone_id,
                    base_track,
                    clock_sample,
                )?;
                decisions.append(&mut found);
                continue;
            }

            // Activity model admitted a Stage-1 motion frame: promote any bound detection hints
            // (preserving exact source_digest, model_receipt_digest, and cascade_receipt_digest).
            if frame_receipt.stage_decision == StageDecision::MotionTriggered {
                let model_digest = frame_receipt
                    .inference_output_digest
                    .unwrap_or(frame_receipt.receipt_digest);
                for hint in &orig_frame.synthetic_detections {
                    let zone = hint
                        .zone_id
                        .as_deref()
                        .unwrap_or(orig_frame.zone_id.as_str());
                    let track_id = if hint.track_id > 0 {
                        hint.track_id
                    } else {
                        self.alloc_track_id()
                    };
                    let obs = LiveObservation {
                        sensor_id: orig_frame.sensor_id.as_str().to_owned(),
                        stream_id: orig_frame.stream_id.as_str().to_owned(),
                        zone_id: zone.to_owned(),
                        track_id,
                        foot_px: hint.foot_px,
                        class_label: hint.class_label.clone(),
                        score_ppm: hint.score_ppm.min(1_000_000),
                        bounded_capture,
                        source_capsule_digest: frame_receipt.source_digest,
                        model_receipt_digest: model_digest,
                        cascade_receipt_digest: frame_receipt.receipt_digest,
                    };
                    let mut found = self.corroborator.ingest_observation(obs)?;
                    decisions.append(&mut found);
                }
            }
        }

        let mut corroborated_count = 0_u64;
        let mut shared_domain_held_count = 0_u64;
        let mut abstained_count = 0_u64;
        let mut insufficient_evidence_count = 0_u64;
        for d in &decisions {
            match d.outcome {
                CorroborationOutcome::Corroborated { .. } => {
                    corroborated_count = corroborated_count.saturating_add(1);
                }
                CorroborationOutcome::SharedFailureDomainHeld { .. } => {
                    shared_domain_held_count = shared_domain_held_count.saturating_add(1);
                }
                CorroborationOutcome::ClockUncertaintyAbstained { .. } => {
                    abstained_count = abstained_count.saturating_add(1);
                }
                CorroborationOutcome::InsufficientEvidenceHeld { .. } => {
                    insufficient_evidence_count = insufficient_evidence_count.saturating_add(1);
                }
            }
        }

        let pressure = batch_receipt.pressure;
        Ok(Some(PerceptionTickOutcome {
            batch_receipt,
            metrics,
            decisions,
            pressure,
            corroborated_count,
            shared_domain_held_count,
            abstained_count,
            insufficient_evidence_count,
        }))
    }

    /// Requests cooperative cancellation of the perception executor during daemon drain.
    pub fn request_cancellation(&self) {
        self.scalar_cx.request_cancellation();
        self.scalar_cx.drain_and_finalize();
    }

    /// Returns resident model pool metrics proving zero weight reloads across all streams.
    #[must_use]
    pub fn pool_metrics(&self) -> fss_reference::ingest::model_pool::ModelLoadMetricsSnapshot {
        self.pool.metrics_snapshot()
    }

    /// Borrows the live corroboration engine for inspection of traces and topology.
    #[must_use]
    pub const fn corroborator(&self) -> &LiveCorroborationEngine {
        &self.corroborator
    }

    fn alloc_track_id(&mut self) -> u64 {
        let id = self.next_track_id;
        self.next_track_id = self.next_track_id.saturating_add(1);
        id
    }
}

fn resolve_resident_model(
    pool: &ResidentModelPool,
    manifest: &SiteManifest,
    config: &PerceptionConfig,
    scalar_cx: &ScalarExecCx,
) -> Result<(ResidentModelKey, bool), DaemonError> {
    let pkg_path = config
        .detector_package_path
        .as_ref()
        .or(manifest.detector_package_path.as_ref());
    let pkg_digest = config
        .detector_package_digest
        .or(manifest.detector_package_digest);
    let min_score_ppm = config
        .detector_min_score_ppm
        .or(manifest.detector_min_score_ppm);

    if let Some(path) = pkg_path {
        let expected_digest = pkg_digest.ok_or_else(|| DaemonError::InvalidManifest {
            detail: "detector_package_path requires pinned detector_package_digest".to_owned(),
        })?;
        let bytes = read_bounded_detector_package(path)?;
        let replay_cx = build_detector_replay_cx(&manifest.site_id, expected_digest)?;
        let resident = pool.load_or_get_rgb_detector(
            &bytes,
            expected_digest,
            DEFAULT_DETECTOR_IMPORT_WORK,
            KernelBackend::OptimizedCpuV1,
            min_score_ppm,
            &replay_cx,
            scalar_cx,
        )?;
        Ok((resident.key().clone(), true))
    } else {
        let resident =
            pool.load_or_get_activity_committed(KernelBackend::ScalarReference, scalar_cx)?;
        Ok((resident.key().clone(), false))
    }
}

fn read_bounded_detector_package(path: &Path) -> Result<Vec<u8>, DaemonError> {
    let meta =
        fs::symlink_metadata(path).map_err(|err| DaemonError::io("stat_detector_package", err))?;
    if !meta.file_type().is_file() || meta.file_type().is_symlink() {
        return Err(DaemonError::InvalidConfig {
            detail: "detector_package_path must be a non-symlink regular file".to_owned(),
        });
    }
    if meta.len() == 0 || meta.len() > MAX_DETECTOR_PACKAGE_BYTES {
        return Err(DaemonError::InvalidConfig {
            detail: format!(
                "detector package size {} exceeds bound 1..={MAX_DETECTOR_PACKAGE_BYTES}",
                meta.len()
            ),
        });
    }
    let file = File::open(path).map_err(|err| DaemonError::io("open_detector_package", err))?;
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    file.take(MAX_DETECTOR_PACKAGE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|err| DaemonError::io("read_detector_package", err))?;
    if bytes.is_empty() || (bytes.len() as u64) > MAX_DETECTOR_PACKAGE_BYTES {
        return Err(DaemonError::InvalidConfig {
            detail: format!("detector package size exceeds bound 1..={MAX_DETECTOR_PACKAGE_BYTES}"),
        });
    }
    Ok(bytes)
}

fn build_model_engine(
    manifest: &SiteManifest,
    config: &PerceptionConfig,
) -> Result<ModelPoolEngine, DaemonError> {
    let default_dims = manifest
        .cameras
        .first()
        .map_or([32, 32], |cam| cam.dimensions);
    let mut cascade_policy = CascadePolicyConfig::default_for_dimensions(default_dims);
    cascade_policy.min_foreground_pixels_trigger = config.min_foreground_pixels_trigger;
    cascade_policy.sentinel_interval_frames = config.sentinel_interval_frames;
    let mut cascade = TwoStageCascade::new(cascade_policy)?;

    let mut pool_budget = PoolBudgetConfig::default();
    for (order, cam) in manifest.cameras.iter().enumerate() {
        cascade.register_stream(StreamRegistration {
            sensor_id: cam.sensor_id.clone(),
            stream_order: order as u32,
            priority: cam.priority_tier,
            dimensions: cam.dimensions,
            ignore_regions: cam.osd_ignore_rects.clone(),
        })?;
        pool_budget.camera_overrides.insert(
            cam.sensor_id.clone(),
            CameraQuotaConfig {
                priority: cam.priority_tier,
                min_guaranteed_frames_per_epoch: 1,
                max_burst_frames_per_epoch: 8,
            },
        );
    }

    let scheduler = FairShareScheduler::new(pool_budget)?;
    let workers =
        WorkerPoolExecutor::new(WorkerPoolConfig::with_workers(config.worker_count.max(1))?)?;
    Ok(ModelPoolEngine::new(cascade, scheduler, workers))
}

fn build_corroborator(
    manifest: &SiteManifest,
    config: &PerceptionConfig,
) -> Result<LiveCorroborationEngine, DaemonError> {
    let topology = manifest.to_site_topology()?;
    let mut fusion_cfg = LiveFusionConfig::default_policy()?;
    if let Some(cal) = config.default_calibration.clone() {
        fusion_cfg = fusion_cfg.with_default_calibration(cal);
    }
    for (label, cal) in &config.class_calibrations {
        fusion_cfg = fusion_cfg.with_calibration(label.clone(), cal.clone());
    }
    let live_cfg = LiveCorroborationConfig {
        clock: config.clock_config,
        window: config.window_config,
        fusion: fusion_cfg,
    };
    Ok(LiveCorroborationEngine::new(topology, live_cfg)?)
}

fn build_detector_replay_cx(
    site_id: &str,
    package_digest: ContentDigest,
) -> Result<ReplayCx, DaemonError> {
    let op_id = OperationId::parse("op:daemon:load_detector")?;
    let budgets = BudgetVector::builder()
        .bytes(MAX_DETECTOR_PACKAGE_BYTES)
        .model_calls(1_024)
        .build()
        .map_err(|err| DaemonError::InvalidConfig {
            detail: format!("detector replay budget failed: {err}"),
        })?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: format!("trace:daemon:{site_id}:detector-load"),
        operation_id: op_id,
        principal: "principal:local-daemon".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 1,
        budgets,
        privacy_scope: format!("privacy:{site_id}"),
        retention_scope: format!("retention:{site_id}"),
        anchor_universe: package_digest,
        generation: 1,
    })
    .map_err(|err| DaemonError::InvalidConfig {
        detail: format!("detector replay authority failed: {err}"),
    })?;
    ReplayCx::from_context_authority(&authority, std::env::temp_dir()).map_err(|err| {
        DaemonError::InvalidConfig {
            detail: format!("detector replay context failed: {err}"),
        }
    })
}
