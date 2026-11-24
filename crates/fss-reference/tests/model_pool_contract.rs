#![forbid(unsafe_code)]
//! Integration and benchmark contract tests for the multi-stream batched pure-Rust ML inference
//! worker pool (`fss_reference::ingest::model_pool`, bead `fss-x4a.31.3.5`).

use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, CaptureInterval, ContentDigest, OperationId, SensorId, TimestampNs};
use fss_reference::ingest::foreground::ForegroundConfig;
use fss_reference::ingest::model_pool::{
    CameraPriorityTier, CameraQuotaConfig, CascadePolicyConfig, FairShareScheduler,
    FramePixelInput, InferenceTask, ModelPoolEngine, ModelPoolError, PoolBudgetConfig,
    ReferenceFramePixels, ResidentModelPool, ResourcePressure, StageDecision, StreamFrameInput,
    StreamRegistration, TwoStageCascade, UnsampledReason, WorkerPoolConfig, WorkerPoolExecutor,
};
use fss_reference::ingest::osd_mask::ImageRect;
use fss_reference::{KernelBackend, ReplayCx, ScalarExecCx};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const YOLOX_NANO_SHA256: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";
const YOLOX_NANO_FMPK: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");

fn sensor(name: &str) -> TestResult<SensorId> {
    Ok(SensorId::parse(name)?)
}

fn capture(seq: u64) -> TestResult<CaptureInterval> {
    let base = i128::from(seq.saturating_add(1)) * 33_333_333;
    Ok(CaptureInterval::new(
        TimestampNs(base),
        TimestampNs(base + 1_000_000),
    )?)
}

fn replay_cx() -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:model-pool-contract".to_owned(),
        operation_id: OperationId::parse("op:model-pool-contract")?,
        principal: "principal:model-pool-contract".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 1,
        budgets: BudgetVector::builder()
            .bytes(128 * 1024 * 1024)
            .model_calls(20_000)
            .build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(b"model-pool-contract-universe"),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        std::env::temp_dir(),
    )?)
}

fn draw_rect_luma(buf: &mut [u8], dims: [u32; 2], rect: ImageRect, value: u8) {
    let w = dims[0] as usize;
    for y in rect.y as usize..(rect.y + rect.height) as usize {
        for x in rect.x as usize..(rect.x + rect.width) as usize {
            buf[y * w + x] = value;
        }
    }
}

fn luma_frame(
    sensor_id: &SensorId,
    frame_sequence: u64,
    dims: [u32; 2],
    is_keyframe: bool,
    pixels: Vec<u8>,
) -> TestResult<StreamFrameInput> {
    let source_digest = ContentDigest::sha256(&pixels);
    Ok(StreamFrameInput {
        sensor_id: sensor_id.clone(),
        frame_sequence,
        capture_interval: capture(frame_sequence)?,
        source_digest,
        dimensions: dims,
        is_keyframe,
        pixels: FramePixelInput::Luma { pixels },
    })
}

#[test]
fn zero_weight_reloads_over_ten_thousand_continuous_frames() -> TestResult {
    let cx = ScalarExecCx::new();
    let pool = ResidentModelPool::default_bounded();
    let resident = pool.load_or_get_activity_committed(KernelBackend::OptimizedCpuV1, &cx)?;
    assert_eq!(pool.metrics_snapshot().loads, 1);

    let dims = [32_u32, 32_u32];
    let cam = sensor("sensor:cam-10k")?;
    let baseline = Arc::new(ReferenceFramePixels {
        dimensions: dims,
        channels: 1,
        bytes: vec![40_u8; 32 * 32],
    });
    let mut active_pixels = vec![40_u8; 32 * 32];
    draw_rect_luma(&mut active_pixels, dims, ImageRect::new(8, 8, 12, 12)?, 210);
    let active_input = FramePixelInput::Luma {
        pixels: active_pixels,
    };
    let active_digest = ContentDigest::sha256(active_input.as_bytes());
    let static_input = FramePixelInput::Luma {
        pixels: vec![40_u8; 32 * 32],
    };
    let static_digest = ContentDigest::sha256(static_input.as_bytes());

    let workers = WorkerPoolExecutor::new(WorkerPoolConfig::with_workers(4)?)?;
    const TOTAL_FRAMES: usize = 10_000;
    const CHUNK_SIZE: usize = 500;
    let (mut active_bits, mut static_bits) = (None, None);

    for chunk_start in (0..TOTAL_FRAMES).step_by(CHUNK_SIZE) {
        let mut tasks = Vec::with_capacity(CHUNK_SIZE);
        for offset in 0..CHUNK_SIZE {
            let seq = (chunk_start + offset) as u64;
            let active = seq % 2 == 1;
            tasks.push(InferenceTask {
                canonical_index: offset,
                stream_order: 0,
                frame_sequence: seq,
                sensor_id: &cam,
                source_digest: if active { active_digest } else { static_digest },
                capture_interval: capture(seq)?,
                dimensions: dims,
                pixels: if active { &active_input } else { &static_input },
                reference_pixels: Some(Arc::clone(&baseline)),
                model_key: resident.key(),
            });
        }
        let results = workers.execute_tasks(&pool, &tasks, &cx)?;
        assert_eq!(results.len(), CHUNK_SIZE);
        for (i, res) in results.iter().enumerate() {
            let bits = res
                .output
                .activity_score_bits
                .ok_or("missing activity score")?;
            if (chunk_start + i) % 2 == 1 {
                assert_eq!(bits, *active_bits.get_or_insert(bits));
                assert!(f32::from_bits(bits) > 0.01);
            } else {
                assert_eq!(bits, *static_bits.get_or_insert(bits));
                assert_eq!(f32::from_bits(bits), 0.0);
            }
        }
    }

    let snap = pool.metrics_snapshot();
    assert_eq!(snap.loads, 1);
    assert!(snap.cache_hits >= TOTAL_FRAMES as u64);
    assert_eq!(snap.frames_inferred, TOTAL_FRAMES as u64);
    Ok(())
}

#[test]
fn bit_exact_multi_worker_determinism_across_1_2_4_8_workers() -> TestResult {
    let cx = ScalarExecCx::new();
    let pool = ResidentModelPool::default_bounded();
    let resident = pool.load_or_get_activity_committed(KernelBackend::OptimizedCpuV1, &cx)?;
    let dims = [32_u32, 32_u32];

    let mut frames = Vec::new();
    for cam in 0..16_u32 {
        let s = sensor(&format!("sensor:det-cam-{cam:02}"))?;
        for seq in 0..12_u64 {
            let mut buf = vec![(30 + cam * 3) as u8; 32 * 32];
            if cam % 5 == 0 && (3..=6).contains(&seq) {
                let x = ((seq as u32 * 3) % 20).min(20);
                draw_rect_luma(&mut buf, dims, ImageRect::new(x, 10, 6, 6)?, 235);
            }
            frames.push(luma_frame(&s, seq, dims, seq % 3 == 0, buf)?);
        }
    }
    let mut shuffled = frames.clone();
    shuffled.reverse();

    let run = |worker_count: usize, input: &[StreamFrameInput]| -> TestResult<_> {
        let mut policy = CascadePolicyConfig::default_for_dimensions(dims);
        policy.sentinel_interval_frames = 2;
        policy.quiescent_keyframe_only = true;
        let mut cascade = TwoStageCascade::new(policy)?;
        for cam in 0..16_u32 {
            let priority = match cam % 4 {
                0 => CameraPriorityTier::ActiveInvestigation,
                1 => CameraPriorityTier::HighConsequenceZone,
                2 => CameraPriorityTier::CorroboratedTrack,
                _ => CameraPriorityTier::Standard,
            };
            cascade.register_stream(StreamRegistration {
                sensor_id: sensor(&format!("sensor:det-cam-{cam:02}"))?,
                stream_order: cam,
                priority,
                dimensions: dims,
                ignore_regions: Vec::new(),
            })?;
        }
        let budget = PoolBudgetConfig {
            budget_vector: BudgetVector::builder()
                .model_calls(28)
                .bytes(64 * 1024 * 1024)
                .build()?,
            default_camera_quota: CameraQuotaConfig {
                priority: CameraPriorityTier::Standard,
                min_guaranteed_frames_per_epoch: 1,
                max_burst_frames_per_epoch: 4,
            },
            ..PoolBudgetConfig::default()
        };
        let mut engine = ModelPoolEngine::new(
            cascade,
            FairShareScheduler::new(budget)?,
            WorkerPoolExecutor::new(WorkerPoolConfig::with_workers(worker_count)?)?,
        );
        let (batch, _) = engine.process_epoch(&pool, resident.key(), 42, input, None, &cx)?;
        Ok(batch)
    };

    let baseline = run(1, &frames)?;
    assert!(baseline.frames_inferred > 0 && baseline.frames_quiescent_skipped > 0);
    for worker_count in [2_usize, 4, 8] {
        let candidate = run(worker_count, &frames)?;
        assert_eq!(baseline.batch_digest, candidate.batch_digest);
        assert_eq!(baseline.frames, candidate.frames);
        assert_eq!(baseline.unsampled_gaps, candidate.unsampled_gaps);
        assert_eq!(baseline.declined, candidate.declined);
    }
    assert_eq!(baseline.batch_digest, run(4, &shuffled)?.batch_digest);
    assert_eq!(pool.metrics_snapshot().loads, 1);
    Ok(())
}

#[test]
fn anti_starvation_fair_share_noisy_camera_cannot_starve_15_quiet_cameras() -> TestResult {
    let cx = ScalarExecCx::new();
    let pool = ResidentModelPool::default_bounded();
    let resident = pool.load_or_get_activity_committed(KernelBackend::OptimizedCpuV1, &cx)?;
    let dims = [32_u32, 32_u32];
    let mut policy = CascadePolicyConfig::default_for_dimensions(dims);
    policy.quiescent_keyframe_only = false;
    policy.sentinel_interval_frames = 2;
    let mut cascade = TwoStageCascade::new(policy)?;

    let noisy_sensor = sensor("sensor:cam-00-noisy")?;
    cascade.register_stream(StreamRegistration {
        sensor_id: noisy_sensor.clone(),
        stream_order: 0,
        priority: CameraPriorityTier::Standard,
        dimensions: dims,
        ignore_regions: Vec::new(),
    })?;
    let mut quiet_sensors = Vec::with_capacity(15);
    for cam in 1..=15_u32 {
        let s = sensor(&format!("sensor:cam-{cam:02}-quiet"))?;
        cascade.register_stream(StreamRegistration {
            sensor_id: s.clone(),
            stream_order: cam,
            priority: CameraPriorityTier::Standard,
            dimensions: dims,
            ignore_regions: Vec::new(),
        })?;
        quiet_sensors.push(s);
    }

    let budget = PoolBudgetConfig {
        budget_vector: BudgetVector::builder()
            .model_calls(20)
            .bytes(64 * 1024 * 1024)
            .build()?,
        max_work_units_per_epoch: 100_000_000,
        max_macs_per_epoch: 100_000_000,
        max_memory_bytes: 64 * 1024 * 1024,
        estimated_work_units_per_inference: 2_000,
        estimated_macs_per_inference: 2_048,
        estimated_bytes_per_inference: 4_096,
        default_camera_quota: CameraQuotaConfig {
            priority: CameraPriorityTier::Standard,
            min_guaranteed_frames_per_epoch: 1,
            max_burst_frames_per_epoch: 6,
        },
        camera_overrides: BTreeMap::new(),
    };
    let mut engine = ModelPoolEngine::new(
        cascade,
        FairShareScheduler::new(budget)?,
        WorkerPoolExecutor::new(WorkerPoolConfig::with_workers(4)?)?,
    );

    let mut frames = Vec::new();
    for seq in 0..=20_u64 {
        let mut pixels = vec![35_u8; 32 * 32];
        if seq > 0 {
            let x = ((seq as u32 * 5) % 22).min(22);
            let y = ((seq as u32 * 3) % 22).min(22);
            draw_rect_luma(&mut pixels, dims, ImageRect::new(x, y, 8, 8)?, 240);
        }
        frames.push(luma_frame(&noisy_sensor, seq, dims, true, pixels)?);
    }
    for q in &quiet_sensors {
        for seq in 0..=2_u64 {
            frames.push(luma_frame(q, seq, dims, true, vec![50_u8; 32 * 32])?);
        }
    }

    let (batch, _) = engine.process_epoch(&pool, resident.key(), 1, &frames, None, &cx)?;
    assert_eq!(batch.frames_inferred, 20);
    assert_eq!(batch.frames_throttled, 15);
    assert_eq!(batch.declined.len(), 15);
    assert_eq!(batch.pressure, ResourcePressure::Critical);
    assert_eq!(batch.unsampled_gaps.budget_throttled_count, 15);

    for q in &quiet_sensors {
        let count = batch
            .frames
            .iter()
            .filter(|f| &f.sensor_id == q && f.stage_decision == StageDecision::SentinelSweep)
            .count();
        assert_eq!(count, 1, "quiet camera {} starved", q.as_str());
    }
    let noisy_inferred = batch
        .frames
        .iter()
        .filter(|f| f.sensor_id == noisy_sensor && f.stage_decision.ran_ml_inference())
        .count();
    assert_eq!(noisy_inferred, 5);
    for d in &batch.declined {
        assert_eq!(d.sensor_id, noisy_sensor);
        assert_eq!(d.unsampled_reason, UnsampledReason::BudgetThrottled);
        assert_eq!(d.pressure, ResourcePressure::Critical);
    }
    Ok(())
}

#[test]
fn osd_ignore_region_suppresses_clock_triggers_real_motion_and_preserves_custody() -> TestResult {
    let cx = ScalarExecCx::new();
    let pool = ResidentModelPool::default_bounded();
    let resident = pool.load_or_get_activity_committed(KernelBackend::OptimizedCpuV1, &cx)?;
    let dims = [48_u32, 32_u32];
    let clock_rect = ImageRect::new(0, 0, 12, 6)?;
    let person_rect = ImageRect::new(24, 10, 10, 14)?;

    let mut cascade = TwoStageCascade::new(CascadePolicyConfig {
        foreground: ForegroundConfig {
            base_threshold: 20,
            threshold_sigma: 2,
            learning_rate_num: 16,
            learning_rate_den: 256,
            minimum_region_pixels: 8,
            dimensions: dims,
        },
        min_foreground_pixels_trigger: 8,
        sentinel_interval_frames: 5,
        post_motion_hold_frames: 1,
        quiescent_keyframe_only: false,
        sentinel_on_first_keyframe: false,
        enable_sensor_health: false,
        health_max_samples_per_stream: 1024 * 1024,
    })?;
    let cam = sensor("sensor:porch-osd")?;
    cascade.register_stream(StreamRegistration {
        sensor_id: cam.clone(),
        stream_order: 0,
        priority: CameraPriorityTier::HighConsequenceZone,
        dimensions: dims,
        ignore_regions: vec![clock_rect],
    })?;
    let mut engine = ModelPoolEngine::new(
        cascade,
        FairShareScheduler::new(PoolBudgetConfig::default())?,
        WorkerPoolExecutor::new(WorkerPoolConfig::with_workers(2)?)?,
    );

    let mut frames = Vec::new();
    let mut orig_digests = Vec::new();
    for seq in 0..=8_u64 {
        let mut pixels = vec![45_u8; (dims[0] * dims[1]) as usize];
        draw_rect_luma(
            &mut pixels,
            dims,
            clock_rect,
            if seq % 2 == 0 { 245 } else { 10 },
        );
        if seq == 7 {
            draw_rect_luma(&mut pixels, dims, person_rect, 235);
        }
        orig_digests.push(ContentDigest::sha256(&pixels));
        frames.push(luma_frame(&cam, seq, dims, true, pixels)?);
    }

    let (batch, _) = engine.process_epoch(&pool, resident.key(), 1, &frames, None, &cx)?;
    for (i, frame) in frames.iter().enumerate() {
        assert_eq!(
            ContentDigest::sha256(frame.pixels.as_bytes()),
            orig_digests[i]
        );
    }
    for (seq, frame) in batch.frames.iter().enumerate().take(9) {
        let expected = match seq {
            5 => StageDecision::SentinelSweep,
            7 => StageDecision::MotionTriggered,
            _ => StageDecision::QuiescentSkipped,
        };
        assert_eq!(frame.stage_decision, expected);
        assert_eq!(frame.stage1.osd_ignore_region_count, 1);
        assert_eq!(frame.unsampled_gap_recorded, !expected.ran_ml_inference());
        assert!(!frame.absence_certifiable);
    }
    assert_eq!(batch.frames_motion_triggered, 1);
    assert_eq!(batch.frames_sentinel_swept, 1);
    assert_eq!(batch.unsampled_gaps.len(), 7);
    Ok(())
}

#[test]
fn sixteen_stream_throughput_and_idle_cpu_reduction_benchmark() -> TestResult {
    let cx = ScalarExecCx::new();
    let pool = ResidentModelPool::default_bounded();
    let resident = pool.load_or_get_activity_committed(KernelBackend::OptimizedCpuV1, &cx)?;

    let dims = [64_u32, 48_u32];
    const STREAMS: u32 = 16;
    const FRAMES_PER_STREAM: u64 = 64;
    let mut policy = CascadePolicyConfig::default_for_dimensions(dims);
    policy.quiescent_keyframe_only = true;
    policy.sentinel_interval_frames = 3;
    policy.post_motion_hold_frames = 1;
    let mut cascade = TwoStageCascade::new(policy)?;

    let mut sensors = Vec::with_capacity(STREAMS as usize);
    for cam in 0..STREAMS {
        let s = sensor(&format!("sensor:bench-cam-{cam:02}"))?;
        cascade.register_stream(StreamRegistration {
            sensor_id: s.clone(),
            stream_order: cam,
            priority: if cam < 3 {
                CameraPriorityTier::HighConsequenceZone
            } else {
                CameraPriorityTier::Standard
            },
            dimensions: dims,
            ignore_regions: vec![ImageRect::new(0, 0, 12, 6)?],
        })?;
        sensors.push(s);
    }

    let budget = PoolBudgetConfig {
        budget_vector: BudgetVector::builder()
            .model_calls(512)
            .bytes(128 * 1024 * 1024)
            .build()?,
        max_work_units_per_epoch: 500_000_000,
        max_macs_per_epoch: 500_000_000,
        max_memory_bytes: 128 * 1024 * 1024,
        default_camera_quota: CameraQuotaConfig {
            priority: CameraPriorityTier::Standard,
            min_guaranteed_frames_per_epoch: 2,
            max_burst_frames_per_epoch: 64,
        },
        ..PoolBudgetConfig::default()
    };
    let mut engine = ModelPoolEngine::new(
        cascade,
        FairShareScheduler::new(budget)?,
        WorkerPoolExecutor::new(WorkerPoolConfig::with_workers(4)?)?,
    );

    let mut frames = Vec::with_capacity((STREAMS as usize) * (FRAMES_PER_STREAM as usize));
    for (cam_idx, s) in sensors.iter().enumerate() {
        for seq in 0..FRAMES_PER_STREAM {
            let mut pixels = vec![40 + (cam_idx as u8) * 5; (dims[0] * dims[1]) as usize];
            draw_rect_luma(
                &mut pixels,
                dims,
                ImageRect::new(0, 0, 12, 6)?,
                if seq % 2 == 0 { 240 } else { 10 },
            );
            if cam_idx < 3 && (16..24).contains(&seq) {
                draw_rect_luma(
                    &mut pixels,
                    dims,
                    ImageRect::new(20 + (seq as u32 - 16) * 3, 16, 12, 16)?,
                    235,
                );
            }
            frames.push(luma_frame(s, seq, dims, seq % 16 == 0, pixels)?);
        }
    }

    let (batch, metrics) = engine.process_epoch(&pool, resident.key(), 1, &frames, None, &cx)?;
    let jsonl = metrics.to_jsonl();
    println!("MODEL_POOL_BENCHMARK_JSONL: {jsonl}");

    assert_eq!(batch.frames_total, (STREAMS as u64) * FRAMES_PER_STREAM);
    assert_eq!(
        batch.frames_inferred + (batch.unsampled_gaps.len() as u64),
        batch.frames_total
    );
    assert_eq!(metrics.weight_loads, 1);
    assert!(metrics.idle_reduction_pct > 85.0);

    let quiet_total = 13_u64 * FRAMES_PER_STREAM;
    let quiet_inferred = batch
        .frames
        .iter()
        .filter(|f| f.stream_order >= 3 && f.stage_decision.ran_ml_inference())
        .count() as u64;
    let quiet_reduction_pct =
        ((quiet_total - quiet_inferred) as f64 * 100.0) / (quiet_total as f64);
    assert!(quiet_reduction_pct > 95.0);
    assert!(quiet_inferred >= 13);
    assert!(metrics.inferences_per_sec >= 12.0);
    for key in [
        "\"inferences_per_sec\":",
        "\"p99_inference_ms\":",
        "\"frames_total\":",
        "\"frames_inferred\":",
        "\"frames_throttled\":",
        "\"idle_reduction_pct\":",
        "\"weight_loads\":",
        "\"detections_total\":",
    ] {
        assert!(jsonl.contains(key), "missing {key} in {jsonl}");
    }
    Ok(())
}

#[test]
fn yolox_nano_fmpk_loads_once_into_resident_pool_and_hits_cache() -> TestResult {
    let rcx = replay_cx()?;
    let scx = ScalarExecCx::new();
    let pool = ResidentModelPool::default_bounded();
    let expected = ContentDigest::parse(YOLOX_NANO_SHA256)?;

    let first = pool.load_or_get_rgb_detector(
        YOLOX_NANO_FMPK,
        expected,
        1 << 40,
        KernelBackend::OptimizedCpuV1,
        None,
        &rcx,
        &scx,
    )?;
    assert!(first.is_rgb_detector());
    assert_eq!(first.key().model_id, "MOD-YOLOXNANO-001");
    assert_eq!(pool.metrics_snapshot().loads, 1);
    assert_eq!(pool.metrics_snapshot().cache_hits, 0);

    let second = pool.load_or_get_rgb_detector(
        YOLOX_NANO_FMPK,
        expected,
        1 << 40,
        KernelBackend::OptimizedCpuV1,
        None,
        &rcx,
        &scx,
    )?;
    assert_eq!(first.resident_digest(), second.resident_digest());
    let acquired = pool.acquire(first.key())?;
    assert_eq!(first.resident_digest(), acquired.resident_digest());
    assert_eq!(pool.metrics_snapshot().loads, 1);
    assert_eq!(pool.metrics_snapshot().cache_hits, 2);

    let refused = pool.load_or_get_rgb_detector(
        YOLOX_NANO_FMPK,
        ContentDigest::sha256(b"wrong-yolox-digest"),
        1 << 40,
        KernelBackend::OptimizedCpuV1,
        None,
        &rcx,
        &scx,
    );
    assert!(matches!(refused, Err(ModelPoolError::DigestMismatch)));
    Ok(())
}
