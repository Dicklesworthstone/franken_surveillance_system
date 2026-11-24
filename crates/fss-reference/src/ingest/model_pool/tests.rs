#![forbid(unsafe_code)]
//! Unit tests for the multi-stream resident ML inference pool (`ingest::model_pool`).

use std::collections::BTreeMap;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, CalibrationGeneration, CaptureInterval, ContentDigest, Generation,
    ModelGeneration, OperationId, SchemaId, SensorId, TimestampNs,
};
use fss_model_ir::{
    AttrValue, AttributeMap, GraphNode, ModelIrGraph, OpCode, TensorPort, encode_canonical_model_ir,
};
use fss_object::{
    ModelId, ModelLicenseRecord, ModelManifestV1, ModelPackage, ModelPackageArchive,
    ModelPackageArtifact,
};
use fss_tensor::{DType, Shape};

use super::*;
use crate::executor_activity_package::{ACTIVITY_MODEL_ID, ACTIVITY_PACKAGE_V1};
use crate::ingest::foreground::ForegroundConfig;
use crate::ingest::osd_mask::ImageRect;
use crate::ingest::rgb_detections::{HeadBoxes, HeadClasses, HeadLayout, HeadScore};
use crate::ingest::rgb_package::{
    GRAPH_ARTIFACT, LICENSE_ARTIFACT, NOTICE_ARTIFACT, PackageHeadSpec, PackageSource,
    RgbPackageSpec, SPEC_ARTIFACT, WEIGHTS_ARTIFACT,
};
use crate::preprocess::ResizeFilter;
use crate::{KernelBackend, ReplayCx, ScalarExecCx};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn sensor(name: &str) -> TestResult<SensorId> {
    Ok(SensorId::parse(name)?)
}

fn capture(seq: u64) -> TestResult<CaptureInterval> {
    let base = i128::from(seq.saturating_add(1)) * 33_000_000;
    Ok(CaptureInterval::new(
        TimestampNs(base),
        TimestampNs(base + 1_000_000),
    )?)
}

fn test_replay_cx() -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:model-pool-unit".to_owned(),
        operation_id: OperationId::parse("op:model-pool-unit")?,
        principal: "principal:model-pool-unit".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 1,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .model_calls(1024)
            .build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(b"model-pool-unit-universe"),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        std::env::temp_dir(),
    )?)
}

fn make_luma_frame(
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

fn draw_rect_luma(buf: &mut [u8], dims: [u32; 2], rect: ImageRect, val: u8) {
    let w = dims[0] as usize;
    for y in rect.y as usize..(rect.y + rect.height) as usize {
        for x in rect.x as usize..(rect.x + rect.width) as usize {
            buf[y * w + x] = val;
        }
    }
}

fn build_compact_rgb_detector_fmpk() -> TestResult<(Vec<u8>, ContentDigest)> {
    let g = Generation(1);
    let mut flat_attr = AttributeMap::new();
    flat_attr.insert("shape".into(), AttrValue::IntList(vec![1, 48]));
    let mut out_attr = AttributeMap::new();
    out_attr.insert("shape".into(), AttrValue::IntList(vec![1, 1, 7]));

    let graph = ModelIrGraph::builder("model:test-compact-det:v1", g)
        .add_input(TensorPort::new(
            "images",
            DType::F32,
            Shape::new(vec![1, 3, 4, 4])?,
            g,
        )?)
        .add_input(TensorPort::new(
            "proj_w",
            DType::F32,
            Shape::new(vec![48, 7])?,
            g,
        )?)
        .add_input(TensorPort::new(
            "proj_b",
            DType::F32,
            Shape::new(vec![1, 7])?,
            g,
        )?)
        .add_output(TensorPort::new(
            "dets",
            DType::F32,
            Shape::new(vec![1, 1, 7])?,
            g,
        )?)
        .add_node(GraphNode::new(
            "n:flat",
            OpCode::Reshape,
            "flatten",
            vec!["images".into()],
            vec!["flat".into()],
            flat_attr,
        )?)
        .add_node(GraphNode::new(
            "n:mm",
            OpCode::MatMul,
            "proj",
            vec!["flat".into(), "proj_w".into()],
            vec!["lin".into()],
            AttributeMap::new(),
        )?)
        .add_node(GraphNode::new(
            "n:add",
            OpCode::Add,
            "bias",
            vec!["lin".into(), "proj_b".into()],
            vec!["row".into()],
            AttributeMap::new(),
        )?)
        .add_node(GraphNode::new(
            "n:out",
            OpCode::Reshape,
            "head",
            vec!["row".into()],
            vec!["dets".into()],
            out_attr,
        )?)
        .build_and_validate()?;

    let mut proj_w = vec![0.0_f32; 48 * 7];
    for row in 0..48 {
        proj_w[row * 7 + 5] = 0.002_f32;
    }
    let proj_b = [0.5_f32, 0.5, 3.5, 3.5, 0.90, 0.70, 0.15];
    let mut data = Vec::with_capacity((proj_w.len() + proj_b.len()) * 4);
    for v in &proj_w {
        data.extend_from_slice(&v.to_le_bytes());
    }
    let w_end = data.len();
    for v in &proj_b {
        data.extend_from_slice(&v.to_le_bytes());
    }
    let b_end = data.len();
    let header = format!(
        "{{\"proj_b\":{{\"dtype\":\"F32\",\"shape\":[1,7],\"data_offsets\":[{w_end},{b_end}]}},\"proj_w\":{{\"dtype\":\"F32\",\"shape\":[48,7],\"data_offsets\":[0,{w_end}]}}}}"
    );
    let mut weights_bytes = (header.len() as u64).to_le_bytes().to_vec();
    weights_bytes.extend_from_slice(header.as_bytes());
    weights_bytes.extend(data);

    let spec = RgbPackageSpec {
        image_input: "images".to_owned(),
        target: [4, 4],
        filter: ResizeFilter::Nearest,
        letterbox_pad: 114,
        masked_rgb: [0, 0, 0],
        scale_to_unit: true,
        head: PackageHeadSpec {
            output_port: "dets".to_owned(),
            layout: HeadLayout::Rows,
            boxes: HeadBoxes::PixelCorners,
            class_score: HeadScore::Probability,
            objectness: Some(HeadScore::Probability),
            classes: HeadClasses::Best,
            minimum_score_ppm: 300_000,
            nms_iou_ppm: 450_000,
            maximum_rows: 16,
            maximum_candidates: 16,
            maximum_detections: 16,
        },
        labels: vec!["person".to_owned(), "vehicle".to_owned()],
        source: PackageSource {
            upstream: "local-test-fixture".to_owned(),
            revision: "v1".to_owned(),
            source_sha256: ContentDigest::sha256(b"compact-test-detector-source"),
            producer: "fss-unit-test".to_owned(),
            opset: 17,
        },
        importer: ContentDigest::sha256(b"compact-test-detector-importer"),
    };
    let license_text = b"MIT License\nTest fixture compact RGB detector package.\n";
    let notice_text = b"Compact test detector notice.\n";
    let artifacts = vec![
        ModelPackageArtifact::new(WEIGHTS_ARTIFACT, weights_bytes)?,
        ModelPackageArtifact::new(GRAPH_ARTIFACT, encode_canonical_model_ir(&graph)?)?,
        ModelPackageArtifact::new(SPEC_ARTIFACT, spec.encode()?)?,
        ModelPackageArtifact::new(LICENSE_ARTIFACT, license_text.to_vec())?,
        ModelPackageArtifact::new(NOTICE_ARTIFACT, notice_text.to_vec())?,
    ];
    let digest_of = |name: &str| -> TestResult<ContentDigest> {
        artifacts
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.digest)
            .ok_or_else(|| format!("missing artifact {name}").into())
    };
    let license = ModelLicenseRecord::new(
        "MIT",
        Some(ContentDigest::sha256(license_text)),
        true,
        Vec::new(),
        "test:compact-detector",
        vec![
            digest_of(GRAPH_ARTIFACT)?,
            digest_of(SPEC_ARTIFACT)?,
            digest_of(NOTICE_ARTIFACT)?,
        ],
        None,
    )?;
    let manifest = ModelManifestV1::new(
        ModelId::parse("MOD-TEST-COMPACT-DET-001")?,
        ModelGeneration::parse("model:test-compact-det:v1")?,
        digest_of(WEIGHTS_ARTIFACT)?,
        SchemaId::parse("fss.rgb_nchw_f32.1x3x4x4.unit")?,
        SchemaId::parse("fss.rgb_dets_f32.1x1x7")?,
        CalibrationGeneration::parse("cal:uncalibrated:none")?,
        license,
    )?;
    let archive = ModelPackageArchive::encode(&ModelPackage::new(manifest, artifacts)?)?;
    let digest = ContentDigest::sha256(&archive);
    Ok((archive, digest))
}

#[test]
fn resident_pool_pins_once_reuses_forever_and_refuses_tampered_digest() -> TestResult {
    let cx = ScalarExecCx::new();
    let pool = ResidentModelPool::default_bounded();

    let first = pool.load_or_get_activity_committed(KernelBackend::OptimizedCpuV1, &cx)?;
    assert_eq!(first.key().model_id, ACTIVITY_MODEL_ID);
    assert_eq!(first.backend(), KernelBackend::OptimizedCpuV1);
    assert_ne!(first.model_digest().bytes(), [0; 32]);
    assert_eq!(pool.metrics_snapshot().loads, 1);

    for _ in 0..100 {
        let again = pool.load_or_get_activity_committed(KernelBackend::OptimizedCpuV1, &cx)?;
        assert_eq!(first.resident_digest(), again.resident_digest());
    }
    let snap = pool.metrics_snapshot();
    assert_eq!(snap.loads, 1);
    assert_eq!(snap.cache_hits, 100);

    let mut tampered = ACTIVITY_PACKAGE_V1.to_vec();
    tampered[0] ^= 0xFF;
    let bad = pool.load_or_get_activity(
        &tampered,
        first.key().package_digest,
        &crate::executor_activity_package::activity_license_policy()?,
        crate::executor_activity::ActivityThresholdPolicy::reference()?,
        KernelBackend::OptimizedCpuV1,
        &cx,
    );
    assert!(matches!(bad, Err(ModelPoolError::DigestMismatch)));
    assert_eq!(pool.metrics_snapshot().loads, 1);

    let tight_pool = ResidentModelPool::new(1, 64 * 1024)?;
    let _ = tight_pool.load_or_get_activity_committed(KernelBackend::OptimizedCpuV1, &cx)?;
    let overflow = tight_pool.load_or_get_activity_committed(KernelBackend::ScalarReference, &cx);
    assert!(matches!(
        overflow,
        Err(ModelPoolError::PoolCapacityExceeded { .. })
    ));
    Ok(())
}

#[test]
fn fair_share_scheduler_guarantees_floor_and_is_input_order_invariant() -> TestResult {
    let noisy = sensor("sensor:cam-00-noisy")?;
    let mut camera_overrides = BTreeMap::new();
    camera_overrides.insert(
        noisy.clone(),
        CameraQuotaConfig {
            priority: CameraPriorityTier::Standard,
            min_guaranteed_frames_per_epoch: 1,
            max_burst_frames_per_epoch: 6,
        },
    );
    let scheduler = FairShareScheduler::new(PoolBudgetConfig {
        budget_vector: BudgetVector::builder()
            .model_calls(20)
            .bytes(64 * 1024 * 1024)
            .build()?,
        max_work_units_per_epoch: 100_000_000,
        max_macs_per_epoch: 100_000_000,
        max_memory_bytes: 64 * 1024 * 1024,
        estimated_work_units_per_inference: 1_000,
        estimated_macs_per_inference: 1_024,
        estimated_bytes_per_inference: 4_096,
        default_camera_quota: CameraQuotaConfig {
            priority: CameraPriorityTier::Standard,
            min_guaranteed_frames_per_epoch: 1,
            max_burst_frames_per_epoch: 6,
        },
        camera_overrides,
    })?;

    let mut candidates = Vec::new();
    for seq in 0..20_u64 {
        candidates.push(ScheduledCandidate {
            canonical_index: seq as usize,
            stream_order: 0,
            frame_sequence: seq,
            sensor_id: noisy.clone(),
            priority: CameraPriorityTier::Standard,
            stage_decision: StageDecision::MotionTriggered,
            requested_work_units: 1_000,
            requested_macs: 1_024,
            requested_bytes: 4_096,
        });
    }
    for cam in 1..=15_u32 {
        candidates.push(ScheduledCandidate {
            canonical_index: 19 + cam as usize,
            stream_order: cam,
            frame_sequence: 0,
            sensor_id: sensor(&format!("sensor:cam-{cam:02}-quiet"))?,
            priority: CameraPriorityTier::Standard,
            stage_decision: StageDecision::SentinelSweep,
            requested_work_units: 1_000,
            requested_macs: 1_024,
            requested_bytes: 4_096,
        });
    }

    let forward = scheduler.schedule_epoch(&candidates)?;
    let mut reversed = candidates.clone();
    reversed.reverse();
    let backward = scheduler.schedule_epoch(&reversed)?;

    assert_eq!(forward.admitted_indices, backward.admitted_indices);
    assert_eq!(forward.declined, backward.declined);
    assert_eq!(forward.admitted_indices.len(), 20);
    assert_eq!(forward.declined.len(), 15);
    assert_eq!(forward.pressure, ResourcePressure::Critical);
    for quiet_idx in 20..35 {
        assert!(forward.admitted_indices.contains(&quiet_idx));
    }
    assert_eq!(
        forward.admitted_indices.iter().filter(|&&i| i < 20).count(),
        5
    );
    for receipt in forward.declined.values() {
        assert_eq!(receipt.sensor_id, noisy);
        assert_eq!(receipt.unsampled_reason, UnsampledReason::BudgetThrottled);
        assert_eq!(receipt.pressure, ResourcePressure::Critical);
    }
    Ok(())
}

#[test]
fn osd_ignore_region_blocks_corner_clock_and_triggers_on_genuine_motion() -> TestResult {
    let cx = ScalarExecCx::new();
    let pool = ResidentModelPool::default_bounded();
    let resident = pool.load_or_get_activity_committed(KernelBackend::OptimizedCpuV1, &cx)?;
    let dims = [32_u32, 32_u32];
    let clock_rect = ImageRect::new(0, 0, 8, 6)?;
    let motion_rect = ImageRect::new(16, 16, 6, 6)?;

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
        sentinel_interval_frames: 4,
        post_motion_hold_frames: 1,
        quiescent_keyframe_only: false,
        sentinel_on_first_keyframe: false,
        enable_sensor_health: false,
        health_max_samples_per_stream: 1024 * 1024,
    })?;
    let cam = sensor("sensor:cam-osd")?;
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
    for seq in 0..=5_u64 {
        let mut pixels = vec![40_u8; 32 * 32];
        draw_rect_luma(
            &mut pixels,
            dims,
            clock_rect,
            if seq % 2 == 0 { 230 } else { 15 },
        );
        if seq == 5 {
            draw_rect_luma(&mut pixels, dims, motion_rect, 220);
        }
        frames.push(make_luma_frame(&cam, seq, dims, true, pixels)?);
    }

    let (batch, _) = engine.process_epoch(&pool, resident.key(), 1, &frames, None, &cx)?;
    assert_eq!(batch.frames[4].stage_decision, StageDecision::SentinelSweep);
    assert_eq!(
        batch.frames[5].stage_decision,
        StageDecision::MotionTriggered
    );
    assert_eq!(batch.frames_motion_triggered, 1);
    assert_eq!(batch.frames_sentinel_swept, 1);
    assert_eq!(batch.unsampled_gaps.len(), 4);
    assert!(
        batch
            .unsampled_gaps
            .records
            .iter()
            .all(|g| !g.absence_certifiable)
    );
    let s4 = batch.frames[4].activity_score().ok_or("missing score 4")?;
    let s5 = batch.frames[5].activity_score().ok_or("missing score 5")?;
    assert!(s5 > s4);
    Ok(())
}

#[test]
fn compact_rgb_detector_fmpk_runs_bit_identically_across_workers() -> TestResult {
    let replay_cx = test_replay_cx()?;
    let scalar_cx = ScalarExecCx::new();
    let (archive, archive_digest) = build_compact_rgb_detector_fmpk()?;
    let pool = ResidentModelPool::default_bounded();
    let model = pool.load_or_get_rgb_detector(
        &archive,
        archive_digest,
        1 << 30,
        KernelBackend::OptimizedCpuV1,
        None,
        &replay_cx,
        &scalar_cx,
    )?;
    assert!(model.is_rgb_detector());

    let dims = [8_u32, 8_u32];
    let mut frames = Vec::new();
    for cam in 0..4_u32 {
        let s = sensor(&format!("sensor:det-{cam}"))?;
        for seq in 0..4_u64 {
            let mut rgb = vec![30_u8; 8 * 8 * 3];
            if seq >= 1 {
                for px in rgb.iter_mut().take(96) {
                    *px = 200_u8.saturating_sub((cam * 10 + seq as u32 * 5) as u8);
                }
            }
            let source_digest = ContentDigest::sha256(&rgb);
            frames.push(StreamFrameInput {
                sensor_id: s.clone(),
                frame_sequence: seq,
                capture_interval: capture(seq)?,
                source_digest,
                dimensions: dims,
                is_keyframe: true,
                pixels: FramePixelInput::Rgb { pixels: rgb },
            });
        }
    }

    let mut digests = Vec::new();
    for worker_count in [1_usize, 2, 4, 8] {
        let mut policy = CascadePolicyConfig::default_for_dimensions(dims);
        policy.quiescent_keyframe_only = false;
        policy.sentinel_interval_frames = 2;
        let mut cascade = TwoStageCascade::new(policy)?;
        for cam in 0..4_u32 {
            cascade.register_stream(StreamRegistration {
                sensor_id: sensor(&format!("sensor:det-{cam}"))?,
                stream_order: cam,
                priority: CameraPriorityTier::Standard,
                dimensions: dims,
                ignore_regions: Vec::new(),
            })?;
        }
        let mut engine = ModelPoolEngine::new(
            cascade,
            FairShareScheduler::new(PoolBudgetConfig::default())?,
            WorkerPoolExecutor::new(WorkerPoolConfig::with_workers(worker_count)?)?,
        );
        let (batch, _) =
            engine.process_epoch(&pool, model.key(), 7, &frames, Some(&replay_cx), &scalar_cx)?;
        assert!(batch.detections_total > 0);
        for frame in &batch.frames {
            if frame.stage_decision.ran_ml_inference() {
                assert_eq!(frame.detections.len(), 1);
                assert_eq!(frame.detections[0].label, "person");
            }
        }
        digests.push(batch.batch_digest);
    }
    assert!(digests.windows(2).all(|p| p[0] == p[1]));
    assert_eq!(pool.metrics_snapshot().loads, 1);
    Ok(())
}

#[test]
fn cooperative_cancellation_stops_cleanly_and_drains() -> TestResult {
    let cx = ScalarExecCx::new();
    let pool = ResidentModelPool::default_bounded();
    let model = pool.load_or_get_activity_committed(KernelBackend::OptimizedCpuV1, &cx)?;
    let dims = [16_u32, 16_u32];
    let cam = sensor("sensor:cancel-cam")?;
    let mut policy = CascadePolicyConfig::default_for_dimensions(dims);
    policy.quiescent_keyframe_only = false;
    policy.sentinel_on_first_keyframe = true;
    let mut cascade = TwoStageCascade::new(policy)?;
    cascade.register_stream(StreamRegistration {
        sensor_id: cam.clone(),
        stream_order: 0,
        priority: CameraPriorityTier::ActiveInvestigation,
        dimensions: dims,
        ignore_regions: Vec::new(),
    })?;
    let mut engine = ModelPoolEngine::new(
        cascade,
        FairShareScheduler::new(PoolBudgetConfig::default())?,
        WorkerPoolExecutor::new(WorkerPoolConfig::with_workers(4)?)?,
    );
    let frames = vec![make_luma_frame(&cam, 0, dims, true, vec![80_u8; 256])?];
    cx.request_cancellation();
    let err = engine.process_epoch(&pool, model.key(), 1, &frames, None, &cx);
    assert!(matches!(err, Err(ModelPoolError::Cancelled)));
    assert!(cx.is_drain_completed());
    Ok(())
}

#[test]
fn sensor_health_screen_optional_integration_records_findings() -> TestResult {
    let replay_cx = test_replay_cx()?;
    let scalar_cx = ScalarExecCx::new();
    let pool = ResidentModelPool::default_bounded();
    let model = pool.load_or_get_activity_committed(KernelBackend::OptimizedCpuV1, &scalar_cx)?;
    let dims = [16_u32, 16_u32];
    let cam = sensor("sensor:dark-health")?;
    let mut policy = CascadePolicyConfig::default_for_dimensions(dims);
    policy.quiescent_keyframe_only = false;
    policy.enable_sensor_health = true;
    let mut cascade = TwoStageCascade::new(policy)?;
    cascade.register_stream(StreamRegistration {
        sensor_id: cam.clone(),
        stream_order: 0,
        priority: CameraPriorityTier::Standard,
        dimensions: dims,
        ignore_regions: Vec::new(),
    })?;
    let mut engine = ModelPoolEngine::new(
        cascade,
        FairShareScheduler::new(PoolBudgetConfig::default())?,
        WorkerPoolExecutor::new(WorkerPoolConfig::with_workers(1)?)?,
    );
    let mut frames = Vec::new();
    for seq in 0..4_u64 {
        frames.push(make_luma_frame(&cam, seq, dims, true, vec![5_u8; 256])?);
    }
    let (batch, _) =
        engine.process_epoch(&pool, model.key(), 1, &frames, Some(&replay_cx), &scalar_cx)?;
    assert_eq!(batch.frames[0].stage1.health_findings_count, 0);
    assert_eq!(batch.frames[1].stage1.health_findings_count, 0);
    assert!(batch.frames[2].stage1.health_findings_count >= 1);
    assert!(batch.frames[3].stage1.health_findings_count >= 1);
    assert!(!batch.absence_certifiable);
    assert!(!batch.effects_authorized);
    Ok(())
}
