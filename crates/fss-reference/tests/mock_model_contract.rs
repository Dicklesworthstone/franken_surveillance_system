#![forbid(unsafe_code)]
//! Integration contract tests for deterministic mock model executor (FSS-020).

use std::error::Error;

use fss_core::{
    CapsuleId, CaptureInterval, ClockBasis, ContentDigest, ContinuityState, DecodeState,
    ExplicitOmission, IntegrityWitness, KnowledgeState, MediaDescriptor, MediaKind,
    ModelGeneration, PrivacyDescriptor, ProbabilityInterval, ProvenanceClass,
    PublicationDescriptor, PublicationState, RedactionState, SensorCapsuleV1, SensorId,
    SourceCustody, TimestampNs,
};
use fss_reference::{
    CorroborationStatus, MAX_CORROBORATION_SOURCES, MAX_DETECTIONS_PER_OUTPUT, MAX_EMBEDDING_DIM,
    MAX_FAULT_REASON_LEN, MAX_INPUT_PAYLOAD_BYTES, MAX_MODEL_GENERATION_BYTES, MockDetection,
    MockEmbedding, MockExecutorOutcome, MockModelError, MockModelExecutor, MockModelFaultSchedule,
    MockModelOutput, MockModelScript, MockModelSpec, MockOutputDigestRequest, MockSemanticLabel,
    ReferenceError, VirtualClock, compare_model_embeddings, compare_model_scores,
    compute_output_digest, encode_coord_to_basis_point, evaluate_corroboration,
    fuse_model_embeddings, fuse_model_scores, is_latest_generation,
};

fn sample_capsule(
    capsule_id_str: &str,
    sensor_id_str: &str,
    seq: u64,
    start_ns: u64,
    end_ns: u64,
) -> Result<SensorCapsuleV1, Box<dyn Error>> {
    let source_digest = ContentDigest::sha256(format!("raw-frame-{seq}").as_bytes());
    let mut capsule = SensorCapsuleV1 {
        schema: SensorCapsuleV1::SCHEMA.to_string(),
        capsule_id: CapsuleId::parse(capsule_id_str)?,
        source_id: fss_core::SourceId::parse("src:cam01-main")?,
        device_id: fss_core::DeviceId::parse("dev:camera-entry-01")?,
        adapter_id: fss_core::AdapterId::parse("adapter:rtsp-pure-rust-01")?,
        sensor_id: SensorId::parse(sensor_id_str)?,
        stream_id: fss_core::StreamId::parse("stream:cam01-video")?,
        source_identity: fss_core::SourceIdentity {
            source_id: fss_core::SourceId::parse("src:cam01-main")?,
            device_id: fss_core::DeviceId::parse("dev:camera-entry-01")?,
            adapter_id: fss_core::AdapterId::parse("adapter:rtsp-pure-rust-01")?,
            source_kind: fss_core::SourceKind::PhysicalSensor,
            media_kind: MediaKind::Video,
            channel: "video_main".to_string(),
            nominal_clock_basis: ClockBasis::HostMonotonic,
            stream_generation: fss_core::StreamGeneration::parse("gen:stream:1080p30-h264")?,
            failure_domain: "power:poe-1".to_string(),
            is_live: true,
        },
        device_identity: fss_core::DeviceIdentity {
            device_id: fss_core::DeviceId::parse("dev:camera-entry-01")?,
            generation: fss_core::DeviceGeneration::parse("gen:dev:2026-09-11:rev1")?,
            manufacturer: "Axis".to_string(),
            model: "P3245-V".to_string(),
            hardware_revision: "HW-2.0".to_string(),
            firmware_version: fss_core::FirmwareGeneration::parse("gen:firmware:v1-2-64")?,
            application_version: None,
            model_generation: Some(ModelGeneration::parse("model:yolo26:fp16:v1")?),
            device_class: fss_core::DeviceClass::Camera,
            capabilities: fss_core::DeviceCapabilities::OPTICAL_ZOOM,
            failure_domain: "power:poe-1".to_string(),
        },
        adapter_identity: fss_core::AdapterIdentity {
            adapter_id: fss_core::AdapterId::parse("adapter:rtsp-pure-rust-01")?,
            generation: fss_core::AdapterGeneration::parse("gen:adapter:rtsp-rust-v1")?,
            adapter_kind: fss_core::AdapterKind::Rtsp,
            protocol_profile: "rtsp:1.0:tcp".to_string(),
            isolation_mode: fss_core::IsolationMode::NativePureRust,
            credential_method: fss_core::CredentialMethod::Token,
            capabilities: fss_core::AdapterCapabilities::STREAMING,
            max_bandwidth_bytes_per_sec: 100_000_000,
            max_buffer_frames: 32,
            request_timeout_ns: 5_000_000_000,
        },
        sequence: seq,
        capture_interval: CaptureInterval::new(
            TimestampNs(start_ns as i128),
            TimestampNs(end_ns as i128),
        )?,
        capture_uncertainty_reason: "conservative_window".to_string(),
        receive_time_ns: TimestampNs((end_ns + 1_000_000) as i128),
        clock_basis: ClockBasis::HostMonotonic,
        custody: SourceCustody::Retained {
            source_digest,
            source_bytes: 4096,
            storage_handle: format!("store://cas/sha256/frame-{seq}"),
        },
        omission: ExplicitOmission::None,
        media: MediaDescriptor {
            kind: MediaKind::Video,
            codec: "h264".to_string(),
            container: Some("mp4".to_string()),
            width: Some(1920),
            height: Some(1080),
            source_bytes: 4096,
            frame_count: 1,
            source_digest: Some(source_digest),
            proxy_digest: None,
        },
        integrity: IntegrityWitness {
            metadata_digest: ContentDigest::sha256(format!("metadata-{seq}").as_bytes()),
            continuity: ContinuityState::Verified,
            decode: DecodeState::Verified,
            firmware_fingerprint: Some("sha256:0123456789abcdef0123456789abcdef".to_string()),
        },
        privacy: PrivacyDescriptor {
            mask_generation: None,
            redaction_state: RedactionState::NotRequired,
            retention_class: "standard_retention_30d".to_string(),
        },
        publication: PublicationDescriptor {
            state: PublicationState::Published,
            root_digest: ContentDigest::sha256(b"manifest-root"),
            ledger_revision: Some(seq),
        },
    };
    capsule.seal_metadata_digest()?;
    Ok(capsule)
}

#[test]
fn test_mock_executor_deterministic_bit_identical_replay() -> Result<(), Box<dyn Error>> {
    let generation = ModelGeneration::parse("model:yolo-person:v1")?;
    let executor = MockModelExecutor::new(generation.clone(), 0xdead_beef_cafe_u64)?;

    let frame = b"test-frame-payload-deterministic-bytes";
    let sensor_id = SensorId::parse("sensor:cam-front")?;
    let interval = CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))?;

    let mut clock_a = VirtualClock::new(42, TimestampNs(10_000_000));
    let mut clock_b = VirtualClock::new(42, TimestampNs(10_000_000));

    let outcome_a = executor.execute_frame(frame, &sensor_id, &interval, &mut clock_a)?;
    let outcome_b = executor.execute_frame(frame, &sensor_id, &interval, &mut clock_b)?;

    let out_a = match outcome_a {
        MockExecutorOutcome::Success(o) => *o,
        other => return Err(format!("expected Success, got {other:?}").into()),
    };
    let out_b = match outcome_b {
        MockExecutorOutcome::Success(o) => *o,
        other => return Err(format!("expected Success, got {other:?}").into()),
    };

    assert_eq!(out_a, out_b);
    assert_eq!(out_a.output_digest, out_b.output_digest);
    assert_eq!(out_a.detections, out_b.detections);
    assert_eq!(out_a.virtual_latency_ns, out_b.virtual_latency_ns);
    assert_eq!(clock_a.now(), clock_b.now());
    assert_eq!(clock_a.step_count(), clock_b.step_count());

    Ok(())
}

#[test]
fn test_mock_executor_different_inputs_produce_different_outputs() -> Result<(), Box<dyn Error>> {
    let generation = ModelGeneration::parse("model:yolo-person:v1")?;
    let executor = MockModelExecutor::new(generation, 0x1234_5678_u64)?;

    let sensor_id = SensorId::parse("sensor:cam-front")?;
    let interval = CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))?;

    let mut clock = VirtualClock::new(42, TimestampNs(10_000_000));

    let out_1 = match executor.execute_frame(b"frame-one", &sensor_id, &interval, &mut clock)? {
        MockExecutorOutcome::Success(o) => *o,
        other => return Err(format!("expected Success, got {other:?}").into()),
    };
    let out_2 = match executor.execute_frame(b"frame-two", &sensor_id, &interval, &mut clock)? {
        MockExecutorOutcome::Success(o) => *o,
        other => return Err(format!("expected Success, got {other:?}").into()),
    };

    assert_ne!(out_1.input_digest, out_2.input_digest);
    assert_ne!(out_1.output_digest, out_2.output_digest);

    Ok(())
}

#[test]
fn test_mock_executor_different_seeds_produce_different_outputs() -> Result<(), Box<dyn Error>> {
    let generation = ModelGeneration::parse("model:yolo-person:v1")?;
    let executor_a = MockModelExecutor::new(generation.clone(), 1111)?;
    let executor_b = MockModelExecutor::new(generation, 2222)?;

    let frame = b"shared-frame-bytes";
    let sensor_id = SensorId::parse("sensor:cam-front")?;
    let interval = CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))?;

    let mut clock_a = VirtualClock::new(42, TimestampNs(10_000_000));
    let mut clock_b = VirtualClock::new(42, TimestampNs(10_000_000));

    let out_a = match executor_a.execute_frame(frame, &sensor_id, &interval, &mut clock_a)? {
        MockExecutorOutcome::Success(o) => *o,
        other => return Err(format!("expected Success, got {other:?}").into()),
    };
    let out_b = match executor_b.execute_frame(frame, &sensor_id, &interval, &mut clock_b)? {
        MockExecutorOutcome::Success(o) => *o,
        other => return Err(format!("expected Success, got {other:?}").into()),
    };

    assert_eq!(out_a.input_digest, out_b.input_digest);
    assert_ne!(out_a.output_digest, out_b.output_digest);

    Ok(())
}

#[test]
fn test_mock_executor_different_generations_produce_different_outputs() -> Result<(), Box<dyn Error>>
{
    let gen_v1 = ModelGeneration::parse("model:detector:v1")?;
    let gen_v2 = ModelGeneration::parse("model:detector:v2")?;

    let executor_1 = MockModelExecutor::new(gen_v1, 42)?;
    let executor_2 = MockModelExecutor::new(gen_v2, 42)?;

    let frame = b"same-image-bytes";
    let sensor_id = SensorId::parse("sensor:cam-front")?;
    let interval = CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))?;

    let mut clock_1 = VirtualClock::new(1, TimestampNs(10_000_000));
    let mut clock_2 = VirtualClock::new(1, TimestampNs(10_000_000));

    let out_1 = match executor_1.execute_frame(frame, &sensor_id, &interval, &mut clock_1)? {
        MockExecutorOutcome::Success(o) => *o,
        other => return Err(format!("expected Success, got {other:?}").into()),
    };
    let out_2 = match executor_2.execute_frame(frame, &sensor_id, &interval, &mut clock_2)? {
        MockExecutorOutcome::Success(o) => *o,
        other => return Err(format!("expected Success, got {other:?}").into()),
    };

    assert_ne!(out_1.generation, out_2.generation);
    assert_ne!(out_1.output_digest, out_2.output_digest);

    Ok(())
}

#[test]
fn test_model_generations_immutable_and_cross_generation_mixing_rejected()
-> Result<(), Box<dyn Error>> {
    let gen_v1 = ModelGeneration::parse("model:yolo:v1")?;
    let gen_v2 = ModelGeneration::parse("model:yolo:v2")?;

    let detection = MockDetection {
        label: MockSemanticLabel::PersonLike,
        probability: ProbabilityInterval::new(0.85, 0.95)?,
        bounding_box: [0.1, 0.1, 0.5, 0.5],
    };

    // Attempting to compare scores across different model generations must fail with typed error
    match compare_model_scores(&detection, &gen_v1, &detection, &gen_v2) {
        Err(MockModelError::CrossGenerationScoreMixing { expected, actual }) => {
            assert_eq!(expected, gen_v1);
            assert_eq!(actual, gen_v2);
        }
        other => {
            return Err(format!("expected CrossGenerationScoreMixing error, got {other:?}").into());
        }
    }

    Ok(())
}

#[test]
fn test_model_score_never_corroborated_on_its_own_single_camera() -> Result<(), Box<dyn Error>> {
    let generation = ModelGeneration::parse("model:detector:v1")?;
    let executor = MockModelExecutor::new(generation.clone(), 777)?;

    let sensor_a = SensorId::parse("sensor:cam-front")?;
    let interval = CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))?;
    let mut clock = VirtualClock::new(1, TimestampNs(10_000_000));

    let out_1 = match executor.execute_frame(b"frame-1", &sensor_a, &interval, &mut clock)? {
        MockExecutorOutcome::Success(o) => *o,
        other => return Err(format!("expected Success, got {other:?}").into()),
    };

    // 1. Output from executor must always be marked UncorroboratedSingleSource
    match &out_1.corroboration {
        CorroborationStatus::UncorroboratedSingleSource {
            sensor_id,
            model_generation,
        } => {
            assert_eq!(sensor_id, &sensor_a);
            assert_eq!(model_generation, generation.as_str());
        }
        CorroborationStatus::Corroborated { .. } => {
            return Err("model output must NEVER be corroborated on its own!".into());
        }
    }

    // 2. Corroborating a single output must be rejected
    match evaluate_corroboration(std::slice::from_ref(&out_1)) {
        Err(MockModelError::InsufficientSourcesForCorroboration {
            count,
            min_required,
        }) => {
            assert_eq!(count, 1);
            assert_eq!(min_required, 2);
        }
        other => return Err(format!("expected InsufficientSources, got {other:?}").into()),
    }

    // 3. Corroborating two outputs from the SAME camera must be rejected
    let out_2 = match executor.execute_frame(b"frame-2", &sensor_a, &interval, &mut clock)? {
        MockExecutorOutcome::Success(o) => *o,
        other => return Err(format!("expected Success, got {other:?}").into()),
    };

    match evaluate_corroboration(&[out_1, out_2]) {
        Err(MockModelError::UncorroboratedSingleSensor { sensor_id }) => {
            assert_eq!(sensor_id, sensor_a);
        }
        other => return Err(format!("expected UncorroboratedSingleSensor, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_model_score_multi_camera_corroboration_success() -> Result<(), Box<dyn Error>> {
    let generation = ModelGeneration::parse("model:detector:v1")?;
    let executor = MockModelExecutor::new(generation.clone(), 999)?;

    let sensor_front = SensorId::parse("sensor:cam-front")?;
    let sensor_side = SensorId::parse("sensor:cam-side")?;
    let interval = CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))?;

    let mut clock = VirtualClock::new(1, TimestampNs(10_000_000));

    let out_front =
        match executor.execute_frame(b"shared-scene-view", &sensor_front, &interval, &mut clock)? {
            MockExecutorOutcome::Success(o) => *o,
            other => return Err(format!("expected Success, got {other:?}").into()),
        };
    let out_side =
        match executor.execute_frame(b"shared-scene-view", &sensor_side, &interval, &mut clock)? {
            MockExecutorOutcome::Success(o) => *o,
            other => return Err(format!("expected Success, got {other:?}").into()),
        };

    let corroborated = evaluate_corroboration(&[out_front, out_side])?;
    assert_eq!(corroborated.generation, generation);
    assert_eq!(corroborated.contributing_sensors.len(), 2);
    assert!(corroborated.contributing_sensors.contains(&sensor_front));
    assert!(corroborated.contributing_sensors.contains(&sensor_side));
    assert!(matches!(
        corroborated.corroboration,
        CorroborationStatus::Corroborated { .. }
    ));

    Ok(())
}

#[test]
fn test_fault_mode_crash_typed_outcome_never_defaults_to_no_detection() -> Result<(), Box<dyn Error>>
{
    let generation = ModelGeneration::parse("model:detector:v1")?;
    let mut fault_schedule = MockModelFaultSchedule::new();

    let frame = b"problematic-crash-frame";
    let digest = ContentDigest::sha256(frame);
    fault_schedule.inject_crash(digest, "GPU memory parity corruption")?;

    let executor = MockModelExecutor::new(generation, 42)?.with_fault_schedule(fault_schedule);

    let sensor_id = SensorId::parse("sensor:cam-1")?;
    let interval = CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))?;
    let mut clock = VirtualClock::new(1, TimestampNs(10_000_000));

    let outcome = executor.execute_frame(frame, &sensor_id, &interval, &mut clock)?;

    match &outcome {
        MockExecutorOutcome::Crashed { reason } => {
            assert!(reason.contains("GPU memory parity corruption"));
        }
        other => return Err(format!("expected Crashed outcome, got {other:?}").into()),
    }

    assert!(!outcome.is_success());
    assert!(outcome.output().is_none());

    Ok(())
}

#[test]
fn test_fault_mode_timeout_typed_outcome_advances_virtual_time() -> Result<(), Box<dyn Error>> {
    let generation = ModelGeneration::parse("model:detector:v1")?;
    let mut fault_schedule = MockModelFaultSchedule::new();

    let frame = b"timeout-trigger-frame";
    let digest = ContentDigest::sha256(frame);
    let timeout_delay_ns = 50_000_000_u64; // 50ms
    fault_schedule.inject_timeout(digest, timeout_delay_ns);

    let executor = MockModelExecutor::with_latency_and_timeout(
        generation, 42, 10_000_000, // nominal 10ms
        30_000_000, // timeout threshold 30ms
    )?
    .with_fault_schedule(fault_schedule);

    let sensor_id = SensorId::parse("sensor:cam-1")?;
    let interval = CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))?;
    let mut clock = VirtualClock::new(1, TimestampNs(10_000_000));
    let time_before = clock.now();

    let outcome = executor.execute_frame(frame, &sensor_id, &interval, &mut clock)?;

    match &outcome {
        MockExecutorOutcome::TimedOut {
            virtual_timeout_ns,
            virtual_elapsed_ns,
        } => {
            assert_eq!(*virtual_timeout_ns, 30_000_000);
            assert_eq!(*virtual_elapsed_ns, 50_000_000);
        }
        other => return Err(format!("expected TimedOut outcome, got {other:?}").into()),
    }

    assert_eq!(clock.now().0, time_before.0 + 50_000_000);
    assert!(!outcome.is_success());

    Ok(())
}

#[test]
fn test_fault_mode_malformed_output_typed_outcome() -> Result<(), Box<dyn Error>> {
    let generation = ModelGeneration::parse("model:detector:v1")?;
    let mut fault_schedule = MockModelFaultSchedule::new();

    let frame = b"malformed-output-frame";
    let digest = ContentDigest::sha256(frame);
    fault_schedule.inject_malformed_output(digest, "NaN probability detected in tensor output")?;

    let executor = MockModelExecutor::new(generation, 42)?.with_fault_schedule(fault_schedule);

    let sensor_id = SensorId::parse("sensor:cam-1")?;
    let interval = CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))?;
    let mut clock = VirtualClock::new(1, TimestampNs(10_000_000));

    let outcome = executor.execute_frame(frame, &sensor_id, &interval, &mut clock)?;

    match &outcome {
        MockExecutorOutcome::MalformedOutput { detail } => {
            assert!(detail.contains("NaN probability detected"));
        }
        other => return Err(format!("expected MalformedOutput outcome, got {other:?}").into()),
    }

    assert!(!outcome.is_success());
    Ok(())
}

#[test]
fn test_bounds_generation_id_at_bound_and_bound_plus_one() -> Result<(), Box<dyn Error>> {
    // MAX_MODEL_GENERATION_BYTES = 256
    // Prefix "model:gen:" is 10 chars.
    let at_bound_str = format!("model:gen:{}", "a".repeat(MAX_MODEL_GENERATION_BYTES - 10));
    assert_eq!(at_bound_str.len(), MAX_MODEL_GENERATION_BYTES);
    let at_bound = ModelGeneration::parse(&at_bound_str);
    assert!(at_bound.is_ok());

    let over_bound_str = format!("model:gen:{}", "a".repeat(MAX_MODEL_GENERATION_BYTES - 9));
    assert_eq!(over_bound_str.len(), MAX_MODEL_GENERATION_BYTES + 1);
    let over_bound = ModelGeneration::parse(&over_bound_str);
    assert!(over_bound.is_err());

    let empty = ModelGeneration::parse("");
    assert!(empty.is_err());

    Ok(())
}

#[test]
fn test_bounds_input_payload_at_bound_and_bound_plus_one() -> Result<(), Box<dyn Error>> {
    let generation = ModelGeneration::parse("model:detector:v1")?;
    let executor = MockModelExecutor::new(generation, 42)?;

    let sensor_id = SensorId::parse("sensor:cam-1")?;
    let interval = CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))?;
    let mut clock = VirtualClock::new(1, TimestampNs(10_000_000));

    // Payload at exactly MAX_INPUT_PAYLOAD_BYTES: must succeed
    let at_bound = vec![0_u8; MAX_INPUT_PAYLOAD_BYTES];
    let res_at_bound = executor.execute_frame(&at_bound, &sensor_id, &interval, &mut clock);
    assert!(res_at_bound.is_ok());

    // Payload at MAX_INPUT_PAYLOAD_BYTES + 1: must be rejected
    let over_bound = vec![0_u8; MAX_INPUT_PAYLOAD_BYTES + 1];
    let res_over_bound = executor.execute_frame(&over_bound, &sensor_id, &interval, &mut clock);
    match res_over_bound {
        Err(MockModelError::InputPayloadTooLarge { actual, max }) => {
            assert_eq!(actual, MAX_INPUT_PAYLOAD_BYTES + 1);
            assert_eq!(max, MAX_INPUT_PAYLOAD_BYTES);
        }
        other => return Err(format!("expected InputPayloadTooLarge, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_bounds_fault_reason_at_bound_and_bound_plus_one() -> Result<(), Box<dyn Error>> {
    let mut schedule = MockModelFaultSchedule::new();
    let digest = ContentDigest::sha256(b"dummy");

    // Exactly MAX_FAULT_REASON_LEN (256): accepted
    let at_bound = "r".repeat(MAX_FAULT_REASON_LEN);
    assert!(schedule.inject_crash(digest, at_bound).is_ok());

    // MAX_FAULT_REASON_LEN + 1 (257): rejected
    let over_bound = "r".repeat(MAX_FAULT_REASON_LEN + 1);
    match schedule.inject_crash(digest, over_bound) {
        Err(MockModelError::FaultReasonTooLong { actual, max }) => {
            assert_eq!(actual, MAX_FAULT_REASON_LEN + 1);
            assert_eq!(max, MAX_FAULT_REASON_LEN);
        }
        other => return Err(format!("expected FaultReasonTooLong, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_bounds_corroboration_sources_at_bound_and_bound_plus_one() -> Result<(), Box<dyn Error>> {
    let generation = ModelGeneration::parse("model:detector:v1")?;
    let executor = MockModelExecutor::new(generation.clone(), 42)?;
    let interval = CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))?;
    let mut clock = VirtualClock::new(1, TimestampNs(10_000_000));

    let mut outputs = Vec::new();
    for i in 0..=MAX_CORROBORATION_SOURCES {
        let sensor_id = SensorId::parse(format!("sensor:cam-{i:03}"))?;
        let out = match executor.execute_frame(b"frame", &sensor_id, &interval, &mut clock)? {
            MockExecutorOutcome::Success(o) => *o,
            other => return Err(format!("expected Success, got {other:?}").into()),
        };
        outputs.push(out);
    }

    // At bound (32 sources): accepted
    let at_bound_slice = &outputs[..MAX_CORROBORATION_SOURCES];
    assert_eq!(at_bound_slice.len(), MAX_CORROBORATION_SOURCES);
    let res_at_bound = evaluate_corroboration(at_bound_slice);
    assert!(res_at_bound.is_ok());

    // Over bound (33 sources): rejected
    let over_bound_slice = &outputs[..=MAX_CORROBORATION_SOURCES];
    assert_eq!(over_bound_slice.len(), MAX_CORROBORATION_SOURCES + 1);
    match evaluate_corroboration(over_bound_slice) {
        Err(MockModelError::TooManyCorroborationSources { actual, max }) => {
            assert_eq!(actual, MAX_CORROBORATION_SOURCES + 1);
            assert_eq!(max, MAX_CORROBORATION_SOURCES);
        }
        other => return Err(format!("expected TooManyCorroborationSources, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_e2e_capsule_execution_with_sensor_capsule_and_virtual_clock() -> Result<(), Box<dyn Error>>
{
    let capsule = sample_capsule(
        "cap:e2e:001",
        "sensor:cam-entry",
        1,
        100_000_000,
        133_333_333,
    )?;
    let generation = ModelGeneration::parse("model:yolo26:fp16:v1")?;
    let executor = MockModelExecutor::new(generation.clone(), 0xfeed_cafe_u64)?;

    let mut clock = VirtualClock::new(42, TimestampNs(200_000_000));
    let initial_clock_time = clock.now();

    let outcome = executor.execute_capsule(&capsule, &mut clock)?;
    let output = match outcome {
        MockExecutorOutcome::Success(o) => *o,
        other => return Err(format!("expected Success, got {other:?}").into()),
    };

    // Assert explicit provenance
    assert_eq!(output.generation, generation);
    assert_eq!(output.sensor_id, capsule.sensor_id);
    assert_eq!(output.input_digest, capsule.integrity.metadata_digest);
    assert_eq!(output.capture_interval, capsule.capture_interval);
    assert_eq!(output.knowledge_state, KnowledgeState::Estimated);
    assert_eq!(output.provenance_class, ProvenanceClass::Predicted);
    assert!(clock.now().0 > initial_clock_time.0);

    // Detections are non-empty and bounded
    assert!(!output.detections.is_empty());
    for det in &output.detections {
        assert!(det.probability.lower >= 0.0);
        assert!(det.probability.upper <= 1.0);
        assert!(det.bounding_box[0] >= 0.0 && det.bounding_box[2] <= 1.0);
        assert!(det.bounding_box[1] >= 0.0 && det.bounding_box[3] <= 1.0);
    }

    Ok(())
}

#[test]
fn test_single_model_score_not_corroborated_when_second_camera_disagrees()
-> Result<(), Box<dyn Error>> {
    let generation = ModelGeneration::parse("model:detector:v1")?;
    let sensor_1 = SensorId::parse("sensor:cam-front")?;
    let sensor_2 = SensorId::parse("sensor:cam-rear")?;
    let interval = CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))?;

    let out_1 = MockModelOutput {
        output_digest: ContentDigest::sha256(b"out1"),
        generation: generation.clone(),
        sensor_id: sensor_1.clone(),
        input_digest: ContentDigest::sha256(b"in1"),
        capture_interval: interval,
        knowledge_state: KnowledgeState::Estimated,
        provenance_class: ProvenanceClass::Predicted,
        detections: vec![MockDetection {
            label: MockSemanticLabel::PersonLike,
            probability: ProbabilityInterval::new(0.80, 0.90)?,
            bounding_box: [0.1, 0.1, 0.5, 0.5],
        }],
        corroboration: CorroborationStatus::UncorroboratedSingleSource {
            sensor_id: sensor_1.clone(),
            model_generation: generation.as_str().to_string(),
        },
        virtual_latency_ns: 10_000_000,
    };

    // Camera 2 detected AnimalLike, NOT PersonLike
    let out_2 = MockModelOutput {
        output_digest: ContentDigest::sha256(b"out2"),
        generation: generation.clone(),
        sensor_id: sensor_2.clone(),
        input_digest: ContentDigest::sha256(b"in2"),
        capture_interval: interval,
        knowledge_state: KnowledgeState::Estimated,
        provenance_class: ProvenanceClass::Predicted,
        detections: vec![MockDetection {
            label: MockSemanticLabel::AnimalLike,
            probability: ProbabilityInterval::new(0.70, 0.85)?,
            bounding_box: [0.2, 0.2, 0.6, 0.6],
        }],
        corroboration: CorroborationStatus::UncorroboratedSingleSource {
            sensor_id: sensor_2,
            model_generation: generation.as_str().to_string(),
        },
        virtual_latency_ns: 10_000_000,
    };

    let result = evaluate_corroboration(&[out_1, out_2]);
    assert!(
        result.is_err(),
        "evaluate_corroboration must reject corroboration when only a single camera observed the label"
    );
    Ok(())
}

#[test]
fn test_canonical_encode_and_output_digest_must_bind_knowledge_state_provenance_and_corroboration()
-> Result<(), Box<dyn Error>> {
    let generation = ModelGeneration::parse("model:detector:v1")?;
    let sensor_id = SensorId::parse("sensor:cam-1")?;
    let interval = CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))?;

    let out_estimated = MockModelOutput {
        output_digest: ContentDigest::sha256(b"dummy1"),
        generation: generation.clone(),
        sensor_id: sensor_id.clone(),
        input_digest: ContentDigest::sha256(b"input"),
        capture_interval: interval,
        knowledge_state: KnowledgeState::Estimated,
        provenance_class: ProvenanceClass::Predicted,
        detections: vec![],
        corroboration: CorroborationStatus::UncorroboratedSingleSource {
            sensor_id: sensor_id.clone(),
            model_generation: generation.as_str().to_string(),
        },
        virtual_latency_ns: 10_000_000,
    };

    let mut out_conflicted = out_estimated.clone();
    out_conflicted.knowledge_state = KnowledgeState::Conflicted;

    let mut out_remembered = out_estimated.clone();
    out_remembered.provenance_class = ProvenanceClass::Remembered;

    let mut out_corroborated = out_estimated.clone();
    out_corroborated.corroboration = CorroborationStatus::Corroborated {
        contributing_sensors: vec![sensor_id.clone(), SensorId::parse("sensor:cam-2")?],
        contributing_generations: vec![generation.as_str().to_string()],
    };

    let bytes_estimated = out_estimated.canonical_bytes();
    let bytes_conflicted = out_conflicted.canonical_bytes();
    let bytes_remembered = out_remembered.canonical_bytes();
    let bytes_corroborated = out_corroborated.canonical_bytes();

    assert_ne!(
        bytes_estimated, bytes_conflicted,
        "outputs with different knowledge states must produce distinct canonical bytes"
    );
    assert_ne!(
        bytes_estimated, bytes_remembered,
        "outputs with different provenance classes must produce distinct canonical bytes"
    );
    assert_ne!(
        bytes_estimated, bytes_corroborated,
        "outputs with different corroboration statuses must produce distinct canonical bytes"
    );

    let digest_estimated = compute_output_digest(&MockOutputDigestRequest::from(&out_estimated))?;
    let digest_conflicted = compute_output_digest(&MockOutputDigestRequest::from(&out_conflicted))?;
    assert_ne!(
        digest_estimated, digest_conflicted,
        "output digests must differ when knowledge state changes"
    );

    Ok(())
}

#[test]
fn test_bounding_box_rounding_eliminates_float_truncation_drift() {
    let coord: f64 = 0.043;
    let basis_pt = encode_coord_to_basis_point(coord);
    assert_eq!(
        basis_pt, 430,
        "Truncation drift: 0.043 * 10000.0 rounded basis point must evaluate to 430, got {basis_pt}"
    );

    let coord2: f64 = 0.051;
    let basis_pt2 = encode_coord_to_basis_point(coord2);
    assert_eq!(
        basis_pt2, 510,
        "Truncation drift: 0.051 * 10000.0 rounded basis point must evaluate to 510, got {basis_pt2}"
    );

    assert_eq!(encode_coord_to_basis_point(0.0), 0);
    assert_eq!(encode_coord_to_basis_point(1.0), 10_000);
}

#[test]
fn test_corroboration_rejects_contradictory_probability_intervals() -> Result<(), Box<dyn Error>> {
    let generation = ModelGeneration::parse("model:detector:v1")?;
    let sensor_1 = SensorId::parse("sensor:cam-1")?;
    let sensor_2 = SensorId::parse("sensor:cam-2")?;
    let interval = CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))?;

    let out_1 = MockModelOutput {
        output_digest: ContentDigest::sha256(b"out1"),
        generation: generation.clone(),
        sensor_id: sensor_1.clone(),
        input_digest: ContentDigest::sha256(b"in1"),
        capture_interval: interval,
        knowledge_state: KnowledgeState::Estimated,
        provenance_class: ProvenanceClass::Predicted,
        detections: vec![MockDetection {
            label: MockSemanticLabel::PersonLike,
            probability: ProbabilityInterval::new(0.80, 0.90)?,
            bounding_box: [0.1, 0.1, 0.5, 0.5],
        }],
        corroboration: CorroborationStatus::UncorroboratedSingleSource {
            sensor_id: sensor_1,
            model_generation: generation.as_str().to_string(),
        },
        virtual_latency_ns: 10_000_000,
    };

    let out_2 = MockModelOutput {
        output_digest: ContentDigest::sha256(b"out2"),
        generation: generation.clone(),
        sensor_id: sensor_2.clone(),
        input_digest: ContentDigest::sha256(b"in2"),
        capture_interval: interval,
        knowledge_state: KnowledgeState::Estimated,
        provenance_class: ProvenanceClass::Predicted,
        detections: vec![MockDetection {
            label: MockSemanticLabel::PersonLike,
            probability: ProbabilityInterval::new(0.10, 0.20)?,
            bounding_box: [0.1, 0.1, 0.5, 0.5],
        }],
        corroboration: CorroborationStatus::UncorroboratedSingleSource {
            sensor_id: sensor_2,
            model_generation: generation.as_str().to_string(),
        },
        virtual_latency_ns: 10_000_000,
    };

    let res = evaluate_corroboration(&[out_1, out_2]);
    match res {
        Err(MockModelError::ContradictoryProbabilityIntervals {
            lower_micro,
            upper_micro,
        }) => {
            assert_eq!(lower_micro, 800_000);
            assert_eq!(upper_micro, 200_000);
        }
        other => {
            return Err(
                format!("expected ContradictoryProbabilityIntervals, got {other:?}").into(),
            );
        }
    }
    Ok(())
}

#[test]
fn test_bounds_detections_per_output_at_bound_and_bound_plus_one() -> Result<(), Box<dyn Error>> {
    let generation = ModelGeneration::parse("model:detector:v1")?;
    let sensor_1 = SensorId::parse("sensor:cam-1")?;
    let sensor_2 = SensorId::parse("sensor:cam-2")?;
    let interval = CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))?;

    let make_detections = |count: usize| -> Result<Vec<MockDetection>, Box<dyn Error>> {
        let mut list = Vec::with_capacity(count);
        for _ in 0..count {
            list.push(MockDetection {
                label: MockSemanticLabel::PersonLike,
                probability: ProbabilityInterval::new(0.60, 0.80)?,
                bounding_box: [0.1, 0.1, 0.5, 0.5],
            });
        }
        Ok(list)
    };

    // Exactly at bound: 64 detections
    let detections_at_bound = make_detections(MAX_DETECTIONS_PER_OUTPUT)?;
    assert_eq!(detections_at_bound.len(), MAX_DETECTIONS_PER_OUTPUT);
    let digest_at_bound = compute_output_digest(&MockOutputDigestRequest {
        generation: &generation,
        sensor_id: &sensor_1,
        input_digest: &ContentDigest::sha256(b"in"),
        capture_interval: &interval,
        knowledge_state: KnowledgeState::Estimated,
        provenance_class: ProvenanceClass::Predicted,
        corroboration: &CorroborationStatus::UncorroboratedSingleSource {
            sensor_id: sensor_1.clone(),
            model_generation: generation.as_str().to_string(),
        },
        detections: &detections_at_bound,
        virtual_latency_ns: 10_000_000,
    });
    assert!(digest_at_bound.is_ok());

    let out_1_at_bound = MockModelOutput {
        output_digest: digest_at_bound?,
        generation: generation.clone(),
        sensor_id: sensor_1.clone(),
        input_digest: ContentDigest::sha256(b"in1"),
        capture_interval: interval,
        knowledge_state: KnowledgeState::Estimated,
        provenance_class: ProvenanceClass::Predicted,
        detections: detections_at_bound,
        corroboration: CorroborationStatus::UncorroboratedSingleSource {
            sensor_id: sensor_1.clone(),
            model_generation: generation.as_str().to_string(),
        },
        virtual_latency_ns: 10_000_000,
    };
    assert!(out_1_at_bound.validate().is_ok());

    let out_2_at_bound = MockModelOutput {
        output_digest: ContentDigest::sha256(b"out2"),
        generation: generation.clone(),
        sensor_id: sensor_2.clone(),
        input_digest: ContentDigest::sha256(b"in2"),
        capture_interval: interval,
        knowledge_state: KnowledgeState::Estimated,
        provenance_class: ProvenanceClass::Predicted,
        detections: make_detections(2)?,
        corroboration: CorroborationStatus::UncorroboratedSingleSource {
            sensor_id: sensor_2.clone(),
            model_generation: generation.as_str().to_string(),
        },
        virtual_latency_ns: 10_000_000,
    };
    assert!(evaluate_corroboration(&[out_1_at_bound, out_2_at_bound]).is_ok());

    // Over bound: 65 detections
    let detections_over_bound = make_detections(MAX_DETECTIONS_PER_OUTPUT + 1)?;
    assert_eq!(detections_over_bound.len(), MAX_DETECTIONS_PER_OUTPUT + 1);
    let digest_over_bound = compute_output_digest(&MockOutputDigestRequest {
        generation: &generation,
        sensor_id: &sensor_1,
        input_digest: &ContentDigest::sha256(b"in"),
        capture_interval: &interval,
        knowledge_state: KnowledgeState::Estimated,
        provenance_class: ProvenanceClass::Predicted,
        corroboration: &CorroborationStatus::UncorroboratedSingleSource {
            sensor_id: sensor_1.clone(),
            model_generation: generation.as_str().to_string(),
        },
        detections: &detections_over_bound,
        virtual_latency_ns: 10_000_000,
    });
    match digest_over_bound {
        Err(MockModelError::TooManyDetections { actual, max }) => {
            assert_eq!(actual, MAX_DETECTIONS_PER_OUTPUT + 1);
            assert_eq!(max, MAX_DETECTIONS_PER_OUTPUT);
        }
        other => return Err(format!("expected TooManyDetections, got {other:?}").into()),
    }

    let out_over_bound = MockModelOutput {
        output_digest: ContentDigest::sha256(b"dummy"),
        generation,
        sensor_id: sensor_1,
        input_digest: ContentDigest::sha256(b"in"),
        capture_interval: interval,
        knowledge_state: KnowledgeState::Estimated,
        provenance_class: ProvenanceClass::Predicted,
        detections: detections_over_bound,
        corroboration: CorroborationStatus::UncorroboratedSingleSource {
            sensor_id: sensor_2,
            model_generation: "model:detector:v1".to_string(),
        },
        virtual_latency_ns: 10_000_000,
    };
    assert!(matches!(
        out_over_bound.validate(),
        Err(MockModelError::TooManyDetections { .. })
    ));

    Ok(())
}

#[test]
fn test_corroboration_rejects_empty_detections_without_fabricating_unknown()
-> Result<(), Box<dyn Error>> {
    let generation = ModelGeneration::parse("model:detector:v1")?;
    let sensor_1 = SensorId::parse("sensor:cam-1")?;
    let sensor_2 = SensorId::parse("sensor:cam-2")?;
    let interval = CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))?;

    let out_empty_1 = MockModelOutput {
        output_digest: ContentDigest::sha256(b"out1"),
        generation: generation.clone(),
        sensor_id: sensor_1.clone(),
        input_digest: ContentDigest::sha256(b"in1"),
        capture_interval: interval,
        knowledge_state: KnowledgeState::Estimated,
        provenance_class: ProvenanceClass::Predicted,
        detections: vec![],
        corroboration: CorroborationStatus::UncorroboratedSingleSource {
            sensor_id: sensor_1,
            model_generation: generation.as_str().to_string(),
        },
        virtual_latency_ns: 10_000_000,
    };

    let out_empty_2 = MockModelOutput {
        output_digest: ContentDigest::sha256(b"out2"),
        generation: generation.clone(),
        sensor_id: sensor_2.clone(),
        input_digest: ContentDigest::sha256(b"in2"),
        capture_interval: interval,
        knowledge_state: KnowledgeState::Estimated,
        provenance_class: ProvenanceClass::Predicted,
        detections: vec![],
        corroboration: CorroborationStatus::UncorroboratedSingleSource {
            sensor_id: sensor_2,
            model_generation: generation.as_str().to_string(),
        },
        virtual_latency_ns: 10_000_000,
    };

    let res = evaluate_corroboration(&[out_empty_1, out_empty_2]);
    assert_eq!(res, Err(MockModelError::NoDetectionsToCorroborate));
    Ok(())
}

#[test]
fn test_corroboration_rejects_cross_generation_mixing() -> Result<(), Box<dyn Error>> {
    let gen_v1 = ModelGeneration::parse("model:detector:v1")?;
    let gen_v2 = ModelGeneration::parse("model:detector:v2")?;
    let sensor_1 = SensorId::parse("sensor:cam-1")?;
    let sensor_2 = SensorId::parse("sensor:cam-2")?;
    let interval = CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))?;

    let detection = MockDetection {
        label: MockSemanticLabel::PersonLike,
        probability: ProbabilityInterval::new(0.85, 0.95)?,
        bounding_box: [0.1, 0.1, 0.5, 0.5],
    };

    let out_v1 = MockModelOutput {
        output_digest: ContentDigest::sha256(b"out1"),
        generation: gen_v1.clone(),
        sensor_id: sensor_1.clone(),
        input_digest: ContentDigest::sha256(b"in1"),
        capture_interval: interval,
        knowledge_state: KnowledgeState::Estimated,
        provenance_class: ProvenanceClass::Predicted,
        detections: vec![detection.clone()],
        corroboration: CorroborationStatus::UncorroboratedSingleSource {
            sensor_id: sensor_1,
            model_generation: gen_v1.as_str().to_string(),
        },
        virtual_latency_ns: 10_000_000,
    };

    let out_v2 = MockModelOutput {
        output_digest: ContentDigest::sha256(b"out2"),
        generation: gen_v2.clone(),
        sensor_id: sensor_2.clone(),
        input_digest: ContentDigest::sha256(b"in2"),
        capture_interval: interval,
        knowledge_state: KnowledgeState::Estimated,
        provenance_class: ProvenanceClass::Predicted,
        detections: vec![detection],
        corroboration: CorroborationStatus::UncorroboratedSingleSource {
            sensor_id: sensor_2,
            model_generation: gen_v2.as_str().to_string(),
        },
        virtual_latency_ns: 10_000_000,
    };

    let res = evaluate_corroboration(&[out_v1, out_v2]);
    assert_eq!(
        res,
        Err(MockModelError::CrossGenerationScoreMixing {
            expected: gen_v1,
            actual: gen_v2,
        })
    );
    Ok(())
}

#[test]
fn test_score_fusion_boundary_enforces_generation_identity() -> Result<(), Box<dyn Error>> {
    let gen_v1 = ModelGeneration::parse("model:detector:v1")?;
    let gen_v2 = ModelGeneration::parse("model:detector:v2")?;

    let det1 = MockDetection {
        label: MockSemanticLabel::PersonLike,
        probability: ProbabilityInterval::new(0.60, 0.90)?,
        bounding_box: [0.1, 0.1, 0.5, 0.5],
    };
    let det2 = MockDetection {
        label: MockSemanticLabel::PersonLike,
        probability: ProbabilityInterval::new(0.70, 0.85)?,
        bounding_box: [0.15, 0.15, 0.45, 0.45],
    };

    // Planted negative: mixing scores across different model generations must fail with typed error
    let err = fuse_model_scores(&det1, &gen_v1, &det2, &gen_v2);
    assert_eq!(
        err,
        Err(MockModelError::CrossGenerationScoreMixing {
            expected: gen_v1.clone(),
            actual: gen_v2,
        })
    );

    // Positive case: fusing scores from same model generation succeeds
    let fused = fuse_model_scores(&det1, &gen_v1, &det2, &gen_v1)?;
    assert!((fused.lower - 0.70).abs() < 1e-6);
    assert!((fused.upper - 0.85).abs() < 1e-6);

    // Contradictory disjoint intervals from same generation fail closed
    let det_disjoint = MockDetection {
        label: MockSemanticLabel::PersonLike,
        probability: ProbabilityInterval::new(0.10, 0.20)?,
        bounding_box: [0.1, 0.1, 0.5, 0.5],
    };
    let contra = fuse_model_scores(&det1, &gen_v1, &det_disjoint, &gen_v1);
    assert!(matches!(
        contra,
        Err(MockModelError::ContradictoryProbabilityIntervals { .. })
    ));

    Ok(())
}

#[test]
fn test_embedding_comparison_and_fusion_boundaries() -> Result<(), Box<dyn Error>> {
    let gen_v1 = ModelGeneration::parse("model:embed:v1")?;
    let gen_v2 = ModelGeneration::parse("model:embed:v2")?;

    let emb1 = MockEmbedding::new(gen_v1.clone(), vec![1.0, 0.0, 0.0])?;
    let emb2 = MockEmbedding::new(gen_v2.clone(), vec![1.0, 0.0, 0.0])?;
    let emb3 = MockEmbedding::new(gen_v1.clone(), vec![0.0, 1.0, 0.0])?;

    // Planted negative 1: compare across different generations rejected
    let cmp_err = compare_model_embeddings(&emb1, &emb2);
    assert_eq!(
        cmp_err,
        Err(MockModelError::CrossGenerationEmbeddingMixing {
            expected: gen_v1.clone(),
            actual: gen_v2.clone(),
        })
    );

    // Planted negative 2: fuse across different generations rejected
    let fuse_err = fuse_model_embeddings(&emb1, &emb2);
    assert_eq!(
        fuse_err,
        Err(MockModelError::CrossGenerationEmbeddingMixing {
            expected: gen_v1.clone(),
            actual: gen_v2,
        })
    );

    // Positive comparison: orthogonal vectors have 0.0 cosine similarity
    let sim = compare_model_embeddings(&emb1, &emb3)?;
    assert!(sim.abs() < 1e-6);

    // Positive comparison: identical vectors have 1.0 cosine similarity
    let sim_ident = compare_model_embeddings(&emb1, &emb1)?;
    assert!((sim_ident - 1.0).abs() < 1e-6);

    // Positive fusion: equal weights normalized
    let fused = fuse_model_embeddings(&emb1, &emb3)?;
    assert_eq!(fused.generation, gen_v1);
    assert_eq!(fused.dim(), 3);
    let expected_val = (0.5_f64).sqrt();
    assert!((fused.vector[0] - expected_val).abs() < 1e-6);
    assert!((fused.vector[1] - expected_val).abs() < 1e-6);
    assert!(fused.vector[2].abs() < 1e-6);

    // Dimension mismatch rejected
    let emb_dim2 = MockEmbedding::new(gen_v1.clone(), vec![1.0, 0.0])?;
    assert_eq!(
        compare_model_embeddings(&emb1, &emb_dim2),
        Err(MockModelError::EmbeddingDimensionMismatch {
            expected: 3,
            actual: 2,
        })
    );
    assert_eq!(
        fuse_model_embeddings(&emb1, &emb_dim2),
        Err(MockModelError::EmbeddingDimensionMismatch {
            expected: 3,
            actual: 2,
        })
    );

    // Bounds on MockEmbedding
    assert_eq!(
        MockEmbedding::new(gen_v1.clone(), vec![]),
        Err(MockModelError::EmptyEmbeddingVector)
    );
    let oversized = vec![0.1; MAX_EMBEDDING_DIM + 1];
    assert_eq!(
        MockEmbedding::new(gen_v1.clone(), oversized),
        Err(MockModelError::EmbeddingDimensionTooLarge {
            actual: MAX_EMBEDDING_DIM + 1,
            max: MAX_EMBEDDING_DIM,
        })
    );
    assert_eq!(
        MockEmbedding::new(gen_v1.clone(), vec![f64::NAN, 1.0]),
        Err(MockModelError::InvalidEmbeddingNorm)
    );

    Ok(())
}

#[test]
fn test_anti_latest_generation_prohibitions() -> Result<(), Box<dyn Error>> {
    // 1. is_latest_generation classifier
    assert!(is_latest_generation("latest"));
    assert!(is_latest_generation("LATEST"));
    assert!(is_latest_generation("latest:v1"));
    assert!(is_latest_generation("model:latest"));
    assert!(is_latest_generation("latest.weights"));
    assert!(!is_latest_generation("model:yolo26:fp16:v1"));
    assert!(!is_latest_generation("mock:model:person:v1"));

    // 2. MockModelExecutor rejects "latest" generation
    let gen_latest_prefix = ModelGeneration::parse("latest:model:v1")?;
    let res_exec = MockModelExecutor::new(gen_latest_prefix, 42);
    assert_eq!(
        res_exec,
        Err(MockModelError::LatestGenerationProhibited {
            generation: "latest:model:v1".to_string(),
        })
    );

    let gen_latest_suffix = ModelGeneration::parse("model:v1:latest")?;
    let res_exec_suffix = MockModelExecutor::new(gen_latest_suffix, 42);
    assert_eq!(
        res_exec_suffix,
        Err(MockModelError::LatestGenerationProhibited {
            generation: "model:v1:latest".to_string(),
        })
    );

    // 3. MockModelSpec rejects "latest" generation
    let script = MockModelScript::Fixed {
        label: MockSemanticLabel::PersonLike,
        probability: ProbabilityInterval::new(0.8, 0.9)?,
    };
    assert!(matches!(
        MockModelSpec::new("latest", script.clone()),
        Err(ReferenceError::InvalidSpec(
            "model_generation_latest_prohibited"
        ))
    ));
    assert!(matches!(
        MockModelSpec::new("latest:v1", script.clone()),
        Err(ReferenceError::InvalidSpec(
            "model_generation_latest_prohibited"
        ))
    ));
    assert!(matches!(
        MockModelSpec::new("model:latest", script.clone()),
        Err(ReferenceError::InvalidSpec(
            "model_generation_latest_prohibited"
        ))
    ));
    assert!(matches!(
        MockModelSpec::new("latest.weights", script),
        Err(ReferenceError::InvalidSpec(
            "model_generation_latest_prohibited"
        ))
    ));

    // 4. MockEmbedding rejects "latest" generation
    let gen_latest = ModelGeneration::parse("model:v1:latest")?;
    assert_eq!(
        MockEmbedding::new(gen_latest, vec![1.0, 0.0]),
        Err(MockModelError::LatestGenerationProhibited {
            generation: "model:v1:latest".to_string(),
        })
    );

    Ok(())
}
