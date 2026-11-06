#![forbid(unsafe_code)]
//! Owned TCP pipeline audio events, backpressure, fencing, and retirement.

use asupersync::{CancelKind, Cx, net::TcpListener, runtime::RuntimeBuilder, time::timeout};
use fss_container::flv_avc::SourceKey;
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_packet::extended_flv::{
    Limits as FlvLimits, aac_track,
    stream::{Framer, SearchMode, SourceRecord},
};
use fss_reference::unifi_direct::{
    ingress::DirectIngress,
    metered::MeteredClock,
    pipeline::{self, AudioEvent, AudioSetupError, Pipeline},
    recording::{self, Push, Recorder},
};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
    tcp_ingress::TcpIngress,
};
use std::{
    error::Error,
    io::{Read, Write},
    time::Duration,
};

type TestResult = Result<(), Box<dyn Error>>;

#[derive(Clone, Copy)]
enum Scenario {
    Drain,
    RetirePending,
    CancelPending,
    Disabled,
}

fn tag(kind: u8, timestamp: u32, payload: &[u8]) -> Vec<u8> {
    let size = payload.len();
    let mut output = vec![
        kind,
        (size >> 16) as u8,
        (size >> 8) as u8,
        size as u8,
        (timestamp >> 16) as u8,
        (timestamp >> 8) as u8,
        timestamp as u8,
        (timestamp >> 24) as u8,
        0,
        0,
        0,
    ];
    output.extend_from_slice(payload);
    output.extend_from_slice(&(11_u32 + size as u32).to_be_bytes());
    output
}

fn scenario(mode: Scenario) -> TestResult {
    let mut input = b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    input.extend(tag(8, 0, &[0xaf, 0, 0x14, 0x08]));
    input.extend(tag(8, 64, &[0xaf, 1, 0xde, 0xad]));
    input.extend(tag(10, 100, &[0xcf, 0, 3, 0]));
    input.extend(tag(8, 128, &[0xaf, 1, 0xbe, 0xef]));
    let expected = input.clone();
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 1024 * 1024;
    budget.network_bytes = 1024 * 1024;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:unifi-audio-pipeline".into(),
            operation_id: OperationId::parse("operation:unifi-audio-pipeline")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::ReadMedia.as_str().into(),
            ],
            deadline: Some(TimestampNs(60_000_000_000)),
            priority: 10,
            budgets: budget,
            privacy_scope: "privacy:fixture".into(),
            retention_scope: "retention:fixture".into(),
            anchor_universe: ContentDigest::sha256(b"synthetic audio pipeline")
                .with_laboratory(true),
            generation: 1,
        },
        RegionId::new("region:unifi-audio-pipeline")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = Cx::current().ok_or("missing runtime context")?;
        let result = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:unifi-audio-pipeline")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: TestResult = async {
                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    let address = listener.local_addr()?;
                    let sender = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut stream =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        stream.write_all(&input)
                    });
                    let (socket, _) =
                        timeout(cx.now(), Duration::from_secs(5), listener.accept()).await??;
                    let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                    let tcp = TcpIngress::new(socket, "fixture:camera", 4096, 1024 * 1024)?;
                    let framer = Framer::new(FlvLimits::default(), 1024 * 1024)?;
                    let recorder = Recorder::new(
                        SourceKey {
                            connection: 1,
                            generation: 1,
                        },
                        recording::Limits::default(),
                    )?;
                    let mut pipeline = Pipeline::new(DirectIngress::new(tcp, framer), recorder);
                    if !matches!(mode, Scenario::Disabled) {
                        pipeline.enable_audio_tracking()?;
                        assert_eq!(
                            pipeline.enable_audio_tracking(),
                            Err(AudioSetupError::AlreadyEnabled)
                        );
                    }
                    let mut originals = Vec::new();
                    let mut events = Vec::new();
                    for _ in 0..128 {
                        let step = timeout(
                            cx.now(),
                            Duration::from_secs(5),
                            pipeline.step(task, cx, clock.now()?),
                        )
                        .await??;
                        if matches!(mode, Scenario::Disabled) {
                            assert_eq!(
                                pipeline.enable_audio_tracking(),
                                Err(AudioSetupError::AlreadyStarted)
                            );
                        }
                        match step {
                            pipeline::Step::Recording(Push::Source { record, .. }) => {
                                originals.extend_from_slice(record.bytes())
                            }
                            pipeline::Step::Progress { .. } => (),
                            pipeline::Step::Eof => break,
                            _ => return Err("unexpected pipeline step".into()),
                        }
                        if pipeline.has_pending_audio() {
                            assert!(matches!(
                                pipeline.step(task, cx, clock.now()?).await,
                                Err(pipeline::Error::AudioPending)
                            ));
                            if matches!(mode, Scenario::RetirePending | Scenario::CancelPending) {
                                if matches!(mode, Scenario::CancelPending) {
                                    let now = clock.now()?;
                                    task.request_cancellation(now)?;
                                    cx.cancel_with(CancelKind::User, None);
                                    assert!(matches!(
                                        pipeline.step(task, cx, now).await,
                                        Err(pipeline::Error::Cancelled)
                                    ));
                                }
                                let retired = pipeline.retire();
                                assert!(matches!(
                                    retired.pending_audio,
                                    Some(AudioEvent::Observed(
                                        aac_track::Observation::Configuration { epoch: 1, .. }
                                    ))
                                ));
                                if matches!(mode, Scenario::CancelPending) {
                                    task.begin_drain(TimestampNs(59_000_000_000))?;
                                }
                                sender.join().map_err(|_| "sender panic")??;
                                return Ok(());
                            }
                            events.push(pipeline.take_audio_event().ok_or("audio event missing")?);
                        }
                    }
                    let retired = pipeline.retire();
                    assert!(retired.pending_audio.is_none());
                    assert!(retired.ingress.buffered.is_none());
                    assert!(retired.ingress.source.pending.is_none());
                    for record in retired.recorder.pending {
                        originals.extend_from_slice(record.bytes());
                    }
                    originals.extend_from_slice(retired.ingress.framing.bytes());
                    assert_eq!(originals, expected);
                    if matches!(mode, Scenario::Disabled) {
                        assert!(events.is_empty());
                    } else {
                        assert_eq!(events.len(), 3);
                        assert!(matches!(
                            events[0],
                            AudioEvent::Observed(aac_track::Observation::Configuration {
                                epoch: 1,
                                sample_rate: 16_000,
                                ..
                            })
                        ));
                        assert!(matches!(
                            events[1],
                            AudioEvent::Observed(aac_track::Observation::Sample {
                                epoch: 1,
                                timestamp_ms: 64,
                                ..
                            })
                        ));
                        assert!(matches!(
                            events[2],
                            AudioEvent::Fenced(aac_track::Error::UnsupportedAudioKind)
                        ));
                    }
                    sender.join().map_err(|_| "sender panic")??;
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() && matches!(mode, Scenario::CancelPending) {
                    TaskOutcome::Cancelled
                } else if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("audio pipeline fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(59_000_000_000),
                }
            },
        )
        .await?;
        result.receipt?;
        result.output
    })
}

#[test]
fn audio_events_apply_backpressure_and_unsupported_audio_does_not_stop_video() -> TestResult {
    scenario(Scenario::Drain)
}

#[test]
fn retirement_returns_pending_audio_observation() -> TestResult {
    scenario(Scenario::RetirePending)
}

#[test]
fn cancellation_returns_pending_audio_observation_at_retirement() -> TestResult {
    scenario(Scenario::CancelPending)
}

#[test]
fn audio_tracking_is_opt_in_and_cannot_start_late() -> TestResult {
    scenario(Scenario::Disabled)
}

fn check_source(original: &[u8], offset: &mut usize, record: &SourceRecord) -> TestResult {
    let end = offset
        .checked_add(record.bytes().len())
        .ok_or("source offset overflow")?;
    if original.get(*offset..end) != Some(record.bytes()) || record.offset() != *offset as u64 {
        return Err("source custody mismatch".into());
    }
    *offset = end;
    Ok(())
}

#[test]
#[ignore = "requires explicitly authorized bounded camera capture on stdin"]
fn owner_camera_audio_video_pipeline_replay() -> TestResult {
    let mut wire = Vec::new();
    std::io::stdin()
        .lock()
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut wire)?;
    if wire.len() > 8 * 1024 * 1024 || !wire.starts_with(b"FLV\x01") {
        return Err("invalid bounded laboratory input".into());
    }
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 16 * 1024 * 1024;
    budget.network_bytes = 16 * 1024 * 1024;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:g4-av-pipeline-lab".into(),
            operation_id: OperationId::parse("operation:g4-av-pipeline-lab")?,
            principal: "principal:owner".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::ReadMedia.as_str().into(),
            ],
            deadline: Some(TimestampNs(90_000_000_000)),
            priority: 10,
            budgets: budget,
            privacy_scope: "privacy:local".into(),
            retention_scope: "retention:lab".into(),
            anchor_universe: ContentDigest::sha256(
                b"owner authorized passive camera audio video laboratory",
            )
            .with_laboratory(true),
            generation: 1,
        },
        RegionId::new("region:g4-av-pipeline-lab")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = Cx::current().ok_or("missing runtime context")?;
        let result = run_owned_async(&mut authority, &mut tree, TaskSpec {
            task_id: TaskId::new("task:g4-av-pipeline-lab")?, started_at: TimestampNs(2),
        }, &cx, async |task, cx| {
            let output: Result<(usize, usize, usize, usize, usize), Box<dyn Error>> = async {
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let address = listener.local_addr()?;
                let original = wire.clone();
                let maximum = u64::try_from(wire.len())?.checked_add(1).ok_or("input limit overflow")?;
                let sender = std::thread::spawn(move || -> std::io::Result<()> {
                    let mut socket = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                    socket.write_all(&wire)
                });
                let (socket, _) = timeout(cx.now(), Duration::from_secs(5), listener.accept()).await??;
                let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                let tcp = TcpIngress::new(socket, "fixture:g4-av-pipeline", 32 * 1024, maximum)?;
                let framer = Framer::with_mode(FlvLimits::default(), 8 * 1024 * 1024, SearchMode::StructuredTrailer16)?;
                let recorder = Recorder::new(SourceKey { connection: 1, generation: 1 }, recording::Limits::default())?;
                let mut pipeline = Pipeline::new(DirectIngress::new(tcp, framer), recorder);
                pipeline.enable_audio_tracking()?;
                let (mut offset, mut segments, mut video_samples, mut audio_samples, mut configs) = (0usize, 0usize, 0usize, 0usize, 0usize);
                let mut ended = false;
                for _ in 0..8192 {
                    match timeout(cx.now(), Duration::from_secs(10), pipeline.step(task, cx, clock.now()?)).await?? {
                        pipeline::Step::Recording(Push::Source { record, .. }) => check_source(&original, &mut offset, &record)?,
                        pipeline::Step::Recording(Push::Buffered) | pipeline::Step::Progress { .. } => (),
                        pipeline::Step::Recording(Push::Segment(segment)) => {
                            for record in segment.source() { check_source(&original, &mut offset, record)?; }
                            if pipeline.initialization().is_none() { return Err("missing video initialization".into()); }
                            segments += 1;
                            video_samples += segment.fragment().samples().len();
                        }
                        pipeline::Step::Eof => { ended = true; break; }
                        pipeline::Step::LimitReached => return Err("unexpected source limit".into()),
                    }
                    if let Some(event) = pipeline.take_audio_event() {
                        match event {
                            AudioEvent::Observed(aac_track::Observation::Configuration { .. }) => configs += 1,
                            AudioEvent::Observed(aac_track::Observation::Sample { .. } | aac_track::Observation::UnconfiguredSample { .. }) => audio_samples += 1,
                            AudioEvent::Observed(_) => return Err("unexpected audio observation".into()),
                            AudioEvent::Fenced(_) => return Err("audio interpreter fenced".into()),
                        }
                    }
                }
                if !ended { return Err("pipeline work limit".into()); }
                sender.join().map_err(|_| "sender panic")??;
                let retired = pipeline.retire();
                if retired.pending_audio.is_some() || retired.ingress.buffered.is_some() || retired.ingress.source.pending.is_some() { return Err("pending source or audio event".into()); }
                for record in &retired.recorder.pending { check_source(&original, &mut offset, record)?; }
                if offset as u64 != retired.ingress.framing.offset || original.get(offset..) != Some(retired.ingress.framing.bytes()) { return Err("unparsed tail mismatch".into()); }
                if segments == 0 || video_samples == 0 || audio_samples == 0 { return Err("missing camera audio or video".into()); }
                Ok((segments, video_samples, audio_samples, configs, retired.ingress.framing.bytes().len()))
            }.await;
            let outcome = if output.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("camera audio video replay failed".into()) };
            TaskCompletion { output, outcome, completed_at: TimestampNs(89_000_000_000) }
        }).await?;
        result.receipt?;
        let (segments, video_samples, audio_samples, configs, tail) = result.output?;
        println!("segments={segments} video_samples={video_samples} audio_samples={audio_samples} audio_configurations={configs} tail_bytes={tail} source=caller_supplied authentication=unverified media_saved=no");
        Ok::<(), Box<dyn Error>>(())
    })
}
