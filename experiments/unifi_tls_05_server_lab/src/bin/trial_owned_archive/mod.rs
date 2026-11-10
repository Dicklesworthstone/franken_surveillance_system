#![forbid(unsafe_code)]
//! Bounded experimental owned-session capture, not a continuous service.
use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
};
use fss_container::{Mp4Limits, flv_avc::SourceKey};
use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, OperationId, RootAuthoritySpec, RuntimeGrant,
};
use fss_reference::unifi_direct::{
    archive, av_bootstrap, av_bootstrap_driver, av_owned_sink, av_unknown_worker_guard as unknown,
    av_worker, conversation, events, management, metered::MeteredClock, pipeline, recording,
    recording_session, recording_storage, source_coordinator, source_handoff, source_worker,
    supervisor,
};
use fss_runtime::execution::TaskCx;
use std::{path::Path, sync::Arc, time::Duration};

struct Retention(ContentDigest);
impl archive::RetainAuthority for Retention {
    fn permits(&self, retention: ContentDigest, _root: ContentDigest) -> bool {
        retention == self.0
    }
}

fn anchor_scope(
    name: &str,
    camera_claim: ContentDigest,
) -> Result<ContentDigest, Box<dyn std::error::Error>> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.unifi-owned-trial.root.v1");
    encoder.text(name);
    encoder.digest(camera_claim);
    Ok(ContentDigest::sha256(&encoder.finish_checked()?))
}

/// Inspect existing archive histories against the operator-trusted root stores.
/// This acquires storage locks but performs no camera operation or redispatch.
pub fn inspect<'task>(
    task: &TaskCx<'task>,
    cx: &Cx,
    clock: MeteredClock<'_, 'task>,
    archive_root: &Path,
    anchor_root: &Path,
    mac: [u8; 6],
    readback: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use fss_object::{
        HostSpoolIo,
        effect_journal::{EffectJournalLimits, FileTrustedRootPinRetainer},
    };
    use fss_runtime::effect_journal::EffectPinRetainer;
    use std::os::unix::fs::MetadataExt;
    if !clock.matches(task, cx)
        || !archive_root.is_absolute()
        || !anchor_root.is_absolute()
        || archive_root.starts_with(anchor_root)
        || anchor_root.starts_with(archive_root)
    {
        return Err("archive recovery paths or task invalid".into());
    }
    for root in [archive_root, anchor_root] {
        let resource = root.to_str().ok_or("recovery path is not UTF-8")?;
        task.checkpoint_for(
            RuntimeGrant::ObjectStage,
            resource,
            clock.now()?,
            &BudgetVector::ZERO,
        )?;
        let metadata = std::fs::symlink_metadata(root)?;
        if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
            return Err("recovery root must be a private directory".into());
        }
    }
    let claim = ContentDigest::sha256(&mac);
    let read_anchor = |name: &str| -> Result<
        fss_runtime::effect_journal::EffectJournalPin,
        Box<dyn std::error::Error>,
    > {
        task.checkpoint_for(
            RuntimeGrant::ObjectStage,
            anchor_root.to_str().ok_or("anchor path")?,
            clock.now()?,
            &BudgetVector::ZERO,
        )?;
        let mut root = FileTrustedRootPinRetainer::open_trusting_storage(
            anchor_root.join(name),
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
            anchor_scope(name, claim)?,
        )?;
        root.retained_pin()?
            .ok_or_else(|| "retained archive anchor missing".into())
    };
    let source_minimum = recording_storage::HistoryMinimum {
        journal: read_anchor("source-journal")?,
        keeper: read_anchor("source-keeper")?,
    };
    let av_minimum = recording_storage::HistoryMinimum {
        journal: read_anchor("av-journal")?,
        keeper: read_anchor("av-keeper")?,
    };
    let parent = archive_root.parent().ok_or("archive parent missing")?;
    let authority = fss_core::region::ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:unifi-owned-recovery".into(),
        operation_id: OperationId::parse("operation:unifi-owned-recovery")?,
        principal: "principal:owner".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 1,
        budgets: BudgetVector::builder().bytes(128 * 1024 * 1024).build()?,
        privacy_scope: "privacy:owner".into(),
        retention_scope: "retention:trial".into(),
        anchor_universe: claim,
        generation: 1,
    })?;
    let source_replay =
        fss_reference::ReplayCx::from_context_authority(&authority, parent.to_path_buf())?;
    let av_replay =
        fss_reference::ReplayCx::from_context_authority(&authority, parent.to_path_buf())?;
    let cfg = recording_storage::Configuration {
        root: archive_root,
        site_lineage: "site:unifi-owned-trial",
        source: SourceKey {
            connection: 1,
            generation: 1,
        },
        camera_claim: claim,
        source_retention: ContentDigest::sha256(b"unifi-owned-trial-retention"),
        source_scope: ContentDigest::sha256(b"unifi-owned-trial-source"),
        av_scope: ContentDigest::sha256(b"unifi-owned-trial-av"),
        source_deployment_limits: fss_reference::DeploymentLimits::standard(),
        av_deployment_limits: fss_reference::DeploymentLimits::standard(),
        limits: archive::Limits::default(),
        max_source_bytes: 1024 * 1024,
        work_limit: 4_000_000_000,
    };
    let recovered = recording_storage::recover_histories(
        task,
        cx,
        clock,
        cfg,
        source_minimum,
        av_minimum,
        source_replay,
        av_replay,
    )?;
    if readback {
        let access = Retention(cfg.source_retention);
        let checked =
            recording_storage::readback_confirmed(task, cx, clock, cfg, &recovered, &access)?;
        let (video, audio) = match checked.av_samples.ok_or("no confirmed A/V root")? {
            recording_storage::ConfirmedSamples::AudioVideo { video, audio } => (video, audio.to_string()),
            recording_storage::ConfirmedSamples::VideoOnly { video } => (video, "unknown".to_owned()),
        };
        let (key, source) = checked.source.ok_or("no confirmed source root")?;
        println!(
            "trial_owned_readback_after_exit=verified source_bytes={source} source_connection={} source_generation={} video_samples={video} audio_frames={audio} scope=latest_confirmed replay_still_required=true capture_bounds=unknown",
            key.connection, key.generation
        );
    }
    println!(
        "trial_owned_recovery=inspection_only source_confirmed={} source_pending={} source_replay_required={} source_keeper_caught_up={} av_confirmed={} av_pending={} av_replay_required={} av_keeper_caught_up={} root_trust=operator_selected independence=unverified camera_identity=unverified",
        recovered.source.journal.confirmed().is_some(),
        recovered.source.journal.pending().is_some(),
        recovered.source.journal.replay_pin().is_some(),
        recovered.source.keeper_caught_up(),
        recovered.av.journal.confirmed().is_some(),
        recovered.av.journal.pending().is_some(),
        recovered.av.journal.replay_pin().is_some(),
        recovered.av.keeper_caught_up()
    );
    Ok(())
}

fn create_retainers<'task>(
    task: &TaskCx<'task>,
    cx: &Cx,
    clock: MeteredClock<'_, 'task>,
    root: &Path,
    camera_claim: ContentDigest,
) -> Result<recording_storage::Retainers, Box<dyn std::error::Error>> {
    use fss_object::{
        HostSpoolIo,
        effect_journal::{EffectJournalLimits, FileTrustedRootPinRetainer},
    };
    use fss_runtime::effect_journal::EffectPinRetainer;
    use std::os::unix::fs::DirBuilderExt;
    if !clock.matches(task, cx) {
        return Err("anchor task mismatch".into());
    }
    let resource = root.to_str().ok_or("anchor path is not UTF-8")?;
    task.checkpoint_for(
        RuntimeGrant::ObjectStage,
        resource,
        clock.now()?,
        &BudgetVector::ZERO,
    )?;
    std::fs::DirBuilder::new().mode(0o700).create(root)?;
    let create = |name: &str| -> Result<Box<dyn EffectPinRetainer>, Box<dyn std::error::Error>> {
        task.checkpoint_for(
            RuntimeGrant::ObjectStage,
            resource,
            clock.now()?,
            &BudgetVector::ZERO,
        )?;
        Ok(Box::new(FileTrustedRootPinRetainer::create(
            root.join(name),
            EffectJournalLimits::default(),
            Arc::new(HostSpoolIo),
            anchor_scope(name, camera_claim)?,
        )?))
    };
    Ok(recording_storage::Retainers {
        source_journal: create("source-journal")?,
        source_keeper: create("source-keeper")?,
        av_journal: create("av-journal")?,
        av_keeper: create("av-keeper")?,
    })
}
impl archive::ReadAuthority for Retention {
    fn permits(&self, retention: ContentDigest, _root: ContentDigest) -> bool {
        retention == self.0
    }
}

fn source_completion(c: source_worker::Completion) -> Result<(), &'static str> {
    if c.runtime.is_err() {
        return Err("source worker runtime failed");
    }
    match c.outcome {
        source_worker::Outcome::Publication(source_worker::Publication::Published { .. }) => Ok(()),
        _ => Err("source publication requires reconciliation"),
    }
}
fn av_completion(
    c: av_worker::UnknownTimeCompletion,
) -> Result<(archive::UnknownTimePin, archive::UnknownTimeAvKind), &'static str> {
    if c.runtime.is_err() {
        return Err("A/V worker runtime failed");
    }
    match c.outcome {
        av_worker::UnknownTimeOutcome::Publication(
            av_worker::UnknownTimePublication::Published(published),
        ) => Ok((published.pin, published.kind)),
        _ => Err("A/V publication requires reconciliation"),
    }
}
fn control(step: supervisor::Step, event: &mut Option<events::Frame>) -> Result<(), &'static str> {
    match step {
        supervisor::Step::Idle | supervisor::Step::Media(pipeline::Step::Progress { .. }) => Ok(()),
        supervisor::Step::Observation(
            fss_reference::unifi_direct::Observation::StreamSettingsReply { success, .. },
        ) if success != Some(false) => Ok(()),
        supervisor::Step::TimeSyncWritten { mut trace } => match trace.take_written() {
            Some(fss_reference::unifi_direct::receive::ManagementWrite::Written { permit })
                if permit.journal_backed() =>
            {
                Ok(())
            }
            _ => Err("clock reply requires reconciliation"),
        },
        supervisor::Step::TimeSyncStopped { error, .. } => {
            eprintln!("trial_owned_time_sync_stopped reason={error:?}");
            Err("control observation requires reconciliation")
        }
        supervisor::Step::CameraEvent(frame) => {
            *event = Some(frame);
            Ok(())
        }
        other => {
            let kind = match other {
                supervisor::Step::Media(_) => "media",
                supervisor::Step::TimeSyncWritten { .. } => "time_sync_written",
                supervisor::Step::TimeSyncStopped { .. } => "time_sync_stopped",
                supervisor::Step::TimeSyncInterrupted { .. } => "time_sync_interrupted",
                supervisor::Step::Observation(_) => "observation",
                supervisor::Step::CameraEvent(_) => "camera_event",
                supervisor::Step::StartupRequest(_) => "startup_request",
                supervisor::Step::StartupEventBackpressure => "startup_event_backpressure",
                supervisor::Step::EventReplyBackpressure => "event_reply_backpressure",
                supervisor::Step::Idle => "idle",
                supervisor::Step::AudioPending => "audio_pending",
                supervisor::Step::ControllerStopped(_) => "controller_stopped",
                supervisor::Step::ControllerError(_) => "controller_error",
                supervisor::Step::MediaError(_) => "media_error",
                supervisor::Step::ConversationError(_) => "conversation_error",
                supervisor::Step::Stopped => "stopped",
            };
            eprintln!("trial_owned_unhandled_control kind={kind}");
            Err("control observation requires reconciliation")
        }
    }
}

fn source_control(
    step: supervisor::Step,
    completion: Option<source_worker::Completion>,
    event: &mut Option<events::Frame>,
) -> Result<(), &'static str> {
    // Both outcomes are already owned: account for each even when the other
    // failed, rather than losing a drained completion or control result.
    let source = completion.map_or(Ok(()), source_completion);
    let control = control(step, event);
    if source.is_err() && control.is_err() {
        eprintln!("trial_owned_source_and_control=both_require_reconciliation");
    }
    source.and(control)
}

fn av_control(
    step: supervisor::Step,
    completion: Option<av_worker::UnknownTimeCompletion>,
    event: &mut Option<events::Frame>,
) -> Result<Option<(archive::UnknownTimePin, archive::UnknownTimeAvKind)>, &'static str> {
    let publication = match completion {
        Some(c) => av_completion(c).map(Some),
        None => Ok(None),
    };
    let control = control(step, event);
    if control.is_err() && publication.as_ref().is_ok_and(Option::is_some) {
        eprintln!("trial_owned_av=published_control_requires_reconciliation");
    }
    if control.is_err() && publication.is_err() {
        eprintln!("trial_owned_av_and_control=both_require_reconciliation");
    }
    publication.and_then(|pin| control.map(|_| pin))
}

/// Start from the real admitted controller and preserve journaled uncertainty.
pub async fn run<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
    supervisor: supervisor::Supervisor<'scope, 'task, IO>,
    owner: &mut conversation::Owner<'_, 'scope, 'task>,
    run_id: &super::trial_run_id::TrialRunId,
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    root: &Path,
    source: SourceKey,
    camera_claim: ContentDigest,
    audio: Option<[u8; 2]>,
    wait: Duration,
    segment_limit: usize,
    management: management::Preconditions,
    reply_events: bool,
    anchor_root: Option<&Path>,
    decode_owned: bool,
) -> Result<usize, Box<dyn std::error::Error>> {
    if !(1..=8).contains(&segment_limit) {
        return Err("invalid segment limit".into());
    }
    let parent = root.parent().ok_or("archive parent missing")?;
    let storage_authority = fss_core::region::ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:unifi-owned-storage".into(),
        operation_id: OperationId::parse("operation:unifi-owned-storage")?,
        principal: "principal:owner".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 1,
        budgets: BudgetVector::builder().bytes(128 * 1024 * 1024).build()?,
        privacy_scope: "privacy:owner".into(),
        retention_scope: "retention:trial".into(),
        anchor_universe: camera_claim,
        generation: 1,
    })?;
    let replay =
        fss_reference::ReplayCx::from_context_authority(&storage_authority, parent.to_path_buf())?;
    let av_replay =
        fss_reference::ReplayCx::from_context_authority(&storage_authority, parent.to_path_buf())?;
    let retention = ContentDigest::sha256(b"unifi-owned-trial-retention");
    let access = Arc::new(Retention(retention));
    let configuration = recording_storage::Configuration {
        root,
        site_lineage: "site:unifi-owned-trial",
        source,
        camera_claim,
        source_retention: retention,
        source_scope: ContentDigest::sha256(b"unifi-owned-trial-source"),
        av_scope: ContentDigest::sha256(b"unifi-owned-trial-av"),
        source_deployment_limits: fss_reference::DeploymentLimits::standard(),
        av_deployment_limits: fss_reference::DeploymentLimits::standard(),
        limits: archive::Limits::default(),
        max_source_bytes: 1024 * 1024,
        work_limit: 4_000_000_000,
    };
    let created = if let Some(anchor_root) = anchor_root {
        let retainers = create_retainers(task, cx, clock, anchor_root, camera_claim)?;
        let created = recording_storage::create_retained(
            task,
            cx,
            clock,
            configuration,
            replay,
            av_replay,
            access.clone(),
            retainers,
        )?;
        println!(
            "trial_owned_anchors=retained root_trust=operator_selected independence=unverified"
        );
        created
    } else {
        recording_storage::create(
            task,
            cx,
            clock,
            configuration,
            replay,
            av_replay,
            access.clone(),
        )?
    };
    let collector = av_bootstrap::Collector::new(
        audio,
        retention,
        av_owned_sink::BootstrapPolicy {
            allow_initial_video_only: true, max_separation_ms: 5_000,
            jitter_ms: 5,
            max_epoch_frames: 1_000_000,
            max_audio_frames: Mp4Limits::default().max_samples,
            media_limits: Mp4Limits::default(),
            evidence_limits: fss_reference::unifi_direct::evidence::Limits::default(),
        },
    );
    let mut session = Box::new(
        recording_session::Session::begin(supervisor, collector, created.coordinator, created.av)
            .map_err(|_| "session startup refused; inspect archive")?,
    );
    let av = source_coordinator::ArchiveAdmission {
        resource: "unifi:owned-av",
        cost: &BudgetVector::ZERO,
    };
    let source_admission = source_coordinator::ArchiveAdmission {
        resource: "unifi:owned-source",
        cost: &BudgetVector::ZERO,
    };
    let deadline = cx.now() + wait;
    let mut count = 0u64;
    let mut published = 0usize;
    let mut pins = Vec::new();
    pins.try_reserve_exact(segment_limit)?;
    let result: Result<(), &'static str> = loop {
        let remaining = Duration::from_nanos(deadline.as_nanos().saturating_sub(cx.now().as_nanos()));
        if remaining.is_zero() {
            break Err("owned capture deadline elapsed");
        }
        // Reserve the idle-poll allowance separately from a clock reply. The
        // total requested allowances remain within this capture's remaining
        // budget; blocking journal calls can still overrun a wall deadline.
        let poll_wait = (remaining / 2).min(Duration::from_millis(100));
        let reply_wait = remaining.saturating_sub(poll_wait).min(Duration::from_secs(5));
        if poll_wait.is_zero() || reply_wait.is_zero() {
            break Err("owned capture deadline elapsed");
        }
        {
            let Some(mut control_handle) = session.control() else {
                break Err("owned control unavailable; reconcile session");
            };
            if control_handle.set_time_sync_reply_wait(Some(reply_wait)).is_err() {
                break Err("clock reply budget refused; reconcile session");
            }
        }
        count += 1;
        if count > 200_000 {
            break Err("owned capture step limit");
        }
        let operation = match run_id.owned_step(count) {
            Ok(op) => op,
            Err(_) => break Err("operation identity refused"),
        };
        let step = Box::pin(session.step(
            owner,
            &operation,
            poll_wait,
            task,
            cx,
            clock,
            av,
            source_admission,
        ))
        .await;
        let mut event = None;
        let step_result: Result<Option<(archive::UnknownTimePin, archive::UnknownTimeAvKind)>, &'static str> = match step {
            recording_session::Step::Bootstrap(
                source_coordinator::BootstrapStep::SourceOffered(
                    source_handoff::BootstrapResult::Accepted {
                        audio: Some(pipeline::AudioEvent::Fenced(error)),
                        ..
                    },
                ),
            ) => {
                eprintln!("trial_owned_audio_fenced reason={error:?}");
                Err("audio fenced")
            },
            recording_session::Step::Bootstrap(
                source_coordinator::BootstrapStep::SourceOffered(
                    source_handoff::BootstrapResult::Accepted { .. },
                )
                | source_coordinator::BootstrapStep::SourceStarted
                | source_coordinator::BootstrapStep::Driver(
                    av_bootstrap_driver::Step::Retained
                    | av_bootstrap_driver::Step::Forward {
                        push: recording::Push::Buffered,
                        ..
                    },
                ),
            ) => Ok(None),
            recording_session::Step::Bootstrap(source_coordinator::BootstrapStep::Driver(
                av_bootstrap_driver::Step::Supervisor(step),
            )) => control(step, &mut event).map(|_| None),
            recording_session::Step::Recording(source_coordinator::Step::Session(
                unknown::SessionEvent::Audio(pipeline::AudioEvent::Observed(
                    fss_packet::extended_flv::aac_track::Observation::Header
                    | fss_packet::extended_flv::aac_track::Observation::Other
                    | fss_packet::extended_flv::aac_track::Observation::Sample { .. }
                    | fss_packet::extended_flv::aac_track::Observation::UnconfiguredSample { .. },
                )),
            )) => Ok(None),
            recording_session::Step::Bootstrap(
                source_coordinator::BootstrapStep::SourceArchive(source_handoff::Drive::Completed(
                    c,
                )),
            ) => source_completion(c).map(|_| None),
            recording_session::Step::Bootstrap(
                source_coordinator::BootstrapStep::SourceArchive(source_handoff::Drive::Control {
                    step,
                    completion,
                }),
            ) => source_control(step, completion, &mut event).map(|_| None),
            recording_session::Step::RecordingStarted(_) => Ok(None),
            recording_session::Step::Recording(source_coordinator::Step::SourceStarted) => Ok(None),
            recording_session::Step::Recording(source_coordinator::Step::SourceOffered(
                source_handoff::Result::Accepted {
                    origin: source_handoff::Origin::Source,
                    ..
                },
            )) => Ok(None),
            recording_session::Step::Recording(source_coordinator::Step::SourceOffered(
                source_handoff::Result::Accepted {
                    origin: source_handoff::Origin::Control { completion },
                    ..
                },
            )) => match completion {
                Some(c) => av_completion(c).map(Some),
                None => Ok(None),
            },
            recording_session::Step::Recording(source_coordinator::Step::SourceArchive(
                source_handoff::Drive::Completed(c),
            )) => source_completion(c).map(|_| None),
            recording_session::Step::Recording(source_coordinator::Step::SourceArchive(
                source_handoff::Drive::Control { step, completion },
            )) => source_control(step, completion, &mut event).map(|_| None),
            recording_session::Step::Recording(source_coordinator::Step::Session(
                unknown::SessionEvent::Advance(
                    unknown::Advance::Source(unknown::Step::SourceQueued)
                    | unknown::Advance::ArchiveStarted,
                ),
            )) => Ok(None),
            recording_session::Step::Recording(source_coordinator::Step::Session(
                unknown::SessionEvent::Advance(unknown::Advance::Source(
                    unknown::Step::Supervisor(supervisor::Step::Media(pipeline::Step::Recording(
                        recording::Push::Buffered,
                    ))),
                )),
            )) => Ok(None),
            recording_session::Step::Recording(source_coordinator::Step::Session(
                unknown::SessionEvent::Advance(unknown::Advance::Source(
                    unknown::Step::Supervisor(step),
                )),
            )) => control(step, &mut event).map(|_| None),
            recording_session::Step::Recording(source_coordinator::Step::Session(
                unknown::SessionEvent::Advance(unknown::Advance::Archive(unknown::Drive::Archive(
                    c,
                ))),
            )) => av_completion(c).map(Some),
            recording_session::Step::Recording(source_coordinator::Step::Session(
                unknown::SessionEvent::Advance(unknown::Advance::Archive(
                    unknown::Drive::Control { step, completion },
                )),
            )) => av_control(step, completion, &mut event),
            other => {
                match &other {
                    recording_session::Step::Bootstrap(event) => eprintln!(
                        "trial_owned_unhandled bootstrap={:?}",
                        std::mem::discriminant(event)
                    ),
                    recording_session::Step::Recording(source_coordinator::Step::Session(
                        unknown::SessionEvent::Advance(unknown::Advance::Source(event)),
                    )) => eprintln!(
                        "trial_owned_unhandled source={:?}",
                        std::mem::discriminant(event)
                    ),
                    recording_session::Step::Recording(source_coordinator::Step::Session(
                        unknown::SessionEvent::Advance(event),
                    )) => eprintln!(
                        "trial_owned_unhandled advance={:?}",
                        std::mem::discriminant(event)
                    ),
                    recording_session::Step::Recording(source_coordinator::Step::Session(
                        unknown::SessionEvent::Audio(event),
                    )) => eprintln!(
                        "trial_owned_unhandled audio={:?}",
                        std::mem::discriminant(event)
                    ),
                    recording_session::Step::Recording(event) => eprintln!(
                        "trial_owned_unhandled recording={:?}",
                        std::mem::discriminant(event)
                    ),
                    _ => eprintln!(
                        "trial_owned_unhandled phase={:?}",
                        std::mem::discriminant(&other)
                    ),
                }
                Err("owned session stopped with an unhandled observation")
            }
        };
        let pin = match step_result {
            Ok(pin) => pin,
            Err(error) => break Err(error),
        };
        if let Some(pin) = pin {
            if pins
                .iter()
                .any(|prior: &(archive::UnknownTimePin, archive::UnknownTimeAvKind)| prior.0.root == pin.0.root)
            {
                break Err("duplicate A/V publication root requires reconciliation");
            }
            pins.push(pin);
            published += 1;
            println!("trial_stage=owned_segment_published count={published} kind={:?}", pin.1);
        }
        if let Some(frame) = event {
            if !frame.response_expected() {
                println!(
                    "trial_owned_event=observed source_bytes_omitted={} identity=network_claim",
                    frame.source().len()
                );
            } else if !reply_events {
                break Err("event reply required; enable the authorized reply option");
            } else {
                let operation =
                    match run_id.owned_event(count) {
                        Ok(value) => value,
                        Err(_) => break Err("event operation identity refused"),
                    };
                let Some(wall) = owner.wall.observe() else {
                    break Err("event reply clock unavailable");
                };
                let Some(mut access) = session.control() else {
                    break Err("event reply control unavailable");
                };
                let mut trace = match access.prepare_journaled_event_reply(
                    owner,
                    &frame,
                    &wall.timestamp,
                    &operation,
                ) {
                    Ok(trace) => trace,
                    Err(_) => break Err("event reply preparation requires reconciliation"),
                };
                if Box::pin(access.dispatch_event_reply_tracked(
                    owner,
                    management,
                    wait.min(Duration::from_secs(5)),
                    &mut trace,
                ))
                .await
                .is_err()
                {
                    break Err("event reply trace unavailable; reconcile journal");
                }
                match trace.take_outcome() {
                    Some(Ok(fss_reference::unifi_direct::receive::ManagementWrite::Written {
                        permit,
                    })) if permit.journal_backed() => println!(
                        "trial_owned_event_reply=written effects_require_reconciliation=true source_bytes_omitted={}",
                        frame.source().len()
                    ),
                    _ => break Err("event reply incomplete; reconcile journal"),
                }
            }
        }
        if published == segment_limit {
            break Ok(());
        }
    };
    if let Err(reason) = result {
        // Preserve the payload-free reason even if later drain or custody checks also fail.
        eprintln!("trial_owned_capture_stop reason={reason}");
    }
    match (*session).stop() {
        recording_session::Stop::Bootstrap(mut stop) => {
            let source_result = stop.join_source().await.map_or(Ok(()), source_completion);
            let (coordinator, driver, resources) =
                stop.finish().map_err(|_| "bootstrap drain incomplete")?;
            let retired = coordinator
                .into_worker()
                .retire()
                .map_err(|_| "source worker still active")?;
            if retired.pending.is_some() || retired.fenced {
                eprintln!("trial_owned_source_custody pending={} fenced={}", retired.pending.is_some(), retired.fenced);
                return Err("source custody requires reconciliation".into());
            }
            drop((driver, resources, retired));
            source_result?;
        }
        recording_session::Stop::Recording(mut stop) => {
            let source_result = stop.join_source().await.map_or(Ok(()), source_completion);
            let av_result = stop.join_av().await.map(av_completion).transpose();
            let (coordinator, guard) = stop.finish().map_err(|_| "recording drain incomplete")?;
            let retired_source = coordinator
                .into_worker()
                .retire()
                .map_err(|_| "source worker still active")?;
            let guard = (*guard).retire().map_err(|_| "A/V worker still active")?;
            if retired_source.pending.is_some()
                || retired_source.fenced
                || guard.held.is_some()
                || guard.worker.fenced
            {
                eprintln!("trial_owned_archive_custody source_pending={} source_fenced={} av_held={} av_fenced={}",
                    retired_source.pending.is_some(), retired_source.fenced, guard.held.is_some(), guard.worker.fenced);
                return Err("archive custody requires reconciliation".into());
            }
            let mut parts = guard.worker.parts;
            if parts.sink.retire().pending.is_some() {
                return Err("A/V source custody requires reconciliation".into());
            }
            drop(retired_source);
            let drained_pin = match (source_result, av_result) {
                (Ok(()), Ok(pin)) => pin,
                (Err(_), Err(_)) => {
                    return Err("source and A/V drain require reconciliation".into());
                }
                (Err(error), Ok(Some(_))) => {
                    eprintln!("trial_owned_av=published_source_requires_reconciliation");
                    return Err(error.into());
                }
                (Err(error), Ok(None)) | (Ok(()), Err(error)) => return Err(error.into()),
            };
            if result.is_ok() && drained_pin.is_some() {
                return Err("unexpected drained A/V publication requires reconciliation".into());
            }
            if result.is_ok() {
                let mut video_samples = 0usize;
                let mut audio_frames = 0usize;
                let mut first_media = None;
                let resource = root.to_str().ok_or("archive path is not UTF-8")?;
                for (pin, kind) in &pins {
                    task.checkpoint_for(
                        RuntimeGrant::ReadMedia,
                        resource,
                        clock.now()?,
                        &BudgetVector::ZERO,
                    )?;
                    let (video_count, audio_count, media) = match kind {
                        archive::UnknownTimeAvKind::AudioVideo => {
                            let clip = archive::read_unknown_time_av_clip(
                                &mut parts.deployment, *pin, access.as_ref(), archive::Limits::default(),
                                &mut fss_geometry::WorkBudget::new(4_000_000_000), &parts.replay,
                            )?;
                            if clip.claimed_source() != source || clip.audio().frames == 0 { return Err("archive A/V source or audio mismatch".into()); }
                            (clip.video_samples(), clip.audio().frames, clip.into_bytes())
                        }
                        archive::UnknownTimeAvKind::VideoOnly => {
                            let clip = archive::read_unknown_time_av_video_only_clip(
                                &mut parts.deployment, *pin, access.as_ref(), archive::Limits::default(),
                                &mut fss_geometry::WorkBudget::new(4_000_000_000), &parts.replay,
                            )?;
                            if clip.claimed_source() != source { return Err("archive video source claim changed".into()); }
                            (clip.video_samples(), 0, clip.into_bytes())
                        }
                    };
                    if video_count == 0 { return Err("archive readback was empty".into()); }
                    video_samples = video_samples
                        .checked_add(video_count)
                        .ok_or("video sample count overflow")?;
                    audio_frames = audio_frames
                        .checked_add(audio_count)
                        .ok_or("audio frame count overflow")?;
                    if decode_owned && first_media.is_none() {
                        first_media = Some(media);
                    }
                }
                println!(
                    "trial_owned_readback segments={} video_samples={video_samples} audio_frames={audio_frames} capture_bounds=unknown",
                    pins.len()
                );
                if decode_owned {
                    let media = if pins.len() > 1 {
                        task.checkpoint_for(RuntimeGrant::ReadMedia, resource, clock.now()?, &BudgetVector::ZERO)?;
                        let roots: Vec<_> = pins.iter().map(|(pin, _)| *pin).collect();
                        let sequence = archive::read_unknown_time_av_sequence(
                            &mut parts.deployment, &roots, access.as_ref(), archive::Limits::default(),
                            archive::AvSequenceLimits { max_fragments: 8, max_bytes: 128 * 1024 * 1024 },
                            &mut fss_geometry::WorkBudget::new(100_000_000_000), &parts.replay,
                        )?;
                        if sequence.parts().len() != pins.len() { return Err("archive sequence incomplete".into()); }
                        println!("trial_owned_sequence segments={} capture_bounds=unknown", sequence.parts().len());
                        sequence.into_bytes()
                    } else {
                        first_media.ok_or("archive video decode was not performed")?
                    };
                    task.checkpoint_for(RuntimeGrant::MediaDecode, resource, clock.now()?, &BudgetVector::ZERO)?;
                    let movie = fss_container::demux::AvcMp4::parse(&media, None, fss_container::demux::DemuxLimits::default())?;
                    let count = movie.samples().len().min(3);
                    if count == 0 { return Err("archive video has no samples".into()); }
                    let annex = movie.annex_b(0, count)?;
                    let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
                    let mut frames = decoder.decode_annex_b(annex.bytes())?;
                    frames.extend(decoder.finish()?);
                    let frame = frames.first().ok_or("archive video did not decode")?;
                    task.checkpoint_for(RuntimeGrant::MediaDecode, resource, clock.now()?, &BudgetVector::ZERO)?;
                    println!("trial_owned_decoded width={} height={} frames={} capture_bounds=unknown", frame.width(), frame.height(), frames.len());
                }
            }
        }
        recording_session::Stop::TransitionRefused { refusal, .. } => {
            match refusal.as_ref() {
                source_coordinator::TransitionRefusal::Source { status, .. } =>
                    eprintln!("trial_owned_transition_refused source_status={status:?}"),
                source_coordinator::TransitionRefusal::NotReady { .. } =>
                    eprintln!("trial_owned_transition_refused reason=not_ready"),
                source_coordinator::TransitionRefusal::Bootstrap { refusal, .. } => match refusal.as_ref() {
                    av_bootstrap_driver::HandoffRefusal::NotReady(_) =>
                        eprintln!("trial_owned_transition_refused reason=driver_not_ready"),
                    av_bootstrap_driver::HandoffRefusal::Bootstrap { refusal, .. } =>
                        eprintln!("trial_owned_transition_refused bootstrap={:?}", refusal.reason),
                },
                source_coordinator::TransitionRefusal::Guard(refusal) =>
                    eprintln!("trial_owned_transition_refused guard={:?}", std::mem::discriminant(refusal.as_ref())),
            }
            return Err("recording transition requires reconciliation".into());
        }
    }
    result.map(|()| published).map_err(Into::into)
}
