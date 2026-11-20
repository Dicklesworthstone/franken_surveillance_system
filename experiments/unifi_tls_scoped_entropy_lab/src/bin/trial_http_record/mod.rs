#![forbid(unsafe_code)]
//! One bounded camera-local HTTP recording attempt. Not a continuous service.

use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
};
use fss_container::{
    Mp4Limits,
    demux::{AvcMp4, DemuxLimits},
    flv_avc::SourceKey,
};
use fss_core::{
    BudgetVector, ContentDigest, IdempotencyKey, OperationId, RootAuthoritySpec, RuntimeGrant,
};
use fss_object::effect_journal::EffectJournalLimits;
use fss_packet::extended_flv::{
    Limits as FlvLimits,
    stream::{Framer, SearchMode},
};
use fss_reference::{
    DeploymentLimits, ReplayCx,
    unifi_direct::{
        archive,
        camera_api::SerializerAuthority,
        camera_http, evidence, handoff,
        http_stream::{
            Preconditions,
            media_archive::{self, Step},
        },
        listener,
        metered::MeteredClock,
        recording, recording_storage,
        source_coordinator::ArchiveAdmission,
        source_worker, video_bootstrap, video_worker,
    },
};
use fss_runtime::{
    effect::{CommitApproval, EffectCoordinator, PrepareSpec},
    execution::TaskCx,
    lease::LeaseRegistry,
};
use std::{
    any::Any,
    cell::{Cell, RefCell},
    error::Error,
    fmt,
    net::Ipv4Addr,
    path::Path,
    sync::Arc,
    time::Duration,
};

use super::{
    trial_http_checkpoint::{self, Capture, Prepared, StartState},
    trial_http_av_record, trial_http_restore,
    trial_run_id::TrialRunId,
};

/// Inputs for a separate encrypted post-change observation checkpoint.
/// These are caller claims, not device identity or authority to dispatch.
pub struct ObservationCheckpoint<'a> {
    pub peer: Ipv4Addr,
    pub start: &'a fss_reference::unifi_direct::StreamStart,
    pub root: &'a Path,
    pub certificate: ContentDigest,
}

struct Access(ContentDigest);
impl archive::RetainAuthority for Access {
    fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
        retention == self.0
    }
}
impl archive::ReadAuthority for Access {
    fn permits(&self, retention: ContentDigest, _: ContentDigest) -> bool {
        retention == self.0
    }
}

// Inspect only the bytes already retained by the failed framer. A structural
// candidate is not an authenticated boundary and does not resume the stream.
fn report_trailer_failure(retirement: &fss_reference::unifi_direct::pipeline::Retirement) {
    use fss_packet::extended_flv::{self, Parse, stream::Phase};
    let remainder = &retirement.ingress.framing;
    let suffix_pending = retirement.ingress.buffered.as_ref()
        .is_some_and(|chunk| chunk.appended < chunk.source.bytes().len());
    if remainder.phase != Phase::Successor {
        println!("trial_http_framing_diagnostic=wrong_phase pending_suffix={suffix_pending} boundary=unverified");
        return;
    }
    match extended_flv::find_next_zero_stream_id(remainder.bytes(), FlvLimits::default()) {
        Ok(Parse::Complete(candidate)) => println!(
            "trial_http_framing_diagnostic=zero_id_candidate trailer_bytes={} pending_suffix={suffix_pending} boundary=unverified",
            candidate.trailer.len()),
        Ok(Parse::NeedMore) => println!("trial_http_framing_diagnostic=need_more pending_suffix={suffix_pending} boundary=unverified"),
        Err(_) => println!("trial_http_framing_diagnostic=zero_id_refused pending_suffix={suffix_pending} boundary=unverified"),
    }
}

// An error may carry the exact source, driver and checkpoint owners until the
// caller reports and retires the trial. Its display never reveals media data.
struct Stopped {
    reason: &'static str,
    _custody: Box<dyn Any>,
}
impl fmt::Debug for Stopped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HttpRecordingStopped")
            .field(&self.reason)
            .finish()
    }
}
impl fmt::Display for Stopped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason)
    }
}
impl Error for Stopped {}
pub(super) fn stopped(reason: &'static str, custody: impl Any) -> Box<dyn Error> {
    Box::new(Stopped {
        reason,
        _custody: Box::new(custody),
    })
}

fn event_reason(event: &Step) -> &'static str {
    match event {
        Step::SourceCompleted(_) => "source publication requires reconciliation",
        Step::VideoCompleted(_) => "video runtime requires reconciliation",
        Step::SourceRefused(_) => "source offer refused",
        Step::VideoRefused(_) => "video offer refused",
        Step::ConfigurationCopyRefused(_) | Step::ConfigurationRefused(_) => {
            "video configuration refused"
        }
        Step::ConfigurationChanged(_) => "video configuration changed",
        Step::SegmentBeforeConfiguration(_) => "video segment preceded configuration",
        Step::WorkerRefused(_) | Step::RecoveredWorkerRefused { .. } => "video worker refused",
        Step::StartRefused(_) => "archive worker start refused",
        Step::SourceRetryRequired | Step::VideoRetryRequired => {
            "archive retry requires authorization"
        }
        Step::ArchiveUnavailable => "archive custody unavailable",
        Step::Media(fss_reference::unifi_direct::pipeline::Step::Eof) => "camera stream ended",
        Step::Media(fss_reference::unifi_direct::pipeline::Step::LimitReached) => {
            "camera stream limit reached"
        }
        Step::MediaError(_) => "camera media failed",
        Step::Configuration => "recording context refused",
        Step::Halted => "recording halted",
        _ => "unexpected recording event",
    }
}

/// Journal and dispatch one explicitly authorized start and archive a bounded
/// number of video fragments. The effect remains indeterminate until independent
/// reconciliation; this is not a reconnecting or continuous service.
pub async fn run<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    http: &mut camera_http::Owner<'_, '_, '_, IO>,
    mut listener: listener::Listener<'_, '_, '_>,
    checkpoint: Prepared,
    conditions: Preconditions,
    authority: &dyn SerializerAuthority,
    leases: &RefCell<LeaseRegistry>,
    effects: &mut EffectCoordinator,
    run_id: &TrialRunId,
    root: &Path,
    resource: &str,
    effect_attempted: &Cell<bool>,
    framing: SearchMode,
    inband: bool,
    dimensions: [u32; 2],
    segments: usize,
    restore_after: bool,
    name_probe: bool,
    observation: ObservationCheckpoint<'_>,
    authorize: impl Fn(Ipv4Addr, u64) -> bool,
) -> Result<(), Box<dyn Error>> {
    if !(1..=8).contains(&segments) {
        return Err("HTTP recording segment limit must be 1 to 8".into());
    }
    let parent = root.parent().ok_or("archive parent missing")?;
    let replay_authority = fss_core::region::ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:http-owned-storage".into(),
        operation_id: OperationId::parse("operation:http-owned-storage")?,
        principal: "principal:owner".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 1,
        budgets: BudgetVector::builder().bytes(256 * 1024 * 1024).build()?,
        privacy_scope: "privacy:owner".into(),
        retention_scope: "retention:trial".into(),
        anchor_universe: conditions.camera,
        generation: 1,
    })?;
    let retention = ContentDigest::sha256(b"unifi-http-record-trial-retention");
    let source = SourceKey {
        connection: 1,
        generation: 1,
    };
    let cfg = recording_storage::Configuration {
        root,
        site_lineage: "site:http-record-trial",
        source,
        camera_claim: conditions.camera,
        source_retention: retention,
        source_scope: ContentDigest::sha256(b"http-trial-source"),
        av_scope: ContentDigest::sha256(b"http-trial-video"),
        source_deployment_limits: DeploymentLimits::standard(),
        av_deployment_limits: DeploymentLimits::standard(),
        source_history_limits: EffectJournalLimits::default(),
        av_history_limits: EffectJournalLimits::default(),
        limits: archive::Limits::default(),
        max_source_bytes: 16 * 1024 * 1024,
        work_limit: 4_000_000_000,
    };
    let storage = recording_storage::create(
        task,
        cx,
        clock,
        cfg,
        ReplayCx::from_context_authority(&replay_authority, parent.to_path_buf())?,
        ReplayCx::from_context_authority(&replay_authority, parent.to_path_buf())?,
        Arc::new(Access(retention)),
    )?;
    let mut recorder = if inband {
        recording::Recorder::new_inband(source, recording::Limits::default())?
    } else {
        recording::Recorder::new(source, recording::Limits::default())?
    };
    recorder.require_dimensions(dimensions)?;
    let capture = Capture {
        framer: Framer::with_mode(FlvLimits::default(), 8 * 1024 * 1024, framing)?,
        recorder,
        storage,
        policy: video_bootstrap::Policy {
            inband,
            retention,
            media_limits: Mp4Limits::default(),
            evidence_limits: evidence::Limits::default(),
        },
        wait: Duration::from_secs(10),
        chunk_bytes: 4096,
        max_bytes: 64 * 1024 * 1024,
    };
    let probe = if name_probe {
        Some(fss_packet::extended_flv::stream::NameProbeOwner::new(
            "onMetaData", &run_id.as_str()[..16], 256 * 1024, 4, 4_000_000,
        )?)
    } else { None };
    let operation = run_id.operation("http-start")?;
    effect_attempted.set(true);
    let prepared = task.prepare_effect(
        cx,
        effects,
        &mut leases.borrow_mut(),
        PrepareSpec {
            operation: &operation,
            idempotency_key: IdempotencyKey::parse(operation.as_str())?,
            request_digest: checkpoint.plan.request_digest(),
            precondition_digest: checkpoint.plan.precondition_digest(),
            resource,
            fence: conditions.lease_fence,
            prepare_grant: RuntimeGrant::CameraSettingPrepare,
            commit_grant: RuntimeGrant::CameraSettingCommit,
            terminal_predicate: "independent serializer observation or reconciliation",
        },
        clock.now()?,
    )?;
    let approval = CommitApproval {
        prepared_digest: prepared.digest(),
        current_precondition_digest: checkpoint.plan.precondition_digest(),
    };
    let permit = task
        .commit_effect(
            cx,
            effects,
            &mut leases.borrow_mut(),
            prepared,
            clock.now()?,
            approval,
        )
        .map_err(|_| "HTTP effect commit refused; inspect journal")?;
    let started = trial_http_checkpoint::start(
        task,
        cx,
        clock,
        http,
        &mut listener,
        checkpoint,
        conditions,
        authority,
        capture,
        permit,
        effects,
        resource,
        &authorize,
    )
    .await;
    let checkpoint = started.checkpoint;
    let mut driver = match started.state {
        StartState::Started(driver) => driver,
        state => {
            let eligible = match &state {
                StartState::Media { refusal, .. } => trial_http_restore::eligible_start_failure(&refusal.failure, refusal.may_have_written, refusal.readback.is_some()),
                _ => false,
            };
            if restore_after && eligible {
                let recovery = trial_http_restore::after_observed_failure(cx, task, clock, http, &checkpoint, conditions, authority, leases, effects, run_id, resource, &observation, &authorize).await;
                if recovery.is_ok() {
                    println!("trial_http_failure_restore=readback_matches restored_checkpoint=anchored recording=failed effects=reconciliation_required");
                } else {
                    eprintln!("trial_http_failure_restore=requires_reconciliation recording=failed");
                }
                return Err(stopped("HTTP stream start refused; reconcile effect", (checkpoint, state, recovery)));
            }
            return Err(stopped(
                "HTTP stream start refused; reconcile effect",
                (checkpoint, state),
            ));
        }
    };
    let _name_probe = if let Some(probe) = probe {
        use fss_reference::unifi_direct::ingress::NameProbeStep;
        let mut matched = None;
        let mut initial_refusal = None;
        let mut refusal_reason = "step_limit";
        if let Err(probe) = driver.begin_name_probe(probe) { initial_refusal = Some(probe); }
        if initial_refusal.is_some() { refusal_reason = "owner_state"; }
        if initial_refusal.is_none() {
            let deadline = cx.now() + Duration::from_secs(10);
            for _ in 0..128 {
                let now = match clock.now() { Ok(now) => now, Err(_) => { refusal_reason = "clock"; break; } };
                match asupersync::time::timeout_at(deadline, driver.probe_name_step(task, cx, now)).await {
                    Ok(Ok(NameProbeStep::Progress { .. })) => (),
                    Ok(Ok(NameProbeStep::Matched { tag_index })) => { matched = Some(tag_index); break; },
                    Ok(Ok(NameProbeStep::Mismatched { .. })) => { refusal_reason = "name_mismatch"; break; },
                    Ok(Ok(NameProbeStep::LimitReached { .. })) => { refusal_reason = "prefix_limit"; break; },
                    Ok(Ok(NameProbeStep::Empty)) => { refusal_reason = "empty"; break; },
                    Ok(Ok(NameProbeStep::Incomplete)) => { refusal_reason = "incomplete"; break; },
                    Ok(Err(error)) => { refusal_reason = trial_http_restore::name_probe_error_label(&error); break; },
                    Err(_) => { refusal_reason = "timeout"; break; },
                }
            }
        }
        let probe = initial_refusal.or_else(|| driver.take_name_probe());
        if let Some(tag_index) = matched {
            println!("trial_http_name_probe=matched tag_index={tag_index} camera_identity=unverified source_boundary=claim");
            probe
        } else {
            eprintln!("trial_http_name_probe_reason={refusal_reason} camera_identity=unverified effect=reconciliation_required");
            driver.abort();
            let source = driver.join_source().await;
            let video = driver.join_video().await;
            let parts = match driver.into_parts() {
                Ok(parts) => parts,
                Err(driver) => return Err(stopped("HTTP name probe worker did not drain", (checkpoint, driver, probe, source, video))),
            };
            let recovery = trial_http_restore::after_observed_failure(cx, task, clock, http, &checkpoint, conditions, authority, leases, effects, run_id, resource, &observation, &authorize).await;
            if recovery.is_ok() {
                println!("trial_http_name_probe=refused restoration=readback_matches effect=reconciliation_required");
            } else {
                eprintln!("trial_http_name_probe=refused restoration=requires_reconciliation");
            }
            return Err(stopped("HTTP name probe did not match; reconcile effect", (checkpoint, parts, probe, source, video, recovery)));
        }
    } else { None };
    let cost = BudgetVector::ZERO;
    let admission = ArchiveAdmission {
        resource,
        cost: &cost,
    };
    let mut published = Vec::with_capacity(segments);
    for _ in 0..4096 {
        let event = driver
            .step(
                task,
                cx,
                clock,
                Duration::from_secs(1),
                admission,
                admission,
            )
            .await;
        match event {
            Step::SourceCompleted(done)
                if done.runtime.is_ok()
                    && matches!(
                        done.outcome,
                        source_worker::Outcome::Publication(
                            source_worker::Publication::Published { .. }
                        )
                    ) =>
            {
                ()
            }
            Step::VideoCompleted(done) if done.runtime.is_ok() => match done.outcome {
                video_worker::Outcome::Publication(video_worker::Publication::Published(value)) => {
                    published.push(value);
                    if published.len() == segments {
                        break;
                    }
                }
                outcome => {
                    driver.abort();
                    let source = driver.join_source().await;
                    let video = driver.join_video().await;
                    return Err(stopped(
                        "video publication requires reconciliation",
                        (checkpoint, driver, published, outcome, source, video),
                    ));
                }
            },
            Step::SourceOffered(_)
            | Step::Configured
            | Step::VideoOffered
            | Step::SourceStarted
            | Step::VideoStarted
            | Step::SourceRunning
            | Step::VideoRunning
            | Step::Idle
            | Step::Media(fss_reference::unifi_direct::pipeline::Step::Progress { .. })
            | Step::Media(fss_reference::unifi_direct::pipeline::Step::Recording(
                recording::Push::Buffered,
            )) => (),
            event => {
                if let Step::MediaError(error) = &event {
                    use fss_reference::unifi_direct::{ingress, pipeline};
                    match error {
                        pipeline::Error::Recording(refusal) => {
                            eprintln!("trial_http_record_media_refusal=recording:{:?}", refusal.reason);
                        }
                        pipeline::Error::Ingress(ingress::Error::Framing(reason)) => {
                            eprintln!("trial_http_record_media_refusal=framing:{reason:?}");
                        }
                        pipeline::Error::Ingress(_) => eprintln!("trial_http_record_media_refusal=ingress"),
                        pipeline::Error::Stopped => eprintln!("trial_http_record_media_refusal=stopped"),
                        pipeline::Error::AudioPending => eprintln!("trial_http_record_media_refusal=audio_pending"),
                        pipeline::Error::Cancelled => eprintln!("trial_http_record_media_refusal=cancelled"),
                    }
                }
                let reason = event_reason(&event);
                driver.abort();
                let source = driver.join_source().await;
                let video = driver.join_video().await;
                let eligible = match &event {
                    Step::Media(fss_reference::unifi_direct::pipeline::Step::Eof | fss_reference::unifi_direct::pipeline::Step::LimitReached) => true,
                    Step::MediaError(error) => trial_http_restore::eligible_media_error(error),
                    _ => false,
                };
                let trailer_mismatch = matches!(&event, Step::MediaError(fss_reference::unifi_direct::pipeline::Error::Ingress(
                    fss_reference::unifi_direct::ingress::Error::Framing(
                        fss_packet::extended_flv::stream::Error::TrailerPolicyMismatch))));
                if (restore_after && eligible) || trailer_mismatch {
                    let parts = match driver.into_parts() {
                        Ok(parts) => parts,
                        Err(driver) => return Err(stopped("HTTP failure workers did not drain", (checkpoint, driver, published, event, source, video))),
                    };
                    let recovery = if restore_after && eligible {
                        let outcome = trial_http_restore::after_observed_failure(cx, task, clock, http, &checkpoint, conditions, authority, leases, effects, run_id, resource, &observation, &authorize).await;
                        if outcome.is_ok() {
                            println!("trial_http_failure_restore=readback_matches restored_checkpoint=anchored recording=failed effects=reconciliation_required");
                        } else {
                            eprintln!("trial_http_failure_restore=requires_reconciliation recording=failed");
                        }
                        Some(outcome)
                    } else { None };
                    if trailer_mismatch {
                        let media_archive::Parts { connected, source: source_owner, resources, video: video_owner,
                            key, camera_claim: owner_claim, policy, source_armed, video_armed, halted } = parts;
                        let fss_reference::unifi_direct::http_stream::media::Detached {
                            camera_claim, permit, readback, comparison, pipeline,
                        } = connected.into_parts();
                        let retirement = pipeline.retire();
                        report_trailer_failure(&retirement);
                        if camera_claim != owner_claim {
                            return Err(stopped("video failure source camera claim changed", (checkpoint, camera_claim,
                                permit, readback, comparison, retirement, source_owner, resources, video_owner,
                                key, owner_claim, policy, source_armed, video_armed, halted, published, event,
                                source, video, recovery)));
                        }
                        let tail = Box::pin(trial_http_av_record::archive_final_tail(retirement, source_owner,
                            key, camera_claim, retention, task, cx, clock, admission)).await;
                        match &tail {
                            Ok(tail) => println!("trial_http_video_failure_tail=verified records={} capture_time=unknown coverage=unproven", tail.records),
                            Err(_) => eprintln!("trial_http_video_failure_tail=requires_reconciliation"),
                        }
                        return Err(stopped(reason, (checkpoint, camera_claim, permit, readback, comparison, tail,
                            resources, video_owner, key, owner_claim, policy, source_armed, video_armed,
                            halted, published, event, source, video, recovery)));
                    }
                    return Err(stopped(reason, (checkpoint, parts, published, event, source, video, recovery)));
                }
                return Err(stopped(
                    reason,
                    (checkpoint, driver, published, event, source, video),
                ));
            }
        }
    }
    if published.len() != segments {
        driver.abort();
        let source = driver.join_source().await;
        let video = driver.join_video().await;
        return Err(stopped(
            "HTTP recording step limit reached",
            (checkpoint, driver, published, source, video),
        ));
    }
    driver.abort();
    let source = driver.join_source().await;
    let video = driver.join_video().await;
    let parts = match driver.into_parts() {
        Ok(parts) => parts,
        Err(driver) => {
            return Err(stopped(
                "HTTP workers did not drain",
                (checkpoint, driver, published),
            ));
        }
    };
    let media_archive::Parts {
        connected,
        source: source_owner,
        resources,
        video: video_owner,
        ..
    } = parts;
    let video_owner = match video_owner {
        Some(owner) => owner,
        None => {
            return Err(stopped(
                "video worker missing",
                (
                    checkpoint,
                    published,
                    connected,
                    source_owner,
                    resources,
                    source,
                    video,
                ),
            ));
        }
    };
    let mut video_owner = match video_owner.retire() {
        Ok(owner) => owner,
        Err(owner) => {
            return Err(stopped(
                "video worker did not retire",
                (
                    checkpoint,
                    published,
                    connected,
                    source_owner,
                    resources,
                    owner,
                    source,
                    video,
                ),
            ));
        }
    };
    let decoded: Result<(u32, u32), Box<dyn Error>> = (|| {
        for publication in &published {
            let clip = archive::read_unknown_time_video_clip(
                &mut video_owner.parts.deployment,
                publication.pin,
                &Access(retention),
                archive::Limits::default(),
                &mut fss_geometry::WorkBudget::new(4_000_000_000),
                &video_owner.parts.replay,
            )?;
            let movie = if inband {
                AvcMp4::parse_inband(clip.bytes(), None, DemuxLimits::default())?
            } else {
                AvcMp4::parse(clip.bytes(), None, DemuxLimits::default())?
            };
            let annex = movie.annex_b(0, 1)?;
            let mut decoder = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits {
                max_pictures: 8,
                ..Default::default()
            })?;
            let mut pictures = decoder.decode_annex_b(annex.bytes())?;
            pictures.extend(decoder.finish()?);
            let picture = pictures
                .first()
                .ok_or("archive contained no decodable picture")?;
            if [picture.width(), picture.height()] != dimensions {
                return Err("archived picture dimensions differ from the selected profile".into());
            }
        }
        Ok((dimensions[0], dimensions[1]))
    })();
    let (width, height) = match decoded {
        Ok(dimensions) => dimensions,
        Err(error) => {
            return Err(stopped(
                "archived video readback failed",
                (
                    checkpoint,
                    published,
                    connected,
                    source_owner,
                    resources,
                    video_owner,
                    source,
                    video,
                    error,
                ),
            ));
        }
    };
    let detached = connected.into_parts();
    let reread = async {
        task.checkpoint_for(
            RuntimeGrant::ObserveStatus,
            resource,
            clock
                .now()
                .map_err(|_| "serializer observation clock unavailable")?,
            &BudgetVector::ZERO,
        )
        .map_err(|_| "serializer observation authority refused")?;
        http.settings_serializers(Duration::from_secs(10))
            .await
            .map(|(_, observed)| observed)
            .map_err(|_| "serializer observation unavailable")
    }
    .await;
    let reread = match reread {
        Ok(reread) => reread,
        Err(reason) => {
            return Err(stopped(
                reason,
                (
                    checkpoint,
                    published,
                    detached,
                    source_owner,
                    resources,
                    video_owner,
                    source,
                    video,
                ),
            ));
        }
    };
    let consistent = (|| {
        let original = detached.readback.binding(&authorize).ok()?;
        let current = reread.binding(&authorize).ok()?;
        let comparison = checkpoint
            .plan
            .observe_readback(&checkpoint.baseline, &reread, &authorize)
            .ok()?;
        Some(
            original == current
                && comparison.change
                    == fss_reference::unifi_direct::http_stream::ReadbackChange::TargetTrackOnly
                && comparison.requested_fields_match,
        )
    })();
    if consistent != Some(true) {
        return Err(stopped(
            "serializer observation changed after recording",
            (
                checkpoint,
                published,
                detached,
                reread,
                source_owner,
                resources,
                video_owner,
                source,
                video,
            ),
        ));
    }
    // Reuse the encrypted snapshot format with the observed values as its
    // baseline. This plan is only an input to checkpoint creation: it is not
    // dispatched, and the separately anchored snapshot does not settle an
    // effect or prove that the peer is the intended physical camera.
    let observation_plan = (|| {
        let binding = reread.binding(&authorize).ok()?;
        let observed_conditions = Preconditions {
            serializers: binding,
            ..conditions
        };
        let plan = fss_reference::unifi_direct::http_stream::Plan::new(
            observation.peer,
            observation.start,
            observed_conditions,
            &reread,
            handoff::Framing::ContentLength,
        )
        .ok()?;
        (plan.request_digest() == checkpoint.plan.request_digest()).then_some(plan)
    })();
    let observation_plan = match observation_plan {
        Some(plan) => plan,
        None => {
            return Err(stopped(
                "serializer observation checkpoint scope refused",
                (
                    checkpoint,
                    published,
                    detached,
                    reread,
                    source_owner,
                    resources,
                    video_owner,
                    source,
                    video,
                ),
            ));
        }
    };
    let observed_checkpoint = match trial_http_checkpoint::prepare(
        task,
        cx,
        clock,
        observation.root.join("observation"),
        observation_plan,
        reread,
        observation.certificate,
    )
    .await
    {
        Ok(checkpoint) => checkpoint,
        Err(reason) => {
            return Err(stopped(
                "serializer observation checkpoint requires inspection",
                (
                    checkpoint,
                    published,
                    detached,
                    source_owner,
                    resources,
                    video_owner,
                    source,
                    video,
                    reason,
                ),
            ));
        }
    };
    let restoration = if restore_after {
        match trial_http_restore::run(cx, task, clock, http, &checkpoint, conditions, authority, leases, effects, run_id, resource, &authorize).await {
            Ok(outcome) => match trial_http_restore::anchor(cx, task, clock, &checkpoint, conditions, &observation, outcome, &authorize).await {
                Ok(anchored) => Some(anchored),
                Err(error) => return Err(stopped("HTTP restoration checkpoint requires inspection", (checkpoint, observed_checkpoint, detached, published, source_owner, resources, video_owner, source, video, error))),
            },
            Err(error) => return Err(stopped("HTTP restoration requires reconciliation", (checkpoint, observed_checkpoint, detached, published, source_owner, resources, video_owner, source, video, error))),
        }
    } else { None };
    if restoration.is_some() {
        println!("trial_http_restore=readback_matches restored_checkpoint=anchored camera_identity=unverified effects=reconciliation_required");
    }
    let fss_reference::unifi_direct::http_stream::media::Detached {
        camera_claim,
        permit,
        readback,
        comparison,
        pipeline,
    } = detached;
    let retirement = pipeline.retire();
    let unclosed = retirement
        .recorder
        .pending
        .iter()
        .map(|record| record.bytes().len())
        .sum::<usize>();
    let unframed = retirement
        .ingress
        .framing
        .bytes()
        .len()
        .saturating_add(retirement.ingress.buffered.as_ref().map_or(0, |value| {
            value.source.bytes().len().saturating_sub(value.appended)
        }))
        .saturating_add(
            retirement
                .ingress
                .source
                .pending
                .as_ref()
                .map_or(0, |value| value.bytes().len()),
        );
    println!(
        "trial_http_record=published decoded_width={} decoded_height={} fragments={} source_unclosed_bytes={} source_unframed_bytes={} audio=false continuous=false readbacks=consistent observation_checkpoint=anchored effect=reconciliation_required",
        width,
        height,
        published.len(),
        unclosed,
        unframed
    );
    let _custody = (
        published,
        checkpoint,
        video_owner,
        source_owner,
        resources,
        source,
        video,
        retirement,
        camera_claim,
        permit,
        readback,
        comparison,
        observed_checkpoint,
        restoration,
    );
    Ok(())
}
