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
        camera_http, evidence,
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
    trial_run_id::TrialRunId,
};

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
fn stopped(reason: &'static str, custody: impl Any) -> Box<dyn Error> {
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

/// Journal and dispatch one explicitly authorized start and archive one video
/// fragment. The effect remains indeterminate until independent reconciliation.
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
    authorize: impl Fn(Ipv4Addr, u64) -> bool,
) -> Result<(), Box<dyn Error>> {
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
        authorize,
    )
    .await;
    let mut driver = match started.state {
        StartState::Started(driver) => driver,
        state => {
            return Err(stopped(
                "HTTP stream start refused; reconcile effect",
                (started.checkpoint, state),
            ));
        }
    };
    let checkpoint = started.checkpoint;
    let cost = BudgetVector::ZERO;
    let admission = ArchiveAdmission {
        resource,
        cost: &cost,
    };
    let mut published = None;
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
                    published = Some(value);
                    break;
                }
                outcome => {
                    driver.abort();
                    let source = driver.join_source().await;
                    let video = driver.join_video().await;
                    return Err(stopped(
                        "video publication requires reconciliation",
                        (checkpoint, driver, outcome, source, video),
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
                let reason = event_reason(&event);
                driver.abort();
                let source = driver.join_source().await;
                let video = driver.join_video().await;
                return Err(stopped(reason, (checkpoint, driver, event, source, video)));
            }
        }
    }
    let published = match published {
        Some(value) => value,
        None => {
            driver.abort();
            let source = driver.join_source().await;
            let video = driver.join_video().await;
            return Err(stopped(
                "HTTP recording step limit reached",
                (checkpoint, driver, source, video),
            ));
        }
    };
    driver.abort();
    let source = driver.join_source().await;
    let video = driver.join_video().await;
    let parts = match driver.into_parts() {
        Ok(parts) => parts,
        Err(driver) => return Err(stopped("HTTP workers did not drain", (checkpoint, driver))),
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
        let clip = archive::read_unknown_time_video_clip(
            &mut video_owner.parts.deployment,
            published.pin,
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
        Ok((picture.width(), picture.height()))
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
    let retirement = connected.into_parts().pipeline.retire();
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
        "trial_http_record=published decoded_width={} decoded_height={} source_unclosed_bytes={} source_unframed_bytes={} audio=false continuous=false effect=reconciliation_required",
        width, height, unclosed, unframed
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
    );
    Ok(())
}
