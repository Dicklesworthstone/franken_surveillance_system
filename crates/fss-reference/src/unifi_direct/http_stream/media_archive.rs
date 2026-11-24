#![forbid(unsafe_code)]
//! Video-only archive driver for an HTTP-started media stream.
//!
//! This joins the existing source and video archive workers to the same native
//! pipeline returned by `media::start`, without inventing a controller session.
//! It does not authenticate the sender, settle the start effect, reconnect,
//! establish capture time, record audio, or enforce a retention duration.

use std::time::Duration;

use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
    time::timeout_at,
};
use fss_container::flv_avc::SourceKey;
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_packet::extended_flv::stream::SourceRecord;
use fss_runtime::{effect::CommittedEffect, execution::TaskCx};

use super::media;
use crate::unifi_direct::{
    av_unknown_worker_guard::BootstrapResources, av_worker, camera_http, listener,
    metered::MeteredClock, pipeline, recording, recording_storage,
    source_coordinator::ArchiveAdmission, source_worker, video_bootstrap, video_owned_sink,
    video_worker,
};

/// All owners retained by the driver, including the unsettled camera effect.
#[must_use = "drain workers and reconcile the retained camera effect"]
pub struct Parts {
    /// The media pipeline, retained readback and committed start effect.
    pub connected: media::Connected,
    /// Original records not included in a completed video segment.
    pub source: source_worker::Worker,
    /// Archive resources before the stream configuration is received.
    pub resources: Option<Box<BootstrapResources>>,
    /// Video worker after configuration is received.
    pub video: Option<video_worker::Worker>,
    /// Caller-bound connection and generation, not authenticated identity.
    pub key: SourceKey,
    /// Caller-bound camera claim.
    pub camera_claim: ContentDigest,
    /// Explicit retention and media policy.
    pub policy: video_bootstrap::Policy,
    /// A first or explicitly reauthorized source attempt is armed.
    pub source_armed: bool,
    /// A first or explicitly reauthorized video attempt is armed.
    pub video_armed: bool,
    /// Admission has stopped; retained owners require accounting.
    pub halted: bool,
}

/// A complete bounded decision or ownership-preserving refusal.
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum Step {
    /// A source was transferred to the archive worker.
    SourceOffered(recording::SourceDisposition),
    /// The initial AVC configuration was retained and its copy offered.
    Configured,
    /// A source was refused unchanged and the driver stopped.
    SourceRefused(source_worker::OfferRefusal),
    /// Configuration duplication failed; the original is returned.
    ConfigurationCopyRefused(SourceRecord),
    /// Configuration construction failed; the original is returned.
    ConfigurationRefused(video_owned_sink::ConstructionRefusal),
    /// A second configuration needs an explicit new archive generation.
    ConfigurationChanged(SourceRecord),
    /// A video segment arrived before a video worker was configured.
    SegmentBeforeConfiguration(recording::Segment),
    /// New video archive worker construction failed with its inputs intact.
    WorkerRefused(video_worker::Parts),
    /// Recovered video worker construction failed with its inputs intact.
    RecoveredWorkerRefused {
        /// Original video worker inputs.
        parts: video_worker::Parts,
        /// Retained rollover history.
        custody: crate::unifi_direct::archive::journal::rollover::WorkerCustody,
    },
    /// A video segment was transferred to the archive worker.
    VideoOffered,
    /// A segment was refused unchanged and the driver stopped.
    VideoRefused(video_worker::OfferRefusal),
    /// A source archive attempt was started.
    SourceStarted,
    /// A video archive attempt was started.
    VideoStarted,
    /// Starting an archive attempt failed; no automatic retry is authorized.
    StartRefused(av_worker::StartError),
    /// A source archive attempt is still running after the bounded wait.
    SourceRunning,
    /// A video archive attempt is still running after the bounded wait.
    VideoRunning,
    /// A source attempt has drained; the caller owns its complete result.
    SourceCompleted(source_worker::Completion),
    /// A video attempt has drained; the caller owns its complete result.
    VideoCompleted(video_worker::Completion),
    /// A pending source needs explicit retry authorization.
    SourceRetryRequired,
    /// A pending video segment needs explicit retry authorization.
    VideoRetryRequired,
    /// Source or video custody cannot currently be inspected.
    ArchiveUnavailable,
    /// A media result not transferred to an archive worker.
    Media(pipeline::Step),
    /// The media pipeline refused; its remaining state is retained.
    MediaError(pipeline::Error),
    /// No media result arrived before the bounded wait.
    Idle,
    /// Invalid wait or runtime/clock context; no work was started.
    Configuration,
    /// Cancellation or an earlier refusal stopped further admission.
    Halted,
}

/// Receives each nonterminal result before any further recording work starts.
/// In particular, the observer must inspect archive completions and decide
/// whether it is appropriate to continue; publication is not implied by a
/// completed worker. A refused event is returned intact to the caller.
pub trait Observer {
    /// Accept the complete result and choose whether this slice continues.
    fn observe(
        &mut self,
        event: Box<Step>,
    ) -> Result<super::super::source_coordinator::Decision, Box<Step>>;
}

/// Bounds and archive authority for one recorder slice.
#[derive(Clone, Copy)]
pub struct SliceConfig<'a> {
    /// Maximum wait per media or archive decision.
    pub wait: Duration,
    /// Maximum number of decisions before yielding.
    pub max_steps: usize,
    /// Resource and cost for source archival work.
    pub source_archive: ArchiveAdmission<'a>,
    /// Resource and cost for video archival work.
    pub video_archive: ArchiveAdmission<'a>,
}

/// The bounded recorder stopped with its driver and outstanding work retained.
#[must_use = "account for any returned event and drain or resume the same driver"]
pub enum SliceStop {
    /// Invalid bounds; no work was polled.
    Configuration,
    /// The step budget was exhausted.
    Yielded,
    /// The observer accepted an event and requested a resumable yield.
    ObserverYielded,
    /// The observer accepted an event and requested a stop.
    ObserverStopped,
    /// The observer returned an event intact.
    ObserverRefused(Box<Step>),
    /// Recording requires caller action or has reached a terminal event.
    Halted(Box<Step>),
}

fn requires_caller(event: &Step) -> bool {
    matches!(
        event,
        Step::SourceRefused(_)
            | Step::ConfigurationCopyRefused(_)
            | Step::ConfigurationRefused(_)
            | Step::ConfigurationChanged(_)
            | Step::SegmentBeforeConfiguration(_)
            | Step::WorkerRefused(_)
            | Step::RecoveredWorkerRefused { .. }
            | Step::VideoRefused(_)
            | Step::StartRefused(_)
            | Step::SourceRetryRequired
            | Step::VideoRetryRequired
            | Step::ArchiveUnavailable
            | Step::Media(pipeline::Step::Eof | pipeline::Step::LimitReached)
            | Step::MediaError(_)
            | Step::Configuration
            | Step::Halted
    )
}

/// One bounded owner for a native media pipeline and its archive workers.
#[must_use = "abort and join workers before recovering all owners"]
pub struct Driver {
    parts: Parts,
}

/// Attachment refusal returns the original stream and storage unchanged.
#[must_use]
pub struct AttachRefusal {
    /// Original HTTP-started stream and start effect.
    pub connected: media::Connected,
    /// Unconsumed archive owners.
    pub storage: recording_storage::Created,
    /// Caller-supplied video policy.
    pub policy: video_bootstrap::Policy,
    /// Caller-supplied camera claim.
    pub camera_claim: ContentDigest,
}

/// Owners needed to start one HTTP-directed video archive.
pub struct Start<'a> {
    /// Exact camera setting and media-listener request.
    pub request: media::Request<'a>,
    /// Fresh source and video archive owners.
    pub storage: recording_storage::Created,
    /// Video archive configuration and retention decision.
    pub policy: video_bootstrap::Policy,
}

/// Payload-free reason an archive cannot start before a camera write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartPreflight {
    /// Runtime, task, clock, listener, source or archive bindings do not match.
    Binding,
    /// The runtime has no blocking pool for archive work.
    MissingBlockingPool,
    /// Retention or media bounds are invalid.
    Policy,
    /// Runtime cancellation was observed before any camera write.
    Cancelled,
}

/// Every stopped start returns its remaining effect and archive owners.
#[must_use = "retain or reconcile every returned owner and camera effect"]
#[allow(clippy::large_enum_variant)]
pub enum StartRefusal<'a> {
    /// No request was sent; all original start inputs are returned.
    Preflight {
        /// Payload-free reason for refusal.
        reason: StartPreflight,
        /// Unconsumed request, storage and video policy.
        inputs: Box<Start<'a>>,
        /// Original unclaimed effect permit.
        permit: CommittedEffect,
    },
    /// The media startup stopped; its effect may require reconciliation.
    Media {
        /// Exact media refusal and retained effect permit.
        refusal: media::Refusal,
        /// Unconsumed archive storage.
        storage: recording_storage::Created,
        /// Original video policy.
        policy: video_bootstrap::Policy,
    },
    /// Media connected, but archive attachment refused all original owners.
    Attach(AttachRefusal),
}

/// Check archive prerequisites, start the camera stream, then attach storage.
/// No blocking pool, mismatched binding, invalid policy, or cancellation can
/// trigger a camera request. A dropped in-flight write can still leave an
/// indeterminate effect in the durable journal; reconcile before any retry.
#[allow(clippy::result_large_err, clippy::too_many_arguments)]
pub async fn start<'a, 'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    http: &mut camera_http::Owner<'_, '_, '_, IO>,
    listener: &mut listener::Listener<'_, '_, '_>,
    inputs: Start<'a>,
    permit: CommittedEffect,
    authorize_observation: impl Fn(std::net::Ipv4Addr, u64) -> bool,
) -> Result<Driver, StartRefusal<'a>> {
    start_with_response(
        task,
        cx,
        clock,
        http,
        listener,
        inputs,
        permit,
        authorize_observation,
        &mut |_, _| Ok(()),
    )
    .await
}

/// Start with caller-owned custody of the camera's untrusted HTTP response.
/// A custody failure retains the permit and never authorizes a retry.
#[allow(clippy::result_large_err, clippy::too_many_arguments)]
pub async fn start_with_response<'a, 'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    http: &mut camera_http::Owner<'_, '_, '_, IO>,
    listener: &mut listener::Listener<'_, '_, '_>,
    inputs: Start<'a>,
    permit: CommittedEffect,
    authorize_observation: impl Fn(std::net::Ipv4Addr, u64) -> bool,
    record_response: &mut media::ResponseRecorder<'_>,
) -> Result<Driver, StartRefusal<'a>> {
    let key = inputs.request.recorder.source_key();
    let camera = inputs.request.current.camera;
    let retention = inputs.policy.retention;
    let reason = if cx.checkpoint().is_err() {
        Some(StartPreflight::Cancelled)
    } else if !cx.has_timer()
        || !clock.matches(task, cx)
        || !http.matches_media_listener(listener)
        || !listener.matches_camera_binding(&clock, &inputs.request.plan.resource())
        || inputs.request.plan.operation() != super::Operation::Start
        || inputs.request.current.listener != listener.local_addr()
        || !listener::valid_accept_config(
            inputs.request.chunk_bytes,
            inputs.request.max_bytes,
            inputs.request.wait,
        )
        || key.connection == 0
        || key.generation == 0
        || inputs.request.recorder.inband_mode() != inputs.policy.inband
        || !inputs.storage.coordinator.matches_binding(key, camera)
        || inputs.storage.coordinator.source_status() != source_worker::Status::Idle
        || !(1..=100_000_000_000).contains(&inputs.storage.av.work_limit)
    {
        Some(StartPreflight::Binding)
    } else if retention.algorithm() != DigestAlgorithm::Sha256
        || retention.is_laboratory()
        || retention.bytes() == [0; 32]
        || inputs.policy.media_limits.validate().is_err()
        || inputs.policy.evidence_limits.validate().is_err()
    {
        Some(StartPreflight::Policy)
    } else if cx.blocking_pool_handle().is_none() {
        Some(StartPreflight::MissingBlockingPool)
    } else {
        None
    };
    if let Some(reason) = reason {
        return Err(StartRefusal::Preflight {
            reason,
            inputs: Box::new(inputs),
            permit,
        });
    }
    let Start {
        request,
        storage,
        policy,
    } = inputs;
    let connected = match media::start_with_response(
        http,
        listener,
        request,
        permit,
        authorize_observation,
        record_response,
    )
    .await
    {
        Ok(connected) => connected,
        Err(refusal) => {
            return Err(StartRefusal::Media {
                refusal,
                storage,
                policy,
            });
        }
    };
    Driver::attach(connected, storage, policy, camera).map_err(StartRefusal::Attach)
}

impl Driver {
    /// Install a bounded metadata-name probe before any recording work. A
    /// matching name is a connection claim, not authenticated peer identity.
    pub fn begin_name_probe(
        &mut self,
        probe: fss_packet::extended_flv::stream::NameProbeOwner,
    ) -> Result<(), fss_packet::extended_flv::stream::NameProbeOwner> {
        if self.parts.halted
            || self.parts.source_armed
            || self.parts.video_armed
            || self.parts.source.status() != source_worker::Status::Idle
            || self.parts.video.is_some()
        {
            return Err(probe);
        }
        self.parts.connected.begin_name_probe(probe)
    }

    /// Advance the installed non-consuming probe under the caller's task.
    /// Dropping a pending call retains its prefix and cumulative work budget.
    pub async fn probe_name_step(
        &mut self,
        task: &TaskCx<'_>,
        cx: &Cx,
        now: fss_core::TimestampNs,
    ) -> Result<crate::unifi_direct::ingress::NameProbeStep, pipeline::NameProbeError> {
        if self.parts.halted {
            return Err(pipeline::NameProbeError::NotFresh);
        }
        self.parts.connected.probe_name_step(task, cx, now).await
    }

    /// Transfer the probe and its remaining work; source bytes remain retained.
    pub fn take_name_probe(&mut self) -> Option<fss_packet::extended_flv::stream::NameProbeOwner> {
        self.parts.connected.take_name_probe()
    }

    /// Drive a bounded number of media and archive decisions in the owning
    /// task. Every nonterminal event is handed to the observer before another
    /// step. This is not a reconnect loop, retention policy, or service.
    /// Stopping does not drain workers or authorize retry: callers must keep
    /// the driver, account for returned events, and resume or explicitly join.
    pub async fn run_slice<'scope, 'task>(
        &mut self,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        config: SliceConfig<'_>,
        observer: &mut dyn Observer,
    ) -> SliceStop {
        if config.wait.is_zero()
            || config.wait > Duration::from_secs(30)
            || !(1..=65_536).contains(&config.max_steps)
        {
            return SliceStop::Configuration;
        }
        for _ in 0..config.max_steps {
            let event = Box::new(
                self.step(
                    task,
                    cx,
                    clock,
                    config.wait,
                    config.source_archive,
                    config.video_archive,
                )
                .await,
            );
            if requires_caller(&event) {
                return SliceStop::Halted(event);
            }
            match observer.observe(event) {
                Ok(super::super::source_coordinator::Decision::Continue) => (),
                Ok(super::super::source_coordinator::Decision::Yield) => {
                    return SliceStop::ObserverYielded;
                }
                Ok(super::super::source_coordinator::Decision::Stop) => {
                    return SliceStop::ObserverStopped;
                }
                Err(event) => return SliceStop::ObserverRefused(event),
            }
        }
        SliceStop::Yielded
    }

    /// Attach fresh storage to the caller-bound stream without starting I/O.
    #[allow(clippy::result_large_err)]
    pub fn attach(
        connected: media::Connected,
        storage: recording_storage::Created,
        policy: video_bootstrap::Policy,
        camera_claim: ContentDigest,
    ) -> Result<Self, AttachRefusal> {
        let key = connected.pipeline.source_key();
        if key.connection == 0
            || key.generation == 0
            || !connected.pipeline.is_ready_for_recording()
            || connected.camera_claim() != camera_claim
            || connected.pipeline.inband_mode() != policy.inband
            || connected.pipeline.audio_tracking_active()
            || connected.pipeline.has_pending_audio()
            || !storage.coordinator.matches_binding(key, camera_claim)
            || storage.coordinator.source_status() != source_worker::Status::Idle
            || !(1..=100_000_000_000).contains(&storage.av.work_limit)
        {
            return Err(AttachRefusal {
                connected,
                storage,
                policy,
                camera_claim,
            });
        }
        Ok(Self {
            parts: Parts {
                connected,
                source: storage.coordinator.into_worker(),
                resources: Some(storage.av),
                video: None,
                key,
                camera_claim,
                policy,
                source_armed: false,
                video_armed: false,
                halted: false,
            },
        })
    }

    /// Authorize one more attempt for a retained source record.
    pub fn authorize_source_retry(&mut self) -> bool {
        if !self.parts.halted
            && !self.parts.source_armed
            && self.parts.source.status() == source_worker::Status::Pending
        {
            self.parts.source_armed = true;
            true
        } else {
            false
        }
    }

    /// Authorize one more attempt for a retained video segment.
    pub fn authorize_video_retry(&mut self) -> bool {
        if !self.parts.halted
            && !self.parts.video_armed
            && self
                .parts
                .video
                .as_ref()
                .is_some_and(|v| v.status() == video_worker::Status::Pending)
        {
            self.parts.video_armed = true;
            true
        } else {
            false
        }
    }

    /// Stop admission and request cancellation; running workers must be joined.
    pub fn abort(&mut self) {
        self.parts.halted = true;
        self.parts.source_armed = false;
        self.parts.video_armed = false;
        self.parts.source.abort();
        if let Some(video) = &mut self.parts.video {
            video.abort();
        }
    }

    /// Join a source attempt without discarding its result.
    pub async fn join_source(&mut self) -> Option<source_worker::Completion> {
        self.parts.source.join().await
    }

    /// Join a video attempt without discarding its result.
    pub async fn join_video(&mut self) -> Option<video_worker::Completion> {
        match &mut self.parts.video {
            Some(video) => video.join().await,
            None => None,
        }
    }

    /// Recover every owner after all archive attempts have drained.
    #[allow(clippy::result_large_err)]
    pub fn into_parts(self) -> Result<Parts, Self> {
        if self.parts.source.is_running()
            || self
                .parts
                .video
                .as_ref()
                .is_some_and(video_worker::Worker::is_running)
        {
            Err(self)
        } else {
            Ok(self.parts)
        }
    }

    /// Process one media or archive decision with bounded media and worker waiting.
    pub async fn step<'scope, 'task>(
        &mut self,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        wait: Duration,
        source_archive: ArchiveAdmission<'_>,
        video_archive: ArchiveAdmission<'_>,
    ) -> Step {
        if self.parts.halted {
            return Step::Halted;
        }
        if wait.is_zero()
            || wait > Duration::from_secs(30)
            || !clock.matches(task, cx)
            || !self.parts.connected.pipeline.is_bound_to_task(task)
        {
            return Step::Configuration;
        }
        if cx.checkpoint().is_err() {
            self.abort();
            return Step::Halted;
        }
        match self.parts.source.status() {
            source_worker::Status::Running => {
                return match timeout_at(cx.now() + wait, self.parts.source.join()).await {
                    Ok(Some(done)) => Step::SourceCompleted(done),
                    Ok(None) => Step::ArchiveUnavailable,
                    Err(_) => Step::SourceRunning,
                };
            }
            source_worker::Status::Pending if self.parts.source_armed => {
                self.parts.source_armed = false;
                return match self.parts.source.start(
                    task,
                    cx,
                    clock,
                    source_archive.resource,
                    source_archive.cost,
                ) {
                    Ok(()) => Step::SourceStarted,
                    Err(error) => Step::StartRefused(error),
                };
            }
            source_worker::Status::Pending => return Step::SourceRetryRequired,
            source_worker::Status::Fenced | source_worker::Status::Unavailable => {
                return Step::ArchiveUnavailable;
            }
            source_worker::Status::Idle => (),
        }
        if let Some(video) = &mut self.parts.video {
            match video.status() {
                video_worker::Status::Running => {
                    return match timeout_at(cx.now() + wait, video.join()).await {
                        Ok(Some(done)) => Step::VideoCompleted(done),
                        Ok(None) => Step::ArchiveUnavailable,
                        Err(_) => Step::VideoRunning,
                    };
                }
                video_worker::Status::Pending if self.parts.video_armed => {
                    self.parts.video_armed = false;
                    return match video.start(
                        task,
                        cx,
                        clock,
                        video_archive.resource,
                        video_archive.cost,
                    ) {
                        Ok(()) => Step::VideoStarted,
                        Err(error) => Step::StartRefused(error),
                    };
                }
                video_worker::Status::Pending => return Step::VideoRetryRequired,
                video_worker::Status::Fenced | video_worker::Status::Unavailable => {
                    return Step::ArchiveUnavailable;
                }
                video_worker::Status::Idle => (),
            }
        }
        let now = match clock.now() {
            Ok(now) => now,
            Err(_) => return Step::Configuration,
        };
        let result = timeout_at(
            cx.now() + wait,
            self.parts.connected.pipeline.step(task, cx, now),
        )
        .await;
        let result = match result {
            Err(_) => return Step::Idle,
            Ok(Err(error)) => {
                self.parts.halted = true;
                return Step::MediaError(error);
            }
            Ok(Ok(result)) => result,
        };
        match result {
            pipeline::Step::Recording(recording::Push::Source {
                record,
                disposition,
            }) => {
                if disposition == recording::SourceDisposition::Configuration {
                    if self.parts.video.is_some() {
                        self.parts.halted = true;
                        return Step::ConfigurationChanged(record);
                    }
                    let copy = match record.try_duplicate() {
                        Ok(copy) => copy,
                        Err(_) => {
                            self.parts.halted = true;
                            return Step::ConfigurationCopyRefused(record);
                        }
                    };
                    let Some(resources) = self.parts.resources.take() else {
                        self.parts.halted = true;
                        return Step::ConfigurationChanged(record);
                    };
                    let sink = match video_owned_sink::Sink::new(video_owned_sink::Inputs {
                        configuration: record,
                        source: self.parts.key,
                        inband: self.parts.policy.inband,
                        retention: self.parts.policy.retention,
                        media_limits: self.parts.policy.media_limits,
                        evidence_limits: self.parts.policy.evidence_limits,
                    }) {
                        Ok(sink) => sink,
                        Err(refusal) => {
                            self.parts.resources = Some(resources);
                            self.parts.halted = true;
                            return Step::ConfigurationRefused(refusal);
                        }
                    };
                    let BootstrapResources {
                        deployment,
                        journal,
                        keeper,
                        replay,
                        authority,
                        limits,
                        work_limit,
                        rollover_custody,
                    } = *resources;
                    let parts = video_worker::Parts {
                        sink,
                        deployment,
                        journal,
                        keeper,
                        replay,
                        authority,
                        limits,
                        work_limit,
                    };
                    let video = match rollover_custody {
                        Some(custody) => match video_worker::Worker::from_recovered(parts, custody)
                        {
                            Ok(video) => video,
                            Err((parts, custody)) => {
                                self.parts.halted = true;
                                return Step::RecoveredWorkerRefused { parts, custody };
                            }
                        },
                        None => match video_worker::Worker::new(parts) {
                            Ok(video) => video,
                            Err(parts) => {
                                self.parts.halted = true;
                                return Step::WorkerRefused(parts);
                            }
                        },
                    };
                    self.parts.video = Some(video);
                    self.offer_source(copy, disposition, true)
                } else {
                    self.offer_source(record, disposition, false)
                }
            }
            pipeline::Step::Recording(recording::Push::Segment(segment)) => {
                let Some(video) = &mut self.parts.video else {
                    self.parts.halted = true;
                    return Step::SegmentBeforeConfiguration(segment);
                };
                match video.offer(segment) {
                    Ok(()) => {
                        self.parts.video_armed = true;
                        Step::VideoOffered
                    }
                    Err(refusal) => {
                        self.parts.halted = true;
                        Step::VideoRefused(refusal)
                    }
                }
            }
            other => {
                if matches!(other, pipeline::Step::Eof | pipeline::Step::LimitReached) {
                    self.parts.halted = true;
                }
                Step::Media(other)
            }
        }
    }

    fn offer_source(
        &mut self,
        record: SourceRecord,
        disposition: recording::SourceDisposition,
        configured: bool,
    ) -> Step {
        match self.parts.source.offer(source_worker::Input::Original {
            record,
            key: self.parts.key,
            disposition,
            camera_claim: self.parts.camera_claim,
        }) {
            Ok(()) => {
                self.parts.source_armed = true;
                if configured {
                    Step::Configured
                } else {
                    Step::SourceOffered(disposition)
                }
            }
            Err(refusal) => {
                self.parts.halted = true;
                Step::SourceRefused(refusal)
            }
        }
    }
}
