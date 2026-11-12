#![forbid(unsafe_code)]
//! Bootstrap video-only publication from the admitted connection's own AVC configuration.
//!
//! Original configuration custody moves to the video sink. A bounded exact copy
//! is separately archived; that copy is not a second observation. Other source
//! records are archived in order before more media is read. The caller must
//! account for every returned control event, completion and refusal.

use std::time::Duration;

use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
};
use fss_container::{Mp4Limits, flv_avc::SourceKey};
use fss_core::{ContentDigest, OperationId};
use fss_packet::extended_flv::stream::SourceRecord;
use fss_runtime::execution::TaskCx;

use super::{
    av_unknown_worker_guard::BootstrapResources, av_worker, conversation, evidence,
    metered::MeteredClock, pipeline, recording, source_coordinator::ArchiveAdmission,
    source_worker, supervisor, video_owned_sink, video_session, video_worker,
};

/// Video initialization policy supplied before any source is read.
#[derive(Clone, Copy)]
pub struct Policy {
    /// Use the in-band AVC profile.
    pub inband: bool,
    /// Identity of the separately authorized retention decision.
    pub retention: ContentDigest,
    /// Video initialization limits.
    pub media_limits: Mp4Limits,
    /// Video evidence limits.
    pub evidence_limits: evidence::Limits,
}

/// Owners retained across bootstrap and returned on refusal or shutdown.
#[must_use]
pub struct Parts<'scope, 'task, IO> {
    /// Admitted controller and source pipeline.
    pub supervisor: supervisor::Supervisor<'scope, 'task, IO>,
    /// Separate-source archive worker.
    pub source: source_worker::Worker,
    /// Video archive resources until the configuration is accepted.
    pub resources: Option<Box<BootstrapResources>>,
    /// Video worker after the configuration is accepted.
    pub video: Option<video_worker::Worker>,
    /// Caller-bound source claim.
    pub key: SourceKey,
    /// Caller-bound camera claim, not independent authentication.
    pub camera_claim: ContentDigest,
    /// Original video initialization policy.
    pub policy: Policy,
    /// Whether one source publication attempt is authorized.
    pub source_armed: bool,
    /// Whether new work is stopped.
    pub halted: bool,
}

/// One bootstrap result, including all control and source custody outcomes.
#[must_use]
pub enum Step {
    /// A supervisor result which does not contain a separately returned source.
    Supervisor(supervisor::Step),
    /// An original source was offered to the separate archive.
    SourceOffered(recording::SourceDisposition),
    /// The exact AVC configuration was retained and a copy offered for archive.
    Configured,
    /// A source was refused and remains caller-owned; bootstrap is halted.
    SourceRefused(source_worker::OfferRefusal),
    /// A configuration could not be duplicated; the original is returned.
    ConfigurationCopyRefused(SourceRecord),
    /// The video sink refused initialization and returned its original inputs.
    ConfigurationRefused(video_owned_sink::ConstructionRefusal),
    /// Video worker construction refused and returned its owners.
    WorkerRefused(video_worker::Parts),
    /// A source archive attempt started.
    SourceStarted,
    /// Starting the source failed; retry requires explicit authorization.
    SourceStartRefused(av_worker::StartError),
    /// A control result and/or a drained source completion.
    SourceArchive {
        /// Bounded control result, if polled.
        control: Option<supervisor::Step>,
        /// Source completion, if drained.
        completion: Option<source_worker::Completion>,
    },
    /// A retained source needs an explicit retry decision.
    SourceRetryRequired(supervisor::Step),
    /// Configuration and source archive have drained; transition is available.
    Ready,
    /// Source state is fenced or cannot be inspected.
    SourceUnavailable,
    /// Task, runtime, or clock does not match the admitted supervisor.
    Context,
    /// The bounded wait is invalid; no work started.
    Configuration,
    /// Cancellation or refusal stopped admission.
    Halted,
}

/// Owns bootstrap until the session is ready or all owners are recovered.
#[must_use = "drain the source worker and recover all owners"]
pub struct Bootstrap<'scope, 'task, IO> {
    parts: Parts<'scope, 'task, IO>,
}

/// Transition failure retains the bootstrap or the exact refused session parts.
#[must_use]
pub enum HandoffRefusal<'scope, 'task, IO> {
    /// Bootstrap is not ready; nothing was consumed.
    NotReady(Bootstrap<'scope, 'task, IO>),
    /// Session attachment refused the supplied owners.
    Attach(video_session::Parts<'scope, 'task, IO>),
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> Bootstrap<'scope, 'task, IO> {
    /// Bind idle owners before reading media; refusal returns all of them.
    pub fn begin(
        supervisor: supervisor::Supervisor<'scope, 'task, IO>,
        source: source_worker::Worker,
        resources: Box<BootstrapResources>,
        key: SourceKey,
        camera_claim: ContentDigest,
        policy: Policy,
    ) -> Result<Self, Parts<'scope, 'task, IO>> {
        let parts = Parts {
            supervisor,
            source,
            resources: Some(resources),
            video: None,
            key,
            camera_claim,
            policy,
            source_armed: false,
            halted: false,
        };
        if parts.supervisor.audio_tracking_active()
            || parts.supervisor.has_pending_audio()
            || parts.supervisor.source_key() != key
            || key.connection == 0
            || key.generation == 0
            || parts.source.status() != source_worker::Status::Idle
            || !(1..=100_000_000_000)
                .contains(&parts.resources.as_ref().expect("present").work_limit)
        {
            return Err(parts);
        }
        Ok(Self { parts })
    }

    /// Access the admitted controller while bootstrap is active.
    pub fn control(&mut self) -> Option<super::recording_session::Control<'_, 'scope, 'task, IO>> {
        (!self.parts.halted)
            .then(|| super::recording_session::Control::from_supervisor(&mut self.parts.supervisor))
    }

    /// Explicitly authorize one retry of the retained source.
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

    /// Stop admission and request cancellation of the source attempt.
    pub fn abort(&mut self) {
        self.parts.halted = true;
        self.parts.source_armed = false;
        self.parts.source.abort();
    }

    /// Join the source attempt and return its exact completion.
    pub async fn join_source(&mut self) -> Option<source_worker::Completion> {
        self.parts.source.join().await
    }

    /// Recover every remaining owner after the source attempt drains.
    pub fn into_parts(self) -> Result<Parts<'scope, 'task, IO>, Self> {
        if self.parts.source.is_running() {
            Err(self)
        } else {
            Ok(self.parts)
        }
    }

    /// Transfer a ready bootstrap to the video-only session.
    pub fn into_session(
        self,
    ) -> Result<video_session::Session<'scope, 'task, IO>, HandoffRefusal<'scope, 'task, IO>> {
        if self.parts.halted
            || self.parts.video.is_none()
            || self.parts.resources.is_some()
            || self.parts.source.status() != source_worker::Status::Idle
            || self.parts.source_armed
        {
            return Err(HandoffRefusal::NotReady(self));
        }
        let Parts {
            supervisor,
            source,
            video: Some(video),
            key,
            camera_claim,
            ..
        } = self.parts
        else {
            unreachable!("readiness checked above")
        };
        video_session::Session::attach(supervisor, video, source, key, camera_claim)
            .map_err(HandoffRefusal::Attach)
    }

    /// Process one bounded control, source or bootstrap decision.
    pub async fn step(
        &mut self,
        owner: &mut conversation::Owner<'_, 'scope, 'task>,
        operation: &OperationId,
        wait: Duration,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        source_archive: ArchiveAdmission<'_>,
    ) -> Step {
        if self.parts.halted {
            return Step::Halted;
        }
        if wait.is_zero() || wait > Duration::from_secs(30) {
            return Step::Configuration;
        }
        if !owner.clock.matches(owner.task, owner.cx)
            || !owner.clock.matches(task, cx)
            || !clock.matches(task, cx)
            || !self.parts.supervisor.matches_clock(&owner.clock)
            || !self.parts.supervisor.matches_clock(&clock)
        {
            return Step::Context;
        }
        if owner.cx.checkpoint().is_err() {
            self.abort();
            return Step::Halted;
        }
        match self.parts.source.status() {
            source_worker::Status::Running => {
                if let Some(completion) = video_session::poll_source(&mut self.parts.source).await {
                    return Step::SourceArchive {
                        control: None,
                        completion: Some(completion),
                    };
                }
                let control = self
                    .parts
                    .supervisor
                    .step_control(owner, operation, wait)
                    .await;
                let completion = video_session::poll_source(&mut self.parts.source).await;
                return Step::SourceArchive {
                    control: Some(control),
                    completion,
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
                    Err(error) => Step::SourceStartRefused(error),
                };
            }
            source_worker::Status::Pending => {
                return Step::SourceRetryRequired(
                    self.parts
                        .supervisor
                        .step_control(owner, operation, wait)
                        .await,
                );
            }
            source_worker::Status::Fenced | source_worker::Status::Unavailable => {
                return Step::SourceUnavailable;
            }
            source_worker::Status::Idle => (),
        }
        if self.parts.video.is_some() {
            return Step::Ready;
        }
        match self.parts.supervisor.step(owner, operation, wait).await {
            supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {
                record,
                disposition,
            })) => {
                if disposition == recording::SourceDisposition::Configuration {
                    let copy = match record.try_duplicate() {
                        Ok(copy) => copy,
                        Err(_) => {
                            self.parts.halted = true;
                            return Step::ConfigurationCopyRefused(record);
                        }
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
                    } = *self
                        .parts
                        .resources
                        .take()
                        .expect("resources precede configuration");
                    let video = match video_worker::Worker::new(video_worker::Parts {
                        sink,
                        deployment,
                        journal,
                        keeper,
                        replay,
                        authority,
                        limits,
                        work_limit,
                    }) {
                        Ok(video) => video,
                        Err(parts) => {
                            self.parts.halted = true;
                            return Step::WorkerRefused(parts);
                        }
                    };
                    self.parts.video = Some(video);
                    match self.parts.source.offer(source_worker::Input::Original {
                        record: copy,
                        key: self.parts.key,
                        disposition,
                        camera_claim: self.parts.camera_claim,
                    }) {
                        Ok(()) => {
                            self.parts.source_armed = true;
                            Step::Configured
                        }
                        Err(refusal) => {
                            self.parts.halted = true;
                            Step::SourceRefused(refusal)
                        }
                    }
                } else {
                    match self.parts.source.offer(source_worker::Input::Original {
                        record,
                        key: self.parts.key,
                        disposition,
                        camera_claim: self.parts.camera_claim,
                    }) {
                        Ok(()) => {
                            self.parts.source_armed = true;
                            Step::SourceOffered(disposition)
                        }
                        Err(refusal) => {
                            self.parts.halted = true;
                            Step::SourceRefused(refusal)
                        }
                    }
                }
            }
            event => Step::Supervisor(event),
        }
    }
}
