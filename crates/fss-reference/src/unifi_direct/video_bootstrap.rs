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
    management, receive, recording_storage, source_worker, supervisor, video_owned_sink,
    video_session, video_worker,
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

/// A selected media source, its controller and fresh or recovered archive
/// owners. All identities are caller-supplied claims, not authentication.
#[must_use = "attach or retain the session, pipeline, and archive owners"]
pub struct SelectedRecording<'scope, 'task, IO> {
    /// Controller session associated with the selected source by the caller.
    pub session: receive::Session<'scope, 'task, IO>,
    /// Selected pipeline, including any buffered prefix bytes.
    pub pipeline: pipeline::Pipeline,
    /// Caller-bound camera, peer and lease preconditions.
    pub management: management::Preconditions,
    /// Source and video archive owners supplied by the caller.
    pub storage: recording_storage::Created,
    /// Separately authorized video retention and media limits.
    pub policy: Policy,
}

/// Refusal retains every input or the exact post-construction bootstrap parts.
#[must_use = "recover and reconcile the returned owners"]
pub enum SelectedRefusal<'scope, 'task, IO> {
    /// Camera or source binding did not match, or preconditions were invalid.
    Binding(SelectedRecording<'scope, 'task, IO>),
    /// Bootstrap refused after controller and storage owners were assembled.
    Bootstrap(Parts<'scope, 'task, IO>),
}

/// Attach an already selected stream to its exact archive owners without
/// reading from the camera or starting a publication. A successful handoff
/// does not establish physical identity, continuity, or recording durability.
pub fn begin_selected<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
    selected: SelectedRecording<'scope, 'task, IO>,
) -> Result<Bootstrap<'scope, 'task, IO>, SelectedRefusal<'scope, 'task, IO>> {
    let key = selected.pipeline.source_key();
    if selected.management.validate().is_err()
        || !selected.storage.coordinator.matches_binding(key, selected.management.camera)
    {
        return Err(SelectedRefusal::Binding(selected));
    }
    let SelectedRecording { session, pipeline, management, storage, policy } = selected;
    let supervisor = supervisor::Supervisor::new(session, pipeline, management);
    Bootstrap::begin(
        supervisor,
        storage.coordinator.into_worker(),
        storage.av,
        key,
        management.camera,
        policy,
    )
    .map_err(SelectedRefusal::Bootstrap)
}

/// The exact owner retained while joining bootstrap and managed recording.
#[must_use = "drain or reconcile the returned owner"]
pub enum ManagedRecordingOwner<'scope, 'task, IO> {
    /// Bootstrap and its source worker remain owned.
    Bootstrap(Bootstrap<'scope, 'task, IO>),
    /// Recording and any rollover remain owned.
    Recording(video_session::ManagedSession<'scope, 'task, IO>),
    /// Session attachment refused after bootstrap; every part is returned.
    Refused(video_session::Parts<'scope, 'task, IO>),
}

/// One complete bootstrap, transition, or managed-recording outcome.
#[must_use = "account for the returned control and publication outcomes"]
pub enum ManagedRecordingStep {
    /// The original bootstrap event, including its source completions.
    Bootstrap(Step),
    /// The ready bootstrap became a managed session; no media was polled.
    RecordingStarted,
    /// The transition refused; the owner remains available for recovery.
    TransitionRefused,
    /// The original managed-session result, including rollover outcomes.
    Recording(video_session::ManagedStep),
    /// Admission was stopped or the transition requires reconciliation.
    Halted,
}

/// Caller-driven transition from a selected source through bootstrap to a
/// managed video session. Dropping a borrowing step wait retains its owner.
/// This does not create storage, authenticate cameras, or establish continuity.
#[must_use = "abort and drain or recover the retained owner"]
pub struct ManagedRecording<'scope, 'task, IO> {
    owner: Option<ManagedRecordingOwner<'scope, 'task, IO>>,
    ready: bool,
    halted: bool,
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> ManagedRecording<'scope, 'task, IO> {
    /// Retain an existing bootstrap without starting any work.
    pub fn new(bootstrap: Bootstrap<'scope, 'task, IO>) -> Self {
        Self { owner: Some(ManagedRecordingOwner::Bootstrap(bootstrap)), ready: false, halted: false }
    }

    /// Retain an existing managed session without polling it or changing its
    /// capacity, retry, or rollover state. Its owner remains caller-supplied.
    pub fn from_managed(recording: video_session::ManagedSession<'scope, 'task, IO>) -> Self {
        Self { owner: Some(ManagedRecordingOwner::Recording(recording)), ready: false, halted: false }
    }

    /// Borrow the controller while the retained phase permits it.
    pub fn control(&mut self) -> Option<super::recording_session::Control<'_, 'scope, 'task, IO>> {
        if self.halted { return None; }
        match self.owner.as_mut()? {
            ManagedRecordingOwner::Bootstrap(bootstrap) => bootstrap.control(),
            ManagedRecordingOwner::Recording(recording) => recording.control(),
            ManagedRecordingOwner::Refused(_) => None,
        }
    }

    /// Offer one caller-prepared rollover supply after recording starts.
    /// A refusal returns the original supplies unchanged.
    pub fn provide(
        &mut self,
        supplies: super::av_rollover_worker::Supplies,
    ) -> Result<(), super::av_rollover_worker::Supplies> {
        if self.halted { return Err(supplies); }
        match self.owner.as_mut() {
            Some(ManagedRecordingOwner::Recording(recording)) => recording.provide(supplies),
            _ => Err(supplies),
        }
    }

    /// Authorize one explicit retry of a retained source in the current phase.
    pub fn authorize_source_retry(&mut self) -> bool {
        if self.halted { return false; }
        match self.owner.as_mut() {
            Some(ManagedRecordingOwner::Bootstrap(bootstrap)) => bootstrap.authorize_source_retry(),
            Some(ManagedRecordingOwner::Recording(recording)) => recording.authorize_source_retry(),
            _ => false,
        }
    }

    /// Authorize one explicit retry of a retained video segment.
    pub fn authorize_video_retry(&mut self) -> bool {
        if self.halted { return false; }
        match self.owner.as_mut() {
            Some(ManagedRecordingOwner::Recording(recording)) => recording.authorize_video_retry(),
            _ => false,
        }
    }

    /// Authorize one explicit rollover retry after a reported refusal.
    pub fn authorize_rollover_retry(&mut self) -> bool {
        if self.halted { return false; }
        match self.owner.as_mut() {
            Some(ManagedRecordingOwner::Recording(recording)) => recording.authorize_rollover_retry(),
            _ => false,
        }
    }

    /// Stop new work and request cancellation of the phase's active workers.
    /// The returned owner still has to be drained and reconciled by the caller.
    pub fn abort(&mut self) {
        self.halted = true;
        match self.owner.as_mut() {
            Some(ManagedRecordingOwner::Bootstrap(bootstrap)) => bootstrap.abort(),
            Some(ManagedRecordingOwner::Recording(recording)) => recording.abort(),
            _ => (),
        }
    }

    /// Advance one bounded phase decision. Ready is reported before the
    /// subsequent call changes phase; all underlying events remain visible.
    pub async fn step(
        &mut self,
        owner: &mut conversation::Owner<'_, 'scope, 'task>,
        operation: &OperationId,
        wait: Duration,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        video_archive: ArchiveAdmission<'_>,
        source_archive: ArchiveAdmission<'_>,
    ) -> ManagedRecordingStep {
        if self.halted { return ManagedRecordingStep::Halted; }
        if self.ready {
            self.ready = false;
            let bootstrap = match self.owner.take() {
                Some(ManagedRecordingOwner::Bootstrap(bootstrap)) => bootstrap,
                other => {
                    self.owner = other;
                    self.halted = true;
                    return ManagedRecordingStep::Halted;
                }
            };
            return match bootstrap.into_session() {
                Ok(session) => {
                    self.owner = Some(ManagedRecordingOwner::Recording(video_session::ManagedSession::new(session)));
                    ManagedRecordingStep::RecordingStarted
                }
                Err(HandoffRefusal::NotReady(bootstrap)) => {
                    self.owner = Some(ManagedRecordingOwner::Bootstrap(bootstrap));
                    self.halted = true;
                    ManagedRecordingStep::TransitionRefused
                }
                Err(HandoffRefusal::Attach(parts)) => {
                    self.owner = Some(ManagedRecordingOwner::Refused(parts));
                    self.halted = true;
                    ManagedRecordingStep::TransitionRefused
                }
            };
        }
        match self.owner.as_mut() {
            Some(ManagedRecordingOwner::Bootstrap(bootstrap)) => {
                let step = bootstrap.step(owner, operation, wait, task, cx, clock, source_archive).await;
                self.ready = matches!(step, Step::Ready);
                ManagedRecordingStep::Bootstrap(step)
            }
            Some(ManagedRecordingOwner::Recording(recording)) => ManagedRecordingStep::Recording(
                recording.step(owner, operation, wait, task, cx, clock, video_archive, source_archive).await,
            ),
            _ => ManagedRecordingStep::Halted,
        }
    }

    /// Return the exact current owner, including any unfinished worker state.
    pub fn into_owner(mut self) -> ManagedRecordingOwner<'scope, 'task, IO> {
        self.owner.take().expect("owner retained between public calls")
    }
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
