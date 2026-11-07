#![forbid(unsafe_code)]
//! Bounded joint supervision of an admitted controller and media pipeline.
//!
//! Each step transfers one observation or media result to the caller. Pending
//! receives are cancel-safe as documented by their owners; no task is detached.
//! This does not reconnect, publish media, authenticate a peer or prove receipt.

use super::{
    AudioCodec, MessageKind, Observation, Retirement as ControllerRetirement, VideoChannel,
    conversation, intent, management, motion, pipeline, receive,
};
use asupersync::{
    io::{AsyncRead, AsyncWrite},
    time::timeout_at,
};
use fss_container::InitializationSegment;
use fss_core::OperationId;
use fss_runtime::effect::CommittedEffect;
use std::{
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
    time::Duration,
};

/// One result. Returned media and recording refusals retain original-source custody.
#[must_use]
#[derive(Debug)]
pub enum Step {
    /// A single media processing result.
    Media(pipeline::Step),
    /// Camera requested a clock update; the journaled local write completed.
    TimeSyncWritten,
    /// A different, untrusted management observation.
    Observation(Observation),
    /// Camera event with exact source bytes; this is an unverified claim.
    CameraEvent(super::events::Frame),
    /// Startup event custody must be drained before more input is read.
    StartupEventBackpressure,
    /// The observed event reply needs a write or an explicit omission.
    EventReplyBackpressure,
    /// Neither source produced a result before the bounded deadline.
    Idle,
    /// A pending audio observation must be transferred before further polling.
    AudioPending,
    /// Controller stopped; the original controller retirement is retained by this owner.
    ControllerStopped(receive::Stop),
    /// Controller refused the receive operation.
    ControllerError(receive::Error),
    /// Media failed; a recording refusal can contain an unaccepted original record.
    MediaError(pipeline::Error),
    /// Clock, cancellation, configuration or management reply failed.
    ConversationError(conversation::Error),
    /// The supervisor was already stopped.
    Stopped,
}

/// Both components' remaining custody when the supervisor ends.
#[must_use]
pub struct Retirement {
    /// Outstanding controller protocol facts.
    pub controller: ControllerRetirement,
    /// Untransferred media source and recorder state.
    pub media: pipeline::Retirement,
}

/// Owns a single admitted management connection and its corresponding pipeline.
pub struct Supervisor<'scope, 'task, IO> {
    session: receive::Session<'scope, 'task, IO>,
    pipeline: pipeline::Pipeline,
    management: management::Preconditions,
    controller_retirement: Option<ControllerRetirement>,
    media_first: bool,
    stopped: bool,
}

enum Ready {
    Controller(Result<receive::Step, receive::Error>),
    Media(Result<pipeline::Step, pipeline::Error>),
    AudioPending,
    Clock,
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> Supervisor<'scope, 'task, IO> {
    /// Join an established controller and pipeline; caller binds them to the same camera.
    pub fn new(
        mut session: receive::Session<'scope, 'task, IO>,
        pipeline: pipeline::Pipeline,
        management: management::Preconditions,
    ) -> Self {
        session.enable_event_capture();
        Self {
            session,
            pipeline,
            management,
            controller_retirement: None,
            media_first: false,
            stopped: false,
        }
    }

    /// Check that a handoff uses the exact clock bound to this session.
    pub(crate) fn matches_clock(&self, clock: &super::metered::MeteredClock<'_, '_>) -> bool {
        self.session.matches_clock(clock)
    }

    /// Borrow the current initialization segment for any returned media fragment.
    pub fn initialization(&self) -> Option<&InitializationSegment> {
        self.pipeline.initialization()
    }

    /// Derive an A/V initialization for this pipeline's observed video
    /// configuration and a caller-supplied AAC configuration. The caller must
    /// establish or explicitly retain uncertainty about the configuration's
    /// source epoch and its relationship to the video clock.
    pub fn av_initialization(
        &self,
        audio: &fss_packet::extended_flv::aac::Configuration<'_>,
    ) -> Result<Option<fss_container::flv_av::Initialization>, fss_container::Mp4Error> {
        self.pipeline.av_initialization(audio)
    }

    /// Attach bounded AAC observation before this pipeline starts processing.
    pub fn enable_audio_tracking(&mut self) -> Result<(), pipeline::AudioSetupError> {
        if self.stopped {
            return Err(pipeline::AudioSetupError::AlreadyStarted);
        }
        self.pipeline.enable_audio_tracking()
    }

    /// Transfer a pending audio result only while the bound task and controller
    /// admission remain live. Withheld observations return at retirement.
    pub fn take_audio_event(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
    ) -> Option<pipeline::AudioEvent> {
        if self.stopped
            || !owner.clock.matches(owner.task, owner.cx)
            || !self.session.matches_clock(&owner.clock)
            || owner.cx.checkpoint().is_err()
            || !self.session.admission_current()
        {
            return None;
        }
        self.pipeline.take_audio_event()
    }

    /// Prepare a source-bound event reply without sending it. The caller must
    /// journal a fresh operation and authorize disclosure before dispatch.
    pub fn prepare_event_reply(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        frame: &super::events::Frame,
        timestamp: &str,
    ) -> Result<management::Intent, receive::Error> {
        if self.stopped {
            return Err(receive::Error::Retired);
        }
        if !owner.clock.matches(owner.task, owner.cx)
            || !self.session.matches_clock(&owner.clock)
            || owner.cx.checkpoint().is_err()
        {
            return Err(receive::Error::Denied);
        }
        self.management
            .validate()
            .map_err(receive::Error::ManagementIntent)?;
        self.session.prepare_event_reply(frame, timestamp)?;
        self.session.management_intent(self.management)
    }

    /// Abandon a locally unwritten reply while retaining its observed request.
    pub fn abandon_event_reply(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        frame: &super::events::Frame,
    ) -> Result<u64, receive::Error> {
        if self.stopped {
            return Err(receive::Error::Retired);
        }
        if !owner.clock.matches(owner.task, owner.cx)
            || !self.session.matches_clock(&owner.clock)
            || owner.cx.checkpoint().is_err()
        {
            return Err(receive::Error::Denied);
        }
        self.session.abandon_event_reply(frame)
    }

    /// Explicitly omit an observed reply; this makes no remote-delivery claim.
    pub fn omit_event_reply(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        frame: &super::events::Frame,
    ) -> Result<(), receive::Error> {
        if self.stopped {
            return Err(receive::Error::Retired);
        }
        if !owner.clock.matches(owner.task, owner.cx)
            || !self.session.matches_clock(&owner.clock)
            || owner.cx.checkpoint().is_err()
        {
            return Err(receive::Error::Denied);
        }
        self.session.omit_event_reply(frame)
    }

    /// Dispatch the prepared reply only with its journaled permit and the
    /// management authority's separate event-disclosure approval.
    pub async fn dispatch_event_reply(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        intent: management::Intent,
        current: management::Preconditions,
        permit: CommittedEffect,
        wait: Duration,
    ) -> Result<receive::ManagementWrite, receive::ManagementRefusal> {
        if self.stopped {
            return Err(receive::ManagementRefusal {
                reason: receive::Error::Retired,
                permit,
            });
        }
        if !owner.clock.matches(owner.task, owner.cx)
            || !self.session.matches_clock(&owner.clock)
            || owner.cx.checkpoint().is_err()
            || current != self.management
            || intent.kind() != MessageKind::EventReply
            || intent.source_digest().is_none()
        {
            return Err(receive::ManagementRefusal {
                reason: receive::Error::Denied,
                permit,
            });
        }
        let result = self
            .session
            .dispatch_management(intent, current, permit, owner.management_authority, wait)
            .await;
        if let Ok(receive::ManagementWrite::Indeterminate { controller, .. }) = &result {
            self.stopped = true;
            self.controller_retirement = Some(*controller);
        }
        result
    }

    /// Prepare an inert baseline motion setting while retaining the media pipeline.
    pub fn prepare_motion(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        enabled: bool,
        timestamp: &str,
        conditions: motion::Preconditions,
    ) -> Result<motion::Intent, receive::Error> {
        if self.stopped {
            return Err(receive::Error::Retired);
        }
        if !owner.clock.matches(owner.task, owner.cx)
            || !self.session.matches_clock(&owner.clock)
            || owner.cx.checkpoint().is_err()
            || conditions.camera != self.management.camera
            || conditions.peer_admission != self.management.peer_admission
            || conditions.session_generation != self.management.session_generation
            || conditions.lease_fence != self.management.lease_fence
        {
            return Err(receive::Error::Denied);
        }
        self.session.prepare_motion(enabled, timestamp, conditions)
    }

    /// Dispatch an explicitly authorized, journal-backed motion setting.
    pub async fn dispatch_motion(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        intent: motion::Intent,
        current: motion::Preconditions,
        permit: CommittedEffect,
        authority: &dyn receive::MotionAuthority,
        wait: Duration,
    ) -> Result<receive::MotionWrite, receive::MotionRefusal> {
        if self.stopped {
            return Err(receive::MotionRefusal {
                reason: receive::Error::Retired,
                permit,
            });
        }
        if !owner.clock.matches(owner.task, owner.cx)
            || !self.session.matches_clock(&owner.clock)
            || owner.cx.checkpoint().is_err()
            || current.camera != self.management.camera
            || current.peer_admission != self.management.peer_admission
            || current.session_generation != self.management.session_generation
            || current.lease_fence != self.management.lease_fence
        {
            return Err(receive::MotionRefusal {
                reason: receive::Error::Denied,
                permit,
            });
        }
        let result = self
            .session
            .dispatch_motion(intent, current, permit, authority, wait)
            .await;
        if let Ok(receive::MotionWrite::Indeterminate { controller, .. }) = &result {
            self.stopped = true;
            self.controller_retirement = Some(*controller);
        }
        result
    }

    /// Prepare a one-track discard request while retaining the media pipeline.
    /// This is inert; dispatch still requires a separately journaled permit and
    /// explicit quiesce authority. It does not prove a prior state can be restored.
    pub fn prepare_quiesce(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        channel: VideoChannel,
        audio: AudioCodec,
        timestamp: &str,
        conditions: intent::Preconditions,
    ) -> Result<intent::Intent, receive::Error> {
        if self.stopped {
            return Err(receive::Error::Retired);
        }
        if !owner.clock.matches(owner.task, owner.cx)
            || !self.session.matches_clock(&owner.clock)
            || owner.cx.checkpoint().is_err()
            || conditions.camera != self.management.camera
            || conditions.peer_admission != self.management.peer_admission
            || conditions.lease_fence != self.management.lease_fence
        {
            return Err(receive::Error::Denied);
        }
        self.session
            .prepare_stream_quiesce(channel, audio, timestamp, conditions)
    }

    /// Abandon a locally unwritten stream request while preserving the running
    /// media owner. A previously committed permit remains a separate obligation.
    pub fn abandon_prepared_stream(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        intent: intent::Intent,
    ) -> Result<super::AbandonedStream, receive::Error> {
        if self.stopped {
            return Err(receive::Error::Retired);
        }
        if !owner.clock.matches(owner.task, owner.cx)
            || !self.session.matches_clock(&owner.clock)
            || owner.cx.checkpoint().is_err()
        {
            return Err(receive::Error::Denied);
        }
        self.session.abandon_prepared_stream(intent)
    }

    /// Dispatch a previously prepared quiesce without dropping the media owner.
    /// A returned committed permit must be reconciled independently; a local
    /// write or camera reply is not proof of restoration or stream inactivity.
    pub async fn dispatch_quiesce(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        intent: intent::Intent,
        current: intent::Preconditions,
        permit: CommittedEffect,
        wait: Duration,
    ) -> Result<receive::StreamWrite, receive::StreamRefusal> {
        if self.stopped {
            return Err(receive::StreamRefusal {
                reason: receive::Error::Retired,
                permit,
            });
        }
        if !matches!(intent.kind(), MessageKind::QuiesceStream(_))
            || !owner.clock.matches(owner.task, owner.cx)
            || !self.session.matches_clock(&owner.clock)
            || owner.cx.checkpoint().is_err()
            || current.camera != self.management.camera
            || current.peer_admission != self.management.peer_admission
            || current.lease_fence != self.management.lease_fence
        {
            return Err(receive::StreamRefusal {
                reason: receive::Error::Denied,
                permit,
            });
        }
        let result = self
            .session
            .dispatch_stream(intent, current, permit, owner.stream_authority, wait)
            .await;
        if let Ok(receive::StreamWrite::Indeterminate { controller, .. }) = &result {
            self.stopped = true;
            self.controller_retirement = Some(*controller);
        }
        result
    }

    /// Poll both sources fairly for at most `wait`, then allow up to another
    /// `wait` to write a requested time-sync reply. Each request requires a
    /// fresh operation identity; reuse is refused by the effect journal.
    pub async fn step(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
    ) -> Step {
        self.step_mode(owner, operation, wait, true).await
    }

    /// Service controller input without polling or consuming media. This uses
    /// the same task, admission, cancellation and time-sync effect checks as
    /// [`Self::step`]; each reply still requires a fresh operation identity.
    pub async fn step_control(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
    ) -> Step {
        self.step_mode(owner, operation, wait, false).await
    }

    async fn step_mode(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
        allow_media: bool,
    ) -> Step {
        if self.stopped {
            return Step::Stopped;
        }
        if wait.is_zero()
            || wait > Duration::from_secs(30)
            || !owner.clock.matches(owner.task, owner.cx)
            || !self.session.matches_clock(&owner.clock)
        {
            self.stopped = true;
            return Step::ConversationError(conversation::Error::Configuration);
        }
        if owner.cx.checkpoint().is_err() {
            self.stopped = true;
            return Step::ConversationError(conversation::Error::Clock);
        }
        let mut media_first = self.media_first;
        let result = timeout_at(
            owner.cx.now() + wait,
            poll_fn(|context| {
                if owner.cx.checkpoint().is_err() {
                    return Poll::Ready(Ready::Clock);
                }
                // A buffered media record must not bypass a revoked controller
                // session merely because media happened to be polled first.
                if !allow_media || !self.session.admission_current() {
                    let mut control = pin!(self.session.next(wait));
                    return control.as_mut().poll(context).map(Ready::Controller);
                }
                if self.pipeline.has_pending_audio() {
                    return Poll::Ready(Ready::AudioPending);
                }
                if !media_first {
                    let mut control = pin!(self.session.next(wait));
                    if let Poll::Ready(value) = control.as_mut().poll(context) {
                        return Poll::Ready(Ready::Controller(value));
                    }
                }
                let now = match owner.clock.now() {
                    Ok(now) => now,
                    Err(_) => return Poll::Ready(Ready::Clock),
                };
                let mut future = pin!(self.pipeline.step(owner.task, owner.cx, now));
                if let Poll::Ready(value) = future.as_mut().poll(context) {
                    return Poll::Ready(Ready::Media(value));
                }
                if media_first {
                    let mut control = pin!(self.session.next(wait));
                    if let Poll::Ready(value) = control.as_mut().poll(context) {
                        return Poll::Ready(Ready::Controller(value));
                    }
                }
                media_first = !media_first;
                Poll::Pending
            }),
        )
        .await;
        if allow_media {
            self.media_first = !self.media_first;
        }
        match result {
            Err(_) if owner.cx.is_cancelled() => {
                self.stopped = true;
                Step::ConversationError(conversation::Error::Clock)
            }
            Err(_) | Ok(Ready::Controller(Ok(receive::Step::WaitElapsed))) => Step::Idle,
            Ok(Ready::Clock) => {
                self.stopped = true;
                Step::ConversationError(conversation::Error::Clock)
            }
            Ok(Ready::AudioPending) => Step::AudioPending,
            Ok(Ready::Controller(Ok(receive::Step::StartupEventBackpressure))) => {
                Step::StartupEventBackpressure
            }
            Ok(Ready::Controller(Ok(receive::Step::EventReplyBackpressure))) => {
                Step::EventReplyBackpressure
            }
            Ok(Ready::Controller(Err(error))) => {
                self.stopped = true;
                Step::ControllerError(error)
            }
            Ok(Ready::Controller(Ok(receive::Step::Retired { reason, controller }))) => {
                self.stopped = true;
                self.controller_retirement = Some(controller);
                Step::ControllerStopped(reason)
            }
            Ok(Ready::Controller(Ok(receive::Step::Observation(
                Observation::TimeSyncRequested,
            )))) => {
                match owner
                    .answer_time_sync(&mut self.session, operation, self.management, wait)
                    .await
                {
                    Ok(()) => Step::TimeSyncWritten,
                    Err(error) => {
                        self.stopped = true;
                        Step::ConversationError(error)
                    }
                }
            }
            Ok(Ready::Controller(Ok(receive::Step::Observation(value)))) => {
                Step::Observation(value)
            }
            Ok(Ready::Controller(Ok(receive::Step::CameraEvent(frame)))) => {
                Step::CameraEvent(frame)
            }
            Ok(Ready::Media(Err(error))) => {
                self.stopped = true;
                Step::MediaError(error)
            }
            Ok(Ready::Media(Ok(value))) => {
                if matches!(value, pipeline::Step::Eof | pipeline::Step::LimitReached) {
                    self.stopped = true;
                }
                Step::Media(value)
            }
        }
    }

    /// Close both transports and return all still-owned state.
    pub fn retire(self) -> Retirement {
        let closed = self.session.retire();
        Retirement {
            controller: self.controller_retirement.unwrap_or(closed),
            media: self.pipeline.retire(),
        }
    }
}
