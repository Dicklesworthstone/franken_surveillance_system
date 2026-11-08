#![forbid(unsafe_code)]
//! Task-owned bridge from a camera supervisor to an unknown-time archive worker.
//!
//! Media is not polled while a segment or archive attempt is outstanding.
//! Control-only work remains independently schedulable. This owner does not
//! authenticate a camera, start a service, establish coverage or infer time.

use std::{
    future::{Future, poll_fn},
    pin::pin,
    sync::Arc,
    task::Poll,
    time::Duration,
};

use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
};
use fss_core::{BudgetVector, OperationId};
use fss_runtime::{effect::CommittedEffect, execution::TaskCx};

use super::{
    AudioCodec, VideoChannel, archive, av_bootstrap_driver, av_owned_sink, av_recording, av_sink,
    av_worker, av_worker_guard::ArchiveState, conversation, events, intent, management,
    metered::MeteredClock, motion, pipeline, receive, recording, supervisor,
};
use crate::{ReferenceDeployment, ReplayCx};

/// Exclusive archive owners required to create an unknown-time worker.
pub struct BootstrapResources {
    /// Local archive owner.
    pub deployment: ReferenceDeployment,
    /// Unknown-time publication intent history.
    pub journal: archive::journal::UnknownTimeJournal,
    /// Separately stored intent-anchor history.
    pub keeper: archive::journal::UnknownTimeAnchorKeeper,
    /// Storage and cancellation authority.
    pub replay: ReplayCx,
    /// Revalidated original-byte retention decision.
    pub authority: Arc<dyn archive::RetainAuthority + Send + Sync>,
    /// Archive limits.
    pub limits: archive::Limits,
    /// Maximum work per publication attempt.
    pub work_limit: u64,
}

/// A guard and the explicitly hypothesized sender-clock origin.
#[must_use]
pub struct BootstrapStarted<'scope, 'task, IO> {
    /// Guard retaining the exact first segment until it is queued.
    pub guard: Guard<'scope, 'task, IO>,
    /// Sender-clock hypothesis; not a physical capture-time observation.
    pub origin: av_recording::SenderClockOrigin,
}

/// Construction refusal retains every source and storage owner.
#[must_use]
pub enum BootstrapRefusal<'scope, 'task, IO> {
    /// Audio observation is inactive or already has an unmatched event.
    Audio {
        /// Original supervisor and bootstrap source.
        handoff: av_bootstrap_driver::Handoff<'scope, 'task, IO>,
        /// Unconsumed archive owners.
        resources: BootstrapResources,
    },
    /// Sink conversion refused; the original handoff and resources are intact.
    Sink {
        /// Original supervisor and bootstrap source.
        handoff: av_bootstrap_driver::Handoff<'scope, 'task, IO>,
        /// Unconsumed archive owners.
        resources: BootstrapResources,
    },
    /// Worker construction refused after conversion; all owners are returned.
    Worker {
        /// Original supervisor.
        supervisor: supervisor::Supervisor<'scope, 'task, IO>,
        /// Unconsumed unknown-time worker parts.
        parts: av_worker::UnknownTimeParts,
        /// Exact first original segment.
        first_segment: recording::Segment,
        /// Original sender-clock hypothesis.
        origin: av_recording::SenderClockOrigin,
    },
}

/// A refused transfer leaves the original segment held by the guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueError {
    /// An audio event must be transferred before publication can proceed.
    AudioPending,
    /// A new configuration or invalid audio epoch requires reconciliation.
    AudioFenced,
    /// There is no held segment.
    NoSegment,
    /// The archive already has pending work.
    Busy,
    /// The worker requires explicit reconciliation.
    Fenced,
    /// The sink refused the segment without consuming it.
    Sink(av_sink::RefusalReason),
}

/// One bounded supervisor or source-transfer result.
#[must_use]
pub enum Step {
    /// A held original segment entered the worker; publication is pending.
    SourceQueued,
    /// A source transfer was refused and remains held.
    QueueRefused(QueueError),
    /// Archive work must finish or reconcile before further media is read.
    ArchivePending,
    /// Runtime cancellation was observed.
    Cancelled,
    /// An audio configuration or error requires explicit reconciliation.
    AudioFenced,
    /// An unrelated supervisor result, retaining its normal ownership rules.
    Supervisor(supervisor::Step),
}

/// Refusal to start a held source or its archive operation.
#[derive(Debug)]
pub enum StartError {
    /// A held segment could not be transferred into the worker.
    Queue(QueueError),
    /// Worker admission failed; its source remains owned.
    Worker(av_worker::StartError),
}

/// One scheduling decision while archive work is active.
#[must_use]
pub enum Drive {
    /// No archive attempt is running.
    NotRunning,
    /// The drained archive result was ready before control was polled.
    Archive(av_worker::UnknownTimeCompletion),
    /// A complete control step and optional drained archive result.
    Control {
        /// Controller outcome.
        step: supervisor::Step,
        /// Archive completion observed after the control step, if any.
        completion: Option<av_worker::UnknownTimeCompletion>,
    },
}

/// One bounded decision by the session's archive scheduler.
#[must_use]
pub enum Advance {
    /// The scheduling task, owner, or clock do not describe the same session.
    Context,
    /// A supervisor/source result; its ownership remains with the caller.
    Source(Step),
    /// A queued segment was admitted to the archive worker.
    ArchiveStarted,
    /// The start was refused; the source remains owned by the guard.
    StartRefused(StartError),
    /// A running attempt was driven alongside control traffic.
    Archive(Drive),
    /// A prior attempt failed; caller must explicitly authorize another attempt.
    RetryRequired,
    /// An uncertain attempt requires retirement and reconciliation.
    RecoveryRequired,
    /// Cancellation was requested and a running worker has drained.
    Cancelled(Option<av_worker::UnknownTimeCompletion>),
}

/// A source, control, archive, or audio observation transferred to the session owner.
#[must_use]
pub enum SessionEvent {
    /// A complete bounded scheduler result.
    Advance(Advance),
    /// An audio interpretation; the associated original source is accounted separately.
    Audio(pipeline::AudioEvent),
}

/// Whether the observer wants this bounded session slice to continue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionDecision {
    /// Continue processing within the supplied limit.
    Continue,
    /// Return to the caller with accepted events and any worker still owned.
    Yield,
    /// Stop and drain any active archive attempt.
    Stop,
}

/// Supplies fresh operation IDs and accepts ownership of session results.
pub trait SessionObserver {
    /// Return an operation ID suitable for the next control step, or stop.
    fn next_operation(&mut self) -> Option<OperationId>;
    /// Accept an event, or return it intact when it cannot be accepted.
    fn observe(&mut self, event: SessionEvent) -> Result<SessionDecision, SessionEvent>;
}

/// Why a bounded session slice stopped. The guard remains caller-owned.
#[must_use]
pub enum SessionStop {
    /// The step limit or wait duration was invalid; no work was started.
    Configuration,
    /// The step budget was exhausted; any running worker stays owned by the guard.
    Yielded,
    /// The observer accepted an event and requested a resumable yield.
    ObserverYielded,
    /// The observer could not supply another operation ID.
    OperationUnavailable {
        /// An archive worker drained after cancellation, if one was running.
        drained: Option<av_worker::UnknownTimeCompletion>,
    },
    /// Admission withheld an audio observation; it remains in the supervisor.
    AudioWithheld,
    /// A terminal or actionable scheduler result, with any running worker drained.
    Halted {
        /// Original scheduler result, including any original source or completion.
        event: Advance,
        /// Cancellation-drained worker result, if the worker was still running.
        drained: Option<av_worker::UnknownTimeCompletion>,
    },
    /// The observer requested a stop after accepting an event.
    ObserverStopped {
        /// Cancellation-drained worker result, if one was running.
        drained: Option<av_worker::UnknownTimeCompletion>,
    },
    /// The observer returned an unaccepted event without consuming it.
    ObserverRefused {
        /// The original unaccepted event.
        event: SessionEvent,
        /// Cancellation-drained worker result, if one was running.
        drained: Option<av_worker::UnknownTimeCompletion>,
    },
}

/// Task-owned supervisor coupled to one unknown-time archival worker.
#[must_use = "drain archive work and retire the supervisor and source owners"]
pub struct Guard<'scope, 'task, IO> {
    supervisor: supervisor::Supervisor<'scope, 'task, IO>,
    worker: av_worker::UnknownTimeWorker,
    held: Option<recording::Segment>,
    archive: ArchiveState,
    audio_fenced: bool,
    retry_required: bool,
}

/// Every owner returned after the archive has actually drained.
#[must_use]
pub struct Retirement {
    /// Original source still held outside the worker, if any.
    pub held: Option<recording::Segment>,
    /// Worker source, storage, journals and fence.
    pub worker: av_worker::UnknownTimeRetirement,
    /// Retired controller and media owners.
    pub supervisor: supervisor::Retirement,
    /// Archive phase at retirement.
    pub archive: ArchiveState,
    /// A later audio configuration or parsing error requires reconciliation.
    pub audio_fenced: bool,
    /// An archive attempt did not complete successfully.
    pub retry_required: bool,
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> Guard<'scope, 'task, IO> {
    /// Build from a completed bootstrap without performing I/O or inventing
    /// capture bounds. All source and storage owners return on refusal.
    pub fn from_bootstrap(
        handoff: av_bootstrap_driver::Handoff<'scope, 'task, IO>,
        resources: BootstrapResources,
    ) -> Result<BootstrapStarted<'scope, 'task, IO>, BootstrapRefusal<'scope, 'task, IO>> {
        if !handoff.supervisor.audio_tracking_active() || handoff.supervisor.has_pending_audio() {
            return Err(BootstrapRefusal::Audio { handoff, resources });
        }
        let av_bootstrap_driver::Handoff {
            supervisor,
            bootstrap,
        } = handoff;
        let av_owned_sink::Bootstrap {
            sink,
            first_segment,
            origin,
        } = bootstrap;
        let sink = match sink.into_unknown_time() {
            Ok(sink) => sink,
            Err(sink) => {
                return Err(BootstrapRefusal::Sink {
                    handoff: av_bootstrap_driver::Handoff {
                        supervisor,
                        bootstrap: av_owned_sink::Bootstrap {
                            sink,
                            first_segment,
                            origin,
                        },
                    },
                    resources,
                });
            }
        };
        let parts = av_worker::UnknownTimeParts {
            sink,
            deployment: resources.deployment,
            journal: resources.journal,
            keeper: resources.keeper,
            replay: resources.replay,
            authority: resources.authority,
            limits: resources.limits,
            work_limit: resources.work_limit,
        };
        let worker = match av_worker::UnknownTimeWorker::new(parts) {
            Ok(worker) => worker,
            Err(parts) => {
                return Err(BootstrapRefusal::Worker {
                    supervisor,
                    parts,
                    first_segment,
                    origin,
                });
            }
        };
        Ok(BootstrapStarted {
            guard: Self {
                supervisor,
                worker,
                held: Some(first_segment),
                archive: ArchiveState::Idle,
                audio_fenced: false,
                retry_required: false,
            },
            origin,
        })
    }

    /// Attach only an idle worker; refusal returns both original owners.
    pub fn new(
        supervisor: supervisor::Supervisor<'scope, 'task, IO>,
        worker: av_worker::UnknownTimeWorker,
    ) -> Result<
        Self,
        (
            supervisor::Supervisor<'scope, 'task, IO>,
            av_worker::UnknownTimeWorker,
        ),
    > {
        if !worker.is_idle()
            || !supervisor.audio_tracking_active()
            || supervisor.has_pending_audio()
        {
            return Err((supervisor, worker));
        }
        Ok(Self {
            supervisor,
            worker,
            held: None,
            archive: ArchiveState::Idle,
            audio_fenced: false,
            retry_required: false,
        })
    }

    /// Current archive phase.
    pub fn archive_state(&self) -> ArchiveState {
        self.archive
    }

    /// Original source held outside the worker, if any.
    pub fn held_segment(&self) -> Option<&recording::Segment> {
        self.held.as_ref()
    }

    /// Hold a segment without consuming it when another source is outstanding.
    pub fn hold_segment(&mut self, segment: recording::Segment) -> Result<(), recording::Segment> {
        if self.held.is_some() || self.archive != ArchiveState::Idle {
            return Err(segment);
        }
        self.held = Some(segment);
        Ok(())
    }

    /// Transfer the held original into the worker, or retain it on refusal.
    pub fn queue_held(&mut self) -> Result<(), QueueError> {
        self.check_audio()?;
        if self.archive != ArchiveState::Idle {
            return Err(QueueError::Busy);
        }
        let segment = self.held.take().ok_or(QueueError::NoSegment)?;
        match self.worker.offer(segment) {
            Ok(()) => {
                self.archive = ArchiveState::Pending;
                Ok(())
            }
            Err(refusal) => {
                let (segment, reason) = match refusal {
                    av_worker::UnknownTimeOfferRefusal::Busy(segment) => {
                        (segment, QueueError::Busy)
                    }
                    av_worker::UnknownTimeOfferRefusal::Fenced(segment) => {
                        (segment, QueueError::Fenced)
                    }
                    av_worker::UnknownTimeOfferRefusal::Sink(refusal) => {
                        (refusal.segment, QueueError::Sink(refusal.reason))
                    }
                };
                self.held = Some(segment);
                Err(reason)
            }
        }
    }

    /// Run one bounded supervisor step, stopping media while a source or
    /// archive attempt is outstanding. Completed segments are queued directly.
    pub async fn step(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
    ) -> Step {
        if owner.cx.checkpoint().is_err() {
            return Step::Cancelled;
        }
        if self.audio_fenced {
            return Step::AudioFenced;
        }
        if self.supervisor.has_pending_audio() {
            return Step::Supervisor(supervisor::Step::AudioPending);
        }
        if self.held.is_some() {
            return match self.queue_held() {
                Ok(()) => Step::SourceQueued,
                Err(error) => Step::QueueRefused(error),
            };
        }
        if self.archive != ArchiveState::Idle {
            return Step::ArchivePending;
        }
        match self.supervisor.step(owner, operation, wait).await {
            supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Segment(
                segment,
            ))) => {
                self.held = Some(segment);
                if self.supervisor.has_pending_audio() {
                    return Step::Supervisor(supervisor::Step::AudioPending);
                }
                match self.queue_held() {
                    Ok(()) => Step::SourceQueued,
                    Err(error) => Step::QueueRefused(error),
                }
            }
            other => Step::Supervisor(other),
        }
    }

    /// Service controller traffic without polling or consuming media.
    pub async fn service_control(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
    ) -> supervisor::Step {
        self.supervisor.step_control(owner, operation, wait).await
    }

    /// Admit the queued source to the region-owned archival worker.
    pub fn start_archive<'a, 'b>(
        &mut self,
        task: &'a TaskCx<'b>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'b>,
        resource: &str,
        cost: &BudgetVector,
    ) -> Result<(), StartError> {
        if !self.supervisor.matches_clock(&clock) {
            return Err(StartError::Worker(av_worker::StartError::Context));
        }
        self.check_audio().map_err(StartError::Queue)?;
        if self.held.is_some() {
            self.queue_held().map_err(StartError::Queue)?;
        }
        match self.archive {
            ArchiveState::Idle => return Err(StartError::Worker(av_worker::StartError::Empty)),
            ArchiveState::Running => {
                return Err(StartError::Worker(av_worker::StartError::Running));
            }
            ArchiveState::Recovery => {
                return Err(StartError::Worker(av_worker::StartError::Fenced));
            }
            ArchiveState::Pending => (),
        }
        self.worker
            .start(task, cx, clock, resource, cost)
            .map_err(StartError::Worker)?;
        self.archive = ArchiveState::Running;
        self.retry_required = false;
        Ok(())
    }

    /// Request cancellation; the archive still must be joined.
    pub fn abort_archive(&self) {
        self.worker.abort();
    }
    /// Whether the worker coordinator observed cancellation.
    pub fn cancellation_observed(&self) -> bool {
        self.worker.cancellation_observed()
    }

    /// Join an attempt, resuming media only after confirmed publication.
    pub async fn join_archive(&mut self) -> Option<av_worker::UnknownTimeCompletion> {
        if self.archive != ArchiveState::Running {
            return None;
        }
        let completion = self.worker.join().await?;
        self.archive = match (&completion.runtime, &completion.outcome) {
            (
                Ok(()),
                av_worker::UnknownTimeOutcome::Publication(
                    av_worker::UnknownTimePublication::Published(_),
                ),
            ) => ArchiveState::Idle,
            (
                Ok(()),
                av_worker::UnknownTimeOutcome::NotStarted
                | av_worker::UnknownTimeOutcome::Publication(
                    av_worker::UnknownTimePublication::Refused { .. },
                ),
            ) => ArchiveState::Pending,
            _ => ArchiveState::Recovery,
        };
        self.retry_required = self.archive != ArchiveState::Idle;
        Some(completion)
    }

    /// Allow a bounded scheduler to retry a definite refusal or unstarted
    /// attempt. Indeterminate outcomes cannot be rearmed here.
    pub fn authorize_retry(&mut self) -> bool {
        if self.archive == ArchiveState::Pending && self.retry_required {
            self.retry_required = false;
            true
        } else {
            false
        }
    }

    /// Schedule one source, archive, or control step. This method does not
    /// create a detached task, reconnect a camera, or infer capture time.
    /// Failure remains latched until an explicit retry or reconciliation.
    pub async fn advance<'a, 'b>(
        &mut self,
        owner: &mut conversation::Owner<'_, 'a, 'b>,
        operation: &OperationId,
        wait: Duration,
        task: &'a TaskCx<'b>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'b>,
        resource: &str,
        cost: &BudgetVector,
    ) -> Advance {
        if !owner.clock.matches(owner.task, owner.cx)
            || !owner.clock.matches(task, cx)
            || !self.supervisor.matches_clock(&owner.clock)
            || !self.supervisor.matches_clock(&clock)
        {
            return Advance::Context;
        }
        if owner.cx.checkpoint().is_err() {
            return Advance::Cancelled(if self.archive == ArchiveState::Running {
                self.cancel_and_join_archive().await
            } else {
                None
            });
        }
        match self.archive {
            ArchiveState::Idle => Advance::Source(self.step(owner, operation, wait).await),
            ArchiveState::Pending if self.retry_required => Advance::RetryRequired,
            ArchiveState::Pending => match self.start_archive(task, cx, clock, resource, cost) {
                Ok(()) => Advance::ArchiveStarted,
                Err(error) => {
                    self.retry_required = true;
                    Advance::StartRefused(error)
                }
            },
            ArchiveState::Running => {
                Advance::Archive(self.drive_archive(owner, operation, wait).await)
            }
            ArchiveState::Recovery => Advance::RecoveryRequired,
        }
    }

    /// Run a bounded sequence of scheduling steps within the owning task.
    /// Events, including original source records, are transferred to the
    /// observer. A yielded slice retains any live worker in this guard; callers
    /// must resume or explicitly cancel and join it before retirement.
    pub async fn run_slice<'a, 'b>(
        &mut self,
        owner: &mut conversation::Owner<'_, 'a, 'b>,
        wait: Duration,
        max_steps: usize,
        task: &'a TaskCx<'b>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'b>,
        resource: &str,
        cost: &BudgetVector,
        observer: &mut dyn SessionObserver,
    ) -> SessionStop {
        if wait.is_zero() || !(1..=65_536).contains(&max_steps) {
            return SessionStop::Configuration;
        }
        if !owner.clock.matches(owner.task, owner.cx)
            || !owner.clock.matches(task, cx)
            || !self.supervisor.matches_clock(&owner.clock)
            || !self.supervisor.matches_clock(&clock)
        {
            return SessionStop::Halted {
                event: Advance::Context,
                drained: None,
            };
        }
        for _ in 0..max_steps {
            let Some(operation) = observer.next_operation() else {
                return SessionStop::OperationUnavailable {
                    drained: self.drain_running().await,
                };
            };
            let advance = self
                .advance(owner, &operation, wait, task, cx, clock, resource, cost)
                .await;
            let event = match advance {
                Advance::Source(Step::Supervisor(supervisor::Step::AudioPending)) => {
                    let Some(audio) = self.take_audio_event(owner) else {
                        return SessionStop::AudioWithheld;
                    };
                    SessionEvent::Audio(audio)
                }
                event if advance_is_terminal(&event) => {
                    return SessionStop::Halted {
                        event,
                        drained: self.drain_running().await,
                    };
                }
                event => SessionEvent::Advance(event),
            };
            match observer.observe(event) {
                Ok(SessionDecision::Continue) => (),
                Ok(SessionDecision::Yield) => return SessionStop::ObserverYielded,
                Ok(SessionDecision::Stop) => {
                    return SessionStop::ObserverStopped {
                        drained: self.drain_running().await,
                    };
                }
                Err(event) => {
                    return SessionStop::ObserverRefused {
                        event,
                        drained: self.drain_running().await,
                    };
                }
            }
        }
        SessionStop::Yielded
    }

    async fn drain_running(&mut self) -> Option<av_worker::UnknownTimeCompletion> {
        if self.archive == ArchiveState::Running {
            self.cancel_and_join_archive().await
        } else {
            None
        }
    }

    /// Finish a full control step while independently observing archive completion.
    pub async fn drive_archive(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
    ) -> Drive {
        if self.archive != ArchiveState::Running {
            return Drive::NotRunning;
        }
        if let Some(completion) = self.poll_archive_once().await {
            return Drive::Archive(completion);
        }
        let step = self.supervisor.step_control(owner, operation, wait).await;
        let completion = self.poll_archive_once().await;
        Drive::Control { step, completion }
    }

    async fn poll_archive_once(&mut self) -> Option<av_worker::UnknownTimeCompletion> {
        poll_fn(|cx| {
            let mut join = pin!(self.join_archive());
            Poll::Ready(match join.as_mut().poll(cx) {
                Poll::Ready(result) => result,
                Poll::Pending => None,
            })
        })
        .await
    }

    /// Request cancellation and await source release and task retirement.
    pub async fn cancel_and_join_archive(&mut self) -> Option<av_worker::UnknownTimeCompletion> {
        self.abort_archive();
        self.join_archive().await
    }

    /// Transfer a pending bounded audio observation under supervisor policy.
    pub fn take_audio_event(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
    ) -> Option<pipeline::AudioEvent> {
        let event = self.supervisor.take_audio_event(owner)?;
        self.audio_fenced |= matches!(
            event,
            pipeline::AudioEvent::Fenced(_)
                | pipeline::AudioEvent::Observed(
                    fss_packet::extended_flv::aac_track::Observation::Configuration { .. }
                )
        );
        Some(event)
    }

    fn check_audio(&self) -> Result<(), QueueError> {
        if self.audio_fenced {
            Err(QueueError::AudioFenced)
        } else if self.supervisor.has_pending_audio() {
            Err(QueueError::AudioPending)
        } else if !self.supervisor.audio_tracking_active() {
            Err(QueueError::AudioFenced)
        } else {
            Ok(())
        }
    }

    /// Prepare a source-bound camera-event reply.
    pub fn prepare_event_reply(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        frame: &events::Frame,
        timestamp: &str,
    ) -> Result<management::Intent, receive::Error> {
        self.supervisor.prepare_event_reply(owner, frame, timestamp)
    }
    /// Omit a camera-event reply under supervisor admission.
    pub fn omit_event_reply(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        frame: &events::Frame,
    ) -> Result<(), receive::Error> {
        self.supervisor.omit_event_reply(owner, frame)
    }
    /// Abandon an unwritten event reply while preserving its request.
    pub fn abandon_event_reply(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        frame: &events::Frame,
    ) -> Result<u64, receive::Error> {
        self.supervisor.abandon_event_reply(owner, frame)
    }
    /// Dispatch a separately journaled event-reply effect.
    pub async fn dispatch_event_reply(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        intent: management::Intent,
        current: management::Preconditions,
        permit: CommittedEffect,
        wait: Duration,
    ) -> Result<receive::ManagementWrite, receive::ManagementRefusal> {
        self.supervisor
            .dispatch_event_reply(owner, intent, current, permit, wait)
            .await
    }
    /// Prepare a motion-setting effect.
    pub fn prepare_motion(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        enabled: bool,
        timestamp: &str,
        conditions: motion::Preconditions,
    ) -> Result<motion::Intent, receive::Error> {
        self.supervisor
            .prepare_motion(owner, enabled, timestamp, conditions)
    }
    /// Dispatch a motion-setting effect under separate authority.
    pub async fn dispatch_motion(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        intent: motion::Intent,
        current: motion::Preconditions,
        permit: CommittedEffect,
        authority: &dyn receive::MotionAuthority,
        wait: Duration,
    ) -> Result<receive::MotionWrite, receive::MotionRefusal> {
        self.supervisor
            .dispatch_motion(owner, intent, current, permit, authority, wait)
            .await
    }
    /// Prepare an inert stream-quiesce request.
    pub fn prepare_quiesce(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        channel: VideoChannel,
        audio: AudioCodec,
        timestamp: &str,
        conditions: intent::Preconditions,
    ) -> Result<intent::Intent, receive::Error> {
        self.supervisor
            .prepare_quiesce(owner, channel, audio, timestamp, conditions)
    }
    /// Abandon an unwritten prepared stream request.
    pub fn abandon_prepared_stream(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        intent: intent::Intent,
    ) -> Result<super::AbandonedStream, receive::Error> {
        self.supervisor.abandon_prepared_stream(owner, intent)
    }
    /// Dispatch a prepared quiesce request with its committed effect permit.
    pub async fn dispatch_quiesce(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        intent: intent::Intent,
        current: intent::Preconditions,
        permit: CommittedEffect,
        wait: Duration,
    ) -> Result<receive::StreamWrite, receive::StreamRefusal> {
        self.supervisor
            .dispatch_quiesce(owner, intent, current, permit, wait)
            .await
    }

    /// Return every owner only after an active archive attempt has drained.
    pub fn retire(self) -> Result<Retirement, Self> {
        let Self {
            supervisor,
            worker,
            held,
            archive,
            audio_fenced,
            retry_required,
        } = self;
        match worker.retire() {
            Ok(worker) => Ok(Retirement {
                held,
                worker,
                supervisor: supervisor.retire(),
                archive,
                audio_fenced,
                retry_required,
            }),
            Err(worker) => Err(Self {
                supervisor,
                worker,
                held,
                archive,
                audio_fenced,
                retry_required,
            }),
        }
    }
}

fn supervisor_is_terminal(step: &supervisor::Step) -> bool {
    matches!(
        step,
        supervisor::Step::Media(pipeline::Step::Eof | pipeline::Step::LimitReached)
            | supervisor::Step::StartupEventBackpressure
            | supervisor::Step::EventReplyBackpressure
            | supervisor::Step::ControllerStopped(_)
            | supervisor::Step::ControllerError(_)
            | supervisor::Step::TimeSyncStopped { .. }
            | supervisor::Step::TimeSyncInterrupted { .. }
            | supervisor::Step::MediaError(_)
            | supervisor::Step::ConversationError(_)
            | supervisor::Step::Stopped
    )
}

fn advance_is_terminal(advance: &Advance) -> bool {
    match advance {
        Advance::Context
        | Advance::StartRefused(_)
        | Advance::RetryRequired
        | Advance::RecoveryRequired
        | Advance::Cancelled(_)
        | Advance::Source(
            Step::QueueRefused(_) | Step::ArchivePending | Step::Cancelled | Step::AudioFenced,
        )
        | Advance::Archive(Drive::NotRunning) => true,
        Advance::Source(Step::Supervisor(step)) | Advance::Archive(Drive::Control { step, .. }) => {
            supervisor_is_terminal(step)
        }
        Advance::Source(Step::SourceQueued)
        | Advance::ArchiveStarted
        | Advance::Archive(Drive::Archive(_)) => false,
    }
}
