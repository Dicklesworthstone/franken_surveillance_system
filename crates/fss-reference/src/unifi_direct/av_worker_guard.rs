#![forbid(unsafe_code)]
//! Bounded owner that couples a camera supervisor to an asynchronous archive.
//!
//! While capture bounds, publication, or reconciliation are pending, media
//! polling stops and the separate controller-only method remains available.
//! This is an explicitly scheduled building block, not a running service.

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
use fss_core::{BudgetVector, CaptureInterval, OperationId};
use fss_runtime::{effect::CommittedEffect, execution::TaskCx};

use super::{
    AudioCodec, VideoChannel, archive, av_bootstrap_driver, av_owned_sink, av_recording, av_sink,
    av_worker, conversation, events, intent, management, metered::MeteredClock, motion, pipeline,
    receive, recording, supervisor,
};
use crate::{ReferenceDeployment, ReplayCx};

/// The archive phase, separate from a segment awaiting capture bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveState {
    /// No archive source or publication is pending.
    Idle,
    /// An owned segment needs a publication attempt or retry.
    Pending,
    /// An admitted operation has not yet been joined.
    Running,
    /// An uncertain outcome requires retirement and reconciliation.
    Recovery,
}

/// Refusal to transfer the retained segment into the worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureError {
    /// A pending audio observation must be transferred first.
    AudioPending,
    /// Audio tracking or its configuration epoch requires reconciliation.
    AudioFenced,
    /// There is no segment waiting for capture bounds.
    NoSegment,
    /// The worker has an existing source or operation.
    Busy,
    /// The worker requires reconciliation.
    Fenced,
    /// The worker's sink rejected the segment configuration or state.
    Sink(av_sink::RefusalReason),
}

/// Refusal before starting an archive task; the source remains owned.
#[derive(Debug)]
pub enum StartError {
    /// A pending audio observation must be transferred first.
    AudioPending,
    /// Audio tracking or its configuration epoch requires reconciliation.
    AudioFenced,
    /// The worker refused admission.
    Worker(av_worker::StartError),
}

#[derive(Clone, Copy)]
enum AudioError {
    Pending,
    Fenced,
}

/// One bounded scheduling decision while an archive attempt is active.
#[must_use]
pub enum Drive {
    /// There is no running archive attempt to drive.
    NotRunning,
    /// An already-retired archive was observed before polling the controller.
    Archive(av_worker::Completion),
    /// One full control step ran. Archive completion may also have occurred.
    Control {
        /// The controller's actual result, including errors or backpressure.
        step: supervisor::Step,
        /// The drained archive result, if available after the control step.
        completion: Option<av_worker::Completion>,
    },
}

/// A task-owned supervisor and a single, separately drained archival worker.
#[must_use = "drain a running archive attempt and retire the retained owners"]
pub struct Guard<'scope, 'task, IO> {
    supervisor: supervisor::Supervisor<'scope, 'task, IO>,
    worker: av_worker::Worker,
    awaiting_capture: Option<recording::Segment>,
    archive: ArchiveState,
    audio_fenced: bool,
}

/// Every owned component returned after all archival work has drained.
#[must_use]
pub struct Retirement {
    /// Segment whose independently justified capture bounds were not supplied.
    pub awaiting_capture: Option<recording::Segment>,
    /// Archive source, journals, storage, and fence state.
    pub worker: av_worker::Retirement,
    /// Controller and media transport owners.
    pub supervisor: supervisor::Retirement,
    /// Archive state at retirement, including any recovery requirement.
    pub archive: ArchiveState,
    /// A later audio configuration or parser failure requires reconciliation.
    pub audio_fenced: bool,
}

/// Exclusive archive owners needed to construct an idle worker.
pub struct BootstrapResources {
    /// Exclusive local archive owner.
    pub deployment: ReferenceDeployment,
    /// Publication-intent journal.
    pub journal: archive::journal::Journal,
    /// Separate intent-anchor journal.
    pub keeper: archive::journal::AnchorKeeper,
    /// Explicit filesystem and cancellation authority.
    pub replay: ReplayCx,
    /// Revalidated original-byte retention decision.
    pub authority: Arc<dyn archive::RetainAuthority + Send + Sync>,
    /// Archive limits.
    pub limits: archive::Limits,
    /// Work allowance per publication attempt.
    pub work_limit: u64,
}

/// An archive guard and its explicitly hypothesized sender-clock origin.
#[must_use]
pub struct BootstrapStarted<'scope, 'task, IO> {
    /// The guard retains the original first segment pending capture bounds.
    pub guard: Guard<'scope, 'task, IO>,
    /// Sender-clock hypothesis, not physical capture-time evidence.
    pub origin: av_recording::SenderClockOrigin,
}

/// A refused construction retains the supervisor, source and storage owners.
#[must_use]
pub struct BootstrapRefusal<'scope, 'task, IO> {
    /// Original controller and media owner.
    pub supervisor: supervisor::Supervisor<'scope, 'task, IO>,
    /// Original sink and all supplied storage owners.
    pub worker_parts: av_worker::Parts,
    /// Original first segment awaiting capture bounds.
    pub first_segment: recording::Segment,
    /// Original sender-clock hypothesis.
    pub origin: av_recording::SenderClockOrigin,
}

impl<'scope, 'task, IO> BootstrapRefusal<'scope, 'task, IO> {
    /// Recover a handoff and resources for an explicit retry or retirement.
    pub fn into_retry(
        self,
    ) -> (
        av_bootstrap_driver::Handoff<'scope, 'task, IO>,
        BootstrapResources,
    ) {
        let av_worker::Parts {
            sink,
            deployment,
            journal,
            keeper,
            replay,
            authority,
            limits,
            work_limit,
        } = self.worker_parts;
        (
            av_bootstrap_driver::Handoff {
                supervisor: self.supervisor,
                bootstrap: av_owned_sink::Bootstrap {
                    sink,
                    first_segment: self.first_segment,
                    origin: self.origin,
                },
            },
            BootstrapResources {
                deployment,
                journal,
                keeper,
                replay,
                authority,
                limits,
                work_limit,
            },
        )
    }
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> Guard<'scope, 'task, IO> {
    /// Build an idle archive worker directly from a bootstrap handoff and
    /// retain its first segment pending independently justified capture bounds.
    /// No task or I/O is started. Every input is returned on construction refusal.
    pub fn from_bootstrap(
        handoff: av_bootstrap_driver::Handoff<'scope, 'task, IO>,
        resources: BootstrapResources,
    ) -> Result<BootstrapStarted<'scope, 'task, IO>, BootstrapRefusal<'scope, 'task, IO>> {
        let av_bootstrap_driver::Handoff {
            supervisor,
            bootstrap,
        } = handoff;
        let av_owned_sink::Bootstrap {
            sink,
            first_segment,
            origin,
        } = bootstrap;
        let BootstrapResources {
            deployment,
            journal,
            keeper,
            replay,
            authority,
            limits,
            work_limit,
        } = resources;
        let parts = av_worker::Parts {
            sink,
            deployment,
            journal,
            keeper,
            replay,
            authority,
            limits,
            work_limit,
        };
        if parts.sink.has_pending() {
            return Err(BootstrapRefusal {
                supervisor,
                worker_parts: parts,
                first_segment,
                origin,
            });
        }
        let worker = match av_worker::Worker::new(parts) {
            Ok(worker) => worker,
            Err(worker_parts) => {
                return Err(BootstrapRefusal {
                    supervisor,
                    worker_parts,
                    first_segment,
                    origin,
                });
            }
        };
        Ok(BootstrapStarted {
            guard: Self {
                supervisor,
                worker,
                awaiting_capture: Some(first_segment),
                archive: ArchiveState::Idle,
                audio_fenced: false,
            },
            origin,
        })
    }

    /// Attach an idle worker. Both original owners are returned on refusal.
    /// The caller must bind their configuration and identity to the same camera.
    pub fn new(
        supervisor: supervisor::Supervisor<'scope, 'task, IO>,
        worker: av_worker::Worker,
    ) -> Result<Self, (supervisor::Supervisor<'scope, 'task, IO>, av_worker::Worker)> {
        if !worker.is_idle() {
            return Err((supervisor, worker));
        }
        Ok(Self {
            supervisor,
            worker,
            awaiting_capture: None,
            archive: ArchiveState::Idle,
            audio_fenced: false,
        })
    }

    /// The current archive phase.
    pub fn archive_state(&self) -> ArchiveState {
        self.archive
    }

    /// Borrow the original source awaiting independently justified bounds.
    pub fn awaiting_capture(&self) -> Option<&recording::Segment> {
        self.awaiting_capture.as_ref()
    }

    /// Retain a completed source from an earlier supervisor step.
    pub fn hold_segment(&mut self, segment: recording::Segment) -> Result<(), recording::Segment> {
        if self.awaiting_capture.is_some() || self.archive != ArchiveState::Idle {
            return Err(segment);
        }
        self.awaiting_capture = Some(segment);
        Ok(())
    }

    /// Assign independent capture bounds; every refusal keeps the segment.
    pub fn supply_capture(&mut self, capture: CaptureInterval) -> Result<(), CaptureError> {
        self.check_audio().map_err(|error| match error {
            AudioError::Pending => CaptureError::AudioPending,
            AudioError::Fenced => CaptureError::AudioFenced,
        })?;
        let segment = self
            .awaiting_capture
            .take()
            .ok_or(CaptureError::NoSegment)?;
        match self.worker.offer(segment, capture) {
            Ok(()) => {
                self.archive = ArchiveState::Pending;
                Ok(())
            }
            Err(refusal) => {
                let (segment, reason) = match refusal {
                    av_worker::OfferRefusal::Busy { segment, .. } => (segment, CaptureError::Busy),
                    av_worker::OfferRefusal::Fenced { segment, .. } => {
                        (segment, CaptureError::Fenced)
                    }
                    av_worker::OfferRefusal::Sink(refusal) => {
                        (refusal.segment, CaptureError::Sink(refusal.reason))
                    }
                };
                self.awaiting_capture = Some(segment);
                Err(reason)
            }
        }
    }

    /// Run one bounded supervisor step only when no source is outstanding.
    pub async fn step(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
    ) -> av_sink::GuardStep {
        if owner.cx.checkpoint().is_err() {
            return av_sink::GuardStep::Cancelled;
        }
        if self.audio_fenced {
            return av_sink::GuardStep::AudioFenced;
        }
        if self.supervisor.has_pending_audio() {
            return av_sink::GuardStep::Supervisor(supervisor::Step::AudioPending);
        }
        if !self.supervisor.audio_tracking_active() {
            return av_sink::GuardStep::AudioFenced;
        }
        if self.awaiting_capture.is_some() {
            return av_sink::GuardStep::CaptureRequired;
        }
        if self.archive != ArchiveState::Idle {
            return av_sink::GuardStep::ArchivePending;
        }
        match self.supervisor.step(owner, operation, wait).await {
            supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Segment(
                segment,
            ))) => {
                self.awaiting_capture = Some(segment);
                av_sink::GuardStep::CaptureRequired
            }
            other => av_sink::GuardStep::Supervisor(other),
        }
    }

    /// Service control only, including while archive work is in flight.
    pub async fn service_control(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
    ) -> supervisor::Step {
        self.supervisor.step_control(owner, operation, wait).await
    }

    /// Admit the pending source to the region-owned worker.
    pub fn start_archive<'a, 'b>(
        &mut self,
        task: &'a TaskCx<'b>,
        cx: &'a Cx,
        clock: MeteredClock<'a, 'b>,
        resource: &str,
        cost: &BudgetVector,
    ) -> Result<(), StartError> {
        self.check_audio().map_err(|error| match error {
            AudioError::Pending => StartError::AudioPending,
            AudioError::Fenced => StartError::AudioFenced,
        })?;
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
        if !self.supervisor.matches_clock(&clock) {
            return Err(StartError::Worker(av_worker::StartError::Context));
        }
        self.worker
            .start(task, cx, clock, resource, cost)
            .map_err(StartError::Worker)?;
        self.archive = ArchiveState::Running;
        Ok(())
    }

    /// Request cancellation, without claiming that the work has drained.
    pub fn abort_archive(&self) {
        self.worker.abort();
    }

    /// Observe whether the worker coordinator saw cancellation.
    pub fn cancellation_observed(&self) -> bool {
        self.worker.cancellation_observed()
    }

    /// Join the worker. Dropping this borrowing wait leaves the owner intact.
    /// Only a confirmed publication with a successful runtime task resumes media.
    pub async fn join_archive(&mut self) -> Option<av_worker::Completion> {
        if self.archive != ArchiveState::Running {
            return None;
        }
        let completion = self.worker.join().await?;
        self.archive = match (&completion.runtime, &completion.outcome) {
            (Ok(()), av_worker::Outcome::Publication(av_worker::Publication::Published(_))) => {
                ArchiveState::Idle
            }
            (
                Ok(()),
                av_worker::Outcome::NotStarted
                | av_worker::Outcome::Publication(av_worker::Publication::Refused { .. }),
            ) => ArchiveState::Pending,
            _ => ArchiveState::Recovery,
        };
        Some(completion)
    }

    /// Drive a running archive without interrupting an in-progress control
    /// effect. A full bounded control step completes before archive readiness
    /// is checked again, so completion observation may be delayed by up to
    /// that step's receive and reply waits. Both results are returned if both
    /// occur. The caller must await this method or reconcile an interrupted
    /// control operation under the supervisor's normal cancellation rules.
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

    // This is intentionally a single poll. Dropping the borrowing join future
    // retains the worker; the actual control step is never raced or dropped.
    async fn poll_archive_once(&mut self) -> Option<av_worker::Completion> {
        poll_fn(|cx| {
            let mut join = pin!(self.join_archive());
            Poll::Ready(match join.as_mut().poll(cx) {
                Poll::Ready(completion) => completion,
                Poll::Pending => None,
            })
        })
        .await
    }

    /// Request cancellation and wait for closure release and task retirement.
    /// A dropped borrowing wait can be resumed by joining again.
    pub async fn cancel_and_join_archive(&mut self) -> Option<av_worker::Completion> {
        self.abort_archive();
        self.join_archive().await
    }

    /// Transfer the supervisor's bounded audio observation under its normal
    /// task, cancellation and controller-admission checks.
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

    fn check_audio(&self) -> Result<(), AudioError> {
        if self.audio_fenced {
            Err(AudioError::Fenced)
        } else if self.supervisor.has_pending_audio() {
            Err(AudioError::Pending)
        } else if !self.supervisor.audio_tracking_active() {
            Err(AudioError::Fenced)
        } else {
            Ok(())
        }
    }

    /// Prepare a source-bound camera event reply under the supervisor's checks.
    pub fn prepare_event_reply(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        frame: &events::Frame,
        timestamp: &str,
    ) -> Result<management::Intent, receive::Error> {
        self.supervisor.prepare_event_reply(owner, frame, timestamp)
    }

    /// Explicitly omit an event reply under the supervisor's checks.
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

    /// Dispatch an event reply with its separately journaled effect permit.
    pub async fn dispatch_event_reply(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        intent: management::Intent,
        current: management::Preconditions,
        permit: CommittedEffect,
        wait: Duration,
    ) -> Result<receive::ManagementWrite, receive::ManagementRefusal> {
        self.supervisor
            .dispatch_event_reply(owner, intent, current, permit, wait)
            .await
    }

    /// Prepare a motion-setting effect under the supervisor's checks.
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

    /// Dispatch a motion setting with an independently committed permit.
    pub async fn dispatch_motion(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
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

    /// Abandon a locally unwritten stream request under the supervisor's checks.
    pub fn abandon_prepared_stream(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        intent: intent::Intent,
    ) -> Result<super::AbandonedStream, receive::Error> {
        self.supervisor.abandon_prepared_stream(owner, intent)
    }

    /// Dispatch a prepared stream-quiesce request with its committed permit.
    pub async fn dispatch_quiesce(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        intent: intent::Intent,
        current: intent::Preconditions,
        permit: CommittedEffect,
        wait: Duration,
    ) -> Result<receive::StreamWrite, receive::StreamRefusal> {
        self.supervisor
            .dispatch_quiesce(owner, intent, current, permit, wait)
            .await
    }

    /// Retire only after the archive operation has actually drained. On
    /// refusal this returns the entire unchanged guard to its caller.
    pub fn retire(self) -> Result<Retirement, Self> {
        let Self {
            supervisor,
            worker,
            awaiting_capture,
            archive,
            audio_fenced,
        } = self;
        match worker.retire() {
            Ok(worker) => Ok(Retirement {
                awaiting_capture,
                worker,
                supervisor: supervisor.retire(),
                archive,
                audio_fenced,
            }),
            Err(worker) => Err(Self {
                supervisor,
                worker,
                awaiting_capture,
                archive,
                audio_fenced,
            }),
        }
    }
}
