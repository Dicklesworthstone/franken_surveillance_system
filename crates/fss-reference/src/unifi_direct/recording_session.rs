#![forbid(unsafe_code)]
//! Own bootstrap and A/V recording across their source-aware transition.
//!
//! This session starts from an already admitted controller and media driver.
//! Its caller still owns authority, operation IDs and every returned event;
//! it does not perform discovery, camera adoption, retries or reconciliation.

use std::time::Duration;

use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
};
use fss_core::OperationId;
use fss_runtime::{effect::CommittedEffect, execution::TaskCx};

use super::{
    AudioCodec, VideoChannel, av_bootstrap, av_bootstrap_driver, av_recording,
    av_unknown_worker_guard::{self, Advance, Guard, SessionEvent},
    av_worker, conversation, events, intent, management,
    metered::MeteredClock,
    motion, pipeline, receive,
    source_coordinator::{self, ArchiveAdmission, Coordinator},
    source_worker, supervisor,
};

/// Exact phase owners returned for shutdown or recovery.
#[must_use]
pub enum Phase<'scope, 'task, IO> {
    /// Bootstrap is still collecting the original first segment.
    Bootstrap {
        /// Task-owned controller, media and retained inputs.
        driver: Box<av_bootstrap_driver::Driver<'scope, 'task, IO>>,
        /// Dedicated A/V archive owners.
        resources: Box<av_unknown_worker_guard::BootstrapResources>,
    },
    /// Bootstrap succeeded and the first source is held by the guard.
    Recording(Box<Guard<'scope, 'task, IO>>),
    /// Transition refused with its original owners retained for reconciliation.
    TransitionRefused(Box<source_coordinator::TransitionRefusal<'scope, 'task, IO>>),
}

/// A complete step remains owned by the session's caller.
#[must_use]
pub enum Step {
    /// A bootstrap or separate-source outcome.
    Bootstrap(source_coordinator::BootstrapStep),
    /// The recording guard was constructed; this is a sender-clock hypothesis.
    RecordingStarted(av_recording::SenderClockOrigin),
    /// A recording, control or archive outcome.
    Recording(source_coordinator::Step),
    /// An audio observation could not be transferred and remains in the guard.
    AudioWithheld,
    /// The transition refused; recover the exact refusal with `into_parts`.
    TransitionRefused,
}

/// Supplies distinct, caller-reserved operations and accepts complete outcomes.
pub trait Observer {
    /// Return an unused operation for this step, or stop before polling work.
    fn next_operation(&mut self) -> Option<OperationId>;
    /// Accept the complete event or return it unchanged.
    fn observe(&mut self, event: Box<Step>) -> Result<source_coordinator::Decision, Box<Step>>;
}

/// A bounded run stopped while the session and its workers remain owned.
#[must_use = "account for the returned event and drain or resume the session"]
pub enum SliceStop {
    /// Bounds were invalid; no operation was requested and no work was polled.
    Configuration,
    /// The step limit was reached.
    Yielded,
    /// The observer accepted an event and requested a resumable yield.
    ObserverYielded,
    /// The observer accepted an event and requested a stop.
    ObserverStopped,
    /// No unused operation was available; no further work was polled.
    OperationUnavailable,
    /// An actionable or terminal event remains with the caller.
    Halted(Box<Step>),
    /// The observer returned an event intact.
    ObserverRefused(Box<Step>),
}

/// Single owner of bootstrap, recording and their separate-source archive.
#[must_use = "drain or recover both the coordinator and phase owners"]
pub struct Session<'scope, 'task, IO> {
    coordinator: Coordinator,
    phase: Option<Phase<'scope, 'task, IO>>,
}

/// A session cannot renew audio before or after its recording phase.
#[derive(Debug)]
pub enum AudioAllowanceError {
    /// The session does not currently own a recording guard.
    NotRecording,
    /// The archive worker refused the requested renewal.
    Worker(av_worker::AudioAllowanceError),
}

/// Explicit per-session authority for automatic AAC allowance renewal.
/// `minimum` should cover the largest permitted segment's AAC frame count.
/// This does not authorize retries, reconnection, publication, or retention.
pub struct AudioAllowancePolicy {
    minimum: u64,
    chunk: u64,
    remaining_budget: u64,
}

impl AudioAllowancePolicy {
    /// Construct a bounded renewal plan. Each clock extension may add no more
    /// than 16 million observations, and the total budget is caller supplied.
    pub fn new(minimum: u64, chunk: u64, budget: u64) -> Option<Self> {
        if minimum == 0 || chunk == 0 || chunk > 16_000_000 {
            return None;
        }
        Some(Self {
            minimum,
            chunk,
            remaining_budget: budget,
        })
    }

    /// Unspent frame observations authorized by the caller.
    pub fn remaining_budget(&self) -> u64 {
        self.remaining_budget
    }
}

/// Result of one policy-aware scheduling step. A renewal is reported before
/// any subsequent source or archive work is started.
#[must_use]
pub enum AudioAllowanceStep {
    /// The normal session returned its complete result.
    Session(Step),
    /// The existing epoch was extended; no session work was polled.
    Renewed {
        /// Allowance before renewal.
        before: u64,
        /// Allowance after renewal.
        after: u64,
        /// Unspent caller-authorized observations.
        budget: u64,
    },
    /// The plan cannot reach its configured minimum without more authority.
    Exhausted {
        /// Current epoch allowance.
        remaining: u64,
        /// Unspent caller-authorized observations.
        budget: u64,
        /// Complete control outcome while media remained paused.
        control: supervisor::Step,
    },
    /// The archive state refused inspection or renewal; media remained paused.
    Refused {
        /// Payload-free refusal.
        error: AudioAllowanceError,
        /// Complete control outcome while media remained paused.
        control: supervisor::Step,
    },
}

/// Exact phase owners after stopping further admission.
#[must_use = "drain active workers and account for all returned owners"]
pub enum Stop<'scope, 'task, IO> {
    /// Bootstrap's separate-source worker must be joined before retirement.
    Bootstrap(source_coordinator::BootstrapShutdown<'scope, 'task, IO>),
    /// Both recording workers must be joined before retirement.
    Recording(source_coordinator::Shutdown<'scope, 'task, IO>),
    /// Transition refused with its source coordinator and refusal retained.
    TransitionRefused {
        /// The separate-source owner, which still requires retirement.
        coordinator: Coordinator,
        /// Original transition owners and reason.
        refusal: Box<source_coordinator::TransitionRefusal<'scope, 'task, IO>>,
    },
}

/// A refused fresh-session attachment retains every supplied owner.
#[must_use = "recover the controller, source and archive owners"]
pub enum BeginRefusal<'scope, 'task, IO> {
    /// Audio tracking could not be enabled before media processing.
    Audio {
        /// Original controller and media owner.
        supervisor: supervisor::Supervisor<'scope, 'task, IO>,
        /// Unconsumed bootstrap collector.
        collector: av_bootstrap::Collector,
        /// Unconsumed source coordinator.
        coordinator: Coordinator,
        /// Unconsumed A/V archive owners.
        resources: Box<av_unknown_worker_guard::BootstrapResources>,
        /// Exact reason audio setup was refused.
        error: pipeline::AudioSetupError,
    },
    /// Driver admission refused after enabling audio tracking.
    Driver {
        /// All controller and collector state returned by driver admission.
        parts: av_bootstrap_driver::Parts<'scope, 'task, IO>,
        /// Unconsumed source coordinator.
        coordinator: Coordinator,
        /// Unconsumed A/V archive owners.
        resources: Box<av_unknown_worker_guard::BootstrapResources>,
    },
}

/// Exclusive, control-only access to the session's existing supervisor.
/// Preparing a request performs no write; dispatch still requires its exact
/// committed effect and the supervisor's current authority checks.
pub struct Control<'a, 'scope, 'task, IO> {
    supervisor: &'a mut supervisor::Supervisor<'scope, 'task, IO>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Control<'_, '_, '_, IO> {
    pub(super) fn from_supervisor<'a, 'scope, 'task>(
        supervisor: &'a mut supervisor::Supervisor<'scope, 'task, IO>,
    ) -> Control<'a, 'scope, 'task, IO> {
        Control { supervisor }
    }

    /// Set the bounded time-sync reply allowance without polling the session.
    /// `None` uses the caller's poll wait; this grants no reply authority.
    pub fn set_time_sync_reply_wait(
        &mut self,
        wait: Option<Duration>,
    ) -> Result<(), conversation::Error> {
        self.supervisor.set_time_sync_reply_wait(wait)
    }

    /// Prepare a reply tied to the original observed event.
    pub fn prepare_event_reply(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        frame: &events::Frame,
        timestamp: &str,
    ) -> Result<management::Intent, receive::Error> {
        self.supervisor.prepare_event_reply(owner, frame, timestamp)
    }
    /// Prepare and journal a source-bound reply before dispatching it.
    pub fn prepare_journaled_event_reply(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        frame: &events::Frame,
        timestamp: &str,
        operation: &OperationId,
    ) -> Result<supervisor::EventReplyTrace, supervisor::EventReplyPreparationError> {
        self.supervisor
            .prepare_journaled_event_reply(owner, frame, timestamp, operation)
    }
    /// Explicitly omit an event reply while retaining its observation.
    pub fn omit_event_reply(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        frame: &events::Frame,
    ) -> Result<(), receive::Error> {
        self.supervisor.omit_event_reply(owner, frame)
    }
    /// Abandon an unwritten reply while retaining its observed request.
    pub fn abandon_event_reply(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        frame: &events::Frame,
    ) -> Result<u64, receive::Error> {
        self.supervisor.abandon_event_reply(owner, frame)
    }
    /// Dispatch an independently journaled event reply.
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
    /// Dispatch a reply while retaining its operation and outcome across cancellation.
    pub async fn dispatch_event_reply_tracked(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        current: management::Preconditions,
        wait: Duration,
        trace: &mut supervisor::EventReplyTrace,
    ) -> Result<(), supervisor::EventReplyTraceUnavailable> {
        self.supervisor
            .dispatch_event_reply_tracked(owner, current, wait, trace)
            .await
    }
    /// Prepare a camera motion-setting change without sending it.
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
    /// Dispatch an independently journaled motion-setting change.
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
    /// Abandon a locally unwritten prepared stream request.
    pub fn abandon_prepared_stream(
        &mut self,
        owner: &conversation::Owner<'_, '_, '_>,
        intent: intent::Intent,
    ) -> Result<super::AbandonedStream, receive::Error> {
        self.supervisor.abandon_prepared_stream(owner, intent)
    }
    /// Dispatch an independently journaled stream-quiesce request.
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
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> Session<'scope, 'task, IO> {
    /// Attach a fresh supervisor before consuming any media.
    ///
    /// The caller supplies the exact controller, collector, separate-source
    /// coordinator and archive owners. This performs no I/O and grants no
    /// authority. Refusal returns every owner; it never restarts a pipeline
    /// that has already processed media or already enabled audio tracking.
    pub fn begin(
        mut supervisor: supervisor::Supervisor<'scope, 'task, IO>,
        collector: av_bootstrap::Collector,
        coordinator: Coordinator,
        resources: Box<av_unknown_worker_guard::BootstrapResources>,
    ) -> Result<Self, BeginRefusal<'scope, 'task, IO>> {
        if let Err(error) = supervisor.enable_audio_tracking() {
            return Err(BeginRefusal::Audio {
                supervisor,
                collector,
                coordinator,
                resources,
                error,
            });
        }
        let driver = match av_bootstrap_driver::Driver::attach(supervisor, collector) {
            Ok(driver) => driver,
            Err(parts) => {
                return Err(BeginRefusal::Driver {
                    parts,
                    coordinator,
                    resources,
                });
            }
        };
        Ok(Self::new(coordinator, Box::new(driver), resources))
    }

    /// Attach already-authorized owners without starting work or making I/O.
    pub fn new(
        coordinator: Coordinator,
        driver: Box<av_bootstrap_driver::Driver<'scope, 'task, IO>>,
        resources: Box<av_unknown_worker_guard::BootstrapResources>,
    ) -> Self {
        Self {
            coordinator,
            phase: Some(Phase::Bootstrap { driver, resources }),
        }
    }

    /// Reassemble an already constructed recording guard and its separate
    /// source owner. This grants no authority and does not start any work.
    pub fn from_recording(coordinator: Coordinator, guard: Box<Guard<'scope, 'task, IO>>) -> Self {
        Self {
            coordinator,
            phase: Some(Phase::Recording(guard)),
        }
    }

    pub(super) fn from_parts(coordinator: Coordinator, phase: Phase<'scope, 'task, IO>) -> Self {
        Self {
            coordinator,
            phase: Some(phase),
        }
    }

    /// Borrow only control operations while keeping all media and archive owners here.
    /// No control is available after a refused transition; recover the refusal instead.
    pub fn control(&mut self) -> Option<Control<'_, 'scope, 'task, IO>> {
        let supervisor = match self.phase.as_mut()? {
            Phase::Bootstrap { driver, .. } => driver.control_supervisor(),
            Phase::Recording(guard) => guard.control_supervisor(),
            Phase::TransitionRefused(_) => return None,
        };
        Some(Control { supervisor })
    }

    /// Check both clocks against the existing controller without polling it.
    pub(super) fn clocks_match(
        &mut self,
        owner: &MeteredClock<'_, '_>,
        clock: &MeteredClock<'_, '_>,
    ) -> bool {
        self.control().is_some_and(|control| {
            control.supervisor.matches_clock(owner) && control.supervisor.matches_clock(clock)
        })
    }

    /// Authorize one retry of a definitely pending separate source.
    pub fn authorize_source_retry(&mut self) -> Result<(), source_coordinator::RetryError> {
        self.coordinator.authorize_retry()
    }

    /// Authorize one retry of a definitely pending A/V archive attempt.
    pub fn authorize_av_retry(&mut self) -> bool {
        match self.phase.as_mut() {
            Some(Phase::Recording(guard)) => guard.authorize_retry(),
            _ => false,
        }
    }

    /// Return a settled A/V capacity boundary only when the separate source
    /// worker is idle. This is a scheduling observation, not rollover authority.
    pub(super) fn ready_rollover(
        &mut self,
        owner_clock: &MeteredClock<'_, '_>,
        clock: &MeteredClock<'_, '_>,
    ) -> Option<av_worker::RolloverNeed> {
        if self.coordinator.source_status() != source_worker::Status::Idle {
            return None;
        }
        match self.phase.as_mut()? {
            Phase::Recording(guard) => {
                if guard.control_supervisor().matches_clock(owner_clock)
                    && guard.control_supervisor().matches_clock(clock)
                {
                    guard.rollover_need()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Service only the existing controller while media is paused at capacity.
    pub(super) async fn rollover_control(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
    ) -> Option<supervisor::Step> {
        match self.phase.as_mut()? {
            Phase::Recording(guard) => Some(guard.service_control(owner, operation, wait).await),
            _ => None,
        }
    }

    /// Explicitly extend the existing AAC epoch allowance without retrying a
    /// failed archive attempt or resetting its timeline.
    pub fn extend_audio_limit(
        &mut self,
        additional_frames: u64,
    ) -> Result<u64, AudioAllowanceError> {
        match self.phase.as_mut() {
            Some(Phase::Recording(guard)) => guard
                .extend_audio_limit(additional_frames)
                .map_err(AudioAllowanceError::Worker),
            _ => Err(AudioAllowanceError::NotRecording),
        }
    }

    /// Apply a caller-bounded renewal policy before starting more work. Active
    /// archive tasks are driven normally so control traffic and cancellation
    /// can drain. No failed publication is automatically retried.
    pub async fn step_with_audio_allowance(
        &mut self,
        policy: &mut AudioAllowancePolicy,
        owner: &mut conversation::Owner<'_, 'scope, 'task>,
        operation: &OperationId,
        wait: Duration,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        av_archive: ArchiveAdmission<'_>,
        source_archive: ArchiveAdmission<'_>,
    ) -> AudioAllowanceStep {
        let context_valid = owner.cx.checkpoint().is_ok()
            && owner.clock.matches(owner.task, owner.cx)
            && owner.clock.matches(task, cx)
            && clock.matches(task, cx);
        if context_valid && self.coordinator.source_status() == source_worker::Status::Idle {
            if let Some(Phase::Recording(guard)) = self.phase.as_mut() {
                if guard.control_supervisor().matches_clock(&owner.clock)
                    && guard.control_supervisor().matches_clock(&clock)
                {
                    match guard.remaining_audio_frames() {
                        Ok(Some(before)) if before < policy.minimum => {
                            if policy.remaining_budget < policy.minimum - before {
                                let control =
                                    Box::pin(guard.service_control(owner, operation, wait)).await;
                                return AudioAllowanceStep::Exhausted {
                                    remaining: before,
                                    budget: policy.remaining_budget,
                                    control,
                                };
                            }
                            let additional = policy.chunk.min(policy.remaining_budget);
                            match guard.extend_audio_limit(additional) {
                                Ok(after) => {
                                    policy.remaining_budget -= additional;
                                    return AudioAllowanceStep::Renewed {
                                        before,
                                        after,
                                        budget: policy.remaining_budget,
                                    };
                                }
                                Err(error) => {
                                    let control =
                                        Box::pin(guard.service_control(owner, operation, wait))
                                            .await;
                                    return AudioAllowanceStep::Refused {
                                        error: AudioAllowanceError::Worker(error),
                                        control,
                                    };
                                }
                            }
                        }
                        Err(error) => {
                            let control =
                                Box::pin(guard.service_control(owner, operation, wait)).await;
                            return AudioAllowanceStep::Refused {
                                error: AudioAllowanceError::Worker(error),
                                control,
                            };
                        }
                        Ok(Some(_)) | Ok(None) => (),
                    }
                }
            }
        }
        AudioAllowanceStep::Session(
            self.step(
                owner,
                operation,
                wait,
                task,
                cx,
                clock,
                av_archive,
                source_archive,
            )
            .await,
        )
    }

    /// Advance once, transferring every result to the caller.
    ///
    /// The phase remains in this owner across every await. Dropping a pending
    /// call therefore does not drop the driver or archive guard. A successful
    /// ready transition has no intervening await and does not poll more media.
    pub async fn step(
        &mut self,
        owner: &mut conversation::Owner<'_, 'scope, 'task>,
        operation: &OperationId,
        wait: Duration,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        av_archive: ArchiveAdmission<'_>,
        source_archive: ArchiveAdmission<'_>,
    ) -> Step {
        match self
            .phase
            .as_mut()
            .expect("session phase is always present")
        {
            Phase::Bootstrap { driver, .. } => {
                let outcome = Box::pin(self.coordinator.bootstrap_step(
                    driver,
                    owner,
                    operation,
                    wait,
                    task,
                    cx,
                    clock,
                    source_archive,
                ))
                .await;
                if matches!(
                    outcome,
                    source_coordinator::BootstrapStep::Driver(av_bootstrap_driver::Step::Ready)
                ) {
                    self.transition()
                } else {
                    Step::Bootstrap(outcome)
                }
            }
            Phase::Recording(guard) => {
                let outcome = Box::pin(self.coordinator.step(
                    guard,
                    owner,
                    operation,
                    wait,
                    task,
                    cx,
                    clock,
                    av_archive,
                    source_archive,
                ))
                .await;
                match outcome {
                    source_coordinator::Step::Session(SessionEvent::Advance(Advance::Source(
                        av_unknown_worker_guard::Step::Supervisor(
                            super::supervisor::Step::AudioPending,
                        ),
                    ))) => match guard.take_audio_event(owner) {
                        Some(audio) => Step::Recording(source_coordinator::Step::Session(
                            SessionEvent::Audio(audio),
                        )),
                        None => Step::AudioWithheld,
                    },
                    other => Step::Recording(other),
                }
            }
            Phase::TransitionRefused(_) => Step::TransitionRefused,
        }
    }

    /// Run bounded steps across bootstrap and recording in the owning task.
    ///
    /// All complete events are transferred to the observer, except actionable
    /// or terminal events, which are returned directly. A refused event is
    /// returned intact. No stop drains workers or authorizes a retry: the
    /// caller must resume, reconcile, or explicitly shut down the same owners.
    /// The observer must reserve operation identities across process restarts.
    pub async fn run_slice(
        &mut self,
        owner: &mut conversation::Owner<'_, 'scope, 'task>,
        wait: Duration,
        max_steps: usize,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        av_archive: ArchiveAdmission<'_>,
        source_archive: ArchiveAdmission<'_>,
        observer: &mut dyn Observer,
    ) -> SliceStop {
        if wait.is_zero() || wait > Duration::from_secs(30) || !(1..=65_536).contains(&max_steps) {
            return SliceStop::Configuration;
        }
        for _ in 0..max_steps {
            let Some(operation) = observer.next_operation() else {
                return SliceStop::OperationUnavailable;
            };
            let step = Box::new(
                Box::pin(self.step(
                    owner,
                    &operation,
                    wait,
                    task,
                    cx,
                    clock,
                    av_archive,
                    source_archive,
                ))
                .await,
            );
            let terminal = match &*step {
                Step::Bootstrap(event) => source_coordinator::bootstrap_is_terminal(event),
                Step::Recording(event) => source_coordinator::is_terminal(event),
                Step::AudioWithheld | Step::TransitionRefused => true,
                Step::RecordingStarted(_) => false,
            };
            if terminal {
                return SliceStop::Halted(step);
            }
            match observer.observe(step) {
                Ok(source_coordinator::Decision::Continue) => (),
                Ok(source_coordinator::Decision::Yield) => return SliceStop::ObserverYielded,
                Ok(source_coordinator::Decision::Stop) => return SliceStop::ObserverStopped,
                Err(event) => return SliceStop::ObserverRefused(event),
            }
        }
        SliceStop::Yielded
    }

    #[inline(never)]
    fn transition(&mut self) -> Step {
        let Some(Phase::Bootstrap { driver, resources }) = self.phase.take() else {
            unreachable!("transition is called only from bootstrap")
        };
        let result = self
            .coordinator
            .prepare_recording_guard(driver, resources)
            .and_then(|prepared| prepared.prepare_guard())
            .and_then(|prepared| prepared.finish());
        match result {
            Ok(started) => {
                let origin = started.origin;
                self.phase = Some(Phase::Recording(Box::new(started.guard)));
                Step::RecordingStarted(origin)
            }
            Err(refusal) => {
                self.phase = Some(Phase::TransitionRefused(Box::new(refusal)));
                Step::TransitionRefused
            }
        }
    }

    /// Recover the exact current phase and separate-source owner.
    pub fn into_parts(self) -> (Coordinator, Phase<'scope, 'task, IO>) {
        (
            self.coordinator,
            self.phase.expect("session phase is always present"),
        )
    }

    /// Stop new session work without requiring the caller to know its phase.
    ///
    /// Worker completion and any indeterminate publication remain caller
    /// obligations. A transition refusal is returned intact for recovery.
    pub fn stop(self) -> Stop<'scope, 'task, IO> {
        let (coordinator, phase) = self.into_parts();
        match phase {
            Phase::Bootstrap { driver, resources } => Stop::Bootstrap(
                source_coordinator::BootstrapShutdown::request(coordinator, driver, resources),
            ),
            Phase::Recording(guard) => {
                Stop::Recording(source_coordinator::Shutdown::request(coordinator, guard))
            }
            Phase::TransitionRefused(refusal) => Stop::TransitionRefused {
                coordinator,
                refusal,
            },
        }
    }

    /// Stop admitting session work and cancel both active recording archives.
    /// Bootstrap and refused transitions are returned unchanged for recovery.
    pub fn request_shutdown(self) -> Result<source_coordinator::Shutdown<'scope, 'task, IO>, Self> {
        if !matches!(self.phase, Some(Phase::Recording(_))) {
            return Err(self);
        }
        let (coordinator, phase) = self.into_parts();
        let Phase::Recording(guard) = phase else {
            unreachable!("phase was checked")
        };
        Ok(source_coordinator::Shutdown::request(coordinator, guard))
    }

    /// Stop bootstrap admission and request cancellation of its source worker.
    /// Other phases are returned unchanged for their own shutdown or recovery.
    pub fn request_bootstrap_shutdown(
        self,
    ) -> Result<source_coordinator::BootstrapShutdown<'scope, 'task, IO>, Self> {
        if !matches!(self.phase, Some(Phase::Bootstrap { .. })) {
            return Err(self);
        }
        let (coordinator, phase) = self.into_parts();
        let Phase::Bootstrap { driver, resources } = phase else {
            unreachable!("phase was checked")
        };
        Ok(source_coordinator::BootstrapShutdown::request(
            coordinator,
            driver,
            resources,
        ))
    }
}
